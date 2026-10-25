#!/usr/bin/env python3
"""Smoke test for tools/fpm_reclaim.py: forged layout offsets only."""
import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import fpm_reclaim  # noqa: E402

D = 0x7F0000000000
K = 0xFE8
SIZE = 8192
ZIF = 0x7F0000200000
CMD = b"id>out/p1"

b = fpm_reclaim.build_payload(D, K, SIZE, ZIF, CMD)
assert len(b) == SIZE
assert struct.unpack_from("<Q", b, K + 0)[0] == D + 56
assert struct.unpack_from("<q", b, K + 56)[0] == 2
assert struct.unpack_from("<Q", b, K + 56 + 16 + 8)[0] == D + 0x300
assert struct.unpack_from("<Q", b, K + 0x300)[0] == D + 0x500
assert struct.unpack_from("<I", b, K + 0x300 + 8)[0] == 0x10A
assert struct.unpack_from("<Q", b, K + 0x508)[0] == D + 0x700
assert struct.unpack_from("<I", b, K + 0x510)[0] == 0x307
assert struct.unpack_from("<Q", b, K + 0x730)[0] == ZIF
assert struct.unpack_from("<Q", b, K + 0x800 + 80)[0] == D + 0x880
assert struct.unpack_from("<Q", b, K + 0x880 + 16)[0] == len(CMD)
assert b[K + 0x880 + 24:K + 0x880 + 24 + len(CMD)] == CMD
try:
    fpm_reclaim.build_payload(D, K, 0x800, ZIF, CMD)
except ValueError:
    pass
else:
    raise SystemExit("expected ValueError for too-small reclaim")
print("RECLAIM_SMOKE_OK")
