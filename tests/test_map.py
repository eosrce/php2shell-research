import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class MapTest(unittest.TestCase):
    def test_map_sections(self):
        text = (ROOT / "docs" / "ROADMAP.md").read_text(encoding="utf-8")
        for marker in ("LAYER 0", "LAYER 1", "LAYER 3", "T12-8M",
                       "T12-128M", "T15", "T2 专项", "T3 专项",
                       "reclaim 8KB endgame 3/3", "加权总体"):
            self.assertIn(marker, text, marker)

    def test_license_boundary(self):
        self.assertTrue((ROOT / "LICENSE").is_file())
        notice = (ROOT / "NOTICE").read_text(encoding="utf-8")
        self.assertIn("self-implemented", notice)
        self.assertIn("original", notice)
        self.assertFalse((ROOT / "src" / "exploit.py").exists(),
                         "the lab-only exploit.py must not be shipped")
        self.assertFalse((ROOT / "upstream").exists(),
                         "no upstream checkout ships in the release")

    def test_docs_index(self):
        text = (ROOT / "docs" / "INDEX.md").read_text(encoding="utf-8")
        self.assertIn("ROADMAP", text)
        self.assertIn("fpm-8m-reclaim", text)


if __name__ == "__main__":
    unittest.main()
