"""p2s - clean-room public package (docs/76).

This package is the planned MIT-licensed replacement for the lab-only
monolithic tool.  It is written from the documented protocol/behavior
(docs/38, 44, 55, 61) and contains no upstream code.  The old tool stays in
the lab tree and is excluded from the release.
"""
__all__ = ["transport", "multipart", "leaks", "warning", "geometry", "proof",
           "workers", "pure128", "cms"]
