"""Multipart encoder for the clean-room p2s package (docs/76 R1).

The encoder is deterministic: the caller may pass a boundary, otherwise a
random one is generated.  Field order is preserved.  No upstream code.
"""
from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Iterable


@dataclass(frozen=True)
class Field:
    name: str
    value: bytes
    filename: str | None = None
    content_type: str | None = None

    def __post_init__(self):
        if isinstance(self.value, str):
            object.__setattr__(self, "value", self.value.encode())


def encode(fields: Iterable[Field], boundary: str | None = None) -> tuple[bytes, str]:
    """Return (body, boundary)."""
    bnd = boundary or ("p2s" + os.urandom(8).hex())
    b = bnd.encode()
    out = bytearray()
    for f in fields:
        if not isinstance(f.value, bytes):
            raise TypeError("field %r: value must be bytes" % f.name)
        out += b"--" + b + b"\r\n"
        out += b'Content-Disposition: form-data; name="' + f.name.encode() + b'"'
        if f.filename is not None:
            out += b'; filename="' + f.filename.encode() + b'"'
        out += b"\r\n"
        if f.content_type:
            out += b"Content-Type: " + f.content_type.encode() + b"\r\n"
        out += b"\r\n" + f.value + b"\r\n"
    out += b"--" + b + b"--\r\n"
    return bytes(out), bnd


def content_type(boundary: str) -> str:
    return "multipart/form-data; boundary=" + boundary
