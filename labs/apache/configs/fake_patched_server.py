#!/usr/bin/env python3
"""Minimal server that advertises a patched PHP version.

Used to test the fork's version gate without needing the (currently
unpublished) php:8.4.27-apache image.  It never executes anything.
"""
from http.server import BaseHTTPRequestHandler, HTTPServer


class Handler(BaseHTTPRequestHandler):
    def _reply(self):
        self.send_response(200)
        self.send_header("X-Powered-By", "PHP/8.4.27")
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(b"patched\n")

    def do_GET(self):
        self._reply()

    def do_POST(self):
        length = int(self.headers.get("Content-Length", "0"))
        if length:
            self.rfile.read(length)
        self._reply()

    def log_message(self, *args):
        pass


if __name__ == "__main__":
    HTTPServer(("127.0.0.1", 18099), Handler).serve_forever()
