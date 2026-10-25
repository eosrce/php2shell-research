"""Proof sources for the clean-room p2s package (docs/76 R2).

A run only counts when the command's output is readable from an independent
source.  The chain writes the command result to a path; this module reads that
path from the local host, over HTTP, or inside an owned lab container, and
optionally requires a match token (for example ``uid=``).

The sources are cleared before a run so a stale file can never look like a
success (AGENTS iron rule #1).
"""
from __future__ import annotations

import os
import subprocess
from dataclasses import dataclass

from . import transport


@dataclass(frozen=True)
class ProofSpec:
    local_path: str = ""
    fetch_path: str = ""
    container: str = ""
    container_path: str = ""
    match: bytes = b""

    def configured(self) -> bool:
        return bool(self.local_path or self.fetch_path or self.container_path)

    def clear(self) -> None:
        if self.local_path:
            try:
                os.unlink(self.local_path)
            except OSError:
                pass
        if self.container and self.container_path:
            subprocess.run(["docker", "exec", self.container, "rm", "-f",
                            self.container_path],
                           capture_output=True, timeout=30)

    def _container_read(self) -> str:
        if not (self.container and self.container_path):
            return ""
        try:
            proc = subprocess.run(
                ["docker", "exec", self.container, "cat",
                 self.container_path],
                capture_output=True, timeout=30)
        except (OSError, subprocess.SubprocessError):
            return ""
        if proc.returncode != 0:
            return ""
        return proc.stdout.decode("latin1", "replace").strip()

    def check(self, endpoint: transport.Endpoint) -> str:
        """Return the proof text, or "" when no source matches."""
        candidates: list[str] = []
        if self.local_path:
            try:
                with open(self.local_path, "rb") as fh:
                    candidates.append(fh.read().decode("latin1", "replace").strip())
            except OSError:
                pass
        if self.fetch_path:
            try:
                resp = transport.get(endpoint, self.fetch_path,
                                     timeout=15, read_cap=1 << 20)
                if resp.status == 200:
                    candidates.append(resp.body.decode("latin1", "replace").strip())
            except OSError:
                pass
        candidates.append(self._container_read())
        for text in candidates:
            if not text:
                continue
            if not self.match or self.match.decode("latin1") in text:
                return text
        return ""
