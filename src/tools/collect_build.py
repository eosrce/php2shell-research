#!/usr/bin/env python3
"""Collect one build entry from a local container into builds/index.json.

The key is the libphp.so fingerprint, not the PHP version: the same version
built for another distro or with other flags has different symbol offsets.
htdata is a heap constant and only meaningful for the recorded config, so pass
--htdata from a verified lab run (or let it inherit the same-version profile).

Authorized lab use only.
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)
import profiles as profile_table  # noqa: E402


def docker(container: str, command: str) -> str:
    p = subprocess.run(["docker", "exec", container, "sh", "-c", command],
                       capture_output=True, text=True)
    return p.stdout.strip() if p.returncode == 0 else ""


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--container", required=True)
    ap.add_argument("--id", default="", help="stable id, e.g. php-8.4.26-apache-debian13")
    ap.add_argument("--source", default="", help="image/package name")
    ap.add_argument("--sapi", default="",
                    help="SAPI label (default: apache2handler for libphp.so)")
    ap.add_argument("--htdata", type=lambda x: int(x, 0), default=None)
    ap.add_argument("--verified", action="store_true",
                    help="mark the entry usable by --profile auto")
    ap.add_argument("--notes", default="")
    ap.add_argument("--db", default=os.path.join(ROOT, "builds", "index.json"))
    args = ap.parse_args()

    version = docker(args.container, "php -r 'echo PHP_VERSION;'")
    arch = docker(args.container, "uname -m")
    distro = docker(args.container, ". /etc/os-release; echo \"$ID-$VERSION_ID\"")
    libphp = docker(args.container, "find / -name libphp.so 2>/dev/null | head -1")
    if not libphp:
        libphp = docker(args.container, "find / -name 'libphp*.so' 2>/dev/null | head -1")
    # `docker exec php -r` reports the CLI SAPI even for the Apache module;
    # a libphp.so build is apache2handler unless the caller says otherwise.
    sapi = args.sapi or ("apache2handler" if libphp.endswith("libphp.so")
                         else docker(args.container, "php -r 'echo PHP_SAPI;'"))
    if not version or not libphp:
        print("[collect] cannot identify PHP version or libphp.so", file=sys.stderr)
        return 2
    sha = docker(args.container, f"sha256sum {libphp} | cut -d' ' -f1")
    build_id = docker(
        args.container,
        f"readelf -n {libphp} 2>/dev/null | awk '/Build ID/ {{print $NF}}'")

    out = os.path.join(ROOT, "out", "collect-offsets.env")
    helper = os.path.join(ROOT, "docker", "offsets.py")
    subprocess.run([sys.executable, helper, args.container, out],
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    zif = dtor = None
    try:
        with open(out, "r", encoding="utf-8") as f:
            for line in f:
                k, _, v = line.strip().partition("=")
                if k == "ZIF_OFFSET":
                    zif = int(v, 0)
                elif k == "DTOR_OFFSET":
                    dtor = int(v, 0)
    finally:
        try:
            os.unlink(out)
        except OSError:
            pass
    if zif is None or dtor is None:
        print("[collect] offsets.py failed", file=sys.stderr)
        return 2

    if args.htdata is None:
        known = profile_table.exact(version)
        htdata = known.htdata_offset if known else 0x690D8
    else:
        htdata = args.htdata

    entry = {
        "id": args.id or f"php-{version}-{sapi}-{distro or 'unknown'}-{sha[:8]}",
        "php_version": version,
        "distro": distro,
        "arch": arch,
        "sapi": sapi,
        "libphp_sha256": sha,
        "build_id": build_id,
        "zif_offset": hex(zif),
        "dtor_offset": hex(dtor),
        "htdata_offset": hex(htdata),
        "in_band_leaks": True,
        "verified": bool(args.verified),
        "verified_on": "2026-10-22" if args.verified else "",
        "verified_config": {
            "memory_limit": "8M",
            "post_max_size": "64M",
            "display_errors": "On",
            "workers": 1,
            "session_name": "PHPSESSID",
        } if args.verified else {},
        "source": args.source or docker(
            args.container, "echo \"$HOSTNAME\""),
        "notes": args.notes,
    }

    try:
        with open(args.db, "r", encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, ValueError):
        data = {"schema": 1, "builds": []}
    builds = data.setdefault("builds", [])
    replaced = False
    for i, old in enumerate(builds):
        if (old.get("id") == entry["id"]
                or (entry["libphp_sha256"] and old.get("libphp_sha256") == entry["libphp_sha256"])):
            builds[i] = entry
            replaced = True
            break
    if not replaced:
        builds.append(entry)
    os.makedirs(os.path.dirname(args.db) or ".", exist_ok=True)
    with open(args.db, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
        f.write("\n")

    print(f"[collect] {'updated' if replaced else 'added'} {entry['id']}")
    print(f"  php={version} distro={distro} arch={arch} sapi={sapi}")
    print(f"  sha256={sha}")
    print(f"  build_id={build_id or '(none)'}")
    print(f"  zif={entry['zif_offset']} dtor={entry['dtor_offset']} "
          f"htdata={entry['htdata_offset']} verified={entry['verified']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
