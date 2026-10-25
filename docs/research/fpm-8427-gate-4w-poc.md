# PHP 8.4.27 FPM 4-worker patch gate (calibrated and registered)

Lab-only research note, curated from `docs/120`. Authorized lab targets only;
see `ACCEPTABLE_USE.md` and `SECURITY.md`. This note records the successful
8.4 calibration and the registration of the **sixth** gate case; the earlier
blocked attempt is kept in the v14 history / `docs/119`.

## Result

- **8.4.26 4w control: 3/3 `OPEN (expected on vulnerable)`, exit 3**
  (83/83/83 s): SR **47/70**, `x.php` 392 B, `?0=id` = `uid=33`; BG
  `+0x370=1` at the free child (data `chunk+0xFD000`);
- **8.4.27 4w gate: 3/3 `PATCH GATE: closed`, exit 0** (86/85/83 s):
  grow SP **7,050,470** B; prime 500/0 B (`fatal=inferred`); SR
  **469 -> 374 -> 724** (i0=0, a5=1/2); R2a/R2a(K2)/R3 = 200; no `x.php`/`uid`;
  sleepers_alive 3/3; BG 3 rounds all 0; `NO_PIN=1` gives the same signature
  (69 s);
- **registered** as matrix case `fpm-8427-gate-4w` (port 19154, image pin
  `sha256:26ba8279...97a99d`, `--profile 8427 --workers 4`):
  `--only` 3x PASS **101/100/100 s** => count
  **65 = 51 proof + 2 refuse + 6 gap + 6 gate**, 23/65 `oracle=http`;
  a gate is not proof and **A/B stays 87.55 / 85.05**.

## Environment

| Item | 8.4.27 gate | 8.4.26 control |
|---|---|---|
| Container | `p2s-gate8427-4w`/**19154** | `p2s-gate8426-4w`/**19155** |
| Image | `p2s-phpfpm-lab:8.4.27-gate` | `p2s-phpfpm-lab:8.4.26-gate` |
| Base | `php:8.4.27-fpm` | `php:8.4.26-fpm` |
| Image id | `sha256:26ba8279...7597a99d` | `sha256:6658d56c...662ca3` |
| Base index digest (current) | `f3397667...ed35eb`; amd64 `031bc09d...` | `f5431b57...` |
| Base index digest (release day) | `e2d8e787...`; amd64 `d8877866...` | - |
| Pool | `www-4.conf` (`pm=static`, 4 children, 120 s) | same |
| Mounts | `php-128m.ini` + `zz-r40-lab.ini` (cleanup=Off), `SYS_PTRACE` | same |
| Scheduling | `_sleep.php` (3 sleepers, marker=pid, free=1) | same |

## Calibration (the key step)

gdb on 8.4.26 (three rounds, same shape) measured a prime plane that differs
from 8.5 **and** 8.2:

```
d = chunk+0xFD000   E = d+0x1C000 = 0x119000   DT = d+0x3000 = 0x100000
```

(8.5.11 plane: `d=0x110000/E=0x12C000/DT=0x113000`; 8.2.34: `d=0xFE000/E=0x11A000`.)

`var_push` writes `E+0x10+8*used`; with the R2a target `progress+0x50`:

- **progress = chunk+0x61000**
- **aim = (0x61050 - 0x119010)/8 = -0x16DF8 = -93688**
- **AIM_W = AIM + (array_push - writer)/8 = -99777** (same value; `(0x62050 - 0x56208)/8 = -0x17C9`)
- **S = 0x84000** (`copy1 = d+0x1018`), **SP = 7,050,470**
- BG layout: data `+0x368`, level **`+0x370`** (8.4 family)

The `-93688` values are new: they are neither the 8.2 family (`-94200`) nor the
8.5 family (`-103416`).

## Failed candidates (why the positive control is not optional)

| Constants tried | 8.4.26 control result | Verdict |
|---|---|---|
| 8.5 family (`S=0x97000`, aim `-103416`) | R2a 502, SR 469 -> 469 -> 914, R3 502 | `ERROR`/rebaseline (exit 2) |
| 8.2 family (`S=0x84000`, aim `-94200`) | R2a 200/374, R2a(K2) 200/725, R3 200, no exploit | `CLOSED (unexpected on control)` (exit 2) |

Both are correctly fail-closed; a vulnerable build can look closed under a mismatched plane, so a closed-only result is **not** a usable gate - only the 8.4 plane separates patched from vulnerable.

## Registration

```python
Case("fpm-8427-gate-4w","gate",19154,"p2s-gate8427-4w",
     runner="fpm8512gate",oracle="gdb",
     extra=["--profile","8427","--workers","4","--script","r41_patch_gate4w.sh",
            "--expect-image",
            "sha256:26ba8279271ff18dc601401becf73b74551c03c0952cd56db0df04927597a99d"])
```

- runner `code/tools/verify_matrix.py` sha256 `d4422a06...bc2195e5`;
- gate script `labs/fpm/r41_patch_gate4w.sh` sha256 `4a94d199...3ec66bf` (hardening; the cross-branch smoke ran with the earlier `b4df6266...`);
- matrix `--only fpm-8427-gate-4w` 3x PASS 101/100/100 s => **count 65**,
  23/65 `oracle=http`; A/B unchanged.

## Hardening (round 11, reverse-review r52)

Gate script updated to sha256 `4a94d199...3ec66bf` (the 1w gate scripts are
unchanged). A gate PASS now requires the BG scan to be verified: `GDB_BG=0`
gives `ERROR (BG unverified)` exit 2 unless `ALLOW_BG_UNVERIFIED=1` (DIAG
only); it also requires the 3-sleeper pin alive (`sleepers_alive=3/3`;
`NO_PIN` is comparison-only) and the pinned lab page sha
(`EXPECT_PAGE_SHA256`). Negative controls: `GDB_BG=0` -> exit 2, `SLEEP_T=1`
-> exit 2. After hardening the four registered 4w cases re-ran **4/4 PASS**
(96.1/94.9/94.5/94.4 s) and the 8426 control still prints
`OPEN (expected on vulnerable)` exit 3.

One follow-up was needed for the matrix runner: `tools/fpm8512_gate_case.py`
used to inherit the caller's `GDB_BG` environment, so a shell exporting
`GDB_BG=0` made the now fail-closed gate exit 2. The wrapper now defaults to
`--gdb-bg 1` (and optionally forwards `--expect-page-sha256`), sha256
`d4b064fa...0becfd`; the gate assertions themselves were not relaxed. Matrix
re-run with the fixed wrapper: **4/4 PASS** (wall 399 s; 94.6/100.7/102.0/
101.4 s) and `fpm-8427-gate-4w` **3/3 PASS** (101.1/100.7/101.3 s).

## Limitations

- 4w pinning is a lab scheduling precondition (exclusive container, `_sleep.php`, cleanup=Off ini); non-exploit primitive;
- BG is one-shot (`[UNVERIFIED]` if unavailable, never 0); the 8.4 plane/constants are this build/shape only;
- `log_errors=Off`: prime fatal is `fatal=inferred` from 500/0 B + SP truncation; each round restarts the container (83-101 s);
- a gate only shows "this chain does not work here": it is **not** proof and must not raise A/B.

## Reproduction

```bash
# 8.4.27 gate (closed expected)
PROFILE=8427 WORKERS=4 CAL=p2s-gate8427-4w PORT=19154 RUNS=3 \
  EXPECT_IMAGE=sha256:26ba8279... bash labs/fpm/r41_patch_gate4w.sh
# 8.4.26 positive control (OPEN (expected on vulnerable), exit 3)
PROFILE=8426 WORKERS=4 CAL=p2s-gate8426-4w PORT=19155 RUNS=3 \
  EXPECT_IMAGE=sha256:6658d56c... bash labs/fpm/r41_patch_gate4w.sh
python3 code/tools/verify_matrix.py --only fpm-8427-gate-4w
```

## Licensing

MIT for the original code in this repository (see `LICENSE`); lab-only use.
All code in this tree is original self-implemented p2s work (MIT).
