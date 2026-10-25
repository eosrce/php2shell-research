# PHP 8.3.36 FPM 4-worker patch gate (pin mode)

Lab-only research note, curated from `docs/117`. Authorized lab targets only;
see `ACCEPTABLE_USE.md` and `SECURITY.md`. This extends the 4-worker gate
pattern to PHP 8.3.36 (the 8.3-branch fix release); it is a **gate**, not a
proof.

## Result

- 8.3.36 gate (`p2s-gate8336-4w`, 19152; image
  `sha256:b229bcfd3c87cae8cf511b9ce8c6cfeefd38aead7d7771c5031c37f732b24965`):
  **3/3 `PATCH GATE: closed`, exit 0** (single round 78.4 s; three independent
  runs 78 / 78 / 78 s): grow SP = 7,048,390 B; prime 500/0 B
  (`fatal=inferred`); markers=3 / free=1; SR **456 -> 361 -> 698**
  (i0=0, a5=1/2); R2a/R2a(K2)/R3 = 200; no `x.php`/`uid`; health 200;
  sleepers_alive 3/3;
- **BG calibration** (`GDB_BG=1`, 3 rounds): `levels[358/360/370]` all 0,
  **level field = `+0x360`** for 8.3;
- 8.3.35 4w positive control (`p2s-gate8335-4w`, 19153; 8.3.35 image id
  `e5a7b81f...`): **`PATCH GATE: OPEN (expected on vulnerable)`, exit 3**
  (78.0 s): SR 47/70 (i0=1/2, `|i:0;`), `x.php` 392 B, `uid=33`;
  BG 3 rounds `+0x360=1` at the free child (`+0x358` = low 32 bits of the
  data pointer, `+0x370` = 0) => **8.3 BG level offset `+0x360` confirmed**;
- `NO_PIN=1` on the same container: closed, same 456 -> 361 -> 698
  (68.9 s) - not 4w-specific;
- matrix `fpm-8336-gate-4w` (`kind=gate`): **3 runs PASS (~78 s)**; gate cases
  are not proofs, A/B stays **87.55 / 85.05**; counts
  **64 = 51 proof + 2 refuse + 6 gap + 5 gate, 23/64 `oracle=http`**.

## Environment

| Item | Value |
|---|---|
| Gate / control | `p2s-gate8336-4w`/**19152** / `p2s-gate8335-4w`/**19153** |
| Image | `p2s-phpfpm-lab:8.3.36-gate` = `sha256:b229bcfd3c87cae8cf511b9ce8c6cfeefd38aead7d7771c5031c37f732b24965` |
| Base | `php:8.3.36-fpm` (index digest `699495096ad60a969b9265aa52808c722b72f5e393f3784b794b168cc095a9e6`, amd64 `aeed6dd8...`) |
| Version | PHP **8.3.36**; gdb + nginx ready; lab page sha `ca83aff9...` |
| Pool | `www-4.conf`: `pm=static`, 4 children, `request_terminate_timeout=120s` |
| Mounts | `php-128m.ini` + `zz-r40-lab.ini` (cleanup=Off, 128M) + `--cap-add SYS_PTRACE` |
| Scheduling | `_sleep.php` (3 sleepers, marker = child pid, free = 1); exclusive container |

## Runner v3

- `labs/fpm/r41_patch_gate4w.sh` selects the branch by `PROFILE`: `8512`/`8511`
  (8.5), `8235`/`8234` (8.2), **`8336`/`8335` (8.3)**; sha256 `db433c73...`
  (v2 `2f3e062d...`). Adding 8.3 left the 8.5/8.2 sanity unchanged (8512
  closed 374/724, 8511 OPEN 47/70 + `x.php` + `uid`; 8235 closed 456/361/698,
  8234 OPEN 47/70 + `x.php` + `uid`);
- 8.3 constants: `S=0x84000`, `AIM=-94200`, `AIM_W=-100289`,
  `SP=7,048,390`, `NL=8` (the 8.2 candidate set matched on the first round);
- **three-offset BG parse**: 8.2 `+0x358`, 8.3 `+0x360`, 8.5 `+0x370`; all
  read, any `==1` accepted with `level1_count==1`;
- preflight: version prefix / `EXPECT_IMAGE` image pin / web-context ini
  (`cleanup=Off`, `enabled=On`, 128M); unknown `PROFILE` or mismatch -> exit 2;
- closed assertions are measured: `SR != 47/70`, no `|i:0;`, no
  `x.php`/`uid`; only exploit signals produce `OPEN`.

## Signed evidence (single round)

| Group | Key values |
|---|---|
| 8.3.36 4w gate | closed exit 0 (78.4 s); grow 7,048,390; prime 500/0 B inferred; SR 456/361/698; BG all 0 (`+0x360`); no `x.php`/`uid` |
| 8.3.35 4w control | OPEN expected exit 3 (78.0 s); SR 47/70; `x.php` 392 B; `uid=33`; BG `+0x360=1` at free child |
| NO_PIN (same 8.3.36 container) | closed (68.9 s); same 456/361/698; not 4w-specific |

## Matrix and gate family

Three matrix runs PASS (~78 s each); case `--only fpm-8336-gate-4w`,
`runner=fpm8512gate`, `oracle=gdb`, `extra=[--profile 8336, --workers 4,
--script r41_patch_gate4w.sh, --expect-image sha256:b229bcfd...]`. The family
now has five instances (`8.5.12 1w/4w`, `8.2.35 1w/4w`, `8.3.36 4w`) with
identical token/exit semantics; a gate says "this chain does not work here",
not "the build is safe" (CVE-2026-115560 stays separate and out of matrix).

## AGENTS #31 correction

In this 4w lab shape both 8.3.35 and 8.3.36 primes end in **HTTP 500/0 B** -
there is **no `exit 70`**. The earlier "exit 70 / upload-progress false
positive" note (#31) applies only to the older container/shape and must not be
applied to this gate.

## Limitations

- 4w pinning is a lab scheduling precondition and **needs an exclusive
  container** (`www-4.conf` + cleanup=Off ini + `zz-r40-lab.ini` +
  `_sleep.php`); non-exploit primitive;
- BG is a **one-shot** gdb read; unavailable reads are `[UNVERIFIED]`, never 0;
- `log_errors=Off`: the prime fatal is recorded as **`fatal=inferred`** from
  500/0 B + SP truncation;
- every round restarts the container (~78 s); **no literal `pm=static 1`
  container** was used, so `NO_PIN=1` on the same container excludes the
  4w-specific explanation;
- gate closed does not cover CVE-2026-115560 or other vulnerabilities.

## Reproduction

```bash
# 8.3.36 4w gate (expect closed, exit 0)
PROFILE=8336 WORKERS=4 CAL=p2s-gate8336-4w PORT=19152 RUNS=3 \
  EXPECT_IMAGE=sha256:b229bcfd3c87cae8cf511b9ce8c6cfeefd38aead7d7771c5031c37f732b24965 \
  bash labs/fpm/r41_patch_gate4w.sh
# 8.3.35 4w positive control (expect OPEN (expected on vulnerable), exit 3)
PROFILE=8335 WORKERS=4 CAL=p2s-gate8335-4w PORT=19153 RUNS=3 \
  bash labs/fpm/r41_patch_gate4w.sh
python3 code/tools/verify_matrix.py --only fpm-8336-gate-4w
```

See `docs/reproducibility.md` for the general lab/oracle rules.

## Licensing

MIT for the original code in this repository (see `LICENSE`); lab-only use.
All code in this tree is original self-implemented p2s work (MIT).
