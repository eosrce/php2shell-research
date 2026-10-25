# PHP 8.2.35 FPM 4-worker patch gate (pin mode)

Lab-only research note, curated from `docs/115`. Authorized lab targets only;
see `ACCEPTABLE_USE.md` and `SECURITY.md`. This extends the 8.2.35 1-worker
gate (`docs/research/fpm-8235-gate.md`) to `WORKERS=4`; it is a **gate**, not
a proof.

## Result

- 8.2.35 gate container (`p2s-gate8235-4w`, 19148; image
  `p2s-phpfpm-lab:8.2.35-gate` = `sha256:ac855a04...f2e7e7`):
  **3/3 `PATCH GATE: closed`, exit 0** (single round 98.9 s; matrix runs
  98.2 / 98.4 s): grow SP = 7,048,390 B; prime 500/0 B (`fatal=inferred`);
  markers=3 / free=1; **BG all 0**; SR **456 -> 361 -> 698** (i0=0, a5=1/2);
  R2a/R2a(K2)/R3 = 200; `x.php` MISSING; `?0=id` = `File not found.`;
  health 200; sleepers_alive 3/3;
- 8.2.34 4w positive control (`p2s-gate8234-4w`, 19149; image
  `p2s-phpfpm-lab:8.2.34` = `sha256:386870e3...b3196d`): **`PATCH GATE: OPEN
  (expected on vulnerable)`, exit 3** (98.1 s): SR 47/70 (i0=1/2),
  `x.php` 392 B, `uid=33`, one child `level=1` (= the free child);
- `NO_PIN=1` on the same 8.2.35 container: closed with the same
  456 -> 361 -> 698 signature (88.1 s) - the closed signature is not
  4w-specific, no re-baseline needed;
- matrix `fpm-8235-gate-4w` (`kind=gate`): **3 runs PASS, 98.2 / 98.4 s**;
  gate cases are not proofs, A/B stays **87.55 / 85.05**; counts
  **63 = 51 proof + 2 refuse + 6 gap + 4 gate, 23/63 `oracle=http`**.

## Environment

| Item | Value |
|---|---|
| Gate container | `p2s-gate8235-4w`, host port **19148** |
| Control container | `p2s-gate8234-4w`, host port **19149** |
| Gate image | `p2s-phpfpm-lab:8.2.35-gate` = `sha256:ac855a04da4f541209e9a57ab4213ebce0931e01f46be5dcbdea933d9ff2e7e7` |
| Control image | `p2s-phpfpm-lab:8.2.34` = `sha256:386870e346a6e9b4ce195b6a78a435de430b238535679ef3f802e74179b3196d` |
| Pool | `www-4.conf`: `pm=static`, `pm.max_children=4`, `request_terminate_timeout=120s`, `catch_workers_output=yes` |
| Mounts | `www-4.conf` + cleanup=Off ini + `zz-r40-lab.ini`; web context `memory_limit=128M`, `upload_progress.enabled=On`, `cleanup=Off` |
| gdb | `--cap-add SYS_PTRACE`; one-shot BG read (8.2 level `+0x358`, 8.5 `+0x370`; both parsed); gate expects all 0, control exactly one `level=1` |
| Scheduling | `_sleep.php` (3 sleepers, marker = child pid, free = 1); exclusive container |

## Runner extension (v2)

- the same `labs/fpm/r41_patch_gate4w.sh` now selects the branch by `PROFILE`:
  `8512`/`8511` (8.5) and `8235`/`8234` (8.2). Script sha256
  `2f3e062d...` (v1 `dcbbffff...` covered only 8.5; adding 8.2 did not change
  the 8.5 sanity: 8512 closed 374/724, 8511 OPEN 47/70 + `x.php` + `uid`);
- 8.2 constants: `S=0x84000`, `AIM=-94200`, `AIM_W=-100289`,
  `SP=7,048,390`, `NL=8`;
- preflight before any verdict: PHP version prefix must match the profile
  (`8.2.35*`/`8.2.34*`, `8.5.12*`/`8.5.11*`), `EXPECT_IMAGE` pins the image
  ID, and the web-context ini must show `cleanup=Off` / `enabled=On` /
  `memory_limit=128M`; unknown `PROFILE`, wrong image or version mismatch is
  `ERROR`/exit 2;
- closed assertions are measured, not hardcoded: `SR != 47/70`, no `|i:0;`,
  no `x.php`/`uid`; only exploit signals produce `OPEN`.

## Signed evidence (single round)

| Group | Key values |
|---|---|
| 8.2.35 4w gate | closed exit 0 (98.9 s); grow 7,048,390; prime 500/0 B inferred; SR 456/361/698; BG all 0; no `x.php`/`uid`; health 200 |
| 8.2.34 4w control | OPEN expected exit 3 (98.1 s); SR 47/70; `x.php` 392 B; `uid=33`; BG one `level=1` at free child |
| NO_PIN (same 8.2.35 container) | closed (88.1 s); same 456/361/698; not 4w-specific |

## Matrix

| Run | Result | Time |
|---|---|---|
| 1 | PASS | 98.2 s |
| 2 | PASS | 98.4 s |
| 3 | PASS | (third PASS) |

Case shape: `--only fpm-8235-gate-4w`, `runner=fpm8512gate`, `oracle=gdb`,
`extra=[--profile 8235, --workers 4, --script r41_patch_gate4w.sh,
--expect-image sha256:ac855a04...]`; PASS only with exit 0 +
`PATCH GATE: closed` + image-ID pin.

## Gate family

`8.5.12 1w` / `8.5.12 4w` / `8.2.35 1w` / `8.2.35 4w` are four instances of
the same fail-closed gate family (identical token/exit semantics). A gate
says "this chain does not work here", not "the build is safe":
CVE-2026-115560 is tested separately and stays out of the matrix.

## Limitations

- 4w pinning is a lab scheduling precondition and **needs an exclusive
  container**: `www-4.conf` (`pm=static`, 4 children, 120 s), the cleanup=Off
  ini + `zz-r40-lab.ini`, and `_sleep.php` (3 sleeper markers, 1 free child);
  non-exploit primitive;
- BG is a **one-shot** gdb read; unavailable reads are `[UNVERIFIED]`, never 0;
- `log_errors=Off`: the prime fatal is recorded as **`fatal=inferred`** from
  500/0 B + SP truncation (there is no fatal text in the logs);
- every round restarts the container (~98 s; 3/3 ~5 min);
- **no literal `pm=static 1` container** was used; `NO_PIN=1` on the same
  container excludes the 4w-specific explanation;
- gate closed does not cover CVE-2026-115560 or other vulnerabilities.

## Reproduction

```bash
# 8.2.35 4w gate (expect closed, exit 0)
PROFILE=8235 WORKERS=4 CAL=p2s-gate8235-4w PORT=19148 RUNS=3 \
  EXPECT_IMAGE=sha256:ac855a04da4f541209e9a57ab4213ebce0931e01f46be5dcbdea933d9ff2e7e7 \
  bash labs/fpm/r41_patch_gate4w.sh
# 8.2.34 4w positive control (expect OPEN (expected on vulnerable), exit 3)
PROFILE=8234 WORKERS=4 CAL=p2s-gate8234-4w PORT=19149 RUNS=3 \
  bash labs/fpm/r41_patch_gate4w.sh
# same-container no-pin control (closed, 456/361/698)
PROFILE=8235 WORKERS=4 NO_PIN=1 CAL=p2s-gate8235-4w PORT=19148 RUNS=1 \
  bash labs/fpm/r41_patch_gate4w.sh
python3 code/tools/verify_matrix.py --only fpm-8235-gate-4w
```

See `docs/reproducibility.md` for the general lab/oracle rules.

## Licensing

MIT for the original code in this repository (see `LICENSE`); lab-only use.
All code in this tree is original self-implemented p2s work (MIT).
