# PHP 8.5.12 FPM 4-worker patch gate (pin mode)

Lab-only research note, curated from `docs/114`. Authorized lab targets only;
see `ACCEPTABLE_USE.md` and `SECURITY.md`. This gate replays the 8.5.11 ->
8.5.12 chain in `WORKERS=4` pin mode; it is a **gate**, not a proof.

## Result

- 8.5.12 gate container (`p2s-gate8512-4w`, 19143): **3/3
  `PATCH GATE: closed`, exit 0** (~94.9 s per run; one round 94 s);
- signature equals the 1-worker gate: grow SP = 7,050,470 B; prime = 500/0 B
  (`fatal=inferred`); R1 SR = 469 B; R2a 200/SR = 374 B and R2a(K2) 200/
  SR = 724 B (no `|i:0;`); R3 200 with no `x.php`; `?0=id` = `File not found.`;
  all children `BG level=0`; health 200;
- 8.5.11 4w positive control (`p2s-gate8511-4w`, 19144): **`PATCH GATE: OPEN
  (expected on vulnerable)`, exit 3** - SR 47/70 with `|i:0;|`, `x.php` 392 B,
  `?0=id` = `uid=33`, exactly one child `level=1` (= the free child);
- `NO_PIN=1` on the same 8.5.12 container: closed with the same 374/724
  signature and all-zero BG (free child 12 vs 11 across runs) - 374/724 are
  body/mode signatures, not 4w-specific;
- matrix `fpm-8512-gate-4w` (`kind=gate`, `oracle=http`): **3 runs PASS,
  94.9 s each**; gate cases are not proofs, A/B stays **87.55 / 85.05**;
  counts **62 = 51 proof + 2 refuse + 6 gap + 3 gate, 23/62 `oracle=http`**.
- **Runner v2**: `labs/fpm/r41_patch_gate4w.sh` sha256
  `2f3e062dbdecd4ab08edff4a50dd5aafc20d8b9a10e43bdf2827363feced06e7`; the
  same script now also selects the 8.2 branch (`PROFILE=8235|8234`, see
  `docs/research/fpm-8235-gate-4w.md`) and keeps the 8.5 gate/control
  signatures unchanged from the v1 `dcbbffff...` runs.

## Environment

| Item | Value |
|---|---|
| Gate container | `p2s-gate8512-4w`, host port **19143** |
| Control container | `p2s-gate8511-4w`, host port **19144** |
| Gate image | `p2s-phpfpm-lab:8.5.12-gate` = `sha256:d06afa5c9a553374d2190e06b02441285c6177586e496777530e239abaf4188c` |
| Control image | `p2s-phpfpm-lab:8.5.11` = `sha256:502117d6add844e973032a36b8db48784b54acb6580f0d59fc9f5f50f9ee918b` |
| Pool | `www-4.conf`: `pm=static`, `pm.max_children=4`, `request_terminate_timeout=120s`, `catch_workers_output=yes` |
| Mounts | `www-4.conf` + `php-128m.ini` + `zz-r40-lab.ini` (cleanup=Off; the 8.5.12 gate image also ships `zz-p2s.ini` cleanup=Off) |
| gdb | `--cap-add SYS_PTRACE`; one-shot BG read (8.5 offsets `+0x368`/`+0x370`, dual parse); gate expects all levels 0, control exactly one `level=1` |
| Web context | `memory_limit=128M`, `upload_progress.enabled=On`, `cleanup=Off`, `save_path=/var/lib/php/sessions` |
| Scheduling | `_sleep.php` (3 sleepers, marker = child pid, free = 1); exclusive container |
| Ports | 19143/19144 are dedicated to this experiment (19131 is the 1w gate) |

## First run was a false positive (instrument bug)

The first draft reported `PATCH GATE: OPEN (REGRESSION)`; it was a script bug,
not a regression:

- the draft called `mkbody r2a` and then `mkbody r3` into the **same**
  `$W/stagebody`; all three "stages" therefore sent the R3 body (writer aim,
  key K3) and the real R2a body was never sent. The arithmetic matches:
  `sr2a = 819 = 374 (R1 record) + 445 (K3 stage record)` and
  `sr2ak2 = 1264 = 819 + 445 (K2 record from R1K2)`; the second "R3 body"
  reused key K3 and overwrote itself, so the size did not grow again;
- the classifier also hardcoded the 1w closed SR values 374/724, so
  `SR=819` failed the closed signature and - with no exploit signal - fell
  into the OPEN branch;
- fix: per-stage body files with a mode/key sidecar and a `BODY ... sha256`
  check before sending; **OPEN only from exploit signals** (`uid=33`,
  `x.php >= 300 B`, SR = 47, SR = 70); any non-exploit closed-signature
  mismatch is `ERROR/rebaseline` (exit 2) and can never be OPEN;
- lesson: never hardcode a previous calibre's SR values in a closed
  assertion; unknown signatures are instrument errors, not verdicts.

## Corrected round (key stdout lines)

| Segment | Measured |
|---|---|
| pin | markers=3, free=1, children=4; `PINCHECK` all levels 0 (gate) / one level=1 at free (control) |
| grow/prime | SP = 7,050,470 B; prime 500/0 B, SP truncated (`fatal=inferred`, `log_errors` off) |
| gate | `sr1=469`, `sr2a=374 (i0=0,a5=1)`, `sr2ak2=724 (i0=0,a5=2)`, R2a/R2aK2/R3 = 200, `x.php=MISSING`, `RCE=[File not found.]`, `no_uid=1` |
| control | `SR=47 (i0=1,a5=0)` / `SR=70 (i0=2,a5=0)`, R2a/R2aK2 = 502, `x.php=392 B`, `uid=33` |
| duration | 94 s/round (1w gate reference 74.1 s); 3/3 ~5 min |

## Limitations

- 4w pinning is a lab scheduling precondition (`_sleep.php` + exclusive
  container + `pm=static` 4 + cleanup=Off ini + `request_terminate_timeout`);
  re-pin markers after container/image changes;
- BG is a one-shot gdb read; matrix runs may use `GDB_BG=0` and record
  `[UNVERIFIED]` - never treat an uncalibrated level as 0;
- `log_errors` is not set in this lab ini: the prime fatal is recorded as
  `fatal=inferred` from 500/0 B + SP truncation;
- every round restarts the container (~94 s; 3/3 ~5 min);
- no literal `pm=static 1` container was used - `NO_PIN=1` on the same
  container excludes the 4w-specific explanation (a literal 1w re-run would
  need a dedicated container);
- a gate says "this chain does not work here", not "the build is safe":
  CVE-2026-115560 (serialize-handler mismatch) is out of scope (docs/109 §8).

## Reproduction

```bash
# 8.5.12 4w gate (expect closed, exit 0)
PROFILE=8512 WORKERS=4 CAL=p2s-gate8512-4w PORT=19143 RUNS=3 \
  bash labs/fpm/r41_patch_gate4w.sh
# 8.5.11 4w positive control (expect OPEN (expected on vulnerable), exit 3)
PROFILE=8511 WORKERS=4 CAL=p2s-gate8511-4w PORT=19144 RUNS=3 \
  bash labs/fpm/r41_patch_gate4w.sh
# same-container no-pin control (closed, 374/724)
PROFILE=8512 WORKERS=4 NO_PIN=1 CAL=p2s-gate8512-4w PORT=19143 RUNS=1 \
  bash labs/fpm/r41_patch_gate4w.sh
python3 code/tools/verify_matrix.py --only fpm-8512-gate-4w
```

See `docs/reproducibility.md` for the general lab/oracle rules.

## Licensing

MIT for the original code in this repository (see `LICENSE`); lab-only use.
All code in this tree is original self-implemented p2s work (MIT).
