# Gate family cross-branch regression (6 gates + 4 controls)

Lab-only research note, curated from `docs/122`. Authorized lab targets only;
see `ACCEPTABLE_USE.md` and `SECURITY.md`. The **full 3x re-validation** ran
after the gate4w hardening; the earlier 1-run smoke is kept as history and is
explicitly superseded.

## Full 3x re-validation

- **6 gate cases x3 = 18/18 PASS** (rc=0, `PATCH GATE: closed`, matrix PASS
  or direct 1w rc0, **attempts=1** - no retry);
- **4 same-branch controls x3 = 12/12 `OPEN (expected on vulnerable)`** (exit 3)
  with SR 47/70, `x.php` 392 B, `uid=33`, `sleepers_alive=3/3`, and
  `level=1` at the family BG offset on every run;
- gate script sha `4a94d199...` (hardening), matrix wrapper
  `fpm8512_gate_case.py` sha `d4b064fa...`.

### Gates (3 runs per case)

| Case | Run 1 | Run 2 | Run 3 | Mode |
|---|---:|---:|---:|---|
| `fpm-8512-gate` | 90 s | 91 s | 92 s | direct 1w |
| `fpm-8235-gate` | 95 s | 96 s | 91 s | direct 1w |
| `fpm-8512-gate-4w` | 133 s | 129 s | 134 s | matrix |
| `fpm-8235-gate-4w` | 139 s | 108 s | 104 s | matrix |
| `fpm-8336-gate-4w` | 103 s | 104 s | 102 s | matrix |
| `fpm-8427-gate-4w` | 102 s | 103 s | 102 s | matrix |

The 1w direct signature: 8512 `sr1=469 sr2a=374 sr2ak2=724 sp=7,050,470
xphp=MISSING bg_level=0 health=200`; 8235 `456/361/698 sp=7,048,390`, rest
same; token `PATCH GATE: closed` (`PROOF: patch gate closed`). The 4w matrix
CSV rows are `PASS,0`; their closed signatures are unchanged from the smoke
(the hardening only adds assertions, not chain changes).

### Controls (3 runs per case)

| Control | Run 1 | Run 2 | Run 3 | BG read |
|---|---:|---:|---:|---|
| `fpm-8511-4w` (8.5) | 133 s | 130 s | 131 s | `+0x370=1`@free |
| `fpm-8234-4w` (8.2) | 124 s | 126 s | 133 s | `+0x358=1`@free |
| `fpm-8335-4w` (8.3) | 134 s | 133 s | 131 s | `+0x360=1`@free |
| `fpm-8426-4w` (8.4) | 124 s | 127 s | 132 s | `+0x370=1`@free |

Every run: `sr2a=47 (i0=1)`, `sr2ak2=70 (i0=2)`, `x.php=392 B`, `uid=33`,
`sleepers_alive=3/3`, grow same as its gate family.

## Closed signatures / branch map

| Branch | Gate (4w) | Image pin | Closed SR | Control | Control image pin | BG level |
|---|---|---|---|---|---|---:|
| 8.5 | `fpm-8512-gate-4w` | `d06afa5c...` | 469 -> 374 -> 724 | `p2s-gate8511-4w` | `502117d6...` | `+0x370` |
| 8.2 | `fpm-8235-gate-4w` | `ac855a04...` | 456 -> 361 -> 698 | `p2s-gate8234-4w` | `386870e3...` | `+0x358` |
| 8.3 | `fpm-8336-gate-4w` | `b229bcfd...` | 456 -> 361 -> 698 | `p2s-gate8335-4w` | `e5a7b81f...` | `+0x360` |
| 8.4 | `fpm-8427-gate-4w` | `26ba8279...` | 469 -> 374 -> 724 | `p2s-gate8426-4w` | `6658d56c...` | `+0x370` |

1w gates (`fpm-8512-gate`, `fpm-8235-gate`) reuse the same family constants
and assertions. Grow SP: 7,050,470 (8.5/8.4) / 7,048,390 (8.2/8.3); prime
500/0 B; no `x.php`/`uid`; page sha `ca83aff9...`; 10/10 containers running;
no FAIL, no skip, no anomaly.

## 1-run smoke (historical, superseded)

The first pass ran one matrix case per gate and one run per control: 6/6 PASS
(runner 69.8-112.2 s) and 4/4 OPEN expected, with the same closed and control
signatures. It was a **smoke only**; the full 3x run above supersedes it and
is the evidence for cross-branch claims.

## Selector trap and fix

The first 3x script used `--only fpm-8512-gate`, which **substring-matched**
`fpm-8512-gate-4w` too, so two matrix runs raced on the shared 4w container
(`PRIME1 FAIL code=000`). The final run used direct 1w wrappers plus unique 4w
names. `verify_matrix.py` is now fixed:

- `--only` is **exact** (comma-separated case names; a prefix never selects
  siblings);
- `--only-substr` is the explicit legacy substring mode;
- an unknown name returns **rc=2** and prints the substring matches as a hint;
- CLI tests **4/4** (`code/tests/test_verify_matrix_cli.py`); project pytest
  **70 passed**.

## Caveats

- **8.4 caveat**: 8.4.27 shares the 8.5 closed signature, but the 8.4.26
  vulnerable plane is its own (`d=chunk+0xFD000`, `E=0x119000`, `DT=0x100000`,
  progress `0x61000`, aim `-93688`) and is measured on a **single image and
  shape**; the control must use `PROFILE=8426` with 8.4 constants.
- The 361/698 vs 374/724 difference is the `tmp_name` path length (14 vs 27
  bytes => 13 B; R2a(K2) differs by 26 B).
- Matrix count stays **65 = 51 proof + 2 refuse + 6 gap + 6 gate** (23/65
  `oracle=http`); A/B **87.55 / 85.05 unchanged** - a gate is not proof.
- Auxiliary: zendkit registers M25-M29 and passes **100 tests** (note only, no
  effect on the matrix).

## References

- `docs/research/fpm-8427-gate-4w-poc.md` (8.4 calibration/hardening);
- `docs/research/fpm-8512-gate-4w.md`, `fpm-8235-gate-4w.md`,
  `fpm-8336-gate-4w.md` (per-branch gate evidence);
- `docs/reproducibility.md` (runner/selector rules); `docs/122` (main log).

## Licensing

MIT for the original code in this repository (see `LICENSE`); lab-only use.
All code in this tree is original self-implemented p2s work (MIT).
