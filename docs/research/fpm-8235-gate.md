# PHP 8.2.35 FPM patch gate (fail-closed)

Lab-only research note, curated from `docs/112` (8.2.35 gate report, 2026-10-31).
Authorized lab targets only; see `ACCEPTABLE_USE.md` and `SECURITY.md`. This is
a **gate**, not a proof: it shows that the same chunk-relative pure-HTTP chain
no longer consumes stale state on the patched 8.2-branch build.

## Result

`r41_patch_gate82.sh` runs the same HTTP-only steps as the 8.2.34 chain
(`r41_http_chain.sh`, `PROFILE=8234` constants reused as the attempted shape)
against the patched 8.2.35 build and emits a machine-readable verdict:

| Verdict | Exit | Meaning |
|---|---|---|
| `PATCH GATE: closed` | 0 | patched build; the chain is dead |
| `PATCH GATE: OPEN (REGRESSION)` | 3 | unexpectedly exploitable (failure) |
| `PATCH GATE: ERROR ...` | 2 | config/instrument error; never a gate pass |

- 8.2.35 gate `RUNS=3`: **3/3 `PATCH GATE: closed`, exit 0** (268.9 s total);
- 8.2.34 positive control (same gate logic, fresh 1-worker container):
  **3/3 `PATCH GATE: OPEN (expected on vulnerable)`, exit 3**
  (`RUNS=3` 255.5 s; a `RUNS=1` control also returned OPEN/exit 3);
- unknown `PROFILE=9999`: `PATCH GATE: ERROR unknown PROFILE=9999
  (use 8234|8235); exit 2`;
- matrix case `fpm-8235-gate` (`kind=gate`, not proof): **3 runs PASS**
  (63.8 / 64.1 s and a third PASS block; 1/1 each, `PATCH GATE: closed`);
  **61 = 51 proof + 2 refuse + 6 gap + 2 gate, 23/61 `oracle=http`**;
  A/B **87.55 / 85.05 unchanged** (gates never raise the score). The case
  wrapper picks this script for `PROFILE` 8235/8234 and the 8.5.12 script for
  8512/8511; token/exit semantics are identical.

**8.2.35 observed behavior** (DIAG + 3/3 identical): grow SP = 7,048,390 B;
prime = **500 / 0 B** with the real OOM fatal still present
(`Allowed memory size of 134217728 bytes exhausted (tried to allocate
7000064 bytes) in /srv/www/_r41prime2.php on line 7`), child PID unchanged;
R1 = 200 with SR = 456 B retained; but after prime
**`BG(unserialize)` level = 0, data = nil** (8.2.34: level = 1);
R2a = **200, SR = 361 B** (not 47 B, no `|i:0;`),
R2a(K2) = **200, SR = 698 B** (not 70 B); R3 = 200 but **no `x.php`**;
host `GET ?0=id` = `File not found.`; health = 200.
The fix does not remove the prime OOM; it removes the **consumability of the
stale state** - same shape as the 8.5.12 gate.

## Image and equal configuration

| Item | Value |
|---|---|
| Gate image | `p2s-phpfpm-lab:8.2.35-gate` = `sha256:ac855a04da4f541209e9a57ab4213ebce0931e01f46be5dcbdea933d9ff2e7e7` (PHP 8.2.35, built 2026-10-28) |
| BASE | `php:8.2.35-fpm` = `sha256:7f97976c601c9710547d7caa20726e59458826a34951d706803d4d6b10b3854b` |
| Gate container | `p2s-fpm8235-128` (id `dff34ca6...`), host port **19140** |
| Positive control | `p2s-gate8234-ctl` (id `bc3a68d6...`), host port **19141**, image `p2s-phpfpm-lab:8.2.34` `sha256:386870e346a6e9b4ce195b6a78a435de430b238535679ef3f802e74179b3196d` |
| Pool | `pm=static`, `pm.max_children=1`, `request_terminate_timeout=120s` (mounted `www-1.conf`) |
| ini | mounted `php-128m-8234-off.ini` copy (cleanup=Off); web context: `serialize_handler=php`, upload_progress enabled, `memory_limit=128M`, `post_max_size=8M` |
| Lab pages | `_r41prime2.php` (sha256 `ca83aff9...9e41829`; same bytes both sides); `_gateinfo.php` installed by the script |

Configuration parity was checked: all 21 `GATE INI_WEB` values equal the
8.2.34 control except `php_version`; page hashes equal on both sides.

## Comparison with the 8.5.12 gate

Both gates use the same wrapper token/exit semantics (`closed` 0, `OPEN
(expected on vulnerable)` 3, `ERROR` 2), the same classifier and no new
matrix runner code; they are two instances of one gate family.

| Dimension | 8.5.12 gate | 8.2.35 gate (this note) |
|---|---|---|
| Fix line | 8.5.12 (8.5 branch fix) | 8.2.35 (8.2 branch fix) |
| Container / port | `p2s-fpm8512-128` / 19131 | `p2s-fpm8235-128` / 19140 |
| Positive control | 8.5.11 / 19137 | 8.2.34 / `p2s-gate8234-ctl` / 19141 |
| grow SP | 7,050,470 B | 7,048,390 B |
| R1 SR | 469 B | 456 B |
| R2a / R2a(K2) SR | 374 B / 724 B | 361 B / 698 B |
| BG offsets | `+0x370`/`+0x368` | `+0x350`/`+0x358` |
| Script | `r41_patch_gate.sh` | `r41_patch_gate82.sh` |
| Verdict | closed (chain dead) | closed (same pattern) |

Both gates show the same lesson: the OOM prime still fires on the patched
build, but the stale state is not consumable, so the chain stops (R2a/R2a(K2)
are 200 with non-oracle SR bytes; no `x.php`, no `uid=33`). A gate says "this
chain does not work here", not "the build is safe": CVE-2026-115560
(serialize-handler mismatch) is counted separately and is out of scope of
this matrix.

## Limitations

- gate semantics only (fail-closed check of this chain); not a proof, not a
  full-security statement;
- `RECREATE=1` rebuilds the container from a pinned image and a mounted ini
  copy (no container-layer writes); VM-side paths (`WWW_CONF`, `IMAGE`,
  `EXPECT_IMAGE`, `EXPECT_PAGE_SHA256`, `WSH`) are lab defaults and
  overridable;
- `GDB_BG=1` reads BG once for the diag record; the verdict itself is
  token/exit based;
- unknown/typo profiles exit 2 by design (a typo must never look like a
  passing gate);
- gate results do not change A/B and are not registered as proof cases.

## Reproduction

```bash
# 8.2.35 gate (expect 3/3 closed, exit 0)
PROFILE=8235 CAL=p2s-fpm8235-128 PORT=19140 RUNS=3 \
  RECREATE=1 IMAGE=p2s-phpfpm-lab:8.2.35-gate \
  EXPECT_IMAGE=sha256:ac855a04da4f541209e9a57ab4213ebce0931e01f46be5dcbdea933d9ff2e7e7 \
  GDB_BG=1 bash labs/fpm/r41_patch_gate82.sh

# 8.2.34 positive control (expect OPEN, exit 3)
PROFILE=8234 CAL=p2s-gate8234-ctl PORT=19141 RUNS=1 \
  RECREATE=1 IMAGE=p2s-phpfpm-lab:8.2.34 \
  EXPECT_IMAGE=sha256:386870e346a6e9b4ce195b6a78a435de430b238535679ef3f802e74179b3196d \
  GDB_BG=1 bash labs/fpm/r41_patch_gate82.sh
```

See `docs/reproducibility.md` for the general lab/oracle rules.

## Licensing

MIT for the original code in this repository (see `LICENSE`); lab-only use.
All code in this tree is original self-implemented p2s work (MIT).
