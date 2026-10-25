# PHP2Shell research snapshot (2026-10-29)

This is a curated public snapshot of the PHP2Shell research workspace. It
ships the FPM research tree plus the self-implemented `src/p2s/` mod_php
chain; all code in this tree is original p2s work (MIT).

## 2026-10-31 snapshot (v9)

Release-candidate notes for the 2026-10-31 milestone (on top of the
2026-10-29 snapshot below). Two pure-HTTP FPM proofs were added to the lab
matrix; both are lab-only and must quote their limitations.

| Proof | Result |
|---|---|
| `fpm-8511-http-1w` (PHP 8.5.11 / FPM / 128M / 1 worker) | **pure-HTTP, gdb-free full chain 3/3 `uid=33`**: in-run `ROUNDS=3` PASS=3/3 (every round `ASSERT OK`); `/srv/www/x.php` 392 B; `GET /x.php?0=id` = `upload_progress_uid=33(www-data)`; measured sampler `NO-GDB CHECK rounds=3 gdb_hits=0` (negative control hits=8); matrix 3 independent runs PASS 86.4 / 88.5 / 87.5 s. Case: `runner=fpm8511http`, `oracle=http`. |
| `fpm-8234-http-1w` (PHP 8.2.34 / FPM / 128M / 1 worker; real-CVE quadrant, pre-8.2.35) | **pure-HTTP, gdb-free full chain 3/3 `uid=33`** with `PROFILE=8234`: in-run `ROUNDS=3` PASS=3/3; `/srv/www/x.php` 392 B; sampler `gdb_hits=0`; matrix 3 independent runs PASS 101.4 / 92.4 / 104.9 s. Case: `runner=fpm8511http --profile 8234`, `oracle=http`. |

- Lab matrix: **57 cases = 49 proof + 2 refuse + 6 gap; 21/57 are
  `oracle=http`**.
- Scoring (docs/87 v42): **A 87.55 / B 85.05** (A = no-gdb only, B = research
  completeness including gdb calibration). The 8.2.34 case does not raise the
  score (single-case rule).
- Limitations that must be quoted with these proofs: lab prime diagnostic
  page `labs/fpm/www/_r41prime2.php`; `session.upload_progress.cleanup=Off`
  (8.5.11 via a conf.d override, 8.2.34 via `labs/fpm/php-128m-8234.ini`);
  `docker restart` and session/`x.php` cleanup between rounds; geometry
  constants are one-off gdb calibrated; carrier floor `F` is per shape/plane.
- Not claimed: stock `cleanup=On` targets, stock application pages, and
  version-independent generalization (8.2.35 / 8.4.27 / 8.5.12+ are fixed).
- New notes: `docs/research/fpm-8511-http.md`, `docs/research/fpm-8234-port.md`.

## 2026-10-31 snapshot (v10)

Release-candidate notes for the multi-worker (4w) milestone (on top of the
v9 snapshot above). The same pure-HTTP engine chains also run on
`pm=static` 4 workers under the lab pinning mode; the runner adds strict
per-round assertions (`ASSERT4`).

| Proof / gate | Result |
|---|---|
| `fpm-8234-http-4w` (PHP 8.2.34 / FPM / 128M / 4 workers; real-CVE quadrant, pre-8.2.35) | **4w pure-HTTP, gdb-free 3/3 `uid=33`**: `WORKERS=4` pinning (3x `_sleep.php` + free=1); in-run `ROUNDS=3` PASS=3/3 (248.3 s, ~83 s/round), measured sampler `gdb_hits=0`; `/srv/www/x.php` 392 B; matrix 3 independent strict runs PASS 103.4 / 168.2 / 138.7 s (VM load; judge = PASS + `ASSERT4`, not seconds). Case: `runner=fpm8511http --profile 8234 --workers 4`, `oracle=http`. |
| `fpm-8511-http-4w` (PHP 8.5.11 / FPM / 128M / 4 workers) | **4w pure-HTTP, gdb-free 3/3 `uid=33`**: in-run `ROUNDS=3` PASS=3/3 (301 s), `gdb_hits=0`; three independent `ROUNDS=1` runs PASS 123 / 110 / 122 s; matrix 3 runs PASS (98.9 / 121.8 s and a third PASS block). Key fix: BG level offset is version-specific (8.2 `+0x358` vs 8.5 `+0x370`) and is now parsed both ways with `level1_count==1`. Case: `runner=fpm8511http --profile 8511 --workers 4`, `oracle=http`. |
| `fpm-8235-gate` (PHP 8.2.35 / FPM / 128M / 1 worker; 8.2-branch fix; **kind=gate**, not proof) | **fail-closed `PATCH GATE: closed` 3/3, exit 0** (268.9 s); vulnerable positive control (8.2.34) 3/3 `OPEN (expected on vulnerable)` exit 3; unknown `PROFILE` exit 2. 8.2.35 still OOMs on prime (500/0 B + `7000064` fatal, child PID unchanged) but `BG level=0`; R2a 200/SR=361 B, R2a(K2) 200/SR=698 B, R3 200 with no `x.php`, `?0=id` = `File not found.` Case: `fpm-8235-gate`. |

- Lab matrix: **61 cases = 51 proof + 2 refuse + 6 gap + 2 gate; 23/61 are
  `oracle=http`**.
- Scoring: **A 87.55 / B 85.05 unchanged** (multi-worker pinning is a lab
  scheduling layer, not a new vulnerability primitive).
- Runner: `labs/fpm/r41_http_chain.sh` (`WORKERS=1|4`, `SLEEP_T`, `P4W_GDB`,
  `ASSERT4`, BG dual-offset parse); lab pages `_sleep.php` (scheduling
  precondition) and `_r41prime2.php`.
- Limitations that must be quoted: `_sleep.php` + an exclusive container +
  `pm=static`/4 children + `cleanup=Off` ini (8.5.11 needs the `zz-r40-lab.ini`
  conf.d override) + `request_terminate_timeout` > `SLEEP_T`; per-round
  `docker restart`; `P4W_GDB=1` is calibration only (the 3/3 runs are
  gdb-free); `log_errors=Off` makes the OOM fatal text unavailable
  (`fatal=inferred` from 500/0 B + SP truncation + calibrated BG=1 + SR
  oracle).
- Gate semantics: `fpm-8235-gate` (8.2.35) and `fpm-8512-gate` (8.5.12) are
  fail-closed checks of this chain (`closed` 0 / `OPEN` 3 / `ERROR` 2, never
  a pass on error). A gate is not a proof, and `closed` does **not** mean the
  build is fully safe - CVE-2026-115560 (serialize-handler mismatch) is
  counted separately and is out of scope of this matrix.
- Not claimed: new CVE primitive, multi-worker on patched builds (8.2.35 /
  8.5.12+), or stock `cleanup=On` targets.
- New notes: `docs/research/fpm-8234-4w.md`, `docs/research/fpm-8511-4w.md`,
  `docs/research/fpm-8235-gate.md`.

## 2026-10-31 snapshot (v11)

Release-candidate notes for the multi-worker patched gate and the 8.5.13
release-day preparation (on top of the v10 snapshot above).

| Gate / readiness | Result |
|---|---|
| `fpm-8512-gate-4w` (PHP 8.5.12 / FPM / 128M / 4 workers; **kind=gate**) | **fail-closed `PATCH GATE: closed` 3/3, exit 0** (~94.9 s/run) with `WORKERS=4` pinning (`_sleep.php`, markers=3/free=1). Signature equals the 1w gate: `sr1=469`, R2a 200/SR=374 B, R2a(K2) 200/SR=724 B, all `BG level=0`, no `x.php`/`uid`. The 8.5.11 4w positive control gives `OPEN (expected on vulnerable)` exit 3 (`SR` 47/70, `x.php` 392 B, `uid=33`, one `level=1`). `NO_PIN=1` on the same container gives the same closed signature, so 374/724 are body/mode signatures, not 4w-specific. |
| 8.5.13 readiness (not released) | Tag 404 / Releases 8.5.12 / docker-library max `8.5.12-fpm-trixie` on 2026-10-31; estimate ~2026-11-19 +/- (RC ~11-05) `[UNVERIFIED]`; apiki/wphost `php-8.5.13` is a trap (still 8.5.12). The `r41_patch_gate8513.sh` gate is prepared (DIAG mode, `BG_VERIFIED`/`ALLOW_BG_UNVERIFIED`, exact-version strictness, image/page digest pins, dedicated port 19145); release-day 24 h checklist in `docs/research/fpm-8513-readiness.md`. |

- **First-run false positive (instrument bug, not a regression)**: the draft
  gate shared one stage body across R2a/R2a(K2)/R3 and hardcoded the 1w SR
  values, so it printed `OPEN (REGRESSION)` while the target is closed. Fixed
  with per-stage body files + mode/key/sha checks; OPEN now requires an
  exploit signal, and unknown closed signatures are `ERROR/rebaseline`.
- Lab matrix: **62 cases = 51 proof + 2 refuse + 6 gap + 3 gate; 23/62 are
  `oracle=http`**.
- Scoring: **A 87.55 / B 85.05 unchanged** (gates and lab pinning never raise
  the score).
- Limitations that must be quoted: 4w pinning is a lab scheduling
  precondition (`_sleep.php` + exclusive container + `pm=static` 4 +
  cleanup=Off ini); BG is a one-shot gdb read (or `[UNVERIFIED]`); with
  `log_errors=Off` the prime fatal is `fatal=inferred`; every round restarts
  the container; 8.5.13 is not released yet; a gate is not a proof and
  `closed` does not mean the build is fully safe (CVE-2026-115560 is counted
  separately).
- New notes: `docs/research/fpm-8512-gate-4w.md`,
  `docs/research/fpm-8513-readiness.md`.

## 2026-10-31 snapshot (v12)

Release-candidate notes for the 8.2.35 4-worker gate, the upstream
fix-commit evidence and the CVE-2026-115560 release-level scope (on top of
v11).

| Gate / evidence | Result |
|---|---|
| `fpm-8235-gate-4w` (PHP 8.2.35 / FPM / 128M / 4 workers; **kind=gate**) | **fail-closed `PATCH GATE: closed` 3/3, exit 0** (98.9 s single round; matrix 98.2 / 98.4 s) with `PROFILE=8235 WORKERS=4` pinning: grow 7,048,390 B, prime 500/0 B (`fatal=inferred`), SR **456 -> 361 -> 698**, BG all 0, no `x.php`/`uid`, sleepers_alive 3/3. The 8.2.34 4w control gives `OPEN (expected on vulnerable)` exit 3 (SR 47/70, `x.php` 392 B, `uid=33`); `NO_PIN=1` on the same container gives the same closed signature. |
| Fix commits (CVE-2026-109618/109619) | Both release branches ship **one patch**: PHP 8.5.12 `31c0ea7d7f` (+ NEWS `3d37ab3b8e`, version `136e049ac1`) and PHP 8.2.35 `01a40e89fb` (+ `afd617c801`, `09a9f29a04`); the public replay `3584a98bda` has an identical fix diff and merges through 8.3/8.4/8.5. Mechanism: delayed OOM instead of bailout, `php_basic_early_rinit()` global reset before rfc1867, incomplete-class-only decode + fail-fast, rfc1867 OOM early stop + header filter, `$_SESSION` delete. `php_session_cancel_decode` is unchanged (GH-24493 remains open). |
| CVE-2026-115560 release-level scope | A variant: **3/3 RCE `uid=33`** on both 8.5.11 and 8.5.12-gate image digests; A2 (no runtime handler switch) NO_RCE; C2 (`php_admin_value[session.serialize_handler]=php`) NO_RCE; C3 (C2 + `enabled=Off`) NO_RCE. `php_admin_flag` cannot express the string handler lock. Still out of scope, not matrix-registered. |

- Lab matrix: **63 cases = 51 proof + 2 refuse + 6 gap + 4 gate; 23/63 are
  `oracle=http`**.
- Scoring: **A 87.55 / B 85.05 unchanged** (gates and app-composed scope do
  not raise the score).
- Limitations that must be quoted: 4w pinning is a lab scheduling
  precondition (exclusive container); image/version/ini preflight must be
  pinned (`EXPECT_IMAGE`); BG is a one-shot gdb read (or `[UNVERIFIED]`);
  `log_errors=Off` makes the prime fatal `fatal=inferred`; every round
  restarts the container; CVE-2026-115560 needs application conditions
  (handler switch + gadget) and is not covered by this matrix.
- New notes: `docs/research/fpm-8235-gate-4w.md`,
  `docs/research/fix-commits-2026-10-31.md`.

## 2026-10-31 snapshot (v13)

Release-candidate notes for the 8.3.36 4-worker gate, the E7 mechanism
verification and the 8.3.36 release/EOL facts (on top of v12).

| Gate / evidence | Result |
|---|---|
| `fpm-8336-gate-4w` (PHP 8.3.36 / FPM / 128M / 4 workers; **kind=gate**) | **fail-closed `PATCH GATE: closed` 3/3, exit 0** (78.4 s single round; three independent 78 s runs) with `PROFILE=8336 WORKERS=4` pinning: grow 7,048,390 B, prime 500/0 B (`fatal=inferred`), SR **456 -> 361 -> 698**, BG all 0 at the 8.3 level field `+0x360`, no `x.php`/`uid`, sleepers 3/3. The 8.3.35 4w control gives `OPEN (expected on vulnerable)` exit 3 (SR 47/70, `x.php` 392 B, `uid=33`, `+0x360=1` at the free child); `NO_PIN=1` on the same container gives the same closed signature. The runner now parses three BG offsets (8.2 `+0x358` / 8.3 `+0x360` / 8.5 `+0x370`). |
| E7 mechanism verification | Runtime (gdb) verification on the official stripped images: `php_basic_early_rinit`, `zend_handle_delayed_oom` and `php_var_unserialize_set_incomplete_classes_only` are **dynsym-exported only on patched** 8.5.12 and absent on 8.5.11. Natural run: patched clears BG inside the prime request (`destroy` 1 -> 0) and the next request is 0; vulnerable stale survives to the pre-RINIT window (`HASH level=1`). A controlled write proves `php_basic_early_rinit` itself clears BG (capability [CONFIRMED]; natural-path "early_rinit did it" [REFINED]; delayed-OOM causality [INFERRED]). |
| 8.3.36 release / EOL | **Pure security release**: fix `3c832b523e` (committer 2026-10-18T17:23:18Z) + NEWS `d59a20c8f9` + version `5ba6ad5192` (tag `php-8.3.36` object `7ed5ca1a...`); ChangeLog has only this entry. **EOL corrections**: PHP 8.3 active support ended 2025-12-31, security fixes until 2027-12-31; PHP 8.2 EOL 2026-12-31; 8.4 until 2028-12-31; 8.5 until 2029-12-31. |

- Lab matrix: **64 cases = 51 proof + 2 refuse + 6 gap + 5 gate; 23/64 are
  `oracle=http`**.
- Scoring: **A 87.55 / B 85.05 unchanged** (gates never raise the score).
- Limitations: same 4w lab preconditions as v12 (exclusive container,
  `_sleep.php`, image/version/ini preflight, one-shot BG read, per-round
  restart, `fatal=inferred`); **AGENTS #31 correction**: in this 4w shape both
  8.3.35 and 8.3.36 primes are 500/0 B with **no `exit 70`** - the old
  upload-progress false-positive note applies only to the older shape.
- New notes: `docs/research/fpm-8336-gate-4w.md`,
  `docs/research/e7-mechanism-verification.md`.

## 2026-10-31 snapshot (v14)

Release-candidate notes for the E7 static/timing CONFIRMED evidence, the
8.4.27 gate PoC ([BLOCKED] control) and the 8.5.13 release-day tooling
(on top of v13).

| Evidence | Result |
|---|---|
| 8.4.27 4-worker gate PoC (**not registered**) | 8.4.27 4w `p2s-gate8427-4w`/19154: **`PATCH GATE: closed`, exit 0** (grow 7,050,470 B, SR **469 -> 374 -> 724**, BG all 0 at `+0x370`, no `x.php`/`uid`; `NO_PIN=1` same signature). But the 8.4.26 4w positive control returns **`ERROR`/rebaseline** (R2a 502, SR 469 -> 469 -> 914): the instrument uses 8.5-family constants and the 8.4.26 vulnerable geometry/aim differs. **[BLOCKED] positive control => gate not registered**; matrix count unchanged 64. |
| E7 static-function recovery & rfc1867 order | Static targets recovered by `nm -D` anchor -> `objdump` call targets -> runtime callback pointer: `php_session_initialize` `0x5c0140`/`0x5bb690`, `php_session_rfc1867_update` `0x5c1830`/`0x5bcd50`, `php_session_rfc1867_callback` `0x5c1a70`/`0x5bcfa0` (8.5.12/8.5.11). gdb: prime has no rfc1867 callback; consumer runs callback -> update -> initialize -> incomplete-only -> flush **before module RINIT**; fail-fast is triggered by the update's `PS(session_status)!=active` check, not by an initialize return value (**[REFINED]**). rfc1867 internal order is now **[CONFIRMED]**; 374/361 B alignment stays **[INFERRED]**. |
| 8.5.13 release-day tooling | `labs/fpm/r41_patch_gate8513.sh`, `labs/fpm/r46_build8513.sh` and the one-command `labs/fpm/r49_release_day_8513.sh` pipeline now ship in the snapshot (build -> DIAG -> closed 3/3 -> 8.5.11 4w positive control -> unknown `PROFILE` -> 115560 reminder; exact-version gate; `BG_VERIFIED`/`ALLOW_BG_UNVERIFIED`; port 19145). |
| 8.4.27 release facts | fix `506e87fa7d` (committer 2026-10-18T17:23:32Z) + NEWS `2f966f79f6` + version `500438163a`; **not** a pure security release; EOL active 2026-12-31 / security 2028-12-31. Its lab image has **two index digests** (release-day original vs current rebuild) - quote both. |

- Lab matrix: **64 cases = 51 proof + 2 refuse + 6 gap + 5 gate (unchanged);
  23/64 `oracle=http`**.
- Scoring: **A 87.55 / B 85.05 unchanged** (a closed-only PoC and tooling do
  not raise the score).
- Limitations: the 8.4 gate is a PoC with a blocked control (do not quote it as
  a verified gate); static/gdb experiments ran on clone containers and are
  mechanism evidence only; the 8.5.13 pipeline needs the released official
  image and exact-version gate before any verdict.
- New notes: `docs/research/fpm-8427-gate-4w-poc.md`; `e7-mechanism-verification.md`
  and `fpm-8513-readiness.md` were extended.

## 2026-10-31 snapshot (v15)

Release-candidate notes for the 8.4 gate registration, the E7
`cancel_decode` closure and the reverse-review corrections (on top of v14).

| Evidence | Result |
|---|---|
| 8.4.27 4-worker gate **registered** (`fpm-8427-gate-4w`) | Re-baselined the 8.4 prime plane on 8.4.26 (`d=chunk+0xFD000`, `E=d+0x1C000`, `DT=d+0x3000`) => progress=chunk+0x61000, aim=-93688, AIM_W=-99777, S=0x84000, SP=7,050,470, BG `+0x370`. **8.4.26 4w control 3/3 `OPEN (expected on vulnerable)`** (83/83/83 s; SR 47/70, x.php 392 B, uid=33) and **8.4.27 4w 3/3 `PATCH GATE: closed`** (86/85/83 s; grow 7,050,470, SR 469 -> 374 -> 724, BG 0, no x/uid, sleepers 3/3); `NO_PIN=1` same. Matrix 3x PASS 101/100/100 s => **65 = 51 proof + 2 refuse + 6 gap + 6 gate; 23/65 `oracle=http`**. Failed candidates (8.5 constants => ERROR, 8.2 constants => closed-like) are recorded as evidence that the positive control is not optional. |
| E7 `php_session_cancel_decode` **[CONFIRMED]** | Static addresses 8.5.12 **0x21d673** / 8.5.11 **0x21d68e** (not inlined); fail-fast stack `cancel_decode <- php_session_decode <- php_session_initialize <- php_session_rfc1867_update <- callback <- rfc1867_post_handler`; `cancel_decode -> php_session_destroy -> php_session_track_init -> zend_delete_global_variable("_SESSION")`; the vulnerable image calls it too (same stack) but still forces `status=active` and flushes => the fix point is the update's status early-exit (**[REFINED]**). rfc1867 timing/order is now **[CONFIRMED]**; only the 374/361 B alignment stays **[INFERRED]**. |
| 8.4.27 release facts (web-r50) | ChangeLog is broad: Core 10 + many extensions (Session 2 entries are `create_sid` fixes, not 109618/619/115560); digests 10-21 `e2d8e787...` -> 10-23 `af172814...` -> 10-28 current `f3397667...`/amd64 `031bc09d...`; CISA KEV has no 10-31 update (catalog 2026.10.30; 115560 not listed). |
| MANIFEST verification (reverse-r51 correction) | MANIFEST sha256 values are **committed Git blobs (LF)**; a fresh clone reproduces them. The reported v14 mismatch was a CRLF worktree artifact - restore with `git checkout -- .` (or hash `git cat-file blob`) before comparing on Windows. |

- Lab matrix: **65 cases = 51 proof + 2 refuse + 6 gap + 6 gate; 23/65
  `oracle=http`**.
- Scoring: **A 87.55 / B 85.05 unchanged** (a gate is not proof).
- Limitations: 4w pinning/exclusive container are lab preconditions; BG is
  one-shot; the 8.4 constants are this build/shape only; gate registration does
  not raise A/B.

## 2026-10-31 snapshot (v16)

Release-candidate notes for the cross-branch gate smoke, the gate fail-closed
hardening, the E7 numeric alignment and the web-r51 corrections (on top of
v15; matrix count unchanged at 65).

| Evidence | Result |
|---|---|
| Cross-branch gate family smoke | **6/6 registered gate cases PASS** (`fpm-8512-gate`, `fpm-8512-gate-4w`, `fpm-8235-gate`, `fpm-8235-gate-4w`, `fpm-8336-gate-4w`, `fpm-8427-gate-4w`; runner 69.8-112.2 s) and **4/4 same-branch controls `OPEN (expected on vulnerable)`** (SR 47/70, `x.php` 392 B, `uid=33`; BG `+0x358`/`+0x360`/`+0x370=1`). This is a **1-run smoke, not a 3/3 re-validation**. Details: `docs/research/gate-family-crossbranch-2026-10-31.md` (evidence txt in `labs/fpm/evidence/`). |
| gate4w fail-closed hardening | script sha256 `4a94d199...3ec66bf`: a PASS now requires BG verified (`GDB_BG=0` -> exit 2 `ERROR (BG unverified)` unless `ALLOW_BG_UNVERIFIED=1`), `sleepers_alive=3/3` (NO_PIN comparison-only), and the pinned `EXPECT_PAGE_SHA256`; negative controls `GDB_BG=0` -> exit 2 and `SLEEP_T=1` -> exit 2. After hardening the four registered 4w cases re-ran **4/4 PASS** (96.1/94.9/94.5/94.4 s). `AIM_W` is documented as `AIM + (array_push - writer)/8` (value unchanged). |
| E7 numeric alignment | 374 B = prefix 43 + `a:5:{` 5 + start_time 31 + content_length 31 + bytes_processed 32 + done 15 + files 216 + `}` 1; 361 B = 374 - 13 (`tmp_name` 27 -> 14); 47 B = prefix 43 + `i:0;` 4. gdb normal R2a path has no CANCEL/DESTROY, so **374/361 are normal `a:5` progress records**; the old fail-fast/`_SESSION`-delete attribution is **[REFINED]** (fail-fast is malformed-only). Only the `i:0;` mechanism remains `[INFERRED]`. |
| web-r51 corrections | issue #24493 / PR #24677 are **not** the 115560 tracker (they are the 8.5.12 `__PHP_Incomplete_*` session-data-loss regression); 115560 is promised for the next regular release, has no public fix/tracking issue, and is not in KEV (catalog 2026.10.30); `3584a98bda` is an ancestor of all four public branches (`behind_by=0`); 8.2 security ends 2026-12-31. |
| Generic release-day pipeline | `labs/fpm/r50_release_day_any.sh` (v2, fail-closed): FAMILY 82\|83\|84\|85 signature table, exact-version base/lab check, `RUNS>=3`, control pinned by `CONTROL_EXPECT_IMAGE` (SR 47/70, x.php 392 B, uid=33), unknown PROFILE exit 2; negative checks (`RUNS=1` FAIL, bad FAMILY FAIL, unpublished 8.3.37 pull FAIL) pass. |

- Lab matrix: **65 cases = 51 proof + 2 refuse + 6 gap + 6 gate (unchanged);
  23/65 `oracle=http`**.
- Scoring: **A 87.55 / B 85.05 unchanged** (a smoke/hardening pass is not proof).
- Limitations: the cross-branch smoke is 1-run per case; the 8.4 family is a
  single image/shape calibration; hardening changes gate error semantics
  (stricter), not the gate predicate.

## 2026-10-31 snapshot (v17)

Full 3x cross-branch re-validation, selector fix and public-data refresh (on
top of v16; matrix count unchanged at 65).

| Evidence | Result |
|---|---|
| Cross-branch **full 3x** | **6 gates x3 = 18/18 PASS** (attempts=1; 8512 90/91/92 s, 8235 95/96/91 s, 8512-4w 133/129/134 s, 8235-4w 139/108/104 s, 8336-4w 103/104/102 s, 8427-4w 102/103/102 s) and **4 controls x3 = 12/12 OPEN (expected on vulnerable)** (SR 47/70, `x.php` 392 B, uid=33, sleepers 3/3, `level=1` at each family BG offset). The v16 1-run smoke is kept as history and marked superseded. |
| Selector trap and fix | `--only` is now **exact** (a prefix no longer selects `-4w` siblings); `--only-substr` is the legacy substring mode; an unknown name returns **rc=2** and prints substring hints. CLI tests **4/4**, project pytest **70 passed**. Root cause: two matrix runs raced on the shared 4w container (`PRIME1 FAIL code=000`). The matrix wrapper `fpm8512_gate_case.py` now defaults to `--gdb-bg 1`, so a caller's `GDB_BG=0` is not inherited. |
| zendkit / public data (note) | zendkit registers M25-M29 and passes **100 tests** (note only, no matrix effect). Public data 2026-10-31: latest releases still 8.5.12/8.4.27/8.3.36/8.2.35 (2026-10-21); 8.5.13/8.4.28 NEWS are placeholders (unpublished); 109618/619 entered CISA KEV on 2026-10-26; 115560 published 2026-10-23 (CVSS 8.1; no patch, next regular release), so the 8.5.13 release-day gate still cannot run. |

- Lab matrix: **65 = 51 proof + 2 refuse + 6 gap + 6 gate (unchanged);
  23/65 `oracle=http`**; A/B **87.55 / 85.05 unchanged**.
- Limitations: the 3x run re-validates the registered gate cases, it is not new
  proof; zendkit/public-data notes do not change the matrix.

## Included

- `src/p2s/` — self-implemented MIT mod_php chain: `transport`, `multipart`,
  `leaks`, `warning` (stage1/2/3 + candidate/attempt/rotate), `pure128`,
  `geometry`, `proof`, `workers`, `cms`, `cli`. No third-party code.
  `p2s.cli --check` refuses patched builds with exit 3
  (mirrors the lab-only `exploit.py`); `--force` is only for negative-control
  labs.
- `src/tools/fpm_chain.py` — 128M FPM chain (deterministic; 1w/4w/official).
- `src/tools/fpm_reclaim.py` — 8M FPM reclaim chain (debug/official, 1w/4w).
- `src/tools/fpm_leak.py` — 8M HTTP-only chunk/PIE leak (debug/official).
- `src/tools/fpm_cal_driver.py`, `collect_build.py`, `geo_cal.py`,
  `zend_gdb.py` — calibration and instrumentation (lab-only helpers that need
  the main workspace fail loudly instead of importing it silently).
- `src/profiles.py`, `src/cms_profiles.py`, `src/builds/index.json` — profiles,
  CMS presets, build fingerprints.
- `labs/fpm/`, `labs/fpm/reclaim/`, `labs/apache/` — lab configs and pages.
- `docs/research/` — mechanism, geometry, claims, methods, patch, CMS, T2/T3.
- `docs/ROADMAP.md` — full ASCII map (2026-10-26 FPM snapshot plus the
  2026-10-29 "What changed" section), `docs/RELEASE-NOTES.md`, `docs/INDEX.md`.
- `tests/` + CI — layout/smoke/license-boundary only; no target traffic.

## Proofs recorded (main research log, not re-run from this snapshot)

| Proof | Result |
|---|---|
| Lab regression matrix (2026-10-29) | **54 cases = 46 proof + 2 refuse + 6 gap; 18 are `oracle=http` (no gdb)**; two WP 8.4.15 de=On pure-HTTP full chains 3/3 `uid=33` (lab variant: `html_errors=On`): `cms-wordpress-on2-p2s` (HTTP helper page) and helper-free `cms-wordpress-on2-p2s-noh` (stage1-A + forged len=0x2000000 SIGSEGV recycle; 12/12 rounds) |
| Clean-room `p2s` warning chain, 8.4.26 | 8M 1w/4w, 16M/32M (3/3 incl. restart), 64M/128M/256M → `uid=33` |
| Clean-room `p2s` pure128, de=Off/128M | 1/5/150 workers 3/3 → `uid=33` |
| Clean-room `p2s` CMS (MediaWiki 1.43.9 / PHP 8.3.35 / 128M / post 8M) | 3/3 `uid=33` incl. container restart (`cms-mediawiki-p2s`, `oracle=http`; chunked 132MiB A + neutral `/_p2s_ip.php`) |
| Symfony pure-HTTP chain (128M FPM) | 3/3 `uid=33` (`symfony-http-1w`, `oracle=http`; restart-armed per stage) |
| mod_php 8.4.26 8M–256M (main chain) | 3/3 / 1/1 per configuration; 4w 3/3 |
| FPM 8.4.26 / 128M / 1w | 4/4 `uid=33` |
| FPM 8.4.26 / 128M / 4w | 4/4 `uid=33` |
| Official stripped 8.4.26-fpm / 128M | 1w 3/3 + 4w 1/1 |
| FPM 8.4.26 / 8M reclaim / debug / 1w | 3/3 `uid=33` |
| 8M HTTP-only leak + endgame (debug / official 1w / official 4w) | 3/3 each `uid=33` |
| FPM 8.3.35 consumer + HTTP-only chain (1w / 4w) | 3/3 each `uid=33` |
| Patched builds 8.4.27 / 8.5.12 | refused, exit 3 |

Application-chain research records (Laravel 13.17 native file session and T18b
pure-HTTP writer, Symfony native file session, WordPress+FPM reclaim) are
documented in the research log; the corresponding app labs are not part of this
curated snapshot.

## Not included

- The lab-only `exploit.py` and any third-party exploit/vector code. The
  mod_php warning/pure128 chain in `src/p2s/` is self-implemented.
- kengwang/cbovin/VABISMO/devploit code; the FPM implementations here are
  independent (see `NOTICE` and `docs/licensing.md`).
- Large binaries, container images, lab logs, internal status documents,
  one-off scripts and the main workspace history.

## Open research questions

1. 128M application HTTP-only chunk/PIE leak (T18 cross-chunk route).
2. WordPress pure-HTTP chain migration: the 128M post-OOM free area starts
   above the `E`/`DT` unserialize objects (anchor 0x6A018), so the current
   chunk-relative carriers cannot reach them (structural blocker; retest
   conditions in the main research log, F113/R16).
3. `pm = dynamic` layouts for the 8M chain.
4. T2 psv phase comparison / T3 second leak channel.
5. aarch64 builds.

## Licensing

MIT for original code; all code in this tree is original self-implemented p2s
work (MIT). See `NOTICE`, `LICENSE`, `ACCEPTABLE_USE.md` and `SECURITY.md`.
