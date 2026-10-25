# CVE-2026-109618/109619 upstream fix commits (2026-10-31)

Lab-only research note, curated from `docs/116` (public php-src commit review,
2026-10-31). Authorized lab use only; see `ACCEPTABLE_USE.md` and `SECURITY.md`.
This note records which upstream commits close the two CVEs and how they map
onto the gate observations, not a new exploit result.

## Result

Both release branches ship the **same single fix patch**, commit message
`"Avoid state corruption via bailout"`:

| Release | Fix commit (committer date) | NEWS | Version commit |
|---|---|---|---|
| PHP 8.5.12 | **`31c0ea7d7f`** (2026-10-18 17:23:46Z) | `3d37ab3b8e` | `136e049ac1` (2026-10-19 17:02:46Z) |
| PHP 8.2.35 | **`01a40e89fb`** (2026-10-18 17:22:38Z) | `afd617c801` | `09a9f29a04` (2026-10-19 07:29:52Z) |
| PHP 8.3.36 | **`3c832b523e`** (2026-10-18 17:23:18Z) | `d59a20c8f9` | `5ba6ad5192` |
| PHP 8.4.27 | **`506e87fa7d`** (2026-10-18 17:23:32Z) | `2f966f79f6` | `500438163a` |

All dates are **committer dates**. The patch was authored 2026-10-18T15:46:02Z; the public replay `3584a98bda` was committed 2026-10-21T14:06:22Z.

**8.3.36 is a pure security release**: its ChangeLog contains only this fix
(fix commit `3c832b523e`, NEWS `d59a20c8f9`, version commit `5ba6ad5192`;
tag `php-8.3.36` object `7ed5ca1a...`).

**8.4.27 is not a pure security release**: Core 10 entries plus many extensions (Session 2 entries are `create_sid` fixes, **not** 109618/619/115560); tag `aa58018e...` -> commit `00d8bae801`. Image digests: 10-21 `e2d8e787...`/amd64 `d8877866...` -> 10-23 `af172814...` -> 10-28 current `f3397667...`/amd64 `031bc09d...` (image id `sha256:26ba8279...`) - quote the release-day and current values. CISA KEV: no 10-31 update (catalog 2026.10.30; 109618/619 added 2026-10-26; 115560 not listed).

- **public replay** `3584a98bda` (committed 2026-10-21T14:06:22Z, on the PHP-8.2 branch): its fix `.diff` SHA256 is **identical** to `01a40e89fb` (`a09493b49f...`), then merged up `c1a5f468d0` (8.2->8.3) -> `8a94bb3822` (8.3->8.4) -> `c7273b9ba8` (8.4->8.5);
- the branches are the same patch modulo context (381/389 common files between the 8.2 and 8.5 diffs); this is why 8.2.35 and 8.5.12 behave identically at the gate [CONFIRMED];
- the patch does **not** touch `php_session_cancel_decode` (0 hits in the `.diff`); issue #24493 is a **separate 8.5.12 regression**, not the 115560 tracker (next section).

## BG-offset evidence layers (M25)

`M25` adds the 8.2 BG layout to zendkit (`_BG_UNSERIALIZE["8.2"] = 0x350`,
level at `+0x358`; 96 tests). The evidence is layered, not uniform:

| Target | Evidence | Status |
|---|---|---|
| 8.2.34 FPM | live `d` data + BG `level` read (prime/consumer) | [CONFIRMED] |
| 8.2.35 FPM | BG `level` only (gate one-shot read; no full live-data re-read) | [CONFIRMED] level; data [UNVERIFIED] |
| 8.2 mod_php / CLI | not live-verified in this round | [UNVERIFIED] |

Cross-SAPI use (mod_php, CLI, other SAPIs) must re-calibrate the offsets
instead of relying on the FPM values.

## Changed surface (8.5.12 fix `.diff`; 8.2.35 analogous)

| Area | Change |
|---|---|
| `Zend/zend_alloc.c` | **+527/-124**: OOM from longjmp/bailout to *delayed OOM* (fallible APIs, hard limit, `max_allocs`) |
| `main/main.c` | **+48/-2**: call `php_basic_early_rinit()` in `php_request_startup()` before request data; reset at shutdown |
| `main/rfc1867.c` | **+189/-27**: fallible realloc, `post_max_size` early stop, unknown/duplicate multipart header filter, OOM -> `fileupload_done`/`cancel_upload` |
| `ext/session/session.c` | **+58/-13**: `PS(in_rfc1867_update)`, `incomplete_classes_only`, `php_session_initialize() == FAILURE` fail-fast, delete `_SESSION` |
| `ext/standard/var_unserializer.re` | **+124/-15**: incomplete-class mode, keep raw `C:`/`E:` payload, reject reserved member names, fallible allocs |
| `ext/standard/var.c`, `zend_execute_API.c` | **+62** / **+37/-13**: globals reset, OOM-safe function calls |
| `Zend/zend_hash.c`, `zend_string.h`, `smart_str` | **+259/-43**, **+98/-18**, fallible variants |
| tests | ~200 new `oom_*.phpt` (8.5: 423 files, 8.2: 389); e.g. `tests/basic/oom_rfc1867_*.phpt`, `ext/session/tests/rfc1867_no_user_code.phpt` |

## Mechanism -> gate observation

| Gate observation | Fix change | Status |
|---|---|---|
| prime still 500/0 B + fatal text, child survives | delayed OOM (`zend_mm_delayed_verror()` + `zend_handle_delayed_oom()` at safe points) instead of `zend_error_noreturn()`+`zend_bailout()`; `memory_limit` still applies | [CONFIRMED] code; [INFERRED] exact log order |
| `BG(unserialize)` level=0 after prime | `php_basic_early_rinit()` runs before `php_hash_environment()`/rfc1867 and memsets `BG(serialize)`/`BG(unserialize)`; delayed OOM no longer skips request shutdown | [CONFIRMED] code path; [INFERRED] gate reading |
| R2a 200 with SR 374 B (8.5.12) / 361 B (8.2.35), no `|i:0;|` | normal `a:5` progress record written by update+flush (byte-verified); incomplete-class-only decode, rfc1867 OOM early stop, no stale `d`/push chain reaches `progress`/`ps_files` | [CONFIRMED] gate result and byte alignment (`docs/121` §7 of the E7 note); fail-fast attribution [REFINED] |
| R3 200, no `x.php`, no `uid` | upstream break: R2a never scalarizes, so `ps_files->basedir` is never rewritten; R3 is not blocked by a separate check | [CONFIRMED] gate result; [INFERRED] mechanism |
| 8.2.35 and 8.5.12 gates agree | identical fix patch (diff SHA256 for the 8.2 replays matches; 8.5 same patch, branch context differs) | [CONFIRMED] |

One-line summary: the fix does not stop the OOM; it removes **cross-request
stale state** (early global reset, delayed OOM, incomplete-only + fail-fast
decode, rfc1867 early stop, `_SESSION` delete), which is exactly what the
gate observes.

## 115560 / issue #24493 correction (web-r51)

- **issue #24493 / PR #24677 are NOT the CVE-2026-115560 tracker**: they are
  the 8.5.12 regression where the upload-progress decoder destroys a whole
  session that stores an object with reserved member names
  (`__PHP_Incomplete_*`); PR #24677 was closed/unmerged (2026-10-25), the
  issue is open.
- The official 2026-10-23 note says the 115560 fix and full advisory come with
  the **next regular release**; as of 2026-10-31 no fix commit or tracking
  issue is public, and KEV (catalog 2026.10.30) does not list 115560.
- The public replay `3584a98bda` is an **ancestor of all four public branches**
  (`behind_by=0`): 8.4.28/8.3.37/8.2.36 already contain the equivalent fix,
  while the 8.4.27/8.3.36/8.2.35 tags carry their private-branch fix.

## Version status

- **8.3.36**: released as a pure security release; PHP 8.3 security fixes until **2027-12-31** (active ended 2025-12-31);
- **8.4.27**: released (not a pure security release); PHP 8.4 active to **2026-12-31**, security to **2028-12-31**;
- **8.5.13**: still `8.5.13-dev` (tag 404); expected ~2026-11-19 +/-
  `[UNVERIFIED]`; third-party apiki `php-8.5.13` is not 8.5.13; its NEWS does
  not list GH-24493/115560, so a future release still needs the gate
  measurement, not an assumption;
- **8.2.36**: not released; PHP 8.2 EOL **2026-12-31**;
- **EOL corrections** (supersede older notes): PHP 8.5 until **2029-12-31**.

## Limitations

- `[CONFIRMED]` = commit/diff/code existence and content; `[INFERRED]` = exact alignment between gate readings and each mechanism;
- the review uses public php-src history/diffs only (no VM/docker run); line counts are from the published `.diff` (8.2.35 may differ slightly in context);
- commit hashes and the merge chain are from the public GitHub mirror.

## References

- `docs/research/fpm-8512-gate.md`, `fpm-8235-gate.md`, `fpm-8512-gate-4w.md`,
  `fpm-8235-gate-4w.md` (gate evidence);
- `docs/research/fpm-8513-readiness.md` (release-day readiness).

## Licensing

MIT for the original code in this repository (see `LICENSE`); lab-only use.
All code in this tree is original self-implemented p2s work (MIT).
