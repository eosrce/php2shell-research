# PHP 8.5.13 release-day readiness (gate prepared, not released)

Lab-only research note, curated from `docs/113`. Authorized lab targets only;
see `ACCEPTABLE_USE.md` and `SECURITY.md`. This note is a readiness checklist,
not a result: 8.5.13 was **not released** when it was written.

## Release status (2026-10-31)

| Check | Result |
|---|---|
| php-src tag `php-8.5.13` | 404 (not tagged) |
| GitHub Releases | latest 8.5.12 |
| docker-library/php | highest `8.5.12-fpm-trixie` |
| `PHP-8.5/main/php_version.h` | `8.5.13-dev` |
| estimate | ~2026-11-19 (Thu) +/- , RC ~11-05 `[UNVERIFIED]` |

The estimate is a scheduling hint only; do not put it in public commitments.

## Traps

- **apiki/wphost `php-8.5.13` is not 8.5.13**: its CHANGELOG admits the binary
  is still 8.5.12 (`FROM php:8.5.12-fpm-alpine3.24`; `php -v` = 8.5.12;
  digest `f7ee4a33...`). Never use it as the 8.5.13 lab base.
- **8.5.13 NEWS does not list GH-24493 / CVE-2026-115560** (`a45ffe71` is not
  on the PHP-8.5 branch; PR #24677 is closed/merged=false; issue #24493 is
  open) - the gate must still be measured, not assumed.
- **CISA KEV**: CVE-2026-109618/109619 entered KEV on 2026-10-26 (catalog
  2026.10.30); CVE-2026-115560 is not in KEV.

## Gate prepared

`r41_patch_gate8513.sh` (main tree) is ready for release day:

- `PROFILE=8513` is explicit; unknown profiles exit 2;
- the first run must be `RUNS=1 DIAG=1`: it prints `GATE DIAG ... patch=fixed`
  and exits 0 without a verdict, for re-baselining the closed assertions;
- `BG_VERIFIED` / `ALLOW_BG_UNVERIFIED`: an uncalibrated BG read is
  `[UNVERIFIED]` by default and only `ALLOW_BG_UNVERIFIED=1` can accept it;
  never treat an uncalibrated level as 0;
- exact-version strictness: a non-DIAG run requires exactly `8.5.13`
  (`8.5.13-dev`/RC builds may only be DIAG'd);
- `EXPECT_IMAGE` (digest) and `EXPECT_PAGE_SHA256` pins;
- dedicated container port **19145** (do not reuse 19143/19144);
- build script `r46_build8513.sh` uses the official `php:8.5.13-fpm` base
  (current pull 403 because it is unreleased).

## Release-day pipeline in this snapshot

The gate, build and pipeline scripts now ship in `labs/fpm/`:

- `labs/fpm/r46_build8513.sh` - build `p2s-phpfpm-lab:8.5.13-gate` from the
  official base with an **exact-version gate** (`php -r echo PHP_VERSION` ==
  `8.5.13`; dev/RC is DIAG-only; apiki trap warned);
- `labs/fpm/r41_patch_gate8513.sh` - the gate itself (DIAG -> RUNS=3;
  `BG_VERIFIED`/`ALLOW_BG_UNVERIFIED`; `EXPECT_IMAGE`/`EXPECT_PAGE_SHA256`;
  port 19145);
- `labs/fpm/r49_release_day_8513.sh` - one-command pipeline: build -> DIAG
  (no verdict) -> `RUNS=3` closed -> 8.5.11 4w positive control
  (`OPEN (expected on vulnerable)`, exit 3) -> unknown `PROFILE` exit 2 ->
  CVE-2026-115560 follow-up reminder. All steps fail-closed; no token = no pass.

Paths in the pipeline are resolved from the script's own directory, so it can
be run from the release checkout after copying the sibling scripts together.

## Release-day 24 h checklist (condensed from docs/109 §9)

1. build the lab image from the official `php:8.5.13-fpm` base with the same
   `Dockerfile.version` recipe; record `IMAGE`/`EXPECT_IMAGE` digests;
2. `PROFILE=8513 CAL=p2s-fpm8513-128 PORT=19145 RUNS=1 DIAG=1` first;
3. re-baseline the closed assertions (SR/grow/prime/child) for 8.5.13;
   do not silently reuse the 8.5.12 defaults;
4. `GDB_BG=0` or `[UNVERIFIED]` until the 8.5.13 BG offset is calibrated;
5. run the 8.5.11 positive control 3/3 `OPEN (expected on vulnerable)` and
   unknown `PROFILE` `ERROR`/exit 2;
6. run `RUNS=3`; any `OPEN (REGRESSION)` = P0, any `ERROR` = fix the
   instrument first (never a PASS);
7. register `fpm-8513-gate` only after PASS; a gate is not proof and A/B does
   not change;
8. test CVE-2026-115560 separately (serialize-handler switch + gadget), not
   in the 109618/619 gate count; `enabled=Off` closes 115560, but
   `php_admin_flag` cannot block a runtime handler switch;
9. record `GATE INI_WEB`/prime/SR bytes and the image/page digest pins;
10. publish within 24 h: docs/109 continuation + docs/68 row + FRAGILE F-row
    + docs/87/00-NOW/ROADMAP.

## Limitations

- a gate only shows "this chain does not work here"; **closed != build safe**
  (CVE-2026-115560 is separate);
- the date and RC estimate are `[UNVERIFIED]` scheduling hints;
- no run is valid on a dev/RC build except as DIAG re-baseline.

## Licensing

MIT for the original code in this repository (see `LICENSE`); lab-only use.
All code in this tree is original self-implemented p2s work (MIT).
