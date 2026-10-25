#!/bin/bash
# r49_release_day_8513.sh - one-command release-day pipeline for the 8.5.13 gate
# (curated release copy; lab-only).
#
# Copyright (c) 2026 The PHP2Shell research authors. MIT License (see LICENSE).
# LAB-ONLY: authorized lab targets only. This pipeline builds a lab image,
# runs the gate, starts/stops containers and sends HTTP traffic; never point it
# at third-party systems. See ACCEPTABLE_USE.md and SECURITY.md.
#
# This copy expects the sibling release scripts in the same directory:
#   labs/fpm/r46_build8513.sh, labs/fpm/r41_patch_gate8513.sh,
#   labs/fpm/r41_patch_gate4w.sh (8.5.11 4w positive control).
# The upstream VM paths (/home/ahost/fpm-lab) are used by r46_build8513.sh.
#
# Preconditions: 8.5.13 has been released and the official php:8.5.13-fpm base
# is pullable from the mirror.  Run this script on the VM (crack-vm).
#
# Steps (all fail-closed; no token => no pass):
#   1. build p2s-phpfpm-lab:8.5.13-gate from the official base (exact 8.5.13)
#   2. RUNS=1 DIAG=1 patient run -> re-baseline print (must be DIAG, not a verdict)
#   3. RUNS=3 gate -> must print `PATCH GATE: closed` and exit 0
#   4. 8.5.11 positive control (4w pin mode, p2s-gate8511-4w/19144) -> 3/3 OPEN exit 3
#   5. unknown PROFILE -> exit 2
#   6. print the 115560 / CVE-2026-115560 reminder (separate issue: re-check NEWS)
#
# Usage (from the repository root):
#   bash labs/fpm/r49_release_day_8513.sh
set -uo pipefail
REPO="$(cd "$(dirname "$0")" && pwd)"
TAG=${TAG:-p2s-phpfpm-lab:8.5.13-gate}
CAL=${CAL:-p2s-fpm8513-128}
PORT=${PORT:-19145}
RUNS=${RUNS:-3}
LOG=${LOG:-/tmp/rd8513}
mkdir -p "$LOG"

fail() { echo "RELEASE-DAY-8513: FAIL: $*" >&2; echo "RELEASE-DAY-8513: FAIL"; exit 1; }

echo "RELEASE-DAY-8513: START $(date -Is)"
echo "RELEASE-DAY-8513: REPO=$REPO"
echo "== step 1: build =="
bash "$REPO/r46_build8513.sh" 2>&1 | tee "$LOG/01_build.log" | tail -8
[ "${PIPESTATUS[0]}" = "0" ] || fail "build (r46_build8513.sh)"
IMG=$(docker inspect --format '{{.Id}}' "$TAG" 2>/dev/null || echo "")
[ -n "$IMG" ] || fail "image $TAG missing after build"
VER=$(docker run --rm --entrypoint php "$TAG" -r 'echo PHP_VERSION;' 2>/dev/null || echo UNKNOWN)
[ "$VER" = "8.5.13" ] || fail "image PHP_VERSION=$VER (expected exact 8.5.13)"
echo "RELEASE-DAY-8513: IMAGE=$TAG ID=$IMG PHP=$VER"

echo "== step 2: DIAG re-baseline (RUNS=1, no verdict) =="
PROFILE=8513 CAL="$CAL" PORT="$PORT" RUNS=1 DIAG=1 RECREATE=1 \
  IMAGE="$TAG" EXPECT_IMAGE="$IMG" \
  bash "$REPO/r41_patch_gate8513.sh" 2>&1 | tee "$LOG/02_diag.log" | tail -20
[ "${PIPESTATUS[0]}" = "0" ] || fail "DIAG run (r41_patch_gate8513.sh DIAG=1)"
grep -q "GATE DIAG:" "$LOG/02_diag.log" || fail "DIAG token missing"
grep -q "PATCH GATE:" "$LOG/02_diag.log" && fail "DIAG emitted a gate verdict; wrong mode"
echo "RELEASE-DAY-8513: DIAG ok (see $LOG/02_diag.log; re-baseline SR/prime values above)"

echo "== step 3: gate RUNS=$RUNS =="
PROFILE=8513 CAL="$CAL" PORT="$PORT" RUNS="$RUNS" \
  IMAGE="$TAG" EXPECT_IMAGE="$IMG" \
  bash "$REPO/r41_patch_gate8513.sh" 2>&1 | tee "$LOG/03_gate.log" | tail -12
RC=${PIPESTATUS[0]}
[ "$RC" = "0" ] || fail "gate exit $RC (expected 0 closed)"
grep -q "PATCH GATE: closed" "$LOG/03_gate.log" || fail "closed token missing"
grep -q "OPEN" "$LOG/03_gate.log" && fail "OPEN token present in gate log"
echo "RELEASE-DAY-8513: GATE closed ($RUNS runs)"

echo "== step 4: 8.5.11 positive control (4w pin mode) =="
CTL=${CTL:-p2s-gate8511-4w}
docker start "$CTL" >/dev/null 2>&1 || true
PROFILE=8511 WORKERS=4 CAL="$CTL" PORT=${CTL_PORT:-19144} RUNS="$RUNS" GDB_BG=1 \
  bash "$REPO/r41_patch_gate4w.sh" 2>&1 | tee "$LOG/04_control.log" | tail -8
RC=${PIPESTATUS[0]}
[ "$RC" = "3" ] || fail "8.5.11 positive control exit $RC (expected 3 OPEN)"
grep -q "OPEN (expected on vulnerable)" "$LOG/04_control.log" || fail "control OPEN token missing"
echo "RELEASE-DAY-8513: control OPEN expected (exit 3)"

echo "== step 5: unknown PROFILE fail-closed =="
PROFILE=9999 CAL="$CAL" PORT="$PORT" RUNS=1 \
  bash "$REPO/r41_patch_gate8513.sh" >"$LOG/05_unknown.log" 2>&1
RC=$?
[ "$RC" = "2" ] || fail "unknown PROFILE exit $RC (expected 2)"
grep -q "PATCH GATE: ERROR" "$LOG/05_unknown.log" || fail "unknown PROFILE error token missing"
echo "RELEASE-DAY-8513: unknown PROFILE exit 2"

echo "== step 6: follow-ups (manual) =="
echo "  * re-check php-src PHP-8.5 NEWS / advisory for CVE-2026-115560 (separate issue)"
echo "  * if 115560 fix landed: run the 115560 lab (enabled=On -> uid, Off -> no) and document"
echo "  * if gate/control results differ from DIAG re-baseline: update docs/109 §9 + docs/113"
echo "RELEASE-DAY-8513: PASS"
exit 0
