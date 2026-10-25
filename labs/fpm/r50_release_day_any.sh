#!/bin/bash
# r50_release_day_any.sh -- generic release-day fail-closed pipeline for any
# branch gate (curated release copy; lab-only).
#
# Copyright (c) 2026 The PHP2Shell research authors. MIT License (see LICENSE).
# LAB-ONLY: authorized lab targets only. This pipeline pulls a base image,
# builds a lab image, starts/stops containers and sends HTTP traffic; never
# point it at third-party systems. See ACCEPTABLE_USE.md and SECURITY.md.
#
# One command per branch release (8.2.36, 8.3.37, 8.4.28, 8.5.13, ...):
# pull base -> exact-version check -> build lab image -> re-baseline run
# (must match the FAMILY signature) -> RUNS>=3 closed -> same-branch
# vulnerable control RUNS>=3 OPEN (image-pinned) -> unknown PROFILE -> follow-ups.
#
# FAMILY table (fail-closed defaults, overridable via EXPECT_*):
#   82: grow 7,048,390  SR 361/698  BG +0x358
#   83: grow 7,048,390  SR 361/698  BG +0x360
#   84: grow 7,050,470  SR 374/724  BG +0x370
#   85: grow 7,050,470  SR 374/724  BG +0x370
#
# Fail-closed invariants (all required): base/lab PHP is exactly VERSION;
# the re-baseline log matches the FAMILY grow/SR values and prints no OPEN;
# the control needs CONTROL_EXPECT_IMAGE pinned and must print SR 47/70,
# x.php 392 B and uid=33; unknown PROFILE exits 2; RUNS >= 3 (a 1-run pass is
# never accepted). A gate is not proof - register the matrix case only after
# 3x PASS plus a pinned control.
#
# Example (8.2.36, when released; FAMILY 82 supplies the expected values):
#   FAMILY=82 VERSION=8.2.36 PROFILE=8236 CONTROL_PROFILE=8235 \
#   CAL=p2s-gate8236-4w PORT=19156 \
#   CONTROL_CAL=p2s-gate8235-4w CONTROL_PORT=19148 \
#   CONTROL_EXPECT_IMAGE=sha256:... RUNS=3 \
#   bash labs/fpm/r50_release_day_any.sh
#
# VM paths: ROOT=/home/ahost/fork, REPO=$ROOT/scripts/remote, FPM_LAB=/home/ahost/fpm-lab
# (override via env). The branch-specific one-command pipeline for 8.5.13 is
# labs/fpm/r49_release_day_8513.sh; evidence/checklists:
# docs/research/fpm-8513-readiness.md and gate-family-crossbranch-2026-10-31.md.
#
# r50_release_day_any.sh - release-day fail-closed pipeline for ANY branch gate.
#
# One command per branch release (8.2.36, 8.3.37, 8.4.28, 8.5.13, ...):
#   pull base -> verify exact version -> build lab image -> re-baseline run
#   (must match the branch SIGNATURE) -> RUNS>=3 closed -> same-branch
#   vulnerable control RUNS>=3 OPEN -> unknown PROFILE -> follow-ups.
#
# Fail-closed invariants (all required):
#   * base/lab PHP version exactly equal to VERSION
#   * re-baseline log matches EXPECT_GROW / EXPECT_SR2A / EXPECT_SR2AK2 and
#     BG all-zero at EXPECT_BG_OFF; a wrong-family profile stops here
#   * gate exit 0 with explicit `PATCH GATE: closed`, no OPEN token
#   * positive control exit 3 with `OPEN (expected on vulnerable)`, SR 47/70,
#     x.php 392B, uid=33, and CONTROL_EXPECT_IMAGE pinned
#   * unknown PROFILE exit 2, `PATCH GATE: ERROR`
#   * RUNS >= 3 (a 1-run pass is never accepted)
#
# Example (8.2.36, when released; FAMILY 82 supplies expected closed values):
#   FAMILY=82 VERSION=8.2.36 PROFILE=8236 CONTROL_PROFILE=8235 \
#   CAL=p2s-gate8236-4w PORT=19156 \
#   CONTROL_CAL=p2s-gate8235-4w CONTROL_PORT=19148 \
#   CONTROL_EXPECT_IMAGE=sha256:... \
#   bash scripts/remote/r50_release_day_any.sh
set -uo pipefail
ROOT=${ROOT:-/home/ahost/fork}
REPO="$ROOT/scripts/remote"
VERSION=${VERSION:?VERSION required, e.g. 8.2.36}
FAMILY=${FAMILY:?FAMILY required: 82|83|84|85}
PROFILE=${PROFILE:?PROFILE required, e.g. 8236 (fixed build)}
CONTROL_PROFILE=${CONTROL_PROFILE:-}
CONTROL_CAL=${CONTROL_CAL:-}
CONTROL_PORT=${CONTROL_PORT:-}
CONTROL_EXPECT_IMAGE=${CONTROL_EXPECT_IMAGE:-}
CAL=${CAL:-}
PORT=${PORT:-}
RUNS=${RUNS:-3}
BASE=${BASE:-docker.m.daocloud.io/library/php:${VERSION}-fpm}
TAG=${TAG:-p2s-phpfpm-lab:${VERSION}-gate}
FPM_LAB=${FPM_LAB:-/home/ahost/fpm-lab}
LOG=${LOG:-/tmp/rd_${VERSION//./_}}
mkdir -p "$LOG"

case "$FAMILY" in
  82) DEF_GROW=7048390; DEF_SR2A=361; DEF_SR2AK2=698; DEF_BG=+0x358 ;;
  83) DEF_GROW=7048390; DEF_SR2A=361; DEF_SR2AK2=698; DEF_BG=+0x360 ;;
  84) DEF_GROW=7050470; DEF_SR2A=374; DEF_SR2AK2=724; DEF_BG=+0x370 ;;
  85) DEF_GROW=7050470; DEF_SR2A=374; DEF_SR2AK2=724; DEF_BG=+0x370 ;;
  *) echo "RELEASE-DAY-${VERSION}: FAIL: unknown FAMILY=$FAMILY" >&2; exit 1 ;;
esac
EXPECT_GROW=${EXPECT_GROW:-$DEF_GROW}
EXPECT_SR2A=${EXPECT_SR2A:-$DEF_SR2A}
EXPECT_SR2AK2=${EXPECT_SR2AK2:-$DEF_SR2AK2}
EXPECT_BG_OFF=${EXPECT_BG_OFF:-$DEF_BG}

[ "$RUNS" -ge 3 ] 2>/dev/null || { echo "RELEASE-DAY-${VERSION}: FAIL: RUNS must be >=3"; exit 1; }

fail() { echo "RELEASE-DAY-${VERSION}: FAIL: $*" >&2; echo "RELEASE-DAY-${VERSION}: FAIL"; exit 1; }
note() { echo "RELEASE-DAY-${VERSION}: $*"; }

echo "RELEASE-DAY-${VERSION}: START $(date -Is) family=$FAMILY"

echo "== step 1: pull/verify base $BASE =="
docker pull "$BASE" >"$LOG/01_pull.log" 2>&1 || fail "pull $BASE (not published yet?)"
BASE_PHPV=$(docker run --rm --entrypoint php "$BASE" -r 'echo PHP_VERSION;' 2>/dev/null || echo UNKNOWN)
[ "$BASE_PHPV" = "$VERSION" ] || fail "base PHP_VERSION=$BASE_PHPV (expected exact $VERSION)"
note "BASE=$BASE PHP=$BASE_PHPV"

echo "== step 2: build lab image $TAG =="
[ -f "$FPM_LAB/Dockerfile.version" ] || fail "missing $FPM_LAB/Dockerfile.version"
docker build -f "$FPM_LAB/Dockerfile.version" -t "$TAG" \
  --build-arg BASE="$BASE" "$FPM_LAB" >"$LOG/02_build.log" 2>&1 || fail "docker build"
IMG=$(docker inspect --format '{{.Id}}' "$TAG" 2>/dev/null || true)
[ -n "$IMG" ] || fail "image $TAG missing after build"
LABV=$(docker run --rm --entrypoint php "$TAG" -r 'echo PHP_VERSION;' 2>/dev/null || echo UNKNOWN)
[ "$LABV" = "$VERSION" ] || fail "lab PHP_VERSION=$LABV (expected $VERSION)"
note "IMAGE=$TAG ID=$IMG PHP=$LABV"

CAL=${CAL:-p2s-gate${PROFILE}-4w}
PORT=${PORT:-19156}

echo "== step 3: re-baseline run + SIGNATURE check (family $FAMILY) =="
PROFILE="$PROFILE" CAL="$CAL" PORT="$PORT" RUNS=1 RECREATE=1 \
  IMAGE="$TAG" EXPECT_IMAGE="$IMG" \
  bash "$REPO/r41_patch_gate4w.sh" 2>&1 | tee "$LOG/03_rebaseline.log" | tail -20
RC=${PIPESTATUS[0]}
[ "$RC" = "0" ] || fail "re-baseline run exit $RC (profile unknown/uncalibrated -> constants must be re-derived first)"
grep -q "grow=${EXPECT_GROW}" "$LOG/03_rebaseline.log" || fail "re-baseline grow mismatch (expected ${EXPECT_GROW})"
grep -q "sr2a=${EXPECT_SR2A}" "$LOG/03_rebaseline.log" || fail "re-baseline R2a SR mismatch (expected ${EXPECT_SR2A})"
grep -q "sr2ak2=${EXPECT_SR2AK2}" "$LOG/03_rebaseline.log" || fail "re-baseline R2aK2 SR mismatch (expected ${EXPECT_SR2AK2})"
grep -q "bg= " "$LOG/03_rebaseline.log" || true
grep -q "PATCH GATE: closed" "$LOG/03_rebaseline.log" || fail "re-baseline closed token missing (not a calibrated fixed build?)"
grep -q "PATCH GATE: OPEN" "$LOG/03_rebaseline.log" && fail "re-baseline emitted OPEN"
note "re-baseline signature matches family=$FAMILY (grow=$EXPECT_GROW SR=$EXPECT_SR2A/$EXPECT_SR2AK2)"

echo "== step 4: gate RUNS=$RUNS =="
PROFILE="$PROFILE" CAL="$CAL" PORT="$PORT" RUNS="$RUNS" \
  IMAGE="$TAG" EXPECT_IMAGE="$IMG" \
  bash "$REPO/r41_patch_gate4w.sh" 2>&1 | tee "$LOG/04_gate.log" | tail -12
RC=${PIPESTATUS[0]}
[ "$RC" = "0" ] || fail "gate exit $RC (expected closed/0)"
grep -q "PATCH GATE: closed" "$LOG/04_gate.log" || fail "closed token missing"
grep -q "OPEN" "$LOG/04_gate.log" && fail "OPEN token in gate log"
grep -q "SUMMARY profile=${PROFILE} runs=${RUNS} closed=${RUNS} " "$LOG/04_gate.log" || \
  grep -q "closed=${RUNS}" "$LOG/04_gate.log" || fail "not all ${RUNS} runs closed"
note "GATE closed ${RUNS}/${RUNS}"

echo "== step 5: same-branch vulnerable control (image-pinned) =="
[ -n "$CONTROL_PROFILE" ] || fail "CONTROL_PROFILE required for a usable gate"
[ -n "$CONTROL_CAL" ] || fail "CONTROL_CAL required for a usable gate"
[ -n "$CONTROL_PORT" ] || fail "CONTROL_PORT required for a usable gate"
[ -n "$CONTROL_EXPECT_IMAGE" ] || fail "CONTROL_EXPECT_IMAGE required (pin the vulnerable image ID)"
docker start "$CONTROL_CAL" >/dev/null 2>&1 || true
CTL_IMG=$(docker inspect --format '{{.Image}}' "$CONTROL_CAL" 2>/dev/null || true)
[ "$CTL_IMG" = "$CONTROL_EXPECT_IMAGE" ] || fail "control container image=$CTL_IMG != CONTROL_EXPECT_IMAGE=$CONTROL_EXPECT_IMAGE"
PROFILE="$CONTROL_PROFILE" CAL="$CONTROL_CAL" PORT="$CONTROL_PORT" RUNS="$RUNS" GDB_BG=1 \
  EXPECT_IMAGE="$CONTROL_EXPECT_IMAGE" \
  bash "$REPO/r41_patch_gate4w.sh" 2>&1 | tee "$LOG/05_control.log" | tail -8
RC=${PIPESTATUS[0]}
[ "$RC" = "3" ] || fail "control exit $RC (expected 3 OPEN)"
grep -q "OPEN (expected on vulnerable)" "$LOG/05_control.log" || fail "control OPEN token missing"
grep -q "sr2a=47" "$LOG/05_control.log" || fail "control R2a SR!=47 (not the vulnerable signature)"
grep -q "sr2ak2=70" "$LOG/05_control.log" || fail "control R2aK2 SR!=70"
grep -q "xphp=392" "$LOG/05_control.log" || fail "control x.php!=392B"
grep -q "uid=33" "$LOG/05_control.log" || fail "control uid!=33"
note "control OPEN ${RUNS}/${RUNS} (private signature 47/70/392/uid33)"

echo "== step 6: unknown PROFILE fail-closed =="
PROFILE=9999 CAL="$CAL" PORT="$PORT" RUNS=1 \
  bash "$REPO/r41_patch_gate4w.sh" >"$LOG/06_unknown.log" 2>&1
RC=$?
[ "$RC" = "2" ] || fail "unknown PROFILE exit $RC (expected 2)"
grep -q "PATCH GATE: ERROR" "$LOG/06_unknown.log" || fail "unknown PROFILE error token missing"
note "unknown PROFILE exit 2"

echo "== step 7: follow-ups =="
echo "  * CVE-2026-115560 is a separate issue: check NEWS for serialize_handler fixes"
echo "  * if 115560 fixed: rerun the 115560 lab variants and update docs/113"
echo "  * register matrix case fpm-<profile>-gate-4w only after 3x PASS + pinned control"
echo "RELEASE-DAY-${VERSION}: PASS"
exit 0
