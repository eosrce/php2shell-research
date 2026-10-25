#!/bin/bash
# r46_build8513.sh -- build the 8.5.13 gate lab image (curated release copy;
# lab-only).
#
# Copyright (c) 2026 The PHP2Shell research authors. MIT License (see LICENSE).
# LAB-ONLY: authorized lab targets only. This script pulls a base image and
# builds a local lab image; never point it at third-party systems. See
# ACCEPTABLE_USE.md and SECURITY.md.
#
# Release-day rules: the base must be the official `php:8.5.13-fpm` (exact
# version check below); dev/RC bases are DIAG-only; the apiki/wphost
# `php-8.5.13` tag is a trap (it still ships 8.5.12). The recipe uses
# /home/ahost/fpm-lab on the VM (override via HOME/BASE_IMAGE/TAG). Then run
# labs/fpm/r41_patch_gate8513.sh (DIAG first) or the full pipeline
# labs/fpm/r49_release_day_8513.sh. Evidence/checklist:
# docs/research/fpm-8513-readiness.md.
#
# Build the 8.5.13 gate lab image from the same recipe as the 8.5.12 gate.
# Run only after 8.5.13 is released (official php:8.5.13-fpm must exist).
#
# Release-day sequence (docs/109 §9):
#   1) bash scripts/remote/r46_build8513.sh          # this script
#   2) PROFILE=8513 ... RUNS=1 DIAG=1 r41_patch_gate8513.sh   # re-baseline
#   3) PROFILE=8513 ... RUNS=3 r41_patch_gate8513.sh            # gate
#   4) positive control: PROFILE=8511 ... RUNS=3 r41_patch_gate.sh (8.5.11 lab)
#   5) unknown PROFILE=9999 -> ERROR exit 2
#
# WARNING: third-party images whose tag says 8.5.13 may still contain PHP
# 8.5.12 (e.g. apiki/wphost:php-8.5.13 is a revision number: FROM php:8.5.12).
# This script verifies `php -r 'echo PHP_VERSION;'` == 8.5.13 and refuses
# otherwise.  Never gate on an unverified/pre-release binary.
set -u
BASE_IMAGE=${BASE_IMAGE:-docker.m.daocloud.io/library/php:8.5.13-fpm}
TAG=${TAG:-p2s-phpfpm-lab:8.5.13-gate}
EXPECT_VERSION=${EXPECT_VERSION:-8.5.13}
echo "=== build 8.5.13-gate image $(date -Is) base=$BASE_IMAGE ==="
echo "--- pull base (daocloud mirror; 403/not found => release not available yet) ---"
docker pull "$BASE_IMAGE" 2>&1 | tail -4 || { echo "BASE_PULL_FAILED (release not published or mirror tag missing)"; exit 1; }
docker image inspect "$BASE_IMAGE" --format 'base_id={{.Id}} created={{.Created}}' 2>/dev/null || true
echo "--- version gate on base (must be exact $EXPECT_VERSION) ---"
BASE_VER=$(docker run --rm --entrypoint php "$BASE_IMAGE" -r 'echo PHP_VERSION;' 2>/dev/null || echo UNKNOWN)
echo "BASE_PHPV=$BASE_VER"
if [ "$BASE_VER" != "$EXPECT_VERSION" ]; then
  echo "BASE_VERSION_MISMATCH expected=$EXPECT_VERSION got=$BASE_VER (third-party/pre-release trap?)"
  case "$BASE_VER" in
    8.5.13-*) echo "dev/RC base: allowed for DIAG only, never for a gate verdict" ;;
  esac
  exit 3
fi
mkdir -p $HOME/gate8513
cp /home/ahost/fpm-lab/Dockerfile.version $HOME/gate8513/Dockerfile.8513
echo "--- docker build ---"
docker build -f $HOME/gate8513/Dockerfile.8513 -t "$TAG" \
  --build-arg BASE="$BASE_IMAGE" /home/ahost/fpm-lab 2>&1 | tail -14
echo "--- verify image ---"
docker image inspect "$TAG" --format 'image_id={{.Id}} created={{.Created}}' 2>/dev/null || echo IMAGE_MISSING
docker run --rm --entrypoint sh "$TAG" -c 'php -v | head -1; php -r "echo PHP_VERSION;"; echo; command -v gdb; ls /srv/www 2>/dev/null | head; grep client_max_body_size /etc/nginx/nginx.conf 2>/dev/null' 2>&1 | head -14
echo "--- web-context prerequisites (fatal-rich + cleanup=Off) ---"
grep -nE 'log_errors|catch_workers_output|request_terminate_timeout' /home/ahost/fpm-lab/www-1.conf || echo "WARN: www-1.conf lacks log_errors/catch_workers_output"
echo "NOTE: mounted php-128m.ini copy must have session.upload_progress.cleanup=Off (gate recreates it)"
echo BUILD8513_DONE
