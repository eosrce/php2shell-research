# Research overview

## Problem

PHP2Shell (CVE-2026-109618 / CVE-2026-109619) is a family of cross-request
session/unserialize bugs. Two properties make the FPM surface interesting:

1. `rfc1867` runs inside `php_hash_environment()`, **before** module RINIT, so
   `php_session_initialize()` / `php_session_decode()` can consume a stale
   `BG(unserialize)` left by a previous request.
2. A request that OOMs in the right place leaves a freed
   `php_unserialize_data` (8216 bytes) and/or stale session globals; the worker
   survives the bailout, so the next request inherits the state.

This repository studies two FPM endgames:

| Endgame | Consumer | Primitive | Proof |
|---|---|---|---|
| **128M ps_files** | stale `BG(unserialize)` decode | rewrite `ps_files->basedir` via `var_push` → arbitrary file write → webshell | 4/4 1w, 4/4 4w, official 3/3+1/1 |
| **8M reclaim** | stale `BG(unserialize)` decode | 8 KB multipart body reclaims `d`; forged `var_hash` → fake reference → fake HashTable → `zif_system` | 3/3 1w debug; 1/1 no-oracle with supplied bases |

The 8M reclaim path exists because the 128M `ps_files` geometry does not
transfer: after the 8M prime the main chunk is fully free, and the first
3-page allocation overwrites the stale header at `0x6e000`. Instead of
protecting the header, the reclaim path **rebuilds** it with a forged
`php_unserialize_data`.

## Research questions

1. ~~Can the 8M reclaim chain be made **fully remote** (HTTP-only chunk/PIE
   leak instead of supplied bases)?~~ **Yes** — `fpm-8m-http-leak.md`: debug
   3/3, official stripped 1w 3/3.
2. ~~Does it transfer to the **official stripped** `php:8.4.26-fpm` image and
   to **4 workers**?~~ **Yes** — 1w 3/3 and 4w 3/3 with three pinned children.
3. Can the reclaim method cover **8.3.35** (and 8.5.11 with a different prime)?
   Still open; the leak geometry is build-specific.
4. Why does the application-build A1 (WordPress 8.4.15) OOM in session decode
   instead of `php_session_reset_id`, and how can the `bin 128` state be
   controlled?
5. T2/T3 remainder: the 8.4.26 `psv` phase difference and a second 8M
   `de=Off` libphp leak channel.
6. Can the 8M chain work under `pm = dynamic`? All proofs so far use
   `pm = static`.

## Non-goals

- A universal exploit for every PHP deployment.
- A scanner or target list.
- Mass exploitation or denial of service.
- Copying third-party exploit code.

## Map

The full path map is [../ROADMAP.md](../ROADMAP.md).
