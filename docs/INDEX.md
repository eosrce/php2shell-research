# Documentation index

This repository contains **research notes only**. Development logs, internal
state documents and one-off scripts are not part of the public research tree.

## Start here

| Doc | Content |
|---|---|
| [../README.md](../README.md) | bilingual overview, status, quick start |
| [ROADMAP.md](ROADMAP.md) | **full ASCII global path map** |
| [research/overview.md](research/overview.md) | problem, two FPM endgames, research questions |
| [research/claims.md](research/claims.md) | claims and evidence strength |
| [RELEASE-NOTES.md](RELEASE-NOTES.md) | what this snapshot contains and what is open |

## PHP-FPM

| Doc | Content |
|---|---|
| [research/fpm-128m.md](research/fpm-128m.md) | 128M deterministic chain: var_push, ps_files, geometry, proof |
| [research/fpm-8m-reclaim.md](research/fpm-8m-reclaim.md) | 8M reclaim: producer, 8KB reclaim, fake HashTable → zif_system |
| [research/fpm-8m-http-leak.md](research/fpm-8m-http-leak.md) | 8M HTTP-only chunk/PIE leak; official stripped + 4-worker endgame |
| [research/fpm-8m-prime.md](research/fpm-8m-prime.md) | 8M prime, empty chunk, structural wall |
| [research/fpm-8511-http.md](research/fpm-8511-http.md) | 8.5.11 FPM 128M pure-HTTP gdb-free chain; matrix `fpm-8511-http-1w` |
| [research/fpm-8234-port.md](research/fpm-8234-port.md) | 8.2.34 FPM real-CVE quadrant port; matrix `fpm-8234-http-1w` |
| [research/fpm-8234-4w.md](research/fpm-8234-4w.md) | 8.2.34 FPM 128M 4-worker pure-HTTP chain (lab pinning + ASSERT4); matrix `fpm-8234-http-4w` |
| [research/fpm-8511-4w.md](research/fpm-8511-4w.md) | 8.5.11 FPM 128M 4-worker pure-HTTP chain; BG dual-offset fix; matrix `fpm-8511-http-4w` |
| [research/fpm-8235-gate.md](research/fpm-8235-gate.md) | 8.2.35 FPM fail-closed patch gate (8.2 branch); matrix `fpm-8235-gate` |
| [research/fpm-8512-gate-4w.md](research/fpm-8512-gate-4w.md) | 8.5.12 FPM 4-worker fail-closed patch gate (pin mode); matrix `fpm-8512-gate-4w` |
| [research/fpm-8513-readiness.md](research/fpm-8513-readiness.md) | 8.5.13 release-day readiness: status, apiki trap, gate prep, 24 h checklist |
| [research/fpm-8235-gate-4w.md](research/fpm-8235-gate-4w.md) | 8.2.35 FPM 4-worker fail-closed patch gate (pin mode); matrix `fpm-8235-gate-4w` |
| [research/fpm-8336-gate-4w.md](research/fpm-8336-gate-4w.md) | 8.3.36 FPM 4-worker fail-closed patch gate (pin mode; BG `+0x360`); matrix `fpm-8336-gate-4w` |
| [research/fix-commits-2026-10-31.md](research/fix-commits-2026-10-31.md) | upstream fix commits for CVE-2026-109618/109619 and gate mechanism mapping |
| [research/fpm-8427-gate-4w-poc.md](research/fpm-8427-gate-4w-poc.md) | 8.4.27 FPM 4-worker gate: calibrated against 8.4.26, **registered** (`fpm-8427-gate-4w`) |
| [research/gate-family-crossbranch-2026-10-31.md](research/gate-family-crossbranch-2026-10-31.md) | cross-branch gate family **full 3x** (18/18 gates + 12/12 controls PASS; selector fix) |

## Methods and adjacent research

| Doc | Content |
|---|---|
| [research/methods.md](research/methods.md) | M1–M8: OOM targeting, pressure primitives, landing algebra, oracles |
| [research/patch.md](research/patch.md) | fixed releases, gates, chunked-body bypass, negative controls |
| [research/cms.md](research/cms.md) | CMS matrix and the WordPress A1 root cause |
| [research/t2-t3.md](research/t2-t3.md) | T2 psv phase and T3 libphp leak: open notes |
| [research/e7-mechanism-verification.md](research/e7-mechanism-verification.md) | E7 runtime verification: dynsym, early_rinit, delayed OOM, incomplete-only, `cancel_decode` |
| [labs/fpm/r49_release_day_8513.sh](../labs/fpm/r49_release_day_8513.sh) | 8.5.13 release-day pipeline (build -> DIAG -> gate -> 8.5.11 control -> unknown PROFILE) |
| [labs/fpm/r50_release_day_any.sh](../labs/fpm/r50_release_day_any.sh) | generic release-day pipeline for any branch gate (FAMILY 82\|83\|84\|85; fail-closed) |

## Engineering and licensing

| Doc | Content |
|---|---|
| [reproducibility.md](reproducibility.md) | lab setup, proof commands, oracle rules |
| [licensing.md](licensing.md) | MIT; all code self-implemented p2s work; related research credited |
| [self-implementation.md](self-implementation.md) | all code self-implemented; no external checkout needed |

## Map update rule

Every research milestone updates `ROADMAP.md` and the status table in
`README.md`. Output the full map, not only a diff.
