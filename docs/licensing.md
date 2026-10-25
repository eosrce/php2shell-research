# Licensing boundary

This document explains the licensing of this repository. It is not legal
advice.

## MIT (original work)

**All code in this tree is original, self-implemented p2s work**, under MIT
(see LICENSE):

- `src/p2s/` (mod_php warning + pure128 chain);
- `src/tools/fpm_chain.py`, `src/tools/fpm_reclaim.py`,
  `src/tools/fpm_cal_driver.py`, `fpm_chain_smoke.py`,
  `fpm_reclaim_smoke.py`, `zend_gdb.py`, `collect_build.py`, `geo_cal.py`,
  `verify_matrix.py`, `research/*`;
- `src/profiles.py`, `src/cms_profiles.py`, `src/builds/index.json`;
- `labs/*`, `tests/*`, `docs/*`, `README.md`, `NOTICE`, `SECURITY.md`,
  `ACCEPTABLE_USE.md`, `CONTRIBUTING.md`, `CITATION.cff`.

## Related public research (ideas credited, no code copied)

| Project | Relation |
|---|---|
| `kengwang/php2shell-fpm-exp` | published FPM chain idea credited; our FPM code is an independent implementation |
| `cbovin/php2shell-poc` | offset values cross-checked against its public lab; our profile code is original |
| `VABISMO/php2shell-nginx-fpm-full-rce` (MIT) | 8M reclaim endgame idea credited; our code is an independent implementation; lab pages keep their MIT license |
| `devploit/php2shell` (MIT) | research-release structure credited; no code copied |

## Third-party code

**No third-party exploit source is fetched, vendored, or required.** Nothing
in this repository is copied from another project; the projects above are
credited for ideas and measurements only.

## Contributions

By contributing original code you agree to MIT. Do not contribute third-party
code unless its license is compatible and the attribution is added to NOTICE.
