# src

Core research code. The tools are scripts, not an installed package; run them
from the repository root.

| File | Purpose |
|---|---|
| `profiles.py` | per-build profiles (symbol offsets, heap geometry, purity) |
| `cms_profiles.py` | CMS presets (`--cms` data) |
| `builds/index.json` | verified build fingerprints (sha256/build-id) |
| `p2s/` | clean-room mod_php chain (warning + pure128), MIT |
| `tools/fpm_chain.py` | 128M FPM chain (deterministic; 1w/4w) |
| `tools/fpm_reclaim.py` | 8M FPM reclaim chain (debug 3/3; needs bases) |
| `tools/fpm_cal_driver.py` | stage-by-stage calibration driver |
| `tools/fpm_chain_smoke.py` | 128M patch/layout smoke |
| `tools/fpm_reclaim_smoke.py` | 8M reclaim payload smoke |
| `tools/zend_gdb.py` | Zend MM gdb command set |
| `tools/collect_build.py` | symbol/build fingerprint collector |
| `tools/geo_cal.py` | heap geometry calibration |
| `tools/research/` | smaller T2/T3 probes |

The `p2s/` package is **included** (MIT): it contains the self-implemented
mod_php warning and pure128 chains. The lab-only `exploit.py` itself is
**not** included, and no third-party exploit or vector code is shipped. All
code in this tree is original p2s work; see `../docs/licensing.md`.
