# Research repository manifest

This repository is a **curated research tree**. It contains research code,
labs, notes and tests; it does not contain development logs, one-off scripts,
internal state documents or third-party exploit source. All code in this tree
is original self-implemented p2s work (MIT).

All sha256 values below are hashes of the **committed Git blobs** (the tree is
LF-normalized by `.gitattributes`).  Verify them from a fresh clone, or with
`git cat-file blob HEAD:<path>`; a Windows working copy that still contains
CRLF line endings can otherwise report false mismatches.

## Layout

| Path | Files | Size |
|---|---:|---:|
| `src/` | 26 | 232.9 KiB |
| `labs/` | 51 | 178.4 KiB |
| `docs/` | 29 | 208.0 KiB |
| `tests/` | 3 | 7.6 KiB |
| `.github/` | 1 | 0.7 KiB |

## Core files (sha256)

| File | sha256 |
|---|---|
| `README.md` | `086f76a0814b47717e6d2513690494ad723658c18e5311a70cf93086e37d7657` |
| `README_EN.md` | `efc785e6c9e603e5b6604c14f903b4c42a71293e33afb28acee8586807dc9c52` |
| `LICENSE` | `ab7f27c74d2db20d07900208dc864aea685c5dd7ae58ff6b5a21c2b83e5d8a0e` |
| `NOTICE` | `6b08285d36b2c2e2ad3a6857af633438f72a5a9b3151ac4f26c76831c95e486b` |
| `SECURITY.md` | `5b805916f342d11e34861fb077770972de418806812246d2fdf41d139e8e8114` |
| `ACCEPTABLE_USE.md` | `a2ee41ad58a18da7cab9295553fc8182ec67a64bc851d4f0a7fb6798def13b0f` |
| `CONTRIBUTING.md` | `f4f735758c737a29195f60c240bee60bb4dc0b01815847d2aefd722879e887a6` |
| `CITATION.cff` | `eaeaac26ae1cff49ea22c90b703685d8c2c9654cfa84d7bbe0af391f41ca415c` |
| `Makefile` | `f0afab6e2f7c77c25aace5274d2f27b453f9169bf038849a5ae8545160158600` |
| `pyproject.toml` | `af03cd162ec88b5b6b0962685b84629082cc45f713ad0c595db08a2afaf1b2d9` |
| `src/profiles.py` | `53080a8405a18a61916ddee78f3ffe9b7f12fa4b4a6d47fe74add6e39674c46a` |
| `src/cms_profiles.py` | `413ecf7086f6b2b0839b270abe85a53ea9044e12e316bf2fb548e4e44e68dd6e` |
| `src/builds/index.json` | `df49d33bcefe568f956d16d8aa8fc52eb58d1b73f0da4653ba6295e84b0482de` |
| `src/tools/fpm_chain.py` | `c1a2c2a0f145a113d51d2cb071211a6c6bf47654cede4fbd3d3013ff00be01f6` |
| `src/tools/fpm_reclaim.py` | `c9368638a33b2c1b6d8ca4624bbcf35fc328a6eb743fcb03fc13425c43d22170` |
| `src/tools/fpm_leak.py` | `a0e6e13e613de86887339af0404f317333fee066f09917559fbe7c81131f0f68` |
| `src/tools/fpm_cal_driver.py` | `316d2066d6095b6f13f2c97015f45699c2f78a5a06d2b85c612d972c2fff3ee8` |
| `src/tools/fpm_chain_smoke.py` | `50799462575fb30dfed9661633120f5118038babb19b3a75cf797de6f6b206cb` |
| `src/tools/fpm_reclaim_smoke.py` | `fdd5cdb0ec231a0976231cb35aaf307ad7355b3f2f13c67fff56bbb4ac6e5464` |
| `src/tools/zend_gdb.py` | `0dbfaa514572546d80d6d27c7720244d9de01fc29c622ff21889c4871d5e8e71` |
| `src/tools/collect_build.py` | `d48c29c88497b9fd9155c21296f1c965f7eb2638ac197086a9ec9af3c1d56efb` |
| `src/tools/geo_cal.py` | `b3a4b117e131bc9182244613c1d1d3ed1d26f6c62b2a979489118ac042c5bf60` |
| `src/p2s/__init__.py` | `e80ea4d857a667495b3dd3e32834915622f5c60ae89b680be634626e6797430f` |
| `src/p2s/cms.py` | `28c5352af9c48b77f163ff1aa3fc70d68ab4c9265de77b42b76c09005d4124dc` |
| `src/p2s/transport.py` | `81b25eaacea40e00edd7731f3f8bfc6c611368b1a22e09457f1f1394ab33383d` |
| `src/p2s/multipart.py` | `971c5d74fbff99bd1db16fbfb65658ed3f201be0f4d0f83aa82b04b60acf9f1f` |
| `src/p2s/leaks.py` | `0ed155b24c7edaedc5c4de6d73f38c2ce60c759e927473e675724854fff8ee42` |
| `src/p2s/geometry.py` | `2cef2081691356f934ba63204e93bfe808e3f3a8365915cdaa5426733650c29f` |
| `src/p2s/proof.py` | `c06a96eaa1bcc106f5b866842fca425f5006f17764cd7f843c0c948e8d22cc4a` |
| `src/p2s/workers.py` | `16d1ed65abed8e73e5fbb3193f41748c826d804806e7342796926517f365a083` |
| `src/p2s/warning.py` | `709a2b1ed25fb21a35a20d0b77089efdd848118a25ddba79b78573fc3707da1d` |
| `src/p2s/pure128.py` | `5fd309843b16daf0aa75aa6b9bbac03fe4552cba90ddaba57c0b12d20cc3cdee` |
| `src/p2s/cli.py` | `6d7bc1e68de93ffe98f22e5aa6292703b13ad31dede4ccbd474fc08665930f61` |
| `tests/test_p2s_smoke.py` | `a0a7bac1b2ea107594edb32b57220dc5a3c3339b8ef9c39311b92f85bd51df2c` |
| `docs/ROADMAP.md` | `b3bc6ab4a7ccfa1f90be0aa58d3509fb8531ced46da60445555cb438dda492b2` |
| `docs/INDEX.md` | `3dcc8879114f81e8946a554d2ade5cd896f6358c7798185845146ed2a832ba60` |
| `docs/RELEASE-NOTES.md` | `1dfec7f194813ddae1c53dcf5faaeebb34fea722ac871ada11e0c5dec34dd451` |
| `docs/research/overview.md` | `d97e2073a28b52f086c375e94bc02b6f1906de43667061eb08cf7f818e952745` |
| `docs/research/fpm-128m.md` | `5f4e28c3802b2458584ce22ad6768d50a4e7ed373b03c8d6d15c7685bae8d802` |
| `docs/research/fpm-8m-reclaim.md` | `a7da731cf1e12b8d4680e64dfb0d45babfe80f619169c730e3ab1f719d6af837` |
| `docs/research/fpm-8m-http-leak.md` | `76c5b27477a0fda5c018423fdc1a803eb0c0c8c11127f016c80dec594c118532` |
| `docs/research/fpm-8m-prime.md` | `70e62e050bb40fdb1a12416573031da2a050aae550126da30cdf81567e685037` |
| `docs/research/methods.md` | `69498f6ba83cd634d02f52f3b17d4bba7d05e9eef77961677cf3ccd157313795` |
| `docs/research/claims.md` | `e8fab1157bf667740e0dbeeb401adcc4021adb991f9db99571e9be841c9d8787` |
| `docs/research/cms.md` | `f1928ca49955f9bdbb42ef2e17cf8058d362ef953f3da7e5dd5957d493808a8a` |
| `docs/research/t2-t3.md` | `8f22a2a29a59d0e7ce316fdf24aab978a2f8469c3ce40451a701da4c2440bb29` |
| `docs/research/patch.md` | `5f1ce4d1eac8a59a1b850683d512bcbc5f91073edbff9e1b60237b3f65e33b03` |

## Deliberately excluded

| Item | Reason |
|---|---|
| third-party exploit source / tooling | not included; all code here is original self-implemented p2s work (MIT) |
| development logs, agent logs, 00-NOW / internal state | not part of the research record |
| one-off scripts / archive | development process, not curated research |
| PHP source tarballs, container images, 7z archives, proof files | large or runtime artifacts |
| `.git` history of the main workspace | not published; this repo has a fresh history |

## Reproduce the research tree

The release tree is regenerated from the main research workspace by selecting
the research code, labs, curated notes, tests and license files. It is not a
snapshot of the development workspace.

