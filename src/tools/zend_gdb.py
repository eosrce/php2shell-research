#!/usr/bin/env python3
"""zend_gdb.py - gdb helpers for the Zend Memory Manager (php2shell lab).

Load it inside gdb:

    (gdb) source /path/to/zend_gdb.py
    (gdb) zend-chunk
    (gdb) zend-bg
    (gdb) zend-ps
    (gdb) zend-land 32792          # print where a 32792-byte emalloc lands
    (gdb) zend-psfiles             # trace ps_files_open (writer offset)

Why a plugin instead of another one-off .gdb file: every calibration in this
project asks the same four questions (where is the chunk, what are the stale
unserialize pointers, where is ps_files, where does a given allocation land).
They are collected here so a new build/limit only needs commands, not new
scripts.  PHP 8.4.26 layout is the default; override with `set $zend_ps_off`
and `set $zend_unserialize_off` when a build differs.

Authorized lab use only.
"""
from __future__ import annotations

import gdb

PS_GLOBALS_OFFSETS = {
    # php_version: (ps_globals symbol name, http_session_vars offset)
    "8.2": 0x140,
    "8.3": 0x168,
    "8.4": 0x168,
    "8.5": 0x168,
}


def _u64(addr: int) -> int:
    return int(gdb.parse_and_eval("*(unsigned long*)%#x" % addr))


def _chunk() -> int:
    return int(gdb.parse_and_eval(
        "(unsigned long)((zend_mm_heap*)alloc_globals.mm_heap)->main_chunk"))


def _ps_globals() -> int:
    return int(gdb.parse_and_eval("(unsigned long)&ps_globals"))


def _bg_unserialize_data() -> int:
    bg = int(gdb.parse_and_eval("(unsigned long)&basic_globals"))
    return _u64(bg + 0x368)


class _ZendChunk(gdb.Command):
    """zend-chunk: print main_chunk and the current chunk-relative addresses."""

    def __init__(self):
        super().__init__("zend-chunk", gdb.COMMAND_USER)

    def invoke(self, arg, from_tty):
        chunk = _chunk()
        print("main_chunk=0x%x" % chunk)
        try:
            size = int(gdb.parse_and_eval(
                "(unsigned long)((zend_mm_heap*)alloc_globals.mm_heap)->size"))
            print("heap.size=0x%x" % size)
        except gdb.error:
            pass


class _ZendBg(gdb.Command):
    """zend-bg: print BG(unserialize) data/last/last_dtor and used_slots."""

    def __init__(self):
        super().__init__("zend-bg", gdb.COMMAND_USER)

    def invoke(self, arg, from_tty):
        data = _bg_unserialize_data()
        if not data:
            print("unserialize.data=0 (no dangling decoder)")
            return
        chunk = data & ~0x1FFFFF
        print("data=0x%x off=0x%x" % (data, data - chunk))
        for name, off in (("last", 0x0), ("first_dtor", 0x8),
                          ("last_dtor", 0x10)):
            try:
                v = _u64(data + off)
            except gdb.error:
                continue
            if not v:
                print("%s=0" % name)
                continue
            print("%s=0x%x off=0x%x used=%d next=0x%x"
                  % (name, v, v - chunk, _u64(v), _u64(v + 8)))


class _ZendPs(gdb.Command):
    """zend-ps: print ps_globals + ps_files fields (8.4 layout by default)."""

    def __init__(self):
        super().__init__("zend-ps", gdb.COMMAND_USER)

    def invoke(self, arg, from_tty):
        ps = _ps_globals()
        print("ps_globals=0x%x" % ps)
        for name, off in (("save_path", 0x0), ("session_name", 0x8),
                          ("id", 0x10), ("mod_data", 0x60),
                          ("http_session_vars", 0x168),
                          ("rfc1867_progress", 0x188)):
            try:
                print("  %-18s 0x%x" % (name, _u64(ps + off)))
            except gdb.error:
                pass
        mod = _u64(ps + 0x60)
        if mod:
            chunk = _chunk()
            print("ps_files=0x%x off=0x%x" % (mod, mod - chunk))
            for name, off in (("last_key", 0x0), ("basedir", 0x8),
                              ("dirdepth", 0x10), ("fd", 0x18)):
                try:
                    print("  ps_files.%-8s 0x%x" % (name, _u64(mod + off)))
                except gdb.error:
                    pass
        bg = _bg_unserialize_data()
        if bg:
            print("BG.unserialize.data=0x%x off=0x%x"
                  % (bg, bg - _chunk()))


class _ZendLand(gdb.Command):
    """zend-land SIZE [LABEL]: print where the next SIZE-byte raw emalloc
    lands (chunk-relative).  SIZE is the *emalloc* size, i.e. value length + 32
    for a zend_string in 8.4 (observed: 32768 -> 32800, 524288 -> 524320);
    ZSTR_VAL is at returned+24.  Useful for the FPM two-field calibration."""

    def __init__(self):
        super().__init__("zend-land", gdb.COMMAND_USER)

    def invoke(self, arg, from_tty):
        parts = arg.split()
        if not parts:
            raise gdb.GdbError("usage: zend-land SIZE [LABEL]")
        target = int(parts[0], 0)
        label = parts[1] if len(parts) > 1 else "land"

        class Finish(gdb.FinishBreakpoint):
            def stop(self):
                try:
                    ptr = int(self.return_value)
                    chunk = _chunk()
                except Exception as exc:  # noqa: BLE001
                    print("LAND_ERR %r" % (exc,), flush=True)
                    return False
                data = ptr + 24
                off = data - chunk
                off_s = ("-0x%x" % (-off)) if off < 0 else ("0x%x" % off)
                print("LAND %s size=%d data=0x%x off=%s page=%d"
                      % (label, target, data, off_s, off // 4096), flush=True)
                return False

        class Hit(gdb.Breakpoint):
            def __init__(self):
                super().__init__("_emalloc", gdb.BP_BREAKPOINT)

            def stop(self):
                try:
                    if int(gdb.parse_and_eval("size")) != target:
                        return False
                except gdb.error:
                    return False
                Finish(internal=True)
                return False

        Hit()
        print("zend-land armed: size=%d label=%s (continue)" % (target, label),
              flush=True)


class _ZendRuns(gdb.Command):
    """zend-runs [MINPAGES]: list free page runs in the main chunk.

    Zend MM's page allocator is best-fit (zend_alloc.c: "Best-Fit Search"),
    so a run is only reused when its length is the smallest one that still
    fits.  A 2-page request therefore does NOT split a 3-page run if any
    2-page run is free.  This command is how the 8M FPM R3 shape is checked:
    the stale php_unserialize_data is a 3-page run, and every text field body
    buffer is FILLUNIT+1 = 5121 bytes (2 pages) before the zend_string copy.
    """

    def __init__(self):
        super().__init__("zend-runs", gdb.COMMAND_USER)

    def invoke(self, arg, from_tty):
        minpages = int(arg.split()[0], 0) if arg.split() else 1
        chunk = _chunk()
        free_tail = int(gdb.parse_and_eval(
            "((zend_mm_chunk*)%#x)->free_tail" % chunk))
        free_pages = int(gdb.parse_and_eval(
            "((zend_mm_chunk*)%#x)->free_pages" % chunk))
        off = int(gdb.parse_and_eval(
            "(unsigned long)&((zend_mm_chunk*)0)->free_map"))
        raw = bytes(gdb.selected_inferior().read_memory(chunk + off, 64))
        words = [int.from_bytes(raw[i:i + 8], "little") for i in range(0, 64, 8)]

        def used(page: int) -> bool:
            return bool((words[page >> 6] >> (page & 63)) & 1)

        runs = []
        start = None
        for page in range(0, 512):
            is_free = (page >= free_tail) or not used(page)
            if is_free and start is None:
                start = page
            elif not is_free and start is not None:
                if page - start >= minpages:
                    runs.append((start, page - start))
                start = None
        if start is not None and 512 - start >= minpages:
            runs.append((start, 512 - start))
        print("main_chunk=0x%x free_pages=%d free_tail=%d runs>=%d:"
              % (chunk, free_pages, free_tail, minpages))
        for page, length in runs:
            print("  run off=0x%06x pages=%d end=0x%06x%s"
                  % (page * 4096, length, (page + length) * 4096,
                     "  <-- TAIL" if page >= free_tail else ""))


class _ZendRunAt(gdb.Command):
    """zend-run-at OFF: report the free run containing chunk+OFF (page aligned)."""

    def __init__(self):
        super().__init__("zend-run-at", gdb.COMMAND_USER)

    def invoke(self, arg, from_tty):
        target = int(arg.split()[0], 0)
        chunk = _chunk()
        free_tail = int(gdb.parse_and_eval(
            "((zend_mm_chunk*)%#x)->free_tail" % chunk))
        off = int(gdb.parse_and_eval(
            "(unsigned long)&((zend_mm_chunk*)0)->free_map"))
        raw = bytes(gdb.selected_inferior().read_memory(chunk + off, 64))
        words = [int.from_bytes(raw[i:i + 8], "little") for i in range(0, 64, 8)]

        def used(page: int) -> bool:
            return bool((words[page >> 6] >> (page & 63)) & 1)

        page = target // 4096
        if page < free_tail and used(page):
            print("chunk+0x%x: page %d is ALLOCATED" % (target, page))
            return
        lo = page
        while lo > 0 and (lo - 1 >= free_tail or not used(lo - 1)):
            lo -= 1
        hi = page
        while hi < 511 and (hi + 1 >= free_tail or not used(hi + 1)):
            hi += 1
        print("chunk+0x%x: FREE run pages %d..%d off=0x%x len=%d pages"
              % (target, lo, hi, lo * 4096, hi - lo + 1))


class _ZendPsfiles(gdb.Command):
    """zend-psfiles: trace ps_files_open and print the ps_files address."""

    def __init__(self):
        super().__init__("zend-psfiles", gdb.COMMAND_USER)

    def invoke(self, arg, from_tty):
        class Open(gdb.Breakpoint):
            def __init__(self):
                super().__init__("ps_files_open", gdb.BP_BREAKPOINT)

            def stop(self):
                try:
                    data = int(gdb.parse_and_eval("data"))
                    key = gdb.parse_and_eval("key")
                except gdb.error:
                    return False
                chunk = _chunk()
                print("PSFILES_OPEN ps_files=0x%x off=0x%x key=%s"
                      % (data, data - chunk, key), flush=True)
                return False

        Open()
        print("zend-psfiles armed (ps_files_open)", flush=True)


for cls in (_ZendChunk, _ZendBg, _ZendPs, _ZendLand, _ZendRuns, _ZendRunAt,
            _ZendPsfiles):
    cls()

print("zend_gdb loaded: zend-chunk zend-bg zend-ps zend-land zend-runs "
      "zend-run-at zend-psfiles")

