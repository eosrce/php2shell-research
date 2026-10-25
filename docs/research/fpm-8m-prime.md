# FPM 8M prime and the structural wall

## The 8M prime shape

The 8M FPM prime uses a session accumulated over many requests:

- 73 small upload-progress records, each followed by a nested-field wall that
  OOMs the parser before END cleanup can delete the record;
- one record with a 1,000,000-byte filename;
- a prime request with `700 × 4000` flat fields plus duplicate keys.

The result on 8.4.26 debug / 8M:

```text
sess_asx ≈ 1,023,325 B
prime -> HTTP 500 (worker survives, pid unchanged)
BG(unserialize).data = chunk+0x6e000  level=1
last                 = chunk+0x139000  used_slots=13
last_dtor            = chunk+0x71000   used_slots=74
```

The OOM stack is `zend_string_alloc(len=1000000)` inside
`php_var_unserialize_internal` — a decode OOM, not a parse OOM.

## The wall

After the prime, `zend_mm_chunk.free_map` shows the whole chunk free:

```text
free_pages=511  free_tail=1
run off=0x1000 pages=511 end=0x200000
```

R3 starts allocating from page 1. The first 3-page allocation reuses the stale
header:

- `BIG_DT=32768` with `--lead 0`: its `zend_string` lands at `0x6e000`;
- `--lead 1..8`: `multipart_buffer_read_body` writes at `0x6e000`;
- a single 8192 text field: its `zend_string` header lands at `0x6e000`;
- a 217 KB guard text field: its body buffer spans `0x63000..0x97ff8`.

`FILLUNIT=5120` and `zend_mm_alloc_pages` is best-fit, but the body buffer and
zend_string of a text field are consecutive. To place the string after
`0x6e000`, the body buffer must write `0x6e000`. This is the **structural
wall**.

## Consequence

The 128M two-field bases (`0x6d018/0x105018`) are not valid on the empty 8M
chunk; they are off by at least `0x1000`. The ps_files path would need a
header-preserving carrier (file filename, low-hole best-fit) or a chunk-base
leak to rebuild the header.

The reclaim path (see `fpm-8m-reclaim.md`) avoids the wall by overwriting the
header with a forged `php_unserialize_data`. That is the preferred 8M endgame.
