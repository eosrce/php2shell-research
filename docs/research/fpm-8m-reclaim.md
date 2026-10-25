# FPM 8M reclaim chain

## Why not the 128M path

After the 8M prime the **main chunk is fully free** (`free_pages=511`,
`free_tail=1`). `BG(unserialize).data` points into free pages. The first
3-page allocation in R3 reuses the stale header at `chunk+0x6e000`:

- a text field's `zend_string` can land exactly on `0x6e000`;
- adding lead fields moves the writer to `multipart_buffer_read_body`;
- a large guard text field's body buffer sweeps through `0x6e000`.

A text field's body buffer and zend_string are consecutive, so a pure
text-field carrier cannot both preserve the header and place a string after
it. The reclaim path does not try: it **overwrites** the stale struct with a
forged one.

## Mechanism

### Producer

A builder pool at 64M writes a ~4MB session. The 8M chain pool GETs a page that
calls `session_start()` **after RINIT**; the decode of the 4MB value OOMs, the
request executor catches the bailout, the worker survives, and
`BG(unserialize) = {level=1, data=d}` remains.

### Consumer

A multipart POST runs `rfc1867` before RINIT. An 8KB text field's body buffer
lands over `d` and contains a forged `php_unserialize_data`:

```text
last              = d + entries
entries.used_slots= 2
data[1]           = d + 0x300
```

The consumer session contains `R:2`; the decode resolves it to a fake
`IS_REFERENCE` at `d+0x300`:

```text
fake zend_reference (d+0x500)
  -> fake zend_array (d+0x700, pDestructor = zif_system)
     -> fake Bucket/execute_data (d+0x800)
        -> fake zend_string (d+0x880, command)
```

At session shutdown, `zval_ptr_dtor` → reference destroy → array destroy →
`pDestructor` → `zif_system`. The worker dies after the command; FPM respawns
it. The proof file, not the HTTP status, is the oracle.

## Geometry (8.4.26 debug / 8M / 1 worker)

| Item | Value |
|---|---|
| `d_off` | `0x6f000` |
| `k` (content offset) | `0xfe8` |
| `reclaim_pads` | `[]` |
| `reclaim_size` | `8192` |
| `zif_system` | `pie+0x50a0f0` |
| `struct_size` | `8216` |
| `BG.data` / `level` | `+872` / `+880` |

Stock `[4096,4096]` / 16KB does **not** cover `d=0x6f000` on this build: the
probe places the 16KB buffer at `0x63000` / `0x77018`, leaving `d` between
them. No pads + 8KB lands the buffer at `d-0xfe8`.

## Proof

| Run | Result |
|---|---|
| endgame (lab oracle) | **3/3** `uid=33(www-data)` |
| `no-oracle` with supplied chunk/PIE | **1/1** `uid=33(www-data)` |
| project tool `fpm_reclaim.py` | **3/3** `uid=33(www-data)` |
| HTTP-only leak + endgame, debug / 1w | **3/3** `uid=33(www-data)` |
| HTTP-only leak + endgame, official stripped / 1w | **3/3** `uid=33(www-data)` |
| HTTP-only leak + endgame, official stripped / 4w | **3/3** `uid=33(www-data)` |

## Preconditions

- page `session_start()` + reflects session values;
- two pools: chain 8M (cleanup On) and builder 64M (cleanup Off), shared
  session dir;
- `session.upload_progress.enabled=On`; worker affinity;
- absolute chunk/PIE bases (oracle/HTTP leak) and the build's `zif_system`
  offset;
- writable `out/` directory relative to the pool `chdir` (the proof file is
  the oracle).

## Open items

- 8.3.35 / 8.5.11 transfer (the leak geometry is build-specific);
- `pm = dynamic` layouts (all proofs here use `pm = static`);
- automatic geometry discovery for a new build (currently re-measured by hand).

The HTTP-only leak itself is closed, including the official stripped image and
the 4-worker layout; see `fpm-8m-http-leak.md`.


## Why this is not a universal exploit

The chain requires two pools, a page that starts a session and reflects it,
a shared session directory, and a build-specific reclaim geometry. A single
8M pool cannot build the 4MB arm without killing the consumer.
