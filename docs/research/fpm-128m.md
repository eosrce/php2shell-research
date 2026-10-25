# FPM 128M deterministic chain

## Mechanism

`php_session_decode()` uses `php_var_unserialize_init()`, which reuses
`BG(unserialize).data` while `BG(unserialize).level != 0`. In FPM the decode
can run **before RINIT** through the multipart upload-progress callback, so a
stale decoder from a previous request is reachable.

`var_push()` appends to the decoder's `var_entries`:

```c
data[used_slots++] = rval;
```

Each push is an 8-byte write at a chunk-relative address. The chain primes the
worker with a large session so the decode OOMs and leaves the stale entries /
dtor blocks in the main chunk, then consumes them with a crafted session:

- a victim session with **N ≥ 2 scalar records** produces exactly N pushes;
- push N−1 writes `ps_files->last_key`;
- push N writes `ps_files->basedir`;
- `dirdepth` is never written;
- the fake `zend_string` at `DT+0x20` (len at `+0x30`, path at `+0x38`) is
  used by `ps_files_path_create`.

`last_key` must differ from the current session key so `ps_files_open()` reopens
the file with the rewritten `basedir`. The first victim record should not be
the integer `1` (its zval value would be freed by `zend_string_release`).

## Geometry (8.4.26 / 128M / debug and official stripped)

| Item | Value |
|---|---|
| `BG.data` | `chunk+0x6e000` |
| `E_OFF` (`last`) | `chunk+0x83000` |
| `DT_OFF` (`last_dtor`) | `chunk+0x6b000` |
| two-field filler | `DT=13312`, `E=45056` |
| data bases | `0x68018` / `0x81018` |
| writer | `ps_files+0 = 0x581e0` |
| fake string | `DT+0x20` (`--r3-str-off 0x20`) |
| prime | `BIG=53`, `PRIME_PRESS=400` |

These are heap-layout constants: they depend on the build and request shape,
not on debug symbols. The same constants were verified on the official stripped
`php:8.4.26-fpm` image.

## Proof

- 8.4.26 / 128M / `pm=static 1`: **4/4** `uid=33(www-data)`.
- 8.4.26 / 128M / `pm=static 4`: **4/4** (prime all children, then R3).
- Official stripped `php:8.4.26-fpm`: **1w 3/3 + 4w 1/1**.

## Preconditions

- page calls `session_start()` and stores ≥2 scalar session values;
- `session.upload_progress.enabled=On`, files save handler;
- `session.save_path` writable by the worker (empty path is not a blocker);
- a writable webroot (for the written webshell);
- worker affinity: single worker, or `--workers` equal to `pm.max_children`.

## Limitations

- 8.5.11 does not transfer (stale blocks in a far chunk).
- 8.3.x is not calibrated.
- `pm=dynamic` / concurrent load is not verified.
- The written file is a session file; it is executable only if it lands in a
  PHP-served directory and the content starts with a valid PHP tag.
