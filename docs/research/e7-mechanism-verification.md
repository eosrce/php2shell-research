# E7 mechanism verification (early_rinit / delayed OOM / incomplete-only)

Lab-only research note, curated from `docs/118`. Authorized lab targets only;
see `ACCEPTABLE_USE.md` and `SECURITY.md`. This note records a **runtime**
verification of the fix mechanisms (gdb on official stripped images), not a
new exploit result.

## Result

On the official 8.5.12/8.5.11 images the official `strip --strip-all` removes
`.symtab` but **keeps exported PHPAPI/ZEND_API symbols in `.dynsym`**, so the
new fix functions can be resolved by name:

| Symbol | 8.5.12 (patched) | 8.5.11 (vulnerable) |
|---|---|---|
| `php_basic_early_rinit` | **T @0x60b0c0** (dynsym) | absent |
| `zend_handle_delayed_oom` | **T @0x73ed30** (dynsym) | absent |
| `php_var_unserialize_set_incomplete_classes_only` | **T @0x6706f0** (dynsym) | absent |
| `php_hash_environment` | T @0x6d62a0 | T @0x6ce000 |
| `basic_globals` / `ps_globals` | B (dynsym) | B (dynsym) |
| `php_session_initialize` / `php_session_rfc1867_update` | not in dynsym (static) | not in dynsym |

- **natural run, patched 8.5.12**: prime `EARLY`/`HASH` level=0, then `BGWRITE 1` (`php_var_unserialize_init` from `php_session_start`) and `BGWRITE 0` (`destroy`, same request); 2x `DELAYED_OOM`; prime 500/0 B with fatal `7000064`; next GET level=0;
- **natural run, vulnerable 8.5.11**: prime `HASH_ENTRY level=0`,
  `BGWRITE level=1` with no same-request destroy; the **next GET**
  `HASH_ENTRY level=1 data=0x71f4...` (stale survives into the pre-RINIT
  window) and is only cleared at module RINIT (`zend_activate_modules`);
- **controlled write, patched 8.5.12**: set `level=1` at the
  `php_basic_early_rinit` entry -> `CW_BGWRITE level=0` with
  `bt: php_basic_early_rinit <- php_request_startup` => the function itself
  clears `BG(unserialize)` [CONFIRMED];
- **incomplete-only**: patched consumer request hits
  `INCOMPLETE_SET (data ptr, esi=1)` twice via `php_session_start`; the
  vulnerable image has no such symbol.

## Interpretation

| Mechanism | Code/build | Runtime (gdb) | Note |
|---|---|---|---|
| `php_basic_early_rinit` clears BG before rfc1867 | [CONFIRMED] static | **clearing capability [CONFIRMED]** (controlled write: entry set 1 -> function writes 0); **natural path [REFINED]**: patched already destroys in the same prime request, so the next request's `EARLY_ENTRY` is 0 (early_rinit is the safety net) | "prime level=0 is caused by early_rinit" does not hold for this path |
| delayed OOM (`zend_handle_delayed_oom`) | [CONFIRMED] static | **call [CONFIRMED]**: 2x `DELAYED_OOM level=0` in the patched prime plus the fatal 7000064; vulnerable has no such symbol | causal link to stale prevention remains **[INFERRED]** |
| incomplete-only / fail-fast | [CONFIRMED] static | **call [CONFIRMED]**: 2x `INCOMPLETE_SET` (second arg 1) on the patched consumer; vulnerable has no such symbol | 374/361 B alignment [CONFIRMED] (§7); fail-fast attribution [REFINED] |
| gate sees BG=0 / prime 500+fatal | - | patched BG 0 [CONFIRMED] here; vulnerable stale survives to HASH [CONFIRMED] | matches the gate numbers; exact 374/361 B still [INFERRED] |

- **rfc1867 timing: [CONFIRMED]** (superseded by the static-recovery section
  below): the static targets were recovered by xref and breakpointed; the
  earlier hash -> module-RINIT differential is retained only as corroboration.

## Evidence

Images 8.5.12-gate `d06afa5c...` / 8.5.11 `502117d6...` (stripped PIE); clone containers `p2s-e7-8512`/19147 and `p2s-e7-8511`/19150; mounts `php-128m-gate.ini` (cleanup=Off) + `www-1.conf` + `_r41prime2.php` (sha256 `ca83aff9...`); gdb 16.3 with `CAP_SYS_PTRACE`; procedure restart -> grow -> restart -> attach -> prime `GET /_r41prime2.php?mb=114&pad=64` -> next GET.

## Limitations

- clone containers only (19131/19113 untouched); gdb pauses a worker - mechanism evidence, **not** gate/proof; cross-request clearing shown with a controlled write; static targets reached by address xref; stripped images keep the dynsym exports used here.

## Static-function recovery & rfc1867 order

Static targets recovered by dynsym anchor -> `objdump` call targets -> runtime
`php_rfc1867_callback` pointer (ps_globals file offsets `0x1cce1e0`/`0x1cce200`;
breakpoints use `base+offset` with `$psg`, not gdb's `$ps`):

| Function | 8.5.12 | 8.5.11 | Recovery |
|---|---|---|---|
| `php_session_start` | 0x5c08d0 | 0x5bbe00 | dynsym anchor |
| `php_session_initialize` | **0x5c0140** | **0x5bb690** | call target in `php_session_start` + source signature |
| `php_session_rfc1867_update` | **0x5c1830** | **0x5bcd50** | call target in the callback + `force_update`/`in_rfc1867_update`/flush signature |
| `php_session_rfc1867_callback` | **0x5c1a70** | **0x5bcfa0** | runtime `*(void**)&php_rfc1867_callback` minus base |

- **prime**: `EARLY`/`HASH` bg=0 -> `INIT_ENTRY` (caller `php_session_start`) -> `BGWRITE 1->0`; no callback/update (no multipart);
- **consumer**: callback -> update (`in_rfc1867_update=1`) -> initialize (incomplete-only arg=1) -> flush -> flag 0, **before module RINIT**; vulnerable keeps `bg=1` until module RINIT;
- **fail-fast** (malformed session): initialize returns 0 but `PS(session_status)!=active` -> update early-exits with no flush; **[REFINED]** the trigger is that status check, not an initialize FAILURE;
- **Upgrades [CONFIRMED]**: static recovery, rfc1867-before-module-RINIT, update order, incomplete-only, fail-fast/no-flush. Remaining **[INFERRED]**: none on mechanism - 374/361 B alignment is [CONFIRMED] (§7), attribution [REFINED].

## `php_session_cancel_decode` (fail-fast branch)

Static (not dynsym), recovered from the warning-string xref + source signature:
8.5.12 **0x21d673** / 8.5.11 **0x21d68e** (both present, not inlined); internal
`call php_session_destroy` (0x21d674 / 0x21d68f) then `php_session_track_init`
(0x21d679 / 0x21d694) -> `zend_delete_global_variable("_SESSION")`;
`php_session_decode` calls it twice (8.5.12 0x21d694/0x21d6b3; 8.5.11 0x21d6af/0x21d6ce).

- fail-fast stack (patched): `cancel_decode <- php_session_decode <- php_session_initialize <- php_session_rfc1867_update <- callback <- rfc1867_post_handler`; no flush afterwards;
- 8.5.11 hits the same `CANCEL_ENTRY` with the same stack/destroy/`_SESSION` delete, but pre-patch update still forces `status=active` and flushes (`Failed to write session data`) => the difference is the update's status early-exit **[REFINED]**;
- **[CONFIRMED]**: address/not-inlined, fail-fast stack, `_SESSION` cleanup, same call on the vulnerable image; 374/361 B alignment [CONFIRMED] (§7); only attribution [REFINED].

## 7. Numeric alignment (374/361 B)

The 8.5.12 R2a request runs UPDATE -> IRFC=1 -> INIT (caller=update) ->
INCOMPLETE_ONLY arg2=1 -> BG 1->0 -> INIT_RET=0 `ps_status=2` -> FLUSH ->
IRFC 0 with **no CANCEL/DESTROY**: patched R2a is a normal decode+flush, and
fail-fast/cancel appears only on a malformed decode (previous section).

| Session file (R2a) | Bytes | Decomposition |
|---|---:|---|
| 8.5.12 patched | **374** | prefix 43 + `a:5:{` 5 + start_time 31 + content_length 31 + bytes_processed 32 + done 15 + files 216 + `}` 1 |
| 8.2.35 patched | **361** | same, `tmp_name` 27 -> 14 (files 216 -> 203): 374 - 13 |
| 8.5.11 vulnerable | **47** | prefix 43 + `i:0;` 4 (`\|i:0;` present) |

`content_length` is the body length (a progress record); 374/361 contain no
`|i:0;`. **Attribution [REFINED]**: the byte counts are the normal `a:5`
progress record written by update+flush, not evidence of fail-fast or
`$_SESSION` deletion. The patched-vs-vulnerable difference is whether the
stale session is consumed (vulnerable rewrites 47 B with `i:0;`); the `i:0;`
mechanism remains **[INFERRED]**. The gate predicate (SR != 47/70, no
`|i:0;`) is unchanged; only its interpretation is clearer.

## References

- `docs/research/fix-commits-2026-10-31.md` (commit/patch mapping);
- `docs/research/fpm-8336-gate-4w.md` (8.3 BG `+0x360` gate evidence).

## Licensing

MIT for the original code in this repository (see `LICENSE`); lab-only use.
All code in this tree is original self-implemented p2s work (MIT).
