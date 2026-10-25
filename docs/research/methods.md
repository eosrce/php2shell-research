# Methods: turning memory corruption into a calibration problem

The reusable method is: **turn an uncontrollable memory corruption into a
sequence of allocations that can be measured and reproduced.**

| # | Method | Implementation |
|---|---|---|
| M1 | **OOM-site targeting**: classify the failing allocation by size + stack | `collect_build`/gdb `_zend_bailout`, OOM classifier |
| M2 | **Pressure-primitive catalogue**: choose per-request increment, persistence, body limits | flat fields, nested fields, fragments, big fields |
| M3 | **Landing algebra**: `data_start = f(size, order)`; solve for sizes; two-field coverage | `geo_cal.py`, `zend_gdb.py:zend-land` |
| M4 | **Stale-state oracle**: read `BG(unserialize)`/`ps_files` directly | `zend-bg`, `zend-ps`, `zend-runs` |
| M5 | **Consumer-semantics counting**: make the number of writes a parameter | `--r3-scalars`, `var_push` |
| M6 | **Three-layer portability**: symbol offsets (build) / heap geometry (shape) / runtime bases (process) | profiles, builds/index.json |
| M7 | **Proof is the only oracle**: clear before run, match content, negative controls | proof files, patched gates |
| M8 | **Capability gates**: refuse patched/unknown builds | exit 3 / exit 5 |

## Calibration loop

```text
[1] fingerprint  X-Powered-By / libphp sha256 / build-id / SAPI / arch
[2] symbols      zif_system / zval_ptr_dtor / ps_globals   (per build)
[3] shape        producer pressure primitive + OOM stack
[4] geometry     zend-land -> solve -> zend-bg / zend-psfiles
[5] oracle       proof file + content match; clear before run
[6] gate         patched exit 3; unknown build exit 5
```

Only **[2] symbols** and **[4] geometry** must be redone for every build.
**[3] shape** must be redone for every configuration (memory_limit, SAPI,
application). **[1]/[5]/[6]** are constants.

## Pitfalls

- `zend_string` emalloc size is `len+32` in 8.4, not `len+24`.
- 4096-byte allocations can be `php_sapi_filter`, not `url_encode`.
- OOM after a fatal error may leave the child alive (delayed OOM): kill the
  child before scanning shapes.
- `gdb` cannot follow `rotate()`: use the proof file as the oracle.
- The linear landing model only holds near the calibrated size; verify every
  new size pair with `zend-land`.
