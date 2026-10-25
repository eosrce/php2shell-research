# Contributing

Contributions that improve **reproducibility** are welcome.

## What to contribute

- new FPM build profiles with a real proof and the exact image tag/digest;
- fixes to the FPM lab (nginx/php-fpm configs, pages);
- calibration improvements for the 8M reclaim chain (HTTP leak, official
  stripped image, 4 workers);
- documentation, the ASCII map, detection/defense guidance;
- tests that do not need a live target.

## What not to contribute

- third-party exploit or vector code (write your own implementation; do not
  copy another project's code);
- real target data, credentials, session files or logs from systems you do not
  own;
- mass-exploitation/target-list tooling;
- changes that make the default behavior target third-party systems.

## Profile workflow

1. Build or pull the exact image; record the image tag/digest and the `php-fpm`
   binary sha256/build-id.
2. Run the calibration driver (`src/tools/fpm_cal_driver.py`) in an isolated lab.
3. Prove the chain end-to-end; record the proof command and output.
4. Add the profile with `verified: true` only after the proof.
5. Add a test or smoke check that does not require the live target.

## Tests

```bash
python3 -m unittest discover -s tests -v
python3 src/tools/fpm_chain_smoke.py
python3 src/tools/fpm_reclaim_smoke.py
python3 -m py_compile $(find src -name '*.py')
```

## Licensing of contributions

By contributing original code, you agree that it is licensed under MIT (see
LICENSE). Do not contribute third-party code unless its license is compatible
and the attribution is included in NOTICE.

## Pull request checklist

- [ ] no target data / secrets / large binaries;
- [ ] tests pass;
- [ ] docs updated (including docs/ROADMAP.md for a milestone);
- [ ] proof recorded if a profile claims `verified: true`;
- [ ] `NOTICE`/`docs/licensing.md` updated if a new source is used.
