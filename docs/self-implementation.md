# Self-implementation boundary

**All code in this tree is self-implemented p2s work (MIT)**, written from
documented behavior and our own lab measurements. No external checkout is
needed to build, test or reproduce the research.

## What this repository contains

- `src/p2s/` - self-implemented mod_php warning + pure128 chain;
- `src/tools/` - FPM chains, leak/reclaim helpers and calibration tools;
- `labs/`, `tests/`, and the research notes in `docs/research/`.

## Related public research

The public projects credited in `NOTICE` (kengwang, cbovin, VABISMO, devploit)
are referenced for published ideas and measurements; their code is not copied
or required. The PHP2Shell vulnerability itself was disclosed by Wiz Research
(link in `NOTICE`).

## Portability notes

The lab code documents its own choices: a wider leaked-pointer acceptance
window, offset derivation through container commands, explicit writable `/out`
handling, no silent fallback to lab offsets, cookie parsing without a fixed
`; path=/` anchor, patched-release gates and `--check` / multi-worker pinning.
These are properties of the self-implemented code, not a patch to another
project.
