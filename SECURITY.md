# Security policy

## Scope

This repository is a **research toolkit** for CVE-2026-109618 / CVE-2026-109619.
It is not a service and it ships no target list. The chains are disruptive:
they send large bodies, trigger OOM conditions and kill PHP workers.

## Reporting a problem in this toolkit

Please open a private security advisory on the repository, or contact the
maintainers listed in `CITATION.cff`. Do not include real target data,
credentials, or logs from systems you do not own.

## Reporting a problem in PHP

The underlying vulnerability is in PHP. Follow the PHP security team's process:
<https://www.php.net/security/>. Do not test third-party systems without
written authorization.

## Supported versions

This release is a research snapshot. The documented proofs are conditional on
the exact build/config recorded in the docs. There is no long-term support
branch; fixes are made on the main branch.

## Safe use

- Run only in an isolated lab or against a target you own / are authorized to
  test.
- Do not run the remote worker-saturation/pinner modes against third-party
  infrastructure.
- Do not publish proof files, session files, or logs from systems you do not
  own.
- Only the self-implemented code in this tree is needed; do not fetch or
  redistribute third-party exploit code.

See [ACCEPTABLE_USE.md](ACCEPTABLE_USE.md).
