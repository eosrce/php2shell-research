# labs

Isolated labs used by the tools.

| Path | Purpose |
|---|---|
| `fpm/` | PHP-FPM 128M and 8M configs/pages; see `fpm/README.md` |
| `apache/` | Apache/mod_php compose, php.ini, apache.conf, test configs |

All labs bind to loopback and are meant for disposable, authorized testing.
Do not point them at third-party infrastructure.

The 128M FPM lab can run on the official `php:8.4.26-fpm` image (stripped).
The 8M reclaim lab needs a debug build or another way to obtain `zif_system`
and the chunk/PIE bases; see `docs/research/fpm-8m-reclaim.md`.
