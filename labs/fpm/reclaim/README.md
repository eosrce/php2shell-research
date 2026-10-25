# 8M FPM reclaim lab

This lab reproduces the 8M reclaim chain in docs/research/fpm-8m-reclaim.md. The pages are our copies of
the MIT-licensed VABISMO lab pages (see NOTICE); no upstream code is vendored.

## Topology

```text
nginx :8080 -> php-fpm [chain]   8M,  cleanup=On
nginx :8081 -> php-fpm [builder] 64M, cleanup=Off
webroot /srv/www  (app.php, bigvar.php, ref.php, out/)
session dir /var/lib/php/sessions (shared)
```

Two pools in one `php-fpm` master; use `php-fpm-reclaim.conf` and
`nginx-reclaim.conf`. Start:

```bash
php-fpm -D -y /srv/php-fpm-reclaim.conf -c /srv/php.ini
nginx -c /etc/nginx/nginx-reclaim.conf -g 'daemon off;'
```

Then run `src/tools/fpm_reclaim.py` with the chunk/PIE bases and the
`--zif-offset` of the build. In a debug build these can be read from
gdb/`/proc/<pid>/maps`; with `--leak` the tool obtains both bases over HTTP
(`src/tools/fpm_leak.py`), so no debugger or oracle is needed.

## HTTP-only leak

`fpm_leak.py` turns the same stale decoder into a read primitive:

```text
stage 1   4KB big field + pads [7168, 1024] -> forged zend_string header at
          chunk+0x73800, read 0x15810 bytes, chunk base by majority vote
stage 2   debug:    16KB fake zval -> chunk+0x1d0,  read+0x3e38 = pie+0x31d400
          official: 16KB fake zval -> chunk+0x56c60, read+0x13b8 = pie+0x7038e0
```

The official handler table at `chunk+0x58030` survives the worker crash that
the endgame causes, so leak and endgame can be repeated on the respawned
child. See `docs/research/fpm-8m-http-leak.md`.

## Geometry used in the proof

```text
d_off=0x6f000  k=0xfe8  reclaim_pads=[]  reclaim_size=8192
zif_system=pie+0x50a0f0  struct_size=8216  BG.data=+872  BG.level=+880
```

The shape is build-specific: the stock `[4096,4096]`/16KB shape does **not**
cover `d=0x6f000` on this build. Re-measure with the lab before changing it.

## 4 workers

Use `php-fpm-reclaim-4w.conf` (`pm.max_children = 4` for the chain pool) and
**pin three children** before running the chain:

```bash
for i in 1 2 3; do
  curl -s -m 40 'http://127.0.0.1:8080/pin.php?us=25000000' &
done
sleep 1.5
```

The leak and the endgame then land on the single free child. Without pinning a
leak request can reach a child that has no stale decoder state and returns 502.

## Proof directory

The endgame command writes `out/p1` relative to the pool's `chdir`; create and
make it writable before the run, otherwise a successful `zif_system` looks
like a failure:

```bash
mkdir -p /srv/www/out && chmod 777 /srv/www/out
```


## Pages

| Page | Purpose |
|---|---|
| `app.php` | `session_start()` + reflects session values; the consumer target |
| `bigvar.php` | writes k0..k3 + a 4MB value; the post-RINIT OOM producer |
| `ref.php` | writes a session with `R:2`; the reference hook |
| `../www/pin.php` | long-running page used to pin children in multi-worker layouts |
