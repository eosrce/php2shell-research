# CMS / application builds

CMS images change the baseline heap and the A1 OOM site. The toolkit ships
presets as **data**, not as a generic application exploit.

## Observed matrix (summary)

| Image family | Result |
|---|---|
| MediaWiki 1.43.9 (8.3.35 / 128M / 150w) | `RCE-INBAND` with 149-worker pin |
| WordPress 6.8.3 / PHP 8.4.15 | gap: A1 OOM in `php_var_unserialize_init` (decode), not `php_session_reset_id` |
| Roundcube | gap: A1 OOM allocation 20480 |
| Drupal | gap: A does not OOM at 132MB chunked field |
| Matomo / Nextcloud / phpMyAdmin / Joomla / PrestaShop | gap: worker/geometry/application coverage |

## WordPress A1 root cause

The A1 shape's OOM stack ends in:

```text
zend_mm_safe_error <- zend_mm_alloc_pages <- _emalloc_large
  <- php_var_unserialize_init          (8.2KB php_unserialize_data)
  <- ps_srlzr_decode_php <- php_session_decode
  <- php_session_initialize <- php_session_rfc1867_callback
```

`php_session_initialize()` order is:

```text
s_open -> s_create_sid -> php_session_reset_id (url_encode 4096) -> s_read -> decode
```

The OOM is after `reset_id`, so `send_cookie` is cleared and the stale `PS(id)`
needed by B1 never forms. The `4096` seen in some logs is
`php_sapi_filter` (parse path), not `url_encode`.

## Next research step

Do not scan total memory. The hypothesis is the **`bin 128` state**:
`zend_string_safe_alloc(3, 32)` is 96 bytes (bin 128). If that bin has a free
slot, `url_encode` succeeds even when the page is exhausted. The calibration
should observe `zend_mm` bin/page state, or pre-fill the 96–128 byte bin with
resident strings so `url_encode` must request a new page.
