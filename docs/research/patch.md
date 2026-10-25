# Patch and version boundary

The vulnerabilities were fixed in PHP 8.2.35, 8.3.36, 8.4.27 and 8.5.12.
The fix adds `php_basic_early_rinit()` before request-body parsing, which
resets the session/unserialize state that the chains depend on.

## Gates in this toolkit

- `PATCHED_AT = {"8.2": 35, "8.3": 36, "8.4": 27, "8.5": 12}`.
- A target at or above the fixed release is refused (exit 3) unless
  `--force` is used for a negative-control lab.
- Unknown builds are refused (exit 5) instead of guessing offsets.

## Chunked bodies

Since 8.2.35, PHP also fixes the `post_max_size` bypass for requests without a
`Content-Length`. On older versions, `Transfer-Encoding: chunked` makes
`SG(request_info).content_length == 0`, so the rfc1867 size guard does not
fire and a huge field can still OOM the worker.

## Negative controls

A patched build must produce:

- `--check` exit 3;
- with `--force`, no proof (stage 1 leak fails).

A toolkit that cannot show this is not measuring the patch, only the target.
