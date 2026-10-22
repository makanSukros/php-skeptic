# PHP2Shell advisory module

**Research snapshot: 2026-10-22. Revalidate during every live assessment.**

This module is for exposure assessment and patch verification, not exploit execution. Do not hard-code the cached versions as an eternal complete advisory database. If official sources conflict, quote the discrepancy, timestamps and affected package stream; leave the decision open until reconciled.

## Primary sources

- PHP announcement, dated 2026-10-21: <https://www.php.net/archive/2026.php>
- CVE-2026-109618, PHP advisory: <https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w>
- CVE-2026-109619, PHP advisory: <https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp>
- Ubuntu vendor status example: <https://ubuntu.com/security/CVE-2026-109618>
- Ubuntu second-CVE status: <https://ubuntu.com/security/CVE-2026-109619>
- Red Hat vendor status: <https://access.redhat.com/security/cve/cve-2026-109618> and <https://access.redhat.com/security/cve/cve-2026-109619>
- CloudLinux package stream/status: <https://blog.cloudlinux.com/php-cve-2026-109618-and-cve-2026-109619>

Read the official source for the actual OS/repository/package stream. Vendor announcements may update rapidly. Do not use a search snippet as the only evidence for a disruptive change.

## Cached upstream fixes

| PHP branch | First fixed upstream release in this snapshot |
|---|---|
| 8.2 | 8.2.35 |
| 8.3 | 8.3.36 |
| 8.4 | 8.4.27 |
| 8.5 | 8.5.12 |

The PHP announcement covers web-serving PHP including FPM, mod_php, CGI, FrankenPHP and LiteSpeed. It reports particularly high risk for mod_php. The assessment must follow the effective runtime, not only the frontend brand.

Distribution and hosting packages can contain backports without matching those upstream version numbers. Match exact package release, OS release, architecture where relevant, repository/vendor and advisory. Unsupported upstream branches require vendor/source review; do not assume either patched or unpatched solely from age.

## CVE-specific assessment

**CVE-2026-109618:** PHP describes corruption associated with interrupted allocation/initialization during OOM handling. Inspect build applicability and effective memory/request controls. Do not intentionally exhaust memory to validate it. The advisory says a patched PHP release is the complete mitigation. Its emergency unlimited-PHP-memory workaround is incomplete and has resource-exhaustion implications; never apply it automatically or advertise it as a fix. Request-size and host resource controls are separate review items.

**CVE-2026-109619:** PHP describes request state surviving after the associated memory is freed and later use by a worker. Inspect build applicability and worker lifecycle. Disabling session upload progress only addresses the documented session path, not all lifecycle variants. Treat any additional version-specific mitigation as a partial, source-verified control; confirm the pre-request effective context and worker replacement. Do not poison worker state to test this on production.

## Evidence chain for each runtime

1. Identify the exact serving route, SAPI/handler, process/module/container and build origin.
2. Match an authoritative upstream/vendor advisory to that exact build and platform.
3. Record installed-build status independently from active-worker status.
4. Inspect relevant effective config and overrides; stored config alone is not proof of a running setting.
5. Record reachability and applicable preconditions as observed/absent/unknown without claiming exploitability from branding or a banner.
6. Verify all relevant pools, detached processes, replicas and alternate handlers after authorized patching. A restart command returning zero is insufficient evidence by itself.

## Allowed decisions

`affected-build-observed`, `vendor-patched-build-observed`, `upstream-fixed-build-observed`, `mitigation-only`, `needs-vendor-verification`, `running-state-unverified`, `route-unmapped`, `not-applicable-with-evidence`, and `unknown` are descriptive statuses. Combine them across separate dimensions; do not force one label to represent everything.

An affected build can be reported as a vulnerability finding without proving code execution. Record “RCE not attempted” rather than “confirmed exploitable.” A proven patched build does not imply the application has no other weaknesses or the host was never compromised.

## Offline helper

`php_version_hint.py` deliberately emits only candidate build hints. Vendor or unknown provenance cannot become “safe” through numeric comparison. Unknown branches, ambiguous strings and prereleases are unverified. The utility does not fetch sources, verify signatures, inspect workers or evaluate application prerequisites.
