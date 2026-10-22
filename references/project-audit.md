# Project deep dive and cross-project isolation

Inspect every authorized project, or report it as unassessed. Work by risk first, not alphabetical order. A deep dive is not a full recursive dump; trace meaningful paths and record coverage.

## Project profile

Identify repository/deployed release relationship, entry points, framework/CMS hints, dependency lockfiles, document root, deployment owner, worker identity, data sensitivity, business-critical flows and public/internal boundaries. Do not execute `artisan`, CMS CLI, Composer scripts, project test suites or application bootstrap simply to discover framework information: they can load untrusted code or touch real services.

Reading a lockfile is preferable to running application code. Dependency analysis tools may send package metadata to external services; obtain egress approval, review exactly what is sent, and use appropriate no-plugin/no-script modes when supported. Never run dependency install/update as part of an audit. A dependency advisory match does not prove a reachable application exploit.

## Review areas

| Area | Evidence to seek | Safe validation boundary |
|---|---|---|
| Authentication/session | Login/session lifecycle, cookie settings, reset/token handling, intended trust boundaries | Test accounts only; no brute force or real-user takeover |
| Authorization/tenancy | Server-side object/tenant checks, route-to-policy linkage, admin boundaries | Source review first; synthetic records in approved staging |
| Input and sensitive sinks | SQL construction, command execution, file inclusion, deserialization, template/render paths, SSRF flows | Trace source-to-sink and safeguards; no production payload execution |
| Uploads/files | Type validation, path control, storage outside executable roots, size limits, server handlers | No production upload without separate approval |
| Exposed material | Document root, debug routes, backup/config source exposure, repository metadata | Do not fetch secret-bearing files to prove exposure; config/metadata first |
| Dependency/config | Exact deployed version/provenance, security config and environment precedence | No package updates or secret dumps |
| Outbound integrations | Email/broadcast, payments, webhooks, jobs and external API side effects | Never submit real broadcasts, purchases or external callbacks |
| Operational boundaries | Queue workers, cron, deployment artifacts, admin tools, private endpoints | Preserve production state and tenant scope |

For each proposed application finding, reconstruct: entry point -> identity/authorization -> data source -> validation -> transformation -> sink -> business impact. Check middleware, framework APIs and deployment config before concluding.

## Cross-project blast-radius map

Build metadata-backed edges for shared OS users/groups, writable code roots, shared FPM pools/sockets, upload/tmp/session locations, mounted volumes, deployment keys, runtime images and administrative services. Avoid collecting credential values. Distinguish shared hosting architecture from proven access; shared UID alone is a risk lead, not evidence that every resource is accessible.

Review file owner/mode and applicable ACL, namespace/container isolation and mandatory-access controls where permitted. Do not read project B's secrets or connect to its database merely to prove project A might reach it. Request separate tenant authorization where needed.

Report a runtime finding once with affected projects listed. Separately report evidence-supported isolation weaknesses that could expand impact. Do not claim lateral movement succeeded unless a separately approved, non-destructive controlled test actually demonstrated the specified access.

## Forgotten deployments

Check discovered old releases, staging subdomains, default vhosts, preview apps, admin utilities and rollback images. Distinguish files present from routed and reachable applications. An inactive directory might be deployment hygiene, not an internet vulnerability.

## Coverage definition

For each project track configuration, source review, dependency review, authorization review, business-side-effect review, logs, runtime verification and controlled validation separately. Each cell is assessed / partial / blocked / not applicable / not assessed, with evidence and reason. Never compress partial coverage into an unexplained green score.
