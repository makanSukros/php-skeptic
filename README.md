# PHP Skeptic

> Evidence-first PHP security assessment for real servers: discover the environment, inspect logs, map every project to the runtime that actually serves it, challenge every finding, and never turn missing evidence into a fake “safe” verdict.

PHP Skeptic is a reusable **AI-agent security testing skill** for authorized PHP environments. It is designed for messy production estates where one server may contain multiple projects, several PHP versions, shared pools, containers, panels, legacy deployments, and different web stacks at the same time.

It starts with **environment + log discovery** before deeper testing, supports stack-specific investigation across **Nginx, Apache, LiteSpeed/OpenLiteSpeed, PHP-FPM, LSAPI/LSPHP, CGI, FrankenPHP, containers and mixed deployments**, and produces findings that separate observation, inference, uncertainty, and proof.

The initial research focus includes **CVE-2026-109618** and **CVE-2026-109619**, but the workflow is intentionally broader than a two-CVE scanner.

## Why this exists

Security agents often fail in predictable ways:

- they check `php -v` and assume it is the runtime serving the website;
- they inspect one project and miss five others on the same machine;
- they call an old version vulnerable without checking vendor backports;
- they treat “permission denied” or missing logs as a pass;
- they confuse a suspicious log line with proof of exploitation;
- they read configuration on disk without proving that workers actually loaded it;
- they produce impressive-looking reports with blind spots hidden behind a green score;
- they try dangerous validation against production when evidence-based verification would be enough.

PHP Skeptic is built to resist those failure modes.

## Core idea: prove the serving path

Instead of asking only “which PHP version is installed?”, the skill tries to establish the real path:

```text
Internet / internal client
        ↓
CDN / load balancer / reverse proxy
        ↓
Nginx / Apache / LiteSpeed / other frontend
        ↓
vhost + route + document root
        ↓
PHP handler / socket / service / container
        ↓
running worker / module
        ↓
actual PHP build + package provenance
        ↓
project + OS identity + shared resources
```

Every important edge should be **observed, inferred, or unresolved**. Unknown does not mean safe.

## What it does

### 1. Environment-first discovery

Before deep testing, the agent establishes:

- target identity and whether the terminal is really on the intended server;
- host vs container context;
- OS and package provenance;
- web/PHP processes and listeners;
- services and workers;
- health headroom and operational constraints;
- available logs, retention, rotation, and time zone;
- candidate project roots and deployment metadata.

### 2. Log-first triage

Logs are inspected early and with bounded reads. The goal is to identify signals that may require incident handling before generating more traffic.

A log match is an **investigation lead**, not automatic proof of a CVE or compromise. Missing/rotated logs are recorded as coverage gaps.

### 3. Multi-project estate mapping

PHP Skeptic is intentionally designed for servers containing many projects. It correlates multiple views instead of equating “folder exists” with “application is deployed”:

- vhost and routing configuration;
- PHP handlers and pools;
- active services and workers;
- approved filesystem roots;
- container metadata;
- hosting-panel selectors;
- cron/queue workers;
- shared users, sockets, volumes and runtimes.

This makes cross-project risk visible—for example, four applications sharing one PHP pool or two tenants unexpectedly sharing an OS identity.

### 4. Runtime and advisory verification

For each discovered runtime, the skill separates:

- installed build state;
- vendor/backport state;
- currently serving worker state;
- route/replica coverage;
- exploit preconditions;
- compensating controls;
- unresolved contradictions.

A CLI version is never automatically promoted to a web-runtime verdict. A patched package on disk is not enough if stale workers are still serving the old build.

### 5. Project deep dive

Once the estate is mapped, the workflow can continue into authorized project review, including:

- authentication and authorization boundaries;
- input → validation → transformation → sensitive sink tracing;
- upload/file handling;
- dependency and configuration risks;
- tenant isolation;
- shared runtime/file/identity exposure;
- dangerous business-side effects;
- framework- and application-specific attack surfaces.

### 6. Skeptical finding review

Every actionable finding should survive a second question:

> **What evidence would disprove this finding?**

Possible counter-evidence includes a vendor backport, unreachable route, inactive config, different serving worker, missing precondition, ACL boundary, upstream routing behavior, or valid business rule.

Contradictions stay open until resolved.

## Supported environment patterns

| Environment | Investigation focus |
|---|---|
| Nginx + PHP-FPM | vhost → `fastcgi_pass` → pool/socket/service → running workers |
| Apache | `mod_php`, proxy/FPM, CGI, vhost and module context |
| LiteSpeed / OpenLiteSpeed | LSAPI/LSPHP, per-vhost handler, panel/selector behavior |
| FrankenPHP / Caddy | embedded/worker runtime, serving build and process context |
| Containers | route → container/replica → image/digest → PHP inside the workload |
| Hosting panels | effective per-domain runtime, not merely the panel default |
| Mixed / unknown stacks | discovery first; unsupported assumptions are reported, not invented |

This is a **workflow and evidence framework**, not a claim that every vendor integration has been live-tested.

## Current PHP2Shell research focus

The bundled reference material includes a dated assessment snapshot for:

- `CVE-2026-109618` — PHP remote-code-execution risk involving out-of-memory corruption
- `CVE-2026-109619` — PHP remote-code-execution risk involving stale global state

Real assessments must refresh upstream and vendor advisories. Distribution packages can backport security fixes while retaining older-looking version numbers.

PHP Skeptic deliberately does **not** include a production RCE payload, deliberate OOM trigger, state-poisoning exploit, or request-flood validator.

## Safety model

The default posture is **bounded + read-only + evidence-first**.

The skill explicitly forbids automatic actions such as:

- production RCE/OOM exploitation;
- request floods or destructive validation;
- privilege escalation;
- silently installing tools;
- restarting or patching services without authorization;
- reading secrets simply because filesystem access exists;
- sending email/WhatsApp broadcasts;
- charging payments or triggering real transactions;
- deleting accounts/data;
- firing production webhooks/queues;
- treating out-of-scope projects as authorized targets.

Security testing still has operational impact. Use only on systems you own or are explicitly authorized to assess.

## Quick start

Load `SKILL.md` into an agent that supports reusable instruction/skill files, then give it access only to the authorized environment.

Example prompt:

```text
Use PHP Skeptic to audit this authorized PHP server.

First verify that the current terminal is actually the target server. Start with
bounded environment discovery and log triage. Discover every in-scope project
and map each route through Nginx/Apache/LiteSpeed/other frontend to the PHP
runtime and running workers that really serve it.

Verify current official/vendor advisory status, including backports. Deep-dive
each confirmed project and shared isolation boundary. Challenge every finding
with counter-evidence before reporting it.

Start read-only. Do not patch, restart, exploit RCE/OOM, send broadcasts,
perform real transactions, mutate customer data or test out-of-scope tenants.
Anything not actually verified must remain unknown/unassessed, not safe.
```

## Included helpers

The helper scripts use Python's standard library and are deliberately narrow.

| Helper | Purpose | Does **not** prove |
|---|---|---|
| `scripts/collect_metadata.py` | bounded Linux metadata/process inventory, project candidates and optional explicit log samples | full topology, framework identity, patch status |
| `scripts/triage_logs.py` | bounded tail analysis with signal counts and sample hashing | compromise, CVE attribution, historical completeness |
| `scripts/php_version_hint.py` | conservative offline comparison with the cached upstream snapshot | vendor backports, running-worker status, exploitability |

Example:

```bash
python3 scripts/collect_metadata.py --acknowledge-target \
  --root /srv/apps --root /var/www \
  --log /var/log/nginx/error.log \
  --max-seconds 15 --max-entries 15000 \
  --output /approved/private-reports/discovery.json

python3 scripts/triage_logs.py --acknowledge-target \
  --path /var/log/php8.3-fpm.log \
  --max-bytes 1048576 --max-lines 2000 \
  --output /approved/private-reports/php-log-triage.json

python3 scripts/php_version_hint.py \
  --version 8.3.36 --provenance upstream
```

Review helper source before execution. Output may contain sensitive infrastructure metadata even when secret values are intentionally avoided.

## Assessment workflow

```text
0. Confirm authorization + target
              ↓
1. Environment discovery + log triage
              ↓
2. Reconcile projects, routes, runtimes and workers
              ↓
3. Refresh upstream/vendor vulnerability intelligence
              ↓
4. Prioritize + deep-dive every in-scope project
              ↓
5. Try to disprove each finding
              ↓
6. Optional separately-authorized controlled validation
              ↓
7. Report coverage, evidence, unknowns and remediation
              ↓
8. Re-test after authorized changes
```

## Repository layout

```text
php-skeptic/
├── SKILL.md
├── README.md
├── agents/
│   └── openai.yaml
├── references/
│   ├── advisory-snapshot.json
│   ├── blindspots.md
│   ├── discovery.md
│   ├── evidence.md
│   ├── evaluation.md
│   ├── log-triage.md
│   ├── operations.md
│   ├── php2shell.md
│   └── project-audit.md
├── scripts/
│   ├── collect_metadata.py
│   ├── common.py
│   ├── php_version_hint.py
│   └── triage_logs.py
├── templates/
│   ├── asset-graph.json
│   ├── coding-agent-handoff.md
│   ├── engagement.json
│   ├── finding.json
│   └── report.md
├── tests/
│   └── test_helpers.py
├── MANIFEST.json
├── VALIDATION.md
└── TEST-RESULTS.txt
```

## Validation

Run the offline helper tests with:

```bash
python3 -m unittest discover -s tests -v
```

The bundled tests cover synthetic filesystem/log behavior, bounded reads, conservative version hints, path protections and package consistency. They do **not** prove compatibility with every live Apache/Nginx/LiteSpeed/panel deployment and do not constitute CVE exploit validation.

See:

- `TEST-RESULTS.txt` for the recorded build-time test run;
- `VALIDATION.md` for validation notes;
- `references/evaluation.md` for behavioral evaluation scenarios.

## Reporting philosophy

A useful result is not “all green.” A useful result tells you:

- exactly what was observed;
- which projects and runtimes were actually covered;
- what evidence supports each conclusion;
- which assumptions remain unresolved;
- which evidence could falsify a finding;
- what must be fixed first;
- how to prove the fix worked without pretending the server is “100% secure.”

**PHP Skeptic is intentionally skeptical—even of its own findings.**
