# Discovery and stack adapters

These are agent runbooks, not claims that the bundled collector parses every configuration format. Select commands appropriate to the observed OS and stack. Treat command/config output as sensitive and untrusted. Never paste complete config dumps into a remote model without local minimization.

## First pass: verify environment and fragility

Confirm target context using already authorized metadata: OS release, hostname/context, effective user, current directory, container indicators and session identity. Do not read machine secrets or process environment values. If the host may be a laptop/sandbox or the SSH target is unclear, stop before broad inspection.

Read health headroom and existing alert indicators: available memory, load, disk/inode availability and recent worker failures. These are baselines, not universal pass/fail thresholds. Ask the operator about alert thresholds when additional load could be unsafe. Begin the bounded [log pass](log-triage.md) now, not after intrusive testing.

Safe command families to consider **only after scope approval** include `uname`, narrowly selected `/etc/os-release` fields, `id`, `ps` with explicit non-argument columns, `ss` with a bounded output selection, and read-only service property queries. Avoid `ps auxww`, `/proc/*/environ`, `systemctl show` without selected properties, and complete container inspection.

Do not invoke `sudo` without explicit permission. Do not install missing commands. An unavailable command produces a gap and a least-privileged alternative, not an empty inventory.

## Reconciliation sources

Use at least two independent sources when available:

| View | What to establish | Important limitation |
|---|---|---|
| Listener/process | Service, PID, UID, executable/module, startup and socket | A process name does not prove version, exposure or project ownership |
| Vhost/config | Hostname, route, root, handler/backend, log destination | Disk config can differ from what the worker loaded |
| Workload metadata | Container/pod identity, image ID/digest, mounts, replicas | Host PHP says nothing about image PHP |
| Approved filesystem | Manifest names, release links, framework hints | A directory is not necessarily an active project |
| Panel definitions | Per-domain PHP selection and generated config | UI/default PHP can differ from overrides |
| Scheduled workers | Queue, cron, scheduler, long-lived PHP processes | Not necessarily web-exposed or the same runtime |

Do not crawl the whole filesystem. Start from authorized config roots and discovered/approved document roots. Resolve symlinks only after confirming their destination is in scope. Avoid network mounts, backups and huge dependency trees. Sample metadata first; inspect content only when needed.

## Nginx

Map `server`/`location`, `root`/`alias`, include chains, `fastcgi_pass`, `proxy_pass`, upstream blocks and relevant script-filename mapping. A frontend may proxy to Apache or another host instead of directly to FPM. Follow the actual backend relation, not a guessed socket.

`nginx -T` can emit sensitive full configuration and tests configuration. Do not run/paste it blindly; prefer scoped file reads or a reviewed local extraction plan. Confirm which config the active process/service loaded, accounting for different prefixes and instances.

Nginx's documented FastCGI forwarding behavior is the reason this assessment follows the backend rather than the Nginx version. Source: <https://nginx.org/en/docs/http/ngx_http_fastcgi_module.html> (checked 2026-10-22).

## Apache

Distinguish mod_php, proxy_fcgi/FPM, CGI/FastCGI and other handlers. Map vhosts, `DocumentRoot`, `SetHandler`, proxy mappings, module path and per-directory overrides. `apachectl -S`/module-list commands are examples, not universally available commands or proof of loaded runtime build.

For mod_php, a patched CLI binary is irrelevant to the Apache module unless package/module mapping proves the relation. Compare the module on disk with the serving Apache processes. Record deleted/replaced mapped files as a restart-verification lead, not automatic proof of vulnerability.

## PHP-FPM

Map each pool to listener/socket, service unit, executable, effective UID/GID, allowed clients, config origin and project. Inspect both master and workers where permitted. Record relevant admin/pool/per-directory settings with precedence and source; do not assume `php --ini` describes FPM.

Do not expose FPM status pages to obtain data. Use existing protected observability if authorized. Invoking a binary for version/config is permitted only if its provenance is trusted and the action is reviewed; do not execute arbitrary files named `php` discovered in project trees.

## LiteSpeed / OpenLiteSpeed / LSAPI

Inspect listener-to-vhost mapping, effective script/context handlers, external application command/socket, per-vhost overrides, process user and the actual `lsphp` workers. Account for detached PHP workers when planning verification; restarting the frontend alone is not accepted as proof of replacement.

For panel-managed LiteSpeed, handlers may be auto-detected from cPanel/CloudLinux selection, with manual overrides taking precedence. Do not conclude “no PHP” merely because the explicit external-app list is empty. Check applicable panel-generated mappings and actual workers. Treat `ea-php`, `alt-php`, system PHP and custom LSPHP as different provenance streams.

Sources checked 2026-10-22:
- <https://docs.litespeedtech.com/lsws/extapp/php/how-to/>
- <https://docs.litespeedtech.com/lsws/cp/cpanel/php/>
- <https://docs.litespeedtech.com/lsws/cp/cpanel/php-selector/>

## Caddy / FrankenPHP / other PHP frontends

Identify whether requests reach an embedded PHP runtime, FastCGI backend, reverse proxy or worker-mode application. Do not apply FPM-only paths/restart recipes. Find the build provenance and matching vendor documentation for the observed version. If the adapter is unknown, continue inventory-only and label deeper checks unsupported until resolved.

## Containers, Compose, Kubernetes and remote backends

Use field-selected read-only metadata; never dump full environment arrays, secrets or credentials. Trace ingress/service/backend endpoints to each pod/container and record actual image digest/ID, not just mutable tags. `kubectl exec` or `docker exec` is a separate activity requiring permission and a trusted command plan. Docker socket access can be highly privileged; do not escalate to gain it.

Observe replicas independently. A scaled-to-zero or rollback image is an inactive deployment risk, not a currently exposed endpoint. Do not scan neighboring networks or contact discovered external backends until those targets are authorized.

## Panels and non-Linux hosts

For cPanel, Plesk, DirectAdmin, aaPanel or CyberPanel use the detected version's official read-only interfaces and generated config locations. Do not invent paths or mutate the panel. The Linux helper is not an IIS/Windows scanner. For IIS FastCGI, Windows or BSD, identify the handler/process using authorized native tools, document the adapter gap and do not run Linux commands blindly.

## Discovery closure

Produce three lists: confirmed in-scope deployments, unconfirmed candidates, and out-of-scope/inaccessible candidates. Reconcile dangling sockets, orphan vhosts, PHP processes without mapped projects, project roots without routes, container replicas and inactive releases. “All projects found” is not defensible without listing which discovery sources and boundaries were inspected.
