#!/usr/bin/env python3
"""Linux-only, bounded metadata collection for an explicitly approved local host.

Not a complete topology scanner. No application code, shell commands or network
requests are executed. Candidate discovery is not an adversarial filesystem sandbox.
"""
from __future__ import annotations

import sys
sys.dont_write_bytecode = True

import argparse
from collections import Counter, deque
import os
from pathlib import Path
import re
import stat
import time
from typing import Any

from common import directory_fd, error_record, positive_int, utc_now, write_report
from triage_logs import scan_log

MARKERS = {'composer.json', 'composer.lock', 'artisan', 'wp-config.php', 'wp-load.php', 'index.php', 'phpunit.xml', 'phpunit.xml.dist'}
EXCLUDED_DIRS = {'.git', '.svn', 'node_modules', 'vendor', 'cache', 'caches', 'logs', 'backups', 'uploads', '__pycache__'}
PROCESS_PATTERN = re.compile(r'^(?:php|lsphp|nginx|apache2|httpd|lshttpd|litespeed|openlitespeed|caddy|frankenphp|docker|containerd|podman)', re.I)


def discover_candidates(root: str | Path, max_entries: int = 15000, max_depth: int = 6,
                        deadline: float | None = None, max_candidates: int = 1000) -> dict[str, Any]:
    """Names/metadata only, no file content. Never regard candidates as deployments."""
    if max_entries < 1 or max_depth < 0 or max_candidates < 1:
        raise ValueError('Invalid discovery budget.')
    p = Path(root)
    if not p.is_absolute():
        return {'root': str(p), 'status': 'not_scanned', 'reason': 'Provide an explicit absolute root.'}
    if p == Path('/'):
        return {'root': str(p), 'status': 'not_scanned', 'reason': 'Whole-filesystem crawling is prohibited.'}
    try:
        with directory_fd(p) as fd:
            root_stat = os.fstat(fd)
    except (OSError, ValueError) as exc:
        return {'root': str(p), 'status': 'not_scanned', 'error': error_record(exc)}
    limit = deadline if deadline is not None else time.monotonic() + 15
    queue = deque([(p, 0)])
    result: dict[str, Any] = {'root': str(p), 'status': 'bounded_metadata_discovery', 'entries_seen': 0,
                              'directories_seen': 0, 'candidates': [], 'skip_counts': {}, 'errors': [],
                              'complete_estate_inventory': False, 'budget_exhausted': False}
    skipped: Counter[str] = Counter()
    while queue:
        if time.monotonic() >= limit or result['entries_seen'] >= max_entries or len(result['candidates']) >= max_candidates:
            result['budget_exhausted'] = True
            break
        current, depth = queue.popleft()
        markers: set[str] = set()
        php_file_seen = False
        try:
            # Recheck all components, but no claim of safety against concurrent renames.
            with directory_fd(current) as fd:
                st = os.fstat(fd)
                if st.st_dev != root_stat.st_dev:
                    skipped['different_filesystem'] += 1
                    continue
                result['directories_seen'] += 1
                with os.scandir(fd) as entries:
                    for entry in entries:
                        if result['entries_seen'] >= max_entries or time.monotonic() >= limit:
                            result['budget_exhausted'] = True
                            break
                        result['entries_seen'] += 1
                        try:
                            if entry.is_symlink():
                                skipped['symlink'] += 1
                                continue
                            if entry.is_dir(follow_symlinks=False):
                                if entry.name in EXCLUDED_DIRS:
                                    skipped['excluded_directory'] += 1
                                elif depth >= max_depth:
                                    skipped['depth_limit'] += 1
                                elif len(queue) >= max_entries:
                                    skipped['queue_limit'] += 1
                                    result['budget_exhausted'] = True
                                else:
                                    queue.append((current / entry.name, depth + 1))
                            elif entry.is_file(follow_symlinks=False):
                                if entry.name in MARKERS:
                                    markers.add(entry.name)
                                if entry.name.lower().endswith('.php'):
                                    php_file_seen = True
                        except OSError as exc:
                            skipped['entry_error'] += 1
                            if len(result['errors']) < 20:
                                result['errors'].append({'directory': str(current), **error_record(exc)})
            if markers or php_file_seen:
                result['candidates'].append({'directory': str(current), 'markers': sorted(markers),
                    'php_filename_seen': php_file_seen, 'uid': st.st_uid, 'gid': st.st_gid,
                    'mode': oct(stat.S_IMODE(st.st_mode)), 'deployment_status': 'unconfirmed',
                    'file_contents_read': False})
        except (OSError, ValueError) as exc:
            skipped['directory_error'] += 1
            if len(result['errors']) < 20:
                result['errors'].append({'directory': str(current), **error_record(exc)})
    result['skip_counts'] = dict(skipped)
    result['pending_directories'] = len(queue)
    result['limitations'] = ['Filename hints are not confirmed projects.', 'Excluded directories, depth/time/entry bounds and inaccessible paths reduce coverage.', 'No runtime versions or configuration semantics are inferred.']
    return result


def read_known_proc(path: str, limit: int = 32768) -> str:
    # Only called with fixed /proc files or numeric /proc/PID paths, never user paths.
    with open(path, 'rb') as f:
        return f.read(limit).decode('utf-8', errors='replace')


def host_metadata(deadline: float) -> dict[str, Any]:
    u = os.uname()
    out: dict[str, Any] = {'observed_at_utc': utc_now(), 'system': u.sysname,
        'kernel_release': u.release, 'architecture': u.machine, 'hostname': u.nodename,
        'effective_uid': os.geteuid(), 'effective_gid': os.getegid(),
        'target_identity_requires_operator_confirmation': True,
        'processes': [], 'processes_examined': 0, 'process_errors': 0, 'gaps': []}
    try:
        mem = {}
        for line in read_known_proc('/proc/meminfo').splitlines():
            key, _, val = line.partition(':')
            if key in {'MemTotal', 'MemAvailable', 'SwapTotal', 'SwapFree'}:
                mem[key + '_kib'] = int(val.strip().split()[0])
        out['memory'] = mem
    except (OSError, ValueError, IndexError):
        out['gaps'].append('memory_metadata_unavailable')
    try:
        out['load_average'] = [float(v) for v in read_known_proc('/proc/loadavg', 1024).split()[:3]]
    except (OSError, ValueError):
        out['gaps'].append('load_metadata_unavailable')
    try:
        with os.scandir('/proc') as pids:
            for entry in pids:
                if not entry.name.isdigit():
                    continue
                if out['processes_examined'] >= 4096 or time.monotonic() >= deadline:
                    out['gaps'].append('process_inventory_budget_exhausted')
                    break
                out['processes_examined'] += 1
                pid = entry.name
                try:
                    name = read_known_proc(f'/proc/{pid}/comm', 256).strip()
                    if not PROCESS_PATTERN.search(name):
                        continue
                    item: dict[str, Any] = {'pid': int(pid), 'comm': name, 'runtime_version': 'unverified'}
                    for line in read_known_proc(f'/proc/{pid}/status', 16384).splitlines():
                        key, _, val = line.partition(':')
                        if key in {'Uid', 'Gid', 'PPid'}:
                            item[key.lower()] = val.strip()
                    try:
                        item['executable_link'] = os.readlink(f'/proc/{pid}/exe')
                    except OSError:
                        item['executable_link'] = 'unavailable'
                    out['processes'].append(item)
                except OSError:
                    out['process_errors'] += 1
    except OSError:
        out['gaps'].append('proc_inventory_unavailable')
    out['limitations'] = ['No command-line arguments, environment values, loaded modules, listeners or container-daemon data collected.', 'Process names/executable links do not establish deployed build provenance or vhost mappings.']
    return out


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--acknowledge-target', action='store_true')
    ap.add_argument('--root', action='append', default=[])
    ap.add_argument('--log', action='append', default=[])
    ap.add_argument('--max-seconds', type=positive_int, default=15)
    ap.add_argument('--max-entries', type=positive_int, default=15000)
    ap.add_argument('--max-depth', type=int, default=6)
    ap.add_argument('--max-log-bytes', type=positive_int, default=1048576)
    ap.add_argument('--max-log-lines', type=positive_int, default=2000)
    ap.add_argument('--output')
    args = ap.parse_args(argv)
    if not args.acknowledge_target:
        ap.error('Confirm the intended local server, scope and report destination; then provide --acknowledge-target.')
    if not sys.platform.startswith('linux'):
        ap.error('This collector supports Linux only. Use a documented native read-only adapter.')
    if not (1 <= args.max_seconds <= 120 and 1 <= args.max_entries <= 100000 and 0 <= args.max_depth <= 12):
        ap.error('Discovery budget exceeds supported limits.')
    if len(args.root) > 16 or len(args.log) > 16 or args.max_log_bytes > 4*1024*1024 or args.max_log_lines > 10000:
        ap.error('At most 16 roots/logs; per-log cap 4 MiB / 10000 lines.')
    start = time.monotonic()
    deadline = start + args.max_seconds
    report: dict[str, Any] = {'schema_version': '1.0', 'helper_version': '0.1.0',
        'mode': 'authorized_local_read_only_metadata', 'started_at_utc': utc_now(),
        'host': host_metadata(deadline), 'logs': [], 'roots': [], 'gaps': [],
        'limits': {'max_seconds': args.max_seconds, 'max_entries_total': args.max_entries,
                   'max_depth': args.max_depth, 'max_log_bytes': args.max_log_bytes,
                   'max_log_lines': args.max_log_lines}}
    # Initial log triage is deliberately before project enumeration.
    for path in dict.fromkeys(args.log):
        if time.monotonic() >= deadline:
            report['logs'].append({'source': path, 'status': 'not_read_time_budget', 'coverage_gap': True})
        else:
            report['logs'].append(scan_log(path, args.max_log_bytes, args.max_log_lines))
    if not args.log:
        report['gaps'].append('No explicit log sources supplied; discover/authorize sources through the log runbook.')
    remaining = args.max_entries
    for root in dict.fromkeys(args.root):
        if remaining < 1 or time.monotonic() >= deadline:
            report['roots'].append({'root': root, 'status': 'not_scanned_budget_exhausted'})
            continue
        result = discover_candidates(root, remaining, args.max_depth, deadline)
        report['roots'].append(result)
        remaining -= result.get('entries_seen', 0)
    if not args.root:
        report['gaps'].append('No approved project roots supplied; no filesystem project discovery performed.')
    report['elapsed_seconds'] = round(time.monotonic() - start, 3)
    report['completed_at_utc'] = utc_now()
    report['limitations'] = [
        'No vulnerability, exploitability, compromise or complete-coverage verdict is produced.',
        'Runbook checks are still required for OS/package provenance, sockets, configs, active mappings, modules, panel selectors, containers, replicas, source review and isolation.',
        'Wall-clock budgets are best-effort between operations; kernel-blocked filesystem reads cannot be interrupted by this helper.',
    ]
    try:
        write_report(report, args.output)
    except (OSError, ValueError) as exc:
        print('Report not written: ' + type(exc).__name__, file=sys.stderr)
        return 2
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
