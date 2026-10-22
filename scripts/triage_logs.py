#!/usr/bin/env python3
"""Bounded generic log triage. No raw log lines and no CVE verdicts."""
from __future__ import annotations

import sys
sys.dont_write_bytecode = True

import argparse
import hashlib
import os
from pathlib import Path
import re
from typing import Any

from common import error_record, positive_int, regular_file, utc_now, write_report

SIGNALS = {
    'php_memory_exhaustion': re.compile(r'allowed memory size\s+of\s+\d+\s+bytes exhausted', re.I),
    'generic_oom': re.compile(r'out[ -]of[ -]memory|oom[ -]kill|cannot allocate memory', re.I),
    'worker_crash': re.compile(r'segmentation fault|sigsegv|signal\s+11\b|core dumped', re.I),
    'php_fatal_error': re.compile(r'php\s+fatal\s+error', re.I),
    'upstream_failure': re.compile(r'upstream prematurely closed|failed to read fastcgi header|connection reset by peer', re.I),
    'upload_progress_mention': re.compile(r'php_session_upload_progress|session\.upload_progress', re.I),
}
COMPRESSED_SUFFIXES = {'.gz', '.xz', '.bz2', '.zip', '.zst', '.7z'}


def scan_log(path: str | Path, max_bytes: int = 1048576, max_lines: int = 2000) -> dict[str, Any]:
    if not 1 <= max_bytes <= 16 * 1024 * 1024 or not 1 <= max_lines <= 100000:
        raise ValueError('Log budget exceeds supported bounds.')
    p = Path(path)
    base: dict[str, Any] = {
        'source': str(p), 'observed_at_utc': utc_now(),
        'cve_verdict': 'not_assessed', 'compromise_verdict': 'not_assessed',
        'max_bytes': max_bytes, 'max_lines': max_lines,
        'raw_lines_included': False,
    }
    if p.suffix.lower() in COMPRESSED_SUFFIXES:
        return {**base, 'status': 'unsupported_compressed_file', 'coverage_gap': True}
    try:
        with regular_file(p) as f:
            before = os.fstat(f.fileno())
            start = max(0, before.st_size - max_bytes)
            f.seek(start)
            data = f.read(min(before.st_size, max_bytes))
            after = os.fstat(f.fileno())
    except (OSError, ValueError) as exc:
        return {**base, 'status': 'not_read', 'error': error_record(exc), 'coverage_gap': True}
    changed = (before.st_size, before.st_mtime_ns) != (after.st_size, after.st_mtime_ns)
    meta = {
        'file_size_at_start': before.st_size, 'file_inode': before.st_ino,
        'file_device': before.st_dev, 'read_offset_bytes': start,
        'bytes_read': len(data), 'raw_sample_sha256': hashlib.sha256(data).hexdigest(),
        'changed_during_read': changed,
    }
    if b'\x00' in data or data.startswith((b'\x1f\x8b', b'PK\x03\x04', b'\xfd7zXZ')):
        return {**base, **meta, 'status': 'unsupported_binary_sample', 'coverage_gap': True}
    chunks = data.splitlines(keepends=True)
    dropped_leading = bool(start and chunks)
    skipped_bytes = 0
    if dropped_leading:
        skipped_bytes += len(chunks.pop(0))
    available = len(chunks)
    if available > max_lines:
        skipped_bytes += sum(map(len, chunks[:-max_lines]))
        chunks = chunks[-max_lines:]
    inspected = b''.join(chunks)
    signals: dict[str, dict[str, int]] = {}
    for number, line in enumerate(chunks, start=1):
        text = line.decode('utf-8', errors='replace')
        for name, regex in SIGNALS.items():
            if regex.search(text):
                item = signals.setdefault(name, {'matching_lines': 0, 'first_sample_line': number, 'last_sample_line': number})
                item['matching_lines'] += 1
                item['last_sample_line'] = number
    sampled = bool(start or available > max_lines)
    return {
        **base, **meta, 'status': 'sampled',
        'sampled_not_full_log': sampled,
        'coverage_gap': bool(sampled or changed),
        'leading_line_discarded_conservatively': dropped_leading,
        'trailing_line_may_be_partial': bool(chunks and not chunks[-1].endswith(b'\n')),
        'available_sample_lines': available, 'lines_scanned': len(chunks),
        'inspected_offset_bytes': start + skipped_bytes,
        'inspected_bytes': len(inspected),
        'inspected_sha256': hashlib.sha256(inspected).hexdigest(),
        'signals': signals,
        'interpretation': 'Generic diagnostic leads only. No matches does not establish absence of exploitation. Sample line numbers are not original file line numbers.',
    }


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--acknowledge-target', action='store_true', help='Acknowledge that these exact files and this session are authorized.')
    ap.add_argument('--path', action='append', required=True)
    ap.add_argument('--max-bytes', type=positive_int, default=1048576)
    ap.add_argument('--max-lines', type=positive_int, default=2000)
    ap.add_argument('--output', help='New report file in an existing private directory; otherwise metadata JSON on stdout.')
    args = ap.parse_args(argv)
    if not args.acknowledge_target:
        ap.error('Confirm target and scope first, then provide --acknowledge-target.')
    if len(args.path) > 16:
        ap.error('At most 16 exact log paths per invocation.')
    if args.max_bytes > 16 * 1024 * 1024 or args.max_lines > 100000:
        ap.error('Budget too large; use a separate approved analysis plan.')
    report = {
        'schema_version': '1.0', 'helper_version': '0.1.0',
        'mode': 'bounded_local_log_triage', 'collected_at_utc': utc_now(),
        'logs': [scan_log(p, args.max_bytes, args.max_lines) for p in dict.fromkeys(args.path)],
    }
    try:
        write_report(report, args.output)
    except (OSError, ValueError) as exc:
        print('Report not written: ' + type(exc).__name__, file=sys.stderr)
        return 2
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
