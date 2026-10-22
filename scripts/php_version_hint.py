#!/usr/bin/env python3
"""Offline upstream version hints, deliberately not deployment/CVE clearance."""
from __future__ import annotations

import sys
sys.dont_write_bytecode = True

import argparse
import json
from pathlib import Path
import re
from typing import Any

SNAPSHOT_PATH = Path(__file__).resolve().parents[1] / 'references' / 'advisory-snapshot.json'


def version_hint(version: str, provenance: str = 'unknown') -> dict[str, Any]:
    if provenance not in {'upstream', 'vendor', 'unknown'}:
        raise ValueError('Unsupported provenance.')
    with SNAPSHOT_PATH.open(encoding='utf-8') as f:
        snapshot = json.load(f)
    out = {
        'input_version': version, 'provenance_asserted_by_caller': provenance,
        'advisory_snapshot_date': snapshot['checked_date'],
        'sources': snapshot['sources'], 'live_sources_verified': False,
        'running_worker_status': 'unverified', 'route_status': 'unverified',
        'exploitability': 'not_tested', 'candidate_build_status': 'unknown',
        'warning': 'An offline hint is not verified vendor, deployment or exploitability status. Refresh official advisories and establish provenance.',
    }
    if provenance == 'vendor':
        return {**out, 'candidate_build_status': 'needs_vendor_verification', 'reason': 'Compare the exact package release and platform to the vendor advisory; upstream numeric comparison is insufficient.'}
    match = re.fullmatch(r'(\d+)\.(\d+)\.(\d+)', version.strip())
    if not match:
        return {**out, 'reason': 'Ambiguous, suffixed or prerelease version; verify exact build provenance.'}
    if provenance == 'unknown':
        return {**out, 'candidate_build_status': 'needs_provenance_verification', 'reason': 'The serving build provenance has not been established.'}
    parts = tuple(map(int, match.groups()))
    branch = f'{parts[0]}.{parts[1]}'
    fixed = snapshot['upstream_first_fixed'].get(branch)
    if fixed is None:
        return {**out, 'reason': 'Branch is not covered by this cached upstream-fix map; consult current upstream/vendor sources.'}
    minimum = tuple(map(int, fixed.split('.')))
    return {
        **out, 'branch': branch, 'cached_upstream_first_fixed': fixed,
        'candidate_build_status': 'matches_cached_fixed_range' if parts >= minimum else 'below_cached_upstream_fix',
        'reason': 'Numerical upstream-release hint only; caller provenance is not independently verified.',
    }


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--version', required=True)
    ap.add_argument('--provenance', choices=['upstream', 'vendor', 'unknown'], default='unknown')
    args = ap.parse_args(argv)
    print(json.dumps(version_hint(args.version, args.provenance), indent=2, ensure_ascii=True))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
