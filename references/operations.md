# Change control and post-fix validation

Audit permission is not patch permission. Do not upgrade, restart, edit configuration, install scanners, enable request-body logging, create public diagnostic pages, kill processes, rotate credentials or change firewall rules during discovery.

## Remediation plan before execution

Specify affected runtime/build/vendor stream, all mapped dependent projects, exact intended change, expected impact, operator approval, maintenance constraints, backup/snapshot state, rollback path and health checks. Use current authoritative instructions for the observed OS/panel/build; do not paste a generic package command across all environments.

If an incident is suspected, coordinate evidence preservation and containment before modifications. Never silently preserve a known-vulnerable rollback image as “safe”; document the risk and make rollback an explicit operational decision.

## Three-part patch proof

**Build proof:** installed package/build provenance matches the source's fixed status for the platform.

**Process proof:** serving workers and loaded modules use the expected build; no relevant old/deleted worker/module remains unexplained. Check all pools, embedded runtimes, detached LSAPI processes and replicas as applicable.

**Route proof:** every enumerated in-scope domain/route is still mapped to the verified runtime; an approved benign health check observes the expected service. A response alone cannot prove absence of memory corruption.

A source-control patch, successful package command, green deployment job, CLI version, or service restart alone satisfies none of the full chain.

## Re-test

Compare to the baseline: error rate/log window, worker state, relevant settings, all replicas, application behavior and only approved test flows. Do not send real broadcasts, charge real payments, delete data or replay production jobs. Report any regression, unverified runtime or deployment route explicitly.

## Recurring use

A later run must refresh sources and re-confirm target context. Reuse still-valid scope/answers but invalidate findings when runtime, image, route, permissions or deployment fingerprint changes. A diff can prioritize new risks; it cannot skip required verification for changed assets.

Scheduling or automatic background operation is outside this bundle. It must be separately configured and authorized by the user's agent/orchestration platform.
