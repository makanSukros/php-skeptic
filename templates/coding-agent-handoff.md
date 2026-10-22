# Remediation handoff

## Objective and approved scope
<Specific outcome, authorized project/repository, environment, approved edits.>

## Evidence-backed problems
<Finding IDs, observed behavior/config, exact source paths/line ranges when verified, affected runtime/routes.>

## Required changes
<Minimal changes tied to findings. Separate PHP/vendor updates from application code changes. Do not guess package commands.>

## Forbidden actions
No real broadcasts, payments, customer mutations, production uploads, secret disclosure, unauthorized package installation/restarts, destructive tests or unrelated refactors. Do not change additional projects without approval.

## Tests
<Tests with synthetic data or isolated staging; positive and negative authorization cases; regression tests; expected results. Never claim unrun tests passed.>

## Deployment and rollback
<Operator-approved plan, affected shared runtimes, rollback risks, post-deploy build/process/route verification.>

## Acceptance evidence
<Required command/output/config/test evidence and outstanding limitations.>
