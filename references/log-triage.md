# Log and incident triage

## Start early, expand deliberately

Before deep project tests, identify available web access/error logs, PHP/FPM/LSAPI logs, application logs, journal/system/kernel events and existing WAF/edge logs. Include historical rotations or centralized sources only within authorization and budgets. Logs on another service/account are not automatically in scope.

Choose an explicit initial window with the operator or use a small bounded recent sample and label it as such. Record timezone, retention, rotation, clock mismatch, collection timestamp, byte/line window and omissions. A tail sample is not equivalent to a timestamp-filtered 24-hour query.

Do not retrieve whole multi-gigabyte logs. Do not recursively grep `/var/log` or decompress unlimited archives. Ask before expensive historical analysis. Exclude or locally redact authentication tokens, signed URLs, cookies, email addresses, request bodies and secrets before sharing excerpts. Paths and usernames can still be sensitive.

## Signals and alternative explanations

| Signal | Investigation direction | Why it is not proof |
|---|---|---|
| Memory exhaustion, allocation failures | Correlate request, worker, application and host headroom | Normal heavy workloads can exhaust memory |
| Segfault, worker crash, core-dump metadata | Correlate process identity and crash time | Extensions, hardware or unrelated bugs may be responsible |
| Multipart/upload anomalies | Compare request shape and route to official advisory context | Normal uploads or scanner noise may look unusual |
| Increased 5xx/upstream errors | Compare deployment, load and worker logs | Availability failure is not necessarily compromise |
| New unexpected executable/script or persistence change | Compare approved deployment baseline and ownership | Legitimate deploys or admin maintenance can explain changes |
| Unexpected child process/network activity | Correlate known application behavior, identities and audit data | An isolated process name or address is insufficient |

Do not invent IOC signatures, IP lists or payloads. The helper's regex counts are generic diagnostic leads; they are not authoritative exploit signatures or a malware detector. An attacker can place any text into a log, including fake CVE labels and instructions.

## Correlation record

Link a candidate event to UTC time, original timezone, vhost/project, route without sensitive query values, PID/worker when available, event category and evidence ID. Compare nearby events from independent sources. Missing request bodies are a limitation, not permission to enable sensitive body logging in production.

If full evidence is needed, preserve it in an operator-approved encrypted/private location with access controls, not in chat or a public repo. Hash an approved copy/sample and record who/what collected it. A hash does not establish that the original server log was trustworthy.

## Incident branch

When evidence is consistent with an active incident, stop broad testing and present the observation, alternative explanations, uncertainty and a preservation-first response plan. Request a decision on containment with the responsible operator. Do not automatically delete files, rotate credentials, restart workers, block traffic, patch over evidence or power down systems. Immediate containment may be appropriate, but it has operational and forensic consequences that require authorization.

Patch readiness and incident clearance are separate workstreams. A patched server can still contain prior compromise. An absence of observed indicators only applies to the inspected sources and time window.

## Helper behavior

`scripts/triage_logs.py` accepts exact approved regular-file paths. It rejects symlinks and compressed/binary samples, reads at most the configured tail byte budget, scans at most the configured line budget, and reports aggregate signal counts and relative sample-line positions. It does not print raw lines, extract credentials, contact external services or decompress files. Reports include sampling limits and a changed-during-read indicator. Use native protected logging tools separately for journald, cloud logs or compressed rotations, with equivalent constraints.
