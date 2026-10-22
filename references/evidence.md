# Evidence, confidence and verdict rules

## Four claim classes

- **Observed:** directly supported by identified local evidence.
- **Source-backed:** a statement from a named authoritative source with retrieval time and scope.
- **Inferred:** a conclusion whose evidence and assumptions are written down.
- **Hypothesis:** plausible but not yet established; explicitly state the next discriminating check.

Do not blur these in prose. A scanner's output is itself an observation about what the scanner reported, not proof that its conclusion is correct.

## Evidence records

Record evidence ID, collection timestamp, target identity, scope, command/check identifier or file/log window, exit status/error, relevant redacted output or structured result, truncation and permissions, and integrity hash where appropriate. Hashing a sample proves sample identity only. Prefer least-sensitive evidence sufficient for reproducibility.

Use local source line ranges or exact config keys where safe. Do not invent line numbers. If a command was only suggested, label it `not run`. If a file changed during reading, record the race and repeat only when safe.

## Separate dimensions

Track independent dimensions instead of one “secure” label:

1. **Build applicability:** affected / patched by verified upstream or vendor / unverified / not applicable with evidence.
2. **Running-state verification:** mapped and verified / older or different worker observed / partial / unknown.
3. **Route coverage:** all enumerated in-scope routes verified / partial / unmapped; this is not a claim of complete global discovery.
4. **Exploitability:** not tested / prerequisites supported / prerequisites unresolved / separately validated in authorized lab.
5. **Incident evidence:** indicators observed / none observed in specified sample / unavailable; never globally “clean.”

## Severity and confidence

Severity explains plausible impact and exposure. Confidence explains evidence quality. Use high/medium/low with rationale, not invented numerical probabilities. Do not turn a generic vendor severity into certainty about this deployment.

## Skeptical reviewer checklist

Could this be a backport? Is that the serving runtime? Does this process belong to this vhost? Is the config loaded or just stored? Is a replica missing? Does a route execute the code? Is the shared resource actually accessible after ACLs/namespaces? Could the log signal be normal load or a deploy? Did a failed command get treated as a negative finding? Is an external source current for this exact vendor stream?

Each finding needs a falsifier: describe evidence that would downgrade or eliminate it. Search for that evidence within scope. Keep unresolved contradictions visible rather than choosing the more dramatic conclusion.

## Release gate

No final conclusion without asset identity, evidence, uncertainty and scope. No claim of successful security testing without stating what actually ran. No skipped/blocked cells marked passed. No unsupported “all clear,” “100% secure,” “unexploitable” or “the entire server is compromised.”
