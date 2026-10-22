# Adaptive blindspot dialogue

The goal is to resolve consequential uncertainty, not make the user fill out an interrogation form. Read current context and the engagement record first. Ask in the user's language, at most three questions per batch. Never repeat an answered question semantically.

## Opening questions only when unresolved

1. Which host/session is the authorized target, and are all projects/tenants in scope or only listed roots?
2. Is this production, and are there no-touch services/actions or an active incident? Default to no writes, no active traffic and no broadcasts.
3. Where may private reports be stored, and what read/log budgets or operating constraints apply?

Do not ask “Nginx or Apache?”, “how many projects?” or “which PHP version?” when authorized metadata can answer. A user who does not know the filesystem layout can authorize a bounded metadata-discovery pass without listing every project first.

## Triggered questions

| Observation | Consequential question / action |
|---|---|
| Shell appears local/sandbox instead of server | Confirm target context before enumeration |
| Several tenants or ownership unclear | Ask which tenant/project contents are authorized |
| Old/missing logs | Ask whether rotated or central sources exist; report missing window |
| Root-only evidence | Request a specific read-only export or narrowly scoped elevation, not a password |
| Shared runtime crosses excluded projects | Report shared dependency and ask before tenant-specific inspection |
| Suspected incident | Ask for preservation/containment decision and responsible operator |
| No staging, risky repro requested | Offer evidence-based applicability assessment; do not run destructive production probes |
| Backport claim without provenance | Ask for exact package/vendor evidence; keep status unverified |
| Active requests would hit broadcast/payment/job route | Do not test it on production; request a safe test route/environment |
| Unknown business authorization model | Ask the intended role/tenant boundary before calling behavior a bug |
| Proposed patch/restart affects many projects | Ask for change scope, maintenance window, rollback and acceptance criteria |

If the user says “don't know,” suggest the next bounded discovery step. If the user says “continue,” use previously approved safe defaults; do not reinterpret it as blanket permission for exploitation or writes. Continue independent read-only work while one branch is blocked. Explain specifically what the missing answer prevents.

After two optional clarification rounds, summarize facts and open questions and deliver useful partial results. Mandatory target/authorization or high-impact change decisions remain blockers for those activities, not for unrelated approved analysis.
