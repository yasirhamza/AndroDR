# Telemetry store — plan gate round 5 findings (2026-10-22)

Reviewers (fresh Opus, read-only; narrow re-gate against 10a9f70):

| Reviewer | Verdict |
|---|---|
| Architect | FAIL (4 SEV-2) |
| Correctness | FAIL (3 SEV-2) |
| Code quality | FAIL (3 SEV-2) |
| Security | FAIL (3 SEV-2) |

All four confirmed that the round-4 roots V1–V10 are resolved. The 13 SEV-2s de-duplicate to six roots.

Four of the six came from two mechanisms added in rounds 3–4 to patch earlier findings:

- **Truncated correlation-member sets.** The newest-1,000 cap with a `truncatedBelow` cutoff, plus a `persistent` flag set when the alert was created.
- **Correlating before the finishing transaction.**

This round **removes those mechanisms** rather than patching them again.

| # | Root cause | Found by | Resolution |
|---|---|---|---|
| W1 | This scan's finding atoms had no row id when correlation ran outside the finishing transaction. | arch, qual | Correlation runs **inside** the finishing transaction, after this scan's timeline rows are inserted, as today's `saveScanWithCorrelation` does. Atoms are bounded to atom-bound categories. The release battery asserts `finish` duration on a 100k-finding import. |
| W2 | Correlation membership was maintained only when an alert was created. `truncatedBelow` compared across ref kinds and counted non-members. The `persistent` flag on member rows could drift. | arch, qual, sec | `alert_member` keeps **every** member (unique `(alertId, kind, refId)`; about 20 B each). Create, join and attach share one `mergeMembers`. Members are compared exactly. A row or fact referenced by `alert_member` is protected on every delete path by that reference. `persistent` now covers only audit, closure and "import interrupted" rows. `memberCount` and `truncatedBelow` are removed. |
| W3 | "No observation at all ⇒ visible" exposed unpinned orphans after an interrupted delete or retention batch, breaking the #342 B1 guarantee. Deletes of `COMPLETE` scans were not resumable. | arch, corr, sec | Visible = a `COMPLETE` observation, **or** no observation **and pinned**, using one shared SQL fragment. A scan is set `DELETING` first. Its own rows are deleted next. Each keyset batch then deletes its observations, its unpinned candidates and their unreferenced bodies in **one transaction**. The `ScanResult` row goes last. `StartupSweep` resumes `IN_PROGRESS` and `DELETING` scans and runs `gcUnobservedUnpinned`. |
| W4 | The late-IOC re-check re-evaluated facts the current scan had just appended, and accepted imported DNS facts with forged recent times. | arch, qual, sec | Facts are selected through `scan_record`: `LIVE_SCAN` observations of `COMPLETE` scans only. |
| W5 | The `MIGRATION_18_19` `level` backfill parsed `findings` with no protection against oversized or corrupt rows. | corr | A shared `MigrationFindingsReader` (chunked `substr`) is used by 18→19 and 19→20. `Migration18To19Test` covers a 3 MB row and a corrupt row. |
| W6 | Findings without a `recordId` (evaluate-only fallbacks) had no kind and no alert key. The audit row on deletion had no size bound and could exceed 2 MB. | corr, sec | Kind follows the migration's rule (an event time in `matchContext`, or an always-event service). Key: `noFactKey(rule, evidence, eventTime)`. A dashboard banner marks `FAILED` scans. The audit row aggregates distinct (rule, level, package) entries with counts, capped at 100 plus "and K more". A gate checks a 50k-finding scan's audit row stays under 16 KB. |

SEV-3s folded in:

- Stale sentences fixed: the spec diagram, plan line 8, the spec's §6 visibility text, `recordChunk` names, and "live **event** fact".
- Evaluate-only mode deduplicates with a bounded 200,000-key set (a documented residual).
- The reserve is checked again before `finish`.
- The redundant `scan_finding(scanId)` index is dropped.
- `evidenceJson` strips member-id lists, is named the authoritative alert evidence, and is counted in storage.
- "Clear all" removes non-persistent, unreferenced `scanResultId = -1` rows again, as today.
- J1 is extended to writer-level rows (C2 K1).
- D2's retention test simulates retention; the real pass comes in D4.

Re-gate scope: all four lenses had a SEV-2, so all four re-run in round 6, narrowly against this file.
