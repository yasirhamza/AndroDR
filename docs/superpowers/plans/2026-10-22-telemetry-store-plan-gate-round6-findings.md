# Telemetry store — plan gate round 6 findings (2026-10-22)

Reviewers: fresh Opus, read-only. This was a narrow re-gate against 20ef130.

| Reviewer | Verdict | SEV-2 count |
|---|---|---|
| Correctness | FAIL | 3 |
| Architect | FAIL | 2 |
| Code quality | FAIL | 3 |
| Security | FAIL | 1 |

The architect now judges the deletion model coherent. All four reviewers confirmed the round-5 roots resolved, with stale plan lines noted. The 9 SEV-2s reduce to three roots.

**X1 — Pinned data whose scan is gone is not readable.**
- Found by: correctness, architect, code quality, security.
- Problem:
  - Plan C4's fact branch still used "no observation at all", without the pin condition.
  - Removing the `persistent` flag from member rows left alert- and signal-referenced rows of deleted scans invisible to every reader.
- Resolution:
  - Facts are read through `PinnedFact.SQL`; rows through `VisibleRow.SQL`.
  - The delete re-homes referenced rows to `scanResultId = -1`, so they stay visible.
  - L2 and the S3 tests assert through the Timeline paging source and the report.

**X2 — A deletion's audit row can be lost.**
- Found by: correctness, architect, code quality, security.
- Problem:
  - The audit row was written last, after its source rows were already deleted.
  - A force-stop mid-delete, followed by the unaudited sweep, erased the only trace of the deletion.
- Resolution:
  - The audit row is written in the same transaction that sets `DELETING`.
  - The sweep writes "import interrupted" only for `IN_PROGRESS` imports.
  - Test: kill the app after the first transaction; exactly one audit row exists.

**X3 — Uncapped membership pinned every member forever.**
- Found by: code quality; security (SEV-3).
- Problem: a chatty app's events escaped retention permanently.
- Resolution:
  - Membership is not pinning. `alert_member` records every member, so matching stays exact. Ids are never reused.
  - Only evidence members pin: the opening 50 and the newest 50 (`evidence = 1`), re-marked on each merge.
  - Member lists live only in `signal_member`. Signal `details` and `correlationId` carry no id lists, so no row grows with chain size.
  - The `member_event_ids` dual-write is removed.

**SEV-3s folded in:**
- Correlation:
  - Time budget (10 s) with cancellation; when exceeded, the scan records "correlation incomplete".
  - Adversarial-density gate (C2).
  - Deterministic join: lowest-id OPEN alert. One CLOSED alert must contain all members; members split across closed alerts open a new alert.
  - Overlap is computed with a TEMP-table join and per-alert match counts.
- Late-IOC re-check: a finding is emitted only when no triggered `scan_finding` already exists for that `(ruleId, recordId)`.
- `noFactKey` falls back to `scanId|ordinal` when there is no event time.
- `finish` target: ≤ 2 s for 100k findings on the F916B.
- Evaluate-only key set: `MutableLongSet` (about 3 MB).
- `signal_member` indices.
- `gcUnobservedUnpinned` runs only when the sweep found work or the store's dirty flag is set. Every pin-removing path passes the facts it un-pins to the delete.
- The reserve is re-checked before `finish` (plan A7).
- The redundant spec index is dropped.
- `storage()` counts pinned orphans and `evidenceJson`.
- Phase A delete order: the scan's rows go first.
- C1 tests for self- and import-exclusion.
- P1 covers `alert_member` references.
- Per-batch retention rule and a crash test (D4).
- `unobservedUnpinnedAfter` DAO.
- Stale "alert-evidence" / "Row members are persistent" / "atoms from scan_finding" wording removed.

Re-gate scope: all four lenses had a SEV-2 → all four re-run in round 7, narrowly.
