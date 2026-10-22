# Telemetry store — plan gate round 9 findings (2026-10-23)

Narrow re-gate of correctness, architect and code quality against 1123367 (security passed round 8). All three confirmed Z1, Z3 and Z4 resolved, Z2 resolved for `deleteScan`. All three failed. That is 4 raw SEV-2s, de-duplicating to two roots. Code citations were verified.

| # | Root | Found by | Resolution |
|---|---|---|---|
| W1 | "Clear all" held the lock for its first transaction only, then ran today's unfiltered `ForensicTimelineEventDao.deleteAll()`. A scan that started and completed meanwhile lost its timeline and signals, and its `signal_member` rows were orphaned. The D3 test contradicted itself. | corr, arch, qual | "Clear all" remembers the ids it set `DELETING` and `clearStartedAt`. It deletes only those scans' rows plus `-1` rows with `timestamp ≤ clearStartedAt`, and signals with their members. Test: a scan started after the first transaction survives intact. |
| W2 | A4's `SignalMemberDao.forSignal(…, after: AtomRef?)` used a type first created in C2 (it would not compile, and made `data/db` depend on `sigma`). | corr | Plain cursor values `afterKind: Int?, afterRefId: Long?`; `ClusterMembers` maps them to and from `AtomRef`. |

SEV-3s folded in:
- **Lock placement.** `scanMutex` moves to a `@Singleton ScanLock`, which removes the Hilt cycle through `ScanOrchestrator`. It exposes `writerRunning: StateFlow<Boolean>`.
- **Delete refusal.** User deletes refuse when `writerRunning` is set. Otherwise they wait up to 2 s for a retention or backfill batch, so the refusal message no longer appears when no scan is running. History disables delete from `writerRunning`.
- **History handling.** `DeleteResult { Done; ScanRunning }` is defined, and History's ViewModel and screen join D3 with a test.
- **Dirty flag.** `StoreDirtyFlag.kt` joins the A5 file list, and a failed retention batch now sets it.
- **Backfill.**
  - It keysets by row id, so malformed rows can't loop.
  - Failed rows don't block the done flag.
  - It takes the lock per batch; correctness comes from the per-batch transaction and the exists-check, not the lock.
  - `StartupSweep.kt` joins C2.
  - Until it finishes, legacy clusters show their members as missing. This gap is accepted explicitly and nothing blocks the Timeline.
- **Live-scan lookback.** It reads rows through `VisibleRow.SQL`, so it never binds rows of `DELETING` scans.
- **Deadline vs. target.** The ≤ 2 s `finish` target applies to a typical import. The 5 s total deadline bounds the worst case.
- **Deadline during binding.** If the total deadline passes during binding or grouping, each affected rule gets a rule-level "not started" entry.
- **Stale test wording.** The leftover D3 test qualifier ("that nothing references") is replaced.
- **C2 test files.** `CorrelationBudgetTest`, `SignalMemberBackfillTest`, `ClusterMembersTest` and `DashboardViewModelTest` are named.
- **Follow-up spec.** §5 now mentions the total deadline.

Re-gate scope: correctness, architect, code quality (each had a SEV-2).
