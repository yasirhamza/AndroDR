# Telemetry store — plan gate round 8 findings (2026-10-22)

Reviewers were fresh Opus instances, read-only, on a narrow re-gate against 00b9fcc (the round-7 fix and the split). Results: correctness FAIL (1 SEV-2), architect FAIL (2), code quality FAIL (2), security PASS (0 SEV-2, 5 SEV-3). That is 5 raw SEV-2s, de-duplicating to four roots. Every lens confirmed the round-7 roots resolved or moot, and found no leftover `alert_member`, re-homing or overlap text. Every cited code line was checked against the source.

| # | Root | Found by | Resolution |
|---|---|---|---|
| Z1 | A row exemption left over from the removed design: plan D2 said scan deletion and "Clear all" keep rows a surviving signal references, contradicting spec §5.1 and plan D3. Kept rows would point at a deleted scan, stay invisible and never be cleaned up (the Y3 leak again) | corr, arch, qual, sec (SEV-3) | Only the 30-day prune exempts referenced rows. "or a `forensic_timeline` row" is dropped from the spec's Pins, and the "not referenced" clause is dropped from "Clear all" in both documents. Test: deleting scan X, whose row is a member of Y's signal, removes the row, leaves no dangling `scanResultId`, and Y's cluster loads the remaining members. |
| Z2 | "Clear all" could mark an `IN_PROGRESS` scan `DELETING` with no lock. `finish` would then bring the scan back, or the writer would insert rows for a scan that no longer exists | arch, sec (SEV-3) | User deletes take `scanMutex.tryLock()` for their first transaction and are refused while a scan runs. `finish` sets `COMPLETE` only `WHERE state = 'IN_PROGRESS'` and rolls back otherwise. Tests in A7 and D3. |
| Z3 | The backfill was not idempotent: `INSERT OR IGNORE` had no unique index. It was not serialised with deletes and had no handling for malformed rows | qual, corr (SEV-3), sec (SEV-3) | Unique `(signalRowId, kind, refId)`. The backfill runs in `StartupSweep` under `scanMutex` before the Timeline is usable, one transaction per 200 signals, with a signal-exists check, `toLongOrNull`, per-row catch (bad rows left untouched), a rewrite of `details` (plus `member_count`) and `correlationId`, and a done flag. The gate allow-lists the backfill file. Legacy report chains print no "0 linked event(s)". Tests cover a kill and re-run, a concurrent delete, and malformed input. |
| Z4 | The per-(rule, group) budget had no total cap, so `finish` was unbounded in rules × groups | qual, sec (SEV-3) | `CorrelationBudget(…, totalMs = 5_000)` also covers atom binding and grouping. Unstarted pairs record `CORRELATION_INCOMPLETE` (capped list). A C2 test with 50 dense packages and an injected clock. |

SEV-3s folded in:
- **Stale entry.** `AlertMember` removed from the D2 file list.
- **Fact reads.** `TelemetryReader.records(factIds)`, batched, for `ClusterMembers`, "Matched record" and the E1 route.
- **Dirty flag.** `StoreDirtyFlag` (DataStore `telemetry_store_dirty`), with its set and clear paths and an A7 test.
- **Migration.** 19→20 maps category `CORRELATION` to STATE with no alert explicitly (F1).
- **D3 step 2.** Restates that facts un-pinned by deleted `signal_member` rows go to `deleteUnobservedUnpinned`.
- **C2 file list.** Today's prune deletes a pruned signal's `signal_member` rows.
- **`ClusterMembers`.** Paged (200), with `VisibleRow` for rows; dangling refs are skipped and counted in `missing`. `member_refs` exports existing members only. The "union" wording is corrected for the C2 commit.
- **`LegacyEventRowCleanup`.** Skips rows that a `signal_member` references.
- **Partial signals.** Signals found before a cut-off are kept, and a test checks it. `SENTINELS` derives from the enum, so `CORRELATION_INCOMPLETE` is excluded from `realFailureCount` automatically (verified at `ScanResult.kt:97`).
- **Dashboard.** A distinct "Correlation incomplete" warning, with C2 files and a ViewModel test.
- **Imports.** An import correlates over its own scan's atoms only (no lookback), so its signals never reference live data.
- **Follow-up spec §5.** `AtomRef` kind values (0 = Row, 1 = Fact) are stable.

Re-gate scope: correctness, architect and code quality (the lenses with SEV-2s). Security passed, and its SEV-3s are the same roots, fixed as it proposed.
