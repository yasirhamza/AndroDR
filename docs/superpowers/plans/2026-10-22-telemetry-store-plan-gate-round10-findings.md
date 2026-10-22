# Telemetry store — plan gate round 10 findings (2026-10-23)

Correctness, architect and code quality each ran a narrow re-gate against dc8fbe9. **All three passed, with no SEV-1 or SEV-2 findings.** Security had already passed in round 8. **The plan gate is closed.**

Reviewers confirmed W1 (the scoped "Clear all") and W2 (the DAO cursor without `AtomRef`) are resolved, and confirmed the code citations. The SEV-3s below were folded in after the gate as wording changes. They add no new mechanism, so no lens was re-run.

| Item | Found by | Change |
|---|---|---|
| `writerRunning` had no write API, and could stick at true after an exception | corr, arch, qual | `ScanLock.withWriter { }` takes the lock, sets a private `MutableStateFlow`, and resets it in `finally`. Only live scan and import sessions call it. A7 test. |
| The order of taking the lock versus opening a transaction was unstated (deadlock risk) | arch | Global rule: `scanMutex` is acquired outside any Room transaction. A7 test with a lock-then-transaction batch while a writer holds the lock. |
| "Clear all" selected `-1` rows by event time (the column is `startTimestamp`, and clock skew could misplace rows); the value was lost if the app was killed | corr, arch, qual | Select by `id ≤ clearMaxRowId` (`MAX(id)` taken in the first transaction). The value is saved in DataStore, and `StartupSweep` finishes a pending clear. |
| "Survives intact" was too strong | corr, arch | A scan that started during "Clear all" survives. Members it bound from pre-clear `-1` rows load as missing, as for `deleteScan`. |
| `VisibleRow.SQL` was first defined in C4 but used in C2 | arch | Defined in A5, next to `PinnedFact.SQL`. |
| `ScanLock.kt` was listed under "Modify ScanOrchestrator" | qual | Moved to A7's Create list. |
| `DeleteResult` shorthand; a refused "Clear all" deselected the scan | qual | Objects implement `DeleteResult`. `confirmClearAll` handles `ScanRunning` before clearing the selection. |
| D3 test files incomplete; no D4 dirty-flag test | qual | `HistoryViewModelTest` added and `HistoryViewModelDiffTest` updated. D4 test: a retention batch that throws sets `StoreDirtyFlag`. |

Raw SEV-2 per round: 48, 37, 28, 11, 13, 9, 9, 5, 4, 0.
