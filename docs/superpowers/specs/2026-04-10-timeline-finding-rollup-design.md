# Timeline Finding-Event Rollup — Design Spec

**Status:** Approved, ready for implementation
**Tracking issue:** #88 (v1 — narrow scope)
**Date:** 2026-04-10

---

## 1. Problem

When the same SIGMA rule fires on the same package across multiple scans, the timeline accumulates duplicate `FindingRow` entries. 5 scans producing 10 findings each yields 50 timeline rows that look identical, creating visual noise that obscures new or changing findings.

The underlying cause: `ForensicTimelineEvent` rows for findings are appended per scan via `OnConflictStrategy.IGNORE`, but no unique constraint exists on the timeline table — so IGNORE has no effect and every scan creates fresh rows.

## 2. Solution

`TimelineViewModel` groups finding events by `(ruleId, packageName)` and keeps only the most recent occurrence per group in the displayed timeline. A "×N" badge on the `FindingCard` shows how many scans confirmed the same finding. Raw events stay in the database untouched — no schema change, no DAO change, no storage dedup. Export and forensic analysis see the full unrolled event stream.

## 3. Scope

**In scope:**
- ViewModel grouping logic in `rollUpFindings()` helper
- Two new fields on `TimelineRow.FindingRow`: `duplicateCount: Int` and `firstSeenTimestamp: Long?`
- "×N" badge composable on `FindingCard`
- Unit tests for the rollup logic

**Out of scope (deferred):**
- Persisting telemetry types (AppTelemetry, DeviceTelemetry, etc.) to Room — see follow-up issue
- Storage-layer deduplication (unique constraints, upserts)
- Export format changes
- Room schema migration
- Any DAO or repository changes

## 4. Data flow

```
Room (forensic_timeline) → raw List<ForensicTimelineEvent>
                          ↓
TimelineViewModel.mergeTimelineRows()
  1. Wrap events as TelemetryRow / FindingRow (existing plan 3 logic)
  2. Group FindingRows by (ruleId, packageName)
  3. Per group: keep the most-recent FindingRow, set duplicateCount = group.size,
     firstSeenTimestamp = earliest occurrence's timestamp
  4. Recombine with TelemetryRows
  5. Sort merged list chronologically
  6. Apply existing filters (hide informational, date range, etc.)
                          ↓
StateFlow<List<TimelineRow>> → TimelineScreen
```

## 5. Grouping key

**`(ruleId, packageName)`** — two finding events with the same rule and same package are the "same finding seen again."

Implications:
- Same rule firing on two DIFFERENT packages = two separate entries (correct)
- Same rule firing on the same package across N scans = one rolled-up entry with ×N badge (correct)
- Different rules firing on the same package = separate entries (correct)
- Severity change between scans does NOT break the group — the most recent severity is shown (the change is implicit; a future version could show "escalated from MEDIUM to HIGH" if needed)

## 6. `TimelineRow.FindingRow` changes

```kotlin
data class FindingRow(
    val finding: Finding,
    val anchorEvent: ForensicTimelineEvent? = null,
    val duplicateCount: Int = 1,
    val firstSeenTimestamp: Long? = null,
) : TimelineRow {
    override val timestamp: Long
        get() = anchorEvent?.startTimestamp ?: Long.MAX_VALUE
}
```

- `duplicateCount = 1` → no badge (single occurrence, same as today)
- `duplicateCount > 1` → "×N" badge renders
- `firstSeenTimestamp` → earliest occurrence's `startTimestamp`; available for detail sheet or tooltip

## 7. Rollup implementation

New private helper in `TimelineRow.kt` (where `mergeTimelineRows` already lives) or in `TimelineViewModel.kt`:

```kotlin
private fun rollUpFindings(rows: List<TimelineRow>): List<TimelineRow> {
    val telemetryRows = rows.filterIsInstance<TimelineRow.TelemetryRow>()
    val findingRows = rows.filterIsInstance<TimelineRow.FindingRow>()

    val rolledUp = findingRows
        .groupBy { it.finding.ruleId to (it.finding.matchContext["package_name"] ?: "") }
        .map { (_, group) ->
            val mostRecent = group.maxBy { it.timestamp }
            val earliest = group.minBy { it.timestamp }
            mostRecent.copy(
                duplicateCount = group.size,
                firstSeenTimestamp = earliest.timestamp,
            )
        }

    return (telemetryRows + rolledUp).sortedByDescending { it.timestamp }
}
```

Called inside `mergeTimelineRows()` or the ViewModel's `combine()` block after the existing merge logic but before the filter step.

## 8. `FindingCard` badge

When `row.duplicateCount > 1`, render a small chip in the existing `Row` alongside the severity badge and category chip:

```kotlin
if (row.duplicateCount > 1) {
    Surface(
        color = MaterialTheme.colorScheme.tertiaryContainer,
        shape = RoundedCornerShape(4.dp),
    ) {
        Text(
            text = "×${row.duplicateCount}",
            style = MaterialTheme.typography.labelSmall,
            modifier = Modifier.padding(horizontal = 4.dp, vertical = 2.dp),
        )
    }
}
```

Low visual weight — does not compete with the severity indicator. Positioned after the category chip, before the rule ID.

## 9. Testing

1. **`rollUpFindings` groups by (ruleId, packageName)**  
   Given 3 FindingRows with same ruleId + packageName from 3 different scans, assert output has 1 row with `duplicateCount = 3` and `firstSeenTimestamp` matching the earliest scan.

2. **Different rules on same package stay separate**  
   Given FindingRows from 2 different rules on the same package, assert 2 rolled-up rows.

3. **Different packages with same rule stay separate**  
   Given FindingRows from the same rule on 2 different packages, assert 2 rolled-up rows.

4. **Single occurrence has duplicateCount = 1**  
   Given 1 FindingRow, assert `duplicateCount = 1` and `firstSeenTimestamp = null` (or same as timestamp).

5. **TelemetryRows are unaffected by rollup**  
   Given a mix of TelemetryRows and FindingRows, assert TelemetryRows pass through unchanged.

6. **Most recent occurrence wins**  
   Given 3 FindingRows with different timestamps, assert the rolled-up row's `timestamp` matches the most recent one.

7. **Existing `TimelineRowMergeTest` still passes**  
   The new rollup step must not break existing merge behavior.

## 10. Risks

**R1. `matchContext["package_name"]` may be missing.** Some findings may not have `package_name` in their match context. In that case, the grouping key is `(ruleId, "")` — all findings from the same rule without a package are grouped together. This is acceptable because such findings are typically device-level (not per-app) and grouping them is correct.

**R2. Severity change across scans is invisible.** If a rule's severity changes between scans (e.g., rule update from MEDIUM to HIGH), the rollup shows only the most recent severity. The earlier severity is not displayed. Acceptable for v1 — severity changes across scans are rare and the forensic export preserves all raw events.

**R3. Group count accuracy.** The 500-row query limit on `getRecentEvents()` means the group count may undercount if a finding has been seen in more than 500 scans' worth of events. In practice this is ~50+ days of daily scans, which is far beyond typical usage. Acceptable.

---

**End of spec.**
