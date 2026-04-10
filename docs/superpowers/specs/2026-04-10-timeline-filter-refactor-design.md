# Timeline Filter Panel Refactor — Design Spec

**Issue**: #100  
**Date**: 2026-04-10  
**Scope**: DATE mode only; SCAN mode unchanged  

## Problem

The timeline screen in DATE mode reads from two independent data sources:

- `viewModel.rows` — merged `TimelineRow` list (findings + telemetry), used for the pinned "Findings" section
- `viewModel.partitionedEvents` — raw `ForensicTimelineEvent` list partitioned into clusters + standalone, used for the date-grouped chronological section

This dual-source architecture means:
- Package/date-range filters affect `events` (via DAO) but not `rows`
- Severity filters could only affect `rows` but not the date-grouped section
- No single filter works consistently across the entire screen
- Package chips act as navigation (scroll-to) rather than true filters (hide non-matching)

## Approach

**ViewModel-side unification**: introduce a new `StateFlow<List<DateGroup>>` that merges findings and telemetry into a single filtered, date-grouped, ready-to-render structure. The screen in DATE mode reads only this flow.

## Design

### 1. New data structure — `DateGroup`

```kotlin
data class DateGroup(
    val label: String,                              // "Apr 10, 2026"
    val findingRows: List<TimelineRow.FindingRow>,
    val clusters: List<EventCluster>,
    val standaloneRows: List<TimelineRow.TelemetryRow>,
)
```

### 2. New ViewModel flow — `dateGroupedRows`

A `StateFlow<List<DateGroup>>` built by combining `rows` + `_severityFilter` + `_groupMode`:

1. If mode is not DATE, emit `emptyList()` (skip computation)
2. Start from `rows` (already merged via `mergeTimelineRows`, already respects `hideInformationalTelemetry`)
3. Apply severity filter (when active: keep only `FindingRow` at selected levels, drop all `TelemetryRow`)
4. Extract `TelemetryRow` events, run `partitionSignals()` to get clusters + standalone
5. Group everything by date label (from timestamp)
6. Sort date groups newest-first; sort items within each group newest-first

Computed on `Dispatchers.Default` via `flowOn`.

### 3. Severity filter state

```kotlin
private val _severityFilter = MutableStateFlow<Set<String>>(emptySet())
val severityFilter: StateFlow<Set<String>> = _severityFilter.asStateFlow()

fun toggleSeverity(level: String) {
    _severityFilter.update { current ->
        if (level in current) current - level else current + level
    }
}
```

Behavior:
- **Empty set** (default): show everything — findings, telemetry, clusters
- **Non-empty set**: severity focus mode — show only `FindingRow` at selected levels; hide all `TelemetryRow` and clusters
- Severity filter **stacks** with package/date-range/source filters (not mutually exclusive)
- Chips (CRITICAL / HIGH / MEDIUM / LOW) are always visible regardless of whether findings at that level exist

### 4. Filter panel UI

Layout within the existing collapsible panel:

```
[ Hide informational telemetry toggle ]     ← existing
[ CRITICAL ] [ HIGH ] [ MEDIUM ] [ LOW ]    ← new severity chips (always visible)
[ WhatsApp ] [ Chrome ] [ Settings ] ...    ← existing package chips
[ DATE | SCAN ]                             ← existing group mode
[ All | 24h | 7d | 30d ]                   ← existing date range
```

Severity chips: `FilterChip` with multi-select. Color-coded via the existing `severityBackgroundFor()` convention.

Package chips: no ViewModel-level behavior change needed. They still call `setPackageFilter()` which restricts the DAO query. Since DATE mode now renders from `rows` (which derives from `events`), the entire screen filters consistently.

### 5. Card tappability

Add `onClick: (() -> Unit)?` parameter to `FindingCard`. When tapped, open `TimelineEventDetailSheet` for the finding's `anchorEvent`. If no anchor event exists, card is not tappable.

### 6. Screen rendering changes (DATE mode)

The DATE mode branch simplifies to:

```
collect: dateGroupedRows

for each DateGroup:
    render date header (label)
    render findingRows (FindingCard with onClick → detail sheet)
    render clusters (CorrelationClusterCard)
    render standaloneRows (TelemetryCard)
```

Findings render within their date group in chronological context, not in a separate pinned section.

**Empty state**: DATE mode checks `dateGroupedRows.isEmpty()` instead of `events.isEmpty()`.

**Removed from screen**:
- The `remember(partitioned)` date-grouping computation block
- The `remember(rows)` for `referencedEventIds` and `findingRows`
- The standalone `hideInformational` filtering of `visibleStandalones`
- Direct collection of `partitionedEvents` for DATE mode rendering

### 7. What stays unchanged

- SCAN mode rendering (reads `scanGroupedEvents` as before)
- `TimelineRow` sealed interface and `mergeTimelineRows()` function
- `partitionSignals()` clustering logic (reused inside `dateGroupedRows`)
- All export functionality
- `rollUpFindings()` dedup logic
- Filter setters (`setPackageFilter`, `setSourceFilter`, `setDateRange`, etc.)
- The `events` flow (still needed for SCAN mode, empty state fallback, export, detail sheet related-events lookup)

### 8. Files modified

| File | Changes |
|------|---------|
| `TimelineViewModel.kt` | Add `_severityFilter`, `toggleSeverity()`, `dateGroupedRows` flow, `DateGroup` data class |
| `TimelineScreen.kt` | Add severity chips to filter panel; replace DATE mode rendering with `dateGroupedRows` iteration; add `onClick` to `FindingCard` usage; remove `partitionedEvents`/`rows` usage in DATE mode |
| `TimelineEventCard.kt` | Add `onClick` parameter to `FindingCard` |
