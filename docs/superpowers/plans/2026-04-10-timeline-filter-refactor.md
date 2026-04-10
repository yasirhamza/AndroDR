# Timeline Filter Panel Refactor — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Unify the DATE mode timeline data flow so the screen reads from one filtered source, and add severity filter chips.

**Architecture:** New `dateGroupedRows` StateFlow in the ViewModel combines `rows` + severity filter + clustering into a ready-to-render `List<DateGroup>`. The screen in DATE mode renders only from this flow. SCAN mode is unchanged.

**Tech Stack:** Kotlin, Jetpack Compose, Kotlin Coroutines/Flow, JUnit 4

**Spec:** `docs/superpowers/specs/2026-04-10-timeline-filter-refactor-design.md`

---

### Task 1: Add `DateGroup` data class and `dateGroupedRows` flow to ViewModel

**Files:**
- Modify: `app/src/main/java/com/androdr/ui/timeline/TimelineViewModel.kt`

- [ ] **Step 1: Add severity filter state**

Add after the `_dateRange` / `dateRange` block (after line 81):

```kotlin
private val _severityFilter = MutableStateFlow<Set<String>>(emptySet())
val severityFilter: StateFlow<Set<String>> = _severityFilter.asStateFlow()

fun toggleSeverity(level: String) {
    _severityFilter.update { current ->
        if (level in current) current - level else current + level
    }
}
```

Add this import at the top of the file:

```kotlin
import kotlinx.coroutines.flow.update
```

- [ ] **Step 2: Add `DateGroup` data class**

Add after the existing `ScanGroup` data class (after line 46):

```kotlin
data class DateGroup(
    val label: String,
    val findingRows: List<TimelineRow.FindingRow>,
    val clusters: List<EventCluster>,
    val standaloneRows: List<TimelineRow.TelemetryRow>,
)
```

- [ ] **Step 3: Add `dateGroupedRows` StateFlow**

Add after the `rows` flow definition (after line 137):

```kotlin
val dateGroupedRows: StateFlow<List<DateGroup>> = combine(
    rows, _severityFilter, _groupMode
) { rowList, severitySet, mode ->
    if (mode != TimelineGroupMode.DATE || rowList.isEmpty()) return@combine emptyList()

    // Step 1: apply severity filter
    val filtered = if (severitySet.isEmpty()) {
        rowList
    } else {
        rowList.filter { row ->
            row is TimelineRow.FindingRow &&
                row.finding.level.uppercase() in severitySet
        }
    }

    // Step 2: cluster telemetry rows via partitionSignals
    val telemetryEvents = filtered
        .filterIsInstance<TimelineRow.TelemetryRow>()
        .map { it.event }
    val (clusters, standaloneEvents) = if (telemetryEvents.isNotEmpty()) {
        partitionSignals(telemetryEvents)
    } else {
        emptyList<EventCluster>() to emptyList<ForensicTimelineEvent>()
    }

    // Build a lookup from event ID to TelemetryRow for standalone rows
    val telemetryByEventId = filtered
        .filterIsInstance<TimelineRow.TelemetryRow>()
        .associateBy { it.event.id }
    val standaloneRows = standaloneEvents.mapNotNull { telemetryByEventId[it.id] }

    val findingRows = filtered.filterIsInstance<TimelineRow.FindingRow>()

    // Step 3: group by date
    val fmt = SimpleDateFormat("MMM dd, yyyy", Locale.US)
    fun dateKey(ts: Long) = if (ts > 0) fmt.format(Date(ts)) else "Unknown Date"

    // Collect all items with their date keys
    data class Bucket(
        val findings: MutableList<TimelineRow.FindingRow> = mutableListOf(),
        val clusters: MutableList<EventCluster> = mutableListOf(),
        val standalone: MutableList<TimelineRow.TelemetryRow> = mutableListOf(),
    )
    val buckets = mutableMapOf<String, Bucket>()

    findingRows.forEach { row ->
        val key = dateKey(row.timestamp)
        buckets.getOrPut(key) { Bucket() }.findings.add(row)
    }
    clusters.forEach { cluster ->
        val key = dateKey(cluster.events.first().startTimestamp)
        buckets.getOrPut(key) { Bucket() }.clusters.add(cluster)
    }
    standaloneRows.forEach { row ->
        val key = dateKey(row.timestamp)
        buckets.getOrPut(key) { Bucket() }.standalone.add(row)
    }

    // Step 4: sort and build DateGroup list
    buckets.map { (label, bucket) ->
        DateGroup(
            label = label,
            findingRows = bucket.findings.sortedByDescending { it.timestamp },
            clusters = bucket.clusters.sortedByDescending { c ->
                c.events.maxOfOrNull { it.startTimestamp } ?: 0L
            },
            standaloneRows = bucket.standalone.sortedByDescending { it.timestamp },
        )
    }.sortedByDescending { group ->
        val maxFinding = group.findingRows.maxOfOrNull { it.timestamp } ?: 0L
        val maxCluster = group.clusters.maxOfOrNull { c ->
            c.events.maxOfOrNull { it.startTimestamp } ?: 0L
        } ?: 0L
        val maxStandalone = group.standaloneRows.maxOfOrNull { it.timestamp } ?: 0L
        maxOf(maxFinding, maxCluster, maxStandalone)
    }
}.flowOn(Dispatchers.Default)
    .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5000), emptyList())
```

- [ ] **Step 4: Verify it compiles**

Run: `./gradlew compileDebugKotlin 2>&1 | tail -5`
Expected: `BUILD SUCCESSFUL`

- [ ] **Step 5: Commit**

```bash
git add app/src/main/java/com/androdr/ui/timeline/TimelineViewModel.kt
git commit -m "feat(timeline): add DateGroup model, severity filter, and dateGroupedRows flow (#100)"
```

---

### Task 2: Unit tests for `dateGroupedRows` logic

The `dateGroupedRows` flow composition is complex. We can't easily unit-test a Hilt ViewModel's StateFlow, but we can extract the pure grouping logic and test it. We'll add a `buildDateGroups` top-level function in `TimelineRow.kt` (alongside `mergeTimelineRows`) and have the ViewModel call it.

**Files:**
- Modify: `app/src/main/java/com/androdr/ui/timeline/TimelineRow.kt`
- Modify: `app/src/main/java/com/androdr/ui/timeline/TimelineViewModel.kt`
- Create: `app/src/test/java/com/androdr/ui/timeline/DateGroupBuilderTest.kt`

- [ ] **Step 1: Extract `buildDateGroups` function into `TimelineRow.kt`**

Add at the bottom of `TimelineRow.kt`, after the `TimelineRow` sealed interface:

```kotlin
/**
 * Groups a filtered list of [TimelineRow] into date-bucketed [DateGroup]s
 * ready for rendering. Telemetry rows are partitioned into correlation
 * clusters and standalone events via [partitionSignals].
 *
 * Pure function — no Android dependencies — so it can be unit-tested.
 */
fun buildDateGroups(rows: List<TimelineRow>): List<DateGroup> {
    if (rows.isEmpty()) return emptyList()

    val telemetryEvents = rows
        .filterIsInstance<TimelineRow.TelemetryRow>()
        .map { it.event }
    val (clusters, standaloneEvents) = if (telemetryEvents.isNotEmpty()) {
        partitionSignals(telemetryEvents)
    } else {
        emptyList<EventCluster>() to emptyList<com.androdr.data.model.ForensicTimelineEvent>()
    }

    val telemetryByEventId = rows
        .filterIsInstance<TimelineRow.TelemetryRow>()
        .associateBy { it.event.id }
    val standaloneRows = standaloneEvents.mapNotNull { telemetryByEventId[it.id] }
    val findingRows = rows.filterIsInstance<TimelineRow.FindingRow>()

    val fmt = java.text.SimpleDateFormat("MMM dd, yyyy", java.util.Locale.US)
    fun dateKey(ts: Long) = if (ts > 0) fmt.format(java.util.Date(ts)) else "Unknown Date"

    data class Bucket(
        val findings: MutableList<TimelineRow.FindingRow> = mutableListOf(),
        val clusters: MutableList<EventCluster> = mutableListOf(),
        val standalone: MutableList<TimelineRow.TelemetryRow> = mutableListOf(),
    )
    val buckets = mutableMapOf<String, Bucket>()

    findingRows.forEach { row ->
        buckets.getOrPut(dateKey(row.timestamp)) { Bucket() }.findings.add(row)
    }
    clusters.forEach { cluster ->
        buckets.getOrPut(dateKey(cluster.events.first().startTimestamp)) { Bucket() }
            .clusters.add(cluster)
    }
    standaloneRows.forEach { row ->
        buckets.getOrPut(dateKey(row.timestamp)) { Bucket() }.standalone.add(row)
    }

    return buckets.map { (label, bucket) ->
        DateGroup(
            label = label,
            findingRows = bucket.findings.sortedByDescending { it.timestamp },
            clusters = bucket.clusters.sortedByDescending { c ->
                c.events.maxOfOrNull { it.startTimestamp } ?: 0L
            },
            standaloneRows = bucket.standalone.sortedByDescending { it.timestamp },
        )
    }.sortedByDescending { group ->
        val maxFinding = group.findingRows.maxOfOrNull { it.timestamp } ?: 0L
        val maxCluster = group.clusters.maxOfOrNull { c ->
            c.events.maxOfOrNull { it.startTimestamp } ?: 0L
        } ?: 0L
        val maxStandalone = group.standaloneRows.maxOfOrNull { it.timestamp } ?: 0L
        maxOf(maxFinding, maxCluster, maxStandalone)
    }
}
```

- [ ] **Step 2: Simplify `dateGroupedRows` in ViewModel to call `buildDateGroups`**

Replace the `dateGroupedRows` body added in Task 1 with:

```kotlin
val dateGroupedRows: StateFlow<List<DateGroup>> = combine(
    rows, _severityFilter, _groupMode
) { rowList, severitySet, mode ->
    if (mode != TimelineGroupMode.DATE || rowList.isEmpty()) return@combine emptyList()

    val filtered = if (severitySet.isEmpty()) {
        rowList
    } else {
        rowList.filter { row ->
            row is TimelineRow.FindingRow &&
                row.finding.level.uppercase() in severitySet
        }
    }

    buildDateGroups(filtered)
}.flowOn(Dispatchers.Default)
    .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5000), emptyList())
```

Remove the `SimpleDateFormat` and `Date` imports from `TimelineViewModel.kt` if they are no longer used elsewhere in the file. Check first — `buildDisplayNames` and `export` don't use them; `ScanGroup` doesn't either. The `SimpleDateFormat`/`Date` imports at lines 29/30 were only used by the old `dateGroupedRows` inline logic and the `export` function. The `export` function uses them too (line 323), so **keep the imports**.

- [ ] **Step 3: Write the test file**

Create `app/src/test/java/com/androdr/ui/timeline/DateGroupBuilderTest.kt`:

```kotlin
package com.androdr.ui.timeline

import com.androdr.data.model.ForensicTimelineEvent
import com.androdr.sigma.Finding
import com.androdr.sigma.FindingCategory
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class DateGroupBuilderTest {

    // 2026-04-10 12:00:00 UTC
    private val day1Noon = 1_744_286_400_000L
    // 2026-04-10 14:00:00 UTC
    private val day1Afternoon = day1Noon + 2 * 3_600_000L
    // 2026-04-09 12:00:00 UTC (previous day)
    private val day2Noon = day1Noon - 24 * 3_600_000L

    private fun event(id: Long, ts: Long, ruleId: String = "") = ForensicTimelineEvent(
        id = id,
        startTimestamp = ts,
        source = "test",
        category = "test",
        description = "event $id",
        ruleId = ruleId,
    )

    private fun telemetryRow(id: Long, ts: Long, ruleId: String = "") =
        TimelineRow.TelemetryRow(event = event(id, ts, ruleId))

    private fun findingRow(
        ruleId: String,
        anchorTs: Long,
        anchorId: Long = anchorTs,
        level: String = "HIGH",
    ): TimelineRow.FindingRow {
        val anchor = event(anchorId, anchorTs, ruleId)
        return TimelineRow.FindingRow(
            finding = Finding(
                ruleId = ruleId,
                title = "Finding for $ruleId",
                level = level,
                category = FindingCategory.APP_RISK,
            ),
            anchorEvent = anchor,
        )
    }

    @Test
    fun `empty input returns empty list`() {
        assertEquals(emptyList<DateGroup>(), buildDateGroups(emptyList()))
    }

    @Test
    fun `telemetry rows on same day grouped into one DateGroup`() {
        val rows: List<TimelineRow> = listOf(
            telemetryRow(1, day1Noon),
            telemetryRow(2, day1Afternoon),
        )

        val groups = buildDateGroups(rows)

        assertEquals(1, groups.size)
        assertEquals(0, groups[0].findingRows.size)
        // standalone count: both events should appear (no clustering for simple events)
        assertTrue(groups[0].standaloneRows.size + groups[0].clusters.sumOf { it.events.size } == 2)
    }

    @Test
    fun `events on different days produce separate DateGroups sorted newest first`() {
        val rows: List<TimelineRow> = listOf(
            telemetryRow(1, day2Noon),
            telemetryRow(2, day1Noon),
        )

        val groups = buildDateGroups(rows)

        assertEquals(2, groups.size)
        // Newest day first
        val newestGroupTs = groups[0].standaloneRows.maxOfOrNull { it.timestamp }
            ?: groups[0].clusters.flatMap { it.events }.maxOfOrNull { it.startTimestamp } ?: 0L
        val oldestGroupTs = groups[1].standaloneRows.maxOfOrNull { it.timestamp }
            ?: groups[1].clusters.flatMap { it.events }.maxOfOrNull { it.startTimestamp } ?: 0L
        assertTrue("Newest group first", newestGroupTs > oldestGroupTs)
    }

    @Test
    fun `finding rows land in correct date group`() {
        val rows: List<TimelineRow> = listOf(
            findingRow("androdr-001", anchorTs = day1Noon, anchorId = 10),
            telemetryRow(1, day2Noon),
        )

        val groups = buildDateGroups(rows)

        assertEquals(2, groups.size)
        val groupWithFinding = groups.first { it.findingRows.isNotEmpty() }
        assertEquals(1, groupWithFinding.findingRows.size)
        assertEquals("androdr-001", groupWithFinding.findingRows[0].finding.ruleId)
    }

    @Test
    fun `severity filter pre-filtering works - only FindingRows survive`() {
        // Simulate what the ViewModel does before calling buildDateGroups
        val allRows: List<TimelineRow> = listOf(
            findingRow("androdr-001", anchorTs = day1Noon, anchorId = 10, level = "HIGH"),
            findingRow("androdr-002", anchorTs = day1Afternoon, anchorId = 11, level = "LOW"),
            telemetryRow(1, day1Noon),
        )

        val severitySet = setOf("HIGH")
        val filtered = allRows.filter { row ->
            row is TimelineRow.FindingRow &&
                row.finding.level.uppercase() in severitySet
        }

        val groups = buildDateGroups(filtered)

        assertEquals(1, groups.size)
        assertEquals(1, groups[0].findingRows.size)
        assertEquals("HIGH", groups[0].findingRows[0].finding.level)
        assertEquals(0, groups[0].standaloneRows.size)
        assertEquals(0, groups[0].clusters.size)
    }
}
```

- [ ] **Step 4: Run the tests**

Run: `./gradlew testDebugUnitTest --tests "com.androdr.ui.timeline.DateGroupBuilderTest" 2>&1 | tail -10`
Expected: All tests PASS

- [ ] **Step 5: Commit**

```bash
git add app/src/main/java/com/androdr/ui/timeline/TimelineRow.kt \
       app/src/main/java/com/androdr/ui/timeline/TimelineViewModel.kt \
       app/src/test/java/com/androdr/ui/timeline/DateGroupBuilderTest.kt
git commit -m "refactor(timeline): extract buildDateGroups and add unit tests (#100)"
```

---

### Task 3: Add `onClick` to `FindingCard`

**Files:**
- Modify: `app/src/main/java/com/androdr/ui/timeline/TimelineEventCard.kt:128-177`

- [ ] **Step 1: Add `onClick` parameter to `FindingCard`**

Change the `FindingCard` signature and add `clickable` modifier:

```kotlin
@Composable
fun FindingCard(
    row: TimelineRow.FindingRow,
    modifier: Modifier = Modifier,
    onClick: (() -> Unit)? = null,
) {
    val finding = row.finding
    Card(
        modifier = modifier.fillMaxWidth().let { m ->
            if (onClick != null) m.clickable(onClick = onClick) else m
        },
```

The rest of `FindingCard` stays exactly as-is (lines 133-177).

- [ ] **Step 2: Verify it compiles**

Run: `./gradlew compileDebugKotlin 2>&1 | tail -5`
Expected: `BUILD SUCCESSFUL` (existing call sites pass no `onClick`, which defaults to `null`)

- [ ] **Step 3: Commit**

```bash
git add app/src/main/java/com/androdr/ui/timeline/TimelineEventCard.kt
git commit -m "feat(timeline): make FindingCard tappable with optional onClick (#100)"
```

---

### Task 4: Add severity filter chips to filter panel

**Files:**
- Modify: `app/src/main/java/com/androdr/ui/timeline/TimelineScreen.kt:243-348` (filter panel)

- [ ] **Step 1: Add severity filter chip row**

In `TimelineScreen.kt`, inside the `AnimatedVisibility(visible = filterPanelExpanded)` Column, add a new `LazyRow` **after** the "Hide informational telemetry" toggle (after the closing `}` of the Row at line 263) and **before** the package filter chips block (line 266):

```kotlin
                // Severity filter chips
                val severityFilter by viewModel.severityFilter.collectAsStateWithLifecycle()
                val severityLevels = listOf("CRITICAL", "HIGH", "MEDIUM", "LOW")

                LazyRow(
                    contentPadding = PaddingValues(horizontal = 16.dp),
                    horizontalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    items(severityLevels) { level ->
                        FilterChip(
                            selected = level in severityFilter,
                            onClick = { viewModel.toggleSeverity(level) },
                            label = { Text(level) }
                        )
                    }
                }
```

- [ ] **Step 2: Verify it compiles**

Run: `./gradlew compileDebugKotlin 2>&1 | tail -5`
Expected: `BUILD SUCCESSFUL`

- [ ] **Step 3: Commit**

```bash
git add app/src/main/java/com/androdr/ui/timeline/TimelineScreen.kt
git commit -m "feat(timeline): add severity filter chips to filter panel (#100)"
```

---

### Task 5: Replace DATE mode rendering with `dateGroupedRows`

This is the core screen refactor. The DATE mode `else` branch (lines 427-553) gets replaced.

**Files:**
- Modify: `app/src/main/java/com/androdr/ui/timeline/TimelineScreen.kt`

- [ ] **Step 1: Collect `dateGroupedRows` and `severityFilter`**

In the state collection block at the top of `TimelineScreen` (around lines 102-109), add:

```kotlin
    val dateGroups by viewModel.dateGroupedRows.collectAsStateWithLifecycle()
```

- [ ] **Step 2: Remove unused DATE-mode state collections**

Remove these lines that are no longer needed for DATE mode rendering (but check SCAN mode and other usages first):

- `val partitioned by viewModel.partitionedEvents.collectAsStateWithLifecycle()` (line 103) — only used in the DATE mode `else` branch. Remove it.
- `val rows by viewModel.rows.collectAsStateWithLifecycle()` (line 104) — only used in the DATE mode branch for `referencedEventIds` and `findingRows`. Remove it.

Keep `val events` — it's used for the empty state check and the detail sheet's related-events lookup (line 567).

- [ ] **Step 3: Replace the empty state check for DATE mode**

Currently the empty state (lines 351-377) checks `events.isEmpty()`. This check applies to both modes. Change it to be mode-aware:

Replace:

```kotlin
        if (events.isEmpty()) {
```

With:

```kotlin
        val isEmpty = if (groupMode == TimelineGroupMode.SCAN) events.isEmpty() else dateGroups.isEmpty()
        if (isEmpty) {
```

- [ ] **Step 4: Replace the DATE mode `else` branch**

Replace the entire `else` block (from `} else {` after the SCAN mode block through to the closing `}` of the column's `LazyColumn`) with:

```kotlin
        } else {
            LazyColumn(
                modifier = Modifier.fillMaxSize(),
                contentPadding = PaddingValues(horizontal = 16.dp, vertical = 8.dp),
                verticalArrangement = Arrangement.spacedBy(8.dp)
            ) {
                dateGroups.forEach { group ->
                    item(key = "header_${group.label}") {
                        Text(
                            text = group.label,
                            style = MaterialTheme.typography.titleSmall,
                            color = MaterialTheme.colorScheme.primary,
                            modifier = Modifier.padding(vertical = 4.dp)
                        )
                    }
                    items(
                        items = group.findingRows,
                        key = { "finding_${it.finding.ruleId}_${it.timestamp}" }
                    ) { row ->
                        FindingCard(
                            row = row,
                            onClick = row.anchorEvent?.let { anchor ->
                                { selectedEvent = anchor }
                            }
                        )
                    }
                    group.clusters.forEachIndexed { idx, cluster ->
                        item(key = "cluster_${group.label}_$idx") {
                            CorrelationClusterCard(
                                cluster = cluster,
                                onEventTap = { selectedEvent = it }
                            )
                        }
                    }
                    items(
                        items = group.standaloneRows,
                        key = { it.event.id }
                    ) { row ->
                        TelemetryCard(row, onClick = { selectedEvent = row.event })
                    }
                }
            }
        }
```

- [ ] **Step 5: Remove the now-unused `DateEntry` private data class**

Delete lines 74-77:

```kotlin
private data class DateEntry(
    val clusters: List<EventCluster> = emptyList(),
    val standaloneEvents: List<ForensicTimelineEvent> = emptyList()
)
```

Also remove the `ForensicTimelineEvent` import if it's no longer used in this file. Check: the detail sheet block (line 558+) still references `ForensicTimelineEvent` via `selectedEvent`, so **keep the import**.

- [ ] **Step 6: Clean up unused imports**

Remove these imports from `TimelineScreen.kt` if they're no longer referenced:

```kotlin
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
```

Check: `SimpleDateFormat`, `Date`, and `Locale` were used only in the old `remember(partitioned)` date-grouping block. With that removed, they can be deleted. Verify none are used elsewhere in the file before removing.

- [ ] **Step 7: Verify it compiles**

Run: `./gradlew compileDebugKotlin 2>&1 | tail -5`
Expected: `BUILD SUCCESSFUL`

- [ ] **Step 8: Run all existing timeline tests**

Run: `./gradlew testDebugUnitTest --tests "com.androdr.ui.timeline.*" 2>&1 | tail -15`
Expected: All tests PASS (existing merge + rollup + new date group tests)

- [ ] **Step 9: Commit**

```bash
git add app/src/main/java/com/androdr/ui/timeline/TimelineScreen.kt
git commit -m "refactor(timeline): replace DATE mode dual-source with unified dateGroupedRows (#100)"
```

---

### Task 6: Run lint and full test suite

**Files:** None (verification only)

- [ ] **Step 1: Run full unit test suite**

Run: `./gradlew testDebugUnitTest 2>&1 | tail -10`
Expected: `BUILD SUCCESSFUL`

- [ ] **Step 2: Run lint**

Run: `./gradlew lintDebug 2>&1 | tail -10`
Expected: No new errors introduced

- [ ] **Step 3: Build debug APK**

Run: `./gradlew assembleDebug 2>&1 | tail -5`
Expected: `BUILD SUCCESSFUL`
