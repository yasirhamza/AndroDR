package com.androdr.ui.timeline

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyRow
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Close
import androidx.compose.material.icons.filled.FilterList
import androidx.compose.material3.Button
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FilterChip
import androidx.compose.material3.Icon
import androidx.compose.material3.InputChip
import androidx.compose.material3.InputChipDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.ModalBottomSheet
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.rememberModalBottomSheetState
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.LiveRegionMode
import androidx.compose.ui.semantics.clearAndSetSemantics
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.liveRegion
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.androdr.R
import com.androdr.data.db.TimelineFilter
import com.androdr.data.model.TelemetrySource

/**
 * The Timeline's one compact filter row (ruling R30): a Filters button with the number of active
 * filters (it opens [TimelineFilterSheet]), one dismissible chip per active filter, then the live
 * count of what the filter shows (spec §6: a count on the filter bar).
 */
@Composable
internal fun TimelineFilterBar(
    chips: List<ActiveFilter>,
    totalCount: Long?,
    onOpenFilters: () -> Unit,
    onDismiss: (ActiveFilter) -> Unit,
) {
    Row(
        modifier = Modifier.fillMaxWidth().padding(start = 16.dp, end = 16.dp, top = 4.dp, bottom = 4.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        val openDescription = stringResource(R.string.cd_timeline_filters, chips.size)
        OutlinedButton(
            onClick = onOpenFilters,
            contentPadding = PaddingValues(horizontal = 12.dp),
            modifier = Modifier.semantics { contentDescription = openDescription },
        ) {
            Icon(Icons.Filled.FilterList, contentDescription = null, modifier = Modifier.size(18.dp))
            Spacer(Modifier.width(6.dp))
            Text(
                if (chips.isEmpty()) stringResource(R.string.timeline_filters)
                else stringResource(R.string.timeline_filters_active, chips.size)
            )
        }
        LazyRow(
            modifier = Modifier.weight(1f),
            contentPadding = PaddingValues(horizontal = 8.dp),
            horizontalArrangement = Arrangement.spacedBy(6.dp),
        ) {
            items(chips, key = { it.toString() }) { chip ->
                val label = activeFilterLabel(chip)
                val removeDescription = stringResource(R.string.cd_timeline_remove_filter, label)
                InputChip(
                    selected = true,
                    onClick = { onDismiss(chip) },
                    label = { Text(label, maxLines = 1) },
                    trailingIcon = {
                        Icon(Icons.Filled.Close, contentDescription = null, Modifier.size(InputChipDefaults.IconSize))
                    },
                    modifier = Modifier.clearAndSetSemantics { contentDescription = removeDescription },
                )
            }
        }
        totalCount?.let {
            Text(
                text = stringResource(R.string.timeline_event_count, it),
                style = MaterialTheme.typography.labelLarge,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                modifier = Modifier.semantics { liveRegion = LiveRegionMode.Polite },
            )
        }
    }
}

/** A chip's text: what the active filter keeps. */
@Composable
internal fun activeFilterLabel(chip: ActiveFilter): String = when (chip) {
    is ActiveFilter.Scan -> stringResource(R.string.timeline_chip_scan)
    is ActiveFilter.Package -> stringResource(R.string.timeline_chip_package, chip.packageName)
    is ActiveFilter.Source -> stringResource(R.string.timeline_chip_source, stringResource(sourceLabel(chip.source)))
    is ActiveFilter.Severity -> chip.level.uppercase()
    is ActiveFilter.DateRange -> stringResource(
        when (rangeHours(chip.from, chip.to)) {
            RANGE_24H -> R.string.timeline_chip_range_24h
            RANGE_7D -> R.string.timeline_chip_range_7d
            RANGE_30D -> R.string.timeline_chip_range_30d
            else -> R.string.timeline_chip_range
        }
    )
    ActiveFilter.FindingsOnly -> stringResource(R.string.timeline_chip_findings_only)
}

private fun sourceLabel(source: TelemetrySource): Int = when (source) {
    TelemetrySource.LIVE_SCAN -> R.string.timeline_source_live
    TelemetrySource.BUGREPORT_IMPORT -> R.string.history_source_bugreport_import
    TelemetrySource.INTRUSION_LOG_IMPORT -> R.string.history_source_intrusion_log_import
}

/** The preset a range was set from (its length in whole hours), or null for no range or another length. */
private fun rangeHours(from: Long?, to: Long?): Int? {
    if (from == null || to == null) return null
    val span = to - from
    return (span / HOUR_MS).toInt().takeIf { it.toLong() * HOUR_MS == span }
}

private const val HOUR_MS = 3_600_000L
private const val RANGE_24H = 24
private const val RANGE_7D = 24 * 7
private const val RANGE_30D = 24 * 30

/** The sheet's actions, so the sheet stays a pure view of [TimelineFilter]. */
internal class TimelineFilterActions(
    val setFindingsOnly: (Boolean) -> Unit,
    val toggleSeverity: (String) -> Unit,
    val setSource: (TelemetrySource?) -> Unit,
    val setRangeHours: (Int?) -> Unit,
    val setGroupMode: (TimelineGroupMode) -> Unit,
)

/**
 * The Filters sheet (ruling R30): the "Show findings and their evidence only" switch, severity,
 * source, date range and grouping. Its open state is saved by the caller (`rememberSaveable`) and
 * every value lives in the ViewModel, so the sheet survives rotation.
 */
@Suppress("LongMethod") // one section per filter
@OptIn(ExperimentalMaterial3Api::class)
@Composable
internal fun TimelineFilterSheet(
    filter: TimelineFilter,
    groupMode: TimelineGroupMode,
    actions: TimelineFilterActions,
    onDismiss: () -> Unit,
) {
    ModalBottomSheet(onDismissRequest = onDismiss, sheetState = rememberModalBottomSheetState()) {
        Column(modifier = Modifier.verticalScroll(rememberScrollState()).padding(bottom = 16.dp)) {
            Text(
                stringResource(R.string.timeline_filters),
                style = MaterialTheme.typography.titleMedium,
                fontWeight = FontWeight.Bold,
                modifier = Modifier.padding(horizontal = 24.dp),
            )
            Row(
                modifier = Modifier.fillMaxWidth().padding(horizontal = 16.dp, vertical = 8.dp),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Switch(checked = filter.findingsAndEvidenceOnly, onCheckedChange = actions.setFindingsOnly)
                Spacer(Modifier.width(8.dp))
                Text(
                    stringResource(R.string.timeline_findings_evidence_only),
                    style = MaterialTheme.typography.bodyMedium,
                )
            }

            SheetSection(stringResource(R.string.timeline_sheet_severity))
            LazyRow(contentPadding = ChipPadding, horizontalArrangement = ChipSpacing) {
                items(SEVERITIES) { level ->
                    FilterChip(
                        selected = level in filter.levels,
                        onClick = { actions.toggleSeverity(level) },
                        label = { Text(level) },
                    )
                }
            }

            SheetSection(stringResource(R.string.timeline_sheet_source))
            LazyRow(contentPadding = ChipPadding, horizontalArrangement = ChipSpacing) {
                item {
                    FilterChip(
                        selected = filter.source == null,
                        onClick = { actions.setSource(null) },
                        label = { Text(stringResource(R.string.timeline_filter_all)) },
                    )
                }
                items(TelemetrySource.entries) { source ->
                    FilterChip(
                        selected = filter.source == source,
                        onClick = { actions.setSource(source) },
                        label = { Text(stringResource(sourceLabel(source))) },
                    )
                }
            }

            SheetSection(stringResource(R.string.timeline_sheet_range))
            val activeHours = rangeHours(filter.from, filter.to)
            val noRange = filter.from == null && filter.to == null
            LazyRow(contentPadding = ChipPadding, horizontalArrangement = ChipSpacing) {
                item {
                    FilterChip(
                        selected = noRange,
                        onClick = { actions.setRangeHours(null) },
                        label = { Text(stringResource(R.string.timeline_filter_all)) },
                    )
                }
                items(RANGE_PRESETS) { (hours, label) ->
                    FilterChip(
                        selected = !noRange && activeHours == hours,
                        onClick = { actions.setRangeHours(hours) },
                        label = { Text(stringResource(label)) },
                    )
                }
            }

            SheetSection(stringResource(R.string.timeline_sheet_group))
            LazyRow(contentPadding = ChipPadding, horizontalArrangement = ChipSpacing) {
                item {
                    FilterChip(
                        selected = groupMode == TimelineGroupMode.DATE,
                        onClick = { actions.setGroupMode(TimelineGroupMode.DATE) },
                        label = { Text(stringResource(R.string.timeline_group_date)) },
                    )
                }
                item {
                    FilterChip(
                        selected = groupMode == TimelineGroupMode.SCAN,
                        onClick = { actions.setGroupMode(TimelineGroupMode.SCAN) },
                        label = { Text(stringResource(R.string.timeline_group_scan)) },
                    )
                }
            }

            Spacer(Modifier.height(16.dp))
            Button(onClick = onDismiss, modifier = Modifier.fillMaxWidth().padding(horizontal = 24.dp)) {
                Text(stringResource(R.string.timeline_sheet_done))
            }
        }
    }
}

@Composable
private fun SheetSection(title: String) {
    Text(
        title,
        style = MaterialTheme.typography.labelLarge,
        color = MaterialTheme.colorScheme.onSurfaceVariant,
        modifier = Modifier.padding(start = 24.dp, end = 24.dp, top = 12.dp, bottom = 4.dp),
    )
}

private val SEVERITIES = listOf("CRITICAL", "HIGH", "MEDIUM", "LOW")
private val RANGE_PRESETS = listOf(
    RANGE_24H to R.string.timeline_range_24h,
    RANGE_7D to R.string.timeline_range_7d,
    RANGE_30D to R.string.timeline_range_30d,
)
private val ChipPadding = PaddingValues(horizontal = 16.dp)
private val ChipSpacing = Arrangement.spacedBy(8.dp)
