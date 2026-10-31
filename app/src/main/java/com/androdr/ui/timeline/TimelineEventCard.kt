@file:Suppress("TooManyFunctions")
// Compose file hosts both public card composables (event card, detail sheet,
// cluster card) and private helpers (LinkedEvidenceRow, DetailSection, etc.)
// that are tightly coupled to the timeline screen and would only fragment if
// split across files.

package com.androdr.ui.timeline

import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ExperimentalLayoutApi
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.ExpandLess
import androidx.compose.material.icons.filled.ExpandMore
import androidx.compose.material.icons.filled.Info
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.ModalBottomSheet
import androidx.compose.material3.SuggestionChip
import androidx.compose.material3.SuggestionChipDefaults
import androidx.compose.material3.Text
import androidx.compose.material3.rememberModalBottomSheetState
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import com.androdr.sigma.AtomRef
import com.androdr.sigma.TaxonomyContract
import androidx.compose.material3.OutlinedButton
import kotlinx.coroutines.launch
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Surface
import com.androdr.R
import com.androdr.data.store.DecodedRecord
import com.androdr.data.model.TimelineRowEntity
import com.androdr.sigma.TimePrecision
import java.util.TimeZone
import com.androdr.reporting.escapeForReport
import com.androdr.data.model.ForensicTimelineEvent
import com.androdr.data.model.TelemetrySource
import com.androdr.sigma.FindingCategory
import com.androdr.ui.common.SeverityChip
import com.androdr.ui.security.ProtectedButton
import com.androdr.ui.telemetry.recordLine
import com.androdr.ui.theme.androdrColors
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

@OptIn(ExperimentalLayoutApi::class)
@Composable
fun TimelineEventCard(
    event: ForensicTimelineEvent,
    onClick: () -> Unit
) {
    // A stored finding row (it carries the finding's `level`) shows its severity and rule (#418: on
    // 848 a critical finding drew as this neutral card and read as informational). Any other row is
    // telemetry: pure observation per spec §3, so no severity badge.
    val colors = MaterialTheme.androdrColors
    val neutralColor = colors.neutral
    val level = event.level?.takeIf { it.isNotBlank() }
    Card(
        modifier = Modifier.fillMaxWidth().clickable(onClick = onClick),
        colors = CardDefaults.cardColors(
            containerColor = level?.let { severityBackgroundFor(it) }
                ?: MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.5f)
        )
    ) {
        Row(
            modifier = Modifier.padding(12.dp),
            horizontalArrangement = Arrangement.spacedBy(10.dp)
        ) {
            if (level == null) {
                Icon(
                    imageVector = Icons.Filled.Info,
                    contentDescription = null,
                    tint = MaterialTheme.colorScheme.onSurfaceVariant,
                    modifier = Modifier.size(20.dp)
                )
            }
            Column(
                modifier = Modifier.weight(1f),
                verticalArrangement = Arrangement.spacedBy(4.dp)
            ) {
                if (level != null) {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        SeverityChip(level = level, active = true)
                        Spacer(Modifier.weight(1f))
                        Text(
                            text = event.ruleId,
                            style = MaterialTheme.typography.labelSmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                    }
                }
                Text(
                    text = rowTime(event),
                    style = MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
                Text(
                    text = event.description,
                    style = MaterialTheme.typography.bodySmall,
                    maxLines = 2, overflow = TextOverflow.Ellipsis
                )
                FlowRow(horizontalArrangement = Arrangement.spacedBy(4.dp)) {
                    if (event.campaignName.isNotEmpty()) TagChip(event.campaignName, colors.critical)
                    if (event.iocType.isNotEmpty()) TagChip(event.iocType, neutralColor)
                    TagChip(event.source, MaterialTheme.colorScheme.primary)
                }
            }
        }
    }
}

/**
 * Finding row renderer — distinct visual treatment with a severity badge,
 * category chip, rule id, title, and description.
 */
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
        colors = CardDefaults.cardColors(
            containerColor = severityBackgroundFor(finding.level)
        )
    ) {
        Column(modifier = Modifier.padding(12.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                SeverityChip(level = finding.level, active = true)
                Spacer(Modifier.width(8.dp))
                CategoryChip(finding.category)
                if (row.duplicateCount > 1) {
                    Spacer(Modifier.width(4.dp))
                    Surface(
                        color = MaterialTheme.colorScheme.tertiaryContainer,
                        shape = RoundedCornerShape(4.dp),
                    ) {
                        Text(
                            text = "\u00d7${row.duplicateCount}",
                            style = MaterialTheme.typography.labelSmall,
                            modifier = Modifier.padding(horizontal = 4.dp, vertical = 2.dp),
                        )
                    }
                }
                Spacer(Modifier.weight(1f))
                Text(
                    text = finding.ruleId,
                    style = MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
            Spacer(Modifier.height(8.dp))
            Text(
                text = finding.title,
                style = MaterialTheme.typography.titleSmall,
                fontWeight = FontWeight.Bold
            )
            if (finding.description.isNotBlank()) {
                Spacer(Modifier.height(4.dp))
                Text(
                    text = finding.description,
                    style = MaterialTheme.typography.bodySmall
                )
            }
        }
    }
}

@Composable
private fun CategoryChip(category: FindingCategory) {
    Surface(
        color = MaterialTheme.colorScheme.secondaryContainer,
        contentColor = MaterialTheme.colorScheme.onSecondaryContainer,
        shape = RoundedCornerShape(4.dp)
    ) {
        Text(
            text = category.name.lowercase().replace('_', ' '),
            style = MaterialTheme.typography.labelSmall,
            modifier = Modifier.padding(horizontal = 6.dp, vertical = 2.dp)
        )
    }
}

@Composable
private fun severityBackgroundFor(level: String): Color {
    val colors = MaterialTheme.androdrColors
    val tint = when (level.uppercase()) {
        "CRITICAL" -> colors.critical
        "HIGH"     -> colors.high
        "MEDIUM"   -> colors.medium
        "LOW"      -> colors.low
        else       -> return MaterialTheme.colorScheme.surface
    }
    return tint.copy(alpha = 0.10f)
}

@Suppress("LongMethod") // Compose detail sheet renders header + all metadata sections + linked evidence
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun TimelineEventDetailSheet(
    event: ForensicTimelineEvent,
    onDismiss: () -> Unit,
    relatedEvents: List<ForensicTimelineEvent> = emptyList(),
    onJumpToRelated: (ForensicTimelineEvent) -> Unit = {},
    onShowOnlyApp: ((String) -> Unit)? = null,
    onCloseAlert: (() -> Unit)? = null,
    onViewTelemetry: (() -> Unit)? = null,
) {
    ModalBottomSheet(
        onDismissRequest = onDismiss,
        sheetState = rememberModalBottomSheetState(skipPartiallyExpanded = true)
    ) {
        Column(
            modifier = Modifier.padding(horizontal = 24.dp, vertical = 16.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp)
        ) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Text(event.category, style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.Bold)
            }
            Text(
                text = "${rowTime(event)}  ${rowDate(event)}",
                style = MaterialTheme.typography.labelMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
            HorizontalDivider()
            DetailSection(stringResource(R.string.timeline_detail_description), event.description)
            if (event.details.isNotEmpty()) {
                DetailSection(stringResource(R.string.timeline_detail_details), event.details)
            }
            if (event.packageName.isNotEmpty()) {
                DetailSection(stringResource(R.string.timeline_detail_package), event.packageName)
                onShowOnlyApp?.let { ShowOnlyAppButton(event.packageName, it) }
            }
            if (event.iocIndicator.isNotEmpty()) {
                DetailSection(
                    stringResource(R.string.timeline_detail_ioc_match),
                    "${event.iocIndicator} (${event.iocType})"
                )
            }
            if (event.campaignName.isNotEmpty()) {
                DetailSection(
                    stringResource(R.string.timeline_detail_campaign),
                    event.campaignName
                )
            }
            if (event.ruleId.isNotEmpty()) {
                DetailSection(stringResource(R.string.timeline_detail_rule), event.ruleId)
            }
            // The row's scan's stored telemetry (spec §8.1 "finding detail").
            onViewTelemetry?.let { open ->
                OutlinedButton(onClick = open) { Text(stringResource(R.string.telemetry_view)) }
            }
            // An alert row (its alert is still OPEN): closing it asks the device credential (spec §5.4).
            onCloseAlert?.let { close ->
                ProtectedButton(onClick = close, modifier = Modifier.fillMaxWidth()) {
                    Text(stringResource(R.string.timeline_close_alert))
                }
            }
            if (event.attackTechniqueId.isNotEmpty()) {
                DetailSection(
                    stringResource(R.string.timeline_detail_mitre),
                    event.attackTechniqueId
                )
            }

            // Linked Evidence: other timeline rows that share this event's
            // correlationId. For DNS-sourced findings (e.g. androdr-003
            // Malicious Domain) this lets the user jump from a finding card
            // to the underlying ioc_match row that triggered it, and vice
            // versa — closes the "unlinked alerts" gap surfaced during
            // Sprint #75 real-device validation.
            if (relatedEvents.isNotEmpty()) {
                HorizontalDivider()
                Text(
                    text = "Linked Evidence (${relatedEvents.size})",
                    style = MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
                Column(verticalArrangement = Arrangement.spacedBy(6.dp)) {
                    relatedEvents.take(8).forEach { related ->
                        LinkedEvidenceRow(related = related, onTap = { onJumpToRelated(related) })
                    }
                    if (relatedEvents.size > 8) {
                        Text(
                            text = "+${relatedEvents.size - 8} more",
                            style = MaterialTheme.typography.labelSmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                    }
                }
            }

            Spacer(modifier = Modifier.height(32.dp))
        }
    }
}

@Composable
private fun LinkedEvidenceRow(
    related: ForensicTimelineEvent,
    onTap: () -> Unit
) {
    Card(
        modifier = Modifier.fillMaxWidth().clickable(onClick = onTap),
        colors = CardDefaults.cardColors(
            containerColor = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.4f)
        )
    ) {
        Row(
            modifier = Modifier.padding(horizontal = 10.dp, vertical = 8.dp),
            horizontalArrangement = Arrangement.spacedBy(8.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Icon(
                imageVector = Icons.Filled.Info,
                contentDescription = null,
                tint = MaterialTheme.colorScheme.onSurfaceVariant,
                modifier = Modifier.size(16.dp)
            )
            Column(modifier = Modifier.weight(1f)) {
                Text(
                    text = related.description,
                    style = MaterialTheme.typography.bodySmall,
                    maxLines = 2,
                    overflow = TextOverflow.Ellipsis
                )
                Text(
                    text = linkedEvidenceLabel(related),
                    style = MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
        }
    }
}

@Composable
private fun DetailSection(label: String, value: String) {
    Column {
        Text(label, style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
        Text(value, style = MaterialTheme.typography.bodyMedium)
    }
}

@Composable
private fun TagChip(text: String, color: Color) {
    SuggestionChip(
        onClick = {},
        label = { Text(text, style = MaterialTheme.typography.labelSmall) },
        colors = SuggestionChipDefaults.suggestionChipColors(
            containerColor = color.copy(alpha = 0.15f), labelColor = color
        ),
        modifier = Modifier.height(24.dp)
    )
}

/**
 * A correlation cluster. A pre-linked cluster shows its rows at once; a signal's members live only
 * in `signal_member` and load page by page through [loadPage] when the card is expanded (spec §5.4).
 * Members whose row or fact is gone are counted, not shown.
 */
@Suppress("LongMethod") // Compose card renders header row, time range, and per-member children with connectors
@Composable
fun CorrelationClusterCard(
    cluster: EventCluster,
    loadPage: suspend (signalRowId: Long, after: AtomRef?) -> ClusterPage,
    onEventTap: (ForensicTimelineEvent) -> Unit
) {
    val colors = MaterialTheme.androdrColors
    val clusterColor = when (cluster.pattern) {
        CorrelationPattern.PERMISSION_THEN_C2,
        CorrelationPattern.INSTALL_THEN_ADMIN     -> colors.critical
        CorrelationPattern.MULTI_PERMISSION_BURST -> colors.high
        else                                      -> colors.neutral
    }
    val signalRowId = cluster.signalRowId
    var expanded by remember(cluster.key) { mutableStateOf(signalRowId == null) }
    var members by remember(cluster.key) { mutableStateOf(cluster.members) }
    var missing by remember(cluster.key) { mutableIntStateOf(0) }
    var next by remember(cluster.key) { mutableStateOf<AtomRef?>(null) }
    var loaded by remember(cluster.key) { mutableStateOf(signalRowId == null) }
    val scope = rememberCoroutineScope()
    fun loadMore() {
        val id = signalRowId ?: return
        scope.launch {
            val page = loadPage(id, next)
            members = members + page.members
            missing += page.missing
            next = page.next
            loaded = true
        }
    }

    Card(
        modifier = Modifier.fillMaxWidth().clickable(enabled = signalRowId != null) {
            expanded = !expanded
            if (expanded && !loaded) loadMore()
        },
        border = BorderStroke(2.dp, clusterColor.copy(alpha = 0.5f)),
        colors = CardDefaults.cardColors(
            containerColor = clusterColor.copy(alpha = 0.04f)
        )
    ) {
        Column(modifier = Modifier.padding(12.dp)) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(8.dp)
            ) {
                // Cluster label can be long (e.g. "Multiple surveillance
                // permissions accessed rapidly (3)") so give it the weighted
                // flex slot and allow a second line with ellipsis overflow.
                Text(
                    if (cluster.memberCount == null && signalRowId != null) cluster.label
                    else "${cluster.label} (${cluster.size})",
                    style = MaterialTheme.typography.labelMedium,
                    fontWeight = FontWeight.Bold,
                    color = clusterColor,
                    maxLines = 2,
                    overflow = TextOverflow.Ellipsis,
                    modifier = Modifier.weight(1f)
                )
                Text(
                    formatTimeRange(cluster.startTimestamp, cluster.endTimestamp),
                    style = MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis
                )
                if (signalRowId != null) {
                    Icon(
                        imageVector = if (expanded) Icons.Filled.ExpandLess else Icons.Filled.ExpandMore,
                        contentDescription = null,
                    )
                }
            }
            if (expanded) {
                Spacer(modifier = Modifier.height(8.dp))
                members.forEachIndexed { index, member ->
                    when (member) {
                        is TimelineMember.RowMember ->
                            TimelineEventCard(event = member.row, onClick = { onEventTap(member.row) })
                        is TimelineMember.FactMember -> FactMemberCard(member)
                    }
                    if (index < members.lastIndex) {
                        // Vertical connector line
                        Box(
                            modifier = Modifier
                                .padding(start = 10.dp)
                                .width(2.dp)
                                .height(4.dp)
                                .background(clusterColor.copy(alpha = 0.3f))
                        )
                    }
                }
                if (missing > 0) {
                    Text(
                        stringResource(R.string.timeline_cluster_members_missing, missing),
                        style = MaterialTheme.typography.labelSmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
                if (next != null) {
                    TextButton(onClick = { loadMore() }) {
                        Text(stringResource(R.string.timeline_cluster_load_more))
                    }
                }
            }
        }
    }
}

/** A stored fact that is a correlation member: its service, time and display summary. */
@Composable
private fun FactMemberCard(member: TimelineMember.FactMember) {
    FactCard(record = member.record, timestamp = member.timestamp)
}

/**
 * A stored event fact: its time, category (or service) and display summary. Used for a Timeline
 * event, a cluster member, and (with [label]) a finding row's nested evidence.
 */
@Composable
fun FactCard(
    record: DecodedRecord,
    timestamp: Long,
    label: String? = null,
    onClick: (() -> Unit)? = null,
) {
    Card(
        modifier = Modifier.fillMaxWidth().let { m -> if (onClick != null) m.clickable(onClick = onClick) else m },
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceContainer)
    ) {
        Column(modifier = Modifier.padding(8.dp)) {
            Text(
                listOfNotNull(label, factTime(record, timestamp), record.category ?: record.service).joinToString("  "),
                style = MaterialTheme.typography.labelSmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            Text(
                factDescription(record) ?: stringResource(R.string.timeline_cluster_fact_unreadable),
                style = MaterialTheme.typography.bodySmall,
                maxLines = 2,
                overflow = TextOverflow.Ellipsis,
            )
        }
    }
}

/**
 * A stored fact's description line (battery B1): the telemetry browser's [recordLine] rule, so a
 * service with no summary rule (e.g. `device_auditor`) shows its subject or first fields. Null, shown
 * as "Record could not be read", ONLY when the body does not decode (`fields == null`).
 */
internal fun factDescription(record: DecodedRecord): String? = recordLine(record)

/** A stored fact's detail: its provenance, time and decoded fields (spec §6 "Matched record"). */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
@Suppress("LongMethod") // header, provenance lines, the app action and every decoded field
fun FactDetailSheet(
    record: DecodedRecord,
    onDismiss: () -> Unit,
    loadProvenance: (suspend (Long) -> FactProvenance?)? = null,
    onShowOnlyApp: ((String) -> Unit)? = null,
) {
    // Off the main thread (the ViewModel reads on IO); null until loaded or when no loader is given.
    var provenance by remember(record.factId) { mutableStateOf<FactProvenance?>(null) }
    LaunchedEffect(record.factId) { provenance = loadProvenance?.invoke(record.factId) }
    ModalBottomSheet(
        onDismissRequest = onDismiss,
        sheetState = rememberModalBottomSheetState(skipPartiallyExpanded = true)
    ) {
        Column(
            modifier = Modifier.padding(horizontal = 24.dp, vertical = 16.dp)
                .verticalScroll(rememberScrollState()),
            verticalArrangement = Arrangement.spacedBy(12.dp)
        ) {
            Text(record.category ?: record.service, style = MaterialTheme.typography.titleMedium,
                fontWeight = FontWeight.Bold)
            val time = record.eventTime ?: record.capturedAt
            Text("${factTime(record, time)}  ${factDate(record, time)}", style = MaterialTheme.typography.labelMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant)
            HorizontalDivider()
            DetailSection(stringResource(R.string.timeline_detail_description),
                factDescription(record) ?: stringResource(R.string.timeline_cluster_fact_unreadable))
            DetailSection(stringResource(R.string.timeline_detail_source), record.service)
            // Provenance (C5 review I4): the source filter matches "observed by", so show both.
            provenance?.let { p ->
                DetailSection(stringResource(R.string.timeline_detail_first_captured_by),
                    stringResource(telemetrySourceLabel(p.firstCapturedBy)))
                DetailSection(
                    stringResource(R.string.timeline_detail_observed_by),
                    if (p.observedBy.isEmpty()) stringResource(R.string.timeline_detail_observed_none)
                    else p.observedBy.map { stringResource(telemetrySourceLabel(it)) }.joinToString(", "),
                )
            }
            record.packageName()?.let { pkg ->
                DetailSection(stringResource(R.string.timeline_detail_package), pkg)
                onShowOnlyApp?.let { ShowOnlyAppButton(pkg, it) }
            }
            record.fields?.forEach { (key, value) ->
                DetailSection(escapeForReport(key), escapeForReport(value.toString()))
            }
            Spacer(modifier = Modifier.height(32.dp))
        }
    }
}

@Composable
@Suppress("LongMethod") // Scan group header with expand/collapse renders type, date, count, severity, chevron
fun ScanGroupHeader(
    group: ScanGroup,
    count: Long?,
    onClick: (() -> Unit)? = null,
    onViewTelemetry: (() -> Unit)? = null,
) {
    val dateStr = remember(group.timestamp) {
        if (group.timestamp > 0) SimpleDateFormat("MMM dd, yyyy HH:mm", Locale.US).format(Date(group.timestamp))
        else ""
    }
    val unknownStr = stringResource(R.string.timeline_scan_unknown)
    val displayDate = dateStr.ifEmpty { unknownStr }
    val typeLabel = when {
        group.scanId == -1L -> stringResource(R.string.timeline_scan_unassociated)
        group.importSource == TelemetrySource.BUGREPORT_IMPORT ->
            stringResource(R.string.timeline_scan_bugreport)
        group.importSource == TelemetrySource.INTRUSION_LOG_IMPORT ->
            stringResource(R.string.timeline_scan_intrusion_log)
        else -> stringResource(R.string.timeline_scan_runtime)
    }

    Card(
        modifier = Modifier.fillMaxWidth().then(
            if (onClick != null) Modifier.clickable { onClick() } else Modifier
        ),
        colors = CardDefaults.cardColors(
            containerColor = MaterialTheme.colorScheme.surfaceContainer
        )
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(12.dp),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically
        ) {
            Column(modifier = Modifier.weight(1f)) {
                Text(
                    typeLabel,
                    style = MaterialTheme.typography.titleSmall,
                    fontWeight = FontWeight.Bold
                )
                Text(
                    displayDate,
                    style = MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
                // The scan's stored telemetry (spec §8.1 "scan headers").
                onViewTelemetry?.let { open ->
                    TextButton(onClick = open) { Text(stringResource(R.string.telemetry_view)) }
                }
            }
            Row(
                horizontalArrangement = Arrangement.spacedBy(8.dp),
                verticalAlignment = Alignment.CenterVertically
            ) {
                if (count != null) {
                    Text(
                        stringResource(R.string.timeline_event_count, count),
                        style = MaterialTheme.typography.labelSmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }
                SeverityChip(level = group.maxSeverity, active = true)
            }
        }
    }
}

private fun formatTimeRange(first: Long, last: Long): String {
    val fmt = SimpleDateFormat("HH:mm", Locale.US)
    return if (first > 0 && last > 0) {
        "${fmt.format(Date(first))}\u2013${fmt.format(Date(last))}"
    } else ""
}

/**
 * A fact's time of day, or [DATE_ONLY] for a day-precision fact (ruling R31): its stored time is the
 * start of its day, so a time of day would be invented.
 */
internal fun factTime(record: DecodedRecord, timestamp: Long): String =
    if (record.precision == TimePrecision.DAY) DATE_ONLY else formatTime(timestamp)

/** The marker a day-precision event shows in place of a time of day. */
internal const val DATE_ONLY = "(date only)"

/**
 * A fact's date: a day-precision fact's calendar date read in UTC (it is stored as that date's UTC
 * midnight, ruling R32), so it is the date the source printed in any viewer zone; otherwise the
 * instant's date on this device.
 */
internal fun factDate(record: DecodedRecord, timestamp: Long): String =
    if (record.precision == TimePrecision.DAY) civilDate(timestamp) else formatDate(timestamp)

/** A row's time of day, or [DATE_ONLY] for a day-precision row (an import finding on a battery day). */
internal fun rowTime(event: ForensicTimelineEvent): String =
    if (event.timestampPrecision.equals(TimelineRowEntity.DAY, ignoreCase = true)) DATE_ONLY
    else formatTime(event.startTimestamp)

/** A Linked Evidence line: the related row's time ([DATE_ONLY] for a day-precision row) and category. */
internal fun linkedEvidenceLabel(related: ForensicTimelineEvent): String = "${rowTime(related)}  ${related.category}"

/** A row's date; a day-precision row's calendar date in UTC (R32). */
internal fun rowDate(event: ForensicTimelineEvent): String =
    if (event.timestampPrecision.equals(TimelineRowEntity.DAY, ignoreCase = true)) civilDate(event.startTimestamp)
    else formatDate(event.startTimestamp)

private fun civilDate(ts: Long): String =
    if (ts > 0) SimpleDateFormat("MMM dd, yyyy", Locale.US).apply { timeZone = TimeZone.getTimeZone("UTC") }
        .format(Date(ts)) else "Unknown"

private fun formatTime(ts: Long) =
    if (ts > 0) SimpleDateFormat("HH:mm:ss", Locale.US).format(Date(ts)) else "??:??:??"

private fun formatDate(ts: Long) =
    if (ts > 0) SimpleDateFormat("MMM dd, yyyy", Locale.US).format(Date(ts)) else "Unknown"

/** "Show only this app" (ruling R33): sets the exact package filter, shown as a dismissible chip. */
@Composable
private fun ShowOnlyAppButton(packageName: String, onShowOnlyApp: (String) -> Unit) {
    OutlinedButton(onClick = { onShowOnlyApp(packageName) }) {
        Text(stringResource(R.string.timeline_show_only_app))
    }
}

/**
 * The fact's package, computed as the store computes `telemetry_record.packageName` (the service's
 * taxonomy package field); null when the service has none or the value is absent or empty.
 */
internal fun DecodedRecord.packageName(): String? =
    TaxonomyContract.packageField(service)?.let { fields?.get(it)?.toString() }?.takeIf { it.isNotEmpty() }
