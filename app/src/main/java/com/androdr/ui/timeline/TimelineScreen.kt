package com.androdr.ui.timeline

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.widget.Toast
import androidx.compose.animation.AnimatedVisibility
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.LazyRow
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.ContentCopy
import androidx.compose.material.icons.filled.Description
import androidx.compose.material.icons.filled.ExpandLess
import androidx.compose.material.icons.filled.ExpandMore
import androidx.compose.material.icons.filled.History
import androidx.compose.material.icons.filled.Share
import androidx.compose.material.icons.filled.Timeline
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FilterChip
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.ModalBottomSheet
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.rememberModalBottomSheetState
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.paging.compose.collectAsLazyPagingItems
import androidx.paging.compose.itemKey
import com.androdr.R
import com.androdr.data.db.TimelineFilter
import com.androdr.data.model.ForensicTimelineEvent
import com.androdr.data.model.effectiveCorrelationId
import com.androdr.data.store.DecodedRecord
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

@Suppress("LongMethod", "CyclomaticComplexMethod")
// Timeline screen combines top bar, filter bar, paged list, empty state, export menu and the
// detail sheets — inherently a longer composable with more branches.
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun TimelineScreen(
    initialPackage: String? = null,
    initialScanId: Long? = null,
    onNavigateToHistory: (() -> Unit)? = null,
    viewModel: TimelineViewModel = hiltViewModel()
) {
    // Apply deep-link filter once on first composition. Treat an empty `initialPackage` as "no
    // filter" — the Apps screen uses empty to mean "this group has no real package".
    LaunchedEffect(initialPackage) {
        when {
            initialPackage == null -> Unit
            initialPackage.isBlank() -> viewModel.setPackageFilter(null)
            else -> viewModel.setPackageFilter(initialPackage)
        }
    }
    // The import screen's link: one scan's rows and the facts it observed.
    LaunchedEffect(initialScanId) {
        if (initialScanId != null) viewModel.setScanFilter(initialScanId)
    }
    val filter by viewModel.filter.collectAsStateWithLifecycle()
    val rows = viewModel.rows.collectAsLazyPagingItems()
    val totalCount by viewModel.totalCount.collectAsStateWithLifecycle()
    val countsVersion by viewModel.countsVersion.collectAsStateWithLifecycle()
    val findings by viewModel.findings.collectAsStateWithLifecycle()
    val shareUri by viewModel.shareUri.collectAsStateWithLifecycle()
    val exporting by viewModel.exporting.collectAsStateWithLifecycle()
    val groupMode by viewModel.groupMode.collectAsStateWithLifecycle()
    val scanGroups by viewModel.scanGroups.collectAsStateWithLifecycle()
    val report by viewModel.report.collectAsStateWithLifecycle()

    val context = LocalContext.current
    val hasRows = (totalCount ?: 0L) > 0L

    var filterPanelExpanded by rememberSaveable { mutableStateOf(true) }
    var findingsExpanded by rememberSaveable { mutableStateOf(true) }
    var exportMenuExpanded by remember { mutableStateOf(false) }
    var showExportModeDialog by remember { mutableStateOf(false) }
    var pendingCopy by remember { mutableStateOf(false) }
    var selectedEvent by remember { mutableStateOf<ForensicTimelineEvent?>(null) }
    var selectedRecord by remember { mutableStateOf<DecodedRecord?>(null) }
    var showReportSheet by remember { mutableStateOf(false) }

    fun copy(preview: ReportPreview) {
        if (preview.truncated) {
            Toast.makeText(context, context.getString(R.string.timeline_report_too_large), Toast.LENGTH_LONG).show()
            return
        }
        val clipboard = context.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
        clipboard.setPrimaryClip(ClipData.newPlainText("AndroDR Timeline", preview.text))
        Toast.makeText(context, context.getString(R.string.timeline_copied), Toast.LENGTH_SHORT).show()
    }

    // Copy to clipboard once report text is ready
    LaunchedEffect(report, pendingCopy) {
        if (pendingCopy && report.text.isNotEmpty()) {
            copy(report)
            pendingCopy = false
        }
    }

    // Launch share intent when a report URI is ready
    LaunchedEffect(shareUri) {
        shareUri?.let { uri ->
            val shareIntent = Intent(Intent.ACTION_SEND).apply {
                type = "text/plain"
                putExtra(Intent.EXTRA_STREAM, uri)
                putExtra(Intent.EXTRA_SUBJECT, "AndroDR Timeline Report")
                addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
            }
            context.startActivity(Intent.createChooser(shareIntent, "Share Timeline Report"))
            viewModel.onShareConsumed()
        }
    }

    Column(modifier = Modifier.fillMaxSize()) {
        TopAppBar(
            title = { Text(stringResource(R.string.timeline_title)) },
            actions = {
                if (onNavigateToHistory != null) {
                    IconButton(onClick = onNavigateToHistory) {
                        Icon(Icons.Filled.History, contentDescription = "Manage scans")
                    }
                }
                IconButton(
                    onClick = {
                        viewModel.generateReport()
                        showReportSheet = true
                    },
                    enabled = hasRows
                ) {
                    Icon(Icons.Filled.Description, contentDescription = stringResource(R.string.cd_view_report))
                }
                IconButton(
                    onClick = {
                        pendingCopy = true
                        viewModel.generateReport()
                    },
                    enabled = hasRows
                ) {
                    Icon(Icons.Filled.ContentCopy, contentDescription = stringResource(R.string.cd_copy_report))
                }
                if (exporting) {
                    CircularProgressIndicator(modifier = Modifier.size(24.dp), strokeWidth = 2.dp)
                } else {
                    Box {
                        IconButton(onClick = { exportMenuExpanded = true }, enabled = hasRows) {
                            Icon(Icons.Filled.Share, contentDescription = stringResource(R.string.cd_export))
                        }
                        DropdownMenu(expanded = exportMenuExpanded, onDismissRequest = { exportMenuExpanded = false }) {
                            DropdownMenuItem(
                                text = { Text(stringResource(R.string.timeline_export_txt)) },
                                onClick = {
                                    exportMenuExpanded = false
                                    viewModel.exportPlaintext()
                                }
                            )
                            DropdownMenuItem(
                                text = { Text(stringResource(R.string.timeline_export_csv)) },
                                onClick = {
                                    exportMenuExpanded = false
                                    viewModel.exportCsv()
                                }
                            )
                            DropdownMenuItem(
                                text = { Text("Full Report…") },
                                onClick = {
                                    exportMenuExpanded = false
                                    showExportModeDialog = true
                                }
                            )
                        }
                    }
                }
            }
        )

        if (filter.scanId != null) {
            Row(
                modifier = Modifier.fillMaxWidth().padding(horizontal = 16.dp),
                verticalAlignment = Alignment.CenterVertically
            ) {
                FilterChip(
                    selected = true,
                    onClick = { viewModel.setScanFilter(null) },
                    label = { Text(stringResource(R.string.timeline_scan_filter_clear)) }
                )
            }
        }

        // The filter bar, with the filter's count.
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .clickable { filterPanelExpanded = !filterPanelExpanded }
                .padding(horizontal = 16.dp, vertical = 8.dp),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.SpaceBetween
        ) {
            Text(
                text = totalCount?.let { stringResource(R.string.timeline_filters_count, it) } ?: "Filters",
                style = MaterialTheme.typography.labelLarge,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
            Icon(
                imageVector = if (filterPanelExpanded) Icons.Filled.ExpandLess else Icons.Filled.ExpandMore,
                contentDescription = if (filterPanelExpanded) "Collapse filters" else "Expand filters",
                tint = MaterialTheme.colorScheme.onSurfaceVariant
            )
        }

        AnimatedVisibility(visible = filterPanelExpanded) {
            TimelineFilterPanel(viewModel, filter, groupMode)
        }

        if (totalCount == 0L && findings.isEmpty() && groupMode == TimelineGroupMode.DATE) {
            TimelineEmptyState()
        } else if (groupMode == TimelineGroupMode.SCAN) {
            LazyColumn(
                modifier = Modifier.fillMaxSize(),
                contentPadding = PaddingValues(horizontal = 16.dp, vertical = 8.dp),
                verticalArrangement = Arrangement.spacedBy(8.dp)
            ) {
                if (scanGroups.isEmpty()) {
                    item {
                        Text(
                            text = stringResource(R.string.timeline_scan_empty),
                            style = MaterialTheme.typography.bodyMedium,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                    }
                }
                items(scanGroups, key = { "scan_${it.scanId}" }) { group ->
                    val count = rememberCount(group.scanId, filter, countsVersion) { viewModel.scanCount(group.scanId) }
                    // A scan header opens that scan's Timeline.
                    ScanGroupHeader(group = group, count = count, onClick = {
                        viewModel.setScanFilter(group.scanId)
                        viewModel.setGroupMode(TimelineGroupMode.DATE)
                    })
                }
            }
        } else {
            LazyColumn(
                modifier = Modifier.fillMaxSize(),
                contentPadding = PaddingValues(horizontal = 16.dp, vertical = 8.dp),
                verticalArrangement = Arrangement.spacedBy(8.dp)
            ) {
                // Pinned section: the current findings (the latest scan's).
                if (findings.isNotEmpty()) {
                    item(key = "current_findings") {
                        Row(
                            modifier = Modifier.fillMaxWidth().clickable { findingsExpanded = !findingsExpanded },
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Text(
                                stringResource(R.string.timeline_current_findings, findings.size),
                                style = MaterialTheme.typography.titleSmall,
                                color = MaterialTheme.colorScheme.primary,
                                modifier = Modifier.weight(1f)
                            )
                            Icon(if (findingsExpanded) Icons.Filled.ExpandLess else Icons.Filled.ExpandMore, null)
                        }
                    }
                    if (findingsExpanded) {
                        items(findings.size, key = { "current_$it" }) { i ->
                            FindingCard(row = TimelineRow.FindingRow(findings[i]))
                        }
                    }
                }
                items(
                    count = rows.itemCount,
                    key = rows.itemKey { rowKey(it) },
                ) { index ->
                    when (val row = rows[index]) {
                        null -> Unit
                        is TimelineRow.DayHeader -> DayHeaderRow(row.day, filter, countsVersion, viewModel)
                        is TimelineRow.StoredRow -> StoredRowCard(
                            row = row,
                            loadPage = viewModel::loadClusterPage,
                            onEventTap = { selectedEvent = it },
                            onRecordTap = { selectedRecord = it },
                        )
                        is TimelineRow.EventRow -> FactCard(
                            record = row.record, timestamp = row.timestamp, onClick = { selectedRecord = row.record },
                        )
                        is TimelineRow.FindingRow -> FindingCard(row = row)
                    }
                }
            }
        }
    }

    selectedEvent?.let { event ->
        // Linked Evidence: loaded rows sharing this row's effective correlation key
        // ("dns:<domain>" or "pkg:<packageName>"; see effectiveCorrelationId).
        val key = event.effectiveCorrelationId()
        val related = if (key.isNotEmpty()) {
            rows.itemSnapshotList.items.filterIsInstance<TimelineRow.StoredRow>().map { it.event }
                .filter { it.effectiveCorrelationId() == key && it.id != event.id }
        } else emptyList()
        TimelineEventDetailSheet(
            event = event,
            onDismiss = { selectedEvent = null },
            relatedEvents = related,
            onJumpToRelated = { selectedEvent = it }
        )
    }
    selectedRecord?.let { record -> FactDetailSheet(record, onDismiss = { selectedRecord = null }) }

    if (showReportSheet) {
        ReportViewSheet(
            report = report,
            onDismiss = { showReportSheet = false; viewModel.clearReport() },
            onCopy = { copy(viewModel.report.value) },
            onShare = { viewModel.shareReport() }
        )
    }

    if (showExportModeDialog) {
        com.androdr.ui.common.ExportModeDialog(
            onDismiss = { showExportModeDialog = false },
            onConfirm = { mode ->
                showExportModeDialog = false
                viewModel.exportFullReport(mode)
            }
        )
    }
}

/** A stable list key per row: an entry by kind and id, a header by its day. */
private fun rowKey(row: TimelineRow): String = when (row) {
    is TimelineRow.Entry -> "e${row.entity.rowKind}_${row.entity.id}"
    is TimelineRow.DayHeader -> "day_${row.day}"
    is TimelineRow.FindingRow -> "finding_${row.finding.ruleId}"
}

@Suppress("LongMethod") // the switch, severity chips, package chips, group mode and date range
@Composable
private fun TimelineFilterPanel(viewModel: TimelineViewModel, filter: TimelineFilter, groupMode: TimelineGroupMode) {
    Column {
        Row(
            modifier = Modifier.fillMaxWidth().padding(horizontal = 16.dp, vertical = 4.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            androidx.compose.material3.Switch(
                checked = filter.findingsAndEvidenceOnly,
                onCheckedChange = viewModel::setFindingsAndEvidenceOnly
            )
            Spacer(Modifier.width(8.dp))
            Text(stringResource(R.string.timeline_findings_evidence_only), style = MaterialTheme.typography.bodyMedium)
        }

        LazyRow(contentPadding = ChipPadding, horizontalArrangement = ChipSpacing) {
            items(listOf("CRITICAL", "HIGH", "MEDIUM", "LOW")) { level ->
                FilterChip(
                    selected = level in filter.levels,
                    onClick = { viewModel.toggleSeverity(level) },
                    label = { Text(level) }
                )
            }
        }

        val packages by viewModel.availablePackages.collectAsStateWithLifecycle()
        if (packages.isNotEmpty()) {
            LazyRow(contentPadding = ChipPadding, horizontalArrangement = ChipSpacing) {
                items(packages.take(PACKAGE_CHIPS)) { pkg ->
                    FilterChip(
                        selected = filter.packageName == pkg,
                        onClick = { viewModel.setPackageFilter(if (filter.packageName == pkg) null else pkg) },
                        label = { Text(pkg.substringAfterLast("."), maxLines = 1) }
                    )
                }
            }
        }

        LazyRow(contentPadding = ChipPadding, horizontalArrangement = ChipSpacing) {
            item {
                FilterChip(
                    selected = groupMode == TimelineGroupMode.DATE,
                    onClick = { viewModel.setGroupMode(TimelineGroupMode.DATE) },
                    label = { Text(stringResource(R.string.timeline_group_date)) }
                )
            }
            item {
                FilterChip(
                    selected = groupMode == TimelineGroupMode.SCAN,
                    onClick = { viewModel.setGroupMode(TimelineGroupMode.SCAN) },
                    label = { Text(stringResource(R.string.timeline_group_scan)) }
                )
            }
        }

        data class RangeOption(val hoursBack: Int?, val label: String)
        val rangeOptions = listOf(
            RangeOption(null, stringResource(R.string.timeline_filter_all)),
            RangeOption(24, stringResource(R.string.timeline_range_24h)),
            RangeOption(24 * 7, stringResource(R.string.timeline_range_7d)),
            RangeOption(24 * 30, stringResource(R.string.timeline_range_30d))
        )
        var activeRangeHours by remember { mutableStateOf<Int?>(null) }
        if (filter.from == null) activeRangeHours = null
        LazyRow(contentPadding = ChipPadding, horizontalArrangement = ChipSpacing) {
            items(rangeOptions) { option ->
                FilterChip(
                    selected = activeRangeHours == option.hoursBack,
                    onClick = {
                        if (option.hoursBack == null) {
                            activeRangeHours = null
                            viewModel.clearDateRange()
                        } else {
                            activeRangeHours = option.hoursBack
                            val now = System.currentTimeMillis()
                            viewModel.setDateRange(now - option.hoursBack * 3600_000L, now)
                        }
                    },
                    label = { Text(option.label) }
                )
            }
        }
        Spacer(modifier = Modifier.height(8.dp))
    }
}

/** A day's header, with the count of what the current filter shows that day. */
@Composable
private fun DayHeaderRow(day: Long, filter: TimelineFilter, countsVersion: Int, viewModel: TimelineViewModel) {
    val count = rememberCount(day, filter, countsVersion) { viewModel.dayCount(day) }
    val label = if (day == TimelineFilter.UNKNOWN_DAY) {
        stringResource(R.string.timeline_unknown_date)
    } else {
        remember(day, filter.zone) {
            SimpleDateFormat("MMM dd, yyyy", Locale.US).apply { timeZone = java.util.TimeZone.getTimeZone(filter.zone) }
                .format(Date(day))
        }
    }
    Text(
        text = count?.let { "$label · ${stringResource(R.string.timeline_event_count, it)}" } ?: label,
        style = MaterialTheme.typography.titleSmall,
        color = MaterialTheme.colorScheme.primary,
        modifier = Modifier.padding(vertical = 4.dp)
    )
}

/** A `forensic_timeline` row: a signal as its cluster, otherwise the row with its nested evidence. */
@Composable
private fun StoredRowCard(
    row: TimelineRow.StoredRow,
    loadPage: suspend (Long, com.androdr.sigma.AtomRef?) -> ClusterPage,
    onEventTap: (ForensicTimelineEvent) -> Unit,
    onRecordTap: (DecodedRecord) -> Unit,
) {
    if (row.event.kind == "signal") {
        CorrelationClusterCard(cluster = signalCluster(row.event), loadPage = loadPage, onEventTap = onEventTap)
        return
    }
    Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
        TimelineEventCard(event = row.event, onClick = { onEventTap(row.event) })
        row.evidence?.let { evidence ->
            Box(modifier = Modifier.padding(start = 16.dp)) {
                FactCard(
                    record = evidence,
                    timestamp = evidence.eventTime ?: evidence.capturedAt,
                    label = stringResource(R.string.timeline_matched_record),
                    onClick = { onRecordTap(evidence) },
                )
            }
        }
    }
}

@Composable
private fun TimelineEmptyState() {
    Box(modifier = Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
        Column(horizontalAlignment = Alignment.CenterHorizontally, verticalArrangement = Arrangement.spacedBy(12.dp)) {
            Icon(
                imageVector = Icons.Filled.Timeline,
                contentDescription = null,
                modifier = Modifier.size(64.dp),
                tint = MaterialTheme.colorScheme.onSurfaceVariant.copy(alpha = 0.5f)
            )
            Text(
                text = stringResource(R.string.timeline_empty),
                style = MaterialTheme.typography.titleMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
            Text(
                text = stringResource(R.string.timeline_empty_hint),
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant.copy(alpha = 0.7f)
            )
        }
    }
}

private const val PACKAGE_CHIPS = 10

/** A count loaded off the composition (null while loading), reloaded when any of [keys] changes. */
@Composable
private fun rememberCount(vararg keys: Any?, load: suspend () -> Long): Long? {
    var count by remember(*keys) { mutableStateOf<Long?>(null) }
    LaunchedEffect(*keys) { count = load() }
    return count
}
private val ChipPadding = PaddingValues(horizontal = 16.dp)
private val ChipSpacing = Arrangement.spacedBy(8.dp)

@Suppress("LongMethod") // Sheet includes header, scrollable body, dividers, and two action buttons
@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun ReportViewSheet(
    report: ReportPreview,
    onDismiss: () -> Unit,
    onCopy: () -> Unit,
    onShare: () -> Unit
) {
    ModalBottomSheet(
        onDismissRequest = onDismiss,
        sheetState = rememberModalBottomSheetState(skipPartiallyExpanded = true)
    ) {
        Column(modifier = Modifier.padding(horizontal = 24.dp, vertical = 16.dp)) {
            Text(
                text = stringResource(R.string.timeline_report_title),
                style = MaterialTheme.typography.titleMedium,
                fontWeight = FontWeight.Bold
            )
            if (report.truncated) {
                Text(
                    text = stringResource(R.string.timeline_report_preview_truncated),
                    style = MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
            Spacer(modifier = Modifier.height(12.dp))
            HorizontalDivider()
            Spacer(modifier = Modifier.height(12.dp))
            Column(modifier = Modifier.weight(1f, fill = false).verticalScroll(rememberScrollState())) {
                if (report.text.isEmpty()) {
                    CircularProgressIndicator(modifier = Modifier.align(Alignment.CenterHorizontally))
                } else {
                    Text(
                        text = report.text,
                        style = MaterialTheme.typography.bodySmall,
                        fontFamily = FontFamily.Monospace,
                        color = MaterialTheme.colorScheme.onSurface
                    )
                }
            }
            Spacer(modifier = Modifier.height(16.dp))
            HorizontalDivider()
            Spacer(modifier = Modifier.height(12.dp))
            Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                OutlinedButton(
                    onClick = onCopy,
                    modifier = Modifier.weight(1f),
                    enabled = report.text.isNotEmpty() && !report.truncated
                ) {
                    Icon(Icons.Filled.ContentCopy, null, Modifier.size(18.dp))
                    Spacer(Modifier.width(8.dp))
                    Text(stringResource(R.string.timeline_copy))
                }
                Button(onClick = onShare, modifier = Modifier.weight(1f), enabled = report.text.isNotEmpty()) {
                    Icon(Icons.Filled.Share, null, Modifier.size(18.dp))
                    Spacer(Modifier.width(8.dp))
                    Text(stringResource(R.string.timeline_share))
                }
            }
            Spacer(modifier = Modifier.height(16.dp))
        }
    }
}
