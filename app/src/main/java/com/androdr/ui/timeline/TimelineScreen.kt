package com.androdr.ui.timeline

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.widget.Toast
import androidx.annotation.StringRes
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
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.ContentCopy
import androidx.compose.material.icons.filled.ExpandLess
import androidx.compose.material.icons.filled.ExpandMore
import androidx.compose.material.icons.filled.MoreVert
import androidx.compose.material.icons.filled.Search
import androidx.compose.material.icons.filled.Share
import androidx.compose.material.icons.filled.Timeline
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.ModalBottomSheet
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
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
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
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
// Timeline screen combines top bar, search, filter bar, paged list, empty state, overflow menu and
// the detail and filter sheets — inherently a longer composable with more branches.
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun TimelineScreen(
    initialPackage: String? = null,
    initialScanId: Long? = null,
    onNavigateToHistory: (() -> Unit)? = null,
    viewModel: TimelineViewModel = hiltViewModel()
) {
    // The deep link (Apps screen: a package, empty meaning "no real package"; import screen: a scan)
    // is applied once per navigation entry: recreation re-delivers it, and re-applying it would
    // bring back a chip the user dismissed (C5 review I1). The ViewModel keeps the guard.
    LaunchedEffect(initialPackage, initialScanId) { viewModel.applyDeepLink(initialPackage, initialScanId) }
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

    val searchText by viewModel.searchText.collectAsStateWithLifecycle()
    val activeFilters by viewModel.activeFilters.collectAsStateWithLifecycle()
    // Saved across rotation: whether search is open and whether the Filters sheet is showing.
    var searchOpen by rememberSaveable { mutableStateOf(searchText.isNotEmpty()) }
    var showFilterSheet by rememberSaveable { mutableStateOf(false) }
    var findingsExpanded by rememberSaveable { mutableStateOf(true) }
    // Ruling R34: the pinned section lists the top PINNED_FINDINGS_PREVIEW until "Show all" (saved).
    var showAllFindings by rememberSaveable { mutableStateOf(false) }
    var menuExpanded by remember { mutableStateOf(false) }
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
        // Top bar (ruling R30): the title (or the open search field), search, and one overflow menu.
        TopAppBar(
            title = {
                if (searchOpen) {
                    TimelineSearchField(text = searchText, onTextChange = viewModel::setSearchText)
                } else {
                    Text(stringResource(R.string.timeline_title))
                }
            },
            // While searching, a back arrow closes search (and clears it); the field's X only clears text.
            navigationIcon = {
                if (searchOpen) {
                    IconButton(onClick = {
                        searchOpen = false
                        viewModel.clearSearch()
                    }) {
                        Icon(
                            Icons.AutoMirrored.Filled.ArrowBack,
                            contentDescription = stringResource(R.string.cd_timeline_search_close),
                        )
                    }
                }
            },
            actions = {
                if (!searchOpen) {
                    IconButton(onClick = { searchOpen = true }) {
                        Icon(Icons.Filled.Search, contentDescription = stringResource(R.string.cd_timeline_search))
                    }
                }
                if (exporting) {
                    CircularProgressIndicator(modifier = Modifier.size(24.dp), strokeWidth = 2.dp)
                }
                Box {
                    IconButton(onClick = { menuExpanded = true }) {
                        Icon(Icons.Filled.MoreVert, contentDescription = stringResource(R.string.cd_timeline_more))
                    }
                    DropdownMenu(expanded = menuExpanded, onDismissRequest = { menuExpanded = false }) {
                        fun close(action: () -> Unit): () -> Unit = {
                            menuExpanded = false
                            action()
                        }
                        onNavigateToHistory?.let { MenuItem(R.string.timeline_menu_history, onClick = close(it)) }
                        MenuItem(R.string.timeline_menu_view_report, enabled = hasRows, onClick = close {
                            viewModel.generateReport()
                            showReportSheet = true
                        })
                        MenuItem(R.string.timeline_menu_copy, enabled = hasRows, onClick = close {
                            pendingCopy = true
                            viewModel.generateReport()
                        })
                        MenuItem(R.string.timeline_export_txt, enabled = hasRows && !exporting,
                            onClick = close(viewModel::exportPlaintext))
                        MenuItem(R.string.timeline_export_csv, enabled = hasRows && !exporting,
                            onClick = close(viewModel::exportCsv))
                        MenuItem(R.string.timeline_export_full, enabled = !exporting,
                            onClick = close { showExportModeDialog = true })
                    }
                }
            }
        )

        // One compact filter row (ruling R30): Filters (n), a chip per active filter, the live count.
        TimelineFilterBar(
            chips = activeFilters,
            totalCount = totalCount,
            onOpenFilters = { showFilterSheet = true },
            onDismiss = viewModel::dismiss,
        )

        // "No timeline events yet" only when nothing narrows the list; a filtered empty list shows its 0 count.
        val unfiltered = showPinnedFindings(filter, activeFilters)
        if (totalCount == 0L && unfiltered && findings.isEmpty() && groupMode == TimelineGroupMode.DATE) {
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
                // Pinned section: the current findings (the latest scan's), shown only while nothing
                // narrows the list, so search and filter results never sit below an unfiltered block.
                if (showPinnedFindings(filter, activeFilters) && findings.isNotEmpty()) {
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
                        val shown = pinnedFindings(findings, showAllFindings)
                        items(shown.size, key = { "current_$it" }) { i ->
                            FindingCard(row = TimelineRow.FindingRow(shown[i]))
                        }
                        if (findings.size > PINNED_FINDINGS_PREVIEW) {
                            item(key = "current_findings_toggle") {
                                PinnedFindingsToggle(showAllFindings, findings.size) {
                                    showAllFindings = !showAllFindings
                                }
                            }
                        }
                    }
                }
                val search = filter.searchText
                if (search != null && totalCount == 0L) {
                    item(key = "no_matches") {
                        Text(
                            stringResource(R.string.timeline_search_no_matches, search),
                            style = MaterialTheme.typography.bodyMedium,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
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
            onShowOnlyApp = { pkg ->
                selectedEvent = null
                viewModel.showOnlyApp(pkg)
            },
            relatedEvents = related,
            onJumpToRelated = { selectedEvent = it }
        )
    }
    selectedRecord?.let { record ->
        FactDetailSheet(
            record = record,
            onDismiss = { selectedRecord = null },
            loadProvenance = viewModel::provenance,
            onShowOnlyApp = { pkg ->
                selectedRecord = null
                viewModel.showOnlyApp(pkg)
            },
        )
    }

    if (showReportSheet) {
        ReportViewSheet(
            report = report,
            onDismiss = { showReportSheet = false; viewModel.clearReport() },
            onCopy = { copy(viewModel.report.value) },
            onShare = { viewModel.shareReport() }
        )
    }

    if (showFilterSheet) {
        TimelineFilterSheet(
            filter = filter,
            groupMode = groupMode,
            actions = TimelineFilterActions(
                setFindingsOnly = viewModel::setFindingsAndEvidenceOnly,
                toggleSeverity = viewModel::toggleSeverity,
                setSource = viewModel::setSourceFilter,
                setRangeHours = viewModel::setRecentHours,
                setGroupMode = viewModel::setGroupMode,
            ),
            onDismiss = { showFilterSheet = false },
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

/** "Show all N" / "Show fewer" under the pinned findings (ruling R34). */
@Composable
private fun PinnedFindingsToggle(showAll: Boolean, total: Int, onToggle: () -> Unit) {
    val description = if (showAll) {
        stringResource(R.string.cd_timeline_findings_show_fewer, PINNED_FINDINGS_PREVIEW)
    } else {
        stringResource(R.string.cd_timeline_findings_show_all, total)
    }
    TextButton(onClick = onToggle, modifier = Modifier.semantics { contentDescription = description }) {
        Text(
            if (showAll) stringResource(R.string.timeline_findings_show_fewer)
            else stringResource(R.string.timeline_findings_show_all, total)
        )
    }
}

/** One overflow-menu entry. */
@Composable
private fun MenuItem(@StringRes label: Int, enabled: Boolean = true, onClick: () -> Unit) {
    DropdownMenuItem(text = { Text(stringResource(label)) }, enabled = enabled, onClick = onClick)
}

/** A stable list key per row: an entry by kind and id, a header by its day. */
private fun rowKey(row: TimelineRow): String = when (row) {
    is TimelineRow.Entry -> "e${row.entity.rowKind}_${row.entity.id}"
    is TimelineRow.DayHeader -> "day_${row.day}_${row.anchor}"
    is TimelineRow.FindingRow -> "finding_${row.finding.ruleId}"
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

/** A count loaded off the composition (null while loading), reloaded when any of [keys] changes. */
@Composable
private fun rememberCount(vararg keys: Any?, load: suspend () -> Long?): Long? {
    var count by remember(*keys) { mutableStateOf<Long?>(null) }
    LaunchedEffect(*keys) { count = load() }
    return count
}

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

/**
 * Whether the pinned "Current findings" section shows (C5 review I2): only while no filter and no
 * search narrow the list. It is the latest scan's findings, unfiltered, so above a filtered or
 * searched list it would bury the results under entries the filter excludes.
 */
internal fun showPinnedFindings(filter: TimelineFilter, activeFilters: List<ActiveFilter>): Boolean =
    activeFilters.isEmpty() && filter.searchText == null
