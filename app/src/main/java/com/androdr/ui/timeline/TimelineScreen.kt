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
import androidx.compose.material.icons.filled.History
import androidx.compose.material.icons.filled.ExpandLess
import androidx.compose.material.icons.filled.ExpandMore
import androidx.compose.material.icons.filled.MoreVert
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
import com.androdr.R
import com.androdr.data.model.ForensicTimelineEvent
import com.androdr.data.model.effectiveCorrelationId
@Suppress("LongMethod", "CyclomaticComplexMethod")
// Timeline screen combines top bar, filter chips, grouped event list,
// empty state, export menu, detail sheet, and correlation-aware jump
// handler — inherently a longer composable with more branches.
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun TimelineScreen(
    initialPackage: String? = null,
    onNavigateToHistory: (() -> Unit)? = null,
    viewModel: TimelineViewModel = hiltViewModel()
) {
    // Apply deep-link filter once on first composition. Treat an empty
    // `initialPackage` as "no filter" — the Apps screen uses empty to mean
    // "this group has no real package (it's DNS-sourced), just show the
    // timeline so the user can browse the underlying evidence".
    LaunchedEffect(initialPackage) {
        when {
            initialPackage == null -> Unit
            initialPackage.isBlank() -> viewModel.setPackageFilter(null)
            else -> viewModel.setPackageFilter(initialPackage)
        }
    }

    val events by viewModel.events.collectAsStateWithLifecycle()
    val dateGroups by viewModel.dateGroupedRows.collectAsStateWithLifecycle()
    val hideInformational by viewModel.hideInformationalTelemetry.collectAsStateWithLifecycle()
    val shareUri by viewModel.shareUri.collectAsStateWithLifecycle()
    val exporting by viewModel.exporting.collectAsStateWithLifecycle()
    val groupMode by viewModel.groupMode.collectAsStateWithLifecycle()
    val scanGroups by viewModel.scanGroupedEvents.collectAsStateWithLifecycle()

    val context = LocalContext.current

    val reportText by viewModel.reportText.collectAsStateWithLifecycle()

    var filterPanelExpanded by rememberSaveable { mutableStateOf(true) }
    var exportMenuExpanded by remember { mutableStateOf(false) }
    var showExportModeDialog by remember { mutableStateOf(false) }
    var pendingCopy by remember { mutableStateOf(false) }

    // Copy to clipboard once report text is ready
    LaunchedEffect(reportText, pendingCopy) {
        if (pendingCopy && reportText.isNotEmpty()) {
            val clipboard = context.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
            clipboard.setPrimaryClip(ClipData.newPlainText("AndroDR Timeline", reportText))
            Toast.makeText(context, context.getString(R.string.timeline_copied), Toast.LENGTH_SHORT).show()
            pendingCopy = false
        }
    }
    var selectedEvent by remember { mutableStateOf<ForensicTimelineEvent?>(null) }
    var showReportSheet by remember { mutableStateOf(false) }

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
                // Manage scan history
                if (onNavigateToHistory != null) {
                    IconButton(onClick = onNavigateToHistory) {
                        Icon(Icons.Filled.History, contentDescription = "Manage scans")
                    }
                }
                // View report
                IconButton(
                    onClick = {
                        viewModel.generateReport()
                        showReportSheet = true
                    },
                    enabled = events.isNotEmpty()
                ) {
                    Icon(Icons.Filled.Description, contentDescription = stringResource(R.string.cd_view_report))
                }
                // Copy to clipboard — generate report, LaunchedEffect copies when ready
                IconButton(
                    onClick = {
                        pendingCopy = true
                        viewModel.generateReport()
                    },
                    enabled = events.isNotEmpty()
                ) {
                    Icon(Icons.Filled.ContentCopy, contentDescription = stringResource(R.string.cd_copy_report))
                }
                // Export menu
                if (exporting) {
                    CircularProgressIndicator(
                        modifier = Modifier.size(24.dp),
                        strokeWidth = 2.dp
                    )
                } else {
                    Box {
                        IconButton(
                            onClick = { exportMenuExpanded = true },
                            enabled = events.isNotEmpty()
                        ) {
                            Icon(Icons.Filled.Share, contentDescription = stringResource(R.string.cd_export))
                        }
                        DropdownMenu(
                            expanded = exportMenuExpanded,
                            onDismissRequest = { exportMenuExpanded = false }
                        ) {
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
                                text = { Text("Full Report\u2026") },
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

        Row(
            modifier = Modifier
                .fillMaxWidth()
                .clickable { filterPanelExpanded = !filterPanelExpanded }
                .padding(horizontal = 16.dp, vertical = 8.dp),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.SpaceBetween
        ) {
            Text(
                text = "Filters",
                style = MaterialTheme.typography.labelLarge,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
            Icon(
                imageVector = if (filterPanelExpanded) Icons.Filled.ExpandLess
                    else Icons.Filled.ExpandMore,
                contentDescription = if (filterPanelExpanded) "Collapse filters"
                    else "Expand filters",
                tint = MaterialTheme.colorScheme.onSurfaceVariant
            )
        }

        AnimatedVisibility(visible = filterPanelExpanded) {
            Column {
                // Hide informational telemetry toggle — when ON, telemetry
                // rows not referenced by any finding are hidden. Finding
                // rows and their anchor telemetry events remain visible.
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(horizontal = 16.dp, vertical = 4.dp),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    androidx.compose.material3.Switch(
                        checked = hideInformational,
                        onCheckedChange = viewModel::setHideInformationalTelemetry
                    )
                    Spacer(Modifier.width(8.dp))
                    Text(
                        text = "Hide informational telemetry",
                        style = MaterialTheme.typography.bodyMedium
                    )
                }

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

                // Package filter chips
                val packages by viewModel.availablePackages.collectAsStateWithLifecycle()
                val packageFilter by viewModel.packageFilter.collectAsStateWithLifecycle()

                if (packages.isNotEmpty()) {
                    LazyRow(
                        contentPadding = PaddingValues(horizontal = 16.dp),
                        horizontalArrangement = Arrangement.spacedBy(8.dp)
                    ) {
                        items(packages.take(10)) { pkg ->
                            FilterChip(
                                selected = packageFilter == pkg,
                                onClick = {
                                    viewModel.setPackageFilter(
                                        if (packageFilter == pkg) null else pkg
                                    )
                                },
                                label = { Text(pkg.substringAfterLast("."), maxLines = 1) }
                            )
                        }
                    }
                }

                // Group mode toggle
                LazyRow(
                    contentPadding = PaddingValues(horizontal = 16.dp),
                    horizontalArrangement = Arrangement.spacedBy(8.dp)
                ) {
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

                // Date range filter chips
                val dateRange by viewModel.dateRange.collectAsStateWithLifecycle()

                data class RangeOption(val hoursBack: Int?, val label: String)
                val rangeOptions = listOf(
                    RangeOption(null, stringResource(R.string.timeline_filter_all)),
                    RangeOption(24, stringResource(R.string.timeline_range_24h)),
                    RangeOption(24 * 7, stringResource(R.string.timeline_range_7d)),
                    RangeOption(24 * 30, stringResource(R.string.timeline_range_30d))
                )
                var activeRangeHours by remember { mutableStateOf<Int?>(null) }

                if (dateRange == null) activeRangeHours = null

                LazyRow(
                    contentPadding = PaddingValues(horizontal = 16.dp),
                    horizontalArrangement = Arrangement.spacedBy(8.dp)
                ) {
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
                                    viewModel.setDateRange(
                                        now - option.hoursBack * 3600_000L, now
                                    )
                                }
                            },
                            label = { Text(option.label) }
                        )
                    }
                }

                Spacer(modifier = Modifier.height(8.dp))
            }
        }

        val isEmpty = if (groupMode == TimelineGroupMode.SCAN) events.isEmpty() else dateGroups.isEmpty()
        if (isEmpty) {
            // Empty state
            Box(
                modifier = Modifier.fillMaxSize(),
                contentAlignment = Alignment.Center
            ) {
                Column(
                    horizontalAlignment = Alignment.CenterHorizontally,
                    verticalArrangement = Arrangement.spacedBy(12.dp)
                ) {
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
        } else if (groupMode == TimelineGroupMode.SCAN) {
            LazyColumn(
                modifier = Modifier.fillMaxSize(),
                contentPadding = PaddingValues(horizontal = 16.dp, vertical = 8.dp),
                verticalArrangement = Arrangement.spacedBy(8.dp)
            ) {
                if (scanGroups.isEmpty()) {
                    item {
                        Box(
                            modifier = Modifier.fillParentMaxSize(),
                            contentAlignment = Alignment.Center
                        ) {
                            Text(
                                text = stringResource(R.string.timeline_scan_empty),
                                style = MaterialTheme.typography.bodyMedium,
                                color = MaterialTheme.colorScheme.onSurfaceVariant
                            )
                        }
                    }
                } else {
                    scanGroups.forEach { group ->
                        item(key = "scan_${group.scanId}") {
                            var expanded by remember { mutableStateOf(false) }
                            Column {
                                ScanGroupHeader(
                                    group = group,
                                    expanded = expanded,
                                    onToggle = { expanded = !expanded }
                                )
                                if (expanded) {
                                    group.clusters.forEach { cluster ->
                                        CorrelationClusterCard(
                                            cluster = cluster,
                                            onEventTap = { selectedEvent = it }
                                        )
                                    }
                                    group.standaloneEvents.forEach { event ->
                                        TimelineEventCard(
                                            event = event,
                                            onClick = { selectedEvent = event }
                                        )
                                    }
                                }
                            }
                        }
                    }
                }
            }
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
    }

    // Detail bottom sheet
    selectedEvent?.let { event ->
        // Linked Evidence: other events that share this row's effective
        // correlation key. Covers two link shapes:
        //   * DNS-sourced findings + ioc_match rows → "dns:<domain>"
        //   * Package-scoped activity (install, lifecycle, permission_use,
        //     findings) → "pkg:<packageName>"
        // See TimelineClusters.effectiveCorrelationId for precedence.
        val key = event.effectiveCorrelationId()
        val related = if (key.isNotEmpty()) {
            events.filter { it.effectiveCorrelationId() == key && it.id != event.id }
        } else emptyList()
        TimelineEventDetailSheet(
            event = event,
            onDismiss = { selectedEvent = null },
            relatedEvents = related,
            onJumpToRelated = { selectedEvent = it }
        )
    }

    // Report viewing bottom sheet
    if (showReportSheet) {
        ReportViewSheet(
            reportText = reportText,
            onDismiss = { showReportSheet = false; viewModel.clearReport() },
            onCopy = {
                val textToCopy = viewModel.reportText.value
                if (textToCopy.isNotEmpty()) {
                    val clipboard = context.getSystemService(Context.CLIPBOARD_SERVICE)
                        as ClipboardManager
                    clipboard.setPrimaryClip(
                        ClipData.newPlainText("AndroDR Timeline", textToCopy)
                    )
                    Toast.makeText(
                        context,
                        context.getString(R.string.timeline_copied),
                        Toast.LENGTH_SHORT
                    ).show()
                }
            },
            onShare = {
                val textToShare = viewModel.reportText.value
                val intent = Intent(Intent.ACTION_SEND).apply {
                    type = "text/plain"
                    putExtra(Intent.EXTRA_TEXT, textToShare)
                    putExtra(Intent.EXTRA_SUBJECT, "AndroDR Forensic Timeline")
                }
                context.startActivity(Intent.createChooser(intent, "Share Timeline"))
            }
        )
    }

    // Full Report export mode dialog (telemetry/findings/both)
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

@Suppress("LongMethod") // Sheet includes header, scrollable body, dividers, and two action
// buttons — the structure cannot be meaningfully split without losing cohesion.
@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun ReportViewSheet(
    reportText: String,
    onDismiss: () -> Unit,
    onCopy: () -> Unit,
    onShare: () -> Unit
) {
    ModalBottomSheet(
        onDismissRequest = onDismiss,
        sheetState = rememberModalBottomSheetState(skipPartiallyExpanded = true)
    ) {
        Column(
            modifier = Modifier.padding(horizontal = 24.dp, vertical = 16.dp)
        ) {
            Text(
                text = stringResource(R.string.timeline_report_title),
                style = MaterialTheme.typography.titleMedium,
                fontWeight = FontWeight.Bold
            )
            Spacer(modifier = Modifier.height(12.dp))
            HorizontalDivider()
            Spacer(modifier = Modifier.height(12.dp))

            // Scrollable report body
            Column(
                modifier = Modifier
                    .weight(1f, fill = false)
                    .verticalScroll(rememberScrollState())
            ) {
                if (reportText.isEmpty()) {
                    CircularProgressIndicator(
                        modifier = Modifier.align(Alignment.CenterHorizontally)
                    )
                } else {
                    Text(
                        text = reportText,
                        style = MaterialTheme.typography.bodySmall,
                        fontFamily = FontFamily.Monospace,
                        color = MaterialTheme.colorScheme.onSurface
                    )
                }
            }

            Spacer(modifier = Modifier.height(16.dp))
            HorizontalDivider()
            Spacer(modifier = Modifier.height(12.dp))

            // Action buttons
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(12.dp)
            ) {
                OutlinedButton(
                    onClick = onCopy,
                    modifier = Modifier.weight(1f),
                    enabled = reportText.isNotEmpty()
                ) {
                    Icon(Icons.Filled.ContentCopy, null, Modifier.size(18.dp))
                    Spacer(Modifier.width(8.dp))
                    Text(stringResource(R.string.timeline_copy))
                }
                Button(
                    onClick = onShare,
                    modifier = Modifier.weight(1f),
                    enabled = reportText.isNotEmpty()
                ) {
                    Icon(Icons.Filled.Share, null, Modifier.size(18.dp))
                    Spacer(Modifier.width(8.dp))
                    Text(stringResource(R.string.timeline_share))
                }
            }
            Spacer(modifier = Modifier.height(16.dp))
        }
    }
}
