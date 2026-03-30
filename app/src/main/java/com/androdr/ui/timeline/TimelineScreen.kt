package com.androdr.ui.timeline

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.widget.Toast
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
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

private data class DateEntry(
    val clusters: MutableList<EventCluster> = mutableListOf(),
    val standaloneEvents: MutableList<ForensicTimelineEvent> = mutableListOf()
)

@Suppress("LongMethod") // Timeline screen combines top bar, filter chips, grouped event list,
// empty state, and export menu — inherently a longer composable.
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun TimelineScreen(
    viewModel: TimelineViewModel = hiltViewModel()
) {
    val events by viewModel.events.collectAsStateWithLifecycle()
    val partitioned by viewModel.partitionedEvents.collectAsStateWithLifecycle()
    val severityFilter by viewModel.severityFilter.collectAsStateWithLifecycle()
    val shareUri by viewModel.shareUri.collectAsStateWithLifecycle()
    val exporting by viewModel.exporting.collectAsStateWithLifecycle()

    val context = LocalContext.current

    val reportText by viewModel.reportText.collectAsStateWithLifecycle()

    var exportMenuExpanded by remember { mutableStateOf(false) }
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
            title = { Text("Timeline") },
            actions = {
                // View report
                IconButton(
                    onClick = {
                        viewModel.generateReport()
                        showReportSheet = true
                    },
                    enabled = events.isNotEmpty()
                ) {
                    Icon(Icons.Filled.Description, contentDescription = "View report")
                }
                // Copy to clipboard
                IconButton(
                    onClick = {
                        if (reportText.isNotEmpty()) {
                            val clipboard = context.getSystemService(Context.CLIPBOARD_SERVICE)
                                as ClipboardManager
                            clipboard.setPrimaryClip(
                                ClipData.newPlainText("AndroDR Timeline", reportText)
                            )
                            Toast.makeText(context, "Timeline copied to clipboard", Toast.LENGTH_SHORT).show()
                        } else {
                            viewModel.generateReport()
                            Toast.makeText(context, "Generating report...", Toast.LENGTH_SHORT).show()
                        }
                    },
                    enabled = events.isNotEmpty()
                ) {
                    Icon(Icons.Filled.ContentCopy, contentDescription = "Copy report")
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
                            Icon(Icons.Filled.Share, contentDescription = "Export")
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
                        }
                    }
                }
            }
        )

        // Severity filter chips
        val filterOptions = listOf(
            null to stringResource(R.string.timeline_filter_all),
            "CRITICAL" to "Critical",
            "HIGH" to "High",
            "MEDIUM" to "Medium"
        )
        LazyRow(
            contentPadding = PaddingValues(horizontal = 16.dp),
            horizontalArrangement = Arrangement.spacedBy(8.dp)
        ) {
            items(filterOptions) { (severity, label) ->
                FilterChip(
                    selected = severityFilter == severity,
                    onClick = { viewModel.setSeverityFilter(severity) },
                    label = { Text(label) }
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
                        onClick = { viewModel.setPackageFilter(if (packageFilter == pkg) null else pkg) },
                        label = { Text(pkg.substringAfterLast("."), maxLines = 1) }
                    )
                }
            }
        }

        Spacer(modifier = Modifier.height(8.dp))

        if (events.isEmpty()) {
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
        } else {
            val (clusters, standalone) = partitioned

            // Build date-grouped structure using mutable lists to avoid O(n^2) list concatenation.
            val dateGrouped = remember(partitioned) {
                val fmt = SimpleDateFormat("MMM dd, yyyy", Locale.US)
                fun dateKey(ts: Long) =
                    if (ts > 0) fmt.format(Date(ts)) else "Unknown Date"

                val dateMap = mutableMapOf<String, DateEntry>()
                clusters.forEach { cluster ->
                    val key = dateKey(cluster.events.first().timestamp)
                    dateMap.getOrPut(key) { DateEntry() }.clusters.add(cluster)
                }
                standalone.forEach { event ->
                    val key = dateKey(event.timestamp)
                    dateMap.getOrPut(key) { DateEntry() }.standaloneEvents.add(event)
                }
                dateMap
            }

            // Sort date keys descending (most recent first) using the original event list order
            val sortedDateKeys = dateGrouped.keys.sortedByDescending { key ->
                val allEvents = (dateGrouped[key]?.clusters?.flatMap { it.events }.orEmpty()) +
                    (dateGrouped[key]?.standaloneEvents.orEmpty())
                allEvents.maxOfOrNull { it.timestamp } ?: 0L
            }

            LazyColumn(
                modifier = Modifier.fillMaxSize(),
                contentPadding = PaddingValues(horizontal = 16.dp, vertical = 8.dp),
                verticalArrangement = Arrangement.spacedBy(8.dp)
            ) {
                sortedDateKeys.forEach { dateLabel ->
                    val entry = dateGrouped[dateLabel] ?: return@forEach
                    item(key = "header_$dateLabel") {
                        Text(
                            text = dateLabel,
                            style = MaterialTheme.typography.titleSmall,
                            color = MaterialTheme.colorScheme.primary,
                            modifier = Modifier.padding(vertical = 4.dp)
                        )
                    }
                    // Render clusters first
                    entry.clusters.forEachIndexed { idx, cluster ->
                        item(key = "cluster_${dateLabel}_$idx") {
                            CorrelationClusterCard(
                                cluster = cluster,
                                onEventTap = { selectedEvent = it }
                            )
                        }
                    }
                    // Then standalone events
                    items(
                        items = entry.standaloneEvents,
                        key = { it.id }
                    ) { event ->
                        TimelineEventCard(
                            event = event,
                            onClick = { selectedEvent = event }
                        )
                    }
                }
            }
        }
    }

    // Detail bottom sheet
    selectedEvent?.let { event ->
        TimelineEventDetailSheet(
            event = event,
            onDismiss = { selectedEvent = null }
        )
    }

    // Report viewing bottom sheet
    if (showReportSheet) {
        ReportViewSheet(
            reportText = reportText,
            onDismiss = { showReportSheet = false },
            onCopy = {
                val clipboard = context.getSystemService(Context.CLIPBOARD_SERVICE)
                    as ClipboardManager
                clipboard.setPrimaryClip(
                    ClipData.newPlainText("AndroDR Timeline", reportText)
                )
                Toast.makeText(context, "Timeline copied to clipboard", Toast.LENGTH_SHORT).show()
            },
            onShare = {
                val intent = Intent(Intent.ACTION_SEND).apply {
                    type = "text/plain"
                    putExtra(Intent.EXTRA_TEXT, reportText)
                    putExtra(Intent.EXTRA_SUBJECT, "AndroDR Forensic Timeline")
                }
                context.startActivity(Intent.createChooser(intent, "Share Timeline"))
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
                text = "Forensic Timeline Report",
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
                    Text("Copy")
                }
                Button(
                    onClick = onShare,
                    modifier = Modifier.weight(1f),
                    enabled = reportText.isNotEmpty()
                ) {
                    Icon(Icons.Filled.Share, null, Modifier.size(18.dp))
                    Spacer(Modifier.width(8.dp))
                    Text("Share")
                }
            }
            Spacer(modifier = Modifier.height(16.dp))
        }
    }
}
