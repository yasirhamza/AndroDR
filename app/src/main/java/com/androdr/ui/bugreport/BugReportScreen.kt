package com.androdr.ui.bugreport

import android.content.Intent
import android.net.Uri
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.annotation.StringRes
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
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
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.BugReport
import androidx.compose.material.icons.filled.Error
import androidx.compose.material.icons.filled.ExpandLess
import androidx.compose.material.icons.filled.ExpandMore
import androidx.compose.material.icons.filled.FolderOpen
import androidx.compose.material.icons.filled.Info
import androidx.compose.material.icons.filled.Share
import androidx.compose.material.icons.filled.Warning
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.androdr.R
import com.androdr.scanner.ArtifactType
import com.androdr.scanner.ScanOrchestrator
import com.androdr.ui.common.FindingCard
import com.androdr.ui.theme.ExtendedColors
import com.androdr.ui.theme.androdrColors
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

@Suppress("LongMethod") // Bug report screen combines file-picker launch, progress state,
// empty-state, completion confirmation, error card, findings list, timeline, and export.
// Splitting into child composables would require threading 5+ state flows through wrappers;
// keeping inline trades length for state-flow locality.
@Composable
fun BugReportScreen(
    viewModel: BugReportViewModel = hiltViewModel()
) {
    val analyzedArtifact by viewModel.analyzedArtifact.collectAsStateWithLifecycle()
    val findings by viewModel.findings.collectAsStateWithLifecycle()
    val timeline by viewModel.timeline.collectAsStateWithLifecycle()
    val intrusionSummary by viewModel.intrusionLogSummary.collectAsStateWithLifecycle()
    val isAnalyzing by viewModel.isAnalyzing.collectAsStateWithLifecycle()
    val analysisFinished by viewModel.analysisFinished.collectAsStateWithLifecycle()
    val errorMessage by viewModel.errorMessage.collectAsStateWithLifecycle()
    val exporting by viewModel.exporting.collectAsStateWithLifecycle()
    val shareUri by viewModel.shareUri.collectAsStateWithLifecycle()

    val context = LocalContext.current

    var instructionsExpanded by remember { mutableStateOf(false) }
    var intrusionInstructionsExpanded by remember { mutableStateOf(false) }

    // Launch share intent when a report URI is ready
    LaunchedEffect(shareUri) {
        shareUri?.let { uri ->
            val shareIntent = Intent(Intent.ACTION_SEND).apply {
                type = "text/plain"
                putExtra(Intent.EXTRA_STREAM, uri)
                putExtra(Intent.EXTRA_SUBJECT, "AndroDR Deep Device Scan")
                addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
            }
            context.startActivity(Intent.createChooser(shareIntent, "Share Analysis Report"))
            viewModel.onShareConsumed()
        }
    }

    // File picker launcher — filter for zip files
    val filePickerLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.OpenDocument()
    ) { uri: Uri? ->
        uri?.let { viewModel.analyzeUri(it) }
    }

    val hasResults = findings.isNotEmpty()

    Column(modifier = Modifier.fillMaxSize()) {
        LazyColumn(
            modifier = Modifier.fillMaxSize(),
            contentPadding = androidx.compose.foundation.layout.PaddingValues(16.dp),
            verticalArrangement = Arrangement.spacedBy(16.dp)
        ) {
            item {
                // How to create a bug report (expandable)
                InstructionsCard(
                    title = stringResource(R.string.bugreport_instructions_title),
                    body = viewModel.instructions,
                    expanded = instructionsExpanded,
                    onToggle = { instructionsExpanded = !instructionsExpanded }
                )
            }

            item {
                // #356: the same screen also accepts an Advanced Protection
                // intrusion log export, which is reachable from a completely
                // different Settings path — undiscoverable without this card.
                InstructionsCard(
                    title = stringResource(R.string.intrusion_log_instructions_title),
                    body = stringResource(R.string.intrusion_log_instructions_body),
                    expanded = intrusionInstructionsExpanded,
                    onToggle = { intrusionInstructionsExpanded = !intrusionInstructionsExpanded }
                )
            }

            item {
                // File picker button
                Button(
                    onClick = {
                        filePickerLauncher.launch(arrayOf("application/zip", "application/octet-stream"))
                    },
                    enabled = !isAnalyzing,
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Icon(
                        imageVector = Icons.Filled.FolderOpen,
                        contentDescription = null,
                        modifier = Modifier.size(20.dp)
                    )
                    Spacer(modifier = Modifier.width(8.dp))
                    Text(stringResource(R.string.bugreport_select_file))
                }
            }

            // Loading state
            if (isAnalyzing) {
                item {
                    Box(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(32.dp),
                        contentAlignment = Alignment.Center
                    ) {
                        Column(
                            horizontalAlignment = Alignment.CenterHorizontally,
                            verticalArrangement = Arrangement.spacedBy(16.dp)
                        ) {
                            CircularProgressIndicator(
                                color = MaterialTheme.colorScheme.primary
                            )
                            Text(
                                text = stringResource(R.string.bugreport_analyzing),
                                style = MaterialTheme.typography.bodyMedium,
                                color = MaterialTheme.colorScheme.onSurfaceVariant
                            )
                        }
                    }
                }
            }

            // Pre-analysis empty state (initial, no analysis attempted yet)
            if (!isAnalyzing && !analysisFinished) {
                item {
                    Box(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(top = 32.dp),
                        contentAlignment = Alignment.Center
                    ) {
                        Column(
                            horizontalAlignment = Alignment.CenterHorizontally,
                            verticalArrangement = Arrangement.spacedBy(12.dp)
                        ) {
                            Icon(
                                imageVector = Icons.Filled.BugReport,
                                contentDescription = null,
                                tint = MaterialTheme.colorScheme.onSurfaceVariant,
                                modifier = Modifier.size(64.dp)
                            )
                            Text(
                                text = stringResource(R.string.bugreport_empty_state),
                                style = MaterialTheme.typography.titleMedium,
                                color = MaterialTheme.colorScheme.onSurfaceVariant
                            )
                            Text(
                                text = stringResource(R.string.bugreport_empty_hint),
                                style = MaterialTheme.typography.bodyMedium,
                                color = MaterialTheme.colorScheme.onSurfaceVariant
                            )
                        }
                    }
                }
            }

            // Error card — analysis threw an unhandled exception
            if (!isAnalyzing && analysisFinished && errorMessage != null) {
                item {
                    Card(
                        modifier = Modifier.fillMaxWidth(),
                        colors = CardDefaults.cardColors(
                            containerColor = MaterialTheme.colorScheme.errorContainer
                        )
                    ) {
                        Row(
                            modifier = Modifier.padding(16.dp),
                            horizontalArrangement = Arrangement.spacedBy(12.dp),
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Icon(
                                imageVector = Icons.Filled.Error,
                                contentDescription = null,
                                tint = MaterialTheme.colorScheme.onErrorContainer
                            )
                            Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
                                Text(
                                    text = stringResource(R.string.bugreport_error_title),
                                    style = MaterialTheme.typography.titleSmall,
                                    fontWeight = FontWeight.SemiBold,
                                    color = MaterialTheme.colorScheme.onErrorContainer
                                )
                                Text(
                                    text = stringResource(
                                        R.string.bugreport_error_hint,
                                        errorMessage ?: ""
                                    ),
                                    style = MaterialTheme.typography.bodySmall,
                                    color = MaterialTheme.colorScheme.onErrorContainer,
                                    maxLines = 6,
                                    overflow = androidx.compose.ui.text.style.TextOverflow.Ellipsis
                                )
                            }
                        }
                    }
                }
            }

            // Intrusion log summary card — shown whenever the imported artifact was an
            // Advanced Protection Intrusion Logging export (#342), independent of whether
            // any SIGMA rule triggered, so the user always sees what was actually analyzed.
            if (!isAnalyzing) {
                intrusionSummary?.let { s ->
                    item {
                        Card(
                            modifier = Modifier.fillMaxWidth(),
                            colors = CardDefaults.cardColors(
                                containerColor = MaterialTheme.colorScheme.surfaceContainerHighest
                            )
                        ) {
                            Column(
                                modifier = Modifier.padding(16.dp),
                                verticalArrangement = Arrangement.spacedBy(4.dp)
                            ) {
                                // Constructed once, not per recomposition (matches the
                                // ScanGroupHeader/HistoryScreen date-formatter pattern).
                                val summaryDateFmt = remember {
                                    SimpleDateFormat("yyyy-MM-dd HH:mm", Locale.US)
                                }
                                Text(
                                    text = stringResource(R.string.intrusion_log_summary_title),
                                    style = MaterialTheme.typography.titleSmall,
                                    fontWeight = FontWeight.SemiBold,
                                    color = MaterialTheme.colorScheme.onSurface
                                )
                                Text(
                                    text = stringResource(
                                        R.string.intrusion_log_summary_counts,
                                        s.dnsEventCount,
                                        s.connectEventCount,
                                        s.securityEventCount
                                    ),
                                    style = MaterialTheme.typography.bodySmall,
                                    color = MaterialTheme.colorScheme.onSurfaceVariant
                                )
                                Text(
                                    text = stringResource(
                                        R.string.intrusion_log_summary_collapsed,
                                        s.duplicatesCollapsed,
                                        s.malformedLines
                                    ),
                                    style = MaterialTheme.typography.bodySmall,
                                    color = MaterialTheme.colorScheme.onSurfaceVariant
                                )
                                val dnsCap = ScanOrchestrator.DNS_PERSIST_CAP
                                val netCap = ScanOrchestrator.CONNECT_PERSIST_CAP
                                if (s.dnsEventCount > dnsCap || s.connectEventCount > netCap) {
                                    Text(
                                        text = stringResource(
                                            R.string.intrusion_log_summary_capped,
                                            minOf(s.dnsEventCount, dnsCap),
                                            s.dnsEventCount,
                                            minOf(s.connectEventCount, netCap),
                                            s.connectEventCount
                                        ),
                                        style = MaterialTheme.typography.bodySmall,
                                        color = MaterialTheme.colorScheme.onSurfaceVariant
                                    )
                                }
                                val secCap = ScanOrchestrator.SECURITY_PERSIST_CAP
                                if (s.securityEventCount > secCap) {
                                    Text(
                                        text = stringResource(
                                            R.string.intrusion_log_summary_capped_security,
                                            secCap,
                                            s.securityEventCount
                                        ),
                                        style = MaterialTheme.typography.bodySmall,
                                        color = MaterialTheme.colorScheme.onSurfaceVariant
                                    )
                                }
                                val findingsCap = ScanOrchestrator.FINDINGS_PERSIST_CAP
                                if (s.triggeredFindingCount > findingsCap) {
                                    Text(
                                        text = stringResource(
                                            R.string.intrusion_log_summary_capped_findings,
                                            findingsCap,
                                            s.triggeredFindingCount
                                        ),
                                        style = MaterialTheme.typography.bodySmall,
                                        color = MaterialTheme.colorScheme.onSurfaceVariant
                                    )
                                }
                                if (s.earliestEventMs != null && s.latestEventMs != null) {
                                    Text(
                                        text = stringResource(
                                            R.string.intrusion_log_summary_range,
                                            summaryDateFmt.format(Date(s.earliestEventMs)),
                                            summaryDateFmt.format(Date(s.latestEventMs))
                                        ),
                                        style = MaterialTheme.typography.bodySmall,
                                        color = MaterialTheme.colorScheme.onSurfaceVariant
                                    )
                                }
                            }
                        }
                    }
                }
            }

            // Completion confirmation card — analysis succeeded but yielded no triggered findings.
            // Without this card the screen would revert to the idle empty-state and the user
            // could not distinguish success-with-no-signals from "spinner crashed silently".
            if (!isAnalyzing && analysisFinished && errorMessage == null && !hasResults) {
                item {
                    Card(
                        modifier = Modifier.fillMaxWidth(),
                        colors = CardDefaults.cardColors(
                            containerColor = MaterialTheme.colorScheme.surfaceContainerHighest
                        )
                    ) {
                        Row(
                            modifier = Modifier.padding(16.dp),
                            horizontalArrangement = Arrangement.spacedBy(12.dp),
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Icon(
                                imageVector = Icons.Filled.Info,
                                contentDescription = null,
                                tint = MaterialTheme.colorScheme.primary
                            )
                            Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
                                Text(
                                    text = stringResource(R.string.bugreport_complete_clean_title),
                                    style = MaterialTheme.typography.titleSmall,
                                    fontWeight = FontWeight.SemiBold,
                                    color = MaterialTheme.colorScheme.onSurface
                                )
                                Text(
                                    // #356: name the artifact that was ACTUALLY
                                    // analyzed — telling an intrusion-log importer
                                    // "your system diagnostic was analyzed"
                                    // misidentifies their evidence.
                                    text = when {
                                        timeline.isNotEmpty() -> stringResource(
                                            R.string.bugreport_complete_timeline_only,
                                            timeline.size
                                        )
                                        analyzedArtifact == ArtifactType.INTRUSION_LOG ->
                                            stringResource(R.string.intrusion_log_complete_clean_hint)
                                        else -> stringResource(R.string.bugreport_complete_clean_hint)
                                    },
                                    style = MaterialTheme.typography.bodySmall,
                                    color = MaterialTheme.colorScheme.onSurfaceVariant
                                )
                            }
                        }
                    }
                }

                // Timeline-only result: still show the timeline + an export button so
                // the user can capture forensic events that didn't trip a SIGMA rule.
                if (timeline.isNotEmpty()) {
                    item {
                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            horizontalArrangement = Arrangement.End,
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            OutlinedButton(
                                onClick = { viewModel.exportReport() },
                                enabled = !exporting
                            ) {
                                Icon(
                                    imageVector = Icons.Filled.Share,
                                    contentDescription = stringResource(R.string.report_export_cd),
                                    modifier = Modifier.size(18.dp)
                                )
                                Spacer(modifier = Modifier.width(6.dp))
                                Text(stringResource(R.string.report_export_label))
                            }
                        }
                    }
                    item {
                        Text(
                            text = stringResource(R.string.bugreport_timeline_count, timeline.size),
                            style = MaterialTheme.typography.titleSmall,
                            fontWeight = FontWeight.SemiBold,
                            color = MaterialTheme.colorScheme.primary
                        )
                    }
                    items(timeline.sortedBy { it.timestamp }) { event ->
                        TimelineEventCard(event = event)
                    }
                }
            }

            // Analysis results — at least one triggered SIGMA finding
            if (!isAnalyzing && hasResults) {
                // Results header names the detected artifact type (#356).
                analyzedArtifactLabel(analyzedArtifact)?.let { labelRes ->
                    item {
                        Text(
                            text = stringResource(labelRes),
                            style = MaterialTheme.typography.labelMedium,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                    }
                }
                // Export button
                item {
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        val totalCount = findings.count {
                            it.triggered && it.level.lowercase() != "informational"
                        }
                        Text(
                            text = stringResource(R.string.bugreport_finding_count, totalCount),
                            style = MaterialTheme.typography.labelLarge,
                            fontWeight = FontWeight.Bold,
                            color = MaterialTheme.colorScheme.onSurface
                        )
                        OutlinedButton(
                            onClick = { viewModel.exportReport() },
                            enabled = !exporting
                        ) {
                            Icon(
                                imageVector = Icons.Filled.Share,
                                contentDescription = stringResource(R.string.report_export_cd),
                                modifier = Modifier.size(18.dp)
                            )
                            Spacer(modifier = Modifier.width(6.dp))
                            Text(stringResource(R.string.report_export_label))
                        }
                    }
                }

                // SIGMA findings (evaluated by rule engine)
                // Exclude informational-level findings from display — they appear in timeline/export only
                val triggeredFindings = findings.filter {
                    it.triggered && it.level.lowercase() != "informational"
                }
                if (triggeredFindings.isNotEmpty()) {
                    item {
                        Text(
                            text = stringResource(R.string.bugreport_rule_findings),
                            style = MaterialTheme.typography.titleSmall,
                            fontWeight = FontWeight.SemiBold,
                            color = MaterialTheme.colorScheme.primary
                        )
                    }
                    items(triggeredFindings) { finding ->
                        FindingCard(finding = finding)
                    }
                }

                // Timeline events
                if (timeline.isNotEmpty()) {
                    item {
                        Text(
                            text = stringResource(R.string.bugreport_timeline_count, timeline.size),
                            style = MaterialTheme.typography.titleSmall,
                            fontWeight = FontWeight.SemiBold,
                            color = MaterialTheme.colorScheme.primary
                        )
                    }
                    items(timeline.sortedBy { it.timestamp }) { event ->
                        TimelineEventCard(event = event)
                    }
                }
            }
        }
    }
}

/**
 * One collapsible "how to obtain this artifact" card. Extracted (#356) so the
 * bug-report and intrusion-log instructions are the same component rather than
 * two copies of the header/divider/expand plumbing.
 */
@Composable
private fun InstructionsCard(
    title: String,
    body: String,
    expanded: Boolean,
    onToggle: () -> Unit
) {
    Card(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(
            containerColor = MaterialTheme.colorScheme.surfaceContainer
        )
    ) {
        Column(modifier = Modifier.padding(16.dp)) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.SpaceBetween
            ) {
                Row(
                    modifier = Modifier.weight(1f),
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    Icon(
                        imageVector = Icons.Filled.Info,
                        contentDescription = null,
                        tint = MaterialTheme.colorScheme.primary
                    )
                    Text(
                        text = title,
                        style = MaterialTheme.typography.titleSmall,
                        fontWeight = FontWeight.SemiBold
                    )
                }
                IconButton(onClick = onToggle) {
                    Icon(
                        imageVector = if (expanded) Icons.Filled.ExpandLess else Icons.Filled.ExpandMore,
                        contentDescription = if (expanded) {
                            stringResource(R.string.cd_collapse)
                        } else {
                            stringResource(R.string.cd_expand)
                        }
                    )
                }
            }

            if (expanded) {
                Spacer(modifier = Modifier.height(12.dp))
                HorizontalDivider(color = MaterialTheme.colorScheme.outlineVariant)
                Spacer(modifier = Modifier.height(12.dp))
                Text(
                    text = body,
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
        }
    }
}

@Composable
private fun TimelineEventCard(event: com.androdr.data.model.TimelineEvent) {
    val (icon, color) = findingIconAndColor(event.severity, MaterialTheme.androdrColors)

    Card(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(
            containerColor = MaterialTheme.colorScheme.surfaceContainerHigh
        )
    ) {
        Row(
            modifier = Modifier.padding(12.dp),
            horizontalArrangement = Arrangement.spacedBy(10.dp)
        ) {
            Icon(
                imageVector = icon,
                contentDescription = event.severity,
                tint = color,
                modifier = Modifier.size(20.dp)
            )
            Column(
                modifier = Modifier.weight(1f),
                verticalArrangement = Arrangement.spacedBy(2.dp)
            ) {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Text(
                        text = event.source,
                        style = MaterialTheme.typography.labelSmall,
                        fontWeight = FontWeight.Bold,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                    Text(
                        text = event.category,
                        style = MaterialTheme.typography.labelSmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }
                Text(
                    text = event.description,
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurface
                )
            }
        }
    }
}

/**
 * The results-header string for the artifact the sniffer routed to (#356), or
 * null when no analysis has completed. UNRECOGNIZED never reaches the results
 * list — [BugReportViewModel] only records the two analyzed types.
 */
@StringRes
private fun analyzedArtifactLabel(type: ArtifactType?): Int? = when (type) {
    ArtifactType.BUG_REPORT -> R.string.bugreport_analyzed_bug_report
    ArtifactType.INTRUSION_LOG -> R.string.bugreport_analyzed_intrusion_log
    ArtifactType.UNRECOGNIZED, null -> null
}

private fun findingIconAndColor(
    severity: String,
    colors: ExtendedColors
): Pair<ImageVector, Color> = when (severity.uppercase()) {
    "CRITICAL" -> Pair(Icons.Filled.Error, colors.critical)
    "HIGH"     -> Pair(Icons.Filled.Warning, colors.high)
    "MEDIUM"   -> Pair(Icons.Filled.Warning, colors.medium)
    "ERROR"    -> Pair(Icons.Filled.Error, colors.critical)
    else       -> Pair(Icons.Filled.Info, colors.neutral)
}
