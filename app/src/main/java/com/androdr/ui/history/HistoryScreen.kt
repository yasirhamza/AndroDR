package com.androdr.ui.history

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.widget.Toast
import androidx.compose.animation.AnimatedVisibility
import androidx.compose.animation.expandVertically
import androidx.compose.animation.shrinkVertically
import androidx.compose.foundation.clickable
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
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.ContentCopy
import androidx.compose.material.icons.filled.Description
import androidx.compose.material.icons.filled.History
import androidx.compose.material.icons.filled.Share
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.ModalBottomSheet
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.SuggestionChip
import androidx.compose.material3.SuggestionChipDefaults
import androidx.compose.material3.Text
import androidx.compose.material3.rememberModalBottomSheetState
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.androdr.R
import com.androdr.data.model.ScanResult
import com.androdr.scanner.ScanOrchestrator
import com.androdr.ui.common.severityColor
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

@Suppress("LongMethod") // History screen combines empty-state, list, share-launch, and bottom sheet
// logic; keeping them together avoids passing share state through multiple composable parameters.
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun HistoryScreen(
    viewModel: HistoryViewModel = hiltViewModel()
) {
    val allScans   by viewModel.allScans.collectAsStateWithLifecycle()
    val selectedScan by viewModel.selectedScan.collectAsStateWithLifecycle()
    val selectedDiff by viewModel.selectedDiff.collectAsStateWithLifecycle()
    val exporting  by viewModel.exporting.collectAsStateWithLifecycle()
    val shareUri   by viewModel.shareUri.collectAsStateWithLifecycle()
    val sheetScan  by viewModel.sheetScan.collectAsStateWithLifecycle()
    val sheetReportText by viewModel.sheetReportText.collectAsStateWithLifecycle()

    val context = LocalContext.current

    // Fire the system share sheet as soon as the URI is ready
    LaunchedEffect(shareUri) {
        val uri = shareUri ?: return@LaunchedEffect
        val intent = Intent(Intent.ACTION_SEND).apply {
            type = "text/plain"
            putExtra(Intent.EXTRA_STREAM, uri)
            putExtra(Intent.EXTRA_SUBJECT, context.getString(R.string.report_share_subject))
            addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
        }
        context.startActivity(Intent.createChooser(intent, context.getString(R.string.report_share_title)))
        viewModel.onShareConsumed()
    }

    if (allScans.isEmpty()) {
        Box(
            modifier = Modifier.fillMaxSize(),
            contentAlignment = Alignment.Center
        ) {
            Column(
                horizontalAlignment = Alignment.CenterHorizontally,
                verticalArrangement = Arrangement.spacedBy(12.dp)
            ) {
                Icon(
                    imageVector = Icons.Filled.History,
                    contentDescription = null,
                    tint = MaterialTheme.colorScheme.onSurfaceVariant,
                    modifier = Modifier.size(64.dp)
                )
                Text(
                    text = stringResource(R.string.no_scan_history),
                    style = MaterialTheme.typography.titleMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
                Text(
                    text = stringResource(R.string.run_first_scan_hint),
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
        }
        return
    }

    LazyColumn(
        modifier = Modifier.fillMaxSize(),
        contentPadding = androidx.compose.foundation.layout.PaddingValues(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp)
    ) {
        items(allScans) { scan ->
            val isSelected = selectedScan?.id == scan.id
            ScanHistoryItem(
                scan = scan,
                isSelected = isSelected,
                diff = if (isSelected) selectedDiff else null,
                isFirstScan = allScans.last().id == scan.id,
                exporting = exporting,
                onClick = { viewModel.selectScan(scan) },
                onExport = { viewModel.exportReport(scan) },
                onViewReport = { viewModel.openSheet(scan) }
            )
        }
    }

    // Detail bottom sheet
    sheetScan?.let { scan ->
        ScanReportBottomSheet(
            scan = scan,
            reportText = sheetReportText,
            onDismiss = { viewModel.closeSheet() }
        )
    }
}

@Suppress("LongMethod")
@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun ScanReportBottomSheet(
    scan: ScanResult,
    reportText: String,
    onDismiss: () -> Unit
) {
    val sheetState = rememberModalBottomSheetState(skipPartiallyExpanded = true)
    val context = LocalContext.current
    val dateFormatter = remember { SimpleDateFormat("MMM d, yyyy  HH:mm", Locale.getDefault()) }
    val dateString = dateFormatter.format(Date(scan.timestamp))
    val riskColor = severityColor(scan.overallRiskLevel.name)

    ModalBottomSheet(
        onDismissRequest = onDismiss,
        sheetState = sheetState,
        containerColor = MaterialTheme.colorScheme.surfaceContainerHigh
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 24.dp)
                .padding(bottom = 16.dp)
        ) {
            // Header: date + risk level
            Row(
                modifier = Modifier.fillMaxWidth(),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.SpaceBetween
            ) {
                Column(modifier = Modifier.weight(1f)) {
                    Text(
                        text = "Scan Report",
                        style = MaterialTheme.typography.titleMedium,
                        fontWeight = FontWeight.Bold
                    )
                    Text(
                        text = dateString,
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }
                SuggestionChip(
                    onClick = {},
                    label = {
                        Text(
                            text = scan.overallRiskLevel.name,
                            style = MaterialTheme.typography.labelSmall,
                            fontWeight = FontWeight.Bold
                        )
                    },
                    colors = SuggestionChipDefaults.suggestionChipColors(
                        containerColor = riskColor.copy(alpha = 0.2f),
                        labelColor = riskColor
                    )
                )
            }

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
                    CircularProgressIndicator(modifier = Modifier.align(Alignment.CenterHorizontally))
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
                    onClick = {
                        val clipboard = context.getSystemService(Context.CLIPBOARD_SERVICE)
                            as ClipboardManager
                        clipboard.setPrimaryClip(
                            ClipData.newPlainText("AndroDR Report", reportText)
                        )
                        Toast.makeText(context, "Report copied to clipboard", Toast.LENGTH_SHORT)
                            .show()
                    },
                    modifier = Modifier.weight(1f),
                    enabled = reportText.isNotEmpty()
                ) {
                    Icon(
                        imageVector = Icons.Filled.ContentCopy,
                        contentDescription = null,
                        modifier = Modifier.size(18.dp)
                    )
                    Spacer(modifier = Modifier.width(8.dp))
                    Text("Copy")
                }
                Button(
                    onClick = {
                        val intent = Intent(Intent.ACTION_SEND).apply {
                            type = "text/plain"
                            putExtra(Intent.EXTRA_TEXT, reportText)
                            putExtra(Intent.EXTRA_SUBJECT, "AndroDR Security Report")
                        }
                        context.startActivity(
                            Intent.createChooser(intent, "Share Security Report")
                        )
                    },
                    modifier = Modifier.weight(1f),
                    enabled = reportText.isNotEmpty()
                ) {
                    Icon(
                        imageVector = Icons.Filled.Share,
                        contentDescription = null,
                        modifier = Modifier.size(18.dp)
                    )
                    Spacer(modifier = Modifier.width(8.dp))
                    Text("Share")
                }
            }

            Spacer(modifier = Modifier.height(8.dp))
        }
    }
}

@Suppress("LongMethod", "LongParameterList") // Scan history item requires all parameters to
// render selection state, diff badges, export spinner, and first-scan indicator together;
// the parameter count is inherent to the component's responsibility surface.
@Composable
private fun ScanHistoryItem(
    scan: ScanResult,
    isSelected: Boolean,
    diff: ScanOrchestrator.ScanDiff?,
    isFirstScan: Boolean,
    exporting: Boolean,
    onClick: () -> Unit,
    onExport: () -> Unit,
    onViewReport: () -> Unit
) {
    val dateFormatter = remember { SimpleDateFormat("MMM d, yyyy  HH:mm", Locale.getDefault()) }
    val dateString = dateFormatter.format(Date(scan.timestamp))

    val riskLevel = scan.overallRiskLevel
    val riskColor = severityColor(riskLevel.name)

    Card(
        modifier = Modifier
            .fillMaxWidth()
            .clickable(onClick = onClick),
        colors = CardDefaults.cardColors(
            containerColor = if (isSelected)
                MaterialTheme.colorScheme.surfaceContainerHigh
            else
                MaterialTheme.colorScheme.surfaceContainer
        )
    ) {
        Column(modifier = Modifier.padding(16.dp)) {
            // Summary row
            Row(
                modifier = Modifier.fillMaxWidth(),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.SpaceBetween
            ) {
                Column(modifier = Modifier.weight(1f)) {
                    Text(
                        text = dateString,
                        style = MaterialTheme.typography.titleSmall,
                        fontWeight = FontWeight.SemiBold
                    )
                    Text(
                        text = "${scan.appRisks.count { it.triggered }} app risk(s) \u00b7 " +
                            "${scan.deviceFlags.count { it.triggered }} device flag(s)",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }
                SuggestionChip(
                    onClick = {},
                    label = {
                        Text(
                            text = riskLevel.name,
                            style = MaterialTheme.typography.labelSmall,
                            fontWeight = FontWeight.Bold
                        )
                    },
                    colors = SuggestionChipDefaults.suggestionChipColors(
                        containerColor = riskColor.copy(alpha = 0.2f),
                        labelColor = riskColor
                    )
                )
            }

            // Expanded detail panel
            AnimatedVisibility(
                visible = isSelected,
                enter = expandVertically(),
                exit = shrinkVertically()
            ) {
                Column(
                    modifier = Modifier.padding(top = 12.dp),
                    verticalArrangement = Arrangement.spacedBy(12.dp)
                ) {
                    HorizontalDivider(color = MaterialTheme.colorScheme.outlineVariant)

                    // Full scan summary
                    Text(
                        text = stringResource(R.string.scan_summary_title),
                        style = MaterialTheme.typography.labelLarge,
                        fontWeight = FontWeight.Bold,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                    Text(
                        text = buildString {
                            append("\u2022 ${scan.appRisks.count { it.triggered }} app risk(s) detected\n")
                            append("\u2022 ${scan.knownMalwareCount} known malware app(s)\n")
                            append("\u2022 ${scan.riskySideloadCount} sideloaded app(s)\n")
                            append("\u2022 ${scan.deviceFlags.count { it.triggered }} device flag(s) triggered")
                        },
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurface
                    )

                    // Diff section
                    if (isFirstScan || diff == null) {
                        Text(
                            text = stringResource(R.string.first_scan_no_comparison),
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                    } else {
                        DiffSection(diff = diff)
                    }

                    // Action buttons row
                    HorizontalDivider(color = MaterialTheme.colorScheme.outlineVariant)
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.End
                    ) {
                        // View Report button
                        IconButton(onClick = onViewReport) {
                            Icon(
                                imageVector = Icons.Filled.Description,
                                contentDescription = "View full report",
                                tint = MaterialTheme.colorScheme.primary
                            )
                        }
                        Text(
                            text = "View Report",
                            style = MaterialTheme.typography.labelMedium,
                            color = MaterialTheme.colorScheme.primary,
                            modifier = Modifier
                                .clickable(onClick = onViewReport)
                                .padding(end = 16.dp)
                        )

                        if (exporting) {
                            CircularProgressIndicator(modifier = Modifier.size(18.dp), strokeWidth = 2.dp)
                        }
                        IconButton(onClick = onExport, enabled = !exporting) {
                            Icon(
                                imageVector = Icons.Filled.Share,
                                contentDescription = stringResource(R.string.report_export_cd),
                                tint = MaterialTheme.colorScheme.primary
                            )
                        }
                        Text(
                            text = stringResource(R.string.report_export_label),
                            style = MaterialTheme.typography.labelMedium,
                            color = if (exporting)
                                MaterialTheme.colorScheme.onSurfaceVariant
                            else
                                MaterialTheme.colorScheme.primary
                        )
                    }
                }
            }
        }
    }
}

@Suppress("LongMethod") // DiffSection renders new/resolved findings with conditional
// sub-sections; all branches are needed in one composable to maintain visual cohesion.
@Composable
private fun DiffSection(diff: ScanOrchestrator.ScanDiff) {
    Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
        val totalNew      = diff.newFindings.size
        val totalResolved = diff.resolvedFindings.size

        if (totalNew > 0) {
            Text(
                text = stringResource(R.string.diff_new_risks),
                style = MaterialTheme.typography.labelMedium,
                fontWeight = FontWeight.Bold,
                color = Color(0xFFCF6679)
            )
            diff.newFindings.forEach { finding ->
                Text(
                    text = "\u2022 ${finding.title} (${finding.level.uppercase()})",
                    style = MaterialTheme.typography.bodySmall,
                    color = Color(0xFFCF6679)
                )
            }
        }

        if (totalResolved > 0) {
            Text(
                text = stringResource(R.string.diff_resolved),
                style = MaterialTheme.typography.labelMedium,
                fontWeight = FontWeight.Bold,
                color = MaterialTheme.colorScheme.primary
            )
            diff.resolvedFindings.forEach { finding ->
                Text(
                    text = "\u2022 ${finding.title}",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.primary
                )
            }
        }

        if (totalNew == 0 && totalResolved == 0) {
            Text(
                text = stringResource(R.string.diff_no_changes),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
        }
    }
}
