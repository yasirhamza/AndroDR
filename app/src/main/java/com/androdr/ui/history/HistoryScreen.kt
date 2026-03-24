package com.androdr.ui.history

import androidx.compose.animation.AnimatedVisibility
import androidx.compose.animation.expandVertically
import androidx.compose.animation.shrinkVertically
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.CheckCircle
import androidx.compose.material.icons.filled.History
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.SuggestionChip
import androidx.compose.material3.SuggestionChipDefaults
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.androdr.R
import com.androdr.data.model.ScanResult
import com.androdr.scanner.ScanOrchestrator
import com.androdr.ui.apps.riskLevelColor
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

@Composable
fun HistoryScreen(
    viewModel: HistoryViewModel = hiltViewModel()
) {
    val allScans by viewModel.allScans.collectAsStateWithLifecycle()
    val selectedScan by viewModel.selectedScan.collectAsStateWithLifecycle()
    val selectedDiff by viewModel.selectedDiff.collectAsStateWithLifecycle()

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
                onClick = { viewModel.selectScan(scan) }
            )
        }
    }
}

@Composable
private fun ScanHistoryItem(
    scan: ScanResult,
    isSelected: Boolean,
    diff: ScanOrchestrator.ScanDiff?,
    isFirstScan: Boolean,
    onClick: () -> Unit
) {
    val dateFormatter = remember { SimpleDateFormat("MMM d, yyyy  HH:mm", Locale.getDefault()) }
    val dateString = dateFormatter.format(Date(scan.timestamp))

    val riskLevel = scan.overallRiskLevel
    val riskColor = riskLevelColor(riskLevel)

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
                        text = "${scan.appRisks.size} app risk(s) · " +
                            "${scan.deviceFlags.count { it.isTriggered }} device flag(s)",
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
                            append("• ${scan.appRisks.size} app risk(s) detected\n")
                            append("• ${scan.knownMalwareCount} known malware app(s)\n")
                            append("• ${scan.riskySideloadCount} sideloaded app(s)\n")
                            append("• ${scan.deviceFlags.count { it.isTriggered }} device flag(s) triggered")
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
                }
            }
        }
    }
}

@Composable
private fun DiffSection(diff: ScanOrchestrator.ScanDiff) {
    Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
        // New risks
        val totalNew = diff.newRisks.size + diff.newFlags.size
        val totalResolved = diff.resolvedRisks.size + diff.resolvedFlags.size

        if (totalNew > 0) {
            Text(
                text = stringResource(R.string.diff_new_risks),
                style = MaterialTheme.typography.labelMedium,
                fontWeight = FontWeight.Bold,
                color = Color(0xFFCF6679)
            )
            diff.newRisks.forEach { app ->
                Text(
                    text = "• ${app.appName} (${app.riskLevel.name})",
                    style = MaterialTheme.typography.bodySmall,
                    color = Color(0xFFCF6679)
                )
            }
            diff.newFlags.forEach { flag ->
                Text(
                    text = "• ${flag.title}",
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
            diff.resolvedRisks.forEach { app ->
                Text(
                    text = "• ${app.appName}",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.primary
                )
            }
            diff.resolvedFlags.forEach { flag ->
                Text(
                    text = "• ${flag.title}",
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

