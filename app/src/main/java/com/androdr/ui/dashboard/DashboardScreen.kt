package com.androdr.ui.dashboard

import androidx.compose.animation.AnimatedVisibility
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
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
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Security
import androidx.compose.material.icons.filled.Warning
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.androdr.R
import com.androdr.data.model.RiskLevel
import com.androdr.data.model.ScanResult
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

@Suppress("LongMethod") // Dashboard orchestrates scan trigger, diff banner, risk card, and
// summary cards together; co-location allows single ViewModel observation without callbacks.
@Composable
fun DashboardScreen(
    viewModel: DashboardViewModel = hiltViewModel(),
    onNavigate: (String) -> Unit
) {
    val latestScan by viewModel.latestScan.collectAsStateWithLifecycle()
    val isScanning by viewModel.isScanning.collectAsStateWithLifecycle()
    val scanDiff by viewModel.scanDiff.collectAsStateWithLifecycle()

    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp)
    ) {
        // Header
        Row(
            verticalAlignment = Alignment.CenterVertically,
            modifier = Modifier.fillMaxWidth()
        ) {
            Icon(
                imageVector = Icons.Filled.Security,
                contentDescription = stringResource(R.string.cd_shield),
                tint = MaterialTheme.colorScheme.primary,
                modifier = Modifier.size(36.dp)
            )
            Spacer(modifier = Modifier.width(12.dp))
            Text(
                text = stringResource(R.string.app_name),
                style = MaterialTheme.typography.headlineMedium,
                fontWeight = FontWeight.Bold,
                color = MaterialTheme.colorScheme.primary
            )
        }

        // Overall risk level card
        RiskLevelCard(latestScan = latestScan)

        // Diff banner
        AnimatedVisibility(
            visible = scanDiff != null &&
                (scanDiff!!.newRisks.isNotEmpty() || scanDiff!!.newFlags.isNotEmpty()),
            enter = fadeIn(),
            exit = fadeOut()
        ) {
            scanDiff?.let { diff ->
                val newCount = diff.newRisks.size + diff.newFlags.size
                DiffBanner(newCount = newCount)
            }
        }

        // Run Scan button
        Button(
            onClick = { viewModel.runScan() },
            enabled = !isScanning,
            modifier = Modifier.fillMaxWidth()
        ) {
            if (isScanning) {
                CircularProgressIndicator(
                    modifier = Modifier.size(20.dp),
                    strokeWidth = 2.dp,
                    color = MaterialTheme.colorScheme.onPrimary
                )
                Spacer(modifier = Modifier.width(8.dp))
                Text(stringResource(R.string.scanning))
            } else {
                Text(stringResource(R.string.run_scan))
            }
        }

        // Summary cards grid (2x2)
        val riskyAppCount = latestScan?.appRisks
            ?.count { it.riskLevel != RiskLevel.LOW } ?: 0
        val deviceFlagCount = latestScan?.deviceFlags
            ?.count { it.isTriggered } ?: 0
        val blockedDnsCount = 0 // DNS blocked count shown via separate screen; no direct field in ScanResult
        val lastScanTime = latestScan?.timestamp?.let { ts ->
            SimpleDateFormat("MMM d, HH:mm", Locale.getDefault()).format(Date(ts))
        } ?: stringResource(R.string.never)

        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.spacedBy(12.dp)
        ) {
            SummaryCard(
                modifier = Modifier.weight(1f),
                title = stringResource(R.string.summary_app_risks),
                value = riskyAppCount.toString(),
                onClick = { onNavigate("apps") }
            )
            SummaryCard(
                modifier = Modifier.weight(1f),
                title = stringResource(R.string.summary_device_flags),
                value = deviceFlagCount.toString(),
                onClick = { onNavigate("device") }
            )
        }

        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.spacedBy(12.dp)
        ) {
            SummaryCard(
                modifier = Modifier.weight(1f),
                title = stringResource(R.string.summary_dns_blocked),
                value = blockedDnsCount.toString(),
                onClick = { onNavigate("network") }
            )
            SummaryCard(
                modifier = Modifier.weight(1f),
                title = stringResource(R.string.summary_last_scan),
                value = lastScanTime,
                onClick = { onNavigate("history") }
            )
        }
    }
}

@Suppress("LongMethod") // Risk level card displays color-coded status, scan timestamp, and
// per-category counts (risks + flags) with conditional null-state; all required for triage.
@Composable
private fun RiskLevelCard(latestScan: ScanResult?) {
    val (riskColor, riskLabel) = when (latestScan?.overallRiskLevel) {
        RiskLevel.CRITICAL -> Pair(Color(0xFFCF6679), "CRITICAL")
        RiskLevel.HIGH -> Pair(Color(0xFFFF9800), "HIGH")
        RiskLevel.MEDIUM -> Pair(Color(0xFFFFD600), "MEDIUM")
        RiskLevel.LOW -> Pair(Color(0xFF00D4AA), "LOW")
        null -> Pair(Color(0xFF00D4AA), "—")
    }

    Card(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(
            containerColor = MaterialTheme.colorScheme.surfaceContainer
        )
    ) {
        Column(
            modifier = Modifier.padding(20.dp),
            verticalArrangement = Arrangement.spacedBy(8.dp)
        ) {
            Text(
                text = "Overall Risk",
                style = MaterialTheme.typography.labelLarge,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
            Row(
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(8.dp)
            ) {
                Surface(
                    shape = MaterialTheme.shapes.small,
                    color = riskColor.copy(alpha = 0.2f)
                ) {
                    Text(
                        text = riskLabel,
                        style = MaterialTheme.typography.headlineSmall,
                        fontWeight = FontWeight.ExtraBold,
                        color = riskColor,
                        modifier = Modifier.padding(horizontal = 12.dp, vertical = 4.dp)
                    )
                }
            }
            if (latestScan == null) {
                Text(
                    text = "No scan performed yet. Tap \"Run Scan\" to analyse your device.",
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            } else {
                val appRiskCount = latestScan.appRisks.size
                val flagCount = latestScan.deviceFlags.count { it.isTriggered }
                Text(
                    text = "$appRiskCount app risk(s) · $flagCount device flag(s) triggered",
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
        }
    }
}

@Suppress("LongMethod") // Diff banner includes icon, count, and explanatory text with spacing
// and color theming; the length is inherent to the Compose declarative layout model.
@Composable
private fun DiffBanner(newCount: Int) {
    Card(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(
            containerColor = Color(0xFFFF9800).copy(alpha = 0.15f)
        )
    ) {
        Row(
            modifier = Modifier.padding(16.dp),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(12.dp)
        ) {
            Icon(
                imageVector = Icons.Filled.Warning,
                contentDescription = null,
                tint = Color(0xFFFF9800)
            )
            Text(
                text = "$newCount new risk(s) since last scan",
                style = MaterialTheme.typography.bodyMedium,
                fontWeight = FontWeight.SemiBold,
                color = Color(0xFFFF9800)
            )
        }
    }
}

@Suppress("LongMethod") // Summary card combines clickable surface, icon row, value text, and
// chevron; the layout length reflects Compose verbosity, not logic complexity.
@Composable
private fun SummaryCard(
    title: String,
    value: String,
    onClick: () -> Unit,
    modifier: Modifier = Modifier
) {
    Card(
        modifier = modifier
            .height(96.dp)
            .clickable(onClick = onClick),
        colors = CardDefaults.cardColors(
            containerColor = MaterialTheme.colorScheme.surfaceContainerHigh
        )
    ) {
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(12.dp),
            verticalArrangement = Arrangement.SpaceBetween
        ) {
            Text(
                text = title,
                style = MaterialTheme.typography.labelMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
            Text(
                text = value,
                style = MaterialTheme.typography.titleLarge,
                fontWeight = FontWeight.Bold,
                color = MaterialTheme.colorScheme.onSurface
            )
        }
    }
}
