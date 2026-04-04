package com.androdr.ui.dashboard

import androidx.compose.animation.AnimatedVisibility
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
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
import androidx.compose.material.icons.filled.BugReport
import androidx.compose.material.icons.filled.Security
import androidx.compose.material.icons.filled.Settings
import androidx.compose.material.icons.filled.CheckCircle
import androidx.compose.material.icons.filled.Error
import androidx.compose.material.icons.filled.Info
import androidx.compose.material.icons.filled.Warning
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
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
import com.androdr.data.model.RiskLevel
import com.androdr.data.model.ScanResult
import com.androdr.ui.common.severityColor
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

@Suppress("LongMethod") // Compose UI functions are inherently long; structure is clear via sections
@Composable
fun DashboardScreen(
    viewModel: DashboardViewModel = hiltViewModel(),
    onNavigate: (String) -> Unit
) {
    val latestScan by viewModel.latestScan.collectAsStateWithLifecycle()
    val isScanning by viewModel.isScanning.collectAsStateWithLifecycle()
    val scanDiff by viewModel.scanDiff.collectAsStateWithLifecycle()
    val matchedDnsCount by viewModel.matchedDnsCount.collectAsStateWithLifecycle()

    val snackbarHostState = remember { SnackbarHostState() }

    LaunchedEffect(Unit) {
        viewModel.iocErrorEvent.collect { message ->
            snackbarHostState.showSnackbar(message)
        }
    }

    Scaffold(
        snackbarHost = { SnackbarHost(snackbarHostState) }
    ) { innerPadding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .verticalScroll(rememberScrollState())
                .padding(innerPadding)
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
                    color = MaterialTheme.colorScheme.primary,
                    modifier = Modifier.weight(1f)
                )
                IconButton(onClick = { onNavigate("settings") }) {
                    Icon(
                        imageVector = Icons.Filled.Settings,
                        contentDescription = stringResource(R.string.cd_settings),
                        tint = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }
            }

            RiskLevelCard(latestScan = latestScan)

            PostScanGuidance(riskLevel = latestScan?.overallRiskLevel, latestScan = latestScan)

            AnimatedVisibility(
                visible = scanDiff != null && scanDiff!!.newFindings.isNotEmpty(),
                enter = fadeIn(),
                exit = fadeOut()
            ) {
                scanDiff?.let { diff ->
                    val newCount = diff.newFindings.size
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
                ?.count { it.triggered && it.level.lowercase() != "informational" } ?: 0
            val deviceFlagCount = latestScan?.deviceFlags
                ?.count { it.triggered } ?: 0
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
                    title = stringResource(R.string.summary_dns_matched),
                    value = matchedDnsCount.toString(),
                    onClick = { onNavigate("network") }
                )
                SummaryCard(
                    modifier = Modifier.weight(1f),
                    title = stringResource(R.string.summary_last_scan),
                    value = lastScanTime,
                    subtitle = if (latestScan != null) "Tap to manage" else null,
                    onClick = { onNavigate("history") }
                )
            }

            // Bug Report Analysis entry point
            Card(
                modifier = Modifier
                    .fillMaxWidth()
                    .clickable { onNavigate("bugreport") },
                colors = CardDefaults.cardColors(
                    containerColor = MaterialTheme.colorScheme.surfaceContainerHigh
                )
            ) {
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(16.dp),
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.spacedBy(12.dp)
                ) {
                    Icon(
                        imageVector = Icons.Filled.BugReport,
                        contentDescription = null,
                        tint = MaterialTheme.colorScheme.primary,
                        modifier = Modifier.size(28.dp)
                    )
                    Column(modifier = Modifier.weight(1f)) {
                        Text(
                            text = stringResource(R.string.dashboard_bugreport_title),
                            style = MaterialTheme.typography.titleSmall,
                            fontWeight = FontWeight.SemiBold
                        )
                        Text(
                            text = stringResource(R.string.dashboard_bugreport_hint),
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                    }
                }
            }
        }
    }
}

@Composable
private fun PostScanGuidance(riskLevel: RiskLevel?, latestScan: ScanResult?) {
    val hasCriticalAppRisks = latestScan?.appRisks?.any {
        it.triggered && it.level.lowercase() == "critical"
    } ?: false

    val (message, icon, color) = when (riskLevel) {
        RiskLevel.CRITICAL -> Triple(
            if (hasCriticalAppRisks) {
                stringResource(R.string.guidance_critical)
            } else {
                stringResource(R.string.guidance_critical_device)
            },
            Icons.Filled.Error,
            Color(0xFFCF6679)
        )
        RiskLevel.HIGH -> Triple(
            stringResource(R.string.guidance_high),
            Icons.Filled.Warning,
            Color(0xFFFF9800)
        )
        RiskLevel.MEDIUM -> Triple(
            stringResource(R.string.guidance_medium),
            Icons.Filled.Info,
            Color(0xFFE6A800)
        )
        RiskLevel.LOW, null -> Triple(
            stringResource(R.string.guidance_low),
            Icons.Filled.CheckCircle,
            Color(0xFF00D4AA)
        )
    }

    if (riskLevel != null) {
        Card(
            modifier = Modifier.fillMaxWidth(),
            colors = CardDefaults.cardColors(
                containerColor = color.copy(alpha = 0.08f)
            )
        ) {
            Row(
                modifier = Modifier.padding(16.dp),
                horizontalArrangement = Arrangement.spacedBy(12.dp),
                verticalAlignment = Alignment.CenterVertically
            ) {
                Icon(icon, contentDescription = null, tint = color, modifier = Modifier.size(24.dp))
                Text(
                    text = message,
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurface
                )
            }
        }
    }
}

@Suppress("LongMethod") // Compose UI layout with conditional risk display
@Composable
private fun RiskLevelCard(latestScan: ScanResult?) {
    val (riskColor, riskLabel) = when (latestScan?.overallRiskLevel) {
        RiskLevel.CRITICAL -> Pair(Color(0xFFCF6679), "CRITICAL")
        RiskLevel.HIGH     -> Pair(Color(0xFFFF9800), "HIGH")
        RiskLevel.MEDIUM   -> Pair(Color(0xFFE6A800), "MEDIUM")
        RiskLevel.LOW      -> Pair(Color(0xFF00D4AA), "LOW")
        null               -> Pair(Color(0xFF00D4AA), "\u2014")
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
                text = stringResource(R.string.dashboard_overall_risk),
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
                    text = stringResource(R.string.dashboard_no_scan_yet),
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            } else {
                Text(
                    text = stringResource(
                        R.string.dashboard_risk_summary,
                        latestScan.appRisks.count { it.triggered && it.level.lowercase() != "informational" },
                        latestScan.deviceFlags.count { it.triggered }
                    ),
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
        }
    }
}

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
                text = stringResource(R.string.dashboard_new_risks, newCount),
                style = MaterialTheme.typography.bodyMedium,
                fontWeight = FontWeight.SemiBold,
                color = Color(0xFFFF9800)
            )
        }
    }
}

@Composable
private fun SummaryCard(
    title: String,
    value: String,
    onClick: () -> Unit,
    modifier: Modifier = Modifier,
    subtitle: String? = null
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
            if (subtitle != null) {
                Text(
                    text = subtitle,
                    style = MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
        }
    }
}
