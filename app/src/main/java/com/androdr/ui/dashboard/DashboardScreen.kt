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
import androidx.compose.material3.FilledTonalButton
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import kotlinx.coroutines.launch
import androidx.compose.ui.Alignment
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.LifecycleEventObserver
import androidx.lifecycle.compose.LocalLifecycleOwner
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.androdr.R
import com.androdr.data.model.RiskLevel
import com.androdr.data.model.ScanWithFindings
import com.androdr.data.repo.CurrentFindingsSummary
import androidx.compose.ui.res.pluralStringResource
import com.androdr.scanner.ScanProgress
import com.androdr.ui.theme.androdrColors
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

@Suppress("LongMethod") // Compose UI functions are inherently long; structure is clear via sections
@Composable
fun DashboardScreen(
    viewModel: DashboardViewModel = hiltViewModel(),
    alertsViewModel: DashboardAlertsViewModel = hiltViewModel(),
    onNavigate: (String) -> Unit
) {
    val currentFindings by viewModel.currentFindings.collectAsStateWithLifecycle()
    val latestScan by viewModel.latestScan.collectAsStateWithLifecycle()
    val isScanning by viewModel.isScanning.collectAsStateWithLifecycle()
    val isUpdatingIntel by viewModel.isUpdatingIntel.collectAsStateWithLifecycle()
    val scanProgress by viewModel.scanProgress.collectAsStateWithLifecycle()
    val scanDiff by viewModel.scanDiff.collectAsStateWithLifecycle()
    val matchedDnsCount by viewModel.matchedDnsCount.collectAsStateWithLifecycle()
    val hasUsageStatsPermission by viewModel.hasUsageStatsPermission.collectAsStateWithLifecycle()

    val snackbarHostState = remember { SnackbarHostState() }
    val scope = rememberCoroutineScope()

    LaunchedEffect(Unit) {
        viewModel.iocErrorEvent.collect { message ->
            snackbarHostState.showSnackbar(message)
        }
    }

    // Re-check Usage Access permission on every lifecycle resume — this is
    // how the banner disappears the moment the user returns from the system
    // Settings screen after granting the permission. Without this hook the
    // banner would stay stale until the next recomposition trigger.
    val lifecycleOwner = LocalLifecycleOwner.current
    DisposableEffect(lifecycleOwner) {
        val observer = LifecycleEventObserver { _, event ->
            if (event == Lifecycle.Event.ON_RESUME) {
                viewModel.refreshUsageStatsPermission()
            }
        }
        lifecycleOwner.lifecycle.addObserver(observer)
        onDispose { lifecycleOwner.lifecycle.removeObserver(observer) }
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

            RiskLevelCard(latestScan = latestScan, current = currentFindings)

            // Warn the user when the previous scan failed to run every check.
            // Without this banner the app would display "Your phone looks secure"
            // (the LOW guidance) even if half the scanners crashed — a real
            // detection-evasion hazard for a security tool.
            AnimatedVisibility(
                visible = !isScanning && latestScan?.isPartialScan == true,
                enter = fadeIn(),
                exit = fadeOut()
            ) {
                latestScan?.let { PartialScanBanner(scan = it) }
            }

            StorageBanners(viewModel, latestScan, isScanning)

            // Distinct from the scanner-failure banner: no scanner failed, but the correlation time
            // budget cut some chain rules off (an app flooding events can cause it), spec §5.2.
            DashboardViewModel.correlationIncomplete(latestScan, isScanning).takeIf { it.isNotEmpty() }?.let {
                WarningBanner(
                    R.string.correlation_incomplete_banner_title, R.string.correlation_incomplete_banner_body,
                    text = it.joinToString("\n"),
                )
            }

            // Usage Access permission banner — shown when PACKAGE_USAGE_STATS
            // hasn't been granted, which silently disables the forensic
            // timeline feature. Previously the app just returned empty
            // timeline data with no user-visible feedback; this banner is
            // the only way to let the user know they need to opt in once
            // in system Settings (PACKAGE_USAGE_STATS cannot be requested
            // via the normal runtime permission dialog).
            AnimatedVisibility(
                visible = !hasUsageStatsPermission,
                enter = fadeIn(),
                exit = fadeOut()
            ) {
                UsageAccessBanner(onOpenSettings = { viewModel.openUsageStatsSettings() })
            }

            PostScanGuidance(latestScan = latestScan, current = currentFindings)

            AnimatedVisibility(
                visible = (scanDiff?.newCount ?: 0) > 0,
                enter = fadeIn(),
                exit = fadeOut()
            ) {
                scanDiff?.let { diff ->
                    val newCount = diff.newCount
                    DiffBanner(newCount = newCount)
                }
            }

            // Open alerts (spec §5.4): they stay open until a person closes them, with the device
            // credential; grouped by rule and matched value, re-surfaced by latest activity.
            OpenAlertsCard(
                viewModel = alertsViewModel,
                current = currentFindings,
                onMessage = { message -> scope.launch { snackbarHostState.showSnackbar(message) } },
            )

            // Run Scan button — when idle. When a scan is running we show a
            // full progress card instead (stage label + linear progress bar +
            // completed-count text) so the user can see that work is actually
            // making forward progress. The old UX was a single spinning button
            // which gave no indication of stages or progress.
            if (isScanning) {
                ScanProgressCard(progress = scanProgress, isUpdatingIntel = isUpdatingIntel)
            } else {
                Button(
                    onClick = { viewModel.runScan() },
                    enabled = true,
                    modifier = Modifier.fillMaxWidth()
                ) {
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
private fun PostScanGuidance(latestScan: ScanWithFindings?, current: CurrentFindingsSummary) {
    val colors = MaterialTheme.androdrColors
    val guidance = DashboardViewModel.guidanceFor(
        scanRisk = latestScan?.overallRiskLevel,
        hasCriticalAppRisks = latestScan?.appRisks?.any { it.triggered && it.level.lowercase() == "critical" } ?: false,
        // A chain of events is the strongest evidence a scan produces; say so (#350).
        hasChains = latestScan?.activityChains?.any { it.triggered } ?: false,
        openAlertCount = current.openAlertCount,
        highestOpenAlert = current.highestOpenAlertLevel,
    ) ?: return
    val alertColor = when (current.highestOpenAlertLevel) {
        RiskLevel.CRITICAL -> colors.critical
        RiskLevel.HIGH -> colors.high
        else -> colors.medium
    }
    val (message, icon, color) = when (guidance) {
        Guidance.CRITICAL -> Triple(stringResource(R.string.guidance_critical), Icons.Filled.Error, colors.critical)
        Guidance.CRITICAL_DEVICE ->
            Triple(stringResource(R.string.guidance_critical_device), Icons.Filled.Error, colors.critical)
        Guidance.CHAINS -> Triple(stringResource(R.string.guidance_chains), Icons.Filled.Warning, colors.high)
        Guidance.HIGH -> Triple(stringResource(R.string.guidance_high), Icons.Filled.Warning, colors.high)
        Guidance.MEDIUM -> Triple(stringResource(R.string.guidance_medium), Icons.Filled.Info, colors.medium)
        Guidance.LOW -> Triple(stringResource(R.string.guidance_low), Icons.Filled.CheckCircle, colors.low)
        // Never "secure" while alerts are open: name how many and the most severe (review I2).
        Guidance.OPEN_ALERTS -> Triple(
            pluralStringResource(
                R.plurals.guidance_open_alerts, current.openAlertCount, current.openAlertCount,
                current.highestOpenAlertLevel?.name ?: RiskLevel.LOW.name,
            ),
            Icons.Filled.Warning, alertColor,
        )
    }
    Card(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(containerColor = color.copy(alpha = 0.08f))
    ) {
        Row(
            modifier = Modifier.padding(16.dp),
            horizontalArrangement = Arrangement.spacedBy(12.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Icon(icon, contentDescription = null, tint = color, modifier = Modifier.size(24.dp))
            Text(
                text = message, style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurface,
            )
        }
    }
}

@Suppress("LongMethod") // Compose UI layout with conditional risk display
@Composable
private fun RiskLevelCard(latestScan: ScanWithFindings?, current: CurrentFindingsSummary) {
    val colors = MaterialTheme.androdrColors
    val openAlertCount = current.openAlertCount
    // At least the most severe open alert (review I2): alerts are current until a person closes them.
    val (riskColor, riskLabel) = when (
        DashboardViewModel.displayRisk(latestScan?.overallRiskLevel, current.highestOpenAlertLevel)
    ) {
        RiskLevel.CRITICAL -> Pair(colors.critical, "CRITICAL")
        RiskLevel.HIGH     -> Pair(colors.high, "HIGH")
        RiskLevel.MEDIUM   -> Pair(colors.medium, "MEDIUM")
        RiskLevel.LOW      -> Pair(colors.low, "LOW")
        null               -> Pair(colors.neutral, "\u2014")
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
                // Import-only: open alerts exist but no live scan, so never "no scan yet" alone.
                Text(
                    text = stringResource(
                        if (openAlertCount > 0) {
                            R.string.dashboard_no_live_scan_alerts
                        } else {
                            R.string.dashboard_no_scan_yet
                        }
                    ),
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            } else {
                Text(
                    text = stringResource(
                        R.string.dashboard_risk_summary,
                        latestScan.appRisks.count { it.triggered && it.level.lowercase() != "informational" },
                        latestScan.deviceFlags.count { it.triggered },
                        latestScan.activityChains.count { it.triggered }
                    ),
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
            current.highestOpenAlertLevel?.takeIf { openAlertCount > 0 }?.let { highest ->
                Text(
                    text = pluralStringResource(R.plurals.dashboard_open_alerts_line, openAlertCount, openAlertCount,
                        highest.name),
                    style = MaterialTheme.typography.bodyMedium,
                    fontWeight = FontWeight.SemiBold,
                )
            }
        }
    }
}

@Composable
private fun DiffBanner(newCount: Int) {
    val colors = MaterialTheme.androdrColors
    Card(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(
            containerColor = colors.high.copy(alpha = 0.15f)
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
                tint = colors.high
            )
            Text(
                text = stringResource(R.string.dashboard_new_risks, newCount),
                style = MaterialTheme.typography.bodyMedium,
                fontWeight = FontWeight.SemiBold,
                color = colors.high
            )
        }
    }
}

/**
 * Informational banner shown on the Dashboard when the app does not have
 * the `PACKAGE_USAGE_STATS` permission. Explains what the permission is
 * used for (forensic timeline) and provides a one-tap button to open the
 * system Usage Access settings screen where the user can grant it.
 */
@Composable
private fun UsageAccessBanner(onOpenSettings: () -> Unit) {
    Card(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(
            containerColor = MaterialTheme.colorScheme.surfaceContainerHigh
        )
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(10.dp)
        ) {
            Row(
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(12.dp)
            ) {
                Icon(
                    imageVector = Icons.Filled.Info,
                    contentDescription = null,
                    tint = MaterialTheme.colorScheme.primary,
                    modifier = Modifier.size(22.dp)
                )
                Text(
                    text = stringResource(R.string.usage_access_banner_title),
                    style = MaterialTheme.typography.titleSmall,
                    fontWeight = FontWeight.SemiBold
                )
            }
            Text(
                text = stringResource(R.string.usage_access_banner_body),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
            FilledTonalButton(
                onClick = onOpenSettings,
                modifier = Modifier.fillMaxWidth()
            ) {
                Text(stringResource(R.string.usage_access_banner_cta))
            }
        }
    }
}

/**
 * Progress card shown while a scan is running. Displays a descriptive
 * stage label, a determinate linear progress bar, and a human-readable
 * counter. Replaces the previous UX of a bare spinning button.
 */
@Suppress("LongMethod") // Compose UI function with sectioned rendering
@Composable
private fun ScanProgressCard(progress: ScanProgress, isUpdatingIntel: Boolean = false) {
    val running = progress as? ScanProgress.Running
    val stageText = when {
        isUpdatingIntel -> stringResource(R.string.updating_intel)
        running?.phase == ScanProgress.Running.Phase.COLLECTING_TELEMETRY ->
            stringResource(R.string.scan_phase_collecting)
        running?.phase == ScanProgress.Running.Phase.EVALUATING_RULES ->
            stringResource(R.string.scan_phase_evaluating)
        running?.phase == ScanProgress.Running.Phase.SAVING_RESULTS ->
            stringResource(R.string.scan_phase_saving)
        else -> stringResource(R.string.scanning)
    }

    Card(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(
            containerColor = MaterialTheme.colorScheme.surfaceContainerHigh
        )
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(10.dp)
        ) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                CircularProgressIndicator(
                    modifier = Modifier.size(18.dp),
                    strokeWidth = 2.dp,
                    color = MaterialTheme.colorScheme.primary
                )
                Spacer(modifier = Modifier.width(12.dp))
                Text(
                    text = stageText,
                    style = MaterialTheme.typography.titleSmall,
                    fontWeight = FontWeight.SemiBold
                )
            }
            if (running != null && running.totalScanners > 0) {
                LinearProgressIndicator(
                    progress = {
                        (running.completedScanners.toFloat() /
                            running.totalScanners.toFloat()).coerceIn(0f, 1f)
                    },
                    modifier = Modifier.fillMaxWidth()
                )
                Text(
                    text = stringResource(
                        R.string.scan_progress_counter,
                        running.completedScanners,
                        running.totalScanners
                    ),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            } else {
                // Initial Idle → Running transition: indeterminate fallback.
                LinearProgressIndicator(
                    modifier = Modifier.fillMaxWidth()
                )
            }
        }
    }
}

/**
 * Warning banner shown when the most recent scan completed with at least
 * one scanner failure ([ScanWithFindings.isPartialScan] == true). Without this
 * banner the Dashboard would claim "Your phone looks secure" even if half
 * the scanners crashed.
 */
@Composable
private fun PartialScanBanner(scan: ScanWithFindings) {
    val colors = MaterialTheme.androdrColors
    Card(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(
            containerColor = colors.high.copy(alpha = 0.15f)
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
                tint = colors.high
            )
            Column(modifier = Modifier.weight(1f)) {
                Text(
                    text = stringResource(R.string.partial_scan_banner_title),
                    style = MaterialTheme.typography.titleSmall,
                    fontWeight = FontWeight.SemiBold,
                    color = colors.high
                )
                Text(
                    text = stringResource(
                        R.string.partial_scan_banner_body,
                        scan.realFailureCount
                    ),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurface
                )
            }
        }
    }
}

/** Storage warnings: the latest result not saved / only partly stored, and dropped DNS events. */
@Composable
private fun StorageBanners(viewModel: DashboardViewModel, latestScan: ScanWithFindings?, isScanning: Boolean) {
    val unsaved by viewModel.latestUnsaved.collectAsStateWithLifecycle()
    val healthFailed by viewModel.storageHealthFailed.collectAsStateWithLifecycle()
    val drops by viewModel.dnsDrops.collectAsStateWithLifecycle()
    when (DashboardViewModel.storageBanner(latestScan, isScanning, unsaved, healthFailed)) {
        StorageBanner.NOT_SAVED ->
            WarningBanner(R.string.storage_not_saved_banner_title, R.string.storage_not_saved_banner_body)
        StorageBanner.PARTLY_STORED ->
            WarningBanner(R.string.storage_failed_banner_title, R.string.storage_failed_banner_body)
        StorageBanner.EARLIER_SCAN_SHOWN ->
            WarningBanner(R.string.storage_earlier_banner_title, R.string.storage_earlier_banner_body)
        StorageBanner.NONE -> Unit
    }
    if (drops.any) {
        WarningBanner(
            R.string.dns_drops_banner_title, R.string.dns_drops_banner_body,
            drops.total.coerceAtMost(Int.MAX_VALUE.toLong()).toInt(),
            onDismiss = viewModel::dismissDnsDrops,
        )
    }
}

@Composable
private fun WarningBanner(
    titleRes: Int,
    bodyRes: Int,
    count: Int? = null,
    onDismiss: (() -> Unit)? = null,
    text: String? = null,
) {
    val colors = MaterialTheme.androdrColors
    Card(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(containerColor = colors.high.copy(alpha = 0.15f))
    ) {
        Row(
            modifier = Modifier.padding(16.dp),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(12.dp)
        ) {
            Icon(imageVector = Icons.Filled.Warning, contentDescription = null, tint = colors.high)
            Column(modifier = Modifier.weight(1f)) {
                Text(
                    text = stringResource(titleRes),
                    style = MaterialTheme.typography.titleSmall,
                    fontWeight = FontWeight.SemiBold,
                    color = colors.high
                )
                Text(
                    text = when {
                        count != null -> stringResource(bodyRes, count)
                        text != null -> stringResource(bodyRes, text)
                        else -> stringResource(bodyRes)
                    },
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurface
                )
            }
            onDismiss?.let { TextButton(onClick = it) { Text(stringResource(R.string.dns_drops_banner_dismiss)) } }
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
