package com.androdr.ui.network

import android.content.Intent
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Block
import androidx.compose.material.icons.filled.CheckCircle
import androidx.compose.material.icons.filled.Wifi
import androidx.compose.material.icons.filled.WifiOff
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Switch
import androidx.compose.material3.SuggestionChip
import androidx.compose.material3.SuggestionChipDefaults
import androidx.compose.material3.Tab
import androidx.compose.material3.TabRow
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.androdr.R
import com.androdr.network.DnsVpnService
import com.androdr.ui.settings.SettingsViewModel
import com.androdr.data.model.DnsEvent
import com.androdr.ui.theme.androdrColors
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

@Suppress("LongMethod") // DNS monitor screen integrates VPN toggle, stats summary, and two event
// lists (recent + matched) with conditional empty states; co-location avoids prop-drilling.
@Composable
fun DnsMonitorScreen(
    viewModel: DnsMonitorViewModel = hiltViewModel(),
    settingsViewModel: SettingsViewModel = hiltViewModel(),
    onRequestVpnPermission: (Intent) -> Unit = {}
) {
    val recentEvents by viewModel.recentEvents.collectAsStateWithLifecycle()
    val matchedEvents by viewModel.matchedEvents.collectAsStateWithLifecycle()
    val isVpnRunning by viewModel.isVpnRunning.collectAsStateWithLifecycle()
    val cellular by viewModel.cellularLatest.collectAsStateWithLifecycle()
    val cellularFindings by viewModel.cellularFindings.collectAsStateWithLifecycle()
    val cellularDeliveries by viewModel.cellularDeliveries.collectAsStateWithLifecycle()
    val cellularHistory by viewModel.cellularHistory.collectAsStateWithLifecycle()
    val cellularStatus by viewModel.cellularStatus.collectAsStateWithLifecycle()


    val blocklistBlockMode by settingsViewModel.blocklistBlockMode.collectAsStateWithLifecycle()
    val domainIocBlockMode by settingsViewModel.domainIocBlockMode.collectAsStateWithLifecycle()
    val context = LocalContext.current

    // The app had no runtime permission request at all. The manifest declared
    // location, but nothing ever asked for it, so on a normal install the
    // cellular monitor was permanently inert — it only ever worked on a device
    // where the grant had been forced with `adb shell pm grant`.
    var locationGranted by remember {
        mutableStateOf(
            com.androdr.cellular.CellularMonitor.hasRequiredPermissions(context)
        )
    }
    val locationPermissionLauncher = rememberLauncherForActivityResult(
        androidx.activity.result.contract.ActivityResultContracts.RequestMultiplePermissions()
    ) { result ->
        // Re-read the real permission state rather than trusting the result
        // map: the button must disappear only when EVERY requirement the
        // monitor checks is satisfied, not just the one the dialog was about.
        locationGranted =
            com.androdr.cellular.CellularMonitor.hasRequiredPermissions(context)
        // Only poke the service if it is ALREADY running. Sending this while
        // the VPN is off would start a service that never calls
        // startForeground() — a background start the platform restricts on
        // Android 14+ — and it would be a no-op anyway, because the monitor is
        // only constructed by startVpn(). When the VPN is off the card already
        // says "Monitor not running", which is the accurate next step.
        if (locationGranted && isVpnRunning) {
            context.startService(
                android.content.Intent(context, DnsVpnService::class.java)
                    .setAction(DnsVpnService.ACTION_RETRY_CELLULAR)
            )
        }
    }

    var selectedTab by remember { mutableIntStateOf(0) }
    val tabs = listOf(
        stringResource(R.string.tab_all_events),
        stringResource(R.string.tab_matched_only),
        stringResource(R.string.tab_cellular),
    )

    // One scrolling list: the status/policy cards are ITEMS, not a fixed header,
    // so they scroll away and the event list gets the full screen. Previously
    // three stacked cards sat above the tabs and the list was squeezed into
    // whatever was left — the events are the primary content here, not a
    // footnote under the controls.
    LazyColumn(modifier = Modifier.fillMaxSize()) {
        item {
        // VPN status card
        Card(
            modifier = Modifier
                .fillMaxWidth()
                .padding(16.dp),
            colors = CardDefaults.cardColors(
                containerColor = MaterialTheme.colorScheme.surfaceContainer
            )
        ) {
            Column(
                modifier = Modifier.padding(20.dp),
                verticalArrangement = Arrangement.spacedBy(12.dp)
            ) {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.SpaceBetween
                ) {
                    Row(
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.spacedBy(8.dp)
                    ) {
                        val vpnIconTint = if (isVpnRunning) MaterialTheme.colorScheme.primary
                            else MaterialTheme.colorScheme.onSurfaceVariant
                        Icon(
                            imageVector = if (isVpnRunning) Icons.Filled.Wifi else Icons.Filled.WifiOff,
                            contentDescription = null,
                            tint = vpnIconTint,
                            modifier = Modifier.size(24.dp)
                        )
                        Column {
                            Text(
                                text = stringResource(R.string.dns_vpn_title),
                                style = MaterialTheme.typography.titleSmall,
                                fontWeight = FontWeight.SemiBold
                            )
                            Text(
                                text = if (isVpnRunning)
                                    stringResource(R.string.vpn_status_running)
                                else
                                    stringResource(R.string.vpn_status_stopped),
                                style = MaterialTheme.typography.bodySmall,
                                color = if (isVpnRunning) MaterialTheme.colorScheme.primary
                                else MaterialTheme.colorScheme.onSurfaceVariant
                            )
                        }
                    }

                    Switch(
                        checked = isVpnRunning,
                        onCheckedChange = { checked ->
                            if (checked) {
                                val permIntent = viewModel.requestVpnPermission(
                                    context as android.app.Activity
                                )
                                if (permIntent != null) {
                                    onRequestVpnPermission(permIntent)
                                } else {
                                    viewModel.toggleVpn(context)
                                }
                            } else {
                                viewModel.toggleVpn(context)
                            }
                        }
                    )
                }

                // Matched count stat
                Text(
                    text = "${matchedEvents.size} ${stringResource(R.string.domains_matched)}",
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )

                // Enable VPN button if not running
                if (!isVpnRunning) {
                    Button(
                        onClick = {
                            val permIntent = viewModel.requestVpnPermission(
                                context as android.app.Activity
                            )
                            if (permIntent != null) {
                                onRequestVpnPermission(permIntent)
                            } else {
                                viewModel.toggleVpn(context)
                            }
                        },
                        modifier = Modifier.fillMaxWidth()
                    ) {
                        Text(stringResource(R.string.enable_vpn))
                    }
                }
            }
        }

        }

        item {
        // Policy toggles
        Card(modifier = Modifier.fillMaxWidth().padding(horizontal = 16.dp)) {
            Column(modifier = Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Text(stringResource(R.string.dns_policy_title), style = MaterialTheme.typography.labelLarge,
                    color = MaterialTheme.colorScheme.onSurfaceVariant)
                Row(modifier = Modifier.fillMaxWidth(),
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.SpaceBetween) {
                    Text(stringResource(R.string.dns_blocklist_block), style = MaterialTheme.typography.bodyMedium)
                    Switch(checked = blocklistBlockMode,
                        onCheckedChange = { settingsViewModel.setBlocklistBlockMode(it) })
                }
                Row(modifier = Modifier.fillMaxWidth(),
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.SpaceBetween) {
                    Text(stringResource(R.string.dns_ioc_domains_block), style = MaterialTheme.typography.bodyMedium)
                    Switch(checked = domainIocBlockMode,
                        onCheckedChange = { settingsViewModel.setDomainIocBlockMode(it) })
                }
            }
        }

        }

        item {
        TabRow(selectedTabIndex = selectedTab) {
            tabs.forEachIndexed { index, title ->
                Tab(
                    selected = selectedTab == index,
                    onClick = { selectedTab = index },
                    text = { Text(title) }
                )
            }
        }

        }

        // Cellular gets its own list, alongside the two DNS lists.
        if (selectedTab == 2) {
            item {
                CellularSummary(
                    snapshot = cellular,
                    findings = cellularFindings,
                    deliveries = cellularDeliveries,
                    status = cellularStatus,
                    locationGranted = locationGranted,
                    onGrantLocation = {
                        locationPermissionLauncher.launch(
                            com.androdr.cellular.CellularMonitor.REQUESTED_PERMISSIONS
                        )
                    },
                )
            }
            // No empty-state item here: CellularSummary already renders the
            // waiting text when there is no snapshot, and adding a second one
            // printed the same paragraph twice.
            if (cellularHistory.isNotEmpty()) {
                items(cellularHistory) { snap ->
                    Box(modifier = Modifier.padding(horizontal = 16.dp, vertical = 4.dp)) {
                        CellularHistoryItem(snap)
                    }
                }
            }
            return@LazyColumn
        }

        // Events list
        val displayEvents = if (selectedTab == 0) recentEvents else matchedEvents

        if (displayEvents.isEmpty()) {
            item {
            Box(
                modifier = Modifier.fillMaxWidth().padding(vertical = 48.dp),
                contentAlignment = Alignment.Center
            ) {
                Column(
                    horizontalAlignment = Alignment.CenterHorizontally,
                    verticalArrangement = Arrangement.spacedBy(12.dp)
                ) {
                    Icon(
                        imageVector = if (selectedTab == 1) Icons.Filled.Block else Icons.Filled.CheckCircle,
                        contentDescription = null,
                        tint = MaterialTheme.colorScheme.onSurfaceVariant,
                        modifier = Modifier.size(48.dp)
                    )
                    Text(
                        text = if (selectedTab == 0)
                            stringResource(R.string.no_dns_events)
                        else
                            stringResource(R.string.no_matched_events),
                        style = MaterialTheme.typography.bodyLarge,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }
            }
            }
        } else {
            items(displayEvents) { event ->
                Box(modifier = Modifier.padding(horizontal = 16.dp, vertical = 4.dp)) {
                    DnsEventItem(event = event)
                }
            }
        }
    }
}

@Suppress("LongMethod") // DNS event item displays timestamp, domain, block status, app name,
// and reason badge together; all are needed for triage context in a single glance.
@Composable
private fun DnsEventItem(event: DnsEvent) {
    val timeFormatter = remember { SimpleDateFormat("HH:mm:ss", Locale.getDefault()) }
    val timeString = timeFormatter.format(Date(event.timestamp))

    val isMatched = event.reason != null

    Card(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(
            containerColor = if (isMatched)
                MaterialTheme.androdrColors.critical.copy(alpha = 0.08f)
            else
                MaterialTheme.colorScheme.surfaceContainerHigh
        )
    ) {
        Row(
            modifier = Modifier.padding(12.dp),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(12.dp)
        ) {
            Column(modifier = Modifier.weight(1f)) {
                Text(
                    text = event.domain,
                    style = MaterialTheme.typography.bodyMedium,
                    fontWeight = FontWeight.SemiBold,
                    color = if (isMatched) MaterialTheme.androdrColors.critical
                    else MaterialTheme.colorScheme.onSurface
                )
                Text(
                    text = event.appName ?: "UID: ${event.appUid}",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
                Text(
                    text = timeString,
                    style = MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }

            SuggestionChip(
                onClick = {},
                label = {
                    Text(
                        text = if (isMatched)
                            stringResource(R.string.status_matched)
                        else
                            stringResource(R.string.status_allowed),
                        style = MaterialTheme.typography.labelSmall,
                        fontWeight = FontWeight.Bold
                    )
                },
                colors = SuggestionChipDefaults.suggestionChipColors(
                    containerColor = if (isMatched)
                        MaterialTheme.androdrColors.criticalContainer
                    else
                        MaterialTheme.colorScheme.primary.copy(alpha = 0.15f),
                    labelColor = if (isMatched) MaterialTheme.androdrColors.critical
                    else MaterialTheme.colorScheme.primary
                )
            )
        }
    }
}

@Composable
private fun CellularSummary(
    snapshot: com.androdr.data.model.CellularSnapshot?,
    findings: List<com.androdr.sigma.Finding>,
    deliveries: Int,
    status: com.androdr.cellular.CellularState.Status,
    locationGranted: Boolean,
    onGrantLocation: () -> Unit,
) {
    Card(modifier = Modifier.fillMaxWidth().padding(horizontal = 16.dp, vertical = 8.dp)) {
        Column(
            modifier = Modifier.padding(12.dp),
            verticalArrangement = Arrangement.spacedBy(6.dp),
        ) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.SpaceBetween,
            ) {
                Text(
                    "Cellular (Tier 1)",
                    style = MaterialTheme.typography.labelLarge,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                Text(
                    // Wall-clock time of the last delivery, not just a count.
                    // Re-registering to the SAME cell leaves every identity
                    // field unchanged, so without a timestamp a live card is
                    // indistinguishable from a frozen one — which is exactly
                    // how this looked after an airplane-mode cycle.
                    if (snapshot == null) {
                        "$deliveries update(s)"
                    } else {
                        "$deliveries update(s) \u00B7 ${
                            java.text.SimpleDateFormat("HH:mm:ss", java.util.Locale.US)
                                .format(java.util.Date(snapshot.capturedAt))
                        }"
                    },
                    style = MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
            if (snapshot == null) {
                CellularWaitingText(status)
                if (!locationGranted) {
                    Button(onClick = onGrantLocation, modifier = Modifier.fillMaxWidth()) {
                        Text("Grant location permission")
                    }
                }
            } else {
                CellularSnapshotLines(snapshot)
                CellularFindingLines(findings)
            }
        }
    }
}

/**
 * An empty card is ambiguous here: getAllCellInfo returns an empty list rather
 * than an error when the caller is not allowed to look, so say which state
 * this is instead of showing nothing.
 */
@Composable
private fun CellularWaitingText(status: com.androdr.cellular.CellularState.Status) {
    val (headline, hint) = when (status) {
        com.androdr.cellular.CellularState.Status.NOT_STARTED ->
            "Monitor not running" to
                "Turn on the Network Monitor above. Cellular telemetry is " +
                    "collected by the same foreground service."
        com.androdr.cellular.CellularState.Status.UNSUPPORTED_API ->
            "Not supported on this Android version" to
                "Cellular telemetry needs Android 12 or newer."
        com.androdr.cellular.CellularState.Status.MISSING_PERMISSION ->
            "Location permission required" to
                "Grant Location and choose Precise. Approximate location does " +
                    "not return cell information."
        com.androdr.cellular.CellularState.Status.NO_TELEPHONY ->
            "No cellular radio" to "This device has no telephony service."
        com.androdr.cellular.CellularState.Status.READ_REFUSED ->
            "The system refused the cell read" to
                "Location is granted but the platform denied access. Check that " +
                    "Location is set to Precise and is allowed while the app is in use."
        com.androdr.cellular.CellularState.Status.AWAITING_FIRST_UPDATE ->
            "Waiting for the first radio update" to
                "The monitor is running and the system returned no cells yet."
        com.androdr.cellular.CellularState.Status.ACTIVE ->
            "Waiting for the first radio update" to "The monitor is running."
    }
    Text(headline, style = MaterialTheme.typography.bodyMedium)
    Text(
        hint,
        style = MaterialTheme.typography.bodySmall,
        color = MaterialTheme.colorScheme.onSurfaceVariant,
    )
}

@Composable
private fun CellularSnapshotLines(snapshot: com.androdr.data.model.CellularSnapshot) {
    val muted = MaterialTheme.colorScheme.onSurfaceVariant
    Text(
        "${snapshot.rat} \u00B7 ${snapshot.operatorAlphaLong ?: "unknown operator"}" +
            " \u00B7 ${snapshot.mcc ?: "?"}/${snapshot.mnc ?: "?"}",
        style = MaterialTheme.typography.bodyMedium,
    )
    Text(
        "TAC ${snapshot.tac ?: "\u2014"} \u00B7 CI ${snapshot.ci ?: "\u2014"} \u00B7 " +
            "PCI ${snapshot.pci ?: "\u2014"} \u00B7 EARFCN ${snapshot.earfcn ?: "\u2014"}",
        style = MaterialTheme.typography.bodySmall,
        color = muted,
    )
    Text(
        "${snapshot.neighborCount} neighbour(s) \u00B7 " +
            "RSRP ${snapshot.servingRsrp?.let { "$it dBm" } ?: "\u2014"} \u00B7 " +
            "TAC changes (5m): ${snapshot.tacChangesLast5m}",
        style = MaterialTheme.typography.bodySmall,
        color = muted,
    )
}

@Composable
private fun CellularFindingLines(findings: List<com.androdr.sigma.Finding>) {
    if (findings.isEmpty()) {
        Text(
            "No cellular findings.",
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        return
    }
    findings.forEach { f ->
        Text(
            "\u26A0 ${f.title} (${f.level})",
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.error,
        )
    }
}

/**
 * One radio update. The timestamp is the point: consecutive updates on a
 * stationary device are otherwise identical, so a list of them is the only
 * thing that makes the monitor visibly alive.
 */
@Composable
private fun CellularHistoryItem(snapshot: com.androdr.data.model.CellularSnapshot) {
    val time = java.text.SimpleDateFormat("HH:mm:ss", java.util.Locale.US)
        .format(java.util.Date(snapshot.capturedAt))
    Card(modifier = Modifier.fillMaxWidth()) {
        Column(
            modifier = Modifier.padding(12.dp),
            verticalArrangement = Arrangement.spacedBy(2.dp),
        ) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Text(
                    "$time \u00B7 ${snapshot.rat}",
                    style = MaterialTheme.typography.bodyMedium,
                )
                if (snapshot.tacChanged || snapshot.ratChanged) {
                    Text(
                        if (snapshot.ratChanged) "RAT CHANGED" else "TAC CHANGED",
                        style = MaterialTheme.typography.labelSmall,
                        color = MaterialTheme.colorScheme.error,
                    )
                }
            }
            Text(
                "TAC ${snapshot.tac ?: "\u2014"} \u00B7 CI ${snapshot.ci ?: "\u2014"} \u00B7 " +
                    "${snapshot.neighborCount} neighbour(s) \u00B7 " +
                    "RSRP ${snapshot.servingRsrp?.let { "$it dBm" } ?: "\u2014"}",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
    }
}
