package com.androdr.ui.network

import android.content.Intent
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
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
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.androdr.R
import com.androdr.ui.settings.SettingsViewModel
import com.androdr.data.model.DnsEvent
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

@Suppress("LongMethod") // DNS monitor screen integrates VPN toggle, stats summary, and two event
// lists (recent + blocked) with conditional empty states; co-location avoids prop-drilling.
@Composable
fun DnsMonitorScreen(
    viewModel: DnsMonitorViewModel = hiltViewModel(),
    settingsViewModel: SettingsViewModel = hiltViewModel(),
    onRequestVpnPermission: (Intent) -> Unit = {}
) {
    val recentEvents by viewModel.recentEvents.collectAsStateWithLifecycle()
    val blockedEvents by viewModel.blockedEvents.collectAsStateWithLifecycle()
    val isVpnRunning by viewModel.isVpnRunning.collectAsStateWithLifecycle()
    val blocklistBlockMode by settingsViewModel.blocklistBlockMode.collectAsStateWithLifecycle()
    val domainIocBlockMode by settingsViewModel.domainIocBlockMode.collectAsStateWithLifecycle()
    val context = LocalContext.current

    var selectedTab by remember { mutableIntStateOf(0) }
    val tabs = listOf(
        stringResource(R.string.tab_all_events),
        stringResource(R.string.tab_blocked_only)
    )

    Column(modifier = Modifier.fillMaxSize()) {
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

                // Blocked count stat
                Text(
                    text = "${blockedEvents.size} ${stringResource(R.string.domains_blocked)}",
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

        // Policy toggles
        Card(modifier = Modifier.fillMaxWidth().padding(horizontal = 16.dp)) {
            Column(modifier = Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Text("DNS Policy", style = MaterialTheme.typography.labelLarge,
                    color = MaterialTheme.colorScheme.onSurfaceVariant)
                Row(modifier = Modifier.fillMaxWidth(),
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.SpaceBetween) {
                    Text("Blocklist: Block", style = MaterialTheme.typography.bodyMedium)
                    Switch(checked = blocklistBlockMode,
                        onCheckedChange = { settingsViewModel.setBlocklistBlockMode(it) })
                }
                Row(modifier = Modifier.fillMaxWidth(),
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.SpaceBetween) {
                    Text("IOC Domains: Block", style = MaterialTheme.typography.bodyMedium)
                    Switch(checked = domainIocBlockMode,
                        onCheckedChange = { settingsViewModel.setDomainIocBlockMode(it) })
                }
            }
        }

        // Tab row
        TabRow(selectedTabIndex = selectedTab) {
            tabs.forEachIndexed { index, title ->
                Tab(
                    selected = selectedTab == index,
                    onClick = { selectedTab = index },
                    text = { Text(title) }
                )
            }
        }

        // Events list
        val displayEvents = if (selectedTab == 0) recentEvents else blockedEvents

        if (displayEvents.isEmpty()) {
            Box(
                modifier = Modifier.fillMaxSize(),
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
                            stringResource(R.string.no_blocked_events),
                        style = MaterialTheme.typography.bodyLarge,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }
            }
        } else {
            LazyColumn(
                modifier = Modifier.fillMaxSize(),
                contentPadding = androidx.compose.foundation.layout.PaddingValues(16.dp),
                verticalArrangement = Arrangement.spacedBy(8.dp)
            ) {
                items(displayEvents) { event ->
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

    Card(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(
            containerColor = if (event.isBlocked)
                Color(0xFFCF6679).copy(alpha = 0.08f)
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
                    color = if (event.isBlocked) Color(0xFFCF6679)
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
                        text = if (event.isBlocked)
                            stringResource(R.string.status_blocked)
                        else
                            stringResource(R.string.status_allowed),
                        style = MaterialTheme.typography.labelSmall,
                        fontWeight = FontWeight.Bold
                    )
                },
                colors = SuggestionChipDefaults.suggestionChipColors(
                    containerColor = if (event.isBlocked)
                        Color(0xFFCF6679).copy(alpha = 0.2f)
                    else
                        MaterialTheme.colorScheme.primary.copy(alpha = 0.15f),
                    labelColor = if (event.isBlocked) Color(0xFFCF6679)
                    else MaterialTheme.colorScheme.primary
                )
            )
        }
    }
}
