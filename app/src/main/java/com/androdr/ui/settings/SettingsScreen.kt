package com.androdr.ui.settings

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import android.content.Intent
import android.os.Build
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

@Suppress("LongMethod") // Settings screen renders all sections (DNS policy, threat database,
// custom rules) in a single scrollable column; splitting would require hoisting many state values.
@Composable
fun SettingsScreen(viewModel: SettingsViewModel = hiltViewModel()) {
    val blocklistBlockMode by viewModel.blocklistBlockMode.collectAsStateWithLifecycle()
    val domainIocBlockMode by viewModel.domainIocBlockMode.collectAsStateWithLifecycle()
    val customRuleUrls by viewModel.customRuleUrls.collectAsStateWithLifecycle()

    val sigmaRuleCount by viewModel.sigmaRuleCount.collectAsStateWithLifecycle()
    val domainIocCount by viewModel.domainIocCount.collectAsStateWithLifecycle()
    val packageIocCount by viewModel.packageIocCount.collectAsStateWithLifecycle()
    val certHashIocCount by viewModel.certHashIocCount.collectAsStateWithLifecycle()
    val cveCount by viewModel.cveCount.collectAsStateWithLifecycle()
    val lastUpdated by viewModel.lastUpdated.collectAsStateWithLifecycle()
    val updating by viewModel.updating.collectAsStateWithLifecycle()
    val hashExporting by viewModel.hashExporting.collectAsStateWithLifecycle()
    val hashShareUri by viewModel.hashShareUri.collectAsStateWithLifecycle()
    val stixExporting by viewModel.stixExporting.collectAsStateWithLifecycle()
    val stixShareUri by viewModel.stixShareUri.collectAsStateWithLifecycle()

    val context = androidx.compose.ui.platform.LocalContext.current
    androidx.compose.runtime.LaunchedEffect(hashShareUri) {
        hashShareUri?.let { uri ->
            val intent = Intent(Intent.ACTION_SEND).apply {
                type = "text/csv"
                putExtra(Intent.EXTRA_STREAM, uri)
                addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
            }
            context.startActivity(Intent.createChooser(intent, "Share App Hashes"))
            viewModel.onHashShareConsumed()
        }
    }
    androidx.compose.runtime.LaunchedEffect(stixShareUri) {
        stixShareUri?.let { uri ->
            val intent = Intent(Intent.ACTION_SEND).apply {
                type = "application/json"
                putExtra(Intent.EXTRA_STREAM, uri)
                addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
            }
            context.startActivity(Intent.createChooser(intent, "Share STIX2 Bundle"))
            viewModel.onStixShareConsumed()
        }
    }

    Scaffold { innerPadding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(innerPadding)
                .padding(16.dp)
                .verticalScroll(rememberScrollState()),
            verticalArrangement = Arrangement.spacedBy(8.dp)
        ) {
            Text(
                text = "Settings",
                style = MaterialTheme.typography.headlineMedium,
                fontWeight = FontWeight.Bold,
                color = MaterialTheme.colorScheme.primary
            )

            Text(
                text = "DNS Blocklist",
                style = MaterialTheme.typography.titleMedium,
                modifier = Modifier.padding(top = 16.dp)
            )
            PolicyToggleRow(
                label = "Block matched domains",
                subtitle = "Off = detect and log only",
                checked = blocklistBlockMode,
                onCheckedChange = { viewModel.setBlocklistBlockMode(it) }
            )
            HorizontalDivider(modifier = Modifier.padding(vertical = 8.dp))

            Text(
                text = "Threat Intelligence Domains",
                style = MaterialTheme.typography.titleMedium
            )
            PolicyToggleRow(
                label = "Block matched domains",
                subtitle = "Off = detect and log only (recommended for EDR)",
                checked = domainIocBlockMode,
                onCheckedChange = { viewModel.setDomainIocBlockMode(it) }
            )
            HorizontalDivider(modifier = Modifier.padding(vertical = 8.dp))

            // Threat Database section
            ThreatDatabaseSection(
                sigmaRuleCount = sigmaRuleCount,
                domainIocCount = domainIocCount,
                packageIocCount = packageIocCount,
                certHashIocCount = certHashIocCount,
                cveCount = cveCount,
                lastUpdated = lastUpdated,
                updating = updating,
                onUpdateClick = { viewModel.triggerUpdate() }
            )
            HorizontalDivider(modifier = Modifier.padding(vertical = 8.dp))

            // Custom Rule URLs section
            Text(
                text = "Custom Rule URLs",
                style = MaterialTheme.typography.titleMedium
            )
            Text(
                text = "Detection rule sources (one per line). Each URL should point to a " +
                    "raw GitHub directory containing a rules.txt manifest.",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
            OutlinedTextField(
                value = customRuleUrls,
                onValueChange = { viewModel.setCustomRuleUrls(it) },
                modifier = Modifier.fillMaxWidth(),
                label = { Text("Rule URLs") },
                placeholder = { Text("https://raw.githubusercontent.com/...") },
                minLines = 3,
                maxLines = 6
            )

            HorizontalDivider(modifier = Modifier.padding(vertical = 8.dp))

            // App Hash Export section
            Text(
                text = "App Hash Export",
                style = MaterialTheme.typography.titleMedium
            )
            Text(
                text = "Export SHA-256 hashes of all installed apps as CSV. " +
                    "Use these hashes to check apps on VirusTotal.",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
            OutlinedButton(
                onClick = { viewModel.exportAppHashes() },
                modifier = Modifier.fillMaxWidth(),
                enabled = !hashExporting
            ) {
                if (hashExporting) {
                    CircularProgressIndicator(
                        modifier = Modifier.size(18.dp),
                        strokeWidth = 2.dp
                    )
                    Text("  Computing hashes...")
                } else {
                    Text("Export App Hashes (CSV)")
                }
            }

            HorizontalDivider(modifier = Modifier.padding(vertical = 8.dp))

            // STIX2 Export section
            Text(
                text = "Scan Findings Export",
                style = MaterialTheme.typography.titleMedium
            )
            Text(
                text = "Export scan findings as a STIX 2.1 JSON bundle for sharing " +
                    "with forensic analysts. Compatible with MVT, MISP, and SIEM platforms.",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
            OutlinedButton(
                onClick = { viewModel.exportStix2() },
                modifier = Modifier.fillMaxWidth(),
                enabled = !stixExporting
            ) {
                if (stixExporting) {
                    CircularProgressIndicator(
                        modifier = Modifier.size(18.dp),
                        strokeWidth = 2.dp
                    )
                    Text("  Exporting...")
                } else {
                    Text("Export Findings (STIX2 JSON)")
                }
            }

            HorizontalDivider(modifier = Modifier.padding(vertical = 8.dp))

            // About section
            Text(
                text = "About",
                style = MaterialTheme.typography.titleMedium
            )
            Card(
                modifier = Modifier.fillMaxWidth(),
                colors = CardDefaults.cardColors(
                    containerColor = MaterialTheme.colorScheme.surfaceContainer
                )
            ) {
                Column(
                    modifier = Modifier.padding(16.dp),
                    verticalArrangement = Arrangement.spacedBy(6.dp)
                ) {
                    StatRow(
                        label = "Version",
                        value = com.androdr.BuildConfig.VERSION_NAME
                    )
                    StatRow(
                        label = "Build",
                        value = com.androdr.BuildConfig.VERSION_CODE.toString()
                    )
                    StatRow(
                        label = "Android",
                        value = "${Build.VERSION.RELEASE} (API ${Build.VERSION.SDK_INT})"
                    )
                    StatRow(
                        label = "Device",
                        value = "${Build.MANUFACTURER} ${Build.MODEL}"
                    )
                    StatRow(
                        label = "Security Patch",
                        value = Build.VERSION.SECURITY_PATCH
                    )
                }
            }

            Spacer(modifier = Modifier.height(16.dp))
        }
    }
}

@Suppress("LongParameterList") // All 8 parameters are needed to render the complete threat
// database stats card with update button and last-updated timestamp.
@Composable
private fun ThreatDatabaseSection(
    sigmaRuleCount: Int,
    domainIocCount: Int,
    packageIocCount: Int,
    certHashIocCount: Int,
    cveCount: Int,
    lastUpdated: Long?,
    updating: Boolean,
    onUpdateClick: () -> Unit
) {
    Text(
        text = "Threat Database",
        style = MaterialTheme.typography.titleMedium
    )

    Card(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(
            containerColor = MaterialTheme.colorScheme.surfaceContainer
        )
    ) {
        Column(
            modifier = Modifier.padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(6.dp)
        ) {
            StatRow(label = "Detection Rules", value = "$sigmaRuleCount loaded")
            StatRow(label = "Threat Domains", value = "$domainIocCount")
            StatRow(label = "Threat Apps", value = "$packageIocCount")
            StatRow(label = "Threat Certificates", value = "$certHashIocCount")
            StatRow(label = "CVE Database", value = "$cveCount Android CVEs")

            HorizontalDivider(modifier = Modifier.padding(vertical = 4.dp))

            val dateFormatter = remember {
                SimpleDateFormat("MMM d, yyyy  HH:mm", Locale.getDefault())
            }
            Text(
                text = if (lastUpdated != null) {
                    "Last updated: ${dateFormatter.format(Date(lastUpdated))}"
                } else {
                    "Last updated: Never"
                },
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )

            Spacer(modifier = Modifier.height(4.dp))

            Button(
                onClick = onUpdateClick,
                modifier = Modifier.fillMaxWidth(),
                enabled = !updating
            ) {
                if (updating) {
                    CircularProgressIndicator(
                        modifier = Modifier.size(18.dp),
                        strokeWidth = 2.dp,
                        color = MaterialTheme.colorScheme.onPrimary
                    )
                    Text(
                        text = "  Updating...",
                        style = MaterialTheme.typography.labelLarge
                    )
                } else {
                    Text("Update Now")
                }
            }
        }
    }
}

@Composable
private fun StatRow(label: String, value: String) {
    Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.SpaceBetween
    ) {
        Text(
            text = label,
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurface
        )
        Text(
            text = value,
            style = MaterialTheme.typography.bodyMedium,
            fontWeight = FontWeight.SemiBold,
            color = MaterialTheme.colorScheme.primary
        )
    }
}

@Composable
private fun PolicyToggleRow(
    label: String,
    subtitle: String,
    checked: Boolean,
    onCheckedChange: (Boolean) -> Unit
) {
    Row(
        modifier = Modifier.fillMaxWidth(),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.SpaceBetween
    ) {
        Column(modifier = Modifier.weight(1f)) {
            Text(text = label, style = MaterialTheme.typography.bodyLarge)
            Text(
                text = subtitle,
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
        }
        Switch(checked = checked, onCheckedChange = onCheckedChange)
    }
}
