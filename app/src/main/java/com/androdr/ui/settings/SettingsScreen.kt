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
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SegmentedButton
import androidx.compose.material3.SegmentedButtonDefaults
import androidx.compose.material3.SingleChoiceSegmentedButtonRow
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.compose.ui.res.stringResource
import com.androdr.R
import com.androdr.ui.theme.ThemeMode
import com.androdr.util.appVersion
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
    val themeMode by viewModel.themeMode.collectAsStateWithLifecycle()

    val sigmaRuleCount by viewModel.sigmaRuleCount.collectAsStateWithLifecycle()
    val domainIocCount by viewModel.domainIocCount.collectAsStateWithLifecycle()
    val packageIocCount by viewModel.packageIocCount.collectAsStateWithLifecycle()
    val certHashIocCount by viewModel.certHashIocCount.collectAsStateWithLifecycle()
    val cveCount by viewModel.cveCount.collectAsStateWithLifecycle()
    val lastUpdated by viewModel.lastUpdated.collectAsStateWithLifecycle()
    val feedHealth by viewModel.feedHealth.collectAsStateWithLifecycle()
    val updating by viewModel.updating.collectAsStateWithLifecycle()
    val hashExporting by viewModel.hashExporting.collectAsStateWithLifecycle()
    val hashShareUri by viewModel.hashShareUri.collectAsStateWithLifecycle()
    val stixExporting by viewModel.stixExporting.collectAsStateWithLifecycle()
    val stixShareUri by viewModel.stixShareUri.collectAsStateWithLifecycle()
    val iocSourceLabel by viewModel.iocSourceLabel.collectAsStateWithLifecycle()
    val sigmaRuleSource by viewModel.sigmaRuleSource.collectAsStateWithLifecycle()
    val updateResult by viewModel.updateResult.collectAsStateWithLifecycle()

    val context = androidx.compose.ui.platform.LocalContext.current
    androidx.compose.runtime.LaunchedEffect(hashShareUri) {
        hashShareUri?.let { uri ->
            val intent = Intent(Intent.ACTION_SEND).apply {
                type = "text/csv"
                putExtra(Intent.EXTRA_STREAM, uri)
                addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
            }
            context.startActivity(Intent.createChooser(intent, context.getString(R.string.settings_hash_export_share)))
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
            context.startActivity(Intent.createChooser(intent, context.getString(R.string.settings_stix_export_share)))
            viewModel.onStixShareConsumed()
        }
    }

    updateResult?.let { result ->
        AlertDialog(
            onDismissRequest = { viewModel.dismissUpdateResult() },
            confirmButton = {
                TextButton(onClick = { viewModel.dismissUpdateResult() }) {
                    Text(stringResource(android.R.string.ok))
                }
            },
            title = { Text(stringResource(R.string.settings_update_complete_title)) },
            text = {
                Column {
                    UpdateStatusRow(stringResource(R.string.settings_update_indicators), result.indicators)
                    UpdateStatusRow(stringResource(R.string.settings_update_known_apps), result.knownApps)
                    UpdateStatusRow(stringResource(R.string.settings_update_sigma_rules), result.sigmaRules)
                    UpdateStatusRow(stringResource(R.string.settings_update_cve_database), result.cveDatabase)
                    UpdateStatusRow(stringResource(R.string.settings_update_oem_prefixes), result.oemPrefixes)
                    UpdateStatusRow(stringResource(R.string.settings_update_brand_registry), result.brandRegistry)
                }
            }
        )
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
                text = stringResource(R.string.settings_title),
                style = MaterialTheme.typography.headlineMedium,
                fontWeight = FontWeight.Bold,
                color = MaterialTheme.colorScheme.primary
            )

            Text(
                text = stringResource(R.string.settings_appearance_title),
                style = MaterialTheme.typography.titleMedium,
                modifier = Modifier.padding(top = 16.dp)
            )
            Text(
                text = stringResource(R.string.settings_appearance_body),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
            ThemeModePicker(
                selected = themeMode,
                onSelect = { viewModel.setThemeMode(it) }
            )
            HorizontalDivider(modifier = Modifier.padding(vertical = 8.dp))

            Text(
                text = stringResource(R.string.settings_dns_blocklist_title),
                style = MaterialTheme.typography.titleMedium,
                modifier = Modifier.padding(top = 16.dp)
            )
            PolicyToggleRow(
                label = stringResource(R.string.settings_block_matched_domains),
                subtitle = stringResource(R.string.settings_block_off_detect_only),
                checked = blocklistBlockMode,
                onCheckedChange = { viewModel.setBlocklistBlockMode(it) }
            )
            HorizontalDivider(modifier = Modifier.padding(vertical = 8.dp))

            Text(
                text = stringResource(R.string.settings_threat_domains_title),
                style = MaterialTheme.typography.titleMedium
            )
            PolicyToggleRow(
                label = stringResource(R.string.settings_block_matched_domains),
                subtitle = stringResource(R.string.settings_block_off_detect_only_recommended),
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
                onUpdateClick = { viewModel.triggerUpdate() },
                iocSourceLabel = iocSourceLabel,
                sigmaRuleSource = sigmaRuleSource,
                feedHealth = feedHealth
            )
            HorizontalDivider(modifier = Modifier.padding(vertical = 8.dp))

            // Custom Rule URLs section
            Text(
                text = stringResource(R.string.settings_custom_rules_title),
                style = MaterialTheme.typography.titleMedium
            )
            Text(
                text = stringResource(R.string.settings_custom_rules_body),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
            OutlinedTextField(
                value = customRuleUrls,
                onValueChange = { viewModel.setCustomRuleUrls(it) },
                modifier = Modifier.fillMaxWidth(),
                label = { Text(stringResource(R.string.settings_custom_rules_label)) },
                placeholder = { Text(stringResource(R.string.settings_custom_rules_placeholder)) },
                minLines = 3,
                maxLines = 6
            )

            HorizontalDivider(modifier = Modifier.padding(vertical = 8.dp))

            // App Hash Export section
            Text(
                text = stringResource(R.string.settings_hash_export_title),
                style = MaterialTheme.typography.titleMedium
            )
            Text(
                text = stringResource(R.string.settings_hash_export_body),
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
                    Text(stringResource(R.string.settings_hash_export_running), Modifier.padding(start = 8.dp))
                } else {
                    Text(stringResource(R.string.settings_hash_export_action))
                }
            }

            HorizontalDivider(modifier = Modifier.padding(vertical = 8.dp))

            // STIX2 Export section
            Text(
                text = stringResource(R.string.settings_stix_export_title),
                style = MaterialTheme.typography.titleMedium
            )
            Text(
                text = stringResource(R.string.settings_stix_export_body),
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
                    Text(stringResource(R.string.settings_stix_export_running), Modifier.padding(start = 8.dp))
                } else {
                    Text(stringResource(R.string.settings_stix_export_action))
                }
            }

            HorizontalDivider(modifier = Modifier.padding(vertical = 8.dp))

            TelemetryStorageSection()

            HorizontalDivider(modifier = Modifier.padding(vertical = 8.dp))

            // About section
            Text(
                text = stringResource(R.string.settings_about_title),
                style = MaterialTheme.typography.titleMedium
            )
            Card(
                modifier = Modifier.fillMaxWidth(),
                colors = CardDefaults.cardColors(
                    containerColor = MaterialTheme.colorScheme.surfaceContainer
                )
            ) {
                val appVersion = remember(context) { context.appVersion() }
                Column(
                    modifier = Modifier.padding(16.dp),
                    verticalArrangement = Arrangement.spacedBy(6.dp)
                ) {
                    val device = listOf(Build.MANUFACTURER, Build.MODEL).joinToString(" ")
                    StatRow(stringResource(R.string.settings_about_version), appVersion.name)
                    StatRow(stringResource(R.string.settings_about_build), appVersion.code.toString())
                    StatRow(
                        stringResource(R.string.settings_about_android),
                        stringResource(
                            R.string.settings_about_android_value, Build.VERSION.RELEASE, Build.VERSION.SDK_INT,
                        ),
                    )
                    StatRow(stringResource(R.string.settings_about_device), device)
                    StatRow(stringResource(R.string.settings_about_security_patch), Build.VERSION.SECURITY_PATCH)
                }
            }

            Spacer(modifier = Modifier.height(16.dp))
        }
    }
}

@Suppress("LongParameterList") // All parameters are needed to render the complete threat
// database stats card with update button, source labels, and last-updated timestamp.
@Composable
private fun ThreatDatabaseSection(
    sigmaRuleCount: Int,
    domainIocCount: Int,
    packageIocCount: Int,
    certHashIocCount: Int,
    cveCount: Int,
    lastUpdated: Long?,
    updating: Boolean,
    onUpdateClick: () -> Unit,
    iocSourceLabel: Map<String, ThreatDataSource> = emptyMap(),
    sigmaRuleSource: ThreatDataSource = ThreatDataSource.BUNDLED,
    feedHealth: List<FeedHealthUi> = emptyList()
) {
    Text(
        text = stringResource(R.string.settings_threat_db_title),
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
            // Each count and where it came from: "<count> (<source>)".
            listOf(
                Triple(R.string.settings_threat_db_rules, sigmaRuleCount, sigmaRuleSource),
                Triple(R.string.settings_threat_db_domains, domainIocCount, iocSourceLabel["domain"]),
                Triple(R.string.settings_threat_db_apps, packageIocCount, iocSourceLabel["package"]),
                Triple(R.string.settings_threat_db_certificates, certHashIocCount, iocSourceLabel["cert_hash"]),
            ).forEach { (label, count, source) ->
                val from = stringResource((source ?: ThreatDataSource.BUNDLED).label)
                StatRow(stringResource(label), stringResource(R.string.settings_threat_db_count_source, count, from))
            }
            StatRow(
                stringResource(R.string.settings_update_cve_database),
                stringResource(R.string.settings_threat_db_cves, cveCount),
            )

            HorizontalDivider(modifier = Modifier.padding(vertical = 4.dp))

            LastUpdatedText(lastUpdated)
            FeedHealthList(feedHealth)

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
                        text = stringResource(R.string.settings_threat_db_updating),
                        modifier = Modifier.padding(start = 8.dp),
                        style = MaterialTheme.typography.labelLarge
                    )
                } else {
                    Text(stringResource(R.string.settings_threat_db_update_now))
                }
            }
        }
    }
}

@Composable
internal fun StatRow(label: String, value: String) {
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
private fun LastUpdatedText(lastUpdated: Long?) {
    val dateFormatter = remember {
        SimpleDateFormat("MMM d, yyyy  HH:mm", Locale.getDefault())
    }
    Text(
        text = if (lastUpdated != null) {
            stringResource(R.string.settings_last_updated, dateFormatter.format(Date(lastUpdated)))
        } else {
            stringResource(R.string.settings_last_updated_never)
        },
        style = MaterialTheme.typography.bodySmall,
        color = MaterialTheme.colorScheme.onSurfaceVariant
    )
}

@Composable
private fun FeedHealthList(feedHealth: List<FeedHealthUi>) {
    if (feedHealth.isEmpty()) return
    Spacer(modifier = Modifier.height(4.dp))
    Text(
        text = stringResource(R.string.settings_feed_health_title),
        style = MaterialTheme.typography.labelMedium,
        color = MaterialTheme.colorScheme.onSurfaceVariant
    )
    feedHealth.forEach { FeedHealthRow(it) }
}

@Composable
private fun FeedHealthRow(feed: FeedHealthUi) {
    val ageText = feedRelativeAge(feed.lastSuccessAt)
    val color = when {
        feed.isStale -> MaterialTheme.colorScheme.error
        else -> MaterialTheme.colorScheme.onSurfaceVariant
    }
    Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.SpaceBetween
    ) {
        Text(
            text = if (feed.isCritical) stringResource(R.string.settings_feed_critical, feed.label) else feed.label,
            style = MaterialTheme.typography.bodySmall,
            color = color
        )
        Text(
            text = if (feed.isStale) stringResource(R.string.settings_feed_stale, ageText) else ageText,
            style = MaterialTheme.typography.bodySmall,
            fontWeight = if (feed.isStale) FontWeight.SemiBold else FontWeight.Normal,
            color = color
        )
    }
}

/** Human "x ago" for a last-success epoch-ms, or "never" for 0. */
@Composable
private fun feedRelativeAge(lastSuccessAt: Long): String {
    if (lastSuccessAt <= 0L) return stringResource(R.string.settings_feed_age_never)
    val deltaMs = System.currentTimeMillis() - lastSuccessAt
    val days = deltaMs / (24 * 60 * 60 * 1000)
    val hours = deltaMs / (60 * 60 * 1000)
    val minutes = deltaMs / (60 * 1000)
    return when {
        days >= 1 -> stringResource(R.string.settings_feed_age_days, days.toInt())
        hours >= 1 -> stringResource(R.string.settings_feed_age_hours, hours.toInt())
        minutes >= 1 -> stringResource(R.string.settings_feed_age_minutes, minutes.toInt())
        else -> stringResource(R.string.settings_feed_age_just_now)
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

@Composable
private fun UpdateStatusRow(label: String, status: String) {
    Row(
        modifier = Modifier.fillMaxWidth().padding(vertical = 4.dp),
        horizontalArrangement = Arrangement.SpaceBetween
    ) {
        Text(label, style = MaterialTheme.typography.bodyMedium)
        Text(
            status,
            style = MaterialTheme.typography.bodyMedium,
            color = if (status.contains("failed", ignoreCase = true)) MaterialTheme.colorScheme.error
                    else MaterialTheme.colorScheme.primary
        )
    }
}

@Composable
private fun ThemeModePicker(
    selected: ThemeMode,
    onSelect: (ThemeMode) -> Unit
) {
    val options = listOf(
        ThemeMode.AUTO to R.string.settings_theme_system,
        ThemeMode.LIGHT to R.string.settings_theme_light,
        ThemeMode.DARK to R.string.settings_theme_dark,
    )
    SingleChoiceSegmentedButtonRow(modifier = Modifier.fillMaxWidth()) {
        options.forEachIndexed { index, (mode, label) ->
            SegmentedButton(
                selected = selected == mode,
                onClick  = { onSelect(mode) },
                shape    = SegmentedButtonDefaults.itemShape(index = index, count = options.size)
            ) {
                Text(stringResource(label))
            }
        }
    }
}
