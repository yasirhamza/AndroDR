package com.androdr.ui.device

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
import androidx.compose.material.icons.filled.CheckCircle
import androidx.compose.material.icons.filled.Cancel
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.SuggestionChip
import androidx.compose.material3.SuggestionChipDefaults
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
import com.androdr.data.model.DeviceFlag
import com.androdr.data.model.Severity

@Composable
fun DeviceAuditScreen(
    viewModel: DeviceAuditViewModel = hiltViewModel()
) {
    val deviceFlags by viewModel.deviceFlags.collectAsStateWithLifecycle()
    val triggeredCount by viewModel.triggeredCount.collectAsStateWithLifecycle()

    val totalCount = deviceFlags.size
    val passedCount = totalCount - triggeredCount

    val triggeredFlags = deviceFlags.filter { it.isTriggered }
        .sortedByDescending { it.severity.ordinal }
    val passedFlags = deviceFlags.filter { !it.isTriggered }

    Column(modifier = Modifier.fillMaxSize()) {
        // Header summary
        Card(
            modifier = Modifier
                .fillMaxWidth()
                .padding(16.dp),
            colors = CardDefaults.cardColors(
                containerColor = MaterialTheme.colorScheme.surfaceContainer
            )
        ) {
            Row(
                modifier = Modifier.padding(20.dp),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(12.dp)
            ) {
                Icon(
                    imageVector = Icons.Filled.CheckCircle,
                    contentDescription = null,
                    tint = MaterialTheme.colorScheme.primary,
                    modifier = Modifier.size(32.dp)
                )
                Column {
                    Text(
                        text = "$passedCount / $totalCount checks passed",
                        style = MaterialTheme.typography.titleMedium,
                        fontWeight = FontWeight.Bold
                    )
                    if (triggeredCount > 0) {
                        Text(
                            text = "$triggeredCount issue(s) require attention",
                            style = MaterialTheme.typography.bodySmall,
                            color = Color(0xFFCF6679)
                        )
                    } else if (totalCount > 0) {
                        Text(
                            text = stringResource(R.string.device_all_clear),
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.primary
                        )
                    }
                }
            }
        }

        if (deviceFlags.isEmpty()) {
            Box(
                modifier = Modifier.fillMaxSize(),
                contentAlignment = Alignment.Center
            ) {
                Text(
                    text = stringResource(R.string.no_scan_yet),
                    style = MaterialTheme.typography.bodyLarge,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
            return
        }

        LazyColumn(
            modifier = Modifier.fillMaxSize(),
            contentPadding = androidx.compose.foundation.layout.PaddingValues(
                start = 16.dp, end = 16.dp, bottom = 16.dp
            ),
            verticalArrangement = Arrangement.spacedBy(8.dp)
        ) {
            if (triggeredFlags.isNotEmpty()) {
                item {
                    SectionHeader(
                        text = stringResource(R.string.section_issues_found),
                        color = Color(0xFFCF6679)
                    )
                }
                items(triggeredFlags) { flag ->
                    DeviceFlagItem(flag = flag)
                }
            }

            if (passedFlags.isNotEmpty()) {
                item {
                    SectionHeader(
                        text = stringResource(R.string.section_checks_passed),
                        color = MaterialTheme.colorScheme.primary
                    )
                }
                items(passedFlags) { flag ->
                    DeviceFlagItem(flag = flag)
                }
            }
        }
    }
}

@Composable
private fun SectionHeader(text: String, color: Color) {
    Text(
        text = text,
        style = MaterialTheme.typography.labelLarge,
        fontWeight = FontWeight.Bold,
        color = color,
        modifier = Modifier.padding(vertical = 8.dp)
    )
}

@Composable
private fun DeviceFlagItem(flag: DeviceFlag) {
    Card(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(
            containerColor = if (flag.isTriggered)
                Color(0xFFCF6679).copy(alpha = 0.08f)
            else
                MaterialTheme.colorScheme.surfaceContainerHigh
        )
    ) {
        Row(
            modifier = Modifier.padding(16.dp),
            horizontalArrangement = Arrangement.spacedBy(12.dp)
        ) {
            // Status indicator
            Icon(
                imageVector = if (flag.isTriggered) Icons.Filled.Cancel else Icons.Filled.CheckCircle,
                contentDescription = if (flag.isTriggered) "Triggered" else "Passed",
                tint = if (flag.isTriggered) Color(0xFFCF6679) else MaterialTheme.colorScheme.primary,
                modifier = Modifier.size(24.dp)
            )

            Column(
                modifier = Modifier.weight(1f),
                verticalArrangement = Arrangement.spacedBy(4.dp)
            ) {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Text(
                        text = flag.title,
                        style = MaterialTheme.typography.titleSmall,
                        fontWeight = FontWeight.SemiBold,
                        modifier = Modifier.weight(1f)
                    )
                    Spacer(modifier = Modifier.width(8.dp))
                    SeverityChip(severity = flag.severity, active = flag.isTriggered)
                }
                if (flag.isTriggered) {
                    Text(
                        text = flag.description,
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }
            }
        }
    }
}

@Composable
private fun SeverityChip(severity: Severity, active: Boolean = true) {
    val severityColor = when (severity) {
        Severity.CRITICAL -> Color(0xFFCF6679)
        Severity.HIGH -> Color(0xFFFF9800)
        Severity.MEDIUM -> Color(0xFFFFD600)
        Severity.INFO -> Color(0xFF00D4AA)
    }
    val label = severity.name
    val color = if (active) severityColor else Color(0xFF888888)
    SuggestionChip(
        onClick = {},
        label = {
            Text(
                text = label,
                style = MaterialTheme.typography.labelSmall,
                fontWeight = FontWeight.Bold
            )
        },
        colors = SuggestionChipDefaults.suggestionChipColors(
            containerColor = color.copy(alpha = 0.2f),
            labelColor = color
        )
    )
}
