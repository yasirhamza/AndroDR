package com.androdr.ui.timeline

import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ExperimentalLayoutApi
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Error
import androidx.compose.material.icons.filled.Info
import androidx.compose.material.icons.filled.Warning
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.ModalBottomSheet
import androidx.compose.material3.SuggestionChip
import androidx.compose.material3.SuggestionChipDefaults
import androidx.compose.material3.Text
import androidx.compose.material3.rememberModalBottomSheetState
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import com.androdr.data.model.ForensicTimelineEvent
import com.androdr.ui.common.SeverityChip
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

@OptIn(ExperimentalLayoutApi::class)
@Composable
fun TimelineEventCard(
    event: ForensicTimelineEvent,
    onClick: () -> Unit
) {
    val (icon, color) = severityIconAndColor(event.severity)

    Card(
        modifier = Modifier.fillMaxWidth().clickable(onClick = onClick),
        colors = CardDefaults.cardColors(containerColor = color.copy(alpha = 0.08f))
    ) {
        Row(
            modifier = Modifier.padding(12.dp),
            horizontalArrangement = Arrangement.spacedBy(10.dp)
        ) {
            Icon(
                imageVector = icon, contentDescription = event.severity,
                tint = color, modifier = Modifier.size(20.dp)
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
                        text = formatTime(event.timestamp),
                        style = MaterialTheme.typography.labelSmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                    SeverityChip(level = event.severity, active = true)
                }
                Text(
                    text = event.description,
                    style = MaterialTheme.typography.bodySmall,
                    maxLines = 2, overflow = TextOverflow.Ellipsis
                )
                FlowRow(horizontalArrangement = Arrangement.spacedBy(4.dp)) {
                    if (event.campaignName.isNotEmpty()) TagChip(event.campaignName, Color(0xFFCF6679))
                    if (event.iocType.isNotEmpty()) TagChip(event.iocType, Color(0xFFFF9800))
                    TagChip(event.source, MaterialTheme.colorScheme.primary)
                }
            }
        }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun TimelineEventDetailSheet(
    event: ForensicTimelineEvent,
    onDismiss: () -> Unit
) {
    ModalBottomSheet(
        onDismissRequest = onDismiss,
        sheetState = rememberModalBottomSheetState(skipPartiallyExpanded = true)
    ) {
        Column(
            modifier = Modifier.padding(horizontal = 24.dp, vertical = 16.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp)
        ) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Text(event.category, style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.Bold)
                SeverityChip(level = event.severity, active = true)
            }
            Text(
                text = "${formatTime(event.timestamp)}  ${formatDate(event.timestamp)}",
                style = MaterialTheme.typography.labelMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
            HorizontalDivider()
            DetailSection("Description", event.description)
            if (event.details.isNotEmpty()) DetailSection("Details", event.details)
            if (event.packageName.isNotEmpty()) DetailSection("Package", event.packageName)
            if (event.iocIndicator.isNotEmpty()) DetailSection("IOC Match", "${event.iocIndicator} (${event.iocType})")
            if (event.campaignName.isNotEmpty()) DetailSection("Campaign", event.campaignName)
            if (event.ruleId.isNotEmpty()) DetailSection("Rule", event.ruleId)
            if (event.attackTechniqueId.isNotEmpty()) DetailSection("MITRE ATT&CK", event.attackTechniqueId)
            Spacer(modifier = Modifier.height(32.dp))
        }
    }
}

@Composable
private fun DetailSection(label: String, value: String) {
    Column {
        Text(label, style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
        Text(value, style = MaterialTheme.typography.bodyMedium)
    }
}

@Composable
private fun TagChip(text: String, color: Color) {
    SuggestionChip(
        onClick = {},
        label = { Text(text, style = MaterialTheme.typography.labelSmall) },
        colors = SuggestionChipDefaults.suggestionChipColors(
            containerColor = color.copy(alpha = 0.15f), labelColor = color
        ),
        modifier = Modifier.height(24.dp)
    )
}

@Composable
fun CorrelationClusterCard(
    cluster: EventCluster,
    onEventTap: (ForensicTimelineEvent) -> Unit
) {
    val clusterColor = when (cluster.pattern) {
        CorrelationPattern.PERMISSION_THEN_C2,
        CorrelationPattern.INSTALL_THEN_ADMIN -> Color(0xFFCF6679) // Red box
        CorrelationPattern.MULTI_PERMISSION_BURST -> Color(0xFFFF9800) // Orange box
        else -> {
            // Severity-based for generic/pre-linked/install-then-permission
            val maxSev = cluster.events.maxOf { severityOrdinal(it.severity) }
            when (maxSev) {
                3 -> Color(0xFFCF6679)
                2 -> Color(0xFFFF9800)
                1 -> Color(0xFFFFD600)
                else -> Color(0xFF00D4AA)
            }
        }
    }

    Card(
        modifier = Modifier.fillMaxWidth(),
        border = BorderStroke(2.dp, clusterColor.copy(alpha = 0.5f)),
        colors = CardDefaults.cardColors(
            containerColor = clusterColor.copy(alpha = 0.04f)
        )
    ) {
        Column(modifier = Modifier.padding(12.dp)) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Text(
                    "${cluster.label} (${cluster.events.size})",
                    style = MaterialTheme.typography.labelMedium,
                    fontWeight = FontWeight.Bold,
                    color = clusterColor
                )
                val timeRange = formatTimeRange(cluster.events)
                Text(
                    timeRange,
                    style = MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
            Spacer(modifier = Modifier.height(8.dp))
            cluster.events.forEachIndexed { index, event ->
                TimelineEventCard(event = event, onClick = { onEventTap(event) })
                if (index < cluster.events.lastIndex) {
                    // Vertical connector line
                    Box(
                        modifier = Modifier
                            .padding(start = 10.dp)
                            .width(2.dp)
                            .height(4.dp)
                            .background(clusterColor.copy(alpha = 0.3f))
                    )
                }
            }
        }
    }
}

@Composable
fun ScanGroupHeader(group: ScanGroup) {
    val fmt = SimpleDateFormat("MMM dd, yyyy HH:mm", Locale.US)
    val dateStr = if (group.timestamp > 0) fmt.format(Date(group.timestamp)) else "Unknown"
    val typeLabel = if (group.isFromBugreport) "Bug Report Analysis" else "Runtime Scan"

    Card(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(
            containerColor = MaterialTheme.colorScheme.surfaceContainer
        )
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(12.dp),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically
        ) {
            Column {
                Text(
                    typeLabel,
                    style = MaterialTheme.typography.titleSmall,
                    fontWeight = FontWeight.Bold
                )
                Text(
                    dateStr,
                    style = MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
            Row(
                horizontalArrangement = Arrangement.spacedBy(8.dp),
                verticalAlignment = Alignment.CenterVertically
            ) {
                Text(
                    "${group.eventCount} events",
                    style = MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
                SeverityChip(level = group.maxSeverity, active = true)
            }
        }
    }
}

private fun formatTimeRange(events: List<ForensicTimelineEvent>): String {
    if (events.isEmpty()) return ""
    val fmt = SimpleDateFormat("HH:mm", Locale.US)
    val first = events.minOf { it.timestamp }
    val last = events.maxOf { it.timestamp }
    return if (first > 0 && last > 0) {
        "${fmt.format(Date(first))}\u2013${fmt.format(Date(last))}"
    } else ""
}

private fun severityOrdinal(level: String): Int = when (level.uppercase()) {
    "CRITICAL" -> 3; "HIGH" -> 2; "MEDIUM" -> 1; else -> 0
}

private fun severityIconAndColor(severity: String) = when (severity.uppercase()) {
    "CRITICAL" -> Icons.Filled.Error to Color(0xFFCF6679)
    "HIGH" -> Icons.Filled.Warning to Color(0xFFFF9800)
    "MEDIUM" -> Icons.Filled.Warning to Color(0xFFFFD600)
    else -> Icons.Filled.Info to Color(0xFF00D4AA)
}

private fun formatTime(ts: Long) =
    if (ts > 0) SimpleDateFormat("HH:mm:ss", Locale.US).format(Date(ts)) else "??:??:??"

private fun formatDate(ts: Long) =
    if (ts > 0) SimpleDateFormat("MMM dd, yyyy", Locale.US).format(Date(ts)) else "Unknown"
