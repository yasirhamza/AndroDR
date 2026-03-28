package com.androdr.ui.timeline

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ExperimentalLayoutApi
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
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

private fun severityIconAndColor(severity: String) = when (severity.uppercase()) {
    "CRITICAL" -> Icons.Filled.Error to Color(0xFFCF6679)
    "HIGH" -> Icons.Filled.Warning to Color(0xFFFF9800)
    "MEDIUM" -> Icons.Filled.Warning to Color(0xFFFFD600)
    else -> Icons.Filled.Info to Color(0xFF00D4AA)
}

private val timeFmt = SimpleDateFormat("HH:mm:ss", Locale.US)
private val dateFmt = SimpleDateFormat("MMM dd, yyyy", Locale.US)
private fun formatTime(ts: Long) = if (ts > 0) timeFmt.format(Date(ts)) else "??:??:??"
private fun formatDate(ts: Long) = if (ts > 0) dateFmt.format(Date(ts)) else "Unknown"
