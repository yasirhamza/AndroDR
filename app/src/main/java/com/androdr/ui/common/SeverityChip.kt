package com.androdr.ui.common

import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.SuggestionChip
import androidx.compose.material3.SuggestionChipDefaults
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight

@Composable
fun SeverityChip(level: String, active: Boolean = true) {
    val severityColor = when (level.lowercase()) {
        "critical" -> Color(0xFFCF6679)
        "high" -> Color(0xFFFF9800)
        "medium" -> Color(0xFFFFD600)
        else -> Color(0xFF00D4AA)
    }
    val color = if (active) severityColor else Color(0xFF888888)
    SuggestionChip(
        onClick = {},
        label = { Text(text = level.uppercase(), style = MaterialTheme.typography.labelSmall, fontWeight = FontWeight.Bold) },
        colors = SuggestionChipDefaults.suggestionChipColors(containerColor = color.copy(alpha = 0.2f), labelColor = color)
    )
}

fun severityColor(level: String): Color = when (level.lowercase()) {
    "critical" -> Color(0xFFCF6679)
    "high" -> Color(0xFFFF9800)
    "medium" -> Color(0xFFFFD600)
    else -> Color(0xFF00D4AA)
}
