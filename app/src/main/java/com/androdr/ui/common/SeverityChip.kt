package com.androdr.ui.common

import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.SuggestionChip
import androidx.compose.material3.SuggestionChipDefaults
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import com.androdr.ui.theme.ExtendedColors
import com.androdr.ui.theme.androdrColors

@Composable
fun SeverityChip(level: String, active: Boolean = true) {
    val colors = MaterialTheme.androdrColors
    val severityHue = severityColor(level, colors)
    val color = if (active) severityHue else MaterialTheme.colorScheme.onSurface.copy(alpha = 0.38f)
    SuggestionChip(
        onClick = {},
        label = {
            Text(
                text = level.uppercase(),
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

/**
 * Non-Composable severity → color lookup. Takes the palette as a parameter so
 * non-Composable callers (e.g. result-formatting helpers) can use it without
 * having to become @Composable themselves. Composable callers should pass
 * `MaterialTheme.androdrColors`.
 */
fun severityColor(level: String, colors: ExtendedColors): Color = when (level.lowercase()) {
    "critical" -> colors.critical
    "high"     -> colors.high
    "medium"   -> colors.medium
    "low"      -> colors.low
    else       -> colors.neutral
}
