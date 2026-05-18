package com.androdr.ui.common

import android.content.res.Configuration
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.SuggestionChip
import androidx.compose.material3.SuggestionChipDefaults
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.tooling.preview.Preview
import androidx.compose.ui.unit.dp
import com.androdr.ui.theme.AndroDRTheme
import com.androdr.ui.theme.ExtendedColors
import com.androdr.ui.theme.ThemeMode
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

@Preview(name = "Severity chips — Dark", uiMode = Configuration.UI_MODE_NIGHT_YES)
@Preview(name = "Severity chips — Light", uiMode = Configuration.UI_MODE_NIGHT_NO)
@Composable
private fun SeverityChipPreview() {
    AndroDRTheme(themeMode = ThemeMode.AUTO) {
        Surface(color = MaterialTheme.colorScheme.background) {
            Row(
                modifier = Modifier.padding(16.dp),
                horizontalArrangement = Arrangement.spacedBy(8.dp)
            ) {
                listOf("critical", "high", "medium", "low").forEach { level ->
                    SeverityChip(level = level)
                }
            }
        }
    }
}
