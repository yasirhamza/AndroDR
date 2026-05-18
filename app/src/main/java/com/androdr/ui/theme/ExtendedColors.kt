package com.androdr.ui.theme

import androidx.compose.material3.MaterialTheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.ReadOnlyComposable
import androidx.compose.runtime.staticCompositionLocalOf
import androidx.compose.ui.graphics.Color

/**
 * App-specific semantic colors that Material 3's ColorScheme does not cover:
 * the four severity tiers and their chip-background tints. Two instances —
 * one dark, one light. AndroDRTheme provides the right one via
 * LocalAndroDRColors. Access through MaterialTheme.androdrColors.
 *
 * Container values are calibrated for the ~20% chip-background use case.
 * For sub-percent washes (alert card backgrounds, 6-15%), call sites should
 * use the base hue with .copy(alpha = …) — e.g. critical.copy(alpha = 0.08f).
 * Such call sites are NOT caught by HardcodedColorGuardTest (the guard only
 * matches Color(0xFF…) literals).
 */
data class ExtendedColors(
    val critical: Color,
    val high: Color,
    val medium: Color,
    val low: Color,
    val neutral: Color,
    val criticalContainer: Color,
    val highContainer: Color,
    val mediumContainer: Color,
    val lowContainer: Color,
)

// Dark values preserve the existing hues so the dark UI is visually unchanged.
val DarkExtendedColors = ExtendedColors(
    critical          = Color(0xFFCF6679),
    high              = Color(0xFFFF9800),
    medium            = Color(0xFFE6A800),
    low               = Color(0xFF64B5F6),
    neutral           = TealPrimary,
    criticalContainer = Color(0x33CF6679), // alpha 0x33 ≈ 0.20
    highContainer     = Color(0x33FF9800),
    mediumContainer   = Color(0x33E6A800),
    lowContainer      = Color(0x3364B5F6),
)

// Light values are darker, deeper shades chosen to satisfy WCAG AA UI contrast (≥ 3.0)
// on background 0xFFFAFAFA. Verified by ExtendedColorsContrastTest.
val LightExtendedColors = ExtendedColors(
    critical          = Color(0xFFB3261E),
    high              = Color(0xFFC25700),
    medium            = Color(0xFF8B6B00),
    low               = Color(0xFF1565C0),
    neutral           = Color(0xFF00695C),  // darker teal (TealPrimaryVariant 0xFF00A882 fails AA on white)
    criticalContainer = Color(0xFFFFDAD6),
    highContainer     = Color(0xFFFFDCC2),
    mediumContainer   = Color(0xFFF6E5B4),
    lowContainer      = Color(0xFFD0E4FF),
)

val LocalAndroDRColors = staticCompositionLocalOf<ExtendedColors> {
    error("AndroDRTheme must wrap the call site (LocalAndroDRColors not provided)")
}

val MaterialTheme.androdrColors: ExtendedColors
    @Composable
    @ReadOnlyComposable
    get() = LocalAndroDRColors.current
