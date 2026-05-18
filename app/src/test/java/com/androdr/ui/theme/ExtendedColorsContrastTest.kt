package com.androdr.ui.theme

import androidx.compose.ui.graphics.Color
import org.junit.Assert.assertTrue
import org.junit.Test

private const val WCAG_AA_UI = 3.0  // UI components and large text; severity chips are UI.

class ExtendedColorsContrastTest {

    @Test
    fun `dark severity colors meet AA against dark background`() {
        val bg = Color(0xFF0A0A0A) // BackgroundDark
        assertAaUi("critical", DarkExtendedColors.critical, bg)
        assertAaUi("high",     DarkExtendedColors.high,     bg)
        assertAaUi("medium",   DarkExtendedColors.medium,   bg)
        assertAaUi("low",      DarkExtendedColors.low,      bg)
        assertAaUi("neutral",  DarkExtendedColors.neutral,  bg)
    }

    @Test
    fun `light severity colors meet AA against light background`() {
        val bg = Color(0xFFFAFAFA)
        assertAaUi("critical", LightExtendedColors.critical, bg)
        assertAaUi("high",     LightExtendedColors.high,     bg)
        assertAaUi("medium",   LightExtendedColors.medium,   bg)
        assertAaUi("low",      LightExtendedColors.low,      bg)
        assertAaUi("neutral",  LightExtendedColors.neutral,  bg)
    }

    @Test
    fun `light severity colors meet AA against their containers`() {
        val light = LightExtendedColors
        assertAaUi("critical/container", light.critical, light.criticalContainer)
        assertAaUi("high/container",     light.high,     light.highContainer)
        assertAaUi("medium/container",   light.medium,   light.mediumContainer)
        assertAaUi("low/container",      light.low,      light.lowContainer)
    }

    private fun assertAaUi(name: String, fg: Color, bg: Color) {
        val ratio = contrastRatio(fg, bg)
        assertTrue(
            "$name: fg=${fg.toHex()} bg=${bg.toHex()} contrast=${"%.2f".format(ratio)} < $WCAG_AA_UI",
            ratio >= WCAG_AA_UI
        )
    }
}

/** WCAG 2.x contrast ratio. fg/bg expected to be fully opaque; alpha is ignored. */
internal fun contrastRatio(fg: Color, bg: Color): Double {
    val l1 = relativeLuminance(fg)
    val l2 = relativeLuminance(bg)
    val lighter = maxOf(l1, l2)
    val darker  = minOf(l1, l2)
    return (lighter + 0.05) / (darker + 0.05)
}

private fun relativeLuminance(c: Color): Double {
    fun chan(v: Float): Double {
        val s = v.toDouble()
        return if (s <= 0.03928) s / 12.92 else Math.pow((s + 0.055) / 1.055, 2.4)
    }
    return 0.2126 * chan(c.red) + 0.7152 * chan(c.green) + 0.0722 * chan(c.blue)
}

private fun Color.toHex(): String = String.format(
    "#%02X%02X%02X",
    (red * 255).toInt(), (green * 255).toInt(), (blue * 255).toInt()
)
