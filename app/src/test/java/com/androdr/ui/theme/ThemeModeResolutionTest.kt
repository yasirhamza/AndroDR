package com.androdr.ui.theme

import org.junit.Assert.assertEquals
import org.junit.Test

class ThemeModeResolutionTest {

    @Test
    fun `AUTO mode follows system dark setting`() {
        assertEquals(true,  resolveDarkTheme(ThemeMode.AUTO, systemInDark = true))
        assertEquals(false, resolveDarkTheme(ThemeMode.AUTO, systemInDark = false))
    }

    @Test
    fun `LIGHT mode forces light regardless of system`() {
        assertEquals(false, resolveDarkTheme(ThemeMode.LIGHT, systemInDark = true))
        assertEquals(false, resolveDarkTheme(ThemeMode.LIGHT, systemInDark = false))
    }

    @Test
    fun `DARK mode forces dark regardless of system`() {
        assertEquals(true, resolveDarkTheme(ThemeMode.DARK, systemInDark = true))
        assertEquals(true, resolveDarkTheme(ThemeMode.DARK, systemInDark = false))
    }
}
