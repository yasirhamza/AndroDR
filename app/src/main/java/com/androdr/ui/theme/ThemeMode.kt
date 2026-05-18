package com.androdr.ui.theme

enum class ThemeMode { AUTO, LIGHT, DARK }

fun resolveDarkTheme(themeMode: ThemeMode, systemInDark: Boolean): Boolean =
    when (themeMode) {
        ThemeMode.LIGHT -> false
        ThemeMode.DARK  -> true
        ThemeMode.AUTO  -> systemInDark
    }
