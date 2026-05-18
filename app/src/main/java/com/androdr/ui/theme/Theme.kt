package com.androdr.ui.theme

import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color

// Primary brand color: teal/security green
val TealPrimary = Color(0xFF00D4AA)
val TealPrimaryVariant = Color(0xFF00A882)
val TealOnPrimary = Color(0xFF003328)

val SurfaceDark = Color(0xFF121212)
val SurfaceContainerDark = Color(0xFF1E1E1E)
val SurfaceContainerHighDark = Color(0xFF2A2A2A)
val OnSurfaceDark = Color(0xFFE0E0E0)
val OnSurfaceVariantDark = Color(0xFFB0B0B0)

val BackgroundDark = Color(0xFF0A0A0A)
val OnBackgroundDark = Color(0xFFE0E0E0)

val ErrorColor = Color(0xFFCF6679)
val OnErrorColor = Color(0xFF690021)

private val DarkColorScheme = darkColorScheme(
    primary = TealPrimary,
    onPrimary = TealOnPrimary,
    primaryContainer = TealPrimaryVariant,
    onPrimaryContainer = Color(0xFFB2FFF0),
    secondary = Color(0xFF4DB6AC),
    onSecondary = Color(0xFF003733),
    secondaryContainer = Color(0xFF00504A),
    onSecondaryContainer = Color(0xFF70F2E6),
    tertiary = Color(0xFF80CBFF),
    onTertiary = Color(0xFF003450),
    tertiaryContainer = Color(0xFF004C70),
    onTertiaryContainer = Color(0xFFCDE5FF),
    error = ErrorColor,
    onError = OnErrorColor,
    errorContainer = Color(0xFF93000A),
    onErrorContainer = Color(0xFFFFDAD6),
    background = BackgroundDark,
    onBackground = OnBackgroundDark,
    surface = SurfaceDark,
    onSurface = OnSurfaceDark,
    surfaceVariant = SurfaceContainerDark,
    onSurfaceVariant = OnSurfaceVariantDark,
    outline = Color(0xFF5A5A5A),
    outlineVariant = Color(0xFF3A3A3A),
    surfaceContainer = SurfaceContainerDark,
    surfaceContainerHigh = SurfaceContainerHighDark,
    surfaceContainerLow = Color(0xFF181818),
)

private val LightColorScheme = lightColorScheme(
    primary              = TealPrimaryVariant,            // 0xFF00A882
    onPrimary            = Color.White,
    primaryContainer     = Color(0xFFB2FFF0),
    onPrimaryContainer   = Color(0xFF003328),
    secondary            = Color(0xFF006B62),
    onSecondary          = Color.White,
    secondaryContainer   = Color(0xFF70F2E6),
    onSecondaryContainer = Color(0xFF00201D),
    tertiary             = Color(0xFF00658E),
    onTertiary           = Color.White,
    tertiaryContainer    = Color(0xFFC5E7FF),
    onTertiaryContainer  = Color(0xFF001E2E),
    error                = Color(0xFFB3261E),
    onError              = Color.White,
    errorContainer       = Color(0xFFFFDAD6),
    onErrorContainer     = Color(0xFF410002),
    background           = Color(0xFFFAFAFA),
    onBackground         = Color(0xFF1A1A1A),
    surface              = Color.White,
    onSurface            = Color(0xFF1A1A1A),
    surfaceVariant       = Color(0xFFEEEEEE),
    onSurfaceVariant     = Color(0xFF4A4A4A),
    outline              = Color(0xFF747878),
    outlineVariant       = Color(0xFFC4C7C7),
    surfaceContainer     = Color(0xFFF1F1F1),
    surfaceContainerHigh = Color(0xFFEAEAEA),
    surfaceContainerLow  = Color(0xFFF6F6F6),
)

@Composable
fun AndroDRTheme(content: @Composable () -> Unit) {
    MaterialTheme(
        colorScheme = DarkColorScheme,
        content = content
    )
}
