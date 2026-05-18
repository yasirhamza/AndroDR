# Light/Dark Theme Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make AndroDR's UI legible on every Android device by introducing a light color scheme that follows the OS setting, a user override (Auto/Light/Dark), a semantic-color layer, and migration of all hardcoded color literals. Fixes the tester-reported invisible-text bug on Honor MagicOS.

**Architecture:** A new `ThemeMode` enum is persisted in `SettingsRepository` (DataStore). `AndroDRTheme` resolves it against `isSystemInDarkTheme()` and provides both a Material 3 `ColorScheme` and an app-specific `ExtendedColors` (severity hues, alert backgrounds) via `CompositionLocal`. The Activity theme drops hardcoded system-bar colors and `forceDarkAllowed` is disabled to stop OEM overrides. Five UI files migrate from hardcoded `Color(0xFF…)` literals to `MaterialTheme.androdrColors.*`, and a unit test guards against regression.

**Tech Stack:** Kotlin, Jetpack Compose, Material 3, Hilt, Jetpack DataStore (Preferences), AndroidX `WindowCompat`. JVM unit tests with JUnit 4.

**Spec:** `docs/superpowers/specs/2026-05-18-light-dark-theme-design.md`

---

## File Structure

**Create (new):**
- `app/src/main/java/com/androdr/ui/theme/ThemeMode.kt` — `ThemeMode` enum + `resolveDarkTheme` pure helper.
- `app/src/main/java/com/androdr/ui/theme/ExtendedColors.kt` — data class, `LocalAndroDRColors`, `DarkExtendedColors`, `LightExtendedColors`, `MaterialTheme.androdrColors` extension.
- `app/src/test/java/com/androdr/ui/theme/ThemeModeResolutionTest.kt` — truth table for `resolveDarkTheme`.
- `app/src/test/java/com/androdr/ui/theme/ExtendedColorsContrastTest.kt` — WCAG AA contrast assertions on both palette instances.
- `app/src/test/java/com/androdr/ui/theme/HardcodedColorGuardTest.kt` — drift guard scanning `*.kt` outside `ui/theme/`.
- `app/src/test/java/com/androdr/data/repo/SettingsRepositoryThemeModeTest.kt` — round-trip test for the new DataStore key.

**Modify:**
- `app/src/main/java/com/androdr/ui/theme/Theme.kt` — add `LightColorScheme`, refactor `AndroDRTheme(themeMode = ...)`, wire `CompositionLocal`.
- `app/src/main/java/com/androdr/data/repo/SettingsRepository.kt` — add `themeMode` Flow + `setThemeMode` + key constant.
- `app/src/main/java/com/androdr/ui/settings/SettingsViewModel.kt` — expose `themeMode` StateFlow + `setThemeMode`.
- `app/src/main/java/com/androdr/ui/settings/SettingsScreen.kt` — add "Appearance" section with 3-option picker.
- `app/src/main/java/com/androdr/MainActivity.kt` — inject `SettingsRepository`, collect theme mode, pass into `AndroDRTheme`, drive system-bar colors from Compose.
- `app/src/main/res/values/themes.xml` — drop hardcoded bar colors, add `android:forceDarkAllowed="false"`, switch parent to DayNight.
- `app/src/main/java/com/androdr/ui/common/SeverityChip.kt` — migrate severity literals.
- `app/src/main/java/com/androdr/ui/common/FindingCard.kt` — migrate severity literals.
- `app/src/main/java/com/androdr/ui/common/EvidenceSheet.kt` — migrate severity literals.
- `app/src/main/java/com/androdr/ui/timeline/TimelineEventCard.kt` — migrate severity literals.
- `app/src/main/java/com/androdr/ui/network/DnsMonitorScreen.kt` — migrate severity literals.

---

## Task 1: ThemeMode enum + pure resolver

**Files:**
- Create: `app/src/main/java/com/androdr/ui/theme/ThemeMode.kt`
- Test: `app/src/test/java/com/androdr/ui/theme/ThemeModeResolutionTest.kt`

- [ ] **Step 1: Write the failing test**

Create `app/src/test/java/com/androdr/ui/theme/ThemeModeResolutionTest.kt`:

```kotlin
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `./gradlew :app:testDebugUnitTest --tests "com.androdr.ui.theme.ThemeModeResolutionTest"`
Expected: FAIL (unresolved reference `ThemeMode`, `resolveDarkTheme`).

- [ ] **Step 3: Implement ThemeMode + resolver**

Create `app/src/main/java/com/androdr/ui/theme/ThemeMode.kt`:

```kotlin
package com.androdr.ui.theme

enum class ThemeMode { AUTO, LIGHT, DARK }

fun resolveDarkTheme(themeMode: ThemeMode, systemInDark: Boolean): Boolean =
    when (themeMode) {
        ThemeMode.LIGHT -> false
        ThemeMode.DARK  -> true
        ThemeMode.AUTO  -> systemInDark
    }
```

- [ ] **Step 4: Run test to verify it passes**

Run: `./gradlew :app:testDebugUnitTest --tests "com.androdr.ui.theme.ThemeModeResolutionTest"`
Expected: PASS (3/3).

- [ ] **Step 5: Commit**

```bash
git add app/src/main/java/com/androdr/ui/theme/ThemeMode.kt \
        app/src/test/java/com/androdr/ui/theme/ThemeModeResolutionTest.kt
git commit -m "feat(theme): add ThemeMode enum and pure resolveDarkTheme helper"
```

---

## Task 2: Persist `themeMode` in SettingsRepository

**Files:**
- Modify: `app/src/main/java/com/androdr/data/repo/SettingsRepository.kt`
- Test: `app/src/test/java/com/androdr/data/repo/SettingsRepositoryThemeModeTest.kt`

- [ ] **Step 1: Write the failing test**

Create `app/src/test/java/com/androdr/data/repo/SettingsRepositoryThemeModeTest.kt`:

```kotlin
package com.androdr.data.repo

import androidx.datastore.core.DataStore
import androidx.datastore.preferences.core.Preferences
import androidx.datastore.preferences.core.PreferenceDataStoreFactory
import com.androdr.ui.theme.ThemeMode
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import java.io.File

class SettingsRepositoryThemeModeTest {

    @get:Rule val tmp = TemporaryFolder()

    private lateinit var dataStore: DataStore<Preferences>
    private lateinit var repo: SettingsRepository
    private lateinit var prefsFile: File

    @Before
    fun setUp() {
        prefsFile = tmp.newFile("test_prefs.preferences_pb")
        dataStore = PreferenceDataStoreFactory.create(produceFile = { prefsFile })
        repo = SettingsRepository(dataStore)
    }

    @After
    fun tearDown() {
        prefsFile.delete()
    }

    @Test
    fun `default themeMode is AUTO`() = runBlocking {
        assertEquals(ThemeMode.AUTO, repo.themeMode.first())
    }

    @Test
    fun `setThemeMode round-trips LIGHT`() = runBlocking {
        repo.setThemeMode(ThemeMode.LIGHT)
        assertEquals(ThemeMode.LIGHT, repo.themeMode.first())
    }

    @Test
    fun `setThemeMode round-trips DARK`() = runBlocking {
        repo.setThemeMode(ThemeMode.DARK)
        assertEquals(ThemeMode.DARK, repo.themeMode.first())
    }

    @Test
    fun `setThemeMode round-trips back to AUTO`() = runBlocking {
        repo.setThemeMode(ThemeMode.DARK)
        repo.setThemeMode(ThemeMode.AUTO)
        assertEquals(ThemeMode.AUTO, repo.themeMode.first())
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `./gradlew :app:testDebugUnitTest --tests "com.androdr.data.repo.SettingsRepositoryThemeModeTest"`
Expected: FAIL (unresolved reference `themeMode` / `setThemeMode`).

- [ ] **Step 3: Add `themeMode` to SettingsRepository**

In `app/src/main/java/com/androdr/data/repo/SettingsRepository.kt`:

Add to the imports block (alphabetical):

```kotlin
import com.androdr.ui.theme.ThemeMode
```

Add inside the class body, after the `domainIocBlockMode` block (around line 30):

```kotlin
val themeMode: Flow<ThemeMode> = dataStore.data
    .map { prefs ->
        when (prefs[KEY_THEME_MODE]) {
            "LIGHT" -> ThemeMode.LIGHT
            "DARK"  -> ThemeMode.DARK
            else    -> ThemeMode.AUTO
        }
    }

suspend fun setThemeMode(mode: ThemeMode) {
    dataStore.edit { it[KEY_THEME_MODE] = mode.name }
}
```

Add to the `companion object` (around line 102):

```kotlin
private val KEY_THEME_MODE = stringPreferencesKey("theme_mode")
```

- [ ] **Step 4: Run test to verify it passes**

Run: `./gradlew :app:testDebugUnitTest --tests "com.androdr.data.repo.SettingsRepositoryThemeModeTest"`
Expected: PASS (4/4).

- [ ] **Step 5: Commit**

```bash
git add app/src/main/java/com/androdr/data/repo/SettingsRepository.kt \
        app/src/test/java/com/androdr/data/repo/SettingsRepositoryThemeModeTest.kt
git commit -m "feat(settings): persist ThemeMode preference in DataStore"
```

---

## Task 3: ExtendedColors data class + CompositionLocal

**Files:**
- Create: `app/src/main/java/com/androdr/ui/theme/ExtendedColors.kt`

- [ ] **Step 1: Create the file**

Create `app/src/main/java/com/androdr/ui/theme/ExtendedColors.kt`:

```kotlin
package com.androdr.ui.theme

import androidx.compose.material3.MaterialTheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.ReadOnlyComposable
import androidx.compose.runtime.staticCompositionLocalOf
import androidx.compose.ui.graphics.Color

/**
 * App-specific semantic colors that Material 3's ColorScheme does not cover:
 * the four severity tiers and their tinted backgrounds. Two instances exist —
 * one for dark, one for light — and AndroDRTheme provides the right one via
 * LocalAndroDRColors. Access through MaterialTheme.androdrColors.
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

val DarkExtendedColors = ExtendedColors(
    critical          = Color(0xFFCF6679),
    high              = Color(0xFFFF9800),
    medium            = Color(0xFFE6A800),
    low               = Color(0xFF64B5F6),
    neutral           = TealPrimary,
    criticalContainer = Color(0x33CF6679),
    highContainer     = Color(0x33FF9800),
    mediumContainer   = Color(0x33E6A800),
    lowContainer      = Color(0x3364B5F6),
)

val LightExtendedColors = ExtendedColors(
    critical          = Color(0xFFB3261E),
    high              = Color(0xFFC25700),
    medium            = Color(0xFF8B6B00),
    low               = Color(0xFF1565C0),
    neutral           = TealPrimaryVariant,
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
```

- [ ] **Step 2: Verify it compiles**

Run: `./gradlew :app:compileDebugKotlin`
Expected: BUILD SUCCESSFUL. Compilation errors here mean either `TealPrimary` / `TealPrimaryVariant` aren't visible (they're top-level in `Theme.kt` already, in the same package, so this should just work) or a typo in an import.

- [ ] **Step 3: Commit**

```bash
git add app/src/main/java/com/androdr/ui/theme/ExtendedColors.kt
git commit -m "feat(theme): add ExtendedColors data class with dark+light severity palettes"
```

---

## Task 4: WCAG AA contrast test for ExtendedColors

**Files:**
- Test: `app/src/test/java/com/androdr/ui/theme/ExtendedColorsContrastTest.kt`

- [ ] **Step 1: Write the failing test**

Create `app/src/test/java/com/androdr/ui/theme/ExtendedColorsContrastTest.kt`:

```kotlin
package com.androdr.ui.theme

import androidx.compose.ui.graphics.Color
import org.junit.Assert.assertTrue
import org.junit.Test

private const val WCAG_AA_LARGE_TEXT_AND_UI = 3.0
private const val WCAG_AA_NORMAL_TEXT = 4.5

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

    private fun assertAaUi(name: String, fg: Color, bg: Color) {
        val ratio = contrastRatio(fg, bg)
        assertTrue(
            "$name (${fg.toHex()}) on (${bg.toHex()}) contrast $ratio < $WCAG_AA_LARGE_TEXT_AND_UI",
            ratio >= WCAG_AA_LARGE_TEXT_AND_UI
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
```

- [ ] **Step 2: Run the test**

Run: `./gradlew :app:testDebugUnitTest --tests "com.androdr.ui.theme.ExtendedColorsContrastTest"`
Expected: PASS (2/2). If a specific color fails, the failure message tells you which one — adjust its value in `ExtendedColors.kt` and re-run until all pass.

Note: The threshold is the WCAG AA UI-component / large-text threshold (3.0). Severity chips and pill backgrounds are UI components, not body text. If you want body-text-strength contrast (4.5), bump the constant — but be aware that some hues (orange in particular) struggle to hit 4.5 on white without going brown.

- [ ] **Step 3: Commit**

```bash
git add app/src/test/java/com/androdr/ui/theme/ExtendedColorsContrastTest.kt
git commit -m "test(theme): assert ExtendedColors meet WCAG AA contrast on both schemes"
```

---

## Task 5: Add `LightColorScheme` to Theme.kt

**Files:**
- Modify: `app/src/main/java/com/androdr/ui/theme/Theme.kt`

- [ ] **Step 1: Add the imports and new scheme**

In `app/src/main/java/com/androdr/ui/theme/Theme.kt`:

Add to imports (alphabetical):

```kotlin
import androidx.compose.material3.lightColorScheme
```

Add immediately after the existing `private val DarkColorScheme = …` block (before the `@Composable fun AndroDRTheme` line, around line 53):

```kotlin
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
```

- [ ] **Step 2: Verify it compiles**

Run: `./gradlew :app:compileDebugKotlin`
Expected: BUILD SUCCESSFUL.

- [ ] **Step 3: Commit**

```bash
git add app/src/main/java/com/androdr/ui/theme/Theme.kt
git commit -m "feat(theme): add LightColorScheme palette"
```

---

## Task 6: Refactor `AndroDRTheme` to accept ThemeMode and provide ExtendedColors

**Files:**
- Modify: `app/src/main/java/com/androdr/ui/theme/Theme.kt`

- [ ] **Step 1: Refactor the AndroDRTheme composable**

In `app/src/main/java/com/androdr/ui/theme/Theme.kt`:

Add to imports:

```kotlin
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.runtime.CompositionLocalProvider
```

Replace the existing `AndroDRTheme` composable (lines 55-61 approximately) with:

```kotlin
@Composable
fun AndroDRTheme(
    themeMode: ThemeMode = ThemeMode.AUTO,
    content: @Composable () -> Unit
) {
    val useDarkTheme = resolveDarkTheme(themeMode, systemInDark = isSystemInDarkTheme())
    val colorScheme    = if (useDarkTheme) DarkColorScheme   else LightColorScheme
    val extendedColors = if (useDarkTheme) DarkExtendedColors else LightExtendedColors

    CompositionLocalProvider(LocalAndroDRColors provides extendedColors) {
        MaterialTheme(
            colorScheme = colorScheme,
            content = content
        )
    }
}
```

- [ ] **Step 2: Verify it compiles and existing usages still build**

Run: `./gradlew :app:compileDebugKotlin`
Expected: BUILD SUCCESSFUL. Existing call sites (`AndroDRTheme { … }`) keep working because `themeMode` has a default value.

- [ ] **Step 3: Commit**

```bash
git add app/src/main/java/com/androdr/ui/theme/Theme.kt
git commit -m "feat(theme): wire AndroDRTheme to ThemeMode + provide ExtendedColors"
```

---

## Task 7: Expose themeMode on SettingsViewModel

**Files:**
- Modify: `app/src/main/java/com/androdr/ui/settings/SettingsViewModel.kt`

- [ ] **Step 1: Add the StateFlow and setter**

In `app/src/main/java/com/androdr/ui/settings/SettingsViewModel.kt`:

Add to imports (alphabetical, after the existing `com.androdr.…` block):

```kotlin
import com.androdr.ui.theme.ThemeMode
```

Add inside the class body, immediately after the existing `domainIocBlockMode` declaration (around line 67):

```kotlin
val themeMode = settingsRepository.themeMode
    .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5_000), ThemeMode.AUTO)

fun setThemeMode(mode: ThemeMode) {
    viewModelScope.launch { settingsRepository.setThemeMode(mode) }
}
```

- [ ] **Step 2: Verify it compiles**

Run: `./gradlew :app:compileDebugKotlin`
Expected: BUILD SUCCESSFUL.

- [ ] **Step 3: Commit**

```bash
git add app/src/main/java/com/androdr/ui/settings/SettingsViewModel.kt
git commit -m "feat(settings-vm): expose themeMode StateFlow and setter"
```

---

## Task 8: Add "Appearance" section to SettingsScreen

**Files:**
- Modify: `app/src/main/java/com/androdr/ui/settings/SettingsScreen.kt`

- [ ] **Step 1: Add imports**

In `app/src/main/java/com/androdr/ui/settings/SettingsScreen.kt`:

Add to imports (alphabetical):

```kotlin
import androidx.compose.material3.SegmentedButton
import androidx.compose.material3.SegmentedButtonDefaults
import androidx.compose.material3.SingleChoiceSegmentedButtonRow
import com.androdr.ui.theme.ThemeMode
```

- [ ] **Step 2: Collect the state**

Inside `fun SettingsScreen(...)`, after the existing `val customRuleUrls by …` line (around line 49), add:

```kotlin
val themeMode by viewModel.themeMode.collectAsStateWithLifecycle()
```

- [ ] **Step 3: Insert the Appearance section**

Inside the `Column { … }` body, **immediately after** the headline `Text("Settings", …)` block (around line 125, before the `Text("DNS Blocklist", …)` line), insert:

```kotlin
Text(
    text = "Appearance",
    style = MaterialTheme.typography.titleMedium,
    modifier = Modifier.padding(top = 16.dp)
)
Text(
    text = "Choose how AndroDR adapts to your system theme.",
    style = MaterialTheme.typography.bodySmall,
    color = MaterialTheme.colorScheme.onSurfaceVariant
)
ThemeModePicker(
    selected = themeMode,
    onSelect = { viewModel.setThemeMode(it) }
)
HorizontalDivider(modifier = Modifier.padding(vertical = 8.dp))
```

- [ ] **Step 4: Add the picker composable**

At the bottom of the file (after `UpdateStatusRow`, around line 429), add:

```kotlin
@Composable
private fun ThemeModePicker(
    selected: ThemeMode,
    onSelect: (ThemeMode) -> Unit
) {
    val options = listOf(
        ThemeMode.AUTO  to "System",
        ThemeMode.LIGHT to "Light",
        ThemeMode.DARK  to "Dark"
    )
    SingleChoiceSegmentedButtonRow(modifier = Modifier.fillMaxWidth()) {
        options.forEachIndexed { index, (mode, label) ->
            SegmentedButton(
                selected = selected == mode,
                onClick  = { onSelect(mode) },
                shape    = SegmentedButtonDefaults.itemShape(index = index, count = options.size)
            ) {
                Text(label)
            }
        }
    }
}
```

- [ ] **Step 5: Verify it compiles**

Run: `./gradlew :app:compileDebugKotlin`
Expected: BUILD SUCCESSFUL.

- [ ] **Step 6: Commit**

```bash
git add app/src/main/java/com/androdr/ui/settings/SettingsScreen.kt
git commit -m "feat(settings-ui): add Appearance section with System/Light/Dark picker"
```

---

## Task 9: Wire themeMode in MainActivity + drive system bars from Compose

**Files:**
- Modify: `app/src/main/java/com/androdr/MainActivity.kt`

- [ ] **Step 1: Add imports**

In `app/src/main/java/com/androdr/MainActivity.kt`:

Add to imports (alphabetical):

```kotlin
import androidx.compose.material3.MaterialTheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.SideEffect
import androidx.compose.runtime.getValue
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.toArgb
import androidx.compose.ui.platform.LocalView
import androidx.core.view.WindowCompat
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.androdr.data.repo.SettingsRepository
import com.androdr.ui.theme.ThemeMode
import javax.inject.Inject
```

- [ ] **Step 2: Inject SettingsRepository and collect themeMode**

Replace the existing `MainActivity` class (lines 45-56) with:

```kotlin
@AndroidEntryPoint
class MainActivity : ComponentActivity() {

    @Inject lateinit var settingsRepository: SettingsRepository

    override fun onCreate(savedInstanceState: android.os.Bundle?) {
        super.onCreate(savedInstanceState)
        WindowCompat.setDecorFitsSystemWindows(window, true)
        setContent {
            val themeMode by settingsRepository.themeMode
                .collectAsStateWithLifecycle(initialValue = ThemeMode.AUTO)
            AndroDRTheme(themeMode = themeMode) {
                SystemBarsEffect()
                AndroDRApp()
            }
        }
    }
}

@Composable
private fun SystemBarsEffect() {
    val view = LocalView.current
    val surface = MaterialTheme.colorScheme.surface
    val surfaceArgb = surface.toArgb()
    // Drive icon brightness from the actual surface luminance — this is the only
    // truthful signal when the user has forced LIGHT on a system-dark device (or
    // vice versa). isSystemInDarkTheme() lies in that case.
    val barsLookDark = surface.computeLuminance() < 0.5f
    if (!view.isInEditMode) {
        SideEffect {
            val window = (view.context as android.app.Activity).window
            window.statusBarColor = surfaceArgb
            window.navigationBarColor = surfaceArgb
            WindowCompat.getInsetsController(window, view).apply {
                isAppearanceLightStatusBars = !barsLookDark
                isAppearanceLightNavigationBars = !barsLookDark
            }
        }
    }
}

private fun Color.computeLuminance(): Float =
    0.2126f * red + 0.7152f * green + 0.0722f * blue
```

Note: `computeLuminance` is a local extension (named to avoid shadowing Compose's built-in `Color.luminance()` on some versions). The check uses `MaterialTheme.colorScheme.surface` directly — the only truthful signal when the user has forced LIGHT on a system-dark device or vice versa.

- [ ] **Step 3: Build the debug APK**

Run: `./gradlew assembleDebug`
Expected: BUILD SUCCESSFUL. If `@Inject lateinit var` fails Hilt validation, confirm `SettingsRepository` is `@Singleton` (it already is in `data/repo/SettingsRepository.kt:20`) and that `MainActivity` already has `@AndroidEntryPoint` (it does).

- [ ] **Step 4: Commit**

```bash
git add app/src/main/java/com/androdr/MainActivity.kt
git commit -m "feat(main): inject SettingsRepository, drive theme + system bars from Compose"
```

---

## Task 10: Update Activity theme XML for OEM hardening

**Files:**
- Modify: `app/src/main/res/values/themes.xml`

- [ ] **Step 1: Rewrite themes.xml**

Replace the entire content of `app/src/main/res/values/themes.xml` with:

```xml
<?xml version="1.0" encoding="utf-8"?>
<resources xmlns:tools="http://schemas.android.com/tools">
    <style name="Theme.AndroDR" parent="Theme.AppCompat.DayNight.NoActionBar">
        <item name="android:forceDarkAllowed" tools:targetApi="29">false</item>
        <item name="android:windowBackground">@android:color/transparent</item>
    </style>
</resources>
```

Changes vs. the previous version:
- Parent switched to `Theme.AppCompat.DayNight.NoActionBar` so the Activity's base resources flip light/dark with the OS (Compose still owns the actual paint, but this keeps any non-Compose AppCompat widgets sane).
- Hardcoded `statusBarColor` / `navigationBarColor` removed — `MainActivity.SystemBarsEffect` now sets these at runtime to track the Compose surface color.
- `android:forceDarkAllowed="false"` added — blocks Honor MagicOS (and any other OEM force-dark / force-light) from overriding the app's intent. `tools:targetApi` suppresses lint on pre-API-29 where the attribute is ignored anyway.
- `windowBackground` set to transparent so there is no flash of the Activity theme's default color before Compose draws.

- [ ] **Step 2: Build the debug APK**

Run: `./gradlew assembleDebug`
Expected: BUILD SUCCESSFUL. If lint fails on `forceDarkAllowed` despite the `tools:targetApi`, add a baseline ignore or downgrade the lint rule — the attribute is genuinely safe on pre-29 (no-op).

- [ ] **Step 3: Commit**

```bash
git add app/src/main/res/values/themes.xml
git commit -m "fix(theme): drop hardcoded bar colors, disable forceDark, switch to DayNight parent"
```

---

## Task 11: Migrate `SeverityChip.kt` to ExtendedColors

**Files:**
- Modify: `app/src/main/java/com/androdr/ui/common/SeverityChip.kt`

- [ ] **Step 1: Read the current file**

Open `app/src/main/java/com/androdr/ui/common/SeverityChip.kt` and identify every `Color(0xFF…)` literal. Expected (from initial grep): four severity colors at lines 14-17 (inside `severityColor()`), a grey at line 19, and a duplicate set at lines 37-40.

- [ ] **Step 2: Replace literals with ExtendedColors lookups**

Inside `SeverityChip.kt`:

- Add to imports:
  ```kotlin
  import androidx.compose.material3.MaterialTheme
  import com.androdr.ui.theme.androdrColors
  ```
  (Remove `import androidx.compose.ui.graphics.Color` only if no `Color(...)` remains after migration. Keep it otherwise.)

- For the `severityColor` function (around line 13):
  ```kotlin
  @Composable
  private fun severityColor(level: String): Color {
      val colors = MaterialTheme.androdrColors
      return when (level.lowercase()) {
          "critical" -> colors.critical
          "high"     -> colors.high
          "medium"   -> colors.medium
          else       -> colors.neutral
      }
  }
  ```
  (Note: if the original used `else -> Color(0xFF00D4AA)` for "low" plus catch-all, prefer the explicit `"low" -> colors.low` branch and keep `else -> colors.neutral` separately. Inspect the actual file to keep the existing branch semantics — the rule is *one severity in, the matching ExtendedColors field out*.)

- For the disabled-grey `Color(0xFF888888)` at line 19:
  ```kotlin
  val color = if (active) severityColor(level) else MaterialTheme.colorScheme.onSurface.copy(alpha = 0.38f)
  ```

- For the duplicate switch at lines 37-40, mirror the same lookup pattern (likely another `severityColor`-style function — apply the same replacement).

- [ ] **Step 3: Verify it compiles**

Run: `./gradlew :app:compileDebugKotlin`
Expected: BUILD SUCCESSFUL.

- [ ] **Step 4: Commit**

```bash
git add app/src/main/java/com/androdr/ui/common/SeverityChip.kt
git commit -m "refactor(ui): SeverityChip uses MaterialTheme.androdrColors"
```

---

## Task 12: Migrate `FindingCard.kt` to ExtendedColors

**Files:**
- Modify: `app/src/main/java/com/androdr/ui/common/FindingCard.kt`

- [ ] **Step 1: Locate the literals**

Open `app/src/main/java/com/androdr/ui/common/FindingCard.kt`. Expected (from initial grep): `Color(0xFFCF6679).copy(alpha = 0.08f)` at line 42 (background), `Color(0xFFCF6679)` at line 54 (icon tint). The `MaterialTheme.colorScheme.primary` branch at line 54 stays as-is.

- [ ] **Step 2: Replace**

Add to imports:

```kotlin
import com.androdr.ui.theme.androdrColors
```

(`MaterialTheme` is already imported.)

Change the card background pattern (around line 42):

```kotlin
containerColor = if (finding.triggered) MaterialTheme.androdrColors.criticalContainer
                 else MaterialTheme.colorScheme.surfaceContainer
```

Change the icon tint (around line 54):

```kotlin
tint = if (finding.triggered) MaterialTheme.androdrColors.critical
       else MaterialTheme.colorScheme.primary
```

- [ ] **Step 3: Verify it compiles**

Run: `./gradlew :app:compileDebugKotlin`
Expected: BUILD SUCCESSFUL.

- [ ] **Step 4: Commit**

```bash
git add app/src/main/java/com/androdr/ui/common/FindingCard.kt
git commit -m "refactor(ui): FindingCard uses MaterialTheme.androdrColors"
```

---

## Task 13: Migrate `EvidenceSheet.kt` to ExtendedColors

**Files:**
- Modify: `app/src/main/java/com/androdr/ui/common/EvidenceSheet.kt`

- [ ] **Step 1: Locate the literals**

Open `app/src/main/java/com/androdr/ui/common/EvidenceSheet.kt`. Expected (from initial grep): `Color(0xFFCF6679)` at lines 108, 158 (alpha 0.06), 205 (container alpha 0.2), 206 (label), 261; `Color(0xFFFF9800)` at lines 281 (container alpha 0.15), 282 (label).

- [ ] **Step 2: Replace**

Add to imports:

```kotlin
import com.androdr.ui.theme.androdrColors
```

Apply this mapping throughout the file:

| Old expression                                  | New expression                                     |
|-------------------------------------------------|----------------------------------------------------|
| `Color(0xFFCF6679)`                             | `MaterialTheme.androdrColors.critical`             |
| `Color(0xFFCF6679).copy(alpha = 0.06f)` or `0.08f` | `MaterialTheme.androdrColors.criticalContainer` (container hex already encodes the right tint) |
| `Color(0xFFCF6679).copy(alpha = 0.2f)`          | `MaterialTheme.androdrColors.criticalContainer`    |
| `Color(0xFFFF9800)`                             | `MaterialTheme.androdrColors.high`                 |
| `Color(0xFFFF9800).copy(alpha = 0.15f)`         | `MaterialTheme.androdrColors.highContainer`        |

Walk the file top-to-bottom and apply each replacement at every site.

- [ ] **Step 3: Verify it compiles**

Run: `./gradlew :app:compileDebugKotlin`
Expected: BUILD SUCCESSFUL.

- [ ] **Step 4: Commit**

```bash
git add app/src/main/java/com/androdr/ui/common/EvidenceSheet.kt
git commit -m "refactor(ui): EvidenceSheet uses MaterialTheme.androdrColors"
```

---

## Task 14: Migrate `TimelineEventCard.kt` to ExtendedColors

**Files:**
- Modify: `app/src/main/java/com/androdr/ui/timeline/TimelineEventCard.kt`

- [ ] **Step 1: Locate the literals**

Open `app/src/main/java/com/androdr/ui/timeline/TimelineEventCard.kt`. Expected (from initial grep): line 68 (`neutralColor = 0xFF00D4AA`), line 100 (CritRed tag), lines 206-209 (severity switch CRITICAL/HIGH/MEDIUM/LOW), lines 373-375 (correlation pattern colors).

- [ ] **Step 2: Replace**

Add to imports:

```kotlin
import androidx.compose.runtime.Composable
import com.androdr.ui.theme.androdrColors
```

(`MaterialTheme` and `Composable` may already be imported — skip if so.)

For the `neutralColor` at line 68: it's inside a Composable, so swap to a Composable-context read. If the variable is declared at top-of-Composable, change:

```kotlin
val neutralColor = MaterialTheme.androdrColors.neutral
```

For the tag chip at line 100 (`TagChip(event.campaignName, Color(0xFFCF6679))`): pull the color first then pass it:

```kotlin
val criticalColor = MaterialTheme.androdrColors.critical
…
if (event.campaignName.isNotEmpty()) TagChip(event.campaignName, criticalColor)
```

For the severity switch around lines 206-209 — convert the function to a `@Composable` (if not already) and replace:

```kotlin
@Composable
private fun severityToColor(severity: String): Color {
    val colors = MaterialTheme.androdrColors
    return when (severity.uppercase()) {
        "CRITICAL" -> colors.critical
        "HIGH"     -> colors.high
        "MEDIUM"   -> colors.medium
        "LOW"      -> colors.low
        else       -> colors.neutral
    }
}
```

For correlation pattern colors at lines 373-375:

```kotlin
@Composable
private fun correlationPatternColor(pattern: CorrelationPattern): Color {
    val colors = MaterialTheme.androdrColors
    return when (pattern) {
        CorrelationPattern.INSTALL_THEN_ADMIN       -> colors.critical
        CorrelationPattern.MULTI_PERMISSION_BURST   -> colors.high
        else                                        -> colors.neutral
    }
}
```

For the one-off `Color(0xFFFF8A65)` at line 207 (deep orange 300): replaced by `colors.high` in the severity switch above.

- [ ] **Step 3: Verify it compiles**

Run: `./gradlew :app:compileDebugKotlin`
Expected: BUILD SUCCESSFUL. If you converted a non-Composable function to `@Composable`, any caller that wasn't already inside a Composable scope must be moved into one. The whole timeline UI is Composable-only, so this should hold.

- [ ] **Step 4: Commit**

```bash
git add app/src/main/java/com/androdr/ui/timeline/TimelineEventCard.kt
git commit -m "refactor(ui): TimelineEventCard uses MaterialTheme.androdrColors"
```

---

## Task 15: Migrate `DnsMonitorScreen.kt` to ExtendedColors

**Files:**
- Modify: `app/src/main/java/com/androdr/ui/network/DnsMonitorScreen.kt`

- [ ] **Step 1: Locate the literals**

Open `app/src/main/java/com/androdr/ui/network/DnsMonitorScreen.kt`. Expected (from initial grep): lines 258 (container alpha 0.08), 273 (label), 302 (container alpha 0.2), 305 (label).

- [ ] **Step 2: Replace**

Add to imports:

```kotlin
import com.androdr.ui.theme.androdrColors
```

Apply:

| Old expression                                  | New expression                                  |
|-------------------------------------------------|-------------------------------------------------|
| `Color(0xFFCF6679)`                             | `MaterialTheme.androdrColors.critical`          |
| `Color(0xFFCF6679).copy(alpha = 0.08f)` / `0.2f` | `MaterialTheme.androdrColors.criticalContainer` |

- [ ] **Step 3: Verify it compiles**

Run: `./gradlew :app:compileDebugKotlin`
Expected: BUILD SUCCESSFUL.

- [ ] **Step 4: Commit**

```bash
git add app/src/main/java/com/androdr/ui/network/DnsMonitorScreen.kt
git commit -m "refactor(ui): DnsMonitorScreen uses MaterialTheme.androdrColors"
```

---

## Task 16: Add the hardcoded-color drift guard test

**Files:**
- Test: `app/src/test/java/com/androdr/ui/theme/HardcodedColorGuardTest.kt`

- [ ] **Step 1: Write the test**

Create `app/src/test/java/com/androdr/ui/theme/HardcodedColorGuardTest.kt`:

```kotlin
package com.androdr.ui.theme

import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/**
 * Guards against re-introducing hardcoded Color(0xFF…) literals in UI code.
 * The only allowed locations for raw color values are inside ui/theme/.
 * If you need a new semantic color, add it to ExtendedColors instead.
 *
 * Suppress per-line with: // hardcoded-color-ok: <reason>
 */
class HardcodedColorGuardTest {

    @Test
    fun `no hardcoded Color(0xFF…) literals outside ui-theme package`() {
        val sourceRoot = findSourceRoot()
        val pattern = Regex("""Color\(0x[0-9A-Fa-f]{8}\)""")
        val allowMarker = "hardcoded-color-ok"

        val offenders = sourceRoot.walkTopDown()
            .filter { it.isFile && it.extension == "kt" }
            .filterNot { it.path.replace('\\', '/').contains("/ui/theme/") }
            .flatMap { file ->
                file.readLines().mapIndexedNotNull { idx, line ->
                    if (pattern.containsMatchIn(line) && !line.contains(allowMarker)) {
                        "${file.relativeTo(sourceRoot)}:${idx + 1}  $line"
                    } else null
                }
            }
            .toList()

        assertTrue(
            "Hardcoded Color(0xFF…) literals found outside ui/theme/.\n" +
                "Move the color to ExtendedColors, or append `// hardcoded-color-ok: <reason>` " +
                "to the line if it is genuinely a one-off (debug overlay, preview fixture, etc.):\n" +
                offenders.joinToString("\n"),
            offenders.isEmpty()
        )
    }

    private fun findSourceRoot(): File {
        // Tests can run from either the repo root or the app module dir. Try both.
        val candidates = listOf(
            File("src/main/java/com/androdr"),
            File("app/src/main/java/com/androdr")
        )
        return candidates.firstOrNull { it.exists() }
            ?: error("Could not locate source root from ${File(".").absolutePath}")
    }
}
```

- [ ] **Step 2: Run the test**

Run: `./gradlew :app:testDebugUnitTest --tests "com.androdr.ui.theme.HardcodedColorGuardTest"`
Expected: PASS. If it FAILS, the failure message lists every remaining `Color(0xFF…)` literal — either migrate the listed sites to `ExtendedColors`, or add a `// hardcoded-color-ok: <reason>` marker on lines that genuinely belong outside the theme (uncommon — most likely the case is "I forgot to migrate one file").

- [ ] **Step 3: Commit**

```bash
git add app/src/test/java/com/androdr/ui/theme/HardcodedColorGuardTest.kt
git commit -m "test(theme): guard against hardcoded Color(0xFF…) literals outside ui/theme"
```

---

## Task 17: Add Compose previews for migrated severity-coded UI

**Files:**
- Modify: `app/src/main/java/com/androdr/ui/common/SeverityChip.kt`
- Modify: `app/src/main/java/com/androdr/ui/common/FindingCard.kt`
- Modify: `app/src/main/java/com/androdr/ui/common/EvidenceSheet.kt`
- Modify: `app/src/main/java/com/androdr/ui/timeline/TimelineEventCard.kt`

- [ ] **Step 1: Add a preview helper at the bottom of `SeverityChip.kt`**

Append to `app/src/main/java/com/androdr/ui/common/SeverityChip.kt`:

```kotlin
@androidx.compose.ui.tooling.preview.Preview(
    name = "Severity chips — Dark",
    uiMode = android.content.res.Configuration.UI_MODE_NIGHT_YES
)
@androidx.compose.ui.tooling.preview.Preview(
    name = "Severity chips — Light",
    uiMode = android.content.res.Configuration.UI_MODE_NIGHT_NO
)
@Composable
private fun SeverityChipPreview() {
    com.androdr.ui.theme.AndroDRTheme(themeMode = com.androdr.ui.theme.ThemeMode.AUTO) {
        androidx.compose.foundation.layout.Surface(
            color = MaterialTheme.colorScheme.background
        ) {
            androidx.compose.foundation.layout.Row(
                modifier = androidx.compose.ui.Modifier
                    .padding(androidx.compose.ui.unit.dp.let { 16.dp }),
                horizontalArrangement = androidx.compose.foundation.layout.Arrangement.spacedBy(8.dp)
            ) {
                listOf("critical", "high", "medium", "low").forEach { level ->
                    SeverityChip(level = level)
                }
            }
        }
    }
}
```

(Adjust the `SeverityChip(...)` call to match the file's actual public API — if it takes more parameters, supply sensible defaults. The point is one composable preview per severity, in both themes.)

- [ ] **Step 2: Do the same for `FindingCard.kt`, `EvidenceSheet.kt`, `TimelineEventCard.kt`**

For each file: add two `@Preview` annotations (Dark/Light) wrapping the public composable with mock data. The previews exist for the implementer and for visual review during PR — not for asserting in CI.

If supplying mock data for `FindingCard` / `EvidenceSheet` / `TimelineEventCard` is more work than the value of the preview, **skip that specific preview** with a `// TODO(post-merge): add preview once Finding/Event factories are extracted` and mention it in the PR description. Don't block this task on building large fixture builders.

- [ ] **Step 3: Verify Android Studio renders the previews**

Run: `./gradlew :app:compileDebugKotlin`
Expected: BUILD SUCCESSFUL. Open the migrated files in Android Studio and confirm the previews render in both Dark and Light modes without contrast issues.

- [ ] **Step 4: Commit**

```bash
git add app/src/main/java/com/androdr/ui/common/SeverityChip.kt \
        app/src/main/java/com/androdr/ui/common/FindingCard.kt \
        app/src/main/java/com/androdr/ui/common/EvidenceSheet.kt \
        app/src/main/java/com/androdr/ui/timeline/TimelineEventCard.kt
git commit -m "test(ui): add light+dark previews for migrated severity-coded composables"
```

---

## Task 18: Final verification — full test suite, lint, smoke

**Files:** none modified.

- [ ] **Step 1: Run the full unit test suite**

Run: `./gradlew :app:testDebugUnitTest`
Expected: ALL TESTS PASS. If a pre-existing test breaks, investigate — but unrelated breakage is not part of this plan's scope. Theme-related failures should not occur if previous tasks passed.

- [ ] **Step 2: Run lint**

Run: `./gradlew lintDebug`
Expected: No NEW errors introduced. Warnings about `android:forceDarkAllowed` requiring API 29 should be suppressed by the `tools:targetApi` attribute added in Task 10. If a true error remains, fix at the source.

- [ ] **Step 3: Build the release APK to confirm shrinker/proguard don't break**

Run: `./gradlew assembleRelease`
Expected: BUILD SUCCESSFUL. If R8 strips a Composable preview unexpectedly, that's fine — previews are dev-only. If R8 strips something real, add the necessary keep rule.

- [ ] **Step 4: Smoke test on emulator**

Run the existing script:
```bash
./scripts/smoke-test.sh
```
Expected: APK installs, app launches, logcat is crash-free. Then manually:
1. Open Settings on the emulator's system, toggle dark mode off → confirm AndroDR follows to light mode within seconds.
2. In AndroDR Settings → Appearance, switch to "Dark" → confirm app forces dark regardless of system.
3. Switch to "Light" → confirm app forces light.
4. Switch to "System" → confirm app re-follows the system setting.
5. Open Dashboard, Apps, Network, Timeline screens in both modes — visually confirm severity chips and finding cards are legible.

- [ ] **Step 5: Manual smoke on Honor device (if available)**

If the tester's Honor device is available, re-test the exact screen where text was reported invisible. Confirm legibility in both system-light and system-dark modes. Capture screenshots for the PR description.

If no Honor device is available: explicitly note "Honor re-test pending — relies on tester verification post-merge" in the PR description. Do not claim the bug fixed without device confirmation.

- [ ] **Step 6: No commit (verification only)**

This task produces no commits. Output goes into the PR description.

---

## Self-Review Notes

Run through the plan once more before handoff:

- **Spec coverage:** every spec section maps to at least one task — ThemeMode (T1), persistence (T2), ExtendedColors (T3), contrast test (T4), light scheme (T5), AndroDRTheme refactor (T6), Settings VM+UI (T7-T8), MainActivity wiring + system bars (T9), manifest hardening (T10), the 5 migration files (T11-T15), drift guard (T16), previews (T17), full verification (T18). Out-of-scope items (dynamic color, androdr-015 FP) remain out.
- **Type consistency:** `ThemeMode` (enum), `resolveDarkTheme(themeMode, systemInDark): Boolean`, `ExtendedColors` (data class), `LocalAndroDRColors`, `MaterialTheme.androdrColors`, `settingsRepository.themeMode` / `setThemeMode(mode)`, `KEY_THEME_MODE` — all referenced consistently across tasks.
- **No placeholders:** every step has either runnable code, an exact command, or a discrete edit instruction with the actual code shown.
- **Out-of-order safety:** each task's "Files" / "Step 1" lists what it touches, so a worker resuming from any task has the context needed without reading earlier tasks.

---

**Plan complete and saved to `docs/superpowers/plans/2026-05-18-light-dark-theme.md`. Two execution options:**

**1. Subagent-Driven (recommended)** — I dispatch a fresh subagent per task, review between tasks, fast iteration.

**2. Inline Execution** — Execute tasks in this session using executing-plans, batch execution with checkpoints.

**Which approach?**
