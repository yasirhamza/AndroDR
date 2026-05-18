# Light/Dark Theme Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make AndroDR's UI legible on every Android device by introducing a light color scheme that follows the OS setting, a user override (Auto/Light/Dark), a semantic-color layer, and migration of all hardcoded color literals. Fixes the tester-reported invisible-text bug on Honor MagicOS.

**Architecture:** A new `ThemeMode` enum is persisted in `SettingsRepository` (DataStore). `AndroDRTheme` resolves it against `isSystemInDarkTheme()` and provides both a Material 3 `ColorScheme` and an app-specific `ExtendedColors` (severity hues, alert backgrounds) via `CompositionLocal`. The Activity theme drops hardcoded system-bar colors and `forceDarkAllowed` is disabled to stop OEM overrides. Nine UI files migrate from hardcoded `Color(0xFF…)` literals to `MaterialTheme.androdrColors.*`, and a unit test guards against regression.

**Key idiom — `severityColor(level, colors)`:** The existing top-level `fun severityColor(level: String): Color` in `SeverityChip.kt` has many non-Composable callers (`AppScanScreen.kt`, `HistoryScreen.kt`, etc.). Rather than convert it to `@Composable` and cascade that requirement, we **add a `colors: ExtendedColors` parameter** so call sites pass the palette in. Composable callers read it from `MaterialTheme.androdrColors`; the function itself stays non-Composable.

**Drift-guard idiom — `.copy(alpha = …)`:** The drift-guard test only catches raw `Color(0xFF…)` literals. Sub-percent tints like the `0.06f`/`0.08f`/`0.15f` washes in `EvidenceSheet` / `DashboardScreen` are migrated to `MaterialTheme.androdrColors.critical.copy(alpha = 0.08f)` (etc.) — those are NOT caught by the guard and preserve the original visual weight. The `*Container` fields in `ExtendedColors` are calibrated for the 20%-ish chip-background use case only.

**Line-number anchors in migration tasks (11-20):** Line numbers cited in migration tasks are correct against `main` at plan-write time. If a rebase has shifted lines, the literals (`Color(0xFFCF6679)` etc.) are unique enough — grep within the named file and migrate every hit. Cited line numbers are an aid, not a hard contract.

**Tech Stack:** Kotlin, Jetpack Compose, Material 3, Hilt, Jetpack DataStore (Preferences), AndroidX `WindowCompat`. JVM unit tests with JUnit 4.

**Spec:** `docs/superpowers/specs/2026-05-18-light-dark-theme-design.md`

---

## File Structure

**Create (new):**
- `app/src/main/java/com/androdr/ui/theme/ThemeMode.kt` — `ThemeMode` enum + `resolveDarkTheme` pure helper.
- `app/src/main/java/com/androdr/ui/theme/ExtendedColors.kt` — data class, `LocalAndroDRColors`, `DarkExtendedColors`, `LightExtendedColors`, `MaterialTheme.androdrColors` extension.
- `app/src/test/java/com/androdr/ui/theme/ThemeModeResolutionTest.kt` — truth table for `resolveDarkTheme`.
- `app/src/test/java/com/androdr/ui/theme/ExtendedColorsContrastTest.kt` — WCAG AA contrast assertions on both palette instances (incl. light containers).
- `app/src/test/java/com/androdr/ui/theme/HardcodedColorGuardTest.kt` — drift guard scanning `*.kt` outside `ui/theme/`.
- `app/src/test/java/com/androdr/data/repo/SettingsRepositoryThemeModeTest.kt` — round-trip test for the new DataStore key.

**Modify (theme + persistence):**
- `app/src/main/java/com/androdr/ui/theme/Theme.kt` — add `LightColorScheme`, refactor `AndroDRTheme(themeMode = ...)`, wire `CompositionLocal`.
- `app/src/main/java/com/androdr/data/repo/SettingsRepository.kt` — add `themeMode` Flow + `setThemeMode` + key constant.
- `app/src/main/java/com/androdr/ui/settings/SettingsViewModel.kt` — expose `themeMode` StateFlow + `setThemeMode`.
- `app/src/main/java/com/androdr/ui/settings/SettingsScreen.kt` — add "Appearance" section with 3-option picker.
- `app/src/main/java/com/androdr/MainActivity.kt` — inject `SettingsRepository`, collect theme mode, pass into `AndroDRTheme`, drive system-bar colors from Compose, wrap content in `Surface`.
- `app/src/main/res/values/themes.xml` — drop hardcoded bar colors, add `android:forceDarkAllowed="false"`. Keep platform parent (project has no AppCompat dependency).

**Modify (color migration — 9 files):**
- `ui/common/SeverityChip.kt` — also refactors `severityColor(level)` signature to `severityColor(level, colors)`.
- `ui/apps/AppScanScreen.kt` — updates all `severityColor(level)` call sites to pass `colors`.
- `ui/common/FindingCard.kt`
- `ui/common/EvidenceSheet.kt`
- `ui/timeline/TimelineEventCard.kt`
- `ui/network/DnsMonitorScreen.kt`
- `ui/history/HistoryScreen.kt` — both `severityColor` call sites AND 2 hardcoded literals.
- `ui/device/DeviceAuditScreen.kt`
- `ui/bugreport/BugReportScreen.kt`
- `ui/dashboard/DashboardScreen.kt` — largest single file (15 literals incl. risk swatches and warning-tint card surfaces).

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

class SettingsRepositoryThemeModeTest {

    @get:Rule val tmp = TemporaryFolder()

    private lateinit var dataStore: DataStore<Preferences>
    private lateinit var repo: SettingsRepository

    @Before
    fun setUp() {
        val file = java.io.File(tmp.root, "test.preferences_pb")
        dataStore = PreferenceDataStoreFactory.create(produceFile = { file })
        repo = SettingsRepository(dataStore)
    }

    @After
    fun tearDown() {
        // TemporaryFolder rule handles cleanup
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

Note: `tmp.root` is used (not `tmp.newFile(...)`) because `PreferenceDataStoreFactory.create` wants the file path; the factory creates the file lazily. `tmp.newFile()` pre-creates an empty file which can confuse the protobuf reader on first read.

- [ ] **Step 2: Run test to verify it fails**

Run: `./gradlew :app:testDebugUnitTest --tests "com.androdr.data.repo.SettingsRepositoryThemeModeTest"`
Expected: FAIL (unresolved reference `themeMode` / `setThemeMode`).

- [ ] **Step 3: Add `themeMode` to SettingsRepository**

In `app/src/main/java/com/androdr/data/repo/SettingsRepository.kt`:

Add to the imports block (alphabetical, in the existing `com.androdr.…` cluster):

```kotlin
import com.androdr.ui.theme.ThemeMode
```

Add inside the class body **immediately after the `setDomainIocBlockMode` function** (the one that ends with `dataStore.edit { it[KEY_DOMAIN_IOC_BLOCK_MODE] = value }`) and **before the `customRuleUrls` declaration** (the `/** Custom SIGMA rule repo URLs ... */` block):

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

Add inside the `companion object` block, **after `KEY_CUSTOM_RULE_URLS`** and before the closing brace:

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
```

- [ ] **Step 2: Verify it compiles**

Run: `./gradlew :app:compileDebugKotlin`
Expected: BUILD SUCCESSFUL.

- [ ] **Step 3: Commit**

```bash
git add app/src/main/java/com/androdr/ui/theme/ExtendedColors.kt
git commit -m "feat(theme): add ExtendedColors data class with dark+light severity palettes"
```

---

## Task 4: WCAG AA contrast test for ExtendedColors

**Files:**
- Test: `app/src/test/java/com/androdr/ui/theme/ExtendedColorsContrastTest.kt`

The light-palette values in Task 3 were pre-computed to pass the UI threshold (3.0) on `0xFFFAFAFA` background and on their matching containers. No iteration should be needed — if a check fails, the implementer should suspect a typo, not retune.

- [ ] **Step 1: Write the test**

Create `app/src/test/java/com/androdr/ui/theme/ExtendedColorsContrastTest.kt`:

```kotlin
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
```

- [ ] **Step 2: Run the test**

Run: `./gradlew :app:testDebugUnitTest --tests "com.androdr.ui.theme.ExtendedColorsContrastTest"`
Expected: PASS (3/3). If a check fails, do NOT retune the palette — the values were pre-validated. A failure means a typo in `ExtendedColors.kt`; re-read the file against Task 3's hex values.

Dark containers are not tested directly: they are alpha-translucent over dark surface, so a chip's effective contrast is severity-text-on-near-black, which the first test already covers.

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

Add immediately after the closing `)` of the existing `private val DarkColorScheme = darkColorScheme(...)` block and before the `@Composable fun AndroDRTheme` declaration:

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

Replace the existing `@Composable fun AndroDRTheme` block (the entire current `AndroDRTheme(content: @Composable () -> Unit) { … }`) with:

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

- [ ] **Step 2: Verify it compiles**

Run: `./gradlew :app:compileDebugKotlin`
Expected: BUILD SUCCESSFUL. Existing callers (`AndroDRTheme { … }`) continue to work because `themeMode` has a default.

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

Add to imports (in the existing `com.androdr.…` cluster, alphabetical):

```kotlin
import com.androdr.ui.theme.ThemeMode
```

Add inside the class body **immediately after the `domainIocBlockMode` `stateIn(...)` declaration** and **before the `customRuleUrls` declaration**:

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

In `app/src/main/java/com/androdr/ui/settings/SettingsScreen.kt`, add to imports:

```kotlin
import androidx.compose.material3.SegmentedButton
import androidx.compose.material3.SegmentedButtonDefaults
import androidx.compose.material3.SingleChoiceSegmentedButtonRow
import com.androdr.ui.theme.ThemeMode
```

(`MaterialTheme`, `Modifier`, `Text`, `HorizontalDivider`, `Column`, `Row`, `fillMaxWidth`, `padding`, `dp`, `collectAsStateWithLifecycle` are already imported in this file — do not re-add.)

- [ ] **Step 2: Collect the state**

Inside `fun SettingsScreen(...)`, in the block of `val … by viewModel.X.collectAsStateWithLifecycle()` declarations near the top, add a line **immediately after `val customRuleUrls by viewModel.customRuleUrls.collectAsStateWithLifecycle()`**:

```kotlin
val themeMode by viewModel.themeMode.collectAsStateWithLifecycle()
```

- [ ] **Step 3: Insert the Appearance section**

Inside the `Column { … }` body, **immediately after the closing brace of the headline `Text("Settings", …)` block** (the one with `style = MaterialTheme.typography.headlineMedium` and `color = MaterialTheme.colorScheme.primary`) and **before the `Text("DNS Blocklist", …)` block**, insert:

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

At the bottom of the file (after the existing private `UpdateStatusRow` composable, as a new top-level declaration), add:

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

## Task 9: Wire themeMode in MainActivity + drive system bars + wrap Surface

**Files:**
- Modify: `app/src/main/java/com/androdr/MainActivity.kt`

- [ ] **Step 1: Add imports**

In `app/src/main/java/com/androdr/MainActivity.kt`, add to imports (alphabetical). Skip any import already present in the file (e.g. `Composable` may already be imported — check before adding):

```kotlin
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.runtime.SideEffect
import androidx.compose.runtime.getValue
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.luminance
import androidx.compose.ui.graphics.toArgb
import androidx.compose.ui.platform.LocalView
import androidx.core.view.WindowCompat
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.androdr.data.repo.SettingsRepository
import com.androdr.ui.theme.ThemeMode
import javax.inject.Inject
```

(`Composable` is already imported; `Modifier` is also already imported.)

- [ ] **Step 2: Inject SettingsRepository and rewire onCreate**

Replace the existing `MainActivity` class body (the `class MainActivity : ComponentActivity() { … }` block — only the class itself, not the top-level `AndroDRApp()` and `bottomNavDestinations` below it) with:

```kotlin
@AndroidEntryPoint
class MainActivity : ComponentActivity() {

    @Inject lateinit var settingsRepository: SettingsRepository

    override fun onCreate(savedInstanceState: android.os.Bundle?) {
        super.onCreate(savedInstanceState)
        setContent {
            val themeMode by settingsRepository.themeMode
                .collectAsStateWithLifecycle(initialValue = ThemeMode.AUTO)
            AndroDRTheme(themeMode = themeMode) {
                SystemBarsEffect()
                Surface(
                    modifier = Modifier.fillMaxSize(),
                    color = MaterialTheme.colorScheme.background
                ) {
                    AndroDRApp()
                }
            }
        }
    }
}

@Composable
private fun SystemBarsEffect() {
    val view = LocalView.current
    val surface = MaterialTheme.colorScheme.surface
    val surfaceArgb = surface.toArgb()
    // Drive icon brightness from the actual surface luminance — this is the
    // only truthful signal when the user has forced LIGHT on a system-dark
    // device or vice versa. isSystemInDarkTheme() lies in that case.
    val barsLookDark = surface.luminance() < 0.5f
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
```

Notes for the implementer:
- `androidx.compose.ui.graphics.luminance` is the Compose built-in WCAG luminance helper; do not write a custom one.
- We do NOT call `WindowCompat.setDecorFitsSystemWindows(window, true)` because that is the platform default — adding it is misleading.
- The `Surface` wrap is required because Task 10 makes the Activity window background transparent; without it, dialogs and translucent areas would show through to whatever the OEM put underneath. `AndroDRApp` internally wraps in `Scaffold`, which also paints a surface — this is a deliberate double-paint: the outer Surface guarantees full-window coverage even at the brief moments before/around Scaffold layout.

- [ ] **Step 3: Build the debug APK**

Run: `./gradlew assembleDebug`
Expected: BUILD SUCCESSFUL. Hilt validation should accept `@Inject lateinit var settingsRepository: SettingsRepository` because `SettingsRepository` is already `@Singleton`.

- [ ] **Step 4: Commit**

```bash
git add app/src/main/java/com/androdr/MainActivity.kt
git commit -m "feat(main): inject SettingsRepository, drive theme + system bars from Compose"
```

---

## Task 10: Update Activity theme XML for OEM hardening

**Files:**
- Modify: `app/src/main/res/values/themes.xml`

The project has **no AppCompat dependency** (verified — `androidx.appcompat` not in `libs.versions.toml` or `app/build.gradle.kts`). Therefore we cannot use `Theme.AppCompat.DayNight.NoActionBar` as a parent. Keep the existing `android:Theme.Material.NoActionBar` platform parent — Compose owns all theming inside, so the XML parent only governs the brief pre-Compose window initialization.

- [ ] **Step 1: Rewrite themes.xml**

Replace the entire content of `app/src/main/res/values/themes.xml` with:

```xml
<?xml version="1.0" encoding="utf-8"?>
<resources xmlns:tools="http://schemas.android.com/tools">
    <style name="Theme.AndroDR" parent="android:Theme.Material.NoActionBar">
        <item name="android:forceDarkAllowed" tools:targetApi="29">false</item>
        <item name="android:windowBackground">@android:color/transparent</item>
    </style>
</resources>
```

Changes vs. the previous version:
- Hardcoded `statusBarColor` / `navigationBarColor` removed — `MainActivity.SystemBarsEffect` now sets these at runtime to track the Compose surface color.
- `android:forceDarkAllowed="false"` added — blocks Honor MagicOS (and other OEM force-dark/force-light) from overriding the app's intent. `tools:targetApi="29"` is a lint hint; the attribute is no-op on older APIs.
- `windowBackground` set to transparent so there is no flash of the platform default color before Compose draws. The new `Surface` wrap in Task 9 paints the actual background.
- Parent kept as `android:Theme.Material.NoActionBar` (the existing one). We do NOT switch to AppCompat or DayNight — neither is available on the dependency graph.

- [ ] **Step 2: Build the debug APK**

Run: `./gradlew assembleDebug && ./gradlew lintDebug`
Expected: BUILD SUCCESSFUL for both. If lint flags `android:forceDarkAllowed`, the `tools:targetApi` should silence it; if not, the rule can be downgraded — the attribute is genuinely safe on pre-29 (no-op).

- [ ] **Step 3: Commit**

```bash
git add app/src/main/res/values/themes.xml
git commit -m "fix(theme): drop hardcoded bar colors, disable forceDark, keep platform parent"
```

---

## Task 11: Refactor `severityColor` + migrate `SeverityChip.kt`

**Files:**
- Modify: `app/src/main/java/com/androdr/ui/common/SeverityChip.kt`

The current file has two things:
1. A `@Composable fun SeverityChip(level: String, active: Boolean = true)` with an inline `val severityColor = when …` (lines 11-34).
2. A top-level non-Composable `fun severityColor(level: String): Color = when …` (lines 36-41) called from `AppScanScreen.kt` and `HistoryScreen.kt`.

We refactor the top-level function to take an `ExtendedColors` parameter so it stays non-Composable. Composable callers will pass `MaterialTheme.androdrColors`.

- [ ] **Step 1: Replace the entire file body**

Replace `app/src/main/java/com/androdr/ui/common/SeverityChip.kt` with:

```kotlin
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
```

Behavior preserved:
- The default branch (`else`) returns `neutral`, which equals `TealPrimary` in dark and the darker teal in light — same as the original `0xFF00D4AA` default.
- The disabled-state grey `Color(0xFF888888)` is replaced by `onSurface.copy(alpha = 0.38f)`, Material 3's standard disabled token; this works in both themes without a hardcoded grey.
- The new function adds a `"low"` branch the original lacked — original returned the default (neutral) for any non-critical/high/medium input. Callers that previously passed `"low"` got the neutral teal; they will now get the `low` blue. **This is a deliberate fix**, not a regression — the old code lumped LOW findings into the neutral bucket.

- [ ] **Step 2: Verify it compiles**

Run: `./gradlew :app:compileDebugKotlin`
Expected: COMPILATION ERROR in `AppScanScreen.kt` and `HistoryScreen.kt` because the new `severityColor(level, colors)` signature requires the second argument. **This is expected** — Task 12 and Task 17 fix the callers. Don't commit yet; proceed to Task 12.

- [ ] **Step 3: Do NOT commit yet**

The migration of `SeverityChip.kt` is intentionally entangled with its callers. Skip commit; the next task makes the compile pass.

---

## Task 12: Update `AppScanScreen.kt` callers of `severityColor`

**Files:**
- Modify: `app/src/main/java/com/androdr/ui/apps/AppScanScreen.kt`

The file has six calls to `severityColor(level)` (lines 170, 247, 325, 428, plus the wrapper `fun riskLevelColor(level: String): Color = severityColor(level)` at line 446). All four call sites in `@Composable` scope need `colors` passed in; the non-Composable `riskLevelColor` wrapper needs the same parameter.

- [ ] **Step 1: Add import**

Add to imports (alphabetical, in the existing `com.androdr.…` cluster):

```kotlin
import androidx.compose.material3.MaterialTheme
import com.androdr.ui.theme.ExtendedColors
import com.androdr.ui.theme.androdrColors
```

(`MaterialTheme` may already be imported — skip if so.)

- [ ] **Step 2: Update each Composable-scope call**

Each of the four `@Composable`-scope sites (around lines 170, 247, 325, 428) currently reads:

```kotlin
val color = severityColor(group.highestLevel)
// or
tint = severityColor(finding.level)
// or
val color = severityColor(level)
```

Replace each with the local-palette pattern. Pick a stable anchor for each site — at the top of the enclosing Composable, add:

```kotlin
val colors = MaterialTheme.androdrColors
```

Then change every `severityColor(X)` in that Composable to `severityColor(X, colors)`.

- [ ] **Step 3: Delete the dead `riskLevelColor` wrapper**

The wrapper at line 446 (`fun riskLevelColor(level: String): Color = severityColor(level)`) has **zero external callers** (verified by `grep -rn "riskLevelColor(" app/src/main/java --include="*.kt"` — only the definition matches). It is dead code. Refactoring it would just postpone removal.

Delete the entire line:

```kotlin
fun riskLevelColor(level: String): Color = severityColor(level)
```

If your grep returns any caller besides the definition itself (the codebase may have evolved since this plan was written): STOP, surface the caller list to the human reviewer, and treat that as a scope expansion. Do NOT silently keep the wrapper.

- [ ] **Step 4: Verify it compiles**

Run: `./gradlew :app:compileDebugKotlin`
Expected: still failing — `HistoryScreen.kt` callers still need fixing. That's Task 17. Don't commit yet.

- [ ] **Step 5: Do NOT commit yet — wait for Task 17 to close the loop**

---

## Task 13: Migrate `FindingCard.kt` to ExtendedColors

**Files:**
- Modify: `app/src/main/java/com/androdr/ui/common/FindingCard.kt`

Two hardcoded literals in the file:
- `Color(0xFFCF6679).copy(alpha = 0.08f)` — card background when finding is triggered.
- `Color(0xFFCF6679)` — icon tint when finding is triggered.

- [ ] **Step 1: Add import**

```kotlin
import com.androdr.ui.theme.androdrColors
```

(`MaterialTheme` is already imported.)

- [ ] **Step 2: Replace the background**

Find the line `containerColor = if (finding.triggered) Color(0xFFCF6679).copy(alpha = 0.08f)` and change to:

```kotlin
containerColor = if (finding.triggered) MaterialTheme.androdrColors.critical.copy(alpha = 0.08f)
                 else MaterialTheme.colorScheme.surfaceContainer
```

(Preserves the 8% wash — using `.criticalContainer` here would be ~3× too dark.)

- [ ] **Step 3: Replace the icon tint**

Find the line `tint = if (finding.triggered) Color(0xFFCF6679) else MaterialTheme.colorScheme.primary,` and change to:

```kotlin
tint = if (finding.triggered) MaterialTheme.androdrColors.critical
       else MaterialTheme.colorScheme.primary,
```

- [ ] **Step 4: Verify it compiles**

Run: `./gradlew :app:compileDebugKotlin`
Expected: the ONLY compile errors should be of the form "No value passed for parameter 'colors'" at `severityColor(...)` call sites in files not yet migrated (`HistoryScreen.kt` etc.). If you see any other error class — especially in the file you just edited — STOP, do not commit, surface the error.

---

## Task 14: Migrate `EvidenceSheet.kt` to ExtendedColors

**Files:**
- Modify: `app/src/main/java/com/androdr/ui/common/EvidenceSheet.kt`

Literals in the file (from initial grep): `Color(0xFFCF6679)` at lines 108, 158 (alpha 0.06), 205 (alpha 0.2), 206, 261; `Color(0xFFFF9800)` at lines 281 (alpha 0.15), 282.

- [ ] **Step 1: Add import**

```kotlin
import com.androdr.ui.theme.androdrColors
```

- [ ] **Step 2: Apply the mapping**

| Old expression                                  | New expression                                                            |
|-------------------------------------------------|---------------------------------------------------------------------------|
| `Color(0xFFCF6679)` (opaque, foreground use)    | `MaterialTheme.androdrColors.critical`                                    |
| `Color(0xFFCF6679).copy(alpha = 0.06f)`         | `MaterialTheme.androdrColors.critical.copy(alpha = 0.06f)`                |
| `Color(0xFFCF6679).copy(alpha = 0.2f)` (chip bg) | `MaterialTheme.androdrColors.criticalContainer` (already ~20% calibrated) |
| `Color(0xFFFF9800)` (opaque, foreground use)    | `MaterialTheme.androdrColors.high`                                        |
| `Color(0xFFFF9800).copy(alpha = 0.15f)`         | `MaterialTheme.androdrColors.high.copy(alpha = 0.15f)`                    |

The rule of thumb: low-alpha washes (≤ 0.15) keep the `.copy(alpha = …)` form on the base hue (drift guard doesn't catch this); only the ~20% chip-bg use becomes `.criticalContainer` / `.highContainer`.

- [ ] **Step 3: Verify it compiles**

Run: `./gradlew :app:compileDebugKotlin`
Expected: the ONLY compile errors should be of the form "No value passed for parameter 'colors'" at `severityColor(...)` call sites in files not yet migrated. If you see any other error class — especially in the file you just edited — STOP, do not commit, surface the error.

---

## Task 15: Migrate `TimelineEventCard.kt` to ExtendedColors

**Files:**
- Modify: `app/src/main/java/com/androdr/ui/timeline/TimelineEventCard.kt`

Literals (from initial grep): line 68 (`neutralColor = 0xFF00D4AA`), line 100 (CritRed tag), lines 206-209 (severity switch), lines 373-375 (correlation pattern colors).

The severity switch and correlation switch should mirror Task 11's pattern — non-Composable helpers that take `colors: ExtendedColors` as a parameter, called with `MaterialTheme.androdrColors`.

- [ ] **Step 1: Add imports**

```kotlin
import com.androdr.ui.theme.ExtendedColors
import com.androdr.ui.theme.androdrColors
```

- [ ] **Step 2: Replace `neutralColor` at line 68**

Inside the enclosing Composable, change `val neutralColor = Color(0xFF00D4AA)` to:

```kotlin
val neutralColor = MaterialTheme.androdrColors.neutral
```

- [ ] **Step 3: Replace the CritRed tag at line 100**

Pull the color from the local palette near the top of the enclosing Composable:

```kotlin
val colors = MaterialTheme.androdrColors
…
if (event.campaignName.isNotEmpty()) TagChip(event.campaignName, colors.critical)
```

- [ ] **Step 4: Migrate `severityBackgroundFor` — keep it `@Composable`, preserve the surface fallback**

The current function at lines 200-213 is:

```kotlin
@Composable
private fun severityBackgroundFor(level: String): Color {
    val tint = when (level.uppercase()) {
        "CRITICAL" -> Color(0xFFCF6679)
        "HIGH" -> Color(0xFFFF8A65)
        "MEDIUM" -> Color(0xFFFFD54F)
        "LOW" -> Color(0xFF64B5F6)
        else -> return MaterialTheme.colorScheme.surface
    }
    return tint.copy(alpha = 0.10f)
}
```

It is **already `@Composable`** (it reads `MaterialTheme.colorScheme.surface`) and the `else` branch *early-returns* the surface color, not a tinted version. Both behaviors must be preserved. Replace with:

```kotlin
@Composable
private fun severityBackgroundFor(level: String): Color {
    val colors = MaterialTheme.androdrColors
    val tint = when (level.uppercase()) {
        "CRITICAL" -> colors.critical
        "HIGH"     -> colors.high
        "MEDIUM"   -> colors.medium
        "LOW"      -> colors.low
        else       -> return MaterialTheme.colorScheme.surface
    }
    return tint.copy(alpha = 0.10f)
}
```

Behavioral notes:
- Stays `@Composable` (it must, to read `androdrColors` and `colorScheme.surface`).
- Surface-fallback `else` branch unchanged.
- The original `0xFFFF8A65` (deep orange 300) for HIGH and `0xFFFFD54F` (amber 300) for MEDIUM are intentionally unified with the standard `colors.high` / `colors.medium`. Document this in the PR description (the wash on HIGH/MEDIUM rows will look slightly different — deeper orange and darker amber).
- Original `0xFF64B5F6` LOW maps to `colors.low` — same hue, no change.

- [ ] **Step 5: Migrate the correlation pattern switch in `CorrelationClusterCard` (lines 371-376)**

The current switch uses Kotlin fall-through to map two patterns to the same red:

```kotlin
val clusterColor = when (cluster.pattern) {
    CorrelationPattern.PERMISSION_THEN_C2,
    CorrelationPattern.INSTALL_THEN_ADMIN -> Color(0xFFCF6679) // Red box
    CorrelationPattern.MULTI_PERMISSION_BURST -> Color(0xFFFF9800) // Orange box
    else -> Color(0xFF00D4AA) // neutral
}
```

`PERMISSION_THEN_C2` MUST stay grouped with `INSTALL_THEN_ADMIN` — dropping it silently demotes a critical correlation. Replace inline (no helper needed; the call site is the only consumer):

```kotlin
val colors = MaterialTheme.androdrColors
val clusterColor = when (cluster.pattern) {
    CorrelationPattern.PERMISSION_THEN_C2,
    CorrelationPattern.INSTALL_THEN_ADMIN     -> colors.critical
    CorrelationPattern.MULTI_PERMISSION_BURST -> colors.high
    else                                      -> colors.neutral
}
```

- [ ] **Step 6: Verify it compiles**

Run: `./gradlew :app:compileDebugKotlin`
Expected: the ONLY compile errors should be of the form "No value passed for parameter 'colors'" at `severityColor(...)` call sites in files not yet migrated. If you see any other error class — especially in the file you just edited — STOP, do not commit, surface the error.

---

## Task 16: Migrate `DnsMonitorScreen.kt` to ExtendedColors

**Files:**
- Modify: `app/src/main/java/com/androdr/ui/network/DnsMonitorScreen.kt`

Literals at lines 258 (alpha 0.08), 273 (label), 302 (alpha 0.2), 305 (label).

- [ ] **Step 1: Add import**

```kotlin
import com.androdr.ui.theme.androdrColors
```

- [ ] **Step 2: Apply the mapping**

| Old expression                                  | New expression                                              |
|-------------------------------------------------|-------------------------------------------------------------|
| `Color(0xFFCF6679)`                             | `MaterialTheme.androdrColors.critical`                      |
| `Color(0xFFCF6679).copy(alpha = 0.08f)`         | `MaterialTheme.androdrColors.critical.copy(alpha = 0.08f)`  |
| `Color(0xFFCF6679).copy(alpha = 0.2f)` (chip bg) | `MaterialTheme.androdrColors.criticalContainer`             |

- [ ] **Step 3: Verify it compiles**

Run: `./gradlew :app:compileDebugKotlin`
Expected: the ONLY remaining compile errors should be "No value passed for parameter 'colors'" at `severityColor(...)` call sites in `HistoryScreen.kt`. If you see any other error class — especially in `DnsMonitorScreen.kt` itself — STOP, do not commit, surface the error.

---

## Task 17: Migrate `HistoryScreen.kt` — both severityColor callers AND hardcoded literals

**Files:**
- Modify: `app/src/main/java/com/androdr/ui/history/HistoryScreen.kt`

The file has two `severityColor(...)` calls (lines 252, 399) that now need `colors` passed AND two hardcoded `Color(0xFFCF6679)` literals (lines 561, 567).

- [ ] **Step 1: Add import**

```kotlin
import com.androdr.ui.theme.androdrColors
```

(`MaterialTheme` may already be imported — skip if so.)

- [ ] **Step 2: Update `severityColor` call sites — each Composable needs its own `colors`**

The two `severityColor(...)` calls are in DIFFERENT enclosing Composables (line 252 in one card; line 399 in another). Compose locals don't leak across function boundaries, so **add `val colors = MaterialTheme.androdrColors` at the top of EACH of the two enclosing Composable bodies** — not just once.

Then change:
- `severityColor(scan.overallRiskLevel.name)` → `severityColor(scan.overallRiskLevel.name, colors)` at line 252.
- `severityColor(riskLevel.name)` → `severityColor(riskLevel.name, colors)` at line 399.

- [ ] **Step 3: Replace hardcoded literals**

At lines 561 and 567, replace `Color(0xFFCF6679)` with `MaterialTheme.androdrColors.critical`.

- [ ] **Step 4: Verify it compiles**

Run: `./gradlew :app:compileDebugKotlin`
Expected: BUILD SUCCESSFUL if `AppScanScreen` (Task 12), `SeverityChip` (Task 11), and the migration tasks so far are all coherent. If still failing, the error message identifies the remaining caller — fix it before proceeding.

- [ ] **Step 5: Commit Tasks 11-17 together**

Tasks 11-17 form one coherent compile-passing unit. Commit them all now:

```bash
git add app/src/main/java/com/androdr/ui/common/SeverityChip.kt \
        app/src/main/java/com/androdr/ui/apps/AppScanScreen.kt \
        app/src/main/java/com/androdr/ui/common/FindingCard.kt \
        app/src/main/java/com/androdr/ui/common/EvidenceSheet.kt \
        app/src/main/java/com/androdr/ui/timeline/TimelineEventCard.kt \
        app/src/main/java/com/androdr/ui/network/DnsMonitorScreen.kt \
        app/src/main/java/com/androdr/ui/history/HistoryScreen.kt
git commit -m "refactor(ui): migrate severity-coded UI to MaterialTheme.androdrColors

severityColor(level) gains a colors: ExtendedColors parameter so it stays
non-Composable and callers (Composable and otherwise) pass MaterialTheme
.androdrColors. SeverityChip, FindingCard, EvidenceSheet, TimelineEventCard,
DnsMonitorScreen, HistoryScreen, and AppScanScreen migrated to the new
palette layer in one coherent compile unit."
```

---

## Task 18: Migrate `DeviceAuditScreen.kt` to ExtendedColors

**Files:**
- Modify: `app/src/main/java/com/androdr/ui/device/DeviceAuditScreen.kt`

Two hardcoded literals: `Color(0xFFCF6679)` at lines 88 and 126.

- [ ] **Step 1: Add import**

```kotlin
import com.androdr.ui.theme.androdrColors
```

- [ ] **Step 2: Replace both literals**

At lines 88 and 126, replace `Color(0xFFCF6679)` with `MaterialTheme.androdrColors.critical`.

- [ ] **Step 3: Verify it compiles**

Run: `./gradlew :app:compileDebugKotlin`
Expected: BUILD SUCCESSFUL.

- [ ] **Step 4: Commit**

```bash
git add app/src/main/java/com/androdr/ui/device/DeviceAuditScreen.kt
git commit -m "refactor(ui): DeviceAuditScreen uses MaterialTheme.androdrColors"
```

---

## Task 19: Migrate `BugReportScreen.kt` to ExtendedColors

**Files:**
- Modify: `app/src/main/java/com/androdr/ui/bugreport/BugReportScreen.kt`

The file's severity switch at lines 491-495 maps levels to (icon, color) pairs:

```kotlin
"CRITICAL" -> Pair(Icons.Filled.Error, Color(0xFFCF6679))
"HIGH"     -> Pair(Icons.Filled.Warning, Color(0xFFFF9800))
"MEDIUM"   -> Pair(Icons.Filled.Warning, Color(0xFFE6A800))
"ERROR"    -> Pair(Icons.Filled.Error, Color(0xFFCF6679))
else       -> Pair(Icons.Filled.Info, Color(0xFF00D4AA))
```

- [ ] **Step 1: Add import**

```kotlin
import com.androdr.ui.theme.androdrColors
```

- [ ] **Step 2: Refactor `findingIconAndColor` to take `colors`**

The switch is inside the non-Composable helper `findingIconAndColor(severity: String)` at line 490. Keep it non-Composable; add the palette parameter:

```kotlin
private fun findingIconAndColor(
    severity: String,
    colors: ExtendedColors
): Pair<ImageVector, Color> = when (severity.uppercase()) {
    "CRITICAL" -> Pair(Icons.Filled.Error, colors.critical)
    "HIGH"     -> Pair(Icons.Filled.Warning, colors.high)
    "MEDIUM"   -> Pair(Icons.Filled.Warning, colors.medium)
    "ERROR"    -> Pair(Icons.Filled.Error, colors.critical)
    else       -> Pair(Icons.Filled.Info, colors.neutral)
}
```

Add an import for `ExtendedColors`:

```kotlin
import com.androdr.ui.theme.ExtendedColors
```

- [ ] **Step 3: Update the caller at line 441**

The only caller is inside `@Composable fun TimelineEventCard(event: ...)` at line 441:

```kotlin
val (icon, color) = findingIconAndColor(event.severity)
```

Change to:

```kotlin
val (icon, color) = findingIconAndColor(event.severity, MaterialTheme.androdrColors)
```

(Verify there are no other callers with `grep -n "findingIconAndColor(" app/src/main/java/com/androdr/ui/bugreport/BugReportScreen.kt`. If new callers appeared, update each the same way.)

- [ ] **Step 4: Verify it compiles**

Run: `./gradlew :app:compileDebugKotlin`
Expected: BUILD SUCCESSFUL.

- [ ] **Step 5: Commit**

```bash
git add app/src/main/java/com/androdr/ui/bugreport/BugReportScreen.kt
git commit -m "refactor(ui): BugReportScreen uses MaterialTheme.androdrColors"
```

---

## Task 20: Migrate `DashboardScreen.kt` to ExtendedColors

**Files:**
- Modify: `app/src/main/java/com/androdr/ui/dashboard/DashboardScreen.kt`

The largest single migration — 15 literals across several semantic groups:
- Lines 300-315: a severity switch (`critical/high/medium/default neutral`) using the *same* base hues as `SeverityChip`.
- Lines 346-350: a *risk-level* switch using **different**, bolder hues:
  - `0xFFFF1744` (bold red) for CRITICAL — "unmistakable danger"
  - `0xFFFF6E40` (deep orange) for HIGH
  - `0xFFFFD54F` (amber 300) for MEDIUM
  - `0xFF00D4AA` (brand teal) for LOW
- Lines 411, 422, 428: a single warning card — orange container + tint + label.
- Lines 567, 578, 585: a second warning card — same orange triad.

The two "risk-level" hues at 346-348 (`0xFFFF1744`, `0xFFFF6E40`, `0xFFFFD54F`) are visibly louder than the base severity hues. Two paths:

**(a) Collapse both groups into the single `androdrColors.*` palette** (recommended). The "bolder" risk hues become regular `colors.critical`/`colors.high`/`colors.medium`. The Dashboard then renders consistently with every other surface. Lose the loud-red attention-grab; gain consistency. **This is the recommended choice** because the inconsistency was unintentional drift, not a designed call-out.

**(b) Add a "loud" tier to `ExtendedColors`** (NOT recommended). Adds three new fields used by exactly one file. Maintenance overhead with no clear win.

The plan proceeds with (a). If the dashboard's risk header *needs* a louder presentation for UX reasons, that's a follow-up design decision, not a migration concern.

DashboardScreen has **four separate `@Composable` functions** that each contain hardcoded literals:
- `PostScanGuidance` (starts at line 287) — severity switch lines 300-315.
- `RiskLevelCard` (starts at line 344) — risk-level switch lines 346-350.
- `DiffBanner` (starts at line 407) — warning card lines 411-428.
- `PartialScanBanner` (starts at line 563) — warning card lines 567-585.

Each Composable needs its own `val colors = MaterialTheme.androdrColors` pull — Compose locals do not leak across function boundaries.

- [ ] **Step 1: Add import + remove the dead one**

Add:

```kotlin
import com.androdr.ui.theme.androdrColors
```

Remove the now-dead import at line 61 (verified: no remaining usages of `severityColor` symbol in the file after this migration):

```kotlin
import com.androdr.ui.common.severityColor   // delete this line
```

Skipping the removal will produce a "Unused import" warning that may fail release lint (CLAUDE.md notes warnings are treated as errors in release builds).

- [ ] **Step 2: Migrate `PostScanGuidance` severity switch (lines 300-315)**

Inside `PostScanGuidance`, add at the top of its body:

```kotlin
val colors = MaterialTheme.androdrColors
```

Replace each literal in the switch:

| Old                  | New              |
|----------------------|------------------|
| `Color(0xFFCF6679)`  | `colors.critical`|
| `Color(0xFFFF9800)`  | `colors.high`    |
| `Color(0xFFE6A800)`  | `colors.medium`  |
| `Color(0xFF00D4AA)`  | `colors.neutral` |

- [ ] **Step 3: Migrate `RiskLevelCard` risk-level switch (lines 346-350)**

Inside `RiskLevelCard` (a different Composable from PostScanGuidance), add its own:

```kotlin
val colors = MaterialTheme.androdrColors
```

Replace each:

| Old                                | New                              |
|------------------------------------|----------------------------------|
| `Color(0xFFFF1744)` (CRITICAL)     | `colors.critical`                |
| `Color(0xFFFF6E40)` (HIGH)         | `colors.high`                    |
| `Color(0xFFFFD54F)` (MEDIUM)       | `colors.medium`                  |
| `Color(0xFF00D4AA)` (LOW)          | `colors.low`                     |
| `Color(0xFF00D4AA)` (null branch)  | `colors.neutral`                 |

The LOW branch shifts from brand teal to actual blue (same deliberate fix as Task 11). Null branch keeps the neutral teal.

- [ ] **Step 4: Migrate `DiffBanner` warning card (lines 411-428)**

Inside `DiffBanner` (yet another Composable), add its own:

```kotlin
val colors = MaterialTheme.androdrColors
```

Replace the three orange uses (container alpha wash, icon tint, label color):

| Old                                       | New                                                  |
|-------------------------------------------|------------------------------------------------------|
| `Color(0xFFFF9800).copy(alpha = 0.15f)`   | `colors.high.copy(alpha = 0.15f)` (keep wash form)   |
| `Color(0xFFFF9800)`                       | `colors.high`                                        |

- [ ] **Step 5: Migrate `PartialScanBanner` warning card (lines 567-585)**

Inside `PartialScanBanner` (fourth Composable), add its own:

```kotlin
val colors = MaterialTheme.androdrColors
```

Apply the same mapping table as Step 4.

- [ ] **Step 6: Verify it compiles**

Run: `./gradlew :app:compileDebugKotlin`
Expected: BUILD SUCCESSFUL.

- [ ] **Step 7: Commit**

```bash
git add app/src/main/java/com/androdr/ui/dashboard/DashboardScreen.kt
git commit -m "refactor(ui): DashboardScreen uses MaterialTheme.androdrColors

Collapses the previously-divergent loud-risk hues (0xFFFF1744 etc.) into
the standard severity palette; gains consistency, gives up the bespoke
loud-red attention grab. If a louder risk-header presentation is wanted
later, raise it as a UX decision (follow-up), not a palette regression."
```

---

## Task 21: Add the hardcoded-color drift guard test

**Files:**
- Test: `app/src/test/java/com/androdr/ui/theme/HardcodedColorGuardTest.kt`

This test runs LAST in the migration sequence so that when it first runs, all nine migration files (Tasks 11-20) are already done. Adding it before then would produce a noisy failure list of work-in-progress.

- [ ] **Step 1: Write the test**

Create `app/src/test/java/com/androdr/ui/theme/HardcodedColorGuardTest.kt`:

```kotlin
package com.androdr.ui.theme

import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/**
 * Guards against re-introducing hardcoded Color(0xFF…) literals in UI code.
 * The only allowed location for raw color values is inside ui/theme/.
 * If you need a new semantic color, add it to ExtendedColors instead.
 *
 * Sub-percent washes — e.g. critical.copy(alpha = 0.08f) — are intentionally
 * allowed and not matched by this regex.
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
                        "${file.relativeTo(sourceRoot)}:${idx + 1}  ${line.trim()}"
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
        // Gradle JVM tests run with cwd = module dir (app/). IDE run configs sometimes
        // use the repo root. Cover both.
        val candidates = listOf(
            File("src/main/java/com/androdr"),
            File("app/src/main/java/com/androdr"),
            File("../app/src/main/java/com/androdr")
        )
        return candidates.firstOrNull { it.exists() }
            ?: error(
                "Could not locate source root from ${File(".").absolutePath}. " +
                    "Tried: ${candidates.map { it.path }}"
            )
    }
}
```

- [ ] **Step 2: Run the test**

Run: `./gradlew :app:testDebugUnitTest --tests "com.androdr.ui.theme.HardcodedColorGuardTest"`
Expected: PASS. If it FAILS, the message lists every remaining `Color(0xFF…)` literal — go migrate it (or add `// hardcoded-color-ok: <reason>` if it genuinely belongs outside the theme; this should be rare).

- [ ] **Step 3: Commit**

```bash
git add app/src/test/java/com/androdr/ui/theme/HardcodedColorGuardTest.kt
git commit -m "test(theme): guard against hardcoded Color(0xFF…) literals outside ui/theme"
```

---

## Task 22: SeverityChip dark/light preview + final verification

**Files:**
- Modify: `app/src/main/java/com/androdr/ui/common/SeverityChip.kt`

A single preview composable for `SeverityChip` proves the new palette renders correctly in both themes. Previews for `FindingCard` / `EvidenceSheet` / `TimelineEventCard` / dashboard cards are intentionally deferred — they require nontrivial fixture builders that aren't worth the scope inflation here. Track them as a UX-polish follow-up if desired; visual review of the running app on emulator (Step 4) covers them for now.

- [ ] **Step 1: Append the preview to `SeverityChip.kt`**

Add to `app/src/main/java/com/androdr/ui/common/SeverityChip.kt`:

```kotlin
import android.content.res.Configuration
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Surface
import androidx.compose.ui.Modifier
import androidx.compose.ui.tooling.preview.Preview
import androidx.compose.ui.unit.dp
import com.androdr.ui.theme.AndroDRTheme
import com.androdr.ui.theme.ThemeMode

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
```

- [ ] **Step 2: Verify it compiles and renders**

Run: `./gradlew :app:compileDebugKotlin`
Expected: BUILD SUCCESSFUL. Open the file in Android Studio and confirm both preview panels render four severity chips with visibly distinct colors.

- [ ] **Step 3: Run the full unit test suite**

Run: `./gradlew :app:testDebugUnitTest`
Expected: ALL TESTS PASS. Any pre-existing test failure unrelated to theme work is out of scope — flag in the PR description.

- [ ] **Step 4: Build release + lint**

Run: `./gradlew assembleRelease && ./gradlew lintDebug`
Expected: BUILD SUCCESSFUL for both. R8 may strip the preview composable — that's fine (dev-only).

- [ ] **Step 5: Emulator smoke test**

Run the existing harness:
```bash
./scripts/smoke-test.sh
```
Expected: APK installs, app launches, logcat is crash-free. Then manually:
1. Open the emulator's system Settings, toggle Dark mode off → confirm AndroDR follows to light within seconds.
2. In AndroDR Settings → Appearance, switch to "Dark" → confirm app forces dark regardless of system.
3. Switch to "Light" → confirm app forces light.
4. Switch to "System" → confirm app re-follows system.
5. Visit Dashboard, Apps, Network, Timeline, History, Device, Bug Report screens in both modes — confirm severity chips, finding cards, evidence sheets, risk swatches, and warning cards are all legible.

- [ ] **Step 6: Honor device re-test (if available)**

If the tester's Honor device is reachable, re-test the exact screen where text was reported invisible. Confirm legibility in both system-light and system-dark. Capture screenshots for the PR description.

If no Honor device is available: explicitly note "Honor re-test pending — relies on tester verification post-merge" in the PR description. Do not claim the bug fixed without device confirmation.

### Visual changes to call out in the PR description

These are deliberate semantic-color migrations that a tester running visual regression WILL notice. Document them so they are not filed as regressions:

- **LOW severity is now blue, not brand teal.** Affects severity chips, finding cards, dashboard risk swatches, timeline backgrounds. The original code lumped LOW into the neutral teal bucket; the new palette gives LOW its own blue (`androdrColors.low`). Intended fix.
- **Dashboard CRITICAL / HIGH / MEDIUM risk swatches lose the "loud" presentation.** Previously `0xFFFF1744` (siren red), `0xFFFF6E40` (deep orange), `0xFFFFD54F` (amber 300). Now use the standard severity palette (`androdrColors.critical / .high / .medium`). The siren-red attention grab is gone; if a louder dashboard banner is wanted, raise as a separate UX decision.
- **TimelineEventCard severity-row washes shift slightly on HIGH and MEDIUM.** Previously `0xFFFF8A65` (deep orange 300) and `0xFFFFD54F` (amber 300) used in `severityBackgroundFor`. Now use `androdrColors.high` (deeper orange) and `androdrColors.medium` (darker amber) at the same 10% alpha. Subtle but visible.
- **SeverityChip disabled state changes from `0xFF888888`** to `colorScheme.onSurface.copy(alpha = 0.38f)` — adapts to theme instead of being a fixed grey.

- [ ] **Step 7: Commit preview + close**

```bash
git add app/src/main/java/com/androdr/ui/common/SeverityChip.kt
git commit -m "test(ui): add light+dark preview for SeverityChip"
```

This task produces no further commits; verification output goes into the PR description.

---

## Self-Review Notes

Plan has been through two full revision cycles, each preceded by a two-reviewer plan-gate review. Verified post-v2-revision:

- **Spec coverage:** every spec section maps to at least one task. Migration covers all 9 files containing hardcoded `Color(0xFF…)` literals (verified by `grep -rn "Color(0x" app/src/main/java --include="*.kt" | grep -v "ui/theme/" | awk -F: '{print $1}' | sort -u`).
- **`severityColor` cascade:** broken by keeping the function non-Composable and threading `ExtendedColors` through callers; Tasks 11-12-17 form one coherent compile-passing unit, committed together.
- **Drift guard:** placed at Task 21 (after all migrations) so it passes the first time it runs; the regex only matches raw `Color(0xFF…)` literals so `.copy(alpha = …)` patterns are intentionally allowed.
- **Type consistency:** `ThemeMode` (enum), `resolveDarkTheme(themeMode, systemInDark): Boolean`, `ExtendedColors` (data class), `LocalAndroDRColors`, `MaterialTheme.androdrColors`, `severityColor(level, colors)`, `riskLevelColor(level, colors)`, `settingsRepository.themeMode` / `setThemeMode(mode)`, `KEY_THEME_MODE` — all referenced consistently across tasks.
- **No fragile anchors:** "around line N" replaced with stable code anchors ("immediately after the closing brace of X", "before declaration Y").
- **Out of scope (still):** Material You dynamic color; `androdr-015` FP on Honor (separate track).

---

**Plan complete and saved to `docs/superpowers/plans/2026-05-18-light-dark-theme.md`. Two execution options:**

**1. Subagent-Driven (recommended)** — fresh subagent per task, review between tasks. Tasks 11-17 should be dispatched as a single bundle (they don't compile independently); Tasks 18-20 can be parallel; Task 21 sequenced last.

**2. Inline Execution** — execute tasks in this session using `superpowers:executing-plans`, batched with checkpoints.

**Which approach?**
