# Spec: Light/Dark theme with OS-following + semantic-color migration

**Issue:** TBD (file before plan execution; covers the tester-reported invisible-text bug on Honor MagicOS).
**Scope of this spec:** Introduce a light color scheme, an OS-following theme mode with user override (Auto / Light / Dark), a semantic-color layer for severity hues, and migrate all 55 hardcoded `Color(0xFF…)` literals outside `ui/theme/` to the new layer.
**Out of scope:** Material You dynamic color (wallpaper-derived palette); the `androdr-015` false-positive bug on Honor (separate track).
**Date:** 2026-05-18

---

## Why

A tester running AndroDR on an Honor device reported text being invisible across multiple screens. Root-cause analysis points at two compounding factors:

1. `ui/theme/Theme.kt` hardcodes a single dark color scheme. The app never reads `isSystemInDarkTheme()`, never exposes a user choice, and there is no light palette to fall back on.
2. Honor MagicOS (Huawei's Android skin) aggressively applies system-wide "force light" / contrast overrides on apps that declare a dark theme. The result is a half-washed UI where the app's dark text-on-dark assumption collides with the OS's forced light background, producing the invisible-text symptom.

The fix on its own — a working light scheme that the app switches to when the OS is in light mode — neutralizes the conflict. The accompanying semantic-color migration is the other half: 55 sites across the UI (severity chips, finding cards, evidence sheets, timeline events, DNS monitor) carry hardcoded colors tuned for a dark background. Without migration, severity chips remain illegible in light mode and the "fix" only half-works.

This is a UX-blocking bug for any tester whose device is in light mode or whose OEM forces it, not a polish item.

## Non-goals

- **No Material You dynamic color.** Adds palette plumbing, dilutes the security/EDR brand identity on Android 12+ devices, and is not necessary to fix the reported bug. Revisit later if there is demand.
- **No new theme variants beyond the two presets.** Just Dark and Light. No high-contrast, no AMOLED, no per-screen overrides.
- **No fix for `androdr-015` ("Unrecognized System App") FP on Honor.** Same tester, different problem — `is_system_app && !is_known_oem_app` fires on Honor's MagicOS preloads because the known-good OEM database does not cover Honor. That gets its own spec.
- **No design-system overhaul.** The existing teal/security identity stays. The light variant is a derivative of the same brand colors at darker shades for AA contrast on white.

## Theme architecture

### `ThemeMode` enum

New file `app/src/main/java/com/androdr/ui/theme/ThemeMode.kt`:

```kotlin
enum class ThemeMode { AUTO, LIGHT, DARK }
```

Persisted in `SettingsRepository` as a string preference (`KEY_THEME_MODE`), default `AUTO`. AUTO means "follow `isSystemInDarkTheme()`".

### `SettingsRepository` additions

New flow + setter in `data/repo/SettingsRepository.kt`:

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

Key constant: `private val KEY_THEME_MODE = stringPreferencesKey("theme_mode")`.

### `AndroDRTheme` Composable

Refactor `ui/theme/Theme.kt` so `AndroDRTheme` accepts a `themeMode: ThemeMode` (default AUTO for previews), resolves to `useDarkTheme: Boolean` via:

```kotlin
val useDarkTheme = when (themeMode) {
    ThemeMode.LIGHT -> false
    ThemeMode.DARK  -> true
    ThemeMode.AUTO  -> isSystemInDarkTheme()
}
val colorScheme = if (useDarkTheme) DarkColorScheme else LightColorScheme
val extended    = if (useDarkTheme) DarkExtendedColors else LightExtendedColors

CompositionLocalProvider(LocalAndroDRColors provides extended) {
    MaterialTheme(colorScheme = colorScheme, content = content)
}
```

### `ExtendedColors` data class + CompositionLocal

New file `ui/theme/ExtendedColors.kt`:

```kotlin
data class ExtendedColors(
    val critical: Color,
    val high: Color,
    val medium: Color,
    val low: Color,
    val neutral: Color,
    val criticalContainer: Color,   // 8-20% alpha-ish backgrounds for chips/cards
    val highContainer: Color,
    val mediumContainer: Color,
    val lowContainer: Color,
)

val LocalAndroDRColors = staticCompositionLocalOf<ExtendedColors> {
    error("AndroDRTheme must wrap the call site")
}

val MaterialTheme.androdrColors: ExtendedColors
    @Composable
    @ReadOnlyComposable
    get() = LocalAndroDRColors.current
```

Two const instances, one for each scheme. The light variants are darker, deeper shades of the existing severity hues so AA contrast holds against `0xFFFAFAFA`.

## Palettes

### Dark scheme

Unchanged. The existing `DarkColorScheme` in `Theme.kt` stays verbatim — no regressions for current users.

### Light scheme

New `lightColorScheme(…)` next to `DarkColorScheme`:

```kotlin
private val LightColorScheme = lightColorScheme(
    primary             = TealPrimaryVariant,         // 0xFF00A882, darker teal, AA on white
    onPrimary           = Color.White,
    primaryContainer    = Color(0xFFB2FFF0),
    onPrimaryContainer  = Color(0xFF003328),
    secondary           = Color(0xFF006B62),
    onSecondary         = Color.White,
    secondaryContainer  = Color(0xFF70F2E6),
    onSecondaryContainer= Color(0xFF00201D),
    tertiary            = Color(0xFF00658E),
    onTertiary          = Color.White,
    tertiaryContainer   = Color(0xFFC5E7FF),
    onTertiaryContainer = Color(0xFF001E2E),
    error               = Color(0xFFB3261E),          // Material light error
    onError             = Color.White,
    errorContainer      = Color(0xFFFFDAD6),
    onErrorContainer    = Color(0xFF410002),
    background          = Color(0xFFFAFAFA),
    onBackground        = Color(0xFF1A1A1A),
    surface             = Color.White,
    onSurface           = Color(0xFF1A1A1A),
    surfaceVariant      = Color(0xFFEEEEEE),
    onSurfaceVariant    = Color(0xFF4A4A4A),
    outline             = Color(0xFF747878),
    outlineVariant      = Color(0xFFC4C7C7),
    surfaceContainer    = Color(0xFFF1F1F1),
    surfaceContainerHigh= Color(0xFFEAEAEA),
    surfaceContainerLow = Color(0xFFF6F6F6),
)
```

Exact values may be tuned during implementation against the contrast-ratio test (see Testing). The contract is "AA pass for every fg/bg pair Compose can produce from this scheme".

### `ExtendedColors` instances

```kotlin
val DarkExtendedColors = ExtendedColors(
    critical          = Color(0xFFCF6679),   // existing dark severity hues, preserved
    high              = Color(0xFFFF9800),
    medium            = Color(0xFFE6A800),
    low               = Color(0xFF64B5F6),
    neutral           = TealPrimary,
    criticalContainer = Color(0xFFCF6679).copy(alpha = 0.20f),
    highContainer     = Color(0xFFFF9800).copy(alpha = 0.20f),
    mediumContainer   = Color(0xFFE6A800).copy(alpha = 0.20f),
    lowContainer      = Color(0xFF64B5F6).copy(alpha = 0.20f),
)

val LightExtendedColors = ExtendedColors(
    critical          = Color(0xFFB3261E),   // darker red, AA on white
    high              = Color(0xFFC25700),   // deep orange
    medium            = Color(0xFF8B6B00),   // dark amber
    low               = Color(0xFF1565C0),   // deep blue
    neutral           = TealPrimaryVariant,
    criticalContainer = Color(0xFFFFDAD6),   // pale red bg
    highContainer     = Color(0xFFFFDCC2),
    mediumContainer   = Color(0xFFF6E5B4),
    lowContainer      = Color(0xFFD0E4FF),
)
```

## Settings UI

`SettingsScreen.kt` gains an "Appearance" section above the existing DNS / Custom rules sections.

UI: a single 3-button segmented control (or radio group, whichever fits existing settings style) labelled **"Theme"** with buttons **System default / Light / Dark**. Default selection follows the persisted `themeMode`. Tap immediately calls `viewModel.setThemeMode(mode)`.

`SettingsViewModel` exposes:

```kotlin
val themeMode: StateFlow<ThemeMode> = settingsRepository.themeMode
    .stateIn(viewModelScope, SharingStarted.Eagerly, ThemeMode.AUTO)

fun setThemeMode(mode: ThemeMode) {
    viewModelScope.launch { settingsRepository.setThemeMode(mode) }
}
```

`MainActivity` collects `settingsRepository.themeMode` as state and passes the value into `AndroDRTheme`. Theme switch is instant; no restart required.

## OEM-override hardening (Honor MagicOS in particular)

Confirmed current state of `app/src/main/res/values/themes.xml`:

```xml
<style name="Theme.AndroDR" parent="android:Theme.Material.NoActionBar">
    <item name="android:statusBarColor">#1A1A2E</item>
    <item name="android:navigationBarColor">#1A1A2E</item>
</style>
```

This is a permanently-dark Activity theme with hardcoded system-bar colors that don't track Compose. Two of the three findings below are direct consequences.

Three concrete changes:

1. **`android:forceDarkAllowed="false"`** added to `Theme.AndroDR`. This blocks Honor's MagicOS force-light/force-dark from overriding Compose's choice. Compose owns the theme; the OS shouldn't.
2. **Remove the hardcoded `statusBarColor` / `navigationBarColor`** from `Theme.AndroDR`. Replace with runtime updates in `MainActivity` (or a small `SystemBarsEffect` Composable) that read `MaterialTheme.colorScheme.surface` and call `WindowCompat.getInsetsController(...).isAppearanceLightStatusBars = !useDarkTheme` plus `window.statusBarColor = surface.toArgb()`. Bars then track theme switches instantly.
3. **Parent theme switch.** `android:Theme.Material.NoActionBar` is a legacy platform theme that may apply implicit text colors. Switch to `Theme.AppCompat.DayNight.NoActionBar` (or `Theme.Material3.DayNight.NoActionBar` if Material 3 XML theme is already on the dependency graph). Audit confirms the Activity inherits no `android:textColorPrimary` overrides; if any are present, remove them so Compose's `onSurface` wins.

## Migration of the 55 hardcoded color sites

Mechanical replacement, file by file:

| Old literal              | Used for                          | Replacement                                                                                |
|--------------------------|-----------------------------------|--------------------------------------------------------------------------------------------|
| `Color(0xFFCF6679)`      | critical severity / error chip    | `MaterialTheme.androdrColors.critical`                                                     |
| `Color(0xFFFF9800)`      | high severity                     | `MaterialTheme.androdrColors.high`                                                         |
| `Color(0xFFE6A800)` / `0xFFFFD54F` | medium severity         | `MaterialTheme.androdrColors.medium`                                                       |
| `Color(0xFF64B5F6)`      | low severity                      | `MaterialTheme.androdrColors.low`                                                          |
| `Color(0xFF00D4AA)`      | neutral severity / brand accent   | `MaterialTheme.androdrColors.neutral` (severity context) or `colorScheme.primary` (brand)  |
| `Color(0xFFFF8A65)`      | one-off in TimelineEventCard      | `MaterialTheme.androdrColors.high` (same severity tier)                                    |
| `Color(0xFF888888)`      | disabled-state grey               | `colorScheme.onSurface.copy(alpha = 0.38f)` (Material disabled token)                      |
| `Color(0xFFCF6679).copy(alpha = N)` | alert backgrounds      | `MaterialTheme.androdrColors.criticalContainer` (drop alpha — light/dark variants already encode the visual weight) |

Files confirmed from the codebase scan:

- `ui/network/DnsMonitorScreen.kt`
- `ui/timeline/TimelineEventCard.kt`
- `ui/common/FindingCard.kt`
- `ui/common/EvidenceSheet.kt`
- `ui/common/SeverityChip.kt`

Implementation should run a fresh `grep -rn "Color(0x" app/src/main/java --include="*.kt" | grep -v "ui/theme/"` to confirm no new sites were added since this spec was written; pick up any newcomers in the same pass.

### Drift guard (durable part)

Add a unit test in `app/src/test/java/com/androdr/ui/theme/HardcodedColorGuardTest.kt`:

```kotlin
class HardcodedColorGuardTest {
    @Test
    fun `no hardcoded Color(0xFF…) literals outside ui-theme package`() {
        val offenders = File("src/main/java/com/androdr")
            .walkTopDown()
            .filter { it.extension == "kt" }
            .filterNot { it.path.contains("/ui/theme/") }
            .flatMap { f ->
                f.readLines().mapIndexedNotNull { idx, line ->
                    Regex("""Color\(0x[0-9A-Fa-f]{8}\)""").find(line)?.let { "${f.name}:${idx + 1}" }
                }
            }
            .toList()
        assertTrue(
            "Hardcoded Color(0xFF…) literals found outside ui/theme/. Move to ExtendedColors:\n" +
                offenders.joinToString("\n"),
            offenders.isEmpty()
        )
    }
}
```

Path resolution may need adjustment for the project's test working directory. The point is: if someone adds a hardcoded color in a future PR, CI breaks and tells them where.

## Testing

### Compose previews

For each of `SeverityChip`, `FindingCard`, `EvidenceSheet`, `TimelineEventCard`, add `@Preview` entries with both `uiMode = UI_MODE_NIGHT_YES` and `UI_MODE_NIGHT_NO`. Visual regression catches obvious contrast failures during code review.

### Contrast unit test

Helper:

```kotlin
fun contrastRatio(fg: Color, bg: Color): Double { /* WCAG luminance math */ }
```

Test asserts: for both `LightExtendedColors` and `DarkExtendedColors`, every severity color against its scheme's `background` and `surface` meets WCAG AA (≥ 4.5 for normal text, ≥ 3.0 for large/UI components). Same for the `*Container` colors against `onSurface`.

### Settings round-trip

`SettingsRepositoryTest` (extend existing or add) verifies `setThemeMode(LIGHT)` then `themeMode.first()` returns `LIGHT`; same for `DARK` and `AUTO`; unknown stored value falls back to `AUTO`.

### `AndroDRTheme` resolution

Unit test with a fake `isSystemInDarkTheme` value confirms the truth table:

| themeMode | isSystemDark | useDark expected |
|-----------|--------------|------------------|
| AUTO      | true         | true             |
| AUTO      | false        | false            |
| LIGHT     | true         | false            |
| LIGHT     | false        | false            |
| DARK      | true         | true             |
| DARK      | false        | true             |

### Manual smoke

- Emulator: install, toggle system dark mode, confirm app follows. Toggle picker through all three modes.
- Physical device, if Honor unit available: re-test the screen the tester originally flagged. Confirm text is legible in both modes and that MagicOS no longer washes the UI.

## Risks

- **Light palette tuning is iterative.** First-pass color values almost certainly won't all pass AA. Implementation should run the contrast test as it goes and adjust.
- **The drift-guard test may produce noise on legitimate uses of `Color(0xFF…)`** (e.g., debug overlays, screenshot tests). Add an opt-out comment marker (`// hardcoded-color-ok: <reason>`) the test recognizes if needed.
- **`forceDarkAllowed="false"` is a manifest change.** Confirm no regression on stock Android devices where Compose theming already handles everything correctly.

## Rollout

Single PR targeting `main` per project convention. All work behind one branch (`fix/light-dark-theme-honor-contrast` or similar). No feature flag; this is a fix.

Filed-issue link gets added to the spec header and PR body once the issue is created.
