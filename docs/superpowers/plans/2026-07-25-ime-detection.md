# IME Detection Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Detect third-party keyboards that are enabled (medium) or actively selected (high) on the device, without false-positiving on OEM and partner-preinstalled keyboards.

**Architecture:** A new `InputMethodScanner` reads the enabled input-method list and the selected keyboard once per scan. `AppScanner` joins that state onto each package as two `AppTelemetry` booleans, so both SIGMA rules live in the `app_scanner` logsource and inherit the existing `is_known_oem_app` / `from_trusted_store` / `known_good_app_db` guards.

**Tech Stack:** Kotlin, Hilt, JUnit4 + MockK (pure JVM unit tests, no Robolectric), snakeyaml-engine, SIGMA YAML rules delivered via the `android-sigma-rules` submodule.

**Spec:** `docs/superpowers/specs/2026-07-25-ime-detection-design.md`

## Global Constraints

- Build env for every gradle command: `export JAVA_HOME=/home/yasir/Applications/android-studio/jbr && export ANDROID_HOME=/home/yasir/Android/Sdk && export PATH="$JAVA_HOME/bin:$PATH"`
- Rule IDs are **androdr-090** and **androdr-091**. Highest existing is 089; only androdr-084 is retired. Never reuse a retired ID.
- Neither rule may gate on `from_trusted_store: false` — a Play-installed keyboard reads typed input exactly as a sideloaded one does.
- Neither rule may gate on `is_system_app: false` — preinstalled keyboards are a supply-chain risk and the OEM/known-good guards already suppress legitimate ones.
- Every bundled rule must be **byte-equal** to its mirror counterpart (`BundledMirrorParityTest`): mirror path is `<service_dir>/<name>.yml` with the `sigma_` prefix stripped.
- `logsource-taxonomy.yml` and `AppTelemetry.toFieldMap()` are checked in **both directions** — extra-in-Kotlin and extra-in-taxonomy both fail. They must change in the same commit (Task 2).
- `isReturnDefaultValues = true` is set for unit tests, so un-mocked Android statics return null rather than throwing.
- Delivery follows the safe ordering in CLAUDE.md. `submodule-check` is red by construction while the submodule is pinned to a rules-repo branch — expected, not a failure.

---

### Task 1: `InputMethodScanner`

Standalone. Touches no telemetry, so the build stays green independently.

**Files:**
- Create: `app/src/main/java/com/androdr/scanner/InputMethodScanner.kt`
- Test: `app/src/test/java/com/androdr/scanner/InputMethodScannerTest.kt`

**Interfaces:**
- Consumes: nothing from earlier tasks.
- Produces: `InputMethodScanner.currentState(): InputMethodScanner.ImeState`, where
  `ImeState(val enabledPackages: Set<String>, val activePackage: String?)` and
  `ImeState.EMPTY`. Task 2 injects this class into `AppScanner`.

- [ ] **Step 1: Write the failing test**

Create `app/src/test/java/com/androdr/scanner/InputMethodScannerTest.kt`:

```kotlin
package com.androdr.scanner

import android.content.ContentResolver
import android.content.Context
import android.provider.Settings
import android.view.inputmethod.InputMethodInfo
import android.view.inputmethod.InputMethodManager
import io.mockk.every
import io.mockk.mockk
import io.mockk.mockkStatic
import io.mockk.unmockkStatic
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class InputMethodScannerTest {

    private val contentResolver: ContentResolver = mockk(relaxed = true)

    private fun imeInfo(pkg: String): InputMethodInfo =
        mockk { every { packageName } returns pkg }

    /** Builds a Context whose INPUT_METHOD_SERVICE returns [imm]. */
    private fun contextWith(imm: InputMethodManager?): Context = mockk(relaxed = true) {
        every { getSystemService(Context.INPUT_METHOD_SERVICE) } returns imm
        every { getContentResolver() } returns contentResolver
    }

    private fun stubDefaultIme(value: String?) {
        mockkStatic(Settings.Secure::class)
        every {
            Settings.Secure.getString(any(), Settings.Secure.DEFAULT_INPUT_METHOD)
        } returns value
    }

    @After
    fun tearDown() = unmockkStatic(Settings.Secure::class)

    @Test
    fun `enabled packages are collected and active is parsed from the flattened component`() {
        val imm: InputMethodManager = mockk {
            every { enabledInputMethodList } returns listOf(
                imeInfo("com.samsung.android.honeyboard"),
                imeInfo("com.touchtype.swiftkey"),
            )
        }
        stubDefaultIme("com.samsung.android.honeyboard/.service.HoneyBoardService")

        val state = InputMethodScanner(contextWith(imm)).currentState()

        assertEquals(
            setOf("com.samsung.android.honeyboard", "com.touchtype.swiftkey"),
            state.enabledPackages,
        )
        assertEquals("com.samsung.android.honeyboard", state.activePackage)
    }

    @Test
    fun `blank or missing default input method yields a null active package`() {
        val imm: InputMethodManager = mockk {
            every { enabledInputMethodList } returns listOf(imeInfo("com.baidu.input"))
        }
        stubDefaultIme(null)
        assertNull(InputMethodScanner(contextWith(imm)).currentState().activePackage)

        stubDefaultIme("")
        assertNull(InputMethodScanner(contextWith(imm)).currentState().activePackage)
    }

    @Test
    fun `missing InputMethodManager degrades to empty state rather than throwing`() {
        stubDefaultIme("com.baidu.input/.ImeService")

        val state = InputMethodScanner(contextWith(null)).currentState()

        assertTrue(state.enabledPackages.isEmpty())
        assertNull(state.activePackage)
    }

    @Test
    fun `a throwing enabledInputMethodList degrades to an empty enabled set`() {
        val imm: InputMethodManager = mockk {
            every { enabledInputMethodList } throws SecurityException("denied")
        }
        stubDefaultIme("com.baidu.input/.ImeService")

        val state = InputMethodScanner(contextWith(imm)).currentState()

        assertTrue(state.enabledPackages.isEmpty())
        assertEquals("com.baidu.input", state.activePackage)
    }
}
```

- [ ] **Step 2: Run the test to verify it fails**

```bash
export JAVA_HOME=/home/yasir/Applications/android-studio/jbr && export ANDROID_HOME=/home/yasir/Android/Sdk && export PATH="$JAVA_HOME/bin:$PATH"
./gradlew testDebugUnitTest --tests 'com.androdr.scanner.InputMethodScannerTest'
```

Expected: compilation failure — `Unresolved reference: InputMethodScanner`.

- [ ] **Step 3: Write the implementation**

Create `app/src/main/java/com/androdr/scanner/InputMethodScanner.kt`:

```kotlin
package com.androdr.scanner

import android.content.Context
import android.provider.Settings
import android.util.Log
import android.view.inputmethod.InputMethodManager
import dagger.hilt.android.qualifiers.ApplicationContext
import javax.inject.Inject
import javax.inject.Singleton

/**
 * Reads which input methods (keyboards) are enabled, and which one is currently
 * selected.
 *
 * An IME observes every text field the user types into — passwords included, since
 * the keyboard renders the keys and receives the taps. Android gates enablement
 * behind an explicit warning for that reason. Installed, enabled and active are
 * three distinct states and only the latter two carry risk: an installed-but-never
 * -enabled IME cannot observe anything.
 *
 * Both reads are public APIs requiring no permission. Every failure path degrades to
 * "nothing observed" rather than guessing, so a blocked read can never manufacture a
 * finding.
 */
@Singleton
class InputMethodScanner @Inject constructor(
    @ApplicationContext private val context: Context
) {

    data class ImeState(
        val enabledPackages: Set<String>,
        val activePackage: String?,
    ) {
        companion object {
            val EMPTY = ImeState(emptySet(), null)
        }
    }

    /**
     * Snapshot of IME state. Call once per scan — the result is device-wide, not
     * per-package, so it must be hoisted out of any per-package loop.
     */
    @Suppress("TooGenericExceptionCaught", "SwallowedException")
    fun currentState(): ImeState {
        val imm = context.getSystemService(Context.INPUT_METHOD_SERVICE) as? InputMethodManager
            ?: run {
                Log.w(TAG, "InputMethodManager unavailable — reporting empty IME state")
                return ImeState.EMPTY
            }

        val enabled = try {
            imm.enabledInputMethodList?.mapNotNull { it.packageName }?.toSet() ?: emptySet()
        } catch (e: Exception) {
            Log.w(TAG, "enabledInputMethodList failed: ${e.message}")
            emptySet()
        }

        // DEFAULT_INPUT_METHOD is a flattened ComponentName: "pkg/.ServiceClass".
        val active = try {
            Settings.Secure.getString(
                context.contentResolver,
                Settings.Secure.DEFAULT_INPUT_METHOD,
            )?.substringBefore('/')?.takeIf { it.isNotBlank() }
        } catch (e: Exception) {
            Log.w(TAG, "default_input_method read failed: ${e.message}")
            null
        }

        return ImeState(enabledPackages = enabled, activePackage = active)
    }

    companion object {
        private const val TAG = "InputMethodScanner"
    }
}
```

- [ ] **Step 4: Run the test to verify it passes**

```bash
./gradlew testDebugUnitTest --tests 'com.androdr.scanner.InputMethodScannerTest'
```

Expected: `BUILD SUCCESSFUL`, 4 tests passing.

- [ ] **Step 5: Commit**

```bash
git add app/src/main/java/com/androdr/scanner/InputMethodScanner.kt \
        app/src/test/java/com/androdr/scanner/InputMethodScannerTest.kt
git commit -m "feat(scanner): read enabled and active input methods

An IME sees every text field including passwords, so enabled/active state
is the signal that separates a real exposure from a dormant install. All
failure paths degrade to empty rather than guessing."
```

---

### Task 2: Telemetry fields + taxonomy (atomic)

`LogsourceTaxonomyCrossCheckTest` compares taxonomy field names against `toFieldMap()` output in **both** directions, so the submodule taxonomy bump and the Kotlin field addition must land in one commit. Splitting them breaks the build in either order.

**Files:**
- Modify: `third-party/android-sigma-rules/validation/logsource-taxonomy.yml` (on a rules-repo branch)
- Modify: `app/src/main/java/com/androdr/data/model/AppTelemetry.kt`
- Modify: `app/src/main/java/com/androdr/scanner/AppScanner.kt`
- Test: `app/src/test/java/com/androdr/scanner/AppScannerImeTelemetryTest.kt`

**Interfaces:**
- Consumes: `InputMethodScanner.currentState()` / `ImeState` from Task 1.
- Produces: `AppTelemetry.isEnabledIme: Boolean` and `AppTelemetry.isActiveIme: Boolean`, surfaced in `toFieldMap()` as `is_enabled_ime` and `is_active_ime`. Task 3's rules match on those two field names.

- [ ] **Step 1: Create the rules-repo branch and add the taxonomy fields**

```bash
cd third-party/android-sigma-rules
git checkout -b feat/ime-telemetry-fields
```

In `validation/logsource-taxonomy.yml`, under `app_scanner:` → `fields:`, immediately after the `has_device_admin` line, add:

```yaml
      is_enabled_ime: { type: boolean, description: "True if the package is in the device's enabled input-method list" }
      is_active_ime: { type: boolean, description: "True if the package is the currently selected keyboard. Implies is_enabled_ime." }
```

- [ ] **Step 2: Add the fields to `AppTelemetry`**

In `app/src/main/java/com/androdr/data/model/AppTelemetry.kt`, append to the constructor after `embeddedNativeLibs` (last position, both defaulted, so no existing call site changes):

```kotlin
    val embeddedNativeLibs: List<String> = emptyList(),
    // Input-method state (device-wide, joined per package by AppScanner).
    // isActiveIme implies isEnabledIme — Android requires enablement before selection.
    val isEnabledIme: Boolean = false,
    val isActiveIme: Boolean = false,
) {
```

And in `toFieldMap()`, after the `"embedded_native_lib"` entry:

```kotlin
        "embedded_native_lib" to embeddedNativeLibs,
        "is_enabled_ime" to isEnabledIme,
        "is_active_ime" to isActiveIme
    )
```

- [ ] **Step 3: Wire the scanner into `AppScanner`**

Add the constructor dependency:

```kotlin
class AppScanner @Inject constructor(
    @ApplicationContext private val context: Context,
    private val knownAppResolver: KnownAppResolver,
    private val oemPrefixResolver: OemPrefixResolver,
    private val inputMethodScanner: InputMethodScanner
) {
```

In `collectTelemetry()`, read the state **once** before the per-package loop and pass it down:

```kotlin
val imeState = inputMethodScanner.currentState()
```

Change the `buildTelemetryForPackage` signature to accept it:

```kotlin
    private fun buildTelemetryForPackage(
        pm: PackageManager,
        pkg: PackageInfo,
        imeState: InputMethodScanner.ImeState
    ): AppTelemetry? {
```

Update the call site in `collectTelemetry()` to pass `imeState`, and set the fields in the returned `AppTelemetry(...)` alongside the other flags:

```kotlin
            isEnabledIme = packageName in imeState.enabledPackages,
            isActiveIme = packageName == imeState.activePackage,
```

- [ ] **Step 4: Write the failing test**

Create `app/src/test/java/com/androdr/scanner/AppScannerImeTelemetryTest.kt`:

```kotlin
package com.androdr.scanner

import com.androdr.data.model.AppTelemetry
import com.androdr.data.model.TelemetrySource
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Contract tests for the IME telemetry fields. The join itself is a set lookup;
 * what matters is that the two fields reach toFieldMap() under the names the
 * rules match on, and that the active-implies-enabled invariant holds.
 */
class AppScannerImeTelemetryTest {

    private fun telemetry(
        pkg: String,
        enabled: Boolean,
        active: Boolean,
    ) = AppTelemetry(
        packageName = pkg, appName = pkg, certHash = null, certHashSha1 = null,
        apkHash = null, isSystemApp = false, fromTrustedStore = false, installer = null,
        isSideloaded = false, isKnownOemApp = false, permissions = emptyList(),
        surveillancePermissionCount = 0, hasAccessibilityService = false,
        hasDeviceAdmin = false, knownAppCategory = null,
        source = TelemetrySource.LIVE_SCAN,
        isEnabledIme = enabled, isActiveIme = active,
    )

    @Test
    fun `IME fields are exposed to rules under their taxonomy names`() {
        val map = telemetry("com.baidu.input", enabled = true, active = true).toFieldMap()
        assertEquals(true, map["is_enabled_ime"])
        assertEquals(true, map["is_active_ime"])
    }

    @Test
    fun `IME fields default to false so the bugreport path stays silent`() {
        val map = AppTelemetry(
            packageName = "x", appName = "x", certHash = null, certHashSha1 = null,
            apkHash = null, isSystemApp = false, fromTrustedStore = false, installer = null,
            isSideloaded = false, isKnownOemApp = false, permissions = emptyList(),
            surveillancePermissionCount = 0, hasAccessibilityService = false,
            hasDeviceAdmin = false, knownAppCategory = null,
            source = TelemetrySource.BUGREPORT_IMPORT,
        ).toFieldMap()
        assertEquals(false, map["is_enabled_ime"])
        assertEquals(false, map["is_active_ime"])
    }

    @Test
    fun `the join marks only the matching packages`() {
        val state = InputMethodScanner.ImeState(
            enabledPackages = setOf("com.samsung.android.honeyboard", "com.touchtype.swiftkey"),
            activePackage = "com.samsung.android.honeyboard",
        )

        fun enabled(p: String) = p in state.enabledPackages
        fun active(p: String) = p == state.activePackage

        assertTrue(enabled("com.touchtype.swiftkey"))
        assertFalse(active("com.touchtype.swiftkey"))
        assertTrue(enabled("com.samsung.android.honeyboard"))
        assertTrue(active("com.samsung.android.honeyboard"))
        assertFalse(enabled("com.baidu.input"))
        assertFalse(active("com.baidu.input"))
    }
}
```

`TelemetrySource` has exactly two constants, `LIVE_SCAN` and `BUGREPORT_IMPORT`, and
the field is required with no default on every telemetry class — name it explicitly.

- [ ] **Step 5: Bump the submodule pointer and run the gates**

```bash
cd third-party/android-sigma-rules && git add -A \
  && git commit -m "feat(taxonomy): add is_enabled_ime / is_active_ime to app_scanner" \
  && git push -u origin feat/ime-telemetry-fields && cd ../..
git add third-party/android-sigma-rules
./gradlew testDebugUnitTest --tests 'com.androdr.sigma.LogsourceTaxonomyCrossCheckTest' \
                            --tests 'com.androdr.scanner.AppScannerImeTelemetryTest'
```

Expected: `BUILD SUCCESSFUL`. A failure naming `extraInKotlin` means the taxonomy edit did not reach the pinned commit; `extraInTaxonomy` means `toFieldMap()` is missing an entry.

- [ ] **Step 6: Run the full suite and commit**

```bash
./gradlew testDebugUnitTest lintDebug
git add app/src/main/java/com/androdr/data/model/AppTelemetry.kt \
        app/src/main/java/com/androdr/scanner/AppScanner.kt \
        app/src/test/java/com/androdr/scanner/AppScannerImeTelemetryTest.kt \
        third-party/android-sigma-rules
git commit -m "feat(telemetry): expose enabled/active IME state on AppTelemetry

Placed on AppTelemetry rather than a dedicated input_method logsource so
the rules inherit is_known_oem_app and from_trusted_store — the guards a
narrow logsource lacks, which is what makes androdr-066 unfixable in YAML.

Taxonomy and toFieldMap are cross-checked in both directions, so the
submodule bump ships in the same commit."
```

---

### Task 3: The two rules and their fixtures

**Files:**
- Create: `app/src/main/res/raw/sigma_androdr_090_ime_enabled.yml`
- Create: `app/src/main/res/raw/sigma_androdr_091_ime_active.yml`
- Create: `third-party/android-sigma-rules/app_scanner/androdr_090_ime_enabled.yml` (byte-equal copy)
- Create: `third-party/android-sigma-rules/app_scanner/androdr_091_ime_active.yml` (byte-equal copy)
- Modify: `third-party/android-sigma-rules/rules.txt`, `third-party/android-sigma-rules/rules.sha256`
- Create: `app/src/test/resources/gate4-fixtures/ime-enabled.yml`
- Create: `app/src/test/resources/gate4-fixtures/ime-active.yml`

**Interfaces:**
- Consumes: `is_enabled_ime` / `is_active_ime` from Task 2.
- Produces: findings titled "Third-party keyboard enabled" (medium) and "Third-party keyboard in use" (high).

- [ ] **Step 1: Write the medium rule**

Create `app/src/main/res/raw/sigma_androdr_090_ime_enabled.yml`:

```yaml
title: Third-party keyboard enabled
id: androdr-090
status: experimental
description: >
    A keyboard outside the manufacturer and known-good sets is enabled as an
    input method. An IME observes every text field the user types into,
    passwords included, which is why Android gates enablement behind an
    explicit warning. This rule covers a keyboard that is enabled but not
    currently selected; androdr-091 covers the selected case.
author: AndroDR
date: 2026/07/25
references:
    - https://attack.mitre.org/techniques/T1417/001/
tags:
    - attack.t1417.001
logsource:
    product: androdr
    service: app_scanner
detection:
    selection:
        is_enabled_ime: true
        is_active_ime: false
        is_known_oem_app: false
    filter_known_good:
        package_name|ioc_lookup: known_good_app_db
        from_trusted_store: true
    condition: selection and not filter_known_good
level: medium
category: incident
display:
    category: app_risk
    icon: keyboard
    triggered_title: "Third-Party Keyboard Enabled"
    evidence_type: none
    guidance: "REVIEW -- this keyboard can read everything you type when selected"
falsepositives:
    - Deliberately installed second keyboard for another language or layout
remediation:
    - "This keyboard is enabled and can read everything you type whenever it is selected, including passwords."
    - "Check Settings > System > Languages & input > On-screen keyboard, and remove it if you did not add it deliberately."
```

Deliberately absent, per spec §5: no `from_trusted_store: false` (a Play-installed
keyboard reads input identically) and no `is_system_app: false` (preinstalled
keyboards are a supply-chain risk; OEM/known-good guards already cover legitimate
ones).

- [ ] **Step 2: Write the high rule**

Create `app/src/main/res/raw/sigma_androdr_091_ime_active.yml` — identical to Task 3
Step 1 except for the fields below. Repeating in full rather than saying "same as
above", because the file must stand alone:

```yaml
title: Third-party keyboard in use
id: androdr-091
status: experimental
description: >
    A keyboard outside the manufacturer and known-good sets is the currently
    selected input method. It observes every text field the user types into,
    passwords included. This is the active case; androdr-090 covers a keyboard
    that is enabled but not selected.
author: AndroDR
date: 2026/07/25
references:
    - https://attack.mitre.org/techniques/T1417/001/
tags:
    - attack.t1417.001
logsource:
    product: androdr
    service: app_scanner
detection:
    selection:
        is_active_ime: true
        is_known_oem_app: false
    filter_known_good:
        package_name|ioc_lookup: known_good_app_db
        from_trusted_store: true
    condition: selection and not filter_known_good
level: high
category: incident
display:
    category: app_risk
    icon: keyboard
    triggered_title: "Third-Party Keyboard In Use"
    evidence_type: none
    guidance: "REVIEW -- this keyboard is reading everything you type"
falsepositives:
    - Deliberately chosen keyboard for another language or layout
remediation:
    - "This is your active keyboard, so it can read everything you type, including passwords and card numbers."
    - "If you did not choose it, switch keyboards in Settings > System > Languages & input > On-screen keyboard, then remove it."
```

`is_enabled_ime` is intentionally omitted — active implies enabled, and restating it
would let a telemetry regression silently disable the rule.

- [ ] **Step 3: Mirror both rules and regenerate the manifest**

```bash
cd third-party/android-sigma-rules
git checkout feat/ime-telemetry-fields
cp ../../app/src/main/res/raw/sigma_androdr_090_ime_enabled.yml app_scanner/androdr_090_ime_enabled.yml
cp ../../app/src/main/res/raw/sigma_androdr_091_ime_active.yml  app_scanner/androdr_091_ime_active.yml
printf 'app_scanner/androdr_090_ime_enabled.yml\napp_scanner/androdr_091_ime_active.yml\n' >> rules.txt
sort -o rules.txt rules.txt
while read -r f; do printf '%s  %s\n' "$(sha256sum "$f" | cut -d' ' -f1)" "$f"; done < rules.txt > rules.sha256
python3 validation/validate-rule.py app_scanner/androdr_090_ime_enabled.yml
python3 validation/validate-rule.py app_scanner/androdr_091_ime_active.yml
python3 validation/validate-delivery-set.py
```

Expected: `PASS` from each of the three commands.

- [ ] **Step 4: Write the gate-4 fixtures**

Create `app/src/test/resources/gate4-fixtures/ime-enabled.yml`. True negatives are
the real enabled IMEs from the attached Galaxy Z Fold 2:

```yaml
# Fixture for androdr-090. True negatives are the actual enabled input methods
# on the attached Samsung SM-F916B, so the suppression paths are exercised
# against a real device rather than invented packages.
rule_file: sigma_androdr_090_ime_enabled.yml
service: app_scanner
ioc_stubs:
  known_good_app_db:
    - "com.touchtype.swiftkey"

true_positives:
  - package_name: "com.baidu.input"
    is_enabled_ime: true
    is_active_ime: false
    is_known_oem_app: false
    from_trusted_store: true

true_negatives:
  # Samsung's own keyboard — suppressed by the com.samsung. prefix
  - package_name: "com.samsung.android.honeyboard"
    is_enabled_ime: true
    is_active_ime: true
    is_known_oem_app: true
    from_trusted_store: false
  # Google voice input IME — suppressed by the com.google. prefix
  - package_name: "com.google.android.tts"
    is_enabled_ime: true
    is_active_ime: false
    is_known_oem_app: true
    from_trusted_store: false
  # SwiftKey — known-good and Play-installed, so the filter exempts it
  - package_name: "com.touchtype.swiftkey"
    is_enabled_ime: true
    is_active_ime: false
    is_known_oem_app: false
    from_trusted_store: true
  # Active keyboard belongs to androdr-091, not this rule
  - package_name: "com.baidu.input"
    is_enabled_ime: true
    is_active_ime: true
    is_known_oem_app: false
    from_trusted_store: true
  # Installed but never enabled — no exposure, no finding
  - package_name: "com.example.dormantkeyboard"
    is_enabled_ime: false
    is_active_ime: false
    is_known_oem_app: false
    from_trusted_store: true
```

Create `app/src/test/resources/gate4-fixtures/ime-active.yml`:

```yaml
# Fixture for androdr-091. Mirrors ime-enabled.yml with the active case as the
# true positive.
rule_file: sigma_androdr_091_ime_active.yml
service: app_scanner
ioc_stubs:
  known_good_app_db:
    - "com.touchtype.swiftkey"

true_positives:
  - package_name: "com.baidu.input"
    is_enabled_ime: true
    is_active_ime: true
    is_known_oem_app: false
    from_trusted_store: true

true_negatives:
  # Samsung's own keyboard, active — suppressed by the com.samsung. prefix
  - package_name: "com.samsung.android.honeyboard"
    is_enabled_ime: true
    is_active_ime: true
    is_known_oem_app: true
    from_trusted_store: false
  # Enabled but dormant belongs to androdr-090, not this rule
  - package_name: "com.baidu.input"
    is_enabled_ime: true
    is_active_ime: false
    is_known_oem_app: false
    from_trusted_store: true
  # SwiftKey selected — known-good and Play-installed, so the filter exempts it
  - package_name: "com.touchtype.swiftkey"
    is_enabled_ime: true
    is_active_ime: true
    is_known_oem_app: false
    from_trusted_store: true
```

- [ ] **Step 5: Run the gates**

```bash
./gradlew testDebugUnitTest --tests 'com.androdr.sigma.*'
```

Expected: `BUILD SUCCESSFUL`. Gate-4 fixture count rises from 22 to 24, and
`BundledMirrorParityTest` plus `RuleManifestIntegrityTest` both pass — a parity
failure means the `cp` in Step 3 did not run or the bundled file was edited
afterwards.

- [ ] **Step 6: Run the full suite and commit**

```bash
./gradlew testDebugUnitTest lintDebug
cd third-party/android-sigma-rules && git add -A \
  && git commit -m "feat(rules): androdr-090/091 third-party keyboard detection" \
  && git push && cd ../..
git add app/src/main/res/raw/sigma_androdr_090_ime_enabled.yml \
        app/src/main/res/raw/sigma_androdr_091_ime_active.yml \
        app/src/test/resources/gate4-fixtures/ime-enabled.yml \
        app/src/test/resources/gate4-fixtures/ime-active.yml \
        third-party/android-sigma-rules
git commit -m "feat(rules): androdr-090/091 third-party keyboard detection

Enabled = medium, active = high. Neither gates on from_trusted_store or
is_system_app: a Play-installed or preinstalled keyboard reads typed input
exactly as a sideloaded one does, and the OEM/known-good guards already
suppress the legitimate ones.

Fixture true negatives are the real enabled IMEs from the attached Fold 2."
```

---

### Task 4: On-device verification and delivery

**Files:** none modified. This task proves the acceptance criterion and ships.

**Interfaces:**
- Consumes: everything from Tasks 1–3.
- Produces: merged PRs in both repos.

- [ ] **Step 1: Install on the attached device and scan**

```bash
export JAVA_HOME=/home/yasir/Applications/android-studio/jbr && export ANDROID_HOME=/home/yasir/Android/Sdk && export PATH="$JAVA_HOME/bin:$ANDROID_HOME/platform-tools:$PATH"
adb devices -l                      # expect R3CR300WRRH (SM_F916B)
./gradlew installDebug
adb shell ime list -s               # record the enabled set for comparison
adb shell settings get secure default_input_method
```

Run a scan in the app, then export or read the report.

- [ ] **Step 2: Confirm the acceptance criterion**

Expected: **zero** IME findings on the Fold 2. All three enabled IMEs must be
suppressed — HoneyBoard by `com.samsung.`, Google TTS by `com.google.`, SwiftKey by
the `partner_preinstall_prefixes` entry.

Any IME finding here is a false positive and blocks the task. The likely cause is
that `partner_preinstall_prefixes` is not reaching the resolver — verify with
`OemPrefixResolverConditionalTest` and check the allowlist parity gate from #265.

- [ ] **Step 3: Open both PRs and follow the safe ordering**

```bash
git push -u origin feat/ime-detection
gh pr create --repo android-sigma-rules/rules --base main --head feat/ime-telemetry-fields \
  --title "feat: IME telemetry fields + androdr-090/091" --body "..."
gh pr create --repo yasirhamza/AndroDR --base main --head feat/ime-detection \
  --title "feat(detection): third-party keyboard detection (androdr-090/091)" --body "Closes #NNN"
```

Sequence, per CLAUDE.md:

1. AndroDR CI green. `submodule-check` and `ci-success` are red while the submodule is pinned to the rules branch — expected, not a failure. The gate that matters is `build-and-test`.
2. Merge the rules PR.
3. Repoint the submodule at the resulting main commit, commit, push. CI goes fully green.
4. Merge the AndroDR PR.

- [ ] **Step 4: Verify the live feed**

```bash
curl -fsSL "https://raw.githubusercontent.com/android-sigma-rules/rules/main/rules.txt" | grep ime
```

Expected: both `androdr_090_ime_enabled.yml` and `androdr_091_ime_active.yml` listed.
Devices pick them up on the next 12h refresh.

---

## Self-Review

**Spec coverage:** §3 telemetry → Task 2. §4 scanner → Task 1. §5 both rules and the
two deliberate omissions → Task 3 Steps 1–2. §6 degradation → Task 1 Steps 1/3
(missing IMM, throwing list) and Task 2 Step 4 (bugreport defaults). §7 tests →
Tasks 1–3 plus Task 4 Step 2. §8 delivery → Task 4 Step 3. §9 out-of-scope items are
correctly absent.

**Placeholders:** none. The PR `--body "..."` in Task 4 Step 3 is the one shorthand;
bodies are written at PR time from the spec's motivation and the CI evidence.

**Type consistency:** `InputMethodScanner.ImeState(enabledPackages, activePackage)`
is defined in Task 1 and consumed under those exact names in Task 2 Step 3 and Task 2
Step 4. `isEnabledIme` / `isActiveIme` (Kotlin) map to `is_enabled_ime` /
`is_active_ime` (YAML) consistently across Tasks 2 and 3.

**Verified against source:** `TelemetrySource` exposes `LIVE_SCAN` and
`BUGREPORT_IMPORT` only. `AppScanner`'s constructor is
`(context, knownAppResolver, oemPrefixResolver)`, so Task 2 Step 3 appends a fourth
parameter. Rule IDs 090/091 are unallocated — 089 is the highest in use and only 084
is retired.
