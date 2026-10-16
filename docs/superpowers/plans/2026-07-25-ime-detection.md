# IME Detection Implementation Plan

> ## ⚠️ SUPERSEDED — DO NOT EXECUTE
>
> This plan implements the 2026-07-25 design, which was replaced on 2026-07-26 after
> two blocking defects were verified against shipped data (see the spec's §11):
>
> 1. **Task 4 builds `androdr-092`**, whose selection is the exact OPPO preload shape
>    (`is_known_oem_app: true` + `is_system_app: false` + `from_trusted_store: false`)
>    that PR #264 had just excluded — re-firing that false positive at `level: high`.
> 2. **Tasks 4's rules carry `is_known_oem_app: false`**, which suppresses the Baidu,
>    Sogou and iFlytek vendor variants outright, so they cannot flag the threat class
>    the feature exists to find.
>
> The rewritten design also splits delivery into two phases, the first of which needs
> no scanner, no telemetry fields and no taxonomy change — so Tasks 1, 2a and 2b are
> no longer Phase 1 work at all.
>
> Read `docs/superpowers/specs/2026-07-25-ime-detection-design.md` and write a fresh
> plan from it.

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** ~~Detect third-party keyboards that are enabled (low), actively selected (medium), or squatting a manufacturer namespace (high)~~ — superseded, see banner above.

**Architecture:** `InputMethodScanner` reads the enabled input-method list and the selected keyboard once per scan as its own tracked scanner. `ScanOrchestrator` joins that device-wide state onto each `AppTelemetry` record, so all three SIGMA rules live in the `app_scanner` logsource. Exemption is a purpose-built `known_good_ime_db`, not the general app allowlist.

**Tech Stack:** Kotlin, Hilt, JUnit4 + MockK (pure JVM, no Robolectric), snakeyaml-engine, SIGMA YAML delivered via the `android-sigma-rules` submodule.

**Spec:** `docs/superpowers/specs/2026-07-25-ime-detection-design.md` (revised after the 2026-07-25 four-agent plan gate)

## Global Constraints

- Build env for every gradle command: `export JAVA_HOME=/home/yasir/Applications/android-studio/jbr && export ANDROID_HOME=/home/yasir/Android/Sdk && export PATH="$JAVA_HOME/bin:$ANDROID_HOME/platform-tools:$PATH"`
- **Every command block runs from `/home/yasir/AndroDR`.** Submodule work uses `git -C third-party/android-sigma-rules …` — never bare `cd`, which stranded the previous draft's later steps in the wrong directory.
- Rule IDs **090, 091, 092**. 089 is highest in use; 084 is the only retired ID.
- Severities: 090 `low`, 091 `medium`, 092 `high`. `high` on 090/091 would violate the MANDATORY multi-condition rule at `.claude/commands/update-rules-author.md:165`; 092 earns it on two independent conditions.
- Exemption is `known_good_ime_db` only. Never `known_good_app_db` — it classifies the Baidu/Sogou/iFlytek vendor variants as `OEM`, and `PlexusKnownAppFeed` writes every entry as `USER_APP`, which `TRUSTED_CATEGORIES` accepts.
- Neither 090 nor 091 gates on `from_trusted_store` or `is_system_app`.
- Bundled rules must be **byte-equal** to their mirror counterparts; same for `known_good_imes.yml` across bundle, mirror, and test fixture.
- Verification commands are `./gradlew testDebugUnitTest lintDebug detekt` — CI runs `detekt` (`ci.yml:140`).
- Manifest regeneration uses `LC_ALL=C sort` — `rules.txt` is C-collated and the default locale reorders it.
- Delivery follows CLAUDE.md safe ordering. `submodule-check` is red by construction while pinned to a rules branch.

- [ ] **Task 0: Create the working branch**

```bash
cd /home/yasir/AndroDR && git checkout -b feat/ime-detection
git -C third-party/android-sigma-rules checkout -b feat/ime-detection
```

---

### Task 1: `InputMethodScanner`

Standalone; touches no telemetry.

**Files:**
- Create: `app/src/main/java/com/androdr/scanner/InputMethodScanner.kt`
- Test: `app/src/test/java/com/androdr/scanner/InputMethodScannerTest.kt`

**Interfaces:**
- Produces: `InputMethodScanner.currentState(): ImeState`, with
  `ImeState(enabledPackages: Set<String>, activePackage: String?)`, methods
  `isEnabled(pkg): Boolean` / `isActive(pkg): Boolean`, and `ImeState.EMPTY`.
  Task 2b consumes all four.

- [ ] **Step 1: Write the failing tests**

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

    /** Spec §3: is_active_ime implies is_enabled_ime, on every path. */
    private fun assertInvariant(state: InputMethodScanner.ImeState) {
        val active = state.activePackage
        if (active != null) {
            assertTrue(
                "invariant violated: active=$active absent from enabled=${state.enabledPackages}",
                state.isEnabled(active),
            )
        }
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
        assertTrue(state.isActive("com.samsung.android.honeyboard"))
        assertTrue(state.isEnabled("com.touchtype.swiftkey"))
        assertTrue(!state.isActive("com.touchtype.swiftkey"))
        assertInvariant(state)
    }

    @Test
    fun `blank or missing default input method yields a null active package`() {
        val imm: InputMethodManager = mockk {
            every { enabledInputMethodList } returns listOf(imeInfo("com.baidu.input"))
        }
        stubDefaultIme(null)
        InputMethodScanner(contextWith(imm)).currentState().let {
            assertNull(it.activePackage); assertInvariant(it)
        }

        stubDefaultIme("")
        InputMethodScanner(contextWith(imm)).currentState().let {
            assertNull(it.activePackage); assertInvariant(it)
        }
    }

    @Test
    fun `missing InputMethodManager degrades to empty state`() {
        stubDefaultIme("com.baidu.input/.ImeService")
        val state = InputMethodScanner(contextWith(null)).currentState()
        assertTrue(state.enabledPackages.isEmpty())
        assertNull(state.activePackage)
        assertInvariant(state)
    }

    /**
     * The two reads fail independently. A throwing enabled-list with a readable
     * default must NOT yield is_active_ime=true alongside is_enabled_ime=false —
     * androdr-091 omits is_enabled_ime and would fire on the contradictory state.
     */
    @Test
    fun `a throwing enabled list still upholds the invariant`() {
        val imm: InputMethodManager = mockk {
            every { enabledInputMethodList } throws SecurityException("denied")
        }
        stubDefaultIme("com.baidu.input/.ImeService")

        val state = InputMethodScanner(contextWith(imm)).currentState()

        assertEquals("com.baidu.input", state.activePackage)
        assertTrue(state.isEnabled("com.baidu.input"))
        assertInvariant(state)
    }
}
```

- [ ] **Step 2: Run to verify failure**

```bash
cd /home/yasir/AndroDR && ./gradlew testDebugUnitTest --tests 'com.androdr.scanner.InputMethodScannerTest'
```

Expected: compilation failure, `Unresolved reference: InputMethodScanner`.

- [ ] **Step 3: Implement**

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
 * Reads which input methods (keyboards) are enabled and which one is selected.
 *
 * An IME observes every text field the user types into, passwords included, which
 * is why Android gates enablement behind an explicit warning. Installed, enabled
 * and active are three distinct states; only the latter two carry exposure.
 *
 * Both reads are public APIs requiring no permission, and they fail independently —
 * see [currentState] for why the active package is folded into the enabled set.
 */
@Singleton
class InputMethodScanner @Inject constructor(
    @ApplicationContext private val context: Context
) {

    data class ImeState(
        val enabledPackages: Set<String>,
        val activePackage: String?,
    ) {
        fun isEnabled(pkg: String): Boolean = pkg in enabledPackages
        fun isActive(pkg: String): Boolean = pkg == activePackage

        companion object {
            val EMPTY = ImeState(emptySet(), null)
        }
    }

    /**
     * Snapshot of IME state — device-wide, not per-package. Called once per scan by
     * [ScanOrchestrator], which joins it onto each AppTelemetry record.
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

        // The invariant (active implies enabled) is enforced HERE rather than asserted
        // downstream: the two reads above fail independently, so a throwing enabled-list
        // with a readable default would otherwise produce is_active_ime=true alongside
        // is_enabled_ime=false. androdr-091 omits is_enabled_ime by design and would
        // fire on that contradictory state.
        return ImeState(
            enabledPackages = enabled + listOfNotNull(active),
            activePackage = active,
        )
    }

    companion object {
        private const val TAG = "InputMethodScanner"
    }
}
```

- [ ] **Step 4: Run to verify pass**

```bash
cd /home/yasir/AndroDR && ./gradlew testDebugUnitTest --tests 'com.androdr.scanner.InputMethodScannerTest'
```

Expected: `BUILD SUCCESSFUL`, 4 tests.

- [ ] **Step 5: Commit**

```bash
cd /home/yasir/AndroDR
git add app/src/main/java/com/androdr/scanner/InputMethodScanner.kt \
        app/src/test/java/com/androdr/scanner/InputMethodScannerTest.kt
git commit -m "feat(scanner): read enabled and active input methods

The two underlying reads fail independently, so the active-implies-enabled
invariant is enforced by construction rather than asserted downstream."
```

---

### Task 2a: Telemetry fields + taxonomy (atomic)

`LogsourceTaxonomyCrossCheckTest` compares taxonomy names against `toFieldMap()` output in **both** directions (`extraInKotlin` and `extraInTaxonomy`), so these must land together. Note it reads the **working-tree** YAML, not the pinned commit.

**Files:**
- Modify: `third-party/android-sigma-rules/validation/logsource-taxonomy.yml`
- Modify: `app/src/main/java/com/androdr/data/model/AppTelemetry.kt`

**Interfaces:**
- Produces: `AppTelemetry.isEnabledIme` / `.isActiveIme`, exposed as `is_enabled_ime` / `is_active_ime`. Task 2b sets them; Task 4's rules match them.

- [ ] **Step 1: Add both taxonomy fields**

In `third-party/android-sigma-rules/validation/logsource-taxonomy.yml`, under `app_scanner:` → `fields:`, after the `embedded_native_lib` entry (matching the Kotlin insertion point in Step 2):

```yaml
      is_enabled_ime: { type: boolean, description: "True if the package is in the device's enabled input-method list" }
      is_active_ime: { type: boolean, description: "True if the package is the currently selected keyboard. Implies is_enabled_ime." }
```

- [ ] **Step 2: Add both fields to `AppTelemetry`**

In `app/src/main/java/com/androdr/data/model/AppTelemetry.kt`, append after `embeddedNativeLibs` (last position, both defaulted — all three construction sites use named arguments, so none break):

```kotlin
    val embeddedNativeLibs: List<String> = emptyList(),
    // Device-wide input-method state, joined per package by ScanOrchestrator.
    // isActiveIme implies isEnabledIme — enforced in InputMethodScanner.currentState().
    val isEnabledIme: Boolean = false,
    val isActiveIme: Boolean = false,
) {
```

and in `toFieldMap()`, after `"embedded_native_lib"`:

```kotlin
        "embedded_native_lib" to embeddedNativeLibs,
        "is_enabled_ime" to isEnabledIme,
        "is_active_ime" to isActiveIme
    )
```

- [ ] **Step 3: Run the lockstep gate**

```bash
cd /home/yasir/AndroDR && ./gradlew testDebugUnitTest --tests 'com.androdr.sigma.LogsourceTaxonomyCrossCheckTest'
```

Expected: `BUILD SUCCESSFUL`. `extraInKotlin` ⇒ the on-disk taxonomy YAML is missing a field; `extraInTaxonomy` ⇒ `toFieldMap()` is missing an entry.

- [ ] **Step 4: Commit both halves together**

```bash
cd /home/yasir/AndroDR
git -C third-party/android-sigma-rules add validation/logsource-taxonomy.yml
git -C third-party/android-sigma-rules commit -m "feat(taxonomy): add is_enabled_ime / is_active_ime to app_scanner"
git add app/src/main/java/com/androdr/data/model/AppTelemetry.kt third-party/android-sigma-rules
git commit -m "feat(telemetry): add IME state fields to AppTelemetry

Taxonomy and toFieldMap are cross-checked in both directions, so the
submodule bump ships in the same commit."
```

---

### Task 2b: Orchestrator registration and join

**Files:**
- Modify: `app/src/main/java/com/androdr/scanner/ScanOrchestrator.kt`
- Test: `app/src/test/java/com/androdr/scanner/ScanOrchestratorImeJoinTest.kt`

**Interfaces:**
- Consumes: `InputMethodScanner` (Task 1), `AppTelemetry.isEnabledIme/isActiveIme` (Task 2a).

`AppScanner` is deliberately **not** modified. Injecting the IME read there would nest it inside `trackedAsync("appScanner", scannerErrors, emptyList())`, so a throw would zero all app telemetry and silence every `app_scanner` rule. Keeping `AppScanner`'s constructor unchanged also leaves `AppScannerTelemetryTest:72`'s positional construction valid.

- [ ] **Step 1: Inject and register as the ninth tracked scanner**

Add `private val inputMethodScanner: InputMethodScanner` to `ScanOrchestrator`'s constructor. Bump `SCANNER_COUNT` from 8 to 9 (and its keep-in-sync comment). Alongside the other `trackedAsync` calls near line 237:

```kotlin
        val imeStateDeferred = trackedAsync(
            "inputMethodScanner", scannerErrors, InputMethodScanner.ImeState.EMPTY
        ) {
            inputMethodScanner.currentState()
        }
```

- [ ] **Step 2: Join at the composition point**

Where `appTelemetryDeferred.await()` is consumed, replace the awaited value with:

```kotlin
        val imeState = imeStateDeferred.await()
        val appTelemetry = appTelemetryDeferred.await().map {
            it.copy(
                isEnabledIme = imeState.isEnabled(it.packageName),
                isActiveIme = imeState.isActive(it.packageName),
            )
        }
```

- [ ] **Step 3: Write the join test**

Create `app/src/test/java/com/androdr/scanner/ScanOrchestratorImeJoinTest.kt`. Model the Hilt-free construction on `ScanOrchestratorErrorHandlingTest.kt`, which already builds a `ScanOrchestrator` with mocked scanners; mirror its `setUp()` and add:

```kotlin
    @Test
    fun `IME state is joined onto the matching packages only`() = runTest {
        every { inputMethodScanner.currentState() } returns InputMethodScanner.ImeState(
            enabledPackages = setOf("com.samsung.android.honeyboard", "com.touchtype.swiftkey"),
            activePackage = "com.samsung.android.honeyboard",
        )
        every { appScanner.collectTelemetry() } returns listOf(
            appTelemetry("com.samsung.android.honeyboard"),
            appTelemetry("com.touchtype.swiftkey"),
            appTelemetry("com.baidu.input"),
        )

        val result = orchestrator.runFullScan()
        val rows = orchestrator.lastAppTelemetry.associateBy { it.packageName }

        assertTrue(rows.getValue("com.samsung.android.honeyboard").isActiveIme)
        assertTrue(rows.getValue("com.touchtype.swiftkey").isEnabledIme)
        assertFalse(rows.getValue("com.touchtype.swiftkey").isActiveIme)
        assertFalse(rows.getValue("com.baidu.input").isEnabledIme)
        assertTrue(rows.values.none { it.isActiveIme && !it.isEnabledIme })
        verify(exactly = 1) { inputMethodScanner.currentState() }   // hoisted out of the loop
    }

    @Test
    fun `a failing IME read does not zero app telemetry`() = runTest {
        every { inputMethodScanner.currentState() } throws SecurityException("denied")
        every { appScanner.collectTelemetry() } returns listOf(appTelemetry("com.baidu.input"))

        val result = orchestrator.runFullScan()

        assertEquals(1, orchestrator.lastAppTelemetry.size)   // app telemetry survives
        assertTrue(result.scannerErrors.any { it.scanner == "inputMethodScanner" })
    }
```

`appTelemetry(pkg)` is a local helper building a minimal `AppTelemetry` with named
arguments and `source = TelemetrySource.LIVE_SCAN`. Adapt the accessor for
`lastAppTelemetry` / `runFullScan`'s return to whatever
`ScanOrchestratorErrorHandlingTest` already uses.

- [ ] **Step 4: Verify and commit**

```bash
cd /home/yasir/AndroDR && ./gradlew testDebugUnitTest lintDebug detekt
git add app/src/main/java/com/androdr/scanner/ScanOrchestrator.kt \
        app/src/test/java/com/androdr/scanner/ScanOrchestratorImeJoinTest.kt
git commit -m "feat(scan): join IME state onto app telemetry in the orchestrator

Registered as a ninth tracked scanner rather than injected into AppScanner:
nesting it there would put the read inside trackedAsync(\"appScanner\", ...,
emptyList()), so a throw would zero all app telemetry and silence every
app_scanner rule."
```

---

### Task 3: `known_good_ime_db`

**Files:**
- Create: `third-party/android-sigma-rules/ioc-data/known-good-imes.yml`
- Create: `app/src/main/res/raw/known_good_imes.yml` (byte-equal)
- Create: `app/src/test/resources/raw/known_good_imes.yml` (byte-equal)
- Modify: `third-party/android-sigma-rules/validation/ioc-lookup-definitions.yml`
- Create: `app/src/main/java/com/androdr/ioc/KnownGoodImeResolver.kt`
- Modify: `app/src/main/java/com/androdr/scanner/ScanOrchestrator.kt` (`initRuleEngine`)
- Test: `app/src/test/java/com/androdr/ioc/KnownGoodImeResolverTest.kt`, `.../KnownGoodImeParityTest.kt`

**Interfaces:**
- Produces: IOC lookup name `known_good_ime_db`, matched by Task 4's rules.

- [ ] **Step 1: Author the allowlist**

Create `third-party/android-sigma-rules/ioc-data/known-good-imes.yml`. Include the OEM stock keyboards (Samsung HoneyBoard, Gboard, the Google TTS voice IME, ColorOS/MIUI/Vivo/HONOR stock), SwiftKey, and the FOSS set: `org.dslul.openboard.inputmethod.latin`, `helium314.keyboard`, `org.futo.inputmethod.latin`, `com.menny.android.anysoftkeyboard`, `rkr.simplekeyboard.inputmethod`, `org.pocketworkstation.pckeyboard`, `com.simplemobiletools.keyboard`, `juloo.keyboard2`.

**Must not appear:** any `com.baidu.input*`, `com.sohu.inputmethod.*`, `com.iflytek.inputmethod.*`, `com.emoji.keyboard.touchpal`, `com.simejikeyboard`, `com.adamrocker.android.input.simeji`.

Follow the `entries:` shape used by the other `ioc-data/*.yml` files so
`validate-ioc-data.py` exercises provenance rather than short-circuiting.

- [ ] **Step 2: Declare the lookup**

In `third-party/android-sigma-rules/validation/ioc-lookup-definitions.yml`, under `lookups:`:

```yaml
  known_good_ime_db:
    type: PACKAGE_NAME
    files: [ioc-data/known-good-imes.yml]
    description: "Curated allowlist of input methods (keyboards) that are not flagged by androdr-090/091. Deliberately separate from known_good_app_db, which classifies vendor cloud keyboards as OEM and accepts the Plexus USER_APP catch-all."
```

- [ ] **Step 3: Resolver, wiring, and the three-way parity gate**

Create `KnownGoodImeResolver` modelled directly on `OemPrefixResolver`: bundled
`R.raw.known_good_imes` load, a `refresh()` fetching
`ioc-data/known-good-imes.yml` from rules main, and a `contains(pkg): Boolean`.
Register it in `ScanOrchestrator.initRuleEngine()`'s `setIocLookups` map:

```kotlin
            "known_good_ime_db" to { v -> knownGoodImeResolver.contains(v.toString()) },
```

Create `KnownGoodImeParityTest` by copying `OemPrefixMirrorParityTest` and
substituting the three `known_good_imes.yml` paths — same CI-hard-fail behaviour,
same negative test.

- [ ] **Step 4: Verify and commit**

```bash
cd /home/yasir/AndroDR
python3 third-party/android-sigma-rules/validation/validate-ioc-data.py third-party/android-sigma-rules/ioc-data/known-good-imes.yml
./gradlew testDebugUnitTest --tests 'com.androdr.sigma.IocLookupDefinitionsCrossCheckTest' --tests 'com.androdr.ioc.*'
./gradlew testDebugUnitTest lintDebug detekt
git -C third-party/android-sigma-rules add -A
git -C third-party/android-sigma-rules commit -m "feat(ioc-data): curated known-good input-method allowlist"
git add -A && git commit -m "feat(ioc): known_good_ime_db lookup + three-way parity gate"
```

---

### Task 4: The three rules, fixtures, and loader registration

**Files:**
- Create: `app/src/main/res/raw/sigma_androdr_09{0,1,2}_*.yml` and byte-equal mirrors in `third-party/android-sigma-rules/app_scanner/`
- Modify: `app/src/main/java/com/androdr/sigma/SigmaRuleEngine.kt` (`BUNDLED_RULE_IDS`)
- Modify: `third-party/android-sigma-rules/rules.txt`, `rules.sha256`
- Create: three gate-4 fixtures; `app/src/test/java/com/androdr/scanner/ImeClassificationTest.kt`; `app/src/test/java/com/androdr/sigma/RuleFieldNameTaxonomyTest.kt`

- [ ] **Step 1: Write the three rules**

Per spec §5. `androdr-090` (`level: low`, no ATT&CK tag), `androdr-091`
(`level: medium`, `tags: [attack.t1417.001]`), `androdr-092` (`level: high`,
`tags: [attack.t1036.005]`). Each written out in full — no cross-references between
files. `filter_known_good` uses `package_name|ioc_lookup: known_good_ime_db` with
**no** `from_trusted_store` clause. Match `androdr-089`'s key ordering (`category:`
immediately after `status:`). `falsepositives` must name accessibility keyboards,
MDM-managed keyboards, non-Latin-script layouts, and deliberately installed second
keyboards. Remediation says a keyboard **can** read what you type, keeps the Settings
path manufacturer-agnostic, and adds the managed-device line from spec §5.

- [ ] **Step 2: Register in the loader manifest**

In `app/src/main/java/com/androdr/sigma/SigmaRuleEngine.kt`, after
`R.raw.sigma_androdr_089_sms_notification_otp_theft` (line ~356):

```kotlin
            R.raw.sigma_androdr_090_ime_enabled,
            R.raw.sigma_androdr_091_ime_active,
            R.raw.sigma_androdr_092_ime_oem_namespace,
```

`BUNDLED_RULE_IDS` is an explicit R8-safe list; `BundledRulesManifestCompletenessTest`
fails without this, and skipping it would ship rules that never load — making Task 5's
on-device check pass vacuously.

- [ ] **Step 3: Mirror and regenerate the manifest**

```bash
cd /home/yasir/AndroDR
for n in 090_ime_enabled 091_ime_active 092_ime_oem_namespace; do
  cp "app/src/main/res/raw/sigma_androdr_$n.yml" "third-party/android-sigma-rules/app_scanner/androdr_$n.yml"
  printf 'app_scanner/androdr_%s.yml\n' "$n" >> third-party/android-sigma-rules/rules.txt
done
LC_ALL=C sort -o third-party/android-sigma-rules/rules.txt third-party/android-sigma-rules/rules.txt
( cd third-party/android-sigma-rules && while read -r f; do printf '%s  %s\n' "$(sha256sum "$f" | cut -d' ' -f1)" "$f"; done < rules.txt > rules.sha256 )
for n in 090_ime_enabled 091_ime_active 092_ime_oem_namespace; do
  python3 third-party/android-sigma-rules/validation/validate-rule.py "third-party/android-sigma-rules/app_scanner/androdr_$n.yml"
done
python3 third-party/android-sigma-rules/validation/validate-delivery-set.py
```

Expected: `PASS` from all four validator invocations.

- [ ] **Step 4: Gate-4 fixtures**

One per rule. True negatives use **real** values: SwiftKey carries
`is_known_oem_app: true` (its actual value via `partner_preinstall_prefixes`), with
the `known_good_ime_db` path covered by a separate, explicitly synthetic package.
Include a `com.baidu.input_mi`-shaped record with `is_known_oem_app: true` as a
documented true negative for 090/091 and a **true positive** for 092.

- [ ] **Step 5: Close the two blind spots the review found**

`ImeClassificationTest` runs `com.baidu.input_mi`,
`com.google.android.inputmethod.latin2` and `com.samsung.evilkeyboard` through the
real `KnownAppResolver` / `OemPrefixResolver` and asserts the resulting
`is_known_oem_app`. Gate-4 feeds field values verbatim and is structurally blind to
this class; this test is what documents why 092 exists.

`RuleFieldNameTaxonomyTest` iterates every bundled rule's detection keys (stripping
`|modifiers`) and asserts each is declared in `logsource-taxonomy.yml` for that
rule's `service`. A typo like `is_ime_enabled` otherwise passes every existing gate
and is silently dead on-device — the class #225 closed for permission literals.

- [ ] **Step 6: Verify and commit**

```bash
cd /home/yasir/AndroDR && ./gradlew testDebugUnitTest lintDebug detekt
```

Expected: gate-4 fixture count 22 → 25; `BundledMirrorParityTest`,
`RuleManifestIntegrityTest`, `BundledRulesManifestCompletenessTest` all green.

---

### Task 5: Adversary fixture and on-device verification

**Files:**
- Create: `test-adversary/fixtures/mercenary/ime-abuse/`

- [ ] **Step 1: Build the fixture**

A minimal app declaring an `InputMethodService` with
`android.permission.BIND_INPUT_METHOD`, named to a package absent from every
allowlist. Follow the layout of the sibling `overlay-permission` fixture.

- [ ] **Step 2: True positive on device**

```bash
cd /home/yasir/AndroDR && adb devices -l          # expect R3CR300WRRH (SM_F916B)
./gradlew installDebug
adb install -r test-adversary/fixtures/mercenary/ime-abuse/app-debug.apk
adb shell ime enable <fixture-ime-id>
adb shell ime set <fixture-ime-id>
```

Scan, then assert androdr-091 fired for the fixture package. Restore with
`adb shell ime reset` and uninstall.

- [ ] **Step 3: Zero-false-positive baseline**

With the fixture removed, scan again. Expected: **zero** findings from 090/091/092.
All three of the Fold 2's enabled IMEs must be suppressed — HoneyBoard by
`com.samsung.`, Google TTS by `com.google.`, SwiftKey by `partner_preinstall_prefixes`.

Read findings from the DB rather than by eye, and pull the `-wal` sidecar or recent
writes are invisible:

```bash
adb exec-out run-as com.androdr.debug cat databases/androdr.db > /tmp/androdr.db
adb exec-out run-as com.androdr.debug cat databases/androdr.db-wal > /tmp/androdr.db-wal
```

Assert both that no `androdr-09*` finding exists **and** that total findings > 0, so
a failed or empty scan cannot masquerade as a clean result.

---

### Task 6: Delivery

- [ ] **Step 1: Open both PRs**

```bash
cd /home/yasir/AndroDR
git -C third-party/android-sigma-rules push -u origin feat/ime-detection
git push -u origin feat/ime-detection
gh pr create --repo android-sigma-rules/rules --base main --head feat/ime-detection \
  --title "feat: IME telemetry fields, known-good-imes allowlist, androdr-090/091/092"
gh pr create --repo yasirhamza/AndroDR --base main --head feat/ime-detection \
  --title "feat(detection): third-party keyboard detection (androdr-090/091/092)"
```

PR bodies are written at creation time from spec §1 motivation, the review record in
§10, and the CI evidence. Resolve the tracking issue number and use `Closes #N`.

- [ ] **Step 2: Safe ordering**

1. AndroDR CI green. `submodule-check` and `ci-success` red while pinned to the rules branch — expected; the gate that matters is `build-and-test`.
2. Merge the rules PR.
3. Repoint the submodule at the resulting main commit, commit, push; CI goes fully green.
4. Merge the AndroDR PR.

- [ ] **Step 3: Confirm live delivery**

```bash
curl -fsSL "https://raw.githubusercontent.com/android-sigma-rules/rules/main/rules.txt" | grep ime
curl -fsSL "https://raw.githubusercontent.com/android-sigma-rules/rules/main/ioc-data/known-good-imes.yml" | head -5
```

Both rule files listed and the allowlist served. Devices pick them up within 12h.

---

## Self-Review

**Spec coverage:** §3 → Task 2a. §4 scanner and invariant → Task 1; orchestrator join → Task 2b. §5 rules → Task 4 Step 1; `known_good_ime_db` → Task 3; androdr-092 → Task 4. §6 degradation → Task 1 Steps 1/3 and Task 2b Step 3's failure test. §7 → Tasks 1–5, including the two blind-spot tests at Task 4 Step 5. §8 → Task 6. §9 items correctly absent.

**Placeholders:** none. `<fixture-ime-id>` in Task 5 is a value the fixture's own manifest determines and `adb shell ime list -a` prints.

**Type consistency:** `ImeState(enabledPackages, activePackage)` with `isEnabled`/`isActive`/`EMPTY` defined in Task 1 and consumed under those names in Tasks 2b. `isEnabledIme`/`isActiveIme` (Kotlin) ↔ `is_enabled_ime`/`is_active_ime` (YAML) consistent across 2a, 2b and 4.

**Review findings addressed:** loader registration (Task 4 Step 2); `AppScanner` constructor untouched, so no positional-construction break; invariant by construction (Task 1 Step 3); real-scanner join test replacing the tautological one (Task 2b Step 3); working directories anchored throughout; `detekt` added; `LC_ALL=C` sort; branch creation (Task 0); fixture provenance corrected (Task 4 Step 4); positive acceptance criterion (Task 5 Step 2); field-name gate (Task 4 Step 5).
