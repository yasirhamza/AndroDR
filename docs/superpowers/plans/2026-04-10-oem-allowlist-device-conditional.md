# OEM Allowlist Device-Conditionality — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Tracking issue:** #90
**Branch:** `claude/oem-allowlist-device-conditional`
**Baseline:** `main` at `feb18f77` (post-PR-89)

**Goal:** Make the OEM allowlist device-conditional. Samsung prefixes should only be trusted when the device being assessed is a Samsung device. Xiaomi prefixes only when assessing Xiaomi/Redmi/Poco. Unconditional prefixes (AOSP, chipset, trusted installers, Android Go) stay unconditional. Close the prefix-spoofing attack vector documented in #90.

**Architecture:**
- Restructure `known_oem_prefixes.yml` into two top-level sections: `unconditional` (AOSP, chipset, trusted installers, Android Go, custom ROMs) and `conditional` (per-vendor blocks keyed on manufacturer/brand match lists).
- `OemPrefixResolver` API changes: every public query method takes a `DeviceIdentity` parameter (manufacturer + brand). Internal cache is keyed on the normalized device identity tuple.
- `DeviceIdentity` is a new value type with two factories: `local()` which reads `Build.MANUFACTURER` / `Build.BRAND`, and `fromSystemProperties(map)` which reads them from a parsed bugreport `getprop` dump.
- Live-scan callers pass `DeviceIdentity.local()`. Bugreport callers extract the device identity from the bugreport's system properties and pass it.
- `BugReportAnalyzer` gains a minimal `getprop` parser that populates `SystemPropertySnapshot` telemetry and extracts manufacturer/brand for the conditional resolver.
- The YAML parser supports the new structure. For safety, it also falls back to the legacy flat structure if encountered (so partial updates can land incrementally).

**Tech Stack:** Kotlin, Hilt, snakeyaml-engine, JUnit 4 + MockK.

**Acceptance criteria:**
- `known_oem_prefixes.yml` restructured into unconditional + conditional sections.
- `DeviceIdentity` value type exists with both `local()` and `fromSystemProperties(...)` factories.
- `OemPrefixResolver` public API takes `DeviceIdentity` at every call site.
- `AppScanner`, `UsageStatsScanner`, `AccessibilityModule`, `ReceiverModule`, `ActivityModule`, `ScanOrchestrator` (9 call sites total) all pass the appropriate `DeviceIdentity`.
- `BugReportAnalyzer` extracts `ro.product.manufacturer` / `ro.product.brand` from the bugreport getprop section and populates `SystemPropertySnapshot`. Uses them when constructing `DeviceIdentity` for bugreport-sourced scans.
- Regression test proves the prefix-spoofing attack is blocked: synthetic telemetry for `com.samsung.android.gearclient` on `manufacturer=google, brand=google` is **not** classified as OEM.
- All existing `OemPrefixResolverTest` assertions still pass (Samsung prefix on a Samsung device is still recognized).
- All existing SIGMA rule behavior preserved on correctly-matched devices.
- All 4 gradle checks (`testDebugUnitTest`, `lintDebug`, `assembleDebug`, `detekt`) pass.

---

## File Structure

### Created

- `app/src/main/java/com/androdr/ioc/DeviceIdentity.kt` — value type + factories
- `app/src/test/java/com/androdr/ioc/DeviceIdentityTest.kt` — factory and normalization tests
- `app/src/main/java/com/androdr/scanner/bugreport/GetpropParser.kt` — parses `getprop` section of bugreport into `SystemPropertySnapshot` list
- `app/src/test/java/com/androdr/scanner/bugreport/GetpropParserTest.kt` — parser tests
- `app/src/test/java/com/androdr/ioc/OemPrefixResolverConditionalTest.kt` — new tests for device-conditional behavior, including the prefix-spoofing regression

### Modified

- `app/src/main/res/raw/known_oem_prefixes.yml` — restructured into unconditional + conditional sections
- `app/src/main/java/com/androdr/ioc/OemPrefixResolver.kt` — API change: accept `DeviceIdentity`, parse new YAML structure, per-device cache
- `app/src/main/java/com/androdr/scanner/AppScanner.kt` — pass `DeviceIdentity.local()` to `isOemPrefix` / `isPartnershipPrefix` calls
- `app/src/main/java/com/androdr/scanner/UsageStatsScanner.kt` — pass `DeviceIdentity.local()`
- `app/src/main/java/com/androdr/scanner/bugreport/AccessibilityModule.kt` — pass `DeviceIdentity` derived from bugreport system properties
- `app/src/main/java/com/androdr/scanner/bugreport/ReceiverModule.kt` — same
- `app/src/main/java/com/androdr/scanner/bugreport/ActivityModule.kt` — same
- `app/src/main/java/com/androdr/scanner/BugReportAnalyzer.kt` — wire `GetpropParser`, populate `SystemPropertySnapshot`, extract device identity, pass it to bugreport modules
- `app/src/main/java/com/androdr/scanner/ScanOrchestrator.kt` — `known_good_app_db` callback uses `DeviceIdentity.local()`
- `app/src/test/java/com/androdr/scanner/AppScannerTelemetryTest.kt` — update resolver setup
- `app/src/test/java/com/androdr/scanner/ScanOrchestratorErrorHandlingTest.kt` — update mock
- `app/src/test/java/com/androdr/scanner/UsageStatsScannerTest.kt` — update resolver setup
- `app/src/test/java/com/androdr/scanner/bugreport/ReceiverModuleTest.kt` — update mock
- `app/src/test/java/com/androdr/scanner/bugreport/AccessibilityModuleTest.kt` — update mock
- `app/src/test/java/com/androdr/scanner/bugreport/ActivityModuleTest.kt` — update mock
- `app/src/test/java/com/androdr/ioc/OemPrefixResolverTest.kt` — update assertions to pass `DeviceIdentity`
- `app/src/test/resources/raw/known_oem_prefixes.yml` — mirror the production YAML restructure

### Not touched

- `FindingCategory` / `RuleCategory` / `SeverityCapPolicy` / `SigmaRuleEngine` / `SigmaRuleParser`
- Any rule YAML file (SIGMA rules continue to read `is_known_oem_app` — we only change how that boolean is computed)
- UI code beyond `SettingsScreen`'s reporting display if that breaks (probably doesn't — it only displays `Build.MANUFACTURER` directly, not via the resolver)
- `IocUpdateWorker.refresh()` (remote fetch logic stays as-is; it just parses the new YAML structure)
- Any telemetry data class beyond what's already shipping

---

## Phase A: `DeviceIdentity` Value Type

### Task A1: Create `DeviceIdentity.kt`

**Files:**
- Create: `app/src/main/java/com/androdr/ioc/DeviceIdentity.kt`

- [ ] **Step 1: Write the file**

```kotlin
package com.androdr.ioc

import android.os.Build

/**
 * Device identity used by [OemPrefixResolver] to decide which conditional
 * OEM prefix blocks apply. The allowlist is keyed on manufacturer and brand
 * so that, for example, Samsung prefixes only suppress findings on Samsung
 * devices — an attacker cannot hide malware under `com.samsung.*` on a Pixel
 * and have it classified as OEM.
 *
 * **Normalization:** manufacturer and brand are stored lowercase, trimmed.
 * The YAML `manufacturer_match` / `brand_match` lists are compared against
 * these normalized values. See #90 for the full attack model and design.
 *
 * Two factories:
 * - [local] reads `Build.MANUFACTURER` and `Build.BRAND` — used by every
 *   runtime scanner for live-device evaluation.
 * - [fromSystemProperties] reads the same fields from a parsed bugreport
 *   `getprop` dump — used by every bugreport module so imported scans
 *   evaluate against the source device's identity, not the local one.
 */
data class DeviceIdentity(
    val manufacturer: String,
    val brand: String,
) {
    companion object {
        /**
         * The identity of the device AndroDR is currently running on.
         * Reads `Build.MANUFACTURER` and `Build.BRAND`, lowercases and trims
         * both. Safe to call from any thread.
         */
        fun local(): DeviceIdentity = DeviceIdentity(
            manufacturer = Build.MANUFACTURER.orEmpty().trim().lowercase(),
            brand = Build.BRAND.orEmpty().trim().lowercase(),
        )

        /**
         * The identity extracted from a bugreport's parsed system properties.
         * Reads `ro.product.manufacturer` and `ro.product.brand` from the
         * given map. Missing keys default to empty strings, which will
         * match nothing in the conditional allowlist — the safe default
         * (only unconditional prefixes apply).
         *
         * @param properties a map of `getprop` key → value from the bugreport
         */
        fun fromSystemProperties(properties: Map<String, String>): DeviceIdentity =
            DeviceIdentity(
                manufacturer = properties["ro.product.manufacturer"]
                    .orEmpty().trim().lowercase(),
                brand = properties["ro.product.brand"]
                    .orEmpty().trim().lowercase(),
            )

        /**
         * An identity that matches no conditional blocks. Useful for tests
         * and for degraded paths where the source device cannot be
         * determined. Only unconditional prefixes apply.
         */
        val UNKNOWN: DeviceIdentity = DeviceIdentity(manufacturer = "", brand = "")
    }
}
```

- [ ] **Step 2: Compile check**

```bash
export JAVA_HOME=/home/yasir/Applications/android-studio/jbr
./gradlew compileDebugKotlin 2>&1 | tail -5
```
Expected: BUILD SUCCESSFUL.

- [ ] **Step 3: Commit**

```bash
git add app/src/main/java/com/androdr/ioc/DeviceIdentity.kt
git commit -m "feat(ioc): add DeviceIdentity value type for conditional OEM resolution (#90)

DeviceIdentity is the device-identity parameter threaded through
OemPrefixResolver so that, for example, Samsung prefixes only suppress
findings on Samsung devices. An attacker cannot hide malware under
com.samsung.* on a Pixel and have it classified as OEM.

Two factories:
- local() reads Build.MANUFACTURER and Build.BRAND for live scans.
- fromSystemProperties() reads ro.product.manufacturer and
  ro.product.brand from a bugreport's parsed getprop dump for
  imported scans.

UNKNOWN is a safe default that matches no conditional blocks —
only unconditional prefixes apply.

Part of #90 (phase A)."
```

### Task A2: Unit tests for `DeviceIdentity`

**Files:**
- Create: `app/src/test/java/com/androdr/ioc/DeviceIdentityTest.kt`

- [ ] **Step 1: Write the tests**

```kotlin
package com.androdr.ioc

import org.junit.Assert.assertEquals
import org.junit.Test

class DeviceIdentityTest {

    @Test
    fun `fromSystemProperties extracts manufacturer and brand`() {
        val props = mapOf(
            "ro.product.manufacturer" to "Samsung",
            "ro.product.brand" to "samsung",
            "ro.build.fingerprint" to "samsung/a51/a51:11/...",
        )
        val identity = DeviceIdentity.fromSystemProperties(props)
        assertEquals("samsung", identity.manufacturer)
        assertEquals("samsung", identity.brand)
    }

    @Test
    fun `fromSystemProperties lowercases and trims values`() {
        val props = mapOf(
            "ro.product.manufacturer" to "  SAMSUNG  ",
            "ro.product.brand" to " SAMSUNG\n",
        )
        val identity = DeviceIdentity.fromSystemProperties(props)
        assertEquals("samsung", identity.manufacturer)
        assertEquals("samsung", identity.brand)
    }

    @Test
    fun `fromSystemProperties returns empty strings when keys are missing`() {
        val props = mapOf("ro.build.fingerprint" to "some value")
        val identity = DeviceIdentity.fromSystemProperties(props)
        assertEquals("", identity.manufacturer)
        assertEquals("", identity.brand)
    }

    @Test
    fun `fromSystemProperties handles brand different from manufacturer (Redmi Xiaomi case)`() {
        val props = mapOf(
            "ro.product.manufacturer" to "Xiaomi",
            "ro.product.brand" to "Redmi",
        )
        val identity = DeviceIdentity.fromSystemProperties(props)
        assertEquals("xiaomi", identity.manufacturer)
        assertEquals("redmi", identity.brand)
    }

    @Test
    fun `UNKNOWN identity has empty manufacturer and brand`() {
        assertEquals("", DeviceIdentity.UNKNOWN.manufacturer)
        assertEquals("", DeviceIdentity.UNKNOWN.brand)
    }

    @Test
    fun `equal identities are data-class equal`() {
        val a = DeviceIdentity(manufacturer = "samsung", brand = "samsung")
        val b = DeviceIdentity(manufacturer = "samsung", brand = "samsung")
        assertEquals(a, b)
        assertEquals(a.hashCode(), b.hashCode())
    }
}
```

- [ ] **Step 2: Run**

```bash
./gradlew testDebugUnitTest --tests "com.androdr.ioc.DeviceIdentityTest" 2>&1 | tail -10
```
Expected: BUILD SUCCESSFUL, 6 tests passing.

- [ ] **Step 3: Commit**

```bash
git add app/src/test/java/com/androdr/ioc/DeviceIdentityTest.kt
git commit -m "test(ioc): DeviceIdentity factories and normalization (#90)"
```

---

## Phase B: Restructure `known_oem_prefixes.yml`

### Task B1: Rewrite the YAML

**Files:**
- Modify: `app/src/main/res/raw/known_oem_prefixes.yml`
- Modify: `app/src/test/resources/raw/known_oem_prefixes.yml` (must stay in sync)

- [ ] **Step 1: Write the restructured YAML**

Write this exact content to both files (production and test resources):

```yaml
version: "2026-04-10"
description: "Known OEM, carrier, and chipset vendor package prefixes. Split into unconditional and device-conditional sections: conditional blocks only apply when the assessed device's manufacturer/brand matches the block's manufacturer_match / brand_match lists. This closes the prefix-spoofing attack from #90 where an attacker could hide malware under a foreign vendor's package namespace on a device that doesn't actually use that vendor."
sources:
  - uad-list
  - plexus-data
  - manual-verification
  - androdr-research

# ============================================================
# UNCONDITIONAL PREFIXES — apply to every device regardless of manufacturer.
# These represent packages that legitimately ship cross-vendor and cannot be
# meaningfully spoofed (either they're signed by Google, or they're chipset
# firmware components that only load if the chipset is present).
# ============================================================
unconditional:
  aosp_prefixes:
    - "com.android."
    - "com.google."
    - "android."

  chipset_prefixes:
    - "com.qualcomm."
    - "com.qti."
    - "vendor.qti."
    - "com.mediatek."
    - "com.mtk."
    - "com.unisoc."
    - "com.sprd."
    - "vendor.unisoc."
    - "vendor.sprd."

  odm_prefixes:
    - "com.bsp."
    - "com.wingtech."
    - "com.longcheer."

  android_go_prefixes:
    - "com.go."

  custom_rom_prefixes:
    - "org.lineageos."
    - "com.cyanogenmod."

  # Trusted app store installer package names. These are compared against
  # installer identity, not against arbitrary package names, so they are
  # safe to keep unconditional.
  trusted_installers:
    - "com.android.vending"             # Google Play Store
    - "com.sec.android.app.samsungapps" # Samsung Galaxy Store
    - "com.samsung.android.app.updatecenter"
    - "com.samsung.android.app.watchmanager"
    - "com.samsung.android.scloud"
    - "com.samsung.android.themestore"
    - "com.samsung.android.spay"
    - "com.sec.android.app.sbrowser"
    - "com.facebook.system"
    - "com.xiaomi.market"
    - "com.xiaomi.mipicks"
    - "com.miui.packageinstaller"
    - "com.heytap.market"
    - "com.coloros.safecenter"
    - "com.huawei.appmarket"
    - "com.bbk.appstore"

# ============================================================
# DEVICE-CONDITIONAL PREFIXES — apply only when the assessed device's
# manufacturer or brand matches the block's manufacturer_match /
# brand_match list. On a device that doesn't match, these prefixes are
# NOT in the applicable set, which means an app using them will be
# classified on its own merits (potentially flagged as sideloaded,
# firmware implant, or system name disguise).
# ============================================================
conditional:

  samsung:
    manufacturer_match: ["samsung"]
    brand_match: ["samsung"]
    strict_prefixes:
      - "com.samsung."
      - "com.sec."
      - "com.osp."
      - "com.knox."
      - "com.skms."
      - "com.mygalaxy."
      - "com.monotype."
      - "com.hiya."
      - "com.sem."
      - "com.swiftkey."
      - "com.shannon."
      - "com.wsomacp"
      - "com.wssyncmldm"
    # Apps pre-installed via Samsung partnerships — counts as OEM only
    # when the app has FLAG_SYSTEM (pre-installed) AND the device is Samsung.
    partnership_prefixes:
      - "com.microsoft."
      - "com.touchtype."
      - "com.facebook."

  xiaomi:
    manufacturer_match: ["xiaomi"]
    brand_match: ["xiaomi", "redmi", "poco"]
    strict_prefixes:
      - "com.miui."
      - "com.xiaomi."
      - "com.mi."
      - "com.duokan."
      - "com.mipay."

  motorola:
    manufacturer_match: ["motorola"]
    brand_match: ["motorola", "lenovo"]
    strict_prefixes:
      - "com.motorola."

  oneplus:
    manufacturer_match: ["oneplus"]
    brand_match: ["oneplus"]
    strict_prefixes:
      - "com.oneplus."

  lg:
    manufacturer_match: ["lge"]
    brand_match: ["lge"]
    strict_prefixes:
      - "com.lge."

  htc:
    manufacturer_match: ["htc"]
    brand_match: ["htc"]
    strict_prefixes:
      - "com.htc."

  sony:
    manufacturer_match: ["sony"]
    brand_match: ["sony"]
    strict_prefixes:
      - "com.sony."

  huawei:
    manufacturer_match: ["huawei", "honor"]
    brand_match: ["huawei", "honor"]
    strict_prefixes:
      - "com.huawei."
      - "com.honor."

  asus:
    manufacturer_match: ["asus"]
    brand_match: ["asus"]
    strict_prefixes:
      - "com.asus."

  oppo:
    manufacturer_match: ["oppo", "oplus"]
    brand_match: ["oppo"]
    strict_prefixes:
      - "com.oppo."
      - "com.coloros."
      - "com.heytap."
      - "com.oplus."

  realme:
    manufacturer_match: ["realme"]
    brand_match: ["realme"]
    strict_prefixes:
      - "com.realme."

  vivo:
    manufacturer_match: ["vivo"]
    brand_match: ["vivo"]
    strict_prefixes:
      - "com.vivo."
      - "com.bbk."

  amazon:
    manufacturer_match: ["amazon"]
    brand_match: ["amazon"]
    strict_prefixes:
      - "com.amazon."

  # US carrier-branded builds: these prefixes apply only when the build
  # brand matches the carrier, typically on carrier-branded phones.
  # NOTE: com.ironsrc.aura.* is intentionally EXCLUDED — IronSource Aura
  # silently installs sponsored apps and should be flagged as invasive
  # bloatware regardless of carrier build.
  us_carrier_tmobile:
    manufacturer_match: []
    brand_match: ["tmobile"]
    strict_prefixes:
      - "com.tmobile."
      - "com.dti."
      - "com.digitalturbine."

  us_carrier_sprint:
    manufacturer_match: []
    brand_match: ["sprint"]
    strict_prefixes:
      - "com.sprint."

  us_carrier_att:
    manufacturer_match: []
    brand_match: ["att"]
    strict_prefixes:
      - "com.att."

  us_carrier_verizon:
    manufacturer_match: []
    brand_match: ["vzw", "verizon"]
    strict_prefixes:
      - "com.vzw."
      - "com.verizon."
```

Copy the same content to `app/src/test/resources/raw/known_oem_prefixes.yml`.

**Note:** The brand `redmi` / `poco` are listed alongside `xiaomi` because those are the brand values on Redmi and Poco devices (manufacturer is still `xiaomi`). Similarly `honor` has a separate manufacturer string post-Huawei-split.

- [ ] **Step 2: Do NOT compile yet** — the parser hasn't been updated. Phase C updates the parser.

---

## Phase C: Update `OemPrefixResolver` to use new structure + `DeviceIdentity`

### Task C1: Rewrite resolver with device-identity-aware API

**Files:**
- Modify: `app/src/main/java/com/androdr/ioc/OemPrefixResolver.kt`

This is the biggest file change in the plan. The resolver needs to:
1. Parse the new YAML structure (unconditional + conditional blocks)
2. Cache the parsed structure in a new `ParsedOemData` shape
3. Expose API methods that take a `DeviceIdentity` and return the applicable prefix set
4. Keep the `isOemPrefix` / `isPartnershipPrefix` / `isTrustedInstaller` method names but add `DeviceIdentity` parameters
5. Keep the existing `refresh()` suspend method working with the new structure

- [ ] **Step 1: Write the new resolver**

Replace the entire content of `app/src/main/java/com/androdr/ioc/OemPrefixResolver.kt` with:

```kotlin
package com.androdr.ioc

import android.content.Context
import android.util.Log
import com.androdr.R
import dagger.hilt.android.qualifiers.ApplicationContext
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.snakeyaml.engine.v2.api.Load
import org.snakeyaml.engine.v2.api.LoadSettings
import java.net.HttpURLConnection
import java.net.URL
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicReference
import javax.inject.Inject
import javax.inject.Singleton

/**
 * Resolves whether a package name belongs to the OEM/system allowlist for
 * a given device identity. See [DeviceIdentity] for the manufacturer/brand
 * model and #90 for the prefix-spoofing attack this prevents.
 *
 * The allowlist YAML (`res/raw/known_oem_prefixes.yml`) has two top-level
 * sections:
 * - `unconditional:` — prefixes that apply to every device (AOSP, chipset,
 *   trusted installers, Android Go, custom ROMs).
 * - `conditional:` — per-vendor blocks keyed by `manufacturer_match` and
 *   `brand_match`. Only blocks whose match list contains the current
 *   device's manufacturer or brand contribute prefixes.
 *
 * Every public query method takes a [DeviceIdentity]. Runtime callers pass
 * [DeviceIdentity.local]; bugreport callers pass
 * [DeviceIdentity.fromSystemProperties].
 *
 * The applicable prefix set for each unique [DeviceIdentity] is cached
 * in [perDeviceCache] to avoid recomputing on every call.
 */
@Singleton
class OemPrefixResolver @Inject constructor(
    @ApplicationContext private val context: Context,
) {

    private val data = AtomicReference<ParsedOemData>(loadBundledData())

    /** Per-(manufacturer,brand) cache of applicable prefix sets. */
    private val perDeviceCache = ConcurrentHashMap<DeviceIdentity, ApplicablePrefixes>()

    @Suppress("TooGenericExceptionCaught")
    private fun loadBundledData(): ParsedOemData {
        return try {
            val yaml = context.resources.openRawResource(R.raw.known_oem_prefixes)
                .bufferedReader().use { it.readText() }
            parseOemPrefixYaml(yaml)
        } catch (e: Exception) {
            Log.w(TAG, "Failed to load bundled OEM prefixes: ${e.message}")
            ParsedOemData.empty()
        }
    }

    /**
     * Returns true iff [packageName] is a strict OEM prefix in the applicable
     * set for [device]. A strict prefix classifies the app as OEM regardless
     * of its FLAG_SYSTEM status.
     */
    fun isOemPrefix(packageName: String, device: DeviceIdentity): Boolean =
        applicablePrefixesFor(device).strict.any { packageName.startsWith(it) }

    /** Alias for [isOemPrefix], preserved for readability. */
    fun isStrictOemPrefix(packageName: String, device: DeviceIdentity): Boolean =
        isOemPrefix(packageName, device)

    /**
     * Returns true iff [packageName] is a partnership prefix in the applicable
     * set for [device]. Partnership prefixes only classify as OEM when the
     * app also has FLAG_SYSTEM (pre-installed). See spec §9 and #90.
     */
    fun isPartnershipPrefix(packageName: String, device: DeviceIdentity): Boolean =
        applicablePrefixesFor(device).partnership.any { packageName.startsWith(it) }

    /**
     * Returns true iff [installer] is a trusted app store. Trusted installers
     * are unconditional (every device), so [device] is accepted but only used
     * for the fallback `isOemPrefix` call.
     */
    fun isTrustedInstaller(installer: String, device: DeviceIdentity): Boolean {
        val d = data.get()
        return installer in d.trustedInstallers ||
            isOemPrefix(installer, device)
    }

    /**
     * Returns the applicable prefix set for [device]: unconditional prefixes
     * plus any conditional blocks whose `manufacturer_match` / `brand_match`
     * contains [device]'s manufacturer or brand.
     */
    fun applicablePrefixesFor(device: DeviceIdentity): ApplicablePrefixes =
        perDeviceCache.getOrPut(device) {
            val d = data.get()
            val strict = mutableSetOf<String>()
            val partnership = mutableSetOf<String>()

            // Unconditional always applies
            strict.addAll(d.unconditionalStrict)

            // Conditional blocks apply iff manufacturer OR brand matches
            for (block in d.conditional) {
                if (block.matches(device)) {
                    strict.addAll(block.strictPrefixes)
                    partnership.addAll(block.partnershipPrefixes)
                }
            }

            ApplicablePrefixes(
                strict = strict.toSet(),
                partnership = partnership.toSet(),
            )
        }

    /**
     * Fetches the latest OEM prefix list from the public rules repo.
     * On success, replaces the in-memory cache AND invalidates [perDeviceCache]
     * so subsequent queries re-derive the applicable set.
     */
    @Suppress("TooGenericExceptionCaught", "ReturnCount")
    suspend fun refresh() = withContext(Dispatchers.IO) {
        try {
            val yaml = fetchUrl(PREFIXES_URL) ?: return@withContext
            val parsed = parseOemPrefixYaml(yaml)

            // Sanity checks — reject obviously malicious remote data
            val allStrict = parsed.unconditionalStrict +
                parsed.conditional.flatMap { it.strictPrefixes }
            val allPartnership = parsed.conditional.flatMap { it.partnershipPrefixes }
            val allPrefixes = allStrict + allPartnership
            if (allPrefixes.any { it.length < 4 }) {
                Log.w(TAG, "Remote OEM prefix feed rejected: prefix too short")
                return@withContext
            }
            if (allPrefixes.size > 500) {
                Log.w(TAG, "Remote OEM prefix feed rejected: too many prefixes (${allPrefixes.size})")
                return@withContext
            }

            if (allPrefixes.isNotEmpty() || parsed.trustedInstallers.isNotEmpty()) {
                data.set(parsed)
                perDeviceCache.clear()
                Log.i(
                    TAG,
                    "OEM data refreshed: ${parsed.unconditionalStrict.size} unconditional + " +
                        "${parsed.conditional.size} conditional blocks, " +
                        "${parsed.trustedInstallers.size} installers",
                )
            }
        } catch (e: Exception) {
            Log.w(TAG, "OEM prefix refresh failed: ${e.message}")
        }
    }

    // ─── Data classes ──────────────────────────────────────────────────────

    /** Raw parsed YAML data. */
    internal data class ParsedOemData(
        val unconditionalStrict: Set<String>,
        val conditional: List<ConditionalBlock>,
        val trustedInstallers: Set<String>,
    ) {
        companion object {
            fun empty() = ParsedOemData(emptySet(), emptyList(), emptySet())
        }
    }

    /** A single conditional block from the YAML. */
    internal data class ConditionalBlock(
        val id: String,
        val manufacturerMatch: Set<String>,
        val brandMatch: Set<String>,
        val strictPrefixes: Set<String>,
        val partnershipPrefixes: Set<String>,
    ) {
        /**
         * A block matches a device iff the device's manufacturer is in
         * [manufacturerMatch] OR the device's brand is in [brandMatch].
         * Either condition is sufficient — allows carrier-branded builds
         * to match on brand even if manufacturer is generic.
         */
        fun matches(device: DeviceIdentity): Boolean =
            device.manufacturer in manufacturerMatch ||
                device.brand in brandMatch
    }

    /** The effective allowlist for a specific device identity. */
    data class ApplicablePrefixes(
        val strict: Set<String>,
        val partnership: Set<String>,
    )

    // ─── YAML parsing ──────────────────────────────────────────────────────

    @Suppress("UNCHECKED_CAST", "TooGenericExceptionCaught", "LongMethod")
    internal fun parseOemPrefixYaml(yamlContent: String): ParsedOemData {
        return try {
            val settings = LoadSettings.builder()
                .setAllowDuplicateKeys(false)
                .setMaxAliasesForCollections(10)
                .build()
            val load = Load(settings)
            val doc = load.loadFromString(yamlContent) as? Map<*, *>
                ?: return ParsedOemData.empty()

            // Parse unconditional section
            val unconditionalMap = doc["unconditional"] as? Map<*, *>
                ?: return parseLegacyFlat(doc) // Fall back to legacy flat structure
            val unconditionalStrict = mutableSetOf<String>()
            for ((key, value) in unconditionalMap) {
                val keyStr = key.toString()
                if (keyStr == "trusted_installers") continue
                if (value is List<*>) {
                    unconditionalStrict.addAll(value.filterIsInstance<String>())
                }
            }

            // Parse trusted installers
            val installers = (unconditionalMap["trusted_installers"] as? List<*>)
                ?.filterIsInstance<String>()
                ?.filter { it.length >= 10 && it.contains('.') }
                ?.take(MAX_INSTALLER_COUNT)
                ?.toSet() ?: emptySet()

            // Parse conditional blocks
            val conditionalMap = doc["conditional"] as? Map<*, *> ?: emptyMap<Any, Any>()
            val conditionalBlocks = mutableListOf<ConditionalBlock>()
            for ((blockKey, blockValue) in conditionalMap) {
                val blockId = blockKey.toString()
                val block = blockValue as? Map<*, *> ?: continue
                val manufacturerMatch = (block["manufacturer_match"] as? List<*>)
                    ?.filterIsInstance<String>()
                    ?.map { it.lowercase() }
                    ?.toSet() ?: emptySet()
                val brandMatch = (block["brand_match"] as? List<*>)
                    ?.filterIsInstance<String>()
                    ?.map { it.lowercase() }
                    ?.toSet() ?: emptySet()
                val strictPrefixes = (block["strict_prefixes"] as? List<*>)
                    ?.filterIsInstance<String>()
                    ?.toSet() ?: emptySet()
                val partnershipPrefixes = (block["partnership_prefixes"] as? List<*>)
                    ?.filterIsInstance<String>()
                    ?.toSet() ?: emptySet()

                if (strictPrefixes.isNotEmpty() || partnershipPrefixes.isNotEmpty()) {
                    conditionalBlocks += ConditionalBlock(
                        id = blockId,
                        manufacturerMatch = manufacturerMatch,
                        brandMatch = brandMatch,
                        strictPrefixes = strictPrefixes,
                        partnershipPrefixes = partnershipPrefixes,
                    )
                }
            }

            ParsedOemData(
                unconditionalStrict = unconditionalStrict,
                conditional = conditionalBlocks,
                trustedInstallers = installers,
            )
        } catch (e: Exception) {
            Log.w(TAG, "Failed to parse OEM prefix YAML: ${e.message}")
            ParsedOemData.empty()
        }
    }

    /**
     * Fallback parser for the legacy flat YAML structure (pre-#90).
     * Every prefix becomes unconditional. Used when a remote feed hasn't
     * been updated to the new structure yet — maintains forward-compat.
     */
    @Suppress("UNCHECKED_CAST")
    private fun parseLegacyFlat(doc: Map<*, *>): ParsedOemData {
        val strictPrefixes = mutableSetOf<String>()
        val partnershipPrefixes = mutableSetOf<String>()
        for ((key, value) in doc) {
            val keyStr = key.toString()
            if (keyStr.endsWith("_prefixes") && value is List<*>) {
                val prefixes = value.filterIsInstance<String>()
                if (keyStr.contains("partner")) {
                    partnershipPrefixes.addAll(prefixes)
                } else {
                    strictPrefixes.addAll(prefixes)
                }
            }
        }
        val installers = (doc["trusted_installers"] as? List<*>)
            ?.filterIsInstance<String>()
            ?.filter { it.length >= 10 && it.contains('.') }
            ?.take(MAX_INSTALLER_COUNT)
            ?.toSet() ?: emptySet()

        // Legacy: everything becomes unconditional, with a single wildcard
        // conditional block for the partnership prefixes so the partnership
        // check still fires.
        val legacyConditional = if (partnershipPrefixes.isNotEmpty()) {
            listOf(ConditionalBlock(
                id = "legacy_wildcard",
                manufacturerMatch = emptySet(),
                brandMatch = emptySet(),
                strictPrefixes = emptySet(),
                partnershipPrefixes = partnershipPrefixes,
            ))
        } else {
            emptyList()
        }

        // The wildcard block never matches (empty match lists), so under
        // the legacy structure, partnership prefixes silently drop. This
        // is acceptable for a transitional fallback — the production YAML
        // is expected to use the new structure.
        return ParsedOemData(
            unconditionalStrict = strictPrefixes,
            conditional = legacyConditional,
            trustedInstallers = installers,
        )
    }

    // ─── HTTP fetch (unchanged) ────────────────────────────────────────────

    @Suppress("TooGenericExceptionCaught", "SwallowedException")
    private fun fetchUrl(url: String): String? {
        val conn = try {
            URL(url).openConnection() as HttpURLConnection
        } catch (e: Exception) { return null }
        return try {
            conn.connectTimeout = TIMEOUT_MS
            conn.readTimeout = TIMEOUT_MS
            conn.setRequestProperty("User-Agent", "AndroDR/1.0")
            if (conn.responseCode == HttpURLConnection.HTTP_OK) {
                val body = conn.inputStream.bufferedReader().use { it.readText() }
                if (body.length > MAX_RESPONSE_SIZE) {
                    Log.w(TAG, "Response too large: ${body.length} bytes")
                    return null
                }
                body
            } else null
        } catch (e: Exception) { null }
        finally { conn.disconnect() }
    }

    companion object {
        private const val TAG = "OemPrefixResolver"
        private const val PREFIXES_URL =
            "https://raw.githubusercontent.com/android-sigma-rules/rules/main/ioc-data/known-oem-prefixes.yml"
        private const val TIMEOUT_MS = 10_000
        private const val MAX_RESPONSE_SIZE = 100_000
        private const val MAX_INSTALLER_COUNT = 50
    }
}
```

- [ ] **Step 2: Try to compile — expect failure**

```bash
./gradlew compileDebugKotlin 2>&1 | tail -20
```

Expected: FAIL. Every caller that uses `isOemPrefix(pkg)` (without DeviceIdentity) will error. This is the cascade — phase D fixes each caller.

- [ ] **Step 3: No commit yet** — commit with phase D's caller updates to avoid an intermediate broken state.

### Task C2: Update the existing `OemPrefixResolverTest`

**Files:**
- Modify: `app/src/test/java/com/androdr/ioc/OemPrefixResolverTest.kt`

- [ ] **Step 1: Update every test method**

Every existing test calls `resolver.isOemPrefix(pkg)` without a `DeviceIdentity`. They need updating. The simplest approach: add a helper and a default device, pass it to every call.

Replace the entire file with:

```kotlin
package com.androdr.ioc

import android.content.Context
import android.content.res.Resources
import com.androdr.R
import io.mockk.every
import io.mockk.mockk
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Legacy behavior tests for OemPrefixResolver. These verify that when the
 * device identity matches the conditional block (e.g., assessing a Samsung
 * device), the appropriate prefixes are classified as OEM. The new
 * device-conditional behavior (Samsung prefix on a Pixel is NOT OEM) is
 * covered by [OemPrefixResolverConditionalTest].
 */
class OemPrefixResolverTest {

    private val resolver: OemPrefixResolver
    private val samsung = DeviceIdentity(manufacturer = "samsung", brand = "samsung")
    private val xiaomi = DeviceIdentity(manufacturer = "xiaomi", brand = "xiaomi")
    private val tmobile = DeviceIdentity(manufacturer = "samsung", brand = "tmobile")
    private val generic = DeviceIdentity(manufacturer = "google", brand = "google")

    init {
        val context: Context = mockk(relaxed = true)
        val resources: Resources = mockk(relaxed = true)
        every { context.resources } returns resources
        val yamlStream = javaClass.classLoader!!
            .getResourceAsStream("raw/known_oem_prefixes.yml")!!
        every { resources.openRawResource(R.raw.known_oem_prefixes) } returns yamlStream
        resolver = OemPrefixResolver(context)
    }

    @Test
    fun `Samsung packages are OEM on a Samsung device`() {
        assertTrue(resolver.isOemPrefix("com.samsung.accessory.zenithmgr", samsung))
        assertTrue(resolver.isOemPrefix("com.sec.android.app.launcher", samsung))
    }

    @Test
    fun `AOSP and Google packages are OEM on any device`() {
        assertTrue(resolver.isOemPrefix("com.google.android.gms", samsung))
        assertTrue(resolver.isOemPrefix("com.google.android.gms", xiaomi))
        assertTrue(resolver.isOemPrefix("com.google.android.gms", generic))
    }

    @Test
    fun `chipset prefixes are OEM on any device`() {
        assertTrue(resolver.isOemPrefix("com.mediatek.op01.phone.plugin", generic))
        assertTrue(resolver.isOemPrefix("com.unisoc.android.wifi", generic))
        assertTrue(resolver.isOemPrefix("com.qualcomm.qti.telephonyservice", samsung))
    }

    @Test
    fun `Xiaomi packages are OEM on a Xiaomi device`() {
        assertTrue(resolver.isOemPrefix("com.miui.notes", xiaomi))
        assertTrue(resolver.isOemPrefix("com.xiaomi.account", xiaomi))
    }

    @Test
    fun `US carrier packages are OEM on carrier-branded builds`() {
        assertTrue(resolver.isOemPrefix("com.tmobile.m1", tmobile))
    }

    @Test
    fun `user apps are not OEM on any device`() {
        assertFalse(resolver.isOemPrefix("com.instagram.android", samsung))
        assertFalse(resolver.isOemPrefix("com.instagram.android", generic))
        assertFalse(resolver.isOemPrefix("com.callapp.contacts", generic))
        assertFalse(resolver.isOemPrefix("com.evil.spy", generic))
    }

    @Test
    fun `bundled installers are trusted`() {
        assertTrue(resolver.isTrustedInstaller("com.android.vending", generic))
        assertTrue(resolver.isTrustedInstaller("com.sec.android.app.samsungapps", samsung))
        assertTrue(resolver.isTrustedInstaller("com.xiaomi.market", xiaomi))
    }

    @Test
    fun `OEM-prefix installers are trusted on matching device`() {
        assertTrue(resolver.isTrustedInstaller("com.samsung.android.app.omcagent", samsung))
        assertTrue(resolver.isTrustedInstaller("com.tmobile.pr.adapt", tmobile))
    }

    @Test
    fun `unknown installers are not trusted`() {
        assertFalse(resolver.isTrustedInstaller("com.unknown.installer", generic))
    }

    @Test
    fun `partnership prefixes are not strict OEM prefixes`() {
        assertFalse(resolver.isOemPrefix("com.facebook.katana", samsung))
        assertFalse(resolver.isOemPrefix("com.microsoft.office.word", samsung))
    }

    @Test
    fun `partnership prefixes match isPartnershipPrefix on Samsung device`() {
        assertTrue(resolver.isPartnershipPrefix("com.facebook.katana", samsung))
        assertTrue(resolver.isPartnershipPrefix("com.microsoft.office.word", samsung))
        assertTrue(resolver.isPartnershipPrefix("com.touchtype.swiftkey", samsung))
    }

    @Test
    fun `android prefix does not match androidmalware packages`() {
        assertFalse(resolver.isOemPrefix("androidmalware.evil.spy", generic))
        assertTrue(resolver.isOemPrefix("android.provider.contacts", generic))
    }
}
```

Note two changes from the original:
- Every call now takes a `DeviceIdentity`.
- The "monotype and hiya are strict OEM prefixes" test is removed because those are now Samsung-conditional.
- The "digitalturbine is a strict OEM prefix" test is replaced by the carrier-branded test (digitalturbine is now under the T-Mobile conditional block).
- The `parseOemPrefixYaml separates strict and partnership prefixes` test is removed; the parser's behavior is exercised through the public API tests.
- The `IronSource Aura is NOT an OEM prefix` test is implicit in the "user apps are not OEM" test since Aura is excluded from every block.

### Task C3: Create the new conditional-behavior test

**Files:**
- Create: `app/src/test/java/com/androdr/ioc/OemPrefixResolverConditionalTest.kt`

- [ ] **Step 1: Write the regression test**

```kotlin
package com.androdr.ioc

import android.content.Context
import android.content.res.Resources
import com.androdr.R
import io.mockk.every
import io.mockk.mockk
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Regression test for #90: device-conditional OEM resolution. The attack
 * this test prevents: an attacker ships a sideloaded APK with a foreign
 * vendor's package prefix (e.g. com.samsung.*) on a device that doesn't
 * actually use that vendor (e.g. a Pixel). Under the old global allowlist,
 * the malware was classified as OEM and suppressed from findings. Under
 * the new conditional allowlist, it's classified on its own merits.
 */
class OemPrefixResolverConditionalTest {

    private val resolver: OemPrefixResolver
    private val pixel = DeviceIdentity(manufacturer = "google", brand = "google")
    private val samsung = DeviceIdentity(manufacturer = "samsung", brand = "samsung")
    private val xiaomi = DeviceIdentity(manufacturer = "xiaomi", brand = "redmi")
    private val unknown = DeviceIdentity.UNKNOWN

    init {
        val context: Context = mockk(relaxed = true)
        val resources: Resources = mockk(relaxed = true)
        every { context.resources } returns resources
        val yamlStream = javaClass.classLoader!!
            .getResourceAsStream("raw/known_oem_prefixes.yml")!!
        every { resources.openRawResource(R.raw.known_oem_prefixes) } returns yamlStream
        resolver = OemPrefixResolver(context)
    }

    @Test
    fun `Samsung prefix is NOT OEM on a Pixel`() {
        // The core of the prefix-spoofing attack. Before #90 this was OEM
        // and would suppress the finding. After #90 it's not OEM and the
        // sideloaded-app / impersonation rules get a shot at it.
        assertFalse(
            "com.samsung.android.gearclient on a Pixel must not be classified as OEM",
            resolver.isOemPrefix("com.samsung.android.gearclient", pixel),
        )
        assertFalse(resolver.isOemPrefix("com.sec.android.app.camera", pixel))
    }

    @Test
    fun `Samsung prefix IS OEM on a Samsung device`() {
        assertTrue(resolver.isOemPrefix("com.samsung.android.gearclient", samsung))
        assertTrue(resolver.isOemPrefix("com.sec.android.app.camera", samsung))
    }

    @Test
    fun `Xiaomi prefix is NOT OEM on a Samsung device`() {
        assertFalse(resolver.isOemPrefix("com.miui.notes", samsung))
        assertFalse(resolver.isOemPrefix("com.xiaomi.account", samsung))
    }

    @Test
    fun `Xiaomi prefix IS OEM on a Redmi device (Xiaomi manufacturer, Redmi brand)`() {
        assertTrue(resolver.isOemPrefix("com.miui.notes", xiaomi))
        assertTrue(resolver.isOemPrefix("com.xiaomi.account", xiaomi))
    }

    @Test
    fun `chipset prefixes apply on ALL devices including Pixel`() {
        // com.unisoc.* on a Pixel is still classified as OEM because Unisoc
        // is a chipset vendor — the package can legitimately appear in
        // firmware across vendors.
        assertTrue(resolver.isOemPrefix("com.unisoc.android.wifi", pixel))
        assertTrue(resolver.isOemPrefix("com.qualcomm.qti.telephonyservice", pixel))
    }

    @Test
    fun `AOSP prefixes apply on ALL devices`() {
        assertTrue(resolver.isOemPrefix("com.android.systemui", pixel))
        assertTrue(resolver.isOemPrefix("com.google.android.gms", samsung))
    }

    @Test
    fun `UNKNOWN device identity only matches unconditional prefixes`() {
        // Safe default: if we can't determine the device (e.g. from a
        // malformed bugreport), conservative behavior is to apply only
        // unconditional prefixes. Samsung/Xiaomi-specific prefixes don't
        // suppress anything.
        assertFalse(resolver.isOemPrefix("com.samsung.android.gearclient", unknown))
        assertFalse(resolver.isOemPrefix("com.miui.notes", unknown))
        assertTrue(resolver.isOemPrefix("com.android.systemui", unknown))
        assertTrue(resolver.isOemPrefix("com.qualcomm.qti.telephonyservice", unknown))
    }

    @Test
    fun `partnership prefixes only apply on the matching OEM device`() {
        // Facebook is a Samsung partnership pre-install. On a Samsung device
        // with a Samsung-pre-installed Facebook app, it's OEM (partnership).
        // On a Pixel, Facebook is user-installed, NOT partnership.
        assertTrue(resolver.isPartnershipPrefix("com.facebook.katana", samsung))
        assertFalse(resolver.isPartnershipPrefix("com.facebook.katana", pixel))
        assertFalse(resolver.isPartnershipPrefix("com.facebook.katana", xiaomi))
    }

    @Test
    fun `applicablePrefixesFor caches per device identity`() {
        // Repeated calls with the same device should return the same set
        // (object identity). Different devices return different sets.
        val a = resolver.applicablePrefixesFor(pixel)
        val b = resolver.applicablePrefixesFor(pixel)
        val c = resolver.applicablePrefixesFor(samsung)
        // Same device → cached (same object identity)
        assertTrue(a === b)
        // Different device → not cached
        assertFalse(a === c)
    }

    @Test
    fun `Huawei manufacturer matches huawei or honor brand`() {
        val honor = DeviceIdentity(manufacturer = "honor", brand = "honor")
        assertTrue(resolver.isOemPrefix("com.huawei.browser", honor))
        assertTrue(resolver.isOemPrefix("com.honor.appmarket", honor))
    }

    @Test
    fun `OPPO manufacturer matches coloros and heytap prefixes`() {
        val oppo = DeviceIdentity(manufacturer = "oppo", brand = "oppo")
        assertTrue(resolver.isOemPrefix("com.oppo.camera", oppo))
        assertTrue(resolver.isOemPrefix("com.coloros.safecenter", oppo))
        assertTrue(resolver.isOemPrefix("com.heytap.market", oppo))
    }
}
```

- [ ] **Step 2: No compile yet** — resolver + callers need to be fully updated first.

---

## Phase D: Update every `OemPrefixResolver` caller

This phase updates the 8 callers to pass a `DeviceIdentity`. Live-scan callers use `DeviceIdentity.local()`. Bugreport callers take it as a parameter from `BugReportAnalyzer`.

### Task D1: Runtime scanners use `DeviceIdentity.local()`

**Files:**
- Modify: `app/src/main/java/com/androdr/scanner/AppScanner.kt`
- Modify: `app/src/main/java/com/androdr/scanner/UsageStatsScanner.kt`
- Modify: `app/src/main/java/com/androdr/scanner/ScanOrchestrator.kt`

- [ ] **Step 1: `AppScanner.kt`**

Find the current calls:
```kotlin
oemPrefixResolver.isTrustedInstaller(installerPackage)  // line 191
oemPrefixResolver.isOemPrefix(packageName)              // line 199
oemPrefixResolver.isPartnershipPrefix(packageName)      // line 200
```

Compute the device identity once at the top of `buildTelemetryForPackage()` (or cache it as a private field, since `AppScanner` scans many packages per call — it's the same identity for all):

Add at class level:
```kotlin
private val localDevice = com.androdr.ioc.DeviceIdentity.local()
```

And update each call:
```kotlin
oemPrefixResolver.isTrustedInstaller(installerPackage, localDevice)
oemPrefixResolver.isOemPrefix(packageName, localDevice)
oemPrefixResolver.isPartnershipPrefix(packageName, localDevice)
```

- [ ] **Step 2: `UsageStatsScanner.kt`**

Same approach:
```kotlin
private val localDevice = com.androdr.ioc.DeviceIdentity.local()
```

Update the two calls at lines 105-106 to pass `localDevice`.

- [ ] **Step 3: `ScanOrchestrator.kt`**

Line 161's callback builds a `known_good_app_db` lookup. The callback runs per-rule-evaluation, so capture the identity outside:

```kotlin
val localDevice = com.androdr.ioc.DeviceIdentity.local()
// ... inside the lookup map construction:
"known_good_app_db" to { v ->
    val pkg = v.toString()
    val entry = knownAppResolver.lookup(pkg)
    (entry != null && entry.category in TRUSTED_CATEGORIES) ||
        oemPrefixResolver.isOemPrefix(pkg, localDevice)
}
```

- [ ] **Step 4: Compile**

```bash
./gradlew compileDebugKotlin 2>&1 | tail -15
```

Expected: still failing on bugreport modules — phase D2 fixes those.

### Task D2: Bugreport modules accept `DeviceIdentity` via constructor

The three bugreport modules (`AccessibilityModule`, `ReceiverModule`, `ActivityModule`) classify packages extracted from the bugreport. They need the device identity of the **source device**, not the local device. The identity is extracted from the bugreport's system properties — this is passed in from `BugReportAnalyzer`.

Two options:
- **Option A**: Pass `DeviceIdentity` to every module call site from the analyzer.
- **Option B**: Store `DeviceIdentity` in a shared context object that `BugReportAnalyzer` populates before dispatching to modules.

Option A is simpler and doesn't require new types. Use it.

**Files:**
- Modify: `app/src/main/java/com/androdr/scanner/bugreport/AccessibilityModule.kt`
- Modify: `app/src/main/java/com/androdr/scanner/bugreport/ReceiverModule.kt`
- Modify: `app/src/main/java/com/androdr/scanner/bugreport/ActivityModule.kt`

- [ ] **Step 1: Change each module's analyze method to take a `DeviceIdentity`**

Look at each module's current method signature. They have something like:
```kotlin
fun analyze(lines: Sequence<String>, capturedAt: Long): ModuleResult
```

Change to:
```kotlin
fun analyze(lines: Sequence<String>, capturedAt: Long, device: DeviceIdentity): ModuleResult
```

Then update the `isOemPrefix(packageName)` call inside each to `isOemPrefix(packageName, device)`.

The exact code structure varies per module — read each one before editing. Keep the signature change minimal (just the one new parameter).

- [ ] **Step 2: Compile**

```bash
./gradlew compileDebugKotlin 2>&1 | tail -15
```

Expected: still failing on `BugReportAnalyzer` — it passes 2 args to `analyze(...)`, now needs 3. Phase E wires that.

---

## Phase E: `GetpropParser` + `BugReportAnalyzer` wiring

### Task E1: Create `GetpropParser`

**Files:**
- Create: `app/src/main/java/com/androdr/scanner/bugreport/GetpropParser.kt`

- [ ] **Step 1: Write the parser**

```kotlin
package com.androdr.scanner.bugreport

import com.androdr.data.model.SystemPropertySnapshot
import com.androdr.data.model.TelemetrySource
import javax.inject.Inject
import javax.inject.Singleton

/**
 * Parses the `getprop` section of a bugreport into [SystemPropertySnapshot]
 * telemetry. Used by [com.androdr.scanner.BugReportAnalyzer] to extract
 * the source device's manufacturer and brand for device-conditional
 * OEM classification (#90).
 *
 * Expected line format from bugreport `dumpsys` / `getprop` output:
 *
 *     [ro.product.manufacturer]: [Samsung]
 *     [ro.product.brand]: [samsung]
 *     [ro.build.fingerprint]: [samsung/a51/a51:11/...]
 *
 * The parser also accepts the alternative format sometimes seen in older
 * bugreports:
 *
 *     ro.product.manufacturer=Samsung
 *
 * Lines that don't match either format are ignored silently.
 */
@Singleton
class GetpropParser @Inject constructor() {

    /**
     * Parses [lines] and returns a list of [SystemPropertySnapshot] for every
     * recognized property. Key and value are stored as-is (the resolver
     * normalizes them).
     *
     * @param lines the full bugreport line sequence, or a pre-filtered slice
     * @param capturedAt epoch milliseconds to set on emitted telemetry rows
     */
    fun parse(lines: Sequence<String>, capturedAt: Long): List<SystemPropertySnapshot> {
        val results = mutableListOf<SystemPropertySnapshot>()
        for (line in lines) {
            val parsed = parseLine(line) ?: continue
            val (key, value) = parsed
            results += SystemPropertySnapshot(
                key = key,
                value = value,
                source = TelemetrySource.BUGREPORT_IMPORT,
                capturedAt = capturedAt,
            )
        }
        return results
    }

    /**
     * Extracts a single property's manufacturer and brand if the sequence
     * contains them. Convenience helper used by `BugReportAnalyzer` to
     * construct a [com.androdr.ioc.DeviceIdentity] without materializing
     * the full snapshot list.
     *
     * Returns a Pair(manufacturer, brand). Missing keys default to empty.
     */
    fun extractManufacturerAndBrand(lines: Sequence<String>): Pair<String, String> {
        var manufacturer = ""
        var brand = ""
        for (line in lines) {
            val parsed = parseLine(line) ?: continue
            when (parsed.first) {
                "ro.product.manufacturer" -> manufacturer = parsed.second
                "ro.product.brand" -> brand = parsed.second
            }
            if (manufacturer.isNotEmpty() && brand.isNotEmpty()) break
        }
        return manufacturer to brand
    }

    private fun parseLine(line: String): Pair<String, String>? {
        // Format 1: [key]: [value]
        val bracketMatch = BRACKET_REGEX.find(line)
        if (bracketMatch != null) {
            return bracketMatch.groupValues[1] to bracketMatch.groupValues[2]
        }
        // Format 2: key=value
        val eqMatch = EQUALS_REGEX.find(line)
        if (eqMatch != null) {
            return eqMatch.groupValues[1] to eqMatch.groupValues[2]
        }
        return null
    }

    private companion object {
        // [ro.product.manufacturer]: [Samsung]
        val BRACKET_REGEX = Regex("""^\s*\[([^\]]+)\]:\s*\[([^\]]*)\]\s*$""")
        // ro.product.manufacturer=Samsung
        val EQUALS_REGEX = Regex("""^\s*([a-zA-Z0-9_.]+)\s*=\s*(.*)\s*$""")
    }
}
```

- [ ] **Step 2: Write the parser tests**

**Create:** `app/src/test/java/com/androdr/scanner/bugreport/GetpropParserTest.kt`

```kotlin
package com.androdr.scanner.bugreport

import com.androdr.data.model.TelemetrySource
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class GetpropParserTest {

    private val parser = GetpropParser()

    @Test
    fun `parses bracket format getprop lines`() {
        val lines = """
            [ro.product.manufacturer]: [Samsung]
            [ro.product.brand]: [samsung]
            [ro.build.fingerprint]: [samsung/a51/a51:11/...]
        """.trimIndent().lines().asSequence()

        val result = parser.parse(lines, capturedAt = 1000L)

        assertEquals(3, result.size)
        assertEquals("ro.product.manufacturer", result[0].key)
        assertEquals("Samsung", result[0].value)
        assertEquals(TelemetrySource.BUGREPORT_IMPORT, result[0].source)
        assertEquals(1000L, result[0].capturedAt)
    }

    @Test
    fun `parses equals format getprop lines`() {
        val lines = """
            ro.product.manufacturer=Samsung
            ro.product.brand=samsung
        """.trimIndent().lines().asSequence()

        val result = parser.parse(lines, capturedAt = 2000L)

        assertEquals(2, result.size)
        assertEquals("ro.product.manufacturer", result[0].key)
        assertEquals("Samsung", result[0].value)
    }

    @Test
    fun `ignores non-getprop lines`() {
        val lines = """
            Some garbage text
            [ro.product.manufacturer]: [Samsung]
            more garbage
            --- section separator ---
            [ro.product.brand]: [samsung]
        """.trimIndent().lines().asSequence()

        val result = parser.parse(lines, capturedAt = 0L)

        assertEquals(2, result.size)
    }

    @Test
    fun `extractManufacturerAndBrand finds both from bracket format`() {
        val lines = """
            Some header text
            [ro.product.manufacturer]: [Google]
            [ro.product.brand]: [google]
            [other.key]: [value]
        """.trimIndent().lines().asSequence()

        val (manufacturer, brand) = parser.extractManufacturerAndBrand(lines)
        assertEquals("Google", manufacturer)
        assertEquals("google", brand)
    }

    @Test
    fun `extractManufacturerAndBrand returns empty strings when missing`() {
        val lines = "no property here".lines().asSequence()
        val (manufacturer, brand) = parser.extractManufacturerAndBrand(lines)
        assertEquals("", manufacturer)
        assertEquals("", brand)
    }

    @Test
    fun `extractManufacturerAndBrand works with brand different from manufacturer`() {
        val lines = """
            [ro.product.manufacturer]: [Xiaomi]
            [ro.product.brand]: [Redmi]
        """.trimIndent().lines().asSequence()
        val (manufacturer, brand) = parser.extractManufacturerAndBrand(lines)
        assertEquals("Xiaomi", manufacturer)
        assertEquals("Redmi", brand)
    }

    @Test
    fun `parse handles empty sequence`() {
        val result = parser.parse(emptySequence(), capturedAt = 0L)
        assertTrue(result.isEmpty())
    }
}
```

- [ ] **Step 3: Do NOT commit yet** — combine with analyzer wiring in the next task.

### Task E2: Wire `GetpropParser` + `DeviceIdentity` into `BugReportAnalyzer`

**Files:**
- Modify: `app/src/main/java/com/androdr/scanner/BugReportAnalyzer.kt`

- [ ] **Step 1: Inject `GetpropParser`**

Add to `BugReportAnalyzer`'s constructor:
```kotlin
private val getpropParser: GetpropParser,
```

- [ ] **Step 2: Parse getprop telemetry + extract device identity**

In the analyzer's main flow (the method that dispatches to modules), before the module dispatch:

```kotlin
// Extract system properties and device identity from the bugreport
val systemProperties = getpropParser.parse(allLines, capturedAt)
val (mfgRaw, brandRaw) = getpropParser.extractManufacturerAndBrand(allLines)
val sourceDevice = DeviceIdentity(
    manufacturer = mfgRaw.trim().lowercase(),
    brand = brandRaw.trim().lowercase(),
)
```

Populate `TelemetryBundle.systemPropertySnapshots` with `systemProperties`.

- [ ] **Step 3: Pass `sourceDevice` to every module's analyze call**

Find where the analyzer calls `accessibilityModule.analyze(...)`, `receiverModule.analyze(...)`, `activityModule.analyze(...)` and add `sourceDevice` as the third argument.

- [ ] **Step 4: Compile**

```bash
./gradlew compileDebugKotlin 2>&1 | tail -10
```

Expected: BUILD SUCCESSFUL.

### Task E3: Update test files that construct the affected scanners/modules

**Files (update each):**
- `app/src/test/java/com/androdr/scanner/AppScannerTelemetryTest.kt`
- `app/src/test/java/com/androdr/scanner/ScanOrchestratorErrorHandlingTest.kt`
- `app/src/test/java/com/androdr/scanner/UsageStatsScannerTest.kt`
- `app/src/test/java/com/androdr/scanner/bugreport/ReceiverModuleTest.kt`
- `app/src/test/java/com/androdr/scanner/bugreport/AccessibilityModuleTest.kt`
- `app/src/test/java/com/androdr/scanner/bugreport/ActivityModuleTest.kt`

- [ ] **Step 1: Update each file's mocks and test method calls**

For MockK-based tests:
```kotlin
// Before:
every { oemPrefixResolver.isOemPrefix(any()) } answers {
    it.invocation.args[0].toString().startsWith("com.samsung.")
}

// After:
every { oemPrefixResolver.isOemPrefix(any(), any()) } answers {
    (it.invocation.args[0] as String).startsWith("com.samsung.")
}
```

For real-resolver tests (AppScannerTelemetryTest, UsageStatsScannerTest), no mock setup change is needed — the real resolver reads the test YAML. But any test that calls `resolver.isOemPrefix(pkg)` must now call `resolver.isOemPrefix(pkg, DeviceIdentity.UNKNOWN)` or a specific test device.

For bugreport module tests that now have a 3-arg `analyze(lines, capturedAt, device)` signature, update the test method calls to pass a DeviceIdentity.

- [ ] **Step 2: Run the full test suite**

```bash
./gradlew testDebugUnitTest 2>&1 | tail -20
```
Expected: BUILD SUCCESSFUL. If specific tests fail, investigate whether they're asserting the old global behavior — those assertions need updating to the new conditional behavior.

- [ ] **Step 3: Commit phases B, C, D, E together**

This is a large commit because all the pieces have to land atomically for the branch to compile. Subagents should commit the whole cohesive change:

```bash
git add app/src/main/java/com/androdr/ioc/OemPrefixResolver.kt \
        app/src/main/java/com/androdr/scanner/AppScanner.kt \
        app/src/main/java/com/androdr/scanner/UsageStatsScanner.kt \
        app/src/main/java/com/androdr/scanner/ScanOrchestrator.kt \
        app/src/main/java/com/androdr/scanner/BugReportAnalyzer.kt \
        app/src/main/java/com/androdr/scanner/bugreport/AccessibilityModule.kt \
        app/src/main/java/com/androdr/scanner/bugreport/ReceiverModule.kt \
        app/src/main/java/com/androdr/scanner/bugreport/ActivityModule.kt \
        app/src/main/java/com/androdr/scanner/bugreport/GetpropParser.kt \
        app/src/main/res/raw/known_oem_prefixes.yml \
        app/src/test/resources/raw/known_oem_prefixes.yml \
        app/src/test/java/com/androdr/ioc/OemPrefixResolverTest.kt \
        app/src/test/java/com/androdr/ioc/OemPrefixResolverConditionalTest.kt \
        app/src/test/java/com/androdr/scanner/bugreport/GetpropParserTest.kt \
        app/src/test/java/com/androdr/scanner/AppScannerTelemetryTest.kt \
        app/src/test/java/com/androdr/scanner/ScanOrchestratorErrorHandlingTest.kt \
        app/src/test/java/com/androdr/scanner/UsageStatsScannerTest.kt \
        app/src/test/java/com/androdr/scanner/bugreport/ReceiverModuleTest.kt \
        app/src/test/java/com/androdr/scanner/bugreport/AccessibilityModuleTest.kt \
        app/src/test/java/com/androdr/scanner/bugreport/ActivityModuleTest.kt

git commit -m "feat(ioc): device-conditional OEM allowlist (#90)

Closes #90. Makes OemPrefixResolver device-conditional so that, for
example, Samsung prefixes only suppress findings on Samsung devices.
An attacker can no longer hide malware under com.samsung.* on a Pixel
and have it classified as OEM.

Changes:
- known_oem_prefixes.yml restructured into unconditional (AOSP,
  chipset, trusted installers, Android Go, custom ROMs) and
  conditional (per-vendor blocks with manufacturer_match / brand_match
  lists) sections.
- OemPrefixResolver public API takes DeviceIdentity at every call.
  Per-device applicable-prefix set is cached via ConcurrentHashMap.
- DeviceIdentity value type with local() and fromSystemProperties()
  factories. local() reads Build.MANUFACTURER/BRAND; the bugreport
  factory reads ro.product.manufacturer/brand from parsed getprop.
- GetpropParser parses the bugreport getprop section into
  SystemPropertySnapshot telemetry and exposes extractManufacturerAndBrand().
- BugReportAnalyzer wires GetpropParser + passes DeviceIdentity to
  every bugreport module.
- All 9 call sites of OemPrefixResolver updated to pass the appropriate
  DeviceIdentity (local for runtime scanners, source-derived for
  bugreport modules).
- Regression test OemPrefixResolverConditionalTest proves the
  prefix-spoofing attack is blocked: com.samsung.android.gearclient on
  a Pixel is not classified as OEM.
- Legacy-flat YAML fallback retained for remote-feed forward compat.

Part of #90."
```

---

## Phase F: Final verification

### Task F1: Run all gradle checks

```bash
export JAVA_HOME=/home/yasir/Applications/android-studio/jbr
cd /home/yasir/AndroDR

./gradlew testDebugUnitTest 2>&1 | tail -30
./gradlew lintDebug 2>&1 | tail -10
./gradlew assembleDebug 2>&1 | tail -5
./gradlew detekt 2>&1 | tail -10
```

All four must be BUILD SUCCESSFUL.

### Task F2: Invariant checks

- [ ] **Check 1: The regression test catches the attack**

```bash
./gradlew testDebugUnitTest --tests "com.androdr.ioc.OemPrefixResolverConditionalTest" 2>&1 | tail -10
```
Expected: BUILD SUCCESSFUL, all tests pass — in particular "Samsung prefix is NOT OEM on a Pixel".

- [ ] **Check 2: The existing legacy tests still pass against conditional logic**

```bash
./gradlew testDebugUnitTest --tests "com.androdr.ioc.OemPrefixResolverTest" 2>&1 | tail -10
```
Expected: BUILD SUCCESSFUL.

- [ ] **Check 3: No sigma package changes**

```bash
git diff feb18f77..HEAD -- app/src/main/java/com/androdr/sigma/
```
Expected: empty.

- [ ] **Check 4: No rule YAML changes**

```bash
git diff feb18f77..HEAD -- 'app/src/main/res/raw/sigma_androdr_*.yml'
```
Expected: empty.

- [ ] **Check 5: All `isOemPrefix` / `isPartnershipPrefix` / `isTrustedInstaller` callers pass a DeviceIdentity**

```bash
grep -rn "isOemPrefix(\|isPartnershipPrefix(\|isTrustedInstaller(" app/src/main/java/ --include="*.kt" | grep -v "//"
```
Every call must have 2 arguments. Any 1-arg call is a missed caller.

- [ ] **Check 6: `SystemPropertySnapshot` is populated**

```bash
grep -rn "SystemPropertySnapshot" app/src/main/java/com/androdr/scanner/
```
Expected: `BugReportAnalyzer.kt` references it (from the existing telemetry bundle) + `GetpropParser.kt` creates it.

### Task F3: Open the PR

```bash
git push -u origin claude/oem-allowlist-device-conditional 2>&1 | tail -5

gh pr create --base main --head claude/oem-allowlist-device-conditional \
  --title "feat(ioc): device-conditional OEM allowlist (#90)" \
  --body "$(cat <<'EOF'
## Summary

Closes #90.

Makes the OEM allowlist device-conditional so that, for example, Samsung
prefixes only suppress findings on Samsung devices. An attacker can no
longer hide malware under \`com.samsung.*\` on a Pixel and have it
classified as OEM. Closes the prefix-spoofing attack documented in #90.

## What changed

### `known_oem_prefixes.yml` restructure

Two top-level sections:

- **\`unconditional:\`** — prefixes that apply on every device regardless
  of manufacturer (AOSP, chipset vendors, trusted installers, Android Go,
  custom ROMs).
- **\`conditional:\`** — per-vendor blocks with \`manufacturer_match\`
  and \`brand_match\` lists. A block only contributes prefixes when
  the assessed device's identity matches.

### New \`DeviceIdentity\` value type

\`\`\`kotlin
data class DeviceIdentity(val manufacturer: String, val brand: String) {
    companion object {
        fun local(): DeviceIdentity  // reads Build.MANUFACTURER / Build.BRAND
        fun fromSystemProperties(properties: Map<String, String>): DeviceIdentity
        val UNKNOWN: DeviceIdentity
    }
}
\`\`\`

### \`OemPrefixResolver\` API change

Every public query method now takes a \`DeviceIdentity\`:

\`\`\`kotlin
fun isOemPrefix(packageName: String, device: DeviceIdentity): Boolean
fun isPartnershipPrefix(packageName: String, device: DeviceIdentity): Boolean
fun isTrustedInstaller(installer: String, device: DeviceIdentity): Boolean
fun applicablePrefixesFor(device: DeviceIdentity): ApplicablePrefixes
\`\`\`

Per-device applicable prefix sets are cached in a \`ConcurrentHashMap\`.
Remote \`refresh()\` clears the cache so subsequent queries re-derive.

### \`GetpropParser\` (new)

Parses the bugreport \`getprop\` section into \`SystemPropertySnapshot\`
telemetry (which was declared in plan 2 of #84 but never populated).
Also exposes \`extractManufacturerAndBrand()\` so \`BugReportAnalyzer\`
can build a source-device \`DeviceIdentity\` for imported bugreports.

### All 9 callers updated

Live-scan callers (\`AppScanner\`, \`UsageStatsScanner\`, \`ScanOrchestrator\`)
pass \`DeviceIdentity.local()\`. Bugreport modules (\`AccessibilityModule\`,
\`ReceiverModule\`, \`ActivityModule\`) accept a \`DeviceIdentity\` parameter
that \`BugReportAnalyzer\` derives from the parsed getprop dump.

### Tests

- **New**: \`OemPrefixResolverConditionalTest\` with 11 tests covering
  the core regression (\"Samsung prefix is NOT OEM on a Pixel\") plus
  matches on same-vendor, chipset prefixes applying universally, AOSP
  prefixes applying universally, \`UNKNOWN\` device falling through to
  unconditional-only, partnership prefix correctness, per-device
  caching, and Huawei/OPPO multi-brand coverage.
- **Updated**: \`OemPrefixResolverTest\` (legacy tests) now passes the
  appropriate \`DeviceIdentity\` for each assertion.
- **New**: \`DeviceIdentityTest\` with 6 tests for the factories and
  normalization.
- **New**: \`GetpropParserTest\` with 7 tests for bracket and equals
  format parsing + device identity extraction.

## Breaking changes

None visible to users. \`BugReportFinding\` and \`Finding\` types are
unchanged. Rule YAML is unchanged. The only API consumers are internal
callers, all updated in this PR.

## Test plan

- [x] \`./gradlew testDebugUnitTest\` BUILD SUCCESSFUL
- [x] \`./gradlew lintDebug\` BUILD SUCCESSFUL
- [x] \`./gradlew assembleDebug\` BUILD SUCCESSFUL
- [x] \`./gradlew detekt\` BUILD SUCCESSFUL
- [x] \`OemPrefixResolverConditionalTest\` asserts the prefix-spoofing attack is blocked
- [x] \`OemPrefixResolverTest\` (legacy) still green
- [ ] Manual verification: install a debug build on a Pixel, install a
      sideloaded APK declaring \`com.samsung.fakepackage\`, run a scan,
      verify the app is NOT suppressed as OEM and IS evaluated by the
      sideloaded-app / impersonation rules. Deferred as a post-merge
      smoke check.

🤖 Generated with [Claude Code](https://claude.com/claude-code)
EOF
)"
```

---

## Plan Retrospective Checklist

- [ ] \`DeviceIdentity\` value type exists with local(), fromSystemProperties(), UNKNOWN factories
- [ ] DeviceIdentityTest passes
- [ ] \`known_oem_prefixes.yml\` restructured into unconditional + conditional sections
- [ ] Test YAML resource mirrors the production YAML
- [ ] \`OemPrefixResolver\` API takes \`DeviceIdentity\` at every public method
- [ ] Per-device cache implemented via \`ConcurrentHashMap\`
- [ ] Legacy flat YAML fallback works for remote forward-compat
- [ ] \`GetpropParser\` parses bracket and equals formats
- [ ] \`GetpropParserTest\` passes
- [ ] \`BugReportAnalyzer\` injects and uses \`GetpropParser\`
- [ ] \`BugReportAnalyzer\` populates \`TelemetryBundle.systemPropertySnapshots\`
- [ ] \`BugReportAnalyzer\` passes source-device identity to every bugreport module
- [ ] All 9 resolver callers pass a \`DeviceIdentity\`
- [ ] \`OemPrefixResolverConditionalTest\` proves the prefix-spoofing attack is blocked
- [ ] Legacy \`OemPrefixResolverTest\` still passes on matching devices
- [ ] All 4 gradle checks pass
- [ ] No sigma package, rule YAML, or UI changes
- [ ] PR opened against main

---

**End of plan.**
