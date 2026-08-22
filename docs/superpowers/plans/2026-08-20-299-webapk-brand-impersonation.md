# WebAPK Brand-Impersonation Detection (#299) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship androdr-092 (scope-anchored WebAPK brand impersonation) and androdr-093 (sideloaded brand impersonation), backed by new `webapk_scope`/`webapk_start_url` emitter fields, a `BrandImpersonationResolver` with `brand_name_db`/`brand_domain_db` lookups, and a seeded financial-brand registry.

**Architecture:** Two new SIGMA rules over one new self-contained resolver (OemPrefixResolver model: bundled res/raw seed + 12h remote refresh + AtomicReference state, no Room). Emitter reads WebAPK shell-manifest meta-data via a targeted per-package `getApplicationInfo(GET_META_DATA)`. Cross-repo: rules-repo branch first (taxonomy, lookup defs, feed data, rules, manifest), AndroDR PR pins the submodule to it; safe-ordering governs the merges.

**Tech Stack:** Kotlin (Hilt, snakeyaml-engine), JUnit4 unit tests, rules-repo Python validators (pyyaml), bash + gh CLI.

**Spec:** `docs/superpowers/specs/2026-08-20-299-webapk-brand-impersonation-design.md` (read it first — it argues every decision below, including the 093 judgment-field redesign and the pre-R1 straggler safety analysis).

## Global Constraints

- Working tree: `/home/yasir/AndroDR/.claude/worktrees/phase2-from-trusted-store`, branch `feat/299-webapk-brand-impersonation` (cut from main). Submodule: `third-party/android-sigma-rules` — do all rules-repo edits there on branch `feat/299-brand-impersonation` (create in Task 1).
- Env for every gradle/adb command: `export JAVA_HOME=/home/yasir/Applications/android-studio/jbr ANDROID_HOME=/home/yasir/Android/Sdk`. `gh` is at `$HOME/.local/bin`.
- Sandbox rejects compound/redirect shell patterns: write multi-step shell (e.g. the `rules.sha256` regen loop) as a script file under `/home/yasir/.claude/jobs/26a3473e/tmp/` and run it.
- Rule YAML: 4-space indent, key order per androdr-089 (`title,id,status,category,description,author,date,references,tags,logsource,detection,level,falsepositives,display,remediation`), `date: 2026/08/20`, ids `androdr-092`/`androdr-093` (090 earmarked for IME, 091 in staging, 084 retired).
- ioc-data YAML: 2-space indent, structural shape (NO `entries:` key — that is what keeps `ioc-entry-schema.json` untouched).
- NO judgment fields (`from_trusted_store`, `is_sideloaded`, `is_known_oem_app`) in either new rule — the allowlist is remove-only.
- No parentheses in rule `condition:` (flat grammar only).
- ScanOrchestrator lookup registrations must be spelled `"name" to {` on one line (the cross-check test extracts keys with `Regex("\"([A-Za-z0-9_]+)\"\\s+to\\s*\\{")`).
- Every rule test pins every field its rule references, explicitly, in every record (anti-vacuity discipline from #296).
- Commit style: conventional commits ending with the Co-Authored-By/Claude-Session trailer used earlier on this branch.
- **HitL GATE:** Task 3's brand seed data must be approved by the user entry-by-entry BEFORE the feed files are written/committed. Do not proceed past that gate without explicit approval.

---

### Task 1: Emitter fields `webapk_scope` / `webapk_start_url` (taxonomy + AppTelemetry + AppScanner, atomic)

**Files:**
- Modify: `third-party/android-sigma-rules/validation/logsource-taxonomy.yml` (app_scanner `fields:`, ends at `embedded_native_lib`, ~line 51)
- Modify: `app/src/main/java/com/androdr/data/model/AppTelemetry.kt` (ctor tail ~line 44; `toFieldMap()` ~lines 46–70)
- Modify: `app/src/main/java/com/androdr/scanner/AppScanner.kt` (`buildTelemetryForPackage`, insert after line ~302, plus companion constants)
- Test (existing, must stay green): `app/src/test/java/com/androdr/sigma/LogsourceTaxonomyCrossCheckTest.kt` — no edit needed; it builds a dummy `AppTelemetry` with named args and compares `toFieldMap().keys` to the taxonomy, so *defaulted* new params require no test change.

**Interfaces:**
- Produces: `AppTelemetry.webapkScope: String?`, `AppTelemetry.webapkStartUrl: String?` (both default `null`); field-map keys `webapk_scope`, `webapk_start_url`. Task 5's rules and Task 6's rule tests key on these names.

- [ ] **Step 1: Create the submodule branch**

```bash
cd third-party/android-sigma-rules && git checkout -b feat/299-brand-impersonation origin/main
```
(Fetch origin first if stale. The submodule must be at rules-main `c37c580` or later.)

- [ ] **Step 2: Add the two taxonomy fields** — append after the `embedded_native_lib:` line, same one-line flow style:

```yaml
      webapk_scope: { kind: raw_fact, type: string, nullable: true, description: "WebAPK web scope URL read from shell-manifest meta-data org.chromium.webapk.shell_apk.scope; null for non-WebAPK packages or when unreadable (AndroDR #299)" }
      webapk_start_url: { kind: raw_fact, type: string, nullable: true, description: "WebAPK start URL read from shell-manifest meta-data org.chromium.webapk.shell_apk.startUrl; null for non-WebAPK packages or when unreadable (AndroDR #299)" }
```

- [ ] **Step 3: Run the cross-check test to verify it fails** (taxonomy now ahead of Kotlin):

```bash
./gradlew testDebugUnitTest --tests "com.androdr.sigma.LogsourceTaxonomyCrossCheckTest"
```
Expected: FAIL — "fields in taxonomy but missing from Kotlin toFieldMap(): [webapk_scope, webapk_start_url]".

- [ ] **Step 4: Add the fields to AppTelemetry** — after `embeddedNativeLibs` in the ctor:

```kotlin
    // WebAPK shell-manifest meta-data (#299): web scope + start URL for
    // org.chromium.webapk.* packages; null for every other app.
    val webapkScope: String? = null,
    val webapkStartUrl: String? = null,
```
and at the end of `toFieldMap()` (after `"embedded_native_lib" to embeddedNativeLibs`):

```kotlin
        // NEW (#299):
        "webapk_scope" to webapkScope,
        "webapk_start_url" to webapkStartUrl
```
(mind the comma on the previous last entry).

- [ ] **Step 5: Re-run the cross-check test** — Expected: PASS.

- [ ] **Step 6: Emit from AppScanner.** In `buildTelemetryForPackage`, after the `embeddedNativeLibs` line (~302) and before `return AppTelemetry(`:

```kotlin
        // WebAPK shell-manifest meta-data (#299). Targeted per-package read:
        // the bulk getInstalledPackages call deliberately omits GET_META_DATA
        // (Binder size pressure), and only org.chromium.webapk.* packages can
        // satisfy the WebAPK rules' selection anyway.
        var webapkScope: String? = null
        var webapkStartUrl: String? = null
        if (packageName.startsWith(WEBAPK_PACKAGE_PREFIX)) {
            @Suppress("TooGenericExceptionCaught", "SwallowedException")
            try {
                val metaData = pm.getApplicationInfo(
                    packageName, PackageManager.GET_META_DATA
                ).metaData
                webapkScope = metaData?.getString(WEBAPK_META_SCOPE)
                webapkStartUrl = metaData?.getString(WEBAPK_META_START_URL)
            } catch (e: Exception) {
                Log.w(
                    TAG,
                    "collectTelemetry: WebAPK meta-data read failed for $packageName: ${e.message}"
                )
            }
        }
```
In the `AppTelemetry(` construction add `webapkScope = webapkScope, webapkStartUrl = webapkStartUrl,` after `embeddedNativeLibs = embeddedNativeLibs,`. In the companion object add:

```kotlin
        private const val WEBAPK_PACKAGE_PREFIX = "org.chromium.webapk."
        private const val WEBAPK_META_SCOPE = "org.chromium.webapk.shell_apk.scope"
        private const val WEBAPK_META_START_URL = "org.chromium.webapk.shell_apk.startUrl"
```

- [ ] **Step 7: Compile + full sigma test package**

```bash
./gradlew testDebugUnitTest --tests "com.androdr.sigma.*"
```
Expected: PASS (taxonomy cross-check, PureEmitterContractTest, DetectionFieldCrossCheckTest all green — no rule references the new fields yet).

- [ ] **Step 8: Commit** (AndroDR side only — the submodule branch is committed in Task 4 with the rest of the rules-repo edits; a dirty-submodule state between tasks is expected and fine):

```bash
git add app/src/main/java/com/androdr/data/model/AppTelemetry.kt app/src/main/java/com/androdr/scanner/AppScanner.kt
git commit -m "feat(scanner): emit webapk_scope/webapk_start_url from WebAPK shell-manifest meta-data (#299)"
```

---

### Task 2: `BrandImpersonationResolver` (TDD — matchers first)

**Files:**
- Create: `app/src/main/java/com/androdr/ioc/BrandImpersonationResolver.kt`
- Create: `app/src/test/java/com/androdr/ioc/BrandImpersonationResolverTest.kt`

**Interfaces:**
- Consumes: `SafeHttpFetch.fetch(url, maxBytes, timeoutMs): String?` (existing), snakeyaml-engine `Load` (same imports as `PublicRepoIocFeed`), `R.raw.brand_names` / `R.raw.brand_domains` (created in Task 3 — until then the bundled load path returns empty; keep it lazily-failing-soft so this task's tests pass without the resources by injecting YAML strings directly).
- Produces: `@Singleton class BrandImpersonationResolver @Inject constructor(@ApplicationContext context: Context)` with `fun matchesBrandName(label: String): Boolean`, `fun matchesBrandDomain(scopeUrl: String): Boolean`, `suspend fun refresh()`, and `internal fun parseBrandYaml(yaml: String, listKey: String): List<String>` for tests. Task 5 registers the two `matches*` functions as lookups.

- [ ] **Step 1: Write the failing tests** — `BrandImpersonationResolverTest.kt`:

```kotlin
package com.androdr.ioc

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Matcher-semantics tests for the brand impersonation registry (#299).
 * Exercises the pure matching core via [BrandImpersonationResolver.BrandMatcher]
 * so no Android Context is needed.
 */
class BrandImpersonationResolverTest {

    private val matcher = BrandImpersonationResolver.BrandMatcher(
        nameVariants = listOf("PayPal", "Chase Bank", "PKO Bank Polski"),
        domains = setOf("paypal.com", "chase.com", "pkobp.pl"),
    )

    // ── name matching: word-boundary, case-insensitive containment ──

    @Test
    fun `exact label matches`() =
        assertTrue(matcher.matchesName("PayPal"))

    @Test
    fun `variant inside longer label matches`() =
        assertTrue(matcher.matchesName("Chase Bank Login"))

    @Test
    fun `case-insensitive`() =
        assertTrue(matcher.matchesName("payPAL secure"))

    @Test
    fun `substring inside a word does NOT match`() {
        // "chase" occurs inside "Purchase" with no word boundary.
        assertFalse(matcher.matchesName("Purchase Tracker"))
    }

    @Test
    fun `multi-token variant does not match its tokens separately`() =
        assertFalse(matcher.matchesName("Chase Online"))

    @Test
    fun `unrelated label does not match`() =
        assertFalse(matcher.matchesName("Sudoku Deluxe"))

    @Test
    fun `blank label does not match`() =
        assertFalse(matcher.matchesName(""))

    // ── domain matching: URL host, label-boundary suffix walk ──

    @Test
    fun `exact scope host matches`() =
        assertTrue(matcher.matchesDomain("https://paypal.com/"))

    @Test
    fun `subdomain scope matches`() =
        assertTrue(matcher.matchesDomain("https://www.paypal.com/signin"))

    @Test
    fun `suffix without label boundary does NOT match`() =
        assertFalse(matcher.matchesDomain("https://notchase.com/"))

    @Test
    fun `unlisted domain does not match`() =
        assertFalse(matcher.matchesDomain("https://evil.example/"))

    @Test
    fun `non-URL scope does not match`() =
        assertFalse(matcher.matchesDomain("not a url"))

    @Test
    fun `blank scope does not match`() =
        assertFalse(matcher.matchesDomain(""))

    @Test
    fun `trailing-dot host is normalized`() =
        assertTrue(matcher.matchesDomain("https://paypal.com./"))

    // ── YAML parsing (structural brands: shape) ──

    @Test
    fun `parses display_names from structural yaml`() {
        val yaml = """
            version: "2026-08-20"
            brands:
              paypal:
                display_names: ["PayPal"]
              chase:
                display_names: ["Chase Bank", "Chase Mobile"]
        """.trimIndent()
        val names = BrandImpersonationResolver.parseBrandYaml(yaml, "display_names")
        assertTrue(names.containsAll(listOf("PayPal", "Chase Bank", "Chase Mobile")))
    }

    @Test
    fun `parses domains and malformed yaml yields empty`() {
        val yaml = """
            brands:
              paypal:
                domains: [paypal.com]
        """.trimIndent()
        assertTrue(BrandImpersonationResolver.parseBrandYaml(yaml, "domains").contains("paypal.com"))
        assertTrue(BrandImpersonationResolver.parseBrandYaml("{ not: [valid", "domains").isEmpty())
    }
}
```

- [ ] **Step 2: Run to verify failure**

```bash
./gradlew testDebugUnitTest --tests "com.androdr.ioc.BrandImpersonationResolverTest"
```
Expected: compile FAIL — `BrandImpersonationResolver` unresolved.

- [ ] **Step 3: Implement** — `BrandImpersonationResolver.kt`:

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
import java.net.URI
import java.util.Locale
import java.util.concurrent.atomic.AtomicReference
import javax.inject.Inject
import javax.inject.Singleton

/**
 * Brand impersonation registry (#299): display-name variants and official
 * domains of impersonation-protected brands (financial/payment).
 *
 * Backs the `brand_name_db` and `brand_domain_db` SIGMA lookups. Follows the
 * OemPrefixResolver delivery model: bundled res/raw seeds for cold start, a
 * direct remote refresh of the two ioc-data files on the 12h intel cycle,
 * and an in-memory AtomicReference swap — no Room.
 *
 * Matching semantics (spec 2026-08-20-299):
 *  - names: word-boundary, case-insensitive containment of a variant in the
 *    emitted app label ("Chase Bank" matches "Chase Bank Login", never
 *    "Purchase Tracker");
 *  - domains: host of the scope URL, label-boundary suffix walk
 *    ("paypal.com" matches "www.paypal.com", never "notpaypal.com").
 */
@Singleton
class BrandImpersonationResolver @Inject constructor(
    @ApplicationContext private val context: Context,
) {

    /** Pure matching core — constructible without a Context for tests. */
    class BrandMatcher(nameVariants: List<String>, private val domains: Set<String>) {

        private val variantPatterns: List<Regex> = nameVariants
            .filter { it.isNotBlank() }
            .take(MAX_NAME_VARIANTS)
            .map {
                Regex(
                    "(?<![\\p{L}\\p{N}])" + Regex.escape(it) + "(?![\\p{L}\\p{N}])",
                    RegexOption.IGNORE_CASE
                )
            }

        fun matchesName(label: String): Boolean {
            if (label.isBlank()) return false
            return variantPatterns.any { it.containsMatchIn(label) }
        }

        @Suppress("SwallowedException", "TooGenericExceptionCaught")
        fun matchesDomain(scopeUrl: String): Boolean {
            if (scopeUrl.isBlank()) return false
            val host = try {
                URI(scopeUrl.trim()).host
            } catch (e: Exception) {
                null
            } ?: return false
            // Label-boundary suffix walk (same semantics as BlocklistManager):
            // strip the leftmost label until a listed domain is hit.
            var candidate = host.trimEnd('.').lowercase(Locale.ROOT)
            while (candidate.isNotEmpty()) {
                if (candidate in domains) return true
                val dot = candidate.indexOf('.')
                if (dot < 0) break
                candidate = candidate.substring(dot + 1)
            }
            return false
        }
    }

    private val bundled: BrandMatcher by lazy {
        BrandMatcher(
            nameVariants = parseBrandYaml(readRawResource(R.raw.brand_names), KEY_NAMES),
            domains = parseBrandYaml(readRawResource(R.raw.brand_domains), KEY_DOMAINS)
                .map { it.lowercase(Locale.ROOT) }.toSet(),
        )
    }

    private val remote = AtomicReference<BrandMatcher?>(null)

    private fun effective(): BrandMatcher = remote.get() ?: bundled

    fun matchesBrandName(label: String): Boolean = effective().matchesName(label)

    fun matchesBrandDomain(scopeUrl: String): Boolean = effective().matchesDomain(scopeUrl)

    /**
     * Fetch the two ioc-data files from rules main and swap them in. Either
     * fetch failing (or yielding an empty parse) keeps the previous state —
     * a partial registry must never replace a fuller one.
     */
    suspend fun refresh() = withContext(Dispatchers.IO) {
        val namesYaml = SafeHttpFetch.fetch(NAMES_URL, maxBytes = MAX_FETCH_BYTES, timeoutMs = TIMEOUT_MS)
        val domainsYaml = SafeHttpFetch.fetch(DOMAINS_URL, maxBytes = MAX_FETCH_BYTES, timeoutMs = TIMEOUT_MS)
        if (namesYaml == null || domainsYaml == null) {
            Log.w(TAG, "refresh: fetch failed (names=${namesYaml != null}, domains=${domainsYaml != null})")
            return@withContext
        }
        val names = parseBrandYaml(namesYaml, KEY_NAMES)
        val domains = parseBrandYaml(domainsYaml, KEY_DOMAINS).map { it.lowercase(Locale.ROOT) }.toSet()
        if (names.isEmpty() || domains.isEmpty()) {
            Log.w(TAG, "refresh: empty parse (names=${names.size}, domains=${domains.size}) — keeping previous state")
            return@withContext
        }
        remote.set(BrandMatcher(names, domains))
        Log.i(TAG, "refresh: ${names.size} name variants, ${domains.size} domains")
    }

    @Suppress("SwallowedException", "TooGenericExceptionCaught")
    private fun readRawResource(resId: Int): String = try {
        context.resources.openRawResource(resId).bufferedReader().use { it.readText() }
    } catch (e: Exception) {
        Log.w(TAG, "readRawResource failed: ${e.message}")
        ""
    }

    companion object {
        private const val TAG = "BrandImpersonation"
        private const val KEY_NAMES = "display_names"
        private const val KEY_DOMAINS = "domains"
        private const val MAX_NAME_VARIANTS = 500
        private const val MAX_LIST_VALUES = 2000
        private const val MAX_FETCH_BYTES = 262_144
        private const val TIMEOUT_MS = 15_000
        private const val NAMES_URL =
            "https://raw.githubusercontent.com/android-sigma-rules/rules/main/ioc-data/brand-names.yml"
        private const val DOMAINS_URL =
            "https://raw.githubusercontent.com/android-sigma-rules/rules/main/ioc-data/brand-domains.yml"

        /**
         * Parse the structural `brands:` shape shared by both files and
         * collect every string under [listKey] across all brands.
         */
        @Suppress("SwallowedException", "TooGenericExceptionCaught")
        internal fun parseBrandYaml(yaml: String, listKey: String): List<String> = try {
            val settings = LoadSettings.builder()
                .setAllowDuplicateKeys(false)
                .setMaxAliasesForCollections(10)
                .build()
            val doc = Load(settings).loadFromString(yaml) as? Map<*, *> ?: emptyMap<Any, Any>()
            val brands = doc["brands"] as? Map<*, *> ?: emptyMap<Any, Any>()
            brands.values.asSequence()
                .mapNotNull { it as? Map<*, *> }
                .flatMap { (it[listKey] as? List<*>).orEmpty().asSequence() }
                .mapNotNull { it?.toString()?.trim()?.takeIf(String::isNotEmpty) }
                .take(MAX_LIST_VALUES)
                .toList()
        } catch (e: Exception) {
            emptyList()
        }
    }
}
```
NOTE: check `SafeHttpFetch`'s actual object/parameter names against `PublicRepoIocFeed.kt:190-191` before compiling and adapt the call if the signature differs.

- [ ] **Step 4: Run tests** — Expected: PASS (the `BrandMatcher` and `parseBrandYaml` paths need no Context; the `bundled` lazy is never touched).

- [ ] **Step 5: Wire the refresh.** Find the refresh site:

```bash
grep -rn "oemPrefixResolver.refresh\|\.refresh()" app/src/main/java/com/androdr/ioc/IntelRefresher.kt app/src/main/java/com/androdr/ioc/IocUpdateWorker.kt 2>/dev/null; grep -rln "oemPrefixResolver.refresh" app/src/main/java
```
Wherever `oemPrefixResolver.refresh()` is invoked on the 12h cycle (expected: `IntelRefresher`), add a constructor injection `private val brandImpersonationResolver: BrandImpersonationResolver,` and the call `brandImpersonationResolver.refresh()` immediately after the OEM one, inside the same error-isolation wrapper style used there (each refresh failure must not abort the others).

- [ ] **Step 6: Full ioc test package + compile**

```bash
./gradlew testDebugUnitTest --tests "com.androdr.ioc.*"
```
Expected: PASS. (`R.raw.brand_names` doesn't exist yet — if compilation fails on the R reference, create the two res/raw files as placeholders NOW with the header-only content `version: "2026-08-20"\nbrands: {}` and note that Task 3 replaces them post-HitL.)

- [ ] **Step 7: Commit**

```bash
git add app/src/main/java/com/androdr/ioc/BrandImpersonationResolver.kt app/src/test/java/com/androdr/ioc/BrandImpersonationResolverTest.kt app/src/main/java/com/androdr/ioc/IntelRefresher.kt
git commit -m "feat(ioc): BrandImpersonationResolver — word-boundary name + scope-host suffix matchers, bundled seed + 12h refresh (#299)"
```
(Include the res/raw placeholders if Step 6 required them.)

---

### Task 3: Brand seed data — **HitL GATE**, then feed files + bundled seeds + parity

**Files:**
- Create: `third-party/android-sigma-rules/ioc-data/brand-names.yml`
- Create: `third-party/android-sigma-rules/ioc-data/brand-domains.yml`
- Modify: `third-party/android-sigma-rules/validation/validate-ioc-complementarity.py` (`IOC_TYPE_BY_FILENAME`, ~line 30)
- Create: `app/src/main/res/raw/brand_names.yml`, `app/src/main/res/raw/brand_domains.yml` (byte-copies of the ioc-data files)
- Modify: `app/src/test/java/com/androdr/ioc/OemPrefixMirrorParityTest.kt` (add the two new pairs — its KDoc at :26-29 invites this)

**Interfaces:**
- Consumes: user approval of the seed table (THE GATE).
- Produces: the exact registry content both rules match against; `R.raw.brand_names`/`R.raw.brand_domains` consumed by Task 2's resolver.

- [ ] **Step 1: STOP — present the draft seed table to the user for per-entry approval.** Draft (curation policy: variants distinctive — multi-token or unambiguous tokens; ambiguous dictionary words banned even at the cost of coverage on brands whose real label is one):

| Brand | display_names | domains |
|---|---|---|
| PayPal | PayPal | paypal.com |
| Chase | Chase Bank, Chase Mobile | chase.com |
| Bank of America | Bank of America, BofA | bankofamerica.com, bofa.com |
| Wells Fargo | Wells Fargo | wellsfargo.com |
| Citi | Citibank, Citi Mobile | citi.com, citibank.com |
| Capital One | Capital One | capitalone.com |
| Venmo | Venmo | venmo.com |
| Cash App | Cash App | cash.app |
| Zelle | Zelle | zellepay.com, zelle.com |
| Barclays | Barclays | barclays.co.uk, barclays.com |
| HSBC | HSBC | hsbc.com, hsbc.co.uk |
| Santander | Santander | santander.com, santander.co.uk, santander.pl |
| Revolut | Revolut | revolut.com |
| N26 | N26 | n26.com |
| Monzo | Monzo | monzo.com |
| ING | ING Bank, ING Banking | ing.com, ing.nl, ing.pl |
| BBVA | BBVA | bbva.com, bbva.es, bbva.mx |
| PKO Bank Polski | PKO Bank Polski, iPKO, IKO | pkobp.pl, ipko.pl |
| mBank | mBank | mbank.pl |
| Nubank | Nubank | nubank.com.br |
| MB WAY | MB WAY | mbway.pt |
| Millennium BCP | Millennium BCP | millenniumbcp.pt |
| Caixa Geral de Depósitos | Caixadirecta | cgd.pt |

Known trade-offs to surface at the gate: "Wise" and bare "Chase"/"Citi" are banned-ambiguous (real single-word labels evade — accepted); "IKO"/"iPKO" are short but non-dictionary.

- [ ] **Step 2 (post-approval): Write `ioc-data/brand-names.yml`** — structural shape, approved entries only:

```yaml
version: "2026-08-20"
description: >
  Display-name variants of brands protected against impersonation
  (AndroDR #299). Consumed by the brand_name_db ioc_lookup (androdr-092,
  androdr-093) via AndroDR's BrandImpersonationResolver: word-boundary,
  case-insensitive containment against the emitted app_name. This file has
  no entries: key by design — it takes validate-ioc-data.py's structural
  early-return path, like known-oem-prefixes.yml.
  CURATION POLICY: variants must be distinctive — multi-token, or single
  tokens that are not dictionary words. Ambiguous words (chase, wise) are
  banned even though some brands' real labels are exactly that; the
  coverage loss is accepted over the false-positive surface.
sources:
  - manual-curation
brands:
  paypal:
    display_names: ["PayPal"]
  chase:
    display_names: ["Chase Bank", "Chase Mobile"]
  # ... one block per approved brand, alphabetical after the first two ...
```
and `ioc-data/brand-domains.yml` in the same shape with `domains:` lists (header notes the host-suffix matching semantics and that domains must be registrable domains, no scheme/path, lowercase).

- [ ] **Step 3: Add both filenames to the complementarity map** in `validation/validate-ioc-complementarity.py`:

```python
    "brand-names.yml":      "BRAND_NAME",
    "brand-domains.yml":    "BRAND_DOMAIN",
```

- [ ] **Step 4: Run the rules-repo validators**

```bash
cd third-party/android-sigma-rules
python3 validation/validate-ioc-data.py ioc-data/brand-names.yml
python3 validation/validate-ioc-data.py ioc-data/brand-domains.yml
python3 validation/validate-ioc-complementarity.py --all --mode advisory
```
Expected: both files "PASS … (no entries)"; complementarity exits 0 (advisory warnings about parser_limited feeds are normal).

- [ ] **Step 5: Copy byte-identical seeds into res/raw** (overwriting Task 2 placeholders if any):

```bash
cp third-party/android-sigma-rules/ioc-data/brand-names.yml app/src/main/res/raw/brand_names.yml
cp third-party/android-sigma-rules/ioc-data/brand-domains.yml app/src/main/res/raw/brand_domains.yml
```

- [ ] **Step 6: Extend `OemPrefixMirrorParityTest`** — read the test, add the two pairs to whatever structure holds the existing `known_oem_prefixes.yml ↔ ioc-data/known-oem-prefixes.yml` case: `app/src/main/res/raw/brand_names.yml ↔ ioc-data/brand-names.yml` and `brand_domains.yml ↔ ioc-data/brand-domains.yml`. Run it red first (before Step 5's copy, if convenient) then green:

```bash
./gradlew testDebugUnitTest --tests "com.androdr.ioc.OemPrefixMirrorParityTest"
```
Expected: PASS.

- [ ] **Step 7: Commit** (AndroDR side; submodule content is committed in Task 4):

```bash
git add app/src/main/res/raw/brand_names.yml app/src/main/res/raw/brand_domains.yml app/src/test/java/com/androdr/ioc/OemPrefixMirrorParityTest.kt
git commit -m "feat(ioc): bundle brand impersonation registry seeds + mirror parity gate (#299)"
```

---### Task 4: Lookup registration + rules-repo contract (atomic: YAML defs + ScanOrchestrator + cross-check literal)

**Files:**
- Modify: `third-party/android-sigma-rules/validation/ioc-lookup-definitions.yml` (append after `known_good_app_db`, before `trusted_installer_db`)
- Modify: `app/src/main/java/com/androdr/scanner/ScanOrchestrator.kt` (`setIocLookups(mapOf(` block, lines ~165-186; constructor ~lines 58-61)
- Modify: `app/src/test/java/com/androdr/sigma/IocLookupDefinitionsCrossCheckTest.kt` (`kotlinLookupNames`, lines 36-43)

**Interfaces:**
- Consumes: `BrandImpersonationResolver.matchesBrandName/matchesBrandDomain` (Task 2).
- Produces: registered lookup names `brand_name_db`, `brand_domain_db` — the exact strings Task 5's rules reference.

- [ ] **Step 1: Run the cross-check test, confirm green baseline**, then add to `ioc-lookup-definitions.yml`:

```yaml
  brand_name_db:
    type: BRAND_NAME
    files: [ioc-data/brand-names.yml]
    description: "Display-name variants of impersonation-protected brands (financial/payment). Word-boundary, case-insensitive match against the emitted app_name via BrandImpersonationResolver. AndroDR #299."

  brand_domain_db:
    type: BRAND_DOMAIN
    files: [ioc-data/brand-domains.yml]
    description: "Official web domains of impersonation-protected brands. Host-suffix match against the emitted webapk_scope URL's host via BrandImpersonationResolver. AndroDR #299."
```

- [ ] **Step 2: Run `IocLookupDefinitionsCrossCheckTest` — verify it FAILS** (YAML ahead of Kotlin).

- [ ] **Step 3: Register in ScanOrchestrator.** Add ctor param `private val brandImpersonationResolver: com.androdr.ioc.BrandImpersonationResolver,` next to the other resolvers, and in the `setIocLookups(mapOf(` block after the `trusted_installer_db` entry:

```kotlin
            // Brand impersonation registry (#299): word-boundary display-name
            // match + scope-host suffix match, resolver-backed (bundled seed
            // + 12h remote refresh). Backs androdr-092/093.
            "brand_name_db" to { v ->
                brandImpersonationResolver.matchesBrandName(v.toString())
            },
            "brand_domain_db" to { v ->
                brandImpersonationResolver.matchesBrandDomain(v.toString())
            }
```
(The one-line `"name" to {` spelling is REQUIRED — the cross-check test regex-extracts it.)

- [ ] **Step 4: Update the test literal** — `kotlinLookupNames` gains `"brand_name_db", "brand_domain_db",`.

- [ ] **Step 5: Run the cross-check + full sigma package — verify PASS**

```bash
./gradlew testDebugUnitTest --tests "com.androdr.sigma.IocLookupDefinitionsCrossCheckTest" --tests "com.androdr.sigma.*"
```

- [ ] **Step 6: Commit AndroDR side + snapshot the submodule branch.** Commit the submodule's accumulated edits (taxonomy from Task 1, feed files + complementarity from Task 3, lookup defs from this task) as one rules-repo commit:

```bash
cd third-party/android-sigma-rules
git add validation/logsource-taxonomy.yml validation/ioc-lookup-definitions.yml validation/validate-ioc-complementarity.py ioc-data/brand-names.yml ioc-data/brand-domains.yml
git commit -m "feat(schema+ioc): webapk_scope/start_url fields, brand_name_db/brand_domain_db lookups, brand registry seed (AndroDR #299)"
```
then in AndroDR:

```bash
git add app/src/main/java/com/androdr/scanner/ScanOrchestrator.kt app/src/test/java/com/androdr/sigma/IocLookupDefinitionsCrossCheckTest.kt third-party/android-sigma-rules
git commit -m "feat(detection): register brand_name_db/brand_domain_db lookups (#299)"
```

---

### Task 5: The two rules (submodule YAML + rules.txt + sha256 + bundled copies + engine manifest)

**Files:**
- Create: `third-party/android-sigma-rules/app_scanner/androdr_092_webapk_brand_impersonation.yml`
- Create: `third-party/android-sigma-rules/app_scanner/androdr_093_sideloaded_brand_impersonation.yml`
- Modify: `third-party/android-sigma-rules/rules.txt` (insert both after `app_scanner/androdr_089_sms_notification_otp_theft.yml`, keeping sort), regenerate `rules.sha256`
- Create: `app/src/main/res/raw/sigma_androdr_092_webapk_brand_impersonation.yml`, `app/src/main/res/raw/sigma_androdr_093_sideloaded_brand_impersonation.yml` (byte-copies)
- Modify: `app/src/main/java/com/androdr/sigma/SigmaRuleEngine.kt` (BUNDLED_RULE_IDS, insert at line ~384 after `R.raw.sigma_androdr_089_sms_notification_otp_theft,`)

**Interfaces:**
- Consumes: field names from Task 1, lookup names from Task 4.
- Produces: rule ids `androdr-092`/`androdr-093`; bundled resources `R.raw.sigma_androdr_092_webapk_brand_impersonation`, `R.raw.sigma_androdr_093_sideloaded_brand_impersonation`; Task 6's tests load these files by path.

- [ ] **Step 1: Write androdr-092** (submodule `app_scanner/androdr_092_webapk_brand_impersonation.yml`):

```yaml
title: WebAPK impersonating a protected brand
id: androdr-092
status: experimental
category: incident
description: >
    A Chrome-minted web app (WebAPK) uses a protected brand's display name,
    but its web scope does not belong to that brand's official domains.
    Google's WebAPK minting service is unauthenticated: any website can be
    minted into a Google-signed WebAPK, and credential-phishing sites
    impersonating banks have shipped this way (documented PKO Bank Polski
    case). The scope is derived from the origin serving the web manifest, so
    an attacker cannot mint a WebAPK scoped to a domain they do not control
    - a brand name over a foreign scope is a high-confidence phishing
    signal. Deliberately independent of installer trust: a phishing WebAPK
    delivered through the Play install path must still fire. A brand-named
    WebAPK with no scope meta-data also fires - every genuinely minted
    WebAPK carries the scope key, so absence is itself suspicious.
author: AndroDR
date: 2026/08/20
references:
    - https://attack.mitre.org/techniques/T1036/005/
    - https://www.bleepingcomputer.com/news/security/webapk-technology-abused-to-install-malware-on-android-devices/
    - https://chromium.googlesource.com/chromium/src/+/HEAD/chrome/android/webapk/README.md
tags:
    - attack.t1036.005
logsource:
    product: androdr
    service: app_scanner
detection:
    selection:
        package_name|startswith: "org.chromium.webapk."
        app_name|ioc_lookup: brand_name_db
    scope_legit:
        webapk_scope|ioc_lookup: brand_domain_db
    condition: selection and not scope_legit
level: high
falsepositives:
    - "A brand's genuine web app served from an official domain missing from the brand-domains registry (e.g. a regional or newly launched domain). Fix by adding the domain to ioc-data/brand-domains.yml - the rule exempts any scope inside a listed official domain."
display:
    category: app_risk
    icon: content_copy
    triggered_title: "Brand Impersonation (Web App)"
    evidence_type: none
    guidance: "UNINSTALL -- web app named like a protected brand but not served from the brand's official site"
remediation:
    - "This web app is named like a well-known brand, but it points at {webapk_scope} - not the brand's official site. Phishing pages disguise themselves as banking apps exactly this way."
    - "Uninstall it: Settings > Apps > [this app] > Uninstall. Then install the brand's official app from Google Play, or use the brand's website directly in your browser."
```

- [ ] **Step 2: Write androdr-093** (submodule `app_scanner/androdr_093_sideloaded_brand_impersonation.yml`):

```yaml
title: Sideloaded app impersonating a protected brand
id: androdr-093
status: experimental
category: incident
description: >
    A sideloaded native app uses a protected brand's display name (a bank or
    payment provider) but was not installed from a trusted app store.
    Banking trojans and phishing droppers routinely name themselves after
    the institution they target. Chrome-minted WebAPKs are excluded here:
    they carry a web scope and are judged by the sharper scope-anchored
    androdr-092 instead.
author: AndroDR
date: 2026/08/20
references:
    - https://attack.mitre.org/techniques/T1036/005/
tags:
    - attack.t1036.005
logsource:
    product: androdr
    service: app_scanner
detection:
    selection:
        is_system_app: false
        app_name|ioc_lookup: brand_name_db
    store_installed:
        installer|ioc_lookup: trusted_installer_db
    filter_known_good:
        # Installer-gated exemption (the androdr-089 pattern, in Phase-2
        # idiom): known_good_app_db is a package-name-only lookup with no
        # signature binding (ADR #51), and a sideloaded fake can adopt any
        # package name. Because the condition requires NOT store_installed,
        # this exemption is unreachable for sideloads by design - an
        # impersonation backstop, not a noise filter.
        package_name|ioc_lookup: known_good_app_db
        installer|ioc_lookup: trusted_installer_db
    filter_webapk:
        package_name|startswith: "org.chromium.webapk."
    condition: selection and not store_installed and not filter_known_good and not filter_webapk
level: high
falsepositives:
    - "A genuinely brand-published APK sideloaded from outside any store (e.g. an APK mirror): the known-good exemption is deliberately unreachable for sideloads (see filter comment), so every sideloaded app whose name matches a protected brand fires and needs user judgement. The safe remediation is to reinstall from Google Play."
display:
    category: app_risk
    icon: content_copy
    triggered_title: "Brand Impersonation (Sideloaded)"
    evidence_type: none
    guidance: "UNINSTALL -- sideloaded app named like a protected brand; likely a fake"
remediation:
    - "This app is named like a well-known brand but was not installed from a trusted app store. Fake banking and payment apps are distributed exactly this way."
    - "Uninstall it: Settings > Apps > [this app] > Uninstall. Then install the brand's official app from Google Play."
```
(NO `implies_flags` on either rule — see spec §2.)

- [ ] **Step 3: rules.txt + rules.sha256.** Insert the two paths after the `androdr_089` line of `rules.txt`, then regenerate the manifest via a script file (sandbox: no inline redirect-into-loop):

```bash
cat > /home/yasir/.claude/jobs/26a3473e/tmp/regen-manifest.sh <<'EOF'
#!/bin/bash
set -e
cd /home/yasir/AndroDR/.claude/worktrees/phase2-from-trusted-store/third-party/android-sigma-rules
while read -r f; do printf '%s  %s\n' "$(sha256sum "$f" | cut -d' ' -f1)" "$f"; done < rules.txt > rules.sha256
EOF
bash /home/yasir/.claude/jobs/26a3473e/tmp/regen-manifest.sh
```

- [ ] **Step 4: Run the rules-repo validators on the new rules**

```bash
cd third-party/android-sigma-rules
python3 validation/validate-rule.py app_scanner/androdr_092_webapk_brand_impersonation.yml
python3 validation/validate-rule.py app_scanner/androdr_093_sideloaded_brand_impersonation.yml
python3 validation/validate-delivery-set.py
```
Expected: all PASS (fields exist in taxonomy, lookups registered in definitions, no judgment fields, id↔filename consistent).

- [ ] **Step 5: Bundle: copy + manifest entries**

```bash
cp third-party/android-sigma-rules/app_scanner/androdr_092_webapk_brand_impersonation.yml app/src/main/res/raw/sigma_androdr_092_webapk_brand_impersonation.yml
cp third-party/android-sigma-rules/app_scanner/androdr_093_sideloaded_brand_impersonation.yml app/src/main/res/raw/sigma_androdr_093_sideloaded_brand_impersonation.yml
```
In `SigmaRuleEngine.kt` after `R.raw.sigma_androdr_089_sms_notification_otp_theft,` (before the atom-rules comment) insert:

```kotlin
            R.raw.sigma_androdr_092_webapk_brand_impersonation,
            R.raw.sigma_androdr_093_sideloaded_brand_impersonation,
```

- [ ] **Step 6: Run the bundling gates**

```bash
./gradlew testDebugUnitTest --tests "com.androdr.sigma.BundledMirrorParityTest" --tests "com.androdr.sigma.BundledRulesManifestCompletenessTest" --tests "com.androdr.sigma.BundledRulesSchemaCrossCheckTest" --tests "com.androdr.sigma.RuleManifestIntegrityTest" --tests "com.androdr.sigma.DetectionFieldCrossCheckTest" --tests "com.androdr.sigma.IocLookupDefinitionsCrossCheckTest"
```
Expected: all PASS.

- [ ] **Step 7: Commit** (submodule commit + AndroDR commit):

```bash
cd third-party/android-sigma-rules
git add app_scanner/androdr_092_webapk_brand_impersonation.yml app_scanner/androdr_093_sideloaded_brand_impersonation.yml rules.txt rules.sha256
git commit -m "feat(rules): androdr-092 WebAPK + androdr-093 sideloaded brand impersonation (AndroDR #299)"
```
```bash
git add app/src/main/res/raw/sigma_androdr_092_webapk_brand_impersonation.yml app/src/main/res/raw/sigma_androdr_093_sideloaded_brand_impersonation.yml app/src/main/java/com/androdr/sigma/SigmaRuleEngine.kt third-party/android-sigma-rules
git commit -m "feat(detection): bundle androdr-092/093 brand impersonation rules (#299)"
```

---

### Task 6: Rule behavior tests (092 + 093)

**Files:**
- Create: `app/src/test/java/com/androdr/sigma/Rule092WebApkBrandImpersonationTest.kt`
- Create: `app/src/test/java/com/androdr/sigma/Rule093SideloadedBrandImpersonationTest.kt`

**Interfaces:**
- Consumes: bundled YAMLs from Task 5 (loaded from disk, Rule010WebApkFilterTest pattern), `SigmaRuleEvaluator.evaluate(rules, records, service, iocLookups)`.

- [ ] **Step 1: Write Rule092 test:**

```kotlin
package com.androdr.sigma

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/**
 * Behavior spec for androdr-092 (#299): a WebAPK whose display name matches
 * a protected brand fires UNLESS its scope is inside the brand ecosystem's
 * official domains. Loads the ACTUAL bundled rule file.
 *
 * Anti-vacuity (#296 lesson): every record pins every field the rule
 * references, and installer-trust fields are pinned BOTH ways to prove the
 * rule is independent of them.
 */
class Rule092WebApkBrandImpersonationTest {

    private fun loadRule(): SigmaRule {
        val f = listOf(
            File("app/src/main/res/raw/sigma_androdr_092_webapk_brand_impersonation.yml"),
            File("src/main/res/raw/sigma_androdr_092_webapk_brand_impersonation.yml"),
        ).firstOrNull { it.isFile }
            ?: error("bundled androdr-092 not found from ${File(".").absolutePath}")
        return SigmaRuleParser.parse(f.readText())
            ?: error("androdr-092 failed to parse")
    }

    // Stubs stand in for BrandImpersonationResolver; matcher semantics are
    // covered by BrandImpersonationResolverTest. Both lookups MUST be
    // registered or the fail-closed evaluator skips the rule whole.
    private val lookups = mapOf<String, (Any) -> Boolean>(
        "brand_name_db" to { v -> v.toString() == "PayPal" },
        "brand_domain_db" to { v -> v.toString() == "https://paypal.com/" },
    )

    private fun fires(record: Map<String, Any?>): Boolean =
        SigmaRuleEvaluator.evaluate(listOf(loadRule()), listOf(record), "app_scanner", lookups)
            .any { it.triggered }

    private fun webapk(
        appName: String,
        scope: String?,
        pkg: String = "org.chromium.webapk.a1b2c3d4_v2",
        fromTrustedStore: Boolean = false,
        installer: String? = null,
    ) = mapOf(
        "package_name" to pkg,
        "app_name" to appName,
        "webapk_scope" to scope,
        "is_system_app" to false,
        "from_trusted_store" to fromTrustedStore,
        "installer" to installer,
    )

    @Test
    fun `brand-named webapk with foreign scope fires`() =
        assertTrue(fires(webapk("PayPal", "https://evil.example/")))

    @Test
    fun `genuine brand webapk with official scope does not fire`() =
        assertFalse(fires(webapk("PayPal", "https://paypal.com/")))

    @Test
    fun `play-installed brand-named webapk with foreign scope STILL fires`() =
        // Installer trust must not gate behavior — the #296 lesson.
        assertTrue(
            fires(
                webapk(
                    "PayPal", "https://evil.example/",
                    fromTrustedStore = true, installer = "com.android.vending",
                )
            )
        )

    @Test
    fun `brand-named webapk with NO scope meta-data fires`() =
        assertTrue(fires(webapk("PayPal", scope = null)))

    @Test
    fun `non-brand webapk does not fire`() =
        assertFalse(fires(webapk("Recipe Box", "https://recipes.example/")))

    @Test
    fun `brand-named NON-webapk package does not fire on this rule`() =
        assertFalse(fires(webapk("PayPal", null, pkg = "com.fake.paypal")))

    @Test
    fun `rule is high severity experimental`() {
        val rule = loadRule()
        assertTrue(rule.level.equals("high", ignoreCase = true))
    }
}
```

- [ ] **Step 2: Write Rule093 test:**

```kotlin
package com.androdr.sigma

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/**
 * Behavior spec for androdr-093 (#299): a sideloaded (non-store-installed)
 * native app whose display name matches a protected brand fires. The
 * known-good exemption is installer-gated and therefore deliberately
 * unreachable for sideloads (impersonation backstop — androdr-089 pattern);
 * WebAPKs are excluded (androdr-092's domain).
 */
class Rule093SideloadedBrandImpersonationTest {

    private fun loadRule(): SigmaRule {
        val f = listOf(
            File("app/src/main/res/raw/sigma_androdr_093_sideloaded_brand_impersonation.yml"),
            File("src/main/res/raw/sigma_androdr_093_sideloaded_brand_impersonation.yml"),
        ).firstOrNull { it.isFile }
            ?: error("bundled androdr-093 not found from ${File(".").absolutePath}")
        return SigmaRuleParser.parse(f.readText())
            ?: error("androdr-093 failed to parse")
    }

    private val lookups = mapOf<String, (Any) -> Boolean>(
        "brand_name_db" to { v -> v.toString() == "PayPal" },
        "trusted_installer_db" to { v -> v.toString() == "com.android.vending" },
        "known_good_app_db" to { v -> v.toString() == "com.paypal.android.p2pmobile" },
    )

    private fun fires(record: Map<String, Any?>): Boolean =
        SigmaRuleEvaluator.evaluate(listOf(loadRule()), listOf(record), "app_scanner", lookups)
            .any { it.triggered }

    private fun app(
        appName: String,
        installer: String?,
        pkg: String = "com.fake.bankapp",
        isSystemApp: Boolean = false,
    ) = mapOf(
        "package_name" to pkg,
        "app_name" to appName,
        "installer" to installer,
        "is_system_app" to isSystemApp,
    )

    @Test
    fun `sideloaded brand-named app fires`() =
        assertTrue(fires(app("PayPal", installer = null)))

    @Test
    fun `store-installed brand-named app does not fire`() =
        assertFalse(fires(app("PayPal", installer = "com.android.vending")))

    @Test
    fun `sideloaded app with GENUINE brand package name still fires`() =
        // The known-good exemption is installer-gated: unreachable for
        // sideloads BY DESIGN (a fake can adopt any package name).
        assertTrue(fires(app("PayPal", installer = null, pkg = "com.paypal.android.p2pmobile")))

    @Test
    fun `system app does not fire`() =
        assertFalse(fires(app("PayPal", installer = null, isSystemApp = true)))

    @Test
    fun `webapk package is excluded (androdr-092 territory)`() =
        assertFalse(fires(app("PayPal", installer = null, pkg = "org.chromium.webapk.a1b2c3d4_v2")))

    @Test
    fun `sideloaded non-brand app does not fire`() =
        assertFalse(fires(app("Sudoku Deluxe", installer = null)))
}
```

- [ ] **Step 3: Run both — expected PASS immediately** (rules already exist from Task 5; these tests are behavior locks, red-first isn't achievable when the artifact predates the test — instead verify each negative case by temporarily flipping its record field and watching it flip, if any assertion is suspicious).

```bash
./gradlew testDebugUnitTest --tests "com.androdr.sigma.Rule092WebApkBrandImpersonationTest" --tests "com.androdr.sigma.Rule093SideloadedBrandImpersonationTest"
```

- [ ] **Step 4: Commit**

```bash
git add app/src/test/java/com/androdr/sigma/Rule092WebApkBrandImpersonationTest.kt app/src/test/java/com/androdr/sigma/Rule093SideloadedBrandImpersonationTest.kt
git commit -m "test(sigma): behavior specs for androdr-092/093 brand impersonation (#299)"
```

---

### Task 7: Full local gate + on-device verification

- [ ] **Step 1: Full unit suite + lint**

```bash
./gradlew testDebugUnitTest lintDebug
```
Expected: BUILD SUCCESSFUL. Fix any fallout (detekt line-length etc.) before proceeding.

- [ ] **Step 2: On-device check (Fold 2, SM-F916B — the only adb-able device).** Install debug, run a scan, then verify: (a) the two existing benign WebAPKs (squoosh/excalidraw) produce NO androdr-092/093 findings; (b) the emitted `webapk_scope` is present (matchContext in the findings DB, or via logcat if no finding is generated — a temporary debug log line is acceptable, removed before the PR). Pull the Room DB **with the -wal sidecar** per the established procedure if DB inspection is used.

```bash
./gradlew installDebug
```
Expected: no brand-impersonation findings on-device; scope observable for the two WebAPKs. (No live positive case is built — positives are unit-tested only; do NOT create a phishing-shaped PWA.)

- [ ] **Step 3: Commit any fixes.**

---

### Task 8: Review ceremony (mandatory)

- [ ] Dispatch the standard 4-agent parallel review (correctness, code-quality, architect, code-security) over the full branch diff (AndroDR + submodule). Fix findings; re-run affected tests; commit fixes.

---

### Task 9: Ship — safe-ordering

- [ ] **Step 1:** Push the submodule branch; open rules-repo PR (base main). PR body must include: the pre-R1 straggler safety analysis from spec §5 (discharges the CAPABILITY CONSTRAINT header), and the note that androdr-092/093 activate only on app 617+.
- [ ] **Step 2:** Confirm the rules-repo `validate` workflow is green (6 jobs).
- [ ] **Step 3:** Push `feat/299-webapk-brand-impersonation`; open AndroDR PR (base main, body `Closes #299`), submodule pinned to the branch head. `submodule-check` red is expected mid-sequence; `build-and-test` is the real gate.
- [ ] **Step 4:** When AndroDR `build-and-test` (and the rest except submodule-check) is green: merge the rules PR to main.
- [ ] **Step 5:** Re-point the submodule to the resulting rules-main commit, push, wait for ALL AndroDR checks green (incl. submodule-check).
- [ ] **Step 6:** Merge the AndroDR PR (squash). Restore the worktree to the parked `worktree-phase2-from-trusted-store` branch; delete the feature branch locally.
- [ ] **Step 7:** Report: rules live on feed (inert until 617+), app-side merged; note the 617 release ships the activation.
