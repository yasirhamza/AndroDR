package com.androdr.sigma

import android.content.Context
import android.content.res.Resources
import com.androdr.R
import com.androdr.data.model.KnownAppCategory
import com.androdr.ioc.DeviceIdentity
import com.androdr.ioc.KnownAppDatabase
import com.androdr.ioc.KnownAppResolver
import com.androdr.ioc.OemPrefixResolver
import io.mockk.every
import io.mockk.mockk
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test
import org.snakeyaml.engine.v2.api.Load
import org.snakeyaml.engine.v2.api.LoadSettings
import java.io.File

/**
 * Companion layer to gate 4 (#269) — NOT a gate-4 change. Gate 4 proves a
 * rule's boolean logic selects and filters correctly; it feeds fixture field
 * values verbatim, so it is blind to how a field is *computed*. This test
 * closes that gap for the two package-name-decidable classification fields by
 * running every fixture-asserted value through the REAL resolvers over the
 * REAL bundled data:
 *
 *  - `known_app_category` — computed from `known_good_apps.json` alone
 *    (mirrors AppScanner's `knownApp?.category?.name`);
 *  - `is_known_oem_app` — DB category ∈ {OEM, AOSP, GOOGLE} OR an OEM prefix
 *    hit (mirrors AppScanner's computation), evaluated under the pinned
 *    neutral [DeviceIdentity.UNKNOWN], which is documented to match no
 *    conditional prefix block.
 *
 * `from_trusted_store` / `is_sideloaded` are OUT OF SCOPE until #267: they
 * depend on installer/system inputs fixtures don't carry (6 fixture files / 33
 * records set them verbatim), and this test deliberately never calls
 * `OemPrefixResolver.isTrustedInstaller` (forgeable, #267).
 *
 * MISMATCH POLICY (polarity-aware — naive equality false-fails on 4 shipped
 * counterfactual TNs, e.g. `com.android.systemui → is_known_oem_app: false`
 * isolating the `is_system_app` filter branch):
 *  - TP records: strict equality — a TP contradicting computed reality is
 *    precisely #269's dead-rule case.
 *  - TN records, boolean field: fail ONLY on asserted-true/computed-false
 *    with no conditional path (the fixture invents a filter that doesn't
 *    exist ⇒ real-device over-fire). Asserted-false/computed-true is a
 *    logged benign counterfactual: reality filters strictly more, the TN
 *    stays a TN.
 *  - String field: strict equality both polarities.
 *
 * CORPUS INVARIANT the TN tolerance rests on (executable guard below): no
 * swept rule may match a lint-scope field with tolerance-inverting polarity —
 * every positive `is_known_oem_app` matcher must be plain equals on exactly
 * {false}, and no lint-scope field may appear inside a `not`-referenced
 * selection. If either ever changes, the guard fails and this policy must be
 * re-evaluated.
 *
 * SKIP PREDICATE: a record is skipped iff its package has no DB
 * {OEM,AOSP,GOOGLE} entry AND no unconditional-prefix hit AND some
 * conditional-prefix hit (e.g. `com.oplus.member` — OEM only on an
 * OPPO-identity device). NOT "neutral computation disagrees with fixture":
 * that would wrongly skip DB-decided packages that also match a conditional
 * prefix (`com.coloros.backuprestore` is exactly that case). The skip census
 * is pinned EXACTLY: skips growing is the dangerous direction (a data refresh
 * silently converting validated records into skips degrades this test toward
 * validating nothing while staying green).
 *
 * Scope: bundled baseline only — the DAO is a relaxed mock and `refreshCache`
 * is never called, so the bundled entry always wins (the on-device Plexus/UAD
 * cache can differ). No Robolectric; `isReturnDefaultValues = true`
 * neutralizes android.util.Log. Data coupling to
 * `scripts/generate_known_good_apps.py` refreshes is INTENDED — it extends
 * #265's drift guard; failure messages name the cause class (DB entry vs
 * prefix, cf. #263/#265).
 */
class FixtureClassificationCrossCheckTest {

    private val yamlLoader = Load(LoadSettings.builder().build())

    private val prefixYamlText: String = javaClass.classLoader!!
        .getResourceAsStream("raw/known_oem_prefixes.yml")!!
        .bufferedReader().use { it.readText() }

    private val prefixResolver: OemPrefixResolver
    private val knownAppResolver: KnownAppResolver

    init {
        val context: Context = mockk(relaxed = true)
        val resources: Resources = mockk(relaxed = true)
        every { context.resources } returns resources
        every { resources.openRawResource(R.raw.known_oem_prefixes) } answers {
            prefixYamlText.byteInputStream()
        }
        // No test-resources mirror exists for known_good_apps.json (2.95 MB);
        // the real bundled file is streamed via the file-path idiom instead.
        every { resources.openRawResource(R.raw.known_good_apps) } answers {
            knownGoodAppsFile().inputStream()
        }
        prefixResolver = OemPrefixResolver(context)
        knownAppResolver = KnownAppResolver(mockk(relaxed = true), KnownAppDatabase(context))
    }

    private val parsedPrefixData by lazy {
        // The resolver's own internal parse — NOT a hand-rolled YAML walk or a
        // hardcoded vendor-identity list, both of which drift silently when a
        // conditional block is added.
        prefixResolver.parseOemPrefixYaml(prefixYamlText)
    }

    private fun knownGoodAppsFile(): File {
        val candidates = listOf(
            File("app/src/main/res/raw/known_good_apps.json"),
            File("src/main/res/raw/known_good_apps.json"),
            File("/home/yasir/AndroDR/app/src/main/res/raw/known_good_apps.json"),
        )
        return candidates.firstOrNull { it.isFile }
            ?: error("known_good_apps.json not found; tried: ${candidates.map { it.absolutePath }}")
    }

    private fun fixtureFiles(): List<File> {
        val candidates = listOf(
            File("app/src/test/resources/gate4-fixtures"),
            File("src/test/resources/gate4-fixtures"),
            File("/home/yasir/AndroDR/app/src/test/resources/gate4-fixtures"),
        )
        val dir = candidates.firstOrNull { it.isDirectory }
            ?: error("gate4-fixtures not found; tried: ${candidates.map { it.absolutePath }}")
        return dir.listFiles { f -> f.name.endsWith(".yml") }?.sorted() ?: emptyList()
    }

    private fun dbOemCategory(pkg: String): Boolean =
        knownAppResolver.lookup(pkg)?.category in OEM_CATEGORIES

    /** Mirrors AppScanner's is_known_oem_app computation under the neutral identity. */
    private fun computedIsKnownOem(pkg: String): Boolean =
        dbOemCategory(pkg) || prefixResolver.isOemPrefix(pkg, NEUTRAL_DEVICE)

    /** See "SKIP PREDICATE" in the class KDoc. */
    private fun isConditionalOnly(pkg: String): Boolean {
        if (dbOemCategory(pkg)) return false
        if (parsedPrefixData.unconditionalStrict.any { pkg.startsWith(it) }) return false
        return parsedPrefixData.conditional.any { block ->
            block.strictPrefixes.any { pkg.startsWith(it) }
        }
    }

    private fun classificationSource(pkg: String): String {
        val entry = knownAppResolver.lookup(pkg)
        return "cause class — DB entry: " +
            (entry?.let { "${it.category} (source ${it.sourceId})" } ?: "none") +
            "; unconditional-prefix hit: " +
            parsedPrefixData.unconditionalStrict.any { pkg.startsWith(it) } +
            " (data refreshed by scripts/generate_known_good_apps.py can flip " +
            "classifications — intended coupling, cf. #263/#265)"
    }

    @Suppress("UNCHECKED_CAST")
    private fun records(root: Map<String, Any?>, key: String): List<Map<String, Any?>> =
        (root[key] as? List<*>)?.mapNotNull { entry ->
            (entry as? Map<*, *>)?.entries?.associate { (k, v) -> k.toString() to v }
        } ?: emptyList()

    @Test
    fun `fixture classification assertions match the real resolvers`() {
        val failures = mutableListOf<String>()
        val skips = mutableListOf<String>()
        var evaluated = 0

        for (file in fixtureFiles()) {
            @Suppress("UNCHECKED_CAST")
            val root = yamlLoader.loadFromString(file.readText()) as? Map<String, Any?>
                ?: error("${file.name}: fixture did not parse to a map")
            for ((section, isTruePositive) in listOf(
                "true_positives" to true,
                "true_negatives" to false,
            )) {
                for (record in records(root, section)) {
                    val pkg = record["package_name"] as? String ?: continue
                    val where = "${file.name}/$section/$pkg"

                    val assertedOem = record["is_known_oem_app"]
                    if (assertedOem is Boolean) {
                        if (isConditionalOnly(pkg)) {
                            skips += pkg
                            println("SKIP $where: OEM only via device-conditional prefix")
                        } else {
                            evaluated++
                            val computed = computedIsKnownOem(pkg)
                            when {
                                isTruePositive && computed != assertedOem ->
                                    failures += "$where: TP asserts is_known_oem_app=" +
                                        "$assertedOem but the real resolvers compute " +
                                        "$computed — the fixture no longer matches " +
                                        "reality (#269 dead-rule case). " +
                                        classificationSource(pkg)
                                !isTruePositive && assertedOem && !computed ->
                                    failures += "$where: TN asserts is_known_oem_app=true " +
                                        "but the real resolvers compute false — the " +
                                        "fixture invents a filter that does not exist; " +
                                        "on a real device this rule OVER-FIRES on this " +
                                        "package. " + classificationSource(pkg)
                                !isTruePositive && !assertedOem && computed ->
                                    println(
                                        "BENIGN COUNTERFACTUAL $where: asserts false, " +
                                            "computes true — reality filters strictly " +
                                            "more; the TN stays a TN " +
                                            "(deliberate branch isolation)",
                                    )
                            }
                        }
                    } else if (assertedOem != null) {
                        // Gate 4 would coerce e.g. a quoted "false" through
                        // matchEquals; this cross-check cannot classify it and
                        // must not silently skip it.
                        failures += "$where: is_known_oem_app has non-boolean YAML " +
                            "type ${assertedOem.javaClass.simpleName} " +
                            "('$assertedOem') — use a bare boolean"
                    }

                    val assertedCategory = record["known_app_category"]
                    if (assertedCategory is String) {
                        evaluated++
                        val computed = knownAppResolver.lookup(pkg)?.category?.name
                        if (computed != assertedCategory) {
                            failures += "$where: asserts known_app_category=" +
                                "'$assertedCategory' but the bundled DB computes " +
                                "'$computed' (strict both polarities — the " +
                                "more/less-filtering argument is boolean-shaped). " +
                                classificationSource(pkg)
                        }
                    } else if (assertedCategory != null) {
                        failures += "$where: known_app_category has non-string YAML " +
                            "type ${assertedCategory.javaClass.simpleName} " +
                            "('$assertedCategory') — use a plain string"
                    }
                }
            }
        }

        assertTrue(
            "Fixture classification cross-check (#269) failed:\n" +
                failures.joinToString("\n") { "  - $it" },
            failures.isEmpty(),
        )

        // Exact skip census: skips GROWING is the dangerous direction (data
        // drift silently converting validated records into skips). A new
        // conditional-only package in a fixture must update this deliberately.
        assertEquals(
            "Device-conditional skip census changed — verify the new/removed " +
                "package is genuinely conditional-only, then update this census",
            mapOf("com.oplus.member" to 2),
            skips.groupingBy { it }.eachCount(),
        )

        // Floor on evaluated assertions (14 today: 13 is_known_oem_app + 1
        // seeded known_app_category) — a data-load failure must not turn this
        // test vacuous.
        assertTrue(
            "Only $evaluated classification assertions evaluated (expected >= 10) — " +
                "fixture discovery or bundled-data load is broken",
            evaluated >= 10,
        )
    }

    @Test
    fun `baidu regression pair pins the DB-entry cause class`() {
        // com.baidu.input is ABSENT from the bundled DB; its sibling
        // com.baidu.input_mi is present as OEM. A fixture asserting
        // is_known_oem_app=false is right for one and wrong for the other —
        // the exact #269 concrete instance. If either assertion fails after a
        // routine data refresh, the classification flipped: re-evaluate every
        // fixture naming the package (cause class: DB entry, not prefix;
        // cf. #263/#265; refresh script: scripts/generate_known_good_apps.py).
        assertTrue(
            "com.baidu.input now resolves as OEM-class in the bundled DB — " +
                "fixtures asserting is_known_oem_app=false for it are now wrong. " +
                classificationSource("com.baidu.input"),
            !computedIsKnownOem("com.baidu.input"),
        )
        assertEquals(
            "com.baidu.input_mi is no longer category OEM in the bundled DB — " +
                "the #269 regression pair lost its positive arm. " +
                classificationSource("com.baidu.input_mi"),
            KnownAppCategory.OEM,
            knownAppResolver.lookup("com.baidu.input_mi")?.category,
        )
    }

    @Test
    fun `no swept rule inverts the TN tolerance polarity`() {
        val bundled = TestRuleRepo.bundledRuleFiles()
        val delivered = TestRuleRepo.submoduleRuleFiles() ?: emptyList()
        val failures = mutableListOf<String>()

        for (file in bundled + delivered) {
            val rule = SigmaRuleParser.parse(file.readText()) ?: continue
            val negated = negatedSelectionNames(rule.detection.condition)
            for ((selName, selection) in rule.detection.selections) {
                for (matcher in selection.fieldMatchers) {
                    if (matcher.fieldName !in LINT_SCOPE_FIELDS) continue
                    if (selName in negated) {
                        failures += "${file.name}: lint-scope field '${matcher.fieldName}' " +
                            "inside not-referenced selection '$selName'"
                    } else if (matcher.fieldName == "is_known_oem_app" &&
                        !(matcher.modifier == SigmaModifier.EQUALS &&
                            !matcher.allRequired &&
                            matcher.values == listOf<Any>(false))
                    ) {
                        failures += "${file.name}: positive is_known_oem_app matcher is not " +
                            "plain equals on exactly {false} (modifier=${matcher.modifier}, " +
                            "values=${matcher.values})"
                    }
                }
            }
        }

        assertTrue(
            "The TN-tolerance corpus invariant no longer holds — re-evaluate " +
                "FixtureClassificationCrossCheckTest's polarity-aware mismatch policy " +
                "(asserted-false/computed-true would become the DANGEROUS direction " +
                "for these rules):\n" + failures.joinToString("\n") { "  - $it" },
            failures.isEmpty(),
        )
    }

    /** Selection names referenced under `not` in the condition (grammar is
     *  separately validated by DetectionFieldCrossCheckTest). */
    private fun negatedSelectionNames(condition: String): Set<String> {
        val tokens = TestRuleRepo.conditionTokens(condition)
        val negated = mutableSetOf<String>()
        tokens.forEachIndexed { i, tok ->
            if (i > 0 && tokens[i - 1].lowercase() == "not" &&
                tok.lowercase() !in TestRuleRepo.CONDITION_KEYWORDS
            ) {
                negated += tok
            }
        }
        return negated
    }

    private companion object {
        val NEUTRAL_DEVICE = DeviceIdentity.UNKNOWN
        val OEM_CATEGORIES = setOf(
            KnownAppCategory.OEM,
            KnownAppCategory.AOSP,
            KnownAppCategory.GOOGLE,
        )
        val LINT_SCOPE_FIELDS = setOf("is_known_oem_app", "known_app_category")
    }
}
