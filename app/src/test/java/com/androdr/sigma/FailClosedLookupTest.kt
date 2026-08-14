package com.androdr.sigma

import com.androdr.data.model.ForensicTimelineEvent
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/**
 * Fail-closed evaluator contract (spec 2026-08-14, Workstream A): a rule
 * referencing an ioc_lookup this binary cannot resolve — unregistered name,
 * or a matcher with no name at all — is SKIPPED whole. The legacy
 * matcher-false fallback inverts negated gates (the #136 Phase-2 over-fire).
 */
class FailClosedLookupTest {

    private val migratedSideloadRule = """
        id: androdr-010
        title: Sideloaded Application
        status: stable
        level: medium
        category: incident
        logsource: { product: androdr, service: app_scanner }
        detection:
          selection:
            is_system_app: false
          store_installed:
            installer|ioc_lookup: trusted_installer_db
          filter_known_good:
            package_name|ioc_lookup: known_good_app_db
          condition: selection and not store_installed and not filter_known_good
    """.trimIndent()

    private val filterLookupRule = """
        id: androdr-777
        title: Filter Lookup Rule
        status: stable
        level: medium
        category: incident
        logsource: { product: androdr, service: app_scanner }
        detection:
          selection:
            has_device_admin: true
          filter_trusted:
            installer|ioc_lookup: trusted_installer_db
          condition: selection and not filter_trusted
    """.trimIndent()

    private val namelessLookupRule = """
        id: androdr-779
        title: Nameless Lookup Rule
        status: stable
        level: medium
        category: incident
        logsource: { product: androdr, service: app_scanner }
        detection:
          selection:
            has_device_admin: true
          store_installed:
            installer|ioc_lookup:
          condition: selection and not store_installed
    """.trimIndent()

    private val noLookupRule = """
        id: androdr-778
        title: No Lookup Rule
        status: stable
        level: medium
        category: incident
        logsource: { product: androdr, service: app_scanner }
        detection:
          selection:
            has_device_admin: true
          condition: selection
    """.trimIndent()

    private fun parse(yaml: String): SigmaRule =
        requireNotNull(SigmaRuleParser.parse(yaml)) { "test rule failed to parse" }

    private val sideloadedRecord = mapOf<String, Any?>(
        "package_name" to "com.evil.app", "is_system_app" to false,
        "installer" to null, "has_device_admin" to true
    )

    private val allRegistered = mapOf<String, (Any) -> Boolean>(
        "trusted_installer_db" to { v -> v == "com.android.vending" },
        "known_good_app_db" to { _ -> false }
    )

    // Atom rules match `computeAtomBindings`' expected shape (level: informational,
    // service: timeline, a `selection` with a `category` equals matcher) PLUS an
    // `ioc_lookup` matcher in the same selection — the shape this binary must
    // refuse to bind on when the lookup is unresolvable.
    private val atomRuleWithLookup = """
        id: androdr-atom-test-lookup
        title: Atom Test With Lookup
        status: production
        level: informational
        category: incident
        logsource: { product: androdr, service: timeline }
        detection:
          selection:
            category: package_install
            installer|ioc_lookup: trusted_installer_db
          condition: selection
    """.trimIndent()

    private fun timelineEvent(id: Long, category: String): ForensicTimelineEvent =
        ForensicTimelineEvent(
            id = id,
            startTimestamp = id * 1000L,
            source = "test",
            category = category,
            description = "test"
        )

    @Test
    fun `unregistered lookup in negated selection - rule skipped, no over-fire`() {
        val findings = SigmaRuleEvaluator.evaluate(
            listOf(parse(migratedSideloadRule)), listOf(sideloadedRecord),
            "app_scanner", iocLookups = emptyMap()
        )
        assertTrue(
            "Rule with unregistered lookup must be skipped whole, got: $findings",
            findings.none { it.ruleId == "androdr-010" }
        )
    }

    @Test
    fun `unregistered lookup in filter - rule skipped, exemption never defeated`() {
        val findings = SigmaRuleEvaluator.evaluate(
            listOf(parse(filterLookupRule)), listOf(sideloadedRecord),
            "app_scanner", iocLookups = emptyMap()
        )
        assertTrue(findings.none { it.ruleId == "androdr-777" })
    }

    @Test
    fun `lookup matcher with NO name is unresolvable even when all names registered`() {
        // Fail-closed on the nameless spelling `installer|ioc_lookup:` — the
        // parser yields values = emptyList(); the legacy branch resolved it to
        // false, inverting the negated gate (the fail-OPEN hole).
        val findings = SigmaRuleEvaluator.evaluate(
            listOf(parse(namelessLookupRule)), listOf(sideloadedRecord),
            "app_scanner", iocLookups = allRegistered
        )
        assertTrue(findings.none { it.ruleId == "androdr-779" })
        assertEquals(
            mapOf("androdr-779" to SigmaRuleEvaluator.MISSING_LOOKUP_NAME),
            SigmaRuleEvaluator.unevaluableRules(listOf(parse(namelessLookupRule)), allRegistered)
        )
    }

    @Test
    fun `registered lookups - behavior identical to today`() {
        val sideloaded = SigmaRuleEvaluator.evaluate(
            listOf(parse(migratedSideloadRule)), listOf(sideloadedRecord),
            "app_scanner", iocLookups = allRegistered
        )
        assertTrue(sideloaded.any { it.ruleId == "androdr-010" && it.triggered })

        val storeRecord = sideloadedRecord + mapOf("installer" to "com.android.vending")
        val exempt = SigmaRuleEvaluator.evaluate(
            listOf(parse(migratedSideloadRule)), listOf(storeRecord),
            "app_scanner", iocLookups = allRegistered
        )
        assertTrue(exempt.none { it.ruleId == "androdr-010" && it.triggered })
    }

    @Test
    fun `mixed rule list - only the lookup rule is skipped`() {
        val findings = SigmaRuleEvaluator.evaluate(
            listOf(parse(migratedSideloadRule), parse(noLookupRule)),
            listOf(sideloadedRecord), "app_scanner", iocLookups = emptyMap()
        )
        assertTrue(findings.none { it.ruleId == "androdr-010" })
        assertTrue(findings.any { it.ruleId == "androdr-778" && it.triggered })
    }

    @Test
    fun `unevaluableRules maps ruleId to first missing name`() {
        val rules = listOf(parse(migratedSideloadRule), parse(noLookupRule))
        assertEquals(
            mapOf("androdr-010" to "trusted_installer_db"),
            SigmaRuleEvaluator.unevaluableRules(rules, emptyMap())
        )
        assertTrue(SigmaRuleEvaluator.unevaluableRules(rules, allRegistered).isEmpty())
    }

    @Test
    fun `engine reports unevaluable rules over its effective set via its own lookups`() {
        val engine = SigmaRuleEngine(io.mockk.mockk(relaxed = true))
        engine.setRemoteRules(listOf(parse(migratedSideloadRule), parse(noLookupRule)))
        engine.setIocLookups(emptyMap())
        assertEquals(mapOf("androdr-010" to "trusted_installer_db"), engine.unevaluableRules())
        engine.setIocLookups(allRegistered)
        assertTrue(engine.unevaluableRules().isEmpty())
    }

    @Test
    fun `computeAtomBindings excludes an atom rule with an unresolvable ioc_lookup`() {
        val engine = SigmaRuleEngine(io.mockk.mockk(relaxed = true))
        engine.setRemoteRules(listOf(parse(atomRuleWithLookup)))
        engine.setIocLookups(emptyMap())

        val bindings = engine.computeAtomBindings(listOf(timelineEvent(id = 1, category = "package_install")))

        assertTrue(
            "Atom rule with an unresolved ioc_lookup must produce no binding — fail-closed " +
                "applies to the binding path too, got: $bindings",
            bindings[1].orEmpty().isEmpty()
        )
    }

    @Test
    fun `computeAtomBindings binds the atom rule once its lookup is registered`() {
        val engine = SigmaRuleEngine(io.mockk.mockk(relaxed = true))
        engine.setRemoteRules(listOf(parse(atomRuleWithLookup)))
        engine.setIocLookups(allRegistered)

        val bindings = engine.computeAtomBindings(listOf(timelineEvent(id = 1, category = "package_install")))

        assertEquals(setOf("androdr-atom-test-lookup"), bindings[1])
    }

    private fun rulesDirectory(): File {
        val candidates = listOf(
            File("app/src/main/res/raw"),
            File("src/main/res/raw"),
            File("/home/yasir/AndroDR/app/src/main/res/raw"),
        )
        return candidates.firstOrNull { it.isDirectory }
            ?: error("Could not locate res/raw; tried: ${candidates.map { it.absolutePath }}")
    }

    /**
     * Corpus lint: no bundled `timeline`-service (atom) rule may carry an
     * `ioc_lookup` matcher. `computeAtomBindings` only pre-filters by the
     * engine's live `unevaluableRules()` set at runtime — this test keeps the
     * binding path *structurally* lookup-free at the corpus level too, so a
     * newly-added atom rule can't reintroduce the hazard the runtime filter
     * exists to guard against.
     */
    @Test
    fun `no bundled timeline atom rule contains an IOC_LOOKUP matcher`() {
        val ruleFiles = rulesDirectory().listFiles { f ->
            f.name.startsWith("sigma_androdr_") &&
                f.name.endsWith(".yml") &&
                !f.name.startsWith("sigma_androdr_corr_")
        }?.sorted() ?: emptyList()

        assertTrue("Expected bundled rule files to be found in res/raw", ruleFiles.isNotEmpty())

        val violations = ruleFiles.mapNotNull { file ->
            val rule = SigmaRuleParser.parse(file.readText()) ?: return@mapNotNull null
            if (rule.service != "timeline") return@mapNotNull null
            val hasLookup = rule.detection.selections.values
                .flatMap { it.fieldMatchers }
                .any { it.modifier == SigmaModifier.IOC_LOOKUP }
            if (hasLookup) "${file.name}: timeline/atom rule '${rule.id}' contains an IOC_LOOKUP matcher" else null
        }

        assertTrue(
            "Atom/timeline rules must stay structurally lookup-free until the binding path " +
                "itself pre-scans unevaluableRules():\n" + violations.joinToString("\n"),
            violations.isEmpty()
        )
    }
}
