package com.androdr.sigma

import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test
import java.io.File

/**
 * Activation gate (#342, architect Important #1 — mistakes-become-tests).
 *
 * The branch's headline claim is that a logsource service cannot be marked
 * `status: active` in the taxonomy without actually being wired for detection.
 * Until this test existed that was enforced by DISCIPLINE only: a taxonomy
 * `status: active` flip with no evaluate path, or an evaluate path with no live
 * caller, passed every other gate — exactly the dead-rule class the `unwired`
 * status warns about, and exactly what would make "network_monitor /
 * security_log activation is indivisible" a promise the machinery does not keep.
 *
 * This is a source-scanning gate (precedent: [IocLookupDefinitionsCrossCheckTest]
 * which scans ScanOrchestrator.kt, [PureEmitterContractTest] which scans the
 * whole main tree). For every taxonomy service with `status: active` EXCEPT the
 * engine-matched `timeline` (which has `field_map: none` / no evaluate method —
 * its atoms bind via [SigmaRuleEngine.computeAtomBindings], not an evaluate*
 * path — so it is excluded explicitly), it proves BOTH halves of activation:
 *
 *  (a) WIRED: an evaluate path passes the service-name literal to
 *      [SigmaRuleEvaluator.evaluate]. Either a dedicated `fun evaluateXxx(` in
 *      SigmaRuleEngine.kt whose body contains the `"service"` literal, OR the
 *      generic `evaluateGeneric(records, service)` path fed the literal from a
 *      bugreport-module call site.
 *
 *  (b) CALLED: that evaluate path has a PRODUCTION caller. Either the dedicated
 *      `fun evaluateXxx(` is referenced somewhere under app/src/main OUTSIDE
 *      SigmaRuleEngine.kt, OR the generic route is live (evaluateGeneric is
 *      called in main AND a bugreport module carries the literal as a
 *      telemetryService value).
 *
 * The service→method mapping is derived from the literal each evaluate method
 * passes, NOT from a name transform: the names do not correspond (`db_info` →
 * `evaluateDatabasePathObservations`, `network_monitor` → `evaluateNetwork`),
 * so a hand-mirrored map would drift silently.
 *
 * Must live in com.androdr.sigma so it can name [SigmaRuleEngine] /
 * [SigmaRuleEvaluator]; the taxonomy is read the same way
 * [LogsourceTaxonomyCrossCheckTest] / [TestRuleRepo.loadTaxonomy] read it.
 */
class ServiceActivationCrossCheckTest {

    /**
     * Evaluate methods in SigmaRuleEngine.kt → the set of lowercase service
     * literals each one passes. Region for a `fun evaluateXxx(` runs from its
     * declaration to the NEXT function declaration of any kind, so a literal in
     * the companion object (e.g. `ATOM_BINDING_FIELD = "category"`) or an
     * unrelated helper never leaks into an evaluate method's literal set.
     */
    private fun evaluateMethodLiterals(engineSrc: String): Map<String, Set<String>> {
        val funDecls = FUN_DECL.findAll(engineSrc)
            .map { it.groupValues[1] to it.range.first }
            .sortedBy { it.second }
            .toList()
        assertTrue(
            "No `fun` declarations found in SigmaRuleEngine.kt — the source-scan " +
                "broke and a vacuous pass would hide a dead service.",
            funDecls.isNotEmpty(),
        )
        val result = mutableMapOf<String, Set<String>>()
        for (i in funDecls.indices) {
            val (name, start) = funDecls[i]
            if (!name.startsWith("evaluate")) continue
            val end = funDecls.getOrNull(i + 1)?.second ?: engineSrc.length
            val body = engineSrc.substring(start, end)
            result[name] = SERVICE_LITERAL.findAll(body).map { it.groupValues[1] }.toSet()
        }
        assertTrue(
            "Found no evaluate* methods in SigmaRuleEngine.kt — extraction broke.",
            result.isNotEmpty(),
        )
        return result
    }

    /** Evaluate methods whose body passes the literal `"$service"`. */
    private fun methodsForService(literals: Map<String, Set<String>>, service: String): Set<String> =
        literals.filterValues { service in it }.keys

    /** True if [methodName] is called (`name(`) anywhere in main outside the engine. */
    private fun referencedInMainOutsideEngine(methodName: String): Boolean {
        val call = Regex("""\b${Regex.escape(methodName)}\s*\(""")
        return mainKotlinFiles()
            .filter { it.name != ENGINE_FILE_NAME }
            .any { call.containsMatchIn(TestRuleRepo.stripKotlinComments(it.readText())) }
    }

    /**
     * The generic route is live for [service] when the generic dispatcher is
     * itself called in production AND a bugreport module carries the literal as
     * a `telemetryService` value (directly or via a `SERVICE` const), i.e. the
     * literal reaches [SigmaRuleEngine.evaluateGeneric] from a real call site.
     */
    private fun genericRouteAvailable(service: String): Boolean {
        if (!referencedInMainOutsideEngine("evaluateGeneric")) return false
        val bugreportDir = File(TestRuleRepo.mainSourceRoot(), BUGREPORT_PKG)
        if (!bugreportDir.isDirectory) return false
        val literal = "\"$service\""
        return bugreportDir.walkTopDown()
            .filter { it.isFile && it.extension == "kt" }
            .any { it.readText().contains(literal) }
    }

    private fun mainKotlinFiles(): Sequence<File> =
        TestRuleRepo.mainSourceRoot().walkTopDown().filter { it.isFile && it.extension == "kt" }

    private fun engineSource(): String =
        TestRuleRepo.stripKotlinComments(TestRuleRepo.mainSourceFile(ENGINE_SOURCE).readText())

    @Test
    fun `source-scan self-check maps a known service to its evaluate method`() {
        val engineSrc = engineSource()
        val literals = evaluateMethodLiterals(engineSrc)
        // Anchor: if extraction ever stops mapping this pair the whole gate is
        // suspect, so fail loudly rather than let every service pass vacuously.
        assertTrue(
            "Expected evaluateNetwork to pass the \"network_monitor\" literal; " +
                "literal extraction broke. Extracted: $literals",
            "evaluateNetwork" in methodsForService(literals, "network_monitor"),
        )
        assertTrue(
            "Expected evaluateSecurityLog to pass the \"security_log\" literal. " +
                "Extracted: $literals",
            "evaluateSecurityLog" in methodsForService(literals, "security_log"),
        )
    }

    @Test
    fun `every active taxonomy service is wired to a called evaluate path`() {
        val taxonomy = TestRuleRepo.loadTaxonomy()
        assumeTrue(
            "Skipping: logsource-taxonomy.yml not found (submodule not initialized).",
            taxonomy != null,
        )
        val engineSrc = engineSource()
        val literals = evaluateMethodLiterals(engineSrc)

        val failures = mutableListOf<String>()
        var checked = 0
        for ((service, entry) in taxonomy!!) {
            // `timeline` is engine-matched (field_map: none): its atoms bind via
            // computeAtomBindings, not an evaluate* path, so it has no evaluate
            // method by design. Excluded explicitly.
            if (service == TIMELINE_SERVICE) continue
            // Non-active services (unwired/staging) are ALLOWED to lack an
            // evaluator — that is exactly what the lifecycle status expresses.
            if (entry.status != STATUS_ACTIVE) continue
            checked++

            val methods = methodsForService(literals, service)
            val genericRoute = genericRouteAvailable(service)

            // (a) WIRED.
            if (methods.isEmpty() && !genericRoute) {
                failures += "$service (active): NOT WIRED — no evaluate path in " +
                    "SigmaRuleEngine.kt passes the \"$service\" literal to " +
                    "SigmaRuleEvaluator.evaluate, and no generic route feeds it. " +
                    "A rule targeting this service is dead. Add fun evaluate$service " +
                    "(or flip the taxonomy status back to unwired)."
                continue
            }

            // (b) CALLED.
            val called = methods.any { referencedInMainOutsideEngine(it) } || genericRoute
            if (!called) {
                failures += "$service (active): WIRED but NEVER CALLED — evaluate " +
                    "method(s) $methods exist in SigmaRuleEngine.kt but are referenced " +
                    "nowhere under app/src/main outside it, and the generic route is " +
                    "not live. A rule targeting this service can never fire. Add a " +
                    "production call site (orchestrator/analyzer)."
            }
        }

        // Guard against a vacuous pass: the shipped taxonomy has ~16 active
        // non-timeline services; if the loop checked almost none, the load or
        // filter broke rather than the tree being clean.
        assertTrue(
            "Only $checked active non-timeline services were checked — the taxonomy " +
                "load or the status filter broke, and a near-empty sweep would hide a " +
                "dead service.",
            checked >= MIN_ACTIVE_SERVICES,
        )

        assertTrue(
            "Activation gate FAILED — an `active` taxonomy service is not fully wired " +
                "for detection (the dead-rule class `unwired` warns about):\n" +
                failures.joinToString("\n") { "  - $it" },
            failures.isEmpty(),
        )
    }

    private companion object {
        const val ENGINE_SOURCE = "com/androdr/sigma/SigmaRuleEngine.kt"
        const val ENGINE_FILE_NAME = "SigmaRuleEngine.kt"
        const val BUGREPORT_PKG = "com/androdr/scanner/bugreport"
        const val TIMELINE_SERVICE = "timeline"
        const val STATUS_ACTIVE = "active"

        /** Floor below which the sweep is suspiciously empty (see call site). */
        const val MIN_ACTIVE_SERVICES = 12

        /** Any Kotlin function declaration (used as region boundaries). */
        val FUN_DECL = Regex("""\bfun\s+(\w+)\s*\(""")

        /** A lowercase snake_case string literal — the shape of every service name. */
        val SERVICE_LITERAL = Regex(""""([a-z][a-z0-9_]*)"""")
    }
}
