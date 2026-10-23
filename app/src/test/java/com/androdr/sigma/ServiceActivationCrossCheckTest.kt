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
 *      telemetryService value), OR a writer appends the service's records to a
 *      session (telemetry store §4.1: the session evaluates every chunk through
 *      `evaluateRecords`) — a production file outside the sigma package names the
 *      service's `*RecordBuilders` constant on an `append`/`appendAll`/`put` line.
 *
 * The service→method mapping is derived from the literal each evaluate method
 * passes, NOT from a name transform: the names do not correspond (`db_info` →
 * `evaluateDatabasePathObservations`, `network_monitor` → `evaluateNetwork`),
 * so a hand-mirrored map would drift silently.
 *
 * The converse holds for `status: emitter_only` (telemetry store, spec §4.2):
 * those services are stored but never rule-evaluated, so they must have NO
 * dedicated evaluate path and no rule may target them.
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
        val builderServiceConstants = builderServiceConstants()
        assertTrue(
            "No service constants found in the *RecordBuilders objects -- the builder scan broke.",
            builderServiceConstants.isNotEmpty(),
        )
        val result = mutableMapOf<String, Set<String>>()
        for (i in funDecls.indices) {
            val (name, start) = funDecls[i]
            // evaluateRecords is the shared dispatcher, not a service's entry point.
            if (!name.startsWith("evaluate") || name == "evaluateRecords") continue
            val end = funDecls.getOrNull(i + 1)?.second ?: engineSrc.length
            val body = engineSrc.substring(start, end)
            // A service is named either by a literal or by a builder constant
            // (`LiveRecordBuilders.APP_SCANNER`); both resolve to the literal.
            val viaBuilder = BUILDER_CONSTANT_REF.findAll(body)
                .mapNotNull { builderServiceConstants[it.groupValues[1] + "." + it.groupValues[2]] }
            result[name] = (SERVICE_LITERAL.findAll(body).map { it.groupValues[1] } + viaBuilder).toSet()
        }
        assertTrue(
            "Found no evaluate* methods in SigmaRuleEngine.kt — extraction broke.",
            result.isNotEmpty(),
        )
        return result
    }

    /**
     * `Builders.CONST` -> service literal, from every `object ...RecordBuilders` in the
     * sigma package: the builders own the service names, the engine only references them.
     */
    private fun builderServiceConstants(): Map<String, String> {
        val result = mutableMapOf<String, String>()
        for (name in BUILDER_FILES) {
            val src = TestRuleRepo.stripKotlinComments(
                TestRuleRepo.mainSourceFile("com/androdr/sigma/$name.kt").readText()
            )
            for (m in CONST_DECL.findAll(src)) result["$name.${m.groupValues[1]}"] = m.groupValues[2]
        }
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
        // The generic route is the bug-report dispatcher (evaluateGeneric) or a direct
        // evaluateRecords call (the writer session, spec 4.1) outside the engine.
        if (!referencedInMainOutsideEngine("evaluateGeneric") &&
            !referencedInMainOutsideEngine("evaluateRecords")
        ) {
            return false
        }
        val bugreportDir = File(TestRuleRepo.mainSourceRoot(), BUGREPORT_PKG)
        if (!bugreportDir.isDirectory) return false
        val literal = "\"$service\""
        // Strip comments first (as referencedInMainOutsideEngine does): a
        // module COMMENT that merely mentions a service literal must not mark the
        // service wired-via-generic — that would be a false PASS hiding a dead
        // service, defeating this gate. String literals survive stripping, so a
        // real `telemetryService = "svc"` (or `SERVICE = "svc"`) still matches.
        return bugreportDir.walkTopDown()
            .filter { it.isFile && it.extension == "kt" }
            .any { TestRuleRepo.stripKotlinComments(it.readText()).contains(literal) }
    }

    /**
     * True when a writer appends [service]'s records to a session: the session's `evaluateRecords`
     * call is live, and a production file outside the sigma package passes the service's builder
     * constant on an append line (`append(`, `appendAll(`, or a writer's local `put(`).
     */
    private fun appendedToSession(service: String, constants: Map<String, String>): Boolean {
        if (!referencedInMainOutsideEngine("evaluateRecords")) return false
        val refs = constants.filterValues { it == service }.keys
        if (refs.isEmpty()) return false
        val appendLine = Regex("""\b(append|appendAll|put)\s*\(""")
        return mainKotlinFiles().filter { "/sigma/" !in it.invariantSeparatorsPath }.any { f ->
            TestRuleRepo.stripKotlinComments(f.readText()).lines().any { line ->
                appendLine.containsMatchIn(line) && refs.any { it in line }
            }
        }
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

        // `timeline` is engine-matched (field_map: none): its atoms bind via
        // computeAtomBindings, not an evaluate* path, so it has no evaluate method
        // by design — excluded explicitly. Non-active services (unwired/staging)
        // are ALLOWED to lack an evaluator: that is exactly what the lifecycle
        // status expresses, so they are filtered out here rather than checked.
        val activeServices = taxonomy!!
            .filterKeys { it != TIMELINE_SERVICE }
            .filterValues { it.status == STATUS_ACTIVE }
            .keys

        val failures = mutableListOf<String>()
        val constants = builderServiceConstants()
        for (service in activeServices) {
            val methods = methodsForService(literals, service)
            val genericRoute = genericRouteAvailable(service)
            val called = methods.any { referencedInMainOutsideEngine(it) } || genericRoute ||
                appendedToSession(service, constants)
            when {
                // (a) WIRED.
                methods.isEmpty() && !genericRoute ->
                    failures += "$service (active): NOT WIRED — no evaluate path in " +
                        "SigmaRuleEngine.kt passes the \"$service\" literal to " +
                        "SigmaRuleEvaluator.evaluate, and no generic route feeds it. " +
                        "A rule targeting this service is dead. Add fun evaluate$service " +
                        "(or flip the taxonomy status back to unwired)."
                // (b) CALLED.
                !called ->
                    failures += "$service (active): WIRED but NEVER CALLED — evaluate " +
                        "method(s) $methods exist in SigmaRuleEngine.kt but are referenced " +
                        "nowhere under app/src/main outside it, and the generic route is " +
                        "not live. A rule targeting this service can never fire. Add a " +
                        "production call site (orchestrator/analyzer)."
            }
        }
        val checked = activeServices.size

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

    @Test
    fun `every taxonomy status is a known lifecycle status`() {
        val taxonomy = TestRuleRepo.loadTaxonomy()
        assumeTrue("Skipping: submodule not initialized.", taxonomy != null)
        val unknown = taxonomy!!.filterValues { it.status !in KNOWN_STATUSES }.mapValues { it.value.status }
        assertTrue(
            "Unknown taxonomy status (this gate only understands $KNOWN_STATUSES): $unknown",
            unknown.isEmpty(),
        )
    }

    /**
     * `emitter_only` services are produced and stored, but no rule may target
     * them (validate-rule.py rejects one outside staging/). So no dedicated
     * evaluate path may exist for one: it would be either dead or the first
     * step to a rule nothing validates. The only tolerated evaluation is the
     * generic bug-report dispatch for the modules in [GENERIC_EMITTER_ONLY],
     * which evaluates whatever service a module names; with no rule allowed on
     * the service it matches nothing.
     */
    @Test
    fun `emitter-only services have no evaluate path`() {
        val taxonomy = TestRuleRepo.loadTaxonomy()
        assumeTrue("Skipping: submodule not initialized.", taxonomy != null)
        val literals = evaluateMethodLiterals(engineSource())
        val emitterOnly = taxonomy!!.filterValues { it.status == STATUS_EMITTER_ONLY }.keys
        assertTrue(
            "Expected the emitter-only services $EXPECTED_EMITTER_ONLY, found $emitterOnly",
            emitterOnly.containsAll(EXPECTED_EMITTER_ONLY),
        )
        val failures = mutableListOf<String>()
        for (service in emitterOnly) {
            val methods = methodsForService(literals, service)
            if (methods.isNotEmpty()) {
                failures += "$service (emitter_only): evaluate method(s) $methods pass its literal"
            }
            val generic = genericRouteAvailable(service)
            if (generic && service !in GENERIC_EMITTER_ONLY) {
                failures += "$service (emitter_only): a bug-report module routes it to evaluateGeneric"
            }
            if (!generic && service in GENERIC_EMITTER_ONLY) {
                failures += "$service: listed in GENERIC_EMITTER_ONLY but no longer generic-routed; remove it"
            }
        }
        assertTrue(
            "Emitter-only gate FAILED:\n" + failures.joinToString("\n") { "  - $it" },
            failures.isEmpty(),
        )
    }

    @Test
    fun `no bundled or delivered rule targets an emitter-only service`() {
        val taxonomy = TestRuleRepo.loadTaxonomy()
        assumeTrue("Skipping: submodule not initialized.", taxonomy != null)
        val emitterOnly = taxonomy!!.filterValues { it.status == STATUS_EMITTER_ONLY }.keys
        val files = TestRuleRepo.bundledRuleFiles() + TestRuleRepo.submoduleRuleFiles().orEmpty()
        val offenders = files.filter { file ->
            val service = SERVICE_LINE.find(file.readText())?.groupValues?.get(1)
            service in emitterOnly
        }.map { it.name }
        assertTrue("Rules targeting an emitter_only service: $offenders", offenders.isEmpty())
    }

    private companion object {
        const val STATUS_EMITTER_ONLY = "emitter_only"
        val KNOWN_STATUSES = setOf("active", "emitter_only", "unwired")

        /** Floor for the emitter-only sweep (spec §4.2's four documented services). */
        val EXPECTED_EMITTER_ONLY = setOf("usage_stats", "system_property", "adb_audit", "activity_audit")

        /**
         * Emitter-only services a bug-report module still hands to the generic
         * dispatcher (AdbKeysModule, ActivityModule). Tolerated because no rule
         * may target them; see `emitter-only services have no evaluate path`.
         */
        val GENERIC_EMITTER_ONLY = setOf("adb_audit", "activity_audit")

        /** `service: <name>` under a rule's logsource. */
        val SERVICE_LINE = Regex("""(?m)^\s+service:\s*([a-z][a-z0-9_]*)\s*$""")

        const val ENGINE_SOURCE = "com/androdr/sigma/SigmaRuleEngine.kt"
        const val ENGINE_FILE_NAME = "SigmaRuleEngine.kt"
        const val BUGREPORT_PKG = "com/androdr/scanner/bugreport"
        const val TIMELINE_SERVICE = "timeline"
        const val STATUS_ACTIVE = "active"

        /** Floor below which the sweep is suspiciously empty (see call site). */
        const val MIN_ACTIVE_SERVICES = 12

        val BUILDER_FILES = listOf("LiveRecordBuilders", "BugReportRecordBuilders", "IntrusionLogRecordBuilders")

        /** `const val NAME = "service"` inside a builder object. */
        val CONST_DECL = Regex("""const val (\w+)\s*=\s*"([a-z][a-z0-9_]*)"""")

        /** `SomeRecordBuilders.NAME` reference in the engine. */
        val BUILDER_CONSTANT_REF = Regex("""\b(\w+RecordBuilders)\.([A-Z][A-Z0-9_]*)\b""")

        /** Any Kotlin function declaration (used as region boundaries). */
        val FUN_DECL = Regex("""\bfun\s+(\w+)\s*\(""")

        /** A lowercase snake_case string literal — the shape of every service name. */
        val SERVICE_LITERAL = Regex(""""([a-z][a-z0-9_]*)"""")
    }
}
