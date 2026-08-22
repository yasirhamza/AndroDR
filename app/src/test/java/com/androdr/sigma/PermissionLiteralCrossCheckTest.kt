package com.androdr.sigma

import com.androdr.scanner.AppScanner
import org.junit.Assert.assertTrue
import org.junit.Test
import org.snakeyaml.engine.v2.api.Load
import org.snakeyaml.engine.v2.api.LoadSettings
import java.io.File

/**
 * Build-time guard against the dead-rule CLASS that silently killed androdr-069
 * (and would silently kill the next NFC/media-projection rule): a bundled
 * `app_scanner` rule that matches `permissions|contains: "X"` can only ever fire
 * if "X" is a short-named member of the set the scanner actually emits in
 * [com.androdr.data.model.AppTelemetry.permissions] —
 * [AppScanner.EXPOSED_PERMISSION_SHORT_NAMES].
 *
 * This test reads that set DIRECTLY from the scanner (not a hardcoded copy), so
 * it can never drift from reality — which is the whole point. It asserts every
 * `permissions` literal in every bundled rule is a member. Adding a rule that
 * references a permission the scanner doesn't expose fails the build at authoring
 * time. See #225.
 *
 * Scope: the `permissions` field only. `service_permissions` / `receiver_permissions`
 * are open-ended (the scanner emits every declared component permission verbatim, FQN),
 * so they have no fixed enum to validate against and are intentionally NOT constrained
 * here. The guard also requires WHOLE short names — substring matchers like
 * `permissions|contains: "ALERT"` are deliberately disallowed (use the exact name).
 *
 * Longer term this is subsumed by the machine-readable telemetry contract (#137);
 * until then it is a tactical, drift-proof guard for the one enumerable field.
 */
class PermissionLiteralCrossCheckTest {

    private val yamlLoader: Load = Load(LoadSettings.builder().build())

    private fun rulesDirectory(): File {
        val candidates = listOf(
            File("app/src/main/res/raw"),
            File("src/main/res/raw"),
            File("/home/yasir/AndroDR/app/src/main/res/raw"),
        )
        return candidates.firstOrNull { it.isDirectory }
            ?: error("Could not locate res/raw; tried: ${candidates.map { it.absolutePath }}")
    }

    private fun bundledRuleFiles(): List<File> =
        rulesDirectory().listFiles { f ->
            f.name.startsWith("sigma_androdr_") &&
                f.name.endsWith(".yml") &&
                !f.name.startsWith("sigma_androdr_corr_")
        }?.sorted() ?: emptyList()

    /** Field name of a SIGMA matcher key, stripping any `|modifier` suffix. */
    private fun fieldName(key: String): String = key.substringBefore('|')

    /** Add the literal value(s) of a single matcher (scalar or list). */
    private fun addLiterals(value: Any?, into: MutableList<String>) {
        when (value) {
            is String -> into.add(value)
            is List<*> -> value.forEach { it?.let { e -> into.add(e.toString()) } }
        }
    }

    /** Recursively collect the literal value(s) of every `permissions` matcher. */
    private fun collectPermissionLiterals(node: Any?, into: MutableList<String>) {
        when (node) {
            is Map<*, *> -> node.forEach { (k, v) ->
                if (k is String && fieldName(k) == "permissions") addLiterals(v, into)
                collectPermissionLiterals(v, into)
            }
            is List<*> -> node.forEach { collectPermissionLiterals(it, into) }
        }
    }

    @Test
    fun `every bundled rule permissions literal is exposed by the scanner`() {
        val exposed = AppScanner.EXPOSED_PERMISSION_SHORT_NAMES
        assertTrue("Exposed permission set is unexpectedly empty", exposed.isNotEmpty())

        val ruleFiles = bundledRuleFiles()
        // Floor guard: a guard test that silently checks ZERO rules (wrong working
        // directory, null listFiles) would pass green having validated nothing —
        // the exact failure mode this test exists to prevent. Mirror the floor in
        // BundledRulesSchemaCrossCheckTest.
        assertTrue(
            "Expected at least 40 bundled rule files but found ${ruleFiles.size} — is the " +
                "test running from the correct working directory?",
            ruleFiles.size >= 40,
        )

        val failures = mutableListOf<String>()

        ruleFiles.forEach { file ->
            @Suppress("UNCHECKED_CAST")
            val root = yamlLoader.loadFromString(file.readText()) as? Map<String, Any?> ?: return@forEach
            val detection = root["detection"] ?: return@forEach
            val literals = mutableListOf<String>()
            collectPermissionLiterals(detection, literals)
            literals.forEach { literal ->
                if (literal !in exposed) {
                    failures += "${file.name}: permissions literal \"$literal\" is not a short-named " +
                        "member of AppScanner.EXPOSED_PERMISSION_SHORT_NAMES $exposed — the rule can " +
                        "never fire (the scanner emits short names like \"NFC\", not this value). " +
                        "Fix: use the exact short name the scanner emits, or add the permission to " +
                        "AppScanner's surveillance/high-risk set. If you intended a SUBSTRING match " +
                        "(e.g. \"ALERT\" for SYSTEM_ALERT_WINDOW), that is intentionally disallowed — " +
                        "use the whole short name."
                }
            }
        }

        assertTrue(
            "Dead-rule guard (#225) found rule(s) matching permissions the scanner never emits:\n" +
                failures.joinToString("\n"),
            failures.isEmpty(),
        )
    }

    /**
     * Recursively collect (matcher key, literals) for every `requested_permissions`
     * matcher. Case-insensitive on the field name so case-variant keys (dead
     * matchers at runtime — the record lookup is case-sensitive) are surfaced
     * for rejection instead of escaping the guard.
     */
    private fun collectRequestedPermissionMatchers(
        node: Any?,
        into: MutableList<Pair<String, List<String>>>,
    ) {
        when (node) {
            is Map<*, *> -> node.forEach { (k, v) ->
                if (k is String && fieldName(k).lowercase() == "requested_permissions") {
                    val literals = mutableListOf<String>()
                    addLiterals(v, literals)
                    into.add(k to literals)
                }
                collectRequestedPermissionMatchers(v, into)
            }
            is List<*> -> node.forEach { collectRequestedPermissionMatchers(it, into) }
        }
    }

    /**
     * `requested_permissions` carries EVERY requested permission verbatim (FQN),
     * so the dead-rule hazard inverts: the field is open-ended, but SUBSTRING
     * matching false-positives (android.permission.NFC is a substring of
     * android.permission.NFC_TRANSACTION_EVENT). Guard:
     *  - exact element-wise equals only (bare key or `|all` combiner), lowercase key
     *  - non-empty literal list (an empty `|all` evaluates vacuously TRUE)
     *  - literals must be FQNs; android.permission.* literals must exist in the
     *    submodule's validation/android-permissions.txt (typo guard; skipped when
     *    the submodule is absent, mirroring DetectionFieldCrossCheckTest)
     *  - NEVER referenced under `not` in the condition: pre-#317 binaries do not
     *    emit the field, a matcher on it is always false there, and negation
     *    inverts that to always-true — silently defeating the exemption and
     *    over-firing on the old fleet via the 12h feed (the #136 Phase-2
     *    inversion class). There is no unknown-field skip floor; positive
     *    references merely no-op.
     */
    @Test
    fun `every bundled rule requested_permissions matcher is exact-equals FQN and never negated`() {
        val knownShortNames = TestRuleRepo.submoduleRoot()
            ?.resolve("validation/android-permissions.txt")
            ?.takeIf { it.isFile }
            ?.readLines()
            ?.map { it.trim() }
            ?.filter { it.isNotEmpty() }
            ?.toSet()

        val failures = mutableListOf<String>()
        bundledRuleFiles().forEach { file ->
            @Suppress("UNCHECKED_CAST")
            val root = yamlLoader.loadFromString(file.readText()) as? Map<String, Any?> ?: return@forEach
            val detection = root["detection"] as? Map<*, *> ?: return@forEach
            checkRequestedPermissionRule(file.name, detection, knownShortNames, failures)
        }

        assertTrue(
            "requested_permissions matching-discipline guard failed:\n" + failures.joinToString("\n"),
            failures.isEmpty(),
        )
    }

    private fun checkRequestedPermissionRule(
        fileName: String,
        detection: Map<*, *>,
        knownShortNames: Set<String>?,
        failures: MutableList<String>,
    ) {
        // Negation guard: `not` binds to exactly the next whitespace token in
        // the evaluator's condition grammar (SigmaRuleEvaluator.evaluateAndGroup).
        val conditionTokens = (detection["condition"] as? String)?.trim()?.split(Regex("\\s+")) ?: emptyList()
        conditionTokens.forEachIndexed { i, token ->
            if (!token.equals("not", ignoreCase = true) || i + 1 >= conditionTokens.size) return@forEachIndexed
            val negated = mutableListOf<Pair<String, List<String>>>()
            collectRequestedPermissionMatchers(detection[conditionTokens[i + 1]], negated)
            if (negated.isNotEmpty()) {
                failures += "$fileName: selection \"${conditionTokens[i + 1]}\" matches " +
                    "requested_permissions and is referenced under `not` — on builds that predate the " +
                    "field, the matcher is always false and negation inverts it to always-true, defeating " +
                    "the exemption and over-firing on the old fleet. Gate the exemption on a field old " +
                    "builds emit, or wait for the fleet floor to cover the emitter."
            }
        }

        val matchers = mutableListOf<Pair<String, List<String>>>()
        collectRequestedPermissionMatchers(detection, matchers)
        matchers.forEach { (key, literals) ->
            checkRequestedPermissionMatcher(fileName, key, literals, knownShortNames, failures)
        }
    }

    private fun checkRequestedPermissionMatcher(
        fileName: String,
        key: String,
        literals: List<String>,
        knownShortNames: Set<String>?,
        failures: MutableList<String>,
    ) {
        if (fieldName(key) != "requested_permissions") {
            failures += "$fileName: matcher key \"$key\" — the field key must be exactly lowercase " +
                "requested_permissions (the runtime record lookup is case-sensitive; a case-variant key " +
                "is a dead matcher)."
        } else if (key != "requested_permissions" && key != "requested_permissions|all") {
            failures += "$fileName: matcher \"$key\" — requested_permissions allows only exact " +
                "element-wise equals (bare key) or the |all combiner. Substring modifiers false-positive: " +
                "android.permission.NFC is a substring of android.permission.NFC_TRANSACTION_EVENT."
        }
        if (literals.isEmpty()) {
            failures += "$fileName: matcher \"$key\" has no literal values — an empty |all list " +
                "evaluates vacuously TRUE on emitting builds."
        }
        literals.forEach { literal ->
            if ('.' !in literal) {
                failures += "$fileName: requested_permissions literal \"$literal\" is not fully " +
                    "qualified — the scanner emits verbatim manifest strings like " +
                    "\"android.permission.NEARBY_WIFI_DEVICES\", so a short name can never match."
            } else if (
                knownShortNames != null &&
                literal.lowercase().startsWith("android.permission.") &&
                literal.substringAfterLast('.').uppercase() !in knownShortNames
            ) {
                failures += "$fileName: requested_permissions literal \"$literal\" is not in the " +
                    "submodule's validation/android-permissions.txt — likely a typo; add the permission " +
                    "there (with a rules-repo PR) if it is real."
            }
        }
    }
}
