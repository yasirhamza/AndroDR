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
 * are open-ended (the scanner emits every declared component permission verbatim),
 * so they are intentionally NOT constrained here.
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

    /** Recursively collect the literal value(s) of every `permissions` matcher. */
    private fun collectPermissionLiterals(node: Any?, into: MutableList<String>) {
        when (node) {
            is Map<*, *> -> node.forEach { (k, v) ->
                if (k is String && fieldName(k) == "permissions") {
                    when (v) {
                        is String -> into.add(v)
                        is List<*> -> v.forEach { it?.let { e -> into.add(e.toString()) } }
                    }
                }
                collectPermissionLiterals(v, into)
            }
            is List<*> -> node.forEach { collectPermissionLiterals(it, into) }
        }
    }

    @Test
    fun `every bundled rule permissions literal is exposed by the scanner`() {
        val exposed = AppScanner.EXPOSED_PERMISSION_SHORT_NAMES
        assertTrue("Exposed permission set is unexpectedly empty", exposed.isNotEmpty())

        val failures = mutableListOf<String>()

        bundledRuleFiles().forEach { file ->
            @Suppress("UNCHECKED_CAST")
            val root = yamlLoader.loadFromString(file.readText()) as? Map<String, Any?> ?: return@forEach
            val detection = root["detection"] ?: return@forEach
            val literals = mutableListOf<String>()
            collectPermissionLiterals(detection, literals)
            literals.forEach { literal ->
                if (literal !in exposed) {
                    failures += "${file.name}: permissions literal \"$literal\" is not a short-named " +
                        "member of AppScanner.EXPOSED_PERMISSION_SHORT_NAMES $exposed — the rule can " +
                        "never fire. Use a short name the scanner emits, or add the permission to " +
                        "AppScanner's surveillance/high-risk set."
                }
            }
        }

        assertTrue(
            "Dead-rule guard (#225) found rule(s) matching permissions the scanner never emits:\n" +
                failures.joinToString("\n"),
            failures.isEmpty(),
        )
    }
}
