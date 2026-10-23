package com.androdr.sigma

import android.content.Context
import io.mockk.mockk
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Gate K1, part 1: every category an atom rule binds to has a producer.
 *
 * An atom whose category nothing produces never binds, so every correlation
 * rule that needs it silently never fires. Categories come from
 * [TimelineCategories.categoryOf] (run over the contract corpus) or from the
 * few detected-change rows written straight to `forensic_timeline`.
 */
class TimelineCategoriesAtomTest {

    /** Bundled atom rules, judged by the engine's own atom definition. */
    private fun atomCategories(): Set<String> {
        val files = TestRuleRepo.rulesDirectory()
            .listFiles { f -> f.name.startsWith("sigma_androdr_atom_") && f.name.endsWith(".yml") }
            .orEmpty()
        assertTrue(
            "Expected at least $MIN_ATOM_FILES atom rule files, found ${files.size}",
            files.size >= MIN_ATOM_FILES,
        )
        val rules = files.map { SigmaRuleParser.parse(it.readText()) ?: error("${it.name} did not parse") }
        val engine = SigmaRuleEngine(mockk<Context>(relaxed = true))
        engine.setRemoteRules(rules)
        val categories = engine.atomCategories()
        assertEquals(
            "Every atom rule file must be an atom by the engine's definition",
            rules.map { it.id }.toSet(), categories.keys,
        )
        return categories.values.toSet()
    }

    @Test
    fun `every atom category is produced by TimelineCategories or a forensic_timeline row`() {
        val produced = ContractCorpus.records().map { (service, fields) ->
            TimelineCategories.categoryOf(service, fields)
        }.toSet()
        val orphaned = atomCategories() - produced - ROW_CATEGORIES.keys
        assertTrue(
            "Atom categories with no producer (the atom can never bind): $orphaned",
            orphaned.isEmpty(),
        )
    }

    @Test
    fun `row-only categories are written by their named producer`() {
        for ((category, producerFile) in ROW_CATEGORIES) {
            val source = TestRuleRepo.stripKotlinComments(TestRuleRepo.mainSourceFile(producerFile).readText())
            assertTrue(
                "$producerFile no longer writes category \"$category\"",
                source.contains("category = \"$category\""),
            )
        }
    }

    private companion object {
        const val MIN_ATOM_FILES = 5

        /**
         * Categories written directly as `forensic_timeline` rows by a live
         * detected-change emitter rather than derived from a telemetry record.
         * Category -> the production file that writes it.
         */
        val ROW_CATEGORIES = mapOf(
            // Live device-admin grant diff; no telemetry service carries it.
            "device_admin_grant" to "com/androdr/scanner/DeviceAdminGrantEmitter.kt",
        )
    }
}
