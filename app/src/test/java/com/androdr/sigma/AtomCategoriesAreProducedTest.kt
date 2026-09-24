package com.androdr.sigma

import android.content.Context
import com.androdr.data.model.TimelineCategories
import io.mockk.mockk
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/**
 * An atom rule must bind to a category something actually writes (#378).
 *
 * `androdr-atom-dns-lookup` selected `dns_match`; producers write `ioc_match`.
 * Atoms bind by exact equality, so it bound to nothing and androdr-corr-003 could
 * never fire -- for five months, with every test green, because the one test
 * that exercised it built its bindings by hand. Nothing checked an atom's
 * category against what the app writes.
 *
 * Checked here for BOTH copies: the bundled rules (res/raw) and the rules repo
 * pinned by the submodule. The rules repo is what devices fetch every 12 hours,
 * and the submodule bump is where a rules change meets AndroDR CI first.
 */
class AtomCategoriesAreProducedTest {

    private fun dir(vararg candidates: String): File =
        candidates.map(::File).firstOrNull { it.isDirectory }
            ?: error("none of ${candidates.toList()} exists")

    private val rawDir = dir("src/main/res/raw", "app/src/main/res/raw")
    private val submoduleTimeline = dir(
        "../third-party/android-sigma-rules/timeline", "third-party/android-sigma-rules/timeline",
    )
    private val mainSources = dir("src/main/java", "app/src/main/java")

    /** The engine's own definition of "atom -> category", applied to [files]. */
    private fun atomCategoriesOf(files: List<File>): Map<String, String> {
        val rules = files.mapNotNull { SigmaRuleParser.parse(it.readText()) }
        val engine = SigmaRuleEngine(mockk<Context>(relaxed = true))
        for (field in listOf("bundledRules", "rules")) {
            SigmaRuleEngine::class.java.getDeclaredField(field).apply { isAccessible = true }.set(engine, rules)
        }
        return engine.atomCategories()
    }

    private fun assertAllProduced(where: String, atoms: Map<String, String>) {
        assertTrue("no atoms found in $where -- the check would be vacuous", atoms.isNotEmpty())
        val dead = atoms.filterValues { it !in TimelineCategories.PRODUCED }
        assertEquals(
            "atom rule(s) in $where bind to a category nothing writes, so they bind to nothing: $dead",
            emptyMap<String, String>(),
            dead,
        )
    }

    @Test
    fun `every bundled atom binds to a category the app writes`() {
        val files = rawDir.listFiles { f -> f.name.startsWith("sigma_androdr_atom_") }!!.toList()

        assertAllProduced("res/raw", atomCategoriesOf(files))
    }

    @Test
    fun `every atom in the pinned rules repo binds to a category the app writes`() {
        val files = submoduleTimeline.listFiles { f -> f.name.endsWith(".yml") }!!.toList()

        assertAllProduced("the android-sigma-rules submodule", atomCategoriesOf(files))
    }

    @Test
    fun `the DNS atom binds to matched lookups`() {
        val files = rawDir.listFiles { f -> f.name == "sigma_androdr_atom_dns_lookup.yml" }!!.toList()

        assertEquals("ioc_match", atomCategoriesOf(files)["androdr-atom-dns-lookup"])
    }

    @Test
    fun `every category in the vocabulary is written by something`() {
        // The vocabulary is only a safe yardstick if it holds no dead value: a
        // category listed here that no producer writes would let a dead atom pass.
        // A producer is a main-source file that builds timeline rows.
        val producers = mainSources.walkTopDown()
            .filter { it.isFile && it.extension == "kt" }
            .map { it.readText() }
            .filter { it.contains("ForensicTimelineEvent(") || it.contains("TimelineEvent(") }
            .filterNot { it.contains("object TimelineCategories") }
            .toList()

        val unwritten = TimelineCategories.PRODUCED.filter { cat ->
            producers.none { it.contains("\"$cat\"") }
        }

        assertEquals("categories no producer writes: $unwritten", emptyList<String>(), unwritten)
    }
}
