package com.androdr.privacy.model

import com.androdr.ioc.TrackerRegistry
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.snakeyaml.engine.v2.api.Load
import org.snakeyaml.engine.v2.api.LoadSettings
import java.io.File

/**
 * The detailed matchers must name exactly the trackers the plain matchers name, on the real
 * bundled list: the details view explains a finding, it must never disagree with it.
 */
class TrackerSetDetailCrossCheckTest {

    private val yaml: String =
        listOf(File("src/main/res/raw/trackers.yml"), File("app/src/main/res/raw/trackers.yml"))
            .first { it.isFile }.readText()

    private val set: TrackerSet = requireNotNull(TrackerRegistry.parse(yaml))

    @Test
    fun `detailed and plain code matching name the same trackers on the real list`() {
        val corpus = set.trackers.flatMap { t ->
            t.codePrefixes.flatMap { listOf(it, "$it.zz") } + t.codeSegments.map { "zz.$it.zz" }
        }
        val detailed = set.matchPackagesDetailed(corpus).map { it.tracker.id }.toSet()
        val plain = set.matchPackages(corpus).map { it.id }.toSet()
        assertEquals(plain, detailed)
        val withCode = set.trackers.filter { it.codePrefixes.isNotEmpty() || it.codeSegments.isNotEmpty() }
        assertTrue(withCode.isNotEmpty())
        assertEquals(withCode.map { it.id }.toSet(), detailed)
    }

    @Test
    fun `detailed and plain domain matching name the same trackers on the real list`() {
        val hosts = set.trackers.flatMap { t ->
            t.domainSuffixes.flatMap { listOf(it, "zz.$it") } + t.domainLabels.flatMap { listOf("$it.zz", "zz.$it.zz") }
        } + listOf("adservice.google.com", "mst1.is.autonavi.com", "mt1.google.cn")
        assertTrue(hosts.size > 100)
        for (host in hosts) {
            val detailed = set.matchDomainDetailed(host).map { it.tracker.id }
            val plain = set.matchDomain(host).map { it.id }.toSet()
            assertFalse("no tracker for $host", plain.isEmpty())
            assertEquals("one detailed match per tracker for $host", detailed.toSet().size, detailed.size)
            assertEquals(host, plain, detailed.toSet())
        }
    }

    @Test
    fun `a pattern is shown as the list writes it apart from an escaped hyphen`() {
        val doc = Load(LoadSettings.builder().build()).loadFromString(yaml)
        val written = (doc as Map<*, *>)["trackers"].let { it as List<*> }
            .flatMap { ((it as Map<*, *>)["domain_patterns"] as? List<*>).orEmpty() }
            .map { it as String }
        assertTrue(written.isNotEmpty())
        for (p in written) {
            val compiled = DomainGrammar.compilePattern(p) ?: continue
            assertEquals(p.replace("\\-", "-"), compiled.pattern.replace("\\-", "-"))
        }
    }
}
