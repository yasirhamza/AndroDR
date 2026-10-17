package com.androdr.ioc

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import java.io.File

class CampaignRegistryTest {

    @get:Rule val tmp = TemporaryFolder()

    private val bundledJson: String by lazy {
        listOf(File("src/main/res/raw/known_campaigns.json"), File("app/src/main/res/raw/known_campaigns.json"))
            .first { it.isFile }.readText()
    }

    private val submoduleYaml: String by lazy {
        listOf(
            File("../third-party/android-sigma-rules/ioc-data/campaigns.yml"),
            File("third-party/android-sigma-rules/ioc-data/campaigns.yml"),
        ).first { it.isFile }.readText()
    }

    private fun registry(cache: File = File(tmp.root, "campaigns.yml")) = CampaignRegistry(cache) { bundledJson }

    @Test
    fun `no cached campaigns yml falls back to the bundled vocabulary`() {
        val campaigns = registry().campaigns()
        assertEquals(CampaignRegistry.parseBundled(bundledJson), campaigns)
        assertEquals(
            setOf("pegasus", "predator", "graphite", "cellebrite", "landfall", "massistant", "midnight-mimosa"),
            campaigns.map { it.key }.toSet(),
        )
    }

    @Test
    fun `bundled fallback folds the paragon alias into the Graphite row`() {
        val r = registry()
        assertEquals("graphite", r.keyFor("paragon"))
        assertEquals("graphite", r.keyFor("graphite"))
        assertEquals("Graphite (Paragon)", r.campaigns().single { it.key == "graphite" }.label)
        assertNull(r.keyFor("unknownkey"))
    }

    @Test
    fun `the pinned campaigns yml parses to the same vocabulary as the bundle`() {
        assertEquals(CampaignRegistry.parseBundled(bundledJson), CampaignRegistry.parseYaml(submoduleYaml))
    }

    @Test
    fun `a verified campaigns yml is cached and then used`() {
        val cache = File(tmp.root, "campaigns.yml")
        val r = registry(cache)
        val yaml = "campaigns:\n  - key: newone\n    label: New One\n    aliases: [n1]\n"
        assertTrue(r.storeVerified(yaml))
        assertTrue(cache.isFile)
        assertEquals(listOf(Campaign("newone", "New One", listOf("n1"))), r.campaigns())
        assertEquals("newone", r.keyFor("n1"))
    }

    @Test
    fun `an invalid campaigns yml is not cached`() {
        val cache = File(tmp.root, "campaigns.yml")
        assertFalse(registry(cache).storeVerified("not: [valid"))
        assertFalse(registry(cache).storeVerified("campaigns: []"))
        assertFalse(cache.exists())
    }

    @Test
    fun `an invalid cached file falls back to the bundle`() {
        val cache = File(tmp.root, "campaigns.yml").apply { writeText("garbage [[[") }
        assertEquals(CampaignRegistry.parseBundled(bundledJson), registry(cache).campaigns())
    }

    @Test
    fun `keys are re-validated and labels sanitised`() {
        val yaml = """
            campaigns:
              - key: "Bad Key"
                label: Bad
              - key: ok-key
                label: "Ok${'‮'}Label with a very long tail that keeps going past forty"
                aliases: [good, "BAD ALIAS"]
              - key: nolabel
        """.trimIndent()
        val parsed = CampaignRegistry.parseYaml(yaml)
        assertEquals(listOf("nolabel", "ok-key"), parsed.map { it.key }) // sorted by key
        val ok = parsed[1]
        assertFalse(ok.label.contains('‮'))
        assertTrue(ok.label.length <= 40)
        assertEquals(listOf("good"), ok.aliases)
        assertEquals("Nolabel", parsed[0].label)
    }

    @Test
    fun `detected_by is read from yaml - present, empty, absent, junk`() {
        val yaml = """
            campaigns:
              - key: a
                label: A
                detected_by: [dns_monitor, app_scanner, dns_monitor]
              - key: b
                label: B
                detected_by: []
              - key: c
                label: C
              - key: d
                label: D
                detected_by: dns_monitor
              - key: e
                label: E
                detected_by: [file_scanner, "Bad Value", "x;y"]
        """.trimIndent()
        val byKey = CampaignRegistry.parseYaml(yaml).associate { it.key to it.detectedBy }
        assertEquals(listOf("app_scanner", "dns_monitor"), byKey["a"])
        assertEquals(emptyList<String>(), byKey["b"])
        assertNull(byKey["c"])
        assertNull(byKey["d"]) // not a list: treated as absent
        assertEquals(listOf("file_scanner"), byKey["e"])
    }

    @Test
    fun `detected_by is read from the bundled json`() {
        val json = """[{"key":"a","label":"A","aliases":[],"detected_by":["dns_monitor"]},
            {"key":"b","label":"B","aliases":[]},{"key":"c","label":"C","aliases":[],"detected_by":"x"}]"""
        val byKey = CampaignRegistry.parseBundled(json).associate { it.key to it.detectedBy }
        assertEquals(listOf("dns_monitor"), byKey["a"])
        assertNull(byKey["b"])
        assertNull(byKey["c"])
    }

    @Test
    fun `the bundle declares detected_by for every campaign`() {
        val byKey = CampaignRegistry.parseBundled(bundledJson).associate { it.key to it.detectedBy }
        assertEquals(
            mapOf(
                "cellebrite" to listOf("app_scanner"), "graphite" to listOf("dns_monitor"),
                "landfall" to emptyList(), "massistant" to listOf("app_scanner"),
                "midnight-mimosa" to listOf("app_scanner", "dns_monitor"), "pegasus" to listOf("dns_monitor"),
                "predator" to listOf("dns_monitor", "file_scanner"),
            ),
            byKey,
        )
    }
}
