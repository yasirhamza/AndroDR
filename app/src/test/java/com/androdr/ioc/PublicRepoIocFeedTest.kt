// app/src/test/java/com/androdr/ioc/PublicRepoIocFeedTest.kt
package com.androdr.ioc

import io.mockk.every
import io.mockk.mockkObject
import io.mockk.unmockkObject
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class PublicRepoIocFeedTest {

    private val feed = PublicRepoIocFeed(
        indicatorDao = io.mockk.mockk(relaxed = true),
        knownAppEntryDao = io.mockk.mockk(relaxed = true)
    )

    @Test
    fun `parseIocYaml extracts entries from valid YAML`() {
        val yaml = """
            version: "2026-03-28"
            description: "Test IOC data"
            sources: []
            entries:
              - indicator: "com.evil.app"
                family: "EvilMalware"
                category: "RAT"
                severity: "CRITICAL"
                description: "Test entry"
                source: "test"
              - indicator: "com.bad.app"
                family: "BadMalware"
                category: "STALKERWARE"
                severity: "HIGH"
                description: "Another test"
                source: "test"
        """.trimIndent()

        val entries = feed.parseIocYaml(yaml)
        assertEquals(2, entries.size)
        assertEquals("com.evil.app", entries[0]["indicator"])
        assertEquals("EvilMalware", entries[0]["family"])
        assertEquals("com.bad.app", entries[1]["indicator"])
    }

    @Test
    fun `parseIocYaml returns empty for empty entries`() {
        val yaml = """
            version: "2026-03-28"
            entries: []
        """.trimIndent()

        val entries = feed.parseIocYaml(yaml)
        assertTrue(entries.isEmpty())
    }

    @Test
    fun `parseIocYaml returns empty for invalid YAML`() {
        val entries = feed.parseIocYaml("not valid yaml [[[")
        assertTrue(entries.isEmpty())
    }

    @Test
    fun `parseIocYaml returns empty for missing entries key`() {
        val yaml = """
            version: "2026-03-28"
            description: "No entries key"
        """.trimIndent()

        val entries = feed.parseIocYaml(yaml)
        assertTrue(entries.isEmpty())
    }

    @Test
    fun `parsePopularAppsYaml extracts entries from valid YAML`() {
        val yaml = """
            version: "2026-03-30"
            description: "Popular apps"
            entries:
              - packageName: "com.whatsapp"
                displayName: "WhatsApp"
              - packageName: "com.instagram.android"
                displayName: "Instagram"
        """.trimIndent()

        val entries = feed.parsePopularAppsYaml(yaml)
        assertEquals(2, entries.size)
        assertEquals("com.whatsapp", entries[0]["packageName"])
        assertEquals("WhatsApp", entries[0]["displayName"])
        assertEquals("com.instagram.android", entries[1]["packageName"])
    }

    @Test
    fun `parsePopularAppsYaml returns empty for empty entries`() {
        val yaml = """
            version: "2026-03-30"
            entries: []
        """.trimIndent()

        val entries = feed.parsePopularAppsYaml(yaml)
        assertTrue(entries.isEmpty())
    }

    @Test
    fun `parsePopularAppsYaml returns empty for invalid YAML`() {
        val entries = feed.parsePopularAppsYaml("not valid yaml [[[")
        assertTrue(entries.isEmpty())
    }

    @Test
    fun `parsePopularAppsYaml returns empty for missing entries key`() {
        val yaml = """
            version: "2026-03-30"
            description: "No entries"
        """.trimIndent()

        val entries = feed.parsePopularAppsYaml(yaml)
        assertTrue(entries.isEmpty())
    }

    // ── Writers populate the v19 layout; campaign key retraction ──

    private fun yaml(vararg entries: String) = "version: \"1\"\nentries:\n" + entries.joinToString("\n")

    private fun stubFetch(files: Map<String, String>) {
        mockkObject(SafeHttpFetch)
        every { SafeHttpFetch.fetch(any(), any(), any()) } returns null
        files.forEach { (suffix, body) ->
            every { SafeHttpFetch.fetch(match { it.endsWith(suffix) }, any(), any()) } returns body
        }
    }

    @After
    fun unmock() = unmockkObject(SafeHttpFetch)

    @Test
    fun `every writer populates family, category and reference`() = runBlocking {
        val entry = { ind: String -> """
              - indicator: "$ind"
                family: "Fam"
                category: "SPYWARE"
                severity: "HIGH"
                description: "d"
                source: "s"
                reference: "https://example.org/r"
                campaign: "predator"
        """.trimIndent() }
        stubFetch(mapOf(
            "package-names.yml" to yaml(entry("com.x.y")),
            "c2-domains.yml" to yaml(entry("Evil.Example")),
            "cert-hashes.yml" to yaml(entry("ABCD")),
            "malware-hashes.yml" to yaml(entry("EF01")),
        ))
        val dao = FakeIndicatorDao()
        PublicRepoIocFeed(dao, io.mockk.mockk(relaxed = true)).update()
        for ((type, value) in listOf("package" to "com.x.y", "domain" to "evil.example",
            "cert_hash" to "abcd", "apk_hash" to "ef01")) {
            val row = dao.lookup(type, value)!!
            assertEquals("$type family", "Fam", row.family)
            assertEquals("$type category", "SPYWARE", row.category)
            assertEquals("$type reference", "https://example.org/r", row.reference)
            assertEquals("$type campaignKey", "predator", row.campaignKey)
        }
    }

    @Test
    fun `campaign key is retracted when ioc-data drops it and does not come back`() = runBlocking {
        val withKey = yaml("""
              - indicator: "pegasus.example"
                family: "Pegasus"
                category: "NATION_STATE_SPYWARE"
                severity: "CRITICAL"
                source: "s"
                reference: "https://example.org/r"
                campaign: "pegasus"
        """.trimIndent())
        val withoutKey = withKey.replace("                campaign: \"pegasus\"\n", "").trimEnd()
            .let { if (it.contains("campaign:")) it.substringBeforeLast("\n") else it }
        val dao = FakeIndicatorDao()
        val feed = PublicRepoIocFeed(dao, io.mockk.mockk(relaxed = true))
        stubFetch(mapOf("c2-domains.yml" to withKey))
        feed.update()
        assertEquals("pegasus", dao.lookup("domain", "pegasus.example")!!.campaignKey)
        stubFetch(mapOf("c2-domains.yml" to withoutKey))
        feed.update()
        assertEquals("", dao.lookup("domain", "pegasus.example")!!.campaignKey)
        feed.update()
        assertEquals("", dao.lookup("domain", "pegasus.example")!!.campaignKey)
    }
}
