// app/src/test/java/com/androdr/ioc/PublicRepoIocFeedTest.kt
package com.androdr.ioc

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class PublicRepoIocFeedTest {

    private val feed = PublicRepoIocFeed(
        iocEntryDao = io.mockk.mockk(),
        domainIocEntryDao = io.mockk.mockk(),
        certHashIocEntryDao = io.mockk.mockk(),
        knownAppEntryDao = io.mockk.mockk()
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
}
