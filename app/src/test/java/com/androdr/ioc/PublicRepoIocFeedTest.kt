// app/src/test/java/com/androdr/ioc/PublicRepoIocFeedTest.kt
package com.androdr.ioc

import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
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

    private var remote = FakeRemote(emptyMap())

    /** Serves [files] (keyed by file name) with a matching, valid manifest. */
    private fun stubFetch(files: Map<String, String>) {
        remote = FakeRemote(files.mapKeys { "ioc-data/${it.key}" })
    }

    private fun feedOf(dao: FakeIndicatorDao) =
        PublicRepoIocFeed(dao, io.mockk.mockk(relaxed = true), IocDataManifest(remote))

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
        feedOf(dao).update()
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
        stubFetch(mapOf("c2-domains.yml" to withKey))
        feedOf(dao).update()
        assertEquals("pegasus", dao.lookup("domain", "pegasus.example")!!.campaignKey)
        stubFetch(mapOf("c2-domains.yml" to withoutKey))
        feedOf(dao).update()
        assertEquals("", dao.lookup("domain", "pegasus.example")!!.campaignKey)
        feedOf(dao).update()
        assertEquals("", dao.lookup("domain", "pegasus.example")!!.campaignKey)
    }

    // ── B9: ioc-data verified against ioc-data.sha256, fail-closed ──

    private fun domainYaml(vararg d: String) = yaml(*d.map { """
              - indicator: "$it"
                family: "Fam"
                category: "SPYWARE"
                severity: "HIGH"
                source: "s"
        """.trimIndent() }.toTypedArray())

    private fun pkgYaml(p: String) = yaml("""
              - indicator: "$p"
                family: "Fam"
                severity: "HIGH"
                source: "s"
        """.trimIndent())

    @Test
    fun `verified file is upserted`() = runBlocking {
        stubFetch(mapOf("c2-domains.yml" to domainYaml("a.example")))
        val dao = FakeIndicatorDao()
        feedOf(dao).update()
        assertEquals("Fam", dao.lookup("domain", "a.example")!!.family)
    }

    @Test
    fun `altered file is skipped and others still load`() = runBlocking {
        stubFetch(mapOf("c2-domains.yml" to domainYaml("a.example"), "package-names.yml" to pkgYaml("com.x.y")))
        remote.set("ioc-data/c2-domains.yml", domainYaml("a.example", "evil.example"))
        val dao = FakeIndicatorDao()
        feedOf(dao).update()
        assertNull(dao.lookup("domain", "a.example"))
        assertNull(dao.lookup("domain", "evil.example"))
        assertNotNull(dao.lookup("package", "com.x.y"))
    }

    @Test
    fun `missing manifest upserts nothing`() = runBlocking {
        stubFetch(mapOf("c2-domains.yml" to domainYaml("a.example"), "package-names.yml" to pkgYaml("com.x.y")))
        remote.setManifest(null)
        val dao = FakeIndicatorDao()
        val result = feedOf(dao).update()
        assertEquals(0, result.written)
        assertTrue(dao.snapshot().isEmpty())
    }

    @Test
    fun `empty or corrupt manifest upserts nothing`() = runBlocking {
        for (body in listOf("", "not a manifest")) {
            stubFetch(mapOf("c2-domains.yml" to domainYaml("a.example")))
            remote.setManifest(body)
            val dao = FakeIndicatorDao()
            feedOf(dao).update()
            assertTrue(dao.snapshot().isEmpty())
        }
    }

    @Test
    fun `domain removed from c2-domains between updates is evicted`() = runBlocking {
        val dao = FakeIndicatorDao()
        stubFetch(mapOf("c2-domains.yml" to domainYaml("keep.example", "gone.example")))
        val feed = feedOf(dao)
        feed.update()
        Thread.sleep(2)
        remote = FakeRemote(mapOf("ioc-data/c2-domains.yml" to domainYaml("keep.example")))
        val result = PublicRepoIocFeed(dao, io.mockk.mockk(relaxed = true), IocDataManifest(remote)).update()
        assertNotNull(dao.lookup("domain", "keep.example"))
        assertNull(dao.lookup("domain", "gone.example"))
        assertEquals(1, result.evicted)
    }

    @Test
    fun `packages verify but domains mismatch - previous domain rows survive`() = runBlocking {
        val dao = FakeIndicatorDao()
        stubFetch(mapOf("c2-domains.yml" to domainYaml("old.example"), "package-names.yml" to pkgYaml("com.x.y")))
        feedOf(dao).update()
        Thread.sleep(2)
        remote = FakeRemote(mapOf("ioc-data/c2-domains.yml" to domainYaml("new.example"),
            "ioc-data/package-names.yml" to pkgYaml("com.x.z")))
        remote.set("ioc-data/c2-domains.yml", "tampered")
        val result = PublicRepoIocFeed(dao, io.mockk.mockk(relaxed = true), IocDataManifest(remote)).update()
        assertNotNull("old domain survives", dao.lookup("domain", "old.example"))
        assertNull(dao.lookup("domain", "new.example"))
        assertNull("package type evicted its own stale row", dao.lookup("package", "com.x.y"))
        assertNotNull(dao.lookup("package", "com.x.z"))
        assertEquals(1, result.evicted)
    }

    // ── campaigns.yml: verified fetch, bundled fallback (B7) ──

    @get:org.junit.Rule val tmp = org.junit.rules.TemporaryFolder()

    private val bundledCampaignsJson: String by lazy {
        listOf(java.io.File("src/main/res/raw/known_campaigns.json"),
            java.io.File("app/src/main/res/raw/known_campaigns.json")).first { it.isFile }.readText()
    }

    private val campaignsYaml = "campaigns:\n  - key: remoteonly\n    label: Remote Only\n"

    @Test
    fun `verified campaigns yml is cached for the registry`() = runBlocking {
        val cache = java.io.File(tmp.root, "campaigns.yml")
        val registry = CampaignRegistry(cache) { bundledCampaignsJson }
        val r = FakeRemote(mapOf("ioc-data/campaigns.yml" to campaignsYaml))
        PublicRepoIocFeed(FakeIndicatorDao(), io.mockk.mockk(relaxed = true), IocDataManifest(r), registry).update()
        assertEquals(listOf(Campaign("remoteonly", "Remote Only")), registry.campaigns())
    }

    @Test
    fun `campaigns yml hash mismatch falls back to the bundled list`() = runBlocking {
        val cache = java.io.File(tmp.root, "campaigns.yml")
        val registry = CampaignRegistry(cache) { bundledCampaignsJson }
        val r = FakeRemote(mapOf("ioc-data/campaigns.yml" to campaignsYaml))
        r.set("ioc-data/campaigns.yml", campaignsYaml + "  - key: injected\n    label: Injected\n")
        PublicRepoIocFeed(FakeIndicatorDao(), io.mockk.mockk(relaxed = true), IocDataManifest(r), registry).update()
        assertTrue("unverified campaigns.yml must not be cached", !cache.exists())
        assertEquals(CampaignRegistry.parseBundled(bundledCampaignsJson), registry.campaigns())
    }

    @Test
    fun `campaigns yml is still cached when an earlier feed step throws`() = runBlocking {
        val cache = java.io.File(tmp.root, "campaigns.yml")
        val registry = CampaignRegistry(cache) { bundledCampaignsJson }
        val r = FakeRemote(mapOf(
            "ioc-data/package-names.yml" to "entries:\n  - indicator: com.x.y\n",
            "ioc-data/campaigns.yml" to campaignsYaml,
        ))
        val dao = io.mockk.mockk<com.androdr.data.db.IndicatorDao>(relaxed = true)
        io.mockk.coEvery { dao.upsertAll(any()) } throws IllegalStateException("db down")
        PublicRepoIocFeed(dao, io.mockk.mockk(relaxed = true), IocDataManifest(r), registry).update()
        assertEquals(listOf(Campaign("remoteonly", "Remote Only")), registry.campaigns())
    }
}
