package com.androdr.ioc.feeds

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class HaGeZiTifFeedTest {

    private val feed = HaGeZiTifFeed()

    @Test
    fun `parseDomainList extracts domains from adblock format`() {
        val text = """
            [Adblock Plus]
            ! Title: HaGeZi TIF
            ||malware.example.com^
            ||phishing.evil.org^
            ||tracker.bad.net^
        """.trimIndent()
        val entries = feed.parseDomainList(text, 1000L)
        assertEquals(3, entries.size)
        assertEquals("malware.example.com", entries[0].domain)
        assertEquals("phishing.evil.org", entries[1].domain)
        assertEquals("tracker.bad.net", entries[2].domain)
    }

    @Test
    fun `parseDomainList skips comments and metadata lines`() {
        val text = """
            [Adblock Plus]
            ! Title: Test
            ! Last modified: today
            ||malware.example.com^
            ||phishing.evil.org^
        """.trimIndent()
        val entries = feed.parseDomainList(text, 1000L)
        assertEquals(2, entries.size)
    }

    @Test
    fun `parseDomainList skips wildcard entries`() {
        val text = """
            ||*.example.com^
            ||clean.example.com^
        """.trimIndent()
        val entries = feed.parseDomainList(text, 1000L)
        assertEquals(1, entries.size)
        assertEquals("clean.example.com", entries[0].domain)
    }

    @Test
    fun `parseDomainList sets correct metadata`() {
        val text = "||evil.example.com^"
        val entries = feed.parseDomainList(text, 9999L)
        val entry = entries[0]
        assertEquals("HaGeZi TIF", entry.campaignName)
        assertEquals("HIGH", entry.severity)
        assertEquals("hagezi_tif", entry.source)
        assertEquals(9999L, entry.fetchedAt)
    }

    @Test
    fun `parseDomainList returns empty list for blank input`() {
        assertTrue(feed.parseDomainList("", 0L).isEmpty())
    }

    @Test
    fun `parseDomainList returns empty list for comments-only input`() {
        val text = """
            [Adblock Plus]
            ! comment one
            ! comment two
        """.trimIndent()
        assertTrue(feed.parseDomainList(text, 0L).isEmpty())
    }

    @Test
    fun `sourceId is hagezi_tif`() {
        assertEquals("hagezi_tif", feed.sourceId)
    }
}
