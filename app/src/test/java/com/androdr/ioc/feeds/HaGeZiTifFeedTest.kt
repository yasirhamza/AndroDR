package com.androdr.ioc.feeds

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class HaGeZiTifFeedTest {

    private val feed = HaGeZiTifFeed()

    @Test
    fun `parseDomainList extracts domains from plain text`() {
        val text = """
            malware.example.com
            phishing.evil.org
            tracker.bad.net
        """.trimIndent()
        val entries = feed.parseDomainList(text, 1000L)
        assertEquals(3, entries.size)
        assertEquals("malware.example.com", entries[0].domain)
        assertEquals("phishing.evil.org", entries[1].domain)
        assertEquals("tracker.bad.net", entries[2].domain)
    }

    @Test
    fun `parseDomainList skips comments and empty lines`() {
        val text = """
            # This is a header comment
            # Another comment
            malware.example.com

            # Inline comment
            phishing.evil.org

        """.trimIndent()
        val entries = feed.parseDomainList(text, 1000L)
        assertEquals(2, entries.size)
    }

    @Test
    fun `parseDomainList lowercases domains`() {
        val text = "Malware.EXAMPLE.Com"
        val entries = feed.parseDomainList(text, 1000L)
        assertEquals("malware.example.com", entries[0].domain)
    }

    @Test
    fun `parseDomainList sets correct metadata`() {
        val text = "evil.example.com"
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
            # comment one
            # comment two
        """.trimIndent()
        assertTrue(feed.parseDomainList(text, 0L).isEmpty())
    }

    @Test
    fun `sourceId is hagezi_tif`() {
        assertEquals("hagezi_tif", feed.sourceId)
    }
}
