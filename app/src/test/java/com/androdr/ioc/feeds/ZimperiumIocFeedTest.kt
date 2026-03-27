package com.androdr.ioc.feeds

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class ZimperiumIocFeedTest {

    private val feed = ZimperiumIocFeed()

    @Test
    fun `parseC2 extracts domains from simple list`() {
        val text = """
            evil.example.com
            malware.bad.org
            192.168.1.100
        """.trimIndent()
        val entries = feed.parseC2(text, "TrickMo", 1000L)
        assertEquals(3, entries.size)
        assertEquals("evil.example.com", entries[0].domain)
        assertEquals("malware.bad.org", entries[1].domain)
        assertEquals("192.168.1.100", entries[2].domain)
    }

    @Test
    fun `parseC2 skips comments and empty lines`() {
        val text = """
            # This is a comment
            evil.example.com

            # Another comment

            malware.bad.org
        """.trimIndent()
        val entries = feed.parseC2(text, "FakeCall", 1000L)
        assertEquals(2, entries.size)
    }

    @Test
    fun `parseC2 lowercases domains`() {
        val text = "Evil.Example.COM"
        val entries = feed.parseC2(text, "Banking-Heist", 1000L)
        assertEquals("evil.example.com", entries[0].domain)
    }

    @Test
    fun `parseC2 sets correct metadata`() {
        val text = "c2.evil.com"
        val entries = feed.parseC2(text, "Crocodilus", 9999L)
        val entry = entries[0]
        assertEquals("Crocodilus", entry.campaignName)
        assertEquals("CRITICAL", entry.severity)
        assertEquals("zimperium", entry.source)
        assertEquals(9999L, entry.fetchedAt)
    }

    @Test
    fun `parseC2 returns empty list for blank input`() {
        assertTrue(feed.parseC2("", "test", 0L).isEmpty())
    }

    @Test
    fun `parseC2 returns empty list for comments-only input`() {
        val text = """
            # comment one
            # comment two
        """.trimIndent()
        assertTrue(feed.parseC2(text, "test", 0L).isEmpty())
    }

    @Test
    fun `campaigns list is not empty`() {
        assertTrue(ZimperiumIocFeed.campaigns.isNotEmpty())
    }
}
