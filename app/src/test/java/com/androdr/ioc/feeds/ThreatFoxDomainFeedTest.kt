package com.androdr.ioc.feeds

import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class ThreatFoxDomainFeedTest {

    private val feed = ThreatFoxDomainFeed()

    // ── parseRecentJson ──────────────────────────────────────────────────────

    private val sampleJson = """
        {
          "query_status": "ok",
          "data": {
            "2024-06-15": [
              {
                "ioc_type": "domain",
                "ioc": "evil-android.example.com",
                "malware": "Anatsa Android Banking Trojan",
                "tags": ["android", "banking"]
              },
              {
                "ioc_type": "domain",
                "ioc": "desktop-only.example.com",
                "malware": "Emotet",
                "tags": ["windows"]
              },
              {
                "ioc_type": "url",
                "ioc": "http://url-not-domain.example.com/path",
                "malware": "Android.Joker",
                "tags": ["android"]
              }
            ],
            "2024-06-14": [
              {
                "ioc_type": "domain",
                "ioc": "http://apk-malware.example.com/download",
                "malware": "MalAPK Dropper",
                "tags": []
              }
            ]
          }
        }
    """.trimIndent()

    @Test
    fun `parseRecentJson filters for android-related domain entries`() {
        val entries = feed.parseRecentJson(sampleJson, 1000L)
        // Should include: evil-android.example.com (tag=android), apk-malware.example.com (malware contains "apk")
        // Should exclude: desktop-only.example.com (no android tags/malware), url-not-domain (ioc_type=url)
        assertEquals(2, entries.size)
        val domains = entries.map { it.domain }.toSet()
        assertTrue(domains.contains("evil-android.example.com"))
        assertTrue(domains.contains("apk-malware.example.com"))
    }

    @Test
    fun `parseRecentJson sets correct metadata`() {
        val entries = feed.parseRecentJson(sampleJson, 9999L)
        val entry = entries.first { it.domain == "evil-android.example.com" }
        assertEquals("Anatsa Android Banking Trojan", entry.campaignName)
        assertEquals("CRITICAL", entry.severity)
        assertEquals("threatfox", entry.source)
        assertEquals(9999L, entry.fetchedAt)
    }

    @Test
    fun `parseRecentJson returns empty list for malformed JSON`() {
        assertTrue(feed.parseRecentJson("not json", 0L).isEmpty())
    }

    @Test
    fun `parseRecentJson returns empty list when data is missing`() {
        val json = """{"query_status": "ok"}"""
        assertTrue(feed.parseRecentJson(json, 0L).isEmpty())
    }

    // ── isAndroidRelated ─────────────────────────────────────────────────────

    @Test
    fun `isAndroidRelated returns true for android tag`() {
        val entry = JSONObject().apply {
            put("tags", JSONArray().apply { put("android") })
            put("malware", "SomeBot")
        }
        assertTrue(feed.isAndroidRelated(entry))
    }

    @Test
    fun `isAndroidRelated returns true for Android tag case insensitive`() {
        val entry = JSONObject().apply {
            put("tags", JSONArray().apply { put("Android") })
            put("malware", "SomeBot")
        }
        assertTrue(feed.isAndroidRelated(entry))
    }

    @Test
    fun `isAndroidRelated returns true for apk in malware field`() {
        val entry = JSONObject().apply {
            put("tags", JSONArray())
            put("malware", "MalAPK Dropper")
        }
        assertTrue(feed.isAndroidRelated(entry))
    }

    @Test
    fun `isAndroidRelated returns true for android in malware field`() {
        val entry = JSONObject().apply {
            put("tags", JSONArray())
            put("malware", "Android.Joker")
        }
        assertTrue(feed.isAndroidRelated(entry))
    }

    @Test
    fun `isAndroidRelated returns false for unrelated entry`() {
        val entry = JSONObject().apply {
            put("tags", JSONArray().apply { put("windows") })
            put("malware", "Emotet")
        }
        assertFalse(feed.isAndroidRelated(entry))
    }

    // ── stripProtocol ────────────────────────────────────────────────────────

    @Test
    fun `stripProtocol removes http prefix`() {
        assertEquals("example.com", feed.stripProtocol("http://example.com"))
    }

    @Test
    fun `stripProtocol removes https prefix`() {
        assertEquals("example.com", feed.stripProtocol("https://example.com"))
    }

    @Test
    fun `stripProtocol removes trailing path`() {
        assertEquals("example.com", feed.stripProtocol("http://example.com/path/to/page"))
    }

    @Test
    fun `stripProtocol removes port`() {
        assertEquals("example.com", feed.stripProtocol("example.com:8080"))
    }

    @Test
    fun `stripProtocol handles bare domain`() {
        assertEquals("example.com", feed.stripProtocol("example.com"))
    }
}
