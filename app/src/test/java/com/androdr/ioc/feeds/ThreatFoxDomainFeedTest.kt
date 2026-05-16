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

    // ── Issue #174: live ThreatFox schema (numeric-id-keyed dict + ioc_value
    //                + tags-as-string) ────────────────────────────────────────

    /**
     * Captured shape of the live `/export/json/recent/` endpoint as of
     * 2026-05-15. Differences from the legacy `sampleJson` above:
     *   - Top-level is a flat dict keyed by numeric ID strings (no `data` wrapper).
     *   - IOC value field is `ioc_value`, not `ioc`.
     *   - `tags` is a comma-separated string, not a JSON array.
     */
    private val liveSchemaJson = """
        {
          "1814938": [
            {
              "ioc_value": "evil-android.example.com",
              "ioc_type": "domain",
              "threat_type": "botnet_cc",
              "malware": "Anatsa",
              "tags": "15May2026,Android,Banking"
            }
          ],
          "1814937": [
            {
              "ioc_value": "desktop-only.example.com",
              "ioc_type": "domain",
              "threat_type": "payload_delivery",
              "malware": "Emotet",
              "tags": "Windows,Commandline"
            }
          ],
          "1814936": [
            {
              "ioc_value": "http://apk-malware.example.com/dl",
              "ioc_type": "domain",
              "threat_type": "payload_delivery",
              "malware": "MalAPK Dropper",
              "tags": ""
            }
          ],
          "1814935": [
            {
              "ioc_value": "url-not-domain.example.com",
              "ioc_type": "url",
              "threat_type": "payload_delivery",
              "malware": "Android.Joker",
              "tags": "Android"
            }
          ]
        }
    """.trimIndent()

    @Test
    fun `parseRecentJson parses live schema (numeric-id keys + ioc_value + tags-as-string)`() {
        val entries = feed.parseRecentJson(liveSchemaJson, 1000L)
        // Should include: evil-android.example.com (tags string contains "Android"),
        //                 apk-malware.example.com (malware contains "apk").
        // Should exclude: desktop-only.example.com (no android signals),
        //                 url-not-domain.example.com (ioc_type=url, not domain).
        val domains = entries.map { it.domain }.toSet()
        assertEquals(2, entries.size)
        assertTrue(domains.contains("evil-android.example.com"))
        assertTrue(domains.contains("apk-malware.example.com"))
    }

    @Test
    fun `parseRecentJson preserves backward-compat with legacy data-wrapper schema`() {
        // The existing sampleJson uses the legacy { data: { date: [...] } }
        // shape. A parser that only handled the live schema would regress this
        // test; we keep both paths working in case abuse.ch reverts.
        val entries = feed.parseRecentJson(sampleJson, 0L)
        assertEquals(2, entries.size)
    }

    @Test
    fun `isAndroidRelated returns true for tags-as-string with Android substring`() {
        val entry = JSONObject().apply {
            put("tags", "15May2026,Android,Banking")
            put("malware", "Anatsa")
        }
        assertTrue(feed.isAndroidRelated(entry))
    }

    @Test
    fun `isAndroidRelated returns true for tags-as-string lowercase android`() {
        val entry = JSONObject().apply {
            put("tags", "banking,android")
            put("malware", "Anatsa")
        }
        assertTrue(feed.isAndroidRelated(entry))
    }

    @Test
    fun `isAndroidRelated returns false for tags-as-string without android signals`() {
        val entry = JSONObject().apply {
            put("tags", "Windows,Commandline,15May2026")
            put("malware", "Emotet")
        }
        assertFalse(feed.isAndroidRelated(entry))
    }

    @Test
    fun `isAndroidRelated handles missing tags field`() {
        val entry = JSONObject().apply {
            put("malware", "SomeBot")
        }
        assertFalse(feed.isAndroidRelated(entry))
    }

    // ── Issue #174: schema-shape conformance against captured live data ─────

    /**
     * Anonymised subset of the live `/export/json/recent/` response captured
     * 2026-05-15. Carries the full live field set (`malware_printable`,
     * `first_seen_utc`, `confidence_level`, `is_compromised`, `reporter`,
     * `anonymous`, etc.) so a parser regression that fails on any unexpected
     * field would surface here. None of these records are Android-tagged —
     * representative of the production reality where ThreatFox's recent
     * window is dominated by Windows malware — so the assertion is
     * "parse succeeds, schema understood, 0 Android matches", which is
     * exactly what we want to defend against a future silent-zero break.
     */
    private val capturedLiveResponse = """
        {
          "1814938": [
            {
              "ioc_value": "henrydegenhart.example.com",
              "ioc_type": "domain",
              "threat_type": "botnet_cc",
              "malware": "win.remus",
              "malware_alias": null,
              "malware_printable": "Remus",
              "first_seen_utc": "2026-05-15 14:34:52",
              "last_seen_utc": null,
              "confidence_level": 100,
              "is_compromised": false,
              "reference": "",
              "tags": "RemusStealer",
              "anonymous": "0",
              "reporter": "abuse_ch"
            }
          ],
          "1814937": [
            {
              "ioc_value": "virtual-pipeline.example.courses",
              "ioc_type": "domain",
              "threat_type": "payload_delivery",
              "malware": "js.clearfake",
              "malware_alias": null,
              "malware_printable": "ClearFake",
              "first_seen_utc": "2026-05-15 14:22:50",
              "last_seen_utc": "2026-05-15 14:23:30",
              "confidence_level": 100,
              "is_compromised": false,
              "reference": null,
              "tags": "15May2026,ClearFake,Commandline,Windows",
              "anonymous": "0",
              "reporter": "Gi7w0rm"
            }
          ],
          "1814926": [
            {
              "ioc_value": "de0e25a3e6c1e1e5998b306b7141b3dc4c0088da9d7bb47c1c00c91e6e4f85d6",
              "ioc_type": "sha256_hash",
              "threat_type": "payload",
              "malware": "js.shai_hulud",
              "tags": "js,shai-hulud,worm"
            }
          ]
        }
    """.trimIndent()

    @Test
    fun `parseRecentJson handles full live field set without error (zero Android matches)`() {
        // Regression guard against the #174 failure mode: parser must complete
        // cleanly on a real-shape response even when no entries match. A return
        // of 0 here is correct; a thrown exception or a positive count would
        // indicate either a parser break or a false-positive Android filter.
        val entries = feed.parseRecentJson(capturedLiveResponse, 0L)
        assertEquals(0, entries.size)
    }

    @Test
    fun `parseRecentJson returns empty list when schema is unrecognized (list at root)`() {
        // Defense against silent-zero on malformed response. A JSON list at
        // root or `data` as a string falls into neither schema; the parser
        // logs a warning and returns empty rather than emitting 0 silently.
        val listAtRoot = """[{"foo": "bar"}]"""
        assertTrue(feed.parseRecentJson(listAtRoot, 0L).isEmpty())

        val dataAsString = """{"query_status": "ok", "data": "unexpected"}"""
        assertTrue(feed.parseRecentJson(dataAsString, 0L).isEmpty())
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
