package com.androdr.ioc

import com.androdr.data.model.KnownAppCategory
import com.androdr.ioc.feeds.UadKnownAppFeed
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class UadKnownAppFeedTest {

    private val feed = UadKnownAppFeed()

    @Test
    fun `OEM entry maps to OEM category`() {
        val json = """{"com.samsung.clock":{"list":"OEM","description":"Samsung Clock"}}"""
        val results = feed.parseUadJson(json)
        assertEquals(1, results.size)
        assertEquals("com.samsung.clock", results[0].packageName)
        assertEquals("Samsung Clock", results[0].displayName)
        assertEquals(KnownAppCategory.OEM, results[0].category)
        assertEquals("uad_ng", results[0].sourceId)
    }

    @Test
    fun `Carrier entry maps to OEM category`() {
        val json = """{"com.att.service":{"list":"Carrier","description":"AT&T Service"}}"""
        val results = feed.parseUadJson(json)
        assertEquals(KnownAppCategory.OEM, results[0].category)
    }

    @Test
    fun `Misc entry maps to OEM category`() {
        val json = """{"com.example.misc":{"list":"Misc","description":"Misc App"}}"""
        val results = feed.parseUadJson(json)
        assertEquals(KnownAppCategory.OEM, results[0].category)
    }

    @Test
    fun `AOSP entry maps to AOSP category`() {
        val json = """{"com.android.settings":{"list":"AOSP","description":"Settings"}}"""
        val results = feed.parseUadJson(json)
        assertEquals(KnownAppCategory.AOSP, results[0].category)
    }

    @Test
    fun `Google entry maps to GOOGLE category`() {
        val json = """{"com.google.android.gms":{"list":"Google","description":"Play Services"}}"""
        val results = feed.parseUadJson(json)
        assertEquals(KnownAppCategory.GOOGLE, results[0].category)
    }

    @Test
    fun `empty JSON object returns empty list`() {
        val results = feed.parseUadJson("{}")
        assertTrue(results.isEmpty())
    }

    @Test
    fun `malformed JSON returns empty list`() {
        val results = feed.parseUadJson("not-json")
        assertTrue(results.isEmpty())
    }

    @Test
    fun `unknown list value is skipped`() {
        val json = """{"com.example.unknown":{"list":"UNKNOWN","description":"Unknown"}}"""
        val results = feed.parseUadJson(json)
        assertTrue(results.isEmpty())
    }
}
