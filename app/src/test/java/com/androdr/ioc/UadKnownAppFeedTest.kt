package com.androdr.ioc

import com.androdr.data.model.KnownAppCategory
import com.androdr.ioc.feeds.UadKnownAppFeed
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class UadKnownAppFeedTest {

    private val feed = UadKnownAppFeed()

    // UAD-ng upstream emits title-case list values ("Oem", "Aosp", "Carrier", "Misc", "Google").
    // See: https://raw.githubusercontent.com/Universal-Debloater-Alliance/universal-android-debloater-next-generation/main/resources/assets/uad_lists.json

    @Test
    fun `Oem entry maps to OEM category`() {
        val json = """{"com.samsung.clock":{"list":"Oem","description":"Samsung Clock"}}"""
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
        val json = """{"com.facebook.katana":{"list":"Misc","description":"Facebook"}}"""
        val results = feed.parseUadJson(json)
        assertEquals(KnownAppCategory.OEM, results[0].category)
    }

    @Test
    fun `Aosp entry maps to AOSP category`() {
        val json = """{"com.android.settings":{"list":"Aosp","description":"Settings"}}"""
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
    fun `Netflix preload in Misc list classifies as OEM not USER_APP`() {
        val json = """{"com.netflix.mediaclient":{"list":"Misc","description":"Netflix"}}"""
        val results = feed.parseUadJson(json)
        assertEquals(1, results.size)
        assertEquals(KnownAppCategory.OEM, results[0].category)
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
