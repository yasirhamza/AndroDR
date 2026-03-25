package com.androdr.ioc

import com.androdr.data.model.KnownAppCategory
import com.androdr.ioc.feeds.PlexusKnownAppFeed
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class PlexusKnownAppFeedTest {

    private val feed = PlexusKnownAppFeed()

    @Test
    fun `single page is parsed correctly`() {
        val json = """
            {
              "data": [
                {"name": "WhatsApp", "package": "com.whatsapp"},
                {"name": "Signal",   "package": "org.thoughtcrime.securesms"}
              ],
              "meta": {"current_page": 1, "total_pages": 1, "per_page": 500, "total_apps": 2}
            }
        """.trimIndent()
        val (entries, meta) = feed.parsePlexusPage(json)!!
        assertEquals(2, entries.size)
        assertEquals("com.whatsapp", entries[0].packageName)
        assertEquals("WhatsApp", entries[0].displayName)
        assertEquals(KnownAppCategory.USER_APP, entries[0].category)
        assertEquals("plexus", entries[0].sourceId)
        assertEquals(1, meta.currentPage)
        assertEquals(1, meta.totalPages)
    }

    @Test
    fun `empty data array returns no entries`() {
        val json = """
            {"data": [], "meta": {"current_page": 1, "total_pages": 1, "per_page": 500, "total_apps": 0}}
        """.trimIndent()
        val (entries, _) = feed.parsePlexusPage(json)!!
        assertTrue(entries.isEmpty())
    }

    @Test
    fun `multi-page meta is parsed correctly`() {
        val json = """
            {"data": [], "meta": {"current_page": 3, "total_pages": 19, "per_page": 500, "total_apps": 9333}}
        """.trimIndent()
        val (_, meta) = feed.parsePlexusPage(json)!!
        assertEquals(3, meta.currentPage)
        assertEquals(19, meta.totalPages)
    }

    @Test
    fun `malformed JSON returns null`() {
        val result = feed.parsePlexusPage("not-json")
        assertTrue(result == null)
    }

    @Test
    fun `morePages is false when currentPage equals totalPages`() {
        val json = """
            {"data": [], "meta": {"current_page": 1, "total_pages": 1, "per_page": 500, "total_apps": 1}}
        """.trimIndent()
        val (_, meta) = feed.parsePlexusPage(json)!!
        assertTrue(meta.currentPage >= meta.totalPages)
    }

    @Test
    fun `morePages is true when currentPage is less than totalPages`() {
        val json = """
            {"data": [], "meta": {"current_page": 1, "total_pages": 2, "per_page": 500, "total_apps": 600}}
        """.trimIndent()
        val (_, meta) = feed.parsePlexusPage(json)!!
        assertTrue(meta.currentPage < meta.totalPages)
    }
}
