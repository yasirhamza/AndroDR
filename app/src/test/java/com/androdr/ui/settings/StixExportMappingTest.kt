package com.androdr.ui.settings

import com.androdr.data.model.ForensicTimelineEvent
import org.junit.Assert.assertEquals
import org.junit.Test

class StixExportMappingTest {
    private fun event(campaign: String = "", app: String = "", desc: String = "d") = ForensicTimelineEvent(
        startTimestamp = 7L, source = "s", category = "c", description = desc, appName = app, campaignName = campaign,
    )

    @Test
    fun `family comes from campaignName and category stays empty`() {
        val i = event(campaign = "Pegasus", app = "App").toExportIndicator("domain", "x.com")
        assertEquals("Pegasus", i.family)
        assertEquals("", i.category)
        assertEquals("androdr_scan", i.source)
        assertEquals(7L, i.fetchedAt)
    }

    @Test
    fun `family falls back to appName then description`() {
        assertEquals("App", event(app = "App").toExportIndicator("package", "p").family)
        assertEquals("desc", event(desc = "desc").toExportIndicator("package", "p").family)
    }
}
