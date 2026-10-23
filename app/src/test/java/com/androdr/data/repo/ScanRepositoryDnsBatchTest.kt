package com.androdr.data.repo

import com.androdr.data.db.ForensicTimelineEventDao
import com.androdr.data.model.DnsEvent
import com.androdr.data.model.ForensicTimelineEvent
import com.androdr.data.model.Indicator
import com.androdr.ioc.IndicatorResolver
import io.mockk.coEvery
import io.mockk.mockk
import io.mockk.slot
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Test

/**
 * Review focus 2: a domain caught by the bundled blocklist (reason `blocklist`)
 * still names its family on the timeline row; the lookup is by the queried
 * domain, not by the reason string.
 */
class ScanRepositoryDnsBatchTest {
    private val timelineDao = mockk<ForensicTimelineEventDao>(relaxed = true)
    private val resolver = mockk<IndicatorResolver>()
    private val repo = ScanRepository(
        scanResultDao = mockk(relaxed = true),
        dnsEventDao = mockk(relaxed = true),
        forensicTimelineEventDao = timelineDao,
        indicatorResolver = resolver,
        scanWrites = mockk(relaxed = true),
        scanLock = ScanLock(),
    )
    private val graphite = Indicator("domain", "forti.external-muki.com", family = "Graphite (Paragon)",
        source = "androdr_public_repo", fetchedAt = 0L)

    private suspend fun storedCampaign(reason: String): String {
        val rows = slot<List<ForensicTimelineEvent>>()
        coEvery { timelineDao.insertAll(capture(rows)) } returns listOf(1L)
        repo.logDnsEventsBatch(listOf(DnsEvent(timestamp = 1L, domain = "forti.external-muki.com",
            appUid = 1, appName = null, isBlocked = true, reason = reason)))
        return rows.captured.single().campaignName
    }

    @Test
    fun `blocklist hit names the family`() = runTest {
        coEvery { resolver.resolveDomainRow("forti.external-muki.com") } returns graphite
        assertEquals("Graphite (Paragon)", storedCampaign("blocklist"))
    }

    @Test
    fun `IOC hit names the family`() = runTest {
        coEvery { resolver.resolveDomainRow("forti.external-muki.com") } returns graphite
        assertEquals("Graphite (Paragon)", storedCampaign("IOC_detect: x"))
    }

    @Test
    fun `no row leaves the campaign empty`() = runTest {
        coEvery { resolver.resolveDomainRow(any()) } returns null
        assertEquals("", storedCampaign("blocklist"))
    }
}
