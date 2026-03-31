package com.androdr.ioc

import com.androdr.data.db.IndicatorDao
import com.androdr.data.model.Indicator
import io.mockk.coEvery
import io.mockk.coVerify
import io.mockk.mockk
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Test

class IocUpdateWorkerTest {

    private val dao: IndicatorDao = mockk(relaxed = true)
    private val resolver: IndicatorResolver = mockk(relaxed = true)

    @Test
    fun `IndicatorUpdater converts and upserts from all feed types`() = runTest {
        val domainFeed = mockk<DomainIocFeed>()
        val certFeed = mockk<CertHashIocFeed>()
        coEvery { domainFeed.sourceId } returns "test_domain"
        coEvery { certFeed.sourceId } returns "test_cert"
        coEvery { domainFeed.fetch() } returns listOf(
            com.androdr.data.model.DomainIocEntry("evil.com", "Pegasus", "CRITICAL", "test", 1000L)
        )
        coEvery { certFeed.fetch() } returns listOf(
            com.androdr.data.model.CertHashIocEntry("abc123", "Trojan", "MALWARE", "HIGH", "desc", "test", 1000L)
        )
        coEvery { dao.count() } returns 2

        val updater = IndicatorUpdater(dao, resolver, listOf(domainFeed), listOf(certFeed), emptyList())
        val total = updater.update()

        assertEquals(2, total)
        coVerify { dao.upsertAll(match { indicators ->
            indicators.any { it.type == "domain" && it.value == "evil.com" }
        }) }
        coVerify { dao.upsertAll(match { indicators ->
            indicators.any { it.type == "cert_hash" && it.value == "abc123" }
        }) }
        coVerify { resolver.refreshCache() }
    }
}
