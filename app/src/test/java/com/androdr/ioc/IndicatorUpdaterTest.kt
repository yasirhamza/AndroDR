package com.androdr.ioc

import com.androdr.data.db.IndicatorDao
import com.androdr.data.model.Indicator
import com.androdr.data.model.CertHashIocEntry
import com.androdr.data.model.DomainIocEntry
import com.androdr.data.model.IocEntry
import com.androdr.ioc.feeds.HaGeZiTifFeed
import com.androdr.ioc.feeds.StalkerwareCertHashFeed
import com.androdr.ioc.feeds.MalwareBazaarCertFeed
import io.mockk.coEvery
import io.mockk.coVerify
import io.mockk.mockk
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class IndicatorUpdaterTest {

    private val dao: IndicatorDao = mockk(relaxed = true)
    private val resolver: IndicatorResolver = mockk(relaxed = true)

    private fun packageFeed(id: String, count: Int): IocFeed = object : IocFeed {
        override val sourceId: String = id
        override suspend fun fetch(): List<IocEntry> = (0 until count).map {
            IocEntry(
                packageName = "com.pkg$it",
                name = "n", category = "c", severity = "LOW",
                description = "d", source = id, fetchedAt = 1_000L + it,
            )
        }
    }

    @Test
    fun `large feed is upserted in bounded chunks rather than one transaction`() = runBlocking {
        val total = IndicatorUpdater.UPSERT_CHUNK_SIZE * 2 + 37
        val sizes = mutableListOf<Int>()
        coEvery { dao.upsertAll(any()) } answers {
            sizes += firstArg<List<Indicator>>().size
        }

        val updater = IndicatorUpdater(
            dao = dao,
            resolver = resolver,
            domainFeeds = emptyList(),
            certHashFeeds = emptyList(),
            packageFeeds = listOf(packageFeed("test_feed", total)),
        )

        val returned = updater.update()

        assertEquals("update() should report the full fetched count", total, returned)
        // No single transaction may exceed the chunk cap.
        assertTrue(
            "no chunk may exceed UPSERT_CHUNK_SIZE; saw $sizes",
            sizes.all { it <= IndicatorUpdater.UPSERT_CHUNK_SIZE },
        )
        // All rows must still be written exactly once in aggregate.
        assertEquals(total, sizes.sum())
        // It must actually be split into multiple transactions (regression guard
        // against reverting to one giant upsert). Derive the expected count from
        // the chunk size rather than hard-coding it, so the assertion tracks
        // UPSERT_CHUNK_SIZE instead of breaking when it is retuned.
        val expectedChunks =
            (total + IndicatorUpdater.UPSERT_CHUNK_SIZE - 1) / IndicatorUpdater.UPSERT_CHUNK_SIZE
        assertTrue("bulk feed must be split across transactions", sizes.size > 1)
        assertEquals(expectedChunks, sizes.size)
    }

    @Test
    fun `empty feed performs no upsert`() = runBlocking {
        val updater = IndicatorUpdater(
            dao = dao,
            resolver = resolver,
            domainFeeds = emptyList(),
            certHashFeeds = emptyList(),
            packageFeeds = listOf(packageFeed("empty_feed", 0)),
        )

        updater.update()

        coVerify(exactly = 0) { dao.upsertAll(any()) }
    }

    // ── Write precedence and eviction (spec R14/R18), with a real in-memory DAO ──

    private val mvtPegasus = "mvt_nso_group_pegasus_indicators_of_compromise"
    private val mvtPredator = "mvt_predator_spyware_indicators_of_compromise"
    private val hagezi = HaGeZiTifFeed.SOURCE_ID

    private class DomainFeedFake(override val sourceId: String) : DomainIocFeed {
        var rows: List<DomainIocEntry> = emptyList()
        override suspend fun fetch() = rows
    }

    private class CertFeedFake(override val sourceId: String) : CertHashIocFeed {
        var rows: List<CertHashIocEntry> = emptyList()
        override suspend fun fetch() = rows
    }

    private fun d(domain: String, family: String, source: String, at: Long) =
        DomainIocEntry(domain, family, "HIGH", source, at)

    private fun updater(fake: FakeIndicatorDao, domains: List<DomainIocFeed> = emptyList(),
                        certs: List<CertHashIocFeed> = emptyList()) =
        IndicatorUpdater(fake, resolver, domains, certs, emptyList())

    @Test
    fun `two consecutive syncs of an unchanged feed leave the row count unchanged`() = runBlocking {
        val fake = FakeIndicatorDao()
        val feed = DomainFeedFake(hagezi)
        val u = updater(fake, listOf(feed))
        feed.rows = listOf(d("a.com", "HaGeZi", hagezi, 100), d("b.com", "HaGeZi", hagezi, 100))
        u.update()
        feed.rows = listOf(d("a.com", "HaGeZi", hagezi, 200), d("b.com", "HaGeZi", hagezi, 200))
        u.update()
        assertEquals(2, fake.count())
    }

    @Test
    fun `MVT family wins over HaGeZi regardless of fetch order`() = runBlocking {
        val fake = FakeIndicatorDao()
        val mvt = DomainFeedFake("mvt_indicators")
        val hz = DomainFeedFake(hagezi)
        mvt.rows = listOf(d("evil.com", "Pegasus", mvtPegasus, 100))
        hz.rows = listOf(d("evil.com", "HaGeZi", hagezi, 100))
        for (order in listOf(listOf(mvt, hz), listOf(hz, mvt))) {
            val f = FakeIndicatorDao()
            updater(f, order).update()
            assertEquals("Pegasus", f.lookup("domain", "evil.com")!!.family)
            assertEquals(mvtPegasus, f.lookup("domain", "evil.com")!!.source)
        }
    }

    @Test
    fun `partial failure - MVT empty on sync 2 keeps the MVT row`() = runBlocking {
        val fake = FakeIndicatorDao()
        val mvt = DomainFeedFake("mvt_indicators")
        val hz = DomainFeedFake(hagezi)
        val u = updater(fake, listOf(mvt, hz))
        mvt.rows = listOf(d("evil.com", "Pegasus", mvtPegasus, 100))
        hz.rows = listOf(d("evil.com", "HaGeZi", hagezi, 100))
        u.update()
        mvt.rows = emptyList()
        hz.rows = listOf(d("evil.com", "HaGeZi", hagezi, 200))
        u.update()
        assertEquals("Pegasus", fake.lookup("domain", "evil.com")!!.family)
    }

    @Test
    fun `one MVT collection failing keeps its rows, a dropped domain of a live collection is evicted`() = runBlocking {
        val fake = FakeIndicatorDao()
        val mvt = DomainFeedFake("mvt_indicators")
        val u = updater(fake, listOf(mvt))
        mvt.rows = listOf(
            d("peg.com", "Pegasus", mvtPegasus, 100),
            d("pred1.com", "Predator", mvtPredator, 100),
            d("pred2.com", "Predator", mvtPredator, 100),
        )
        u.update()
        mvt.rows = listOf(d("pred1.com", "Predator", mvtPredator, 200)) // Pegasus download failed
        u.update()
        assertEquals("Pegasus rows survive", "Pegasus", fake.lookup("domain", "peg.com")?.family)
        assertEquals("kept Predator row", "Predator", fake.lookup("domain", "pred1.com")?.family)
        assertNull("dropped from a live collection", fake.lookup("domain", "pred2.com"))
    }

    @Test
    fun `a cert in both cert feeds ends with the stalkerware attribution`() = runBlocking {
        val fake = FakeIndicatorDao()
        val mb = CertFeedFake(MalwareBazaarCertFeed.SOURCE_ID)
        val sw = CertFeedFake(StalkerwareCertHashFeed.SOURCE_ID)
        mb.rows = listOf(CertHashIocEntry("abc", "MBFam", "MALWARE", "HIGH", "", mb.sourceId, 100))
        sw.rows = listOf(CertHashIocEntry("abc", "SWFam", "STALKERWARE", "HIGH", "", sw.sourceId, 100))
        for (order in listOf(listOf(mb, sw), listOf(sw, mb))) {
            val f = FakeIndicatorDao()
            updater(f, certs = order).update()
            assertEquals("SWFam", f.lookup("cert_hash", "abc")!!.family)
        }
    }

    @Test
    fun `accepted gap - rules repo drops a value MVT also lists, MVT restores it next cycle`() = runBlocking {
        val fake = FakeIndicatorDao()
        val mvt = DomainFeedFake("mvt_indicators")
        val u = updater(fake, listOf(mvt))
        mvt.rows = listOf(d("evil.com", "Pegasus", mvtPegasus, 100))
        // Rules repo owns the value (rank 100 > MVT).
        fake.upsertAll(listOf(Indicator(type = "domain", value = "evil.com", family = "RulesFam",
            source = SourceRank.RULES_REPO, fetchedAt = 50)))
        u.update() // MVT row filtered as owned
        assertEquals(SourceRank.RULES_REPO, fake.lookup("domain", "evil.com")!!.source)
        // Rules repo evicts the value (its verified fetch no longer lists it).
        fake.deleteStaleEntriesOfType(SourceRank.RULES_REPO, "domain", 1_000)
        assertNull(fake.lookup("domain", "evil.com"))
        mvt.rows = listOf(d("evil.com", "Pegasus", mvtPegasus, 300))
        u.update()
        assertEquals("Pegasus", fake.lookup("domain", "evil.com")!!.family)
    }

    @Test
    fun `DomainIocEntry toIndicator carries the campaign key`() {
        val ind = DomainIocEntry("evil.com", "Pegasus", "CRITICAL", mvtPegasus, 100, campaignKey = "pegasus")
            .toIndicator()
        assertEquals("pegasus", ind.campaignKey)
    }

    @Test
    fun `campaign key survives the MVT entry to indicator write`() = runBlocking {
        val fake = FakeIndicatorDao()
        val mvt = DomainFeedFake("mvt_indicators")
        mvt.rows = listOf(DomainIocEntry("evil.com", "Pegasus", "CRITICAL", mvtPegasus, 100, campaignKey = "pegasus"))
        updater(fake, listOf(mvt)).update()
        assertEquals("pegasus", fake.lookup("domain", "evil.com")!!.campaignKey)
    }
}
