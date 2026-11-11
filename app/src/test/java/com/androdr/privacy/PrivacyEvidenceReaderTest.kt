package com.androdr.privacy

import com.androdr.data.db.AppDatabase
import com.androdr.data.db.RoomTestDb
import com.androdr.data.model.DnsEvent
import com.androdr.data.model.NetworkStatus
import com.androdr.data.model.PrivacyAppResult
import com.androdr.data.model.PrivacyCodeDetail
import com.androdr.data.model.PrivacyDomainDetail
import com.androdr.data.model.PrivacyScan
import com.androdr.data.model.PrivacyTrackerEvidence
import com.androdr.privacy.model.SignatureKind
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner

@RunWith(RobolectricTestRunner::class)
class PrivacyEvidenceReaderTest {
    private lateinit var db: AppDatabase
    private lateinit var reader: PrivacyEvidenceReader

    @Before fun setUp() {
        db = RoomTestDb.inMemory()
        reader = PrivacyEvidenceReader(db.privacyDao(), db.dnsEventDao())
    }

    @After fun tearDown() { db.close() }

    private fun seedScan(hasDetails: Boolean = true): Long = runBlocking {
        val dao = db.privacyDao()
        val id = dao.insertScan(
            PrivacyScan(
                startedAt = 1, finishedAt = 2, appsTotal = 1, appsInspected = 1, appsPartial = 0, appsFailed = 0,
                registrySize = 428, registrySha256 = "abc", dnsWindowStart = 0, dnsCoverageDays = 3,
                usageCoverageFrom = null, networkStatus = NetworkStatus.COMPLETE.name, hasDetails = hasDetails,
            ),
        )
        dao.upsertResults(listOf(PrivacyAppResult(id, "com.x", 7, "X", false, "INSPECTED", null)))
        dao.upsertEvidence(
            listOf(
                PrivacyTrackerEvidence(id, "com.x", 12, "Flurry", "https://flurry.com", "Analytics", true, 4, 2,
                    null, 5, 9, false),
            ),
        )
        id
    }

    private fun dns(app: String, domain: String, ts: Long) =
        DnsEvent(timestamp = ts, domain = domain, appUid = 10_100, appName = app, isBlocked = false, reason = null)

    @Test fun `details are loaded for the latest completed scan`() = runBlocking {
        val id = seedScan()
        db.privacyDao().upsertCodeDetail(
            listOf(
                PrivacyCodeDetail(id, "com.x", 12, "CODE_PREFIX", "com.flurry", 260, "com.flurry.a\ncom.flurry.b"),
                PrivacyCodeDetail(id, "com.x", 12, "SOMETHING_NEW", "?", 1, "q"),
            ),
        )
        db.privacyDao().upsertDomainDetail(
            listOf(
                PrivacyDomainDetail(id, "com.x", 12, "a.flurry.com", "DOMAIN_SUFFIX", "flurry.com", 1, 1, null, 5, 5),
                PrivacyDomainDetail(id, "com.x", 12, "b.flurry.com", "DOMAIN_SUFFIX", "flurry.com", 3, 2, 1, 6, 9),
            ),
        )
        val d = requireNotNull(reader.load("com.x", 12))
        assertEquals(id, d.scan.id)
        assertEquals("X", d.app.appLabel)
        assertEquals("Flurry", d.evidence.trackerName)
        assertEquals(
            listOf(CodeSignature(SignatureKind.CODE_PREFIX, "com.flurry", listOf("com.flurry.a", "com.flurry.b"), 260)),
            d.code,
        )
        assertEquals(listOf("b.flurry.com", "a.flurry.com"), d.domains.map { it.domain })
        assertEquals(DomainLine("b.flurry.com", SignatureKind.DOMAIN_SUFFIX, "flurry.com", 3, 2, 1, 6, 9), d.domains[0])
        assertNull(d.domains[1].background)
    }

    @Test fun `nothing is loaded when the app and tracker are not in the latest scan`() = runBlocking {
        seedScan()
        assertNull(reader.load("com.x", 99))
        assertNull(reader.load("com.y", 12))
    }

    @Test fun `nothing is loaded when there is no completed scan`() = runBlocking {
        assertNull(reader.load("com.x", 12))
    }

    @Test fun `a result from before details were recorded loads with no detail`() = runBlocking {
        seedScan(hasDetails = false)
        val d = requireNotNull(reader.load("com.x", 12))
        assertFalse(d.scan.hasDetails)
        assertTrue(d.code.isEmpty())
        assertTrue(d.domains.isEmpty())
    }

    @Test fun `recent lookups are the newest 50, newest first`() = runBlocking {
        db.dnsEventDao().insertAll(List(60) { dns("com.x", "a.flurry.com", 1_000L + it) })
        val times = reader.recentLookups("com.x", "a.flurry.com")
        assertEquals(PrivacyEvidenceReader.MAX_RECENT_LOOKUPS, times.size)
        assertEquals((1_059L downTo 1_010L).toList(), times)
    }

    @Test fun `recent lookups are read by the recorded spelling`() = runBlocking {
        db.dnsEventDao().insertAll(
            listOf(
                dns("com.x", "T.AppsFlyer.com.", 5), dns("com.x", "t.appsflyer.com", 6),
                dns("com.x", "T.AppsFlyer.com.", 7),
            ),
        )
        assertEquals(listOf(7L, 5L), reader.recentLookups("com.x", "T.AppsFlyer.com."))
    }

    @Test fun `recent lookups of another app are not returned`() = runBlocking {
        db.dnsEventDao().insertAll(listOf(dns("com.other", "a.flurry.com", 5)))
        assertEquals(emptyList<Long>(), reader.recentLookups("com.x", "a.flurry.com"))
    }
}
