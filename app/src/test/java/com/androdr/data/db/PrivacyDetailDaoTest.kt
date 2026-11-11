package com.androdr.data.db

import com.androdr.data.model.NetworkStatus
import com.androdr.data.model.PrivacyAppResult
import com.androdr.data.model.PrivacyCodeDetail
import com.androdr.data.model.PrivacyDomainDetail
import com.androdr.data.model.PrivacyScan
import com.androdr.data.model.PrivacyTrackerEvidence
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

/** The schema-23 detail tables: read per app + tracker, deleted with their scan and by "Delete privacy results". */
@RunWith(RobolectricTestRunner::class)
class PrivacyDetailDaoTest {
    private lateinit var db: AppDatabase
    private lateinit var dao: PrivacyDao

    @Before fun setUp() {
        db = RoomTestDb.inMemory()
        dao = db.privacyDao()
    }

    @After fun tearDown() { db.close() }

    private fun scan(hasDetails: Boolean = false) = PrivacyScan(
        startedAt = 1, finishedAt = 2, appsTotal = 1, appsInspected = 1, appsPartial = 0,
        appsFailed = 0, registrySize = 5, registrySha256 = "abc", dnsWindowStart = 0,
        dnsCoverageDays = 0, usageCoverageFrom = null, networkStatus = NetworkStatus.COMPLETE.name,
        hasDetails = hasDetails,
    )

    private fun code(scanId: Long, pkg: String, tracker: Int, signature: String) =
        PrivacyCodeDetail(scanId, pkg, tracker, "CODE_PREFIX", signature, 1, "$signature.x")

    private fun domain(scanId: Long, pkg: String, tracker: Int, domain: String, lookups: Int) =
        PrivacyDomainDetail(scanId, pkg, tracker, domain, "DOMAIN_SUFFIX", "flurry.com", lookups, 1, null, 10, 20)

    private fun count(table: String): Int =
        db.query("SELECT COUNT(*) FROM $table", null).use { it.moveToFirst(); it.getInt(0) }

    private suspend fun seed(scanId: Long) {
        dao.upsertCodeDetail(
            listOf(code(scanId, "a", 1, "com.z"), code(scanId, "a", 1, "com.y"), code(scanId, "a", 2, "com.q"),
                code(scanId, "b", 1, "com.y")),
        )
        dao.upsertDomainDetail(
            listOf(domain(scanId, "a", 1, "x.flurry.com", 3), domain(scanId, "a", 1, "y.flurry.com", 9),
                domain(scanId, "a", 2, "x.flurry.com", 3), domain(scanId, "b", 1, "x.flurry.com", 1)),
        )
    }

    @Test fun `detail is read for one app and tracker only`() = runBlocking {
        val id = dao.insertScan(scan())
        seed(id)
        assertEquals(listOf("com.y", "com.z"), dao.codeDetail(id, "a", 1).map { it.signature })
        assertEquals(listOf("y.flurry.com", "x.flurry.com"), dao.domainDetail(id, "a", 1).map { it.domain })
        assertEquals(listOf("com.q"), dao.codeDetail(id, "a", 2).map { it.signature })
        assertEquals(1, dao.domainDetail(id, "b", 1).size)
    }

    @Test fun `one result and one evidence row are read by key`() = runBlocking {
        val id = dao.insertScan(scan())
        dao.upsertResults(listOf(PrivacyAppResult(id, "a", 1, "A", false, "INSPECTED", null)))
        dao.upsertEvidence(
            listOf(PrivacyTrackerEvidence(id, "a", 1, "T", "w", "Ads", true, 0, 0, null, null, null, false)),
        )
        assertEquals("A", dao.resultFor(id, "a")?.appLabel)
        assertNull(dao.resultFor(id, "b"))
        assertEquals("T", dao.evidenceFor(id, "a", 1)?.trackerName)
        assertNull(dao.evidenceFor(id, "a", 2))
    }

    @Test fun `deleting scans before an id deletes their detail`() = runBlocking {
        val old = dao.insertScan(scan())
        val new = dao.insertScan(scan())
        seed(old)
        seed(new)
        dao.deleteScansBefore(new)
        assertEquals(4, count("privacy_code_detail"))
        assertEquals(4, count("privacy_domain_detail"))
        assertTrue(dao.codeDetail(old, "a", 1).isEmpty())
        assertTrue(dao.domainDetail(old, "a", 1).isEmpty())
    }

    @Test fun `deleting everything deletes the detail`() = runBlocking {
        seed(dao.insertScan(scan()))
        dao.deleteAll()
        assertEquals(0, count("privacy_code_detail"))
        assertEquals(0, count("privacy_domain_detail"))
    }

    @Test fun `a scan row keeps whether details were recorded`() = runBlocking {
        val with = dao.insertScan(scan(hasDetails = true))
        dao.insertScan(scan())
        val rows = db.query("SELECT id, hasDetails FROM privacy_scan ORDER BY id", null).use { c ->
            buildList { while (c.moveToNext()) add(c.getLong(0) to (c.getInt(1) == 1)) }
        }
        assertTrue(rows.first { it.first == with }.second)
        assertFalse(rows.first { it.first != with }.second)
    }
}
