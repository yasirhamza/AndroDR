package com.androdr.data.db

import com.androdr.data.model.NetworkStatus
import com.androdr.data.model.PrivacyAppResult
import com.androdr.data.model.PrivacyPackageSet
import com.androdr.data.model.PrivacyScan
import com.androdr.data.model.PrivacyTrackerEvidence
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner

@RunWith(RobolectricTestRunner::class)
class PrivacyDaoTest {
    private lateinit var db: AppDatabase
    private lateinit var dao: PrivacyDao

    @Before fun setUp() {
        db = RoomTestDb.inMemory()
        dao = db.privacyDao()
    }

    @After fun tearDown() { db.close() }

    private fun scan(started: Long) = PrivacyScan(
        startedAt = started, finishedAt = null, appsTotal = 2, appsInspected = 0, appsPartial = 0,
        appsFailed = 0, registrySize = 5, registrySha256 = "abc", dnsWindowStart = 0,
        dnsCoverageDays = 0, usageCoverageFrom = null, networkStatus = NetworkStatus.PENDING.name
    )

    private fun result(scanId: Long, pkg: String) = PrivacyAppResult(scanId, pkg, 1L, pkg, false, "OK", null)

    private fun evidence(scanId: Long, pkg: String) = PrivacyTrackerEvidence(
        scanId, pkg, 1, "T", "t.example", "Ads\u001FAnalytics", true, 3, 2, null, null, null, false
    )

    private suspend fun finish(id: Long) =
        dao.finishScan(id, 500L, 2, 0, 0, 1, null, NetworkStatus.COMPLETE.name)

    private fun count(table: String): Int =
        db.query("SELECT COUNT(*) FROM $table", null).use { it.moveToFirst(); it.getInt(0) }

    @Test fun `latestCompleted ignores an unfinished scan`() = runBlocking {
        val done = dao.insertScan(scan(1))
        finish(done)
        dao.insertScan(scan(2))
        assertEquals(done, dao.latestCompleted().first()?.id)
        assertEquals("COMPLETE", dao.latestCompleted().first()?.networkStatus)
    }

    @Test fun `latestCompletedOnce agrees with latestCompleted`() = runBlocking {
        assertNull(dao.latestCompletedOnce())
        assertNull(dao.latestCompleted().first())
        val a = dao.insertScan(scan(1)); finish(a)
        val b = dao.insertScan(scan(2)); finish(b)
        dao.insertScan(scan(3))
        assertEquals(b, dao.latestCompletedOnce()?.id)
        assertEquals(dao.latestCompleted().first(), dao.latestCompletedOnce())
    }

    @Test fun `deleteScansBefore removes older scans' results and evidence only`() = runBlocking {
        val old = dao.insertScan(scan(1))
        val keep = dao.insertScan(scan(2))
        dao.upsertResults(listOf(result(old, "a"), result(keep, "a")))
        dao.upsertEvidence(listOf(evidence(old, "a"), evidence(keep, "a")))
        dao.upsertPackageSet(PrivacyPackageSet("a", 1, 2, 1, "x"))
        dao.deleteScansBefore(keep)
        assertEquals(emptyList<PrivacyAppResult>(), dao.resultsOnce(old))
        assertEquals(emptyList<PrivacyTrackerEvidence>(), dao.evidenceOnce(old))
        assertEquals(1, dao.resultsOnce(keep).size)
        assertEquals(1, dao.evidenceOnce(keep).size)
        assertEquals(1, dao.results(keep).first().size)
        assertEquals(1, dao.evidence(keep).first().size)
        assertEquals("x", dao.packageSet("a")?.packagesText)
        assertEquals(1, count("privacy_scan"))
    }

    @Test fun `deleteAll empties all four tables`() = runBlocking {
        val id = dao.insertScan(scan(1))
        dao.upsertResults(listOf(result(id, "a")))
        dao.upsertEvidence(listOf(evidence(id, "a")))
        dao.upsertPackageSet(PrivacyPackageSet("a", 1, 2, 1, "x"))
        dao.deleteAll()
        for (t in listOf("privacy_scan", "privacy_app_result", "privacy_tracker_evidence", "privacy_package_set")) {
            assertEquals(t, 0, count(t))
        }
    }

    @Test fun `packageSet round-trips`() = runBlocking {
        val row = PrivacyPackageSet("a", 7, 8, 2, "p.q\nr.s")
        dao.upsertPackageSet(row)
        assertEquals(row, dao.packageSet("a"))
        dao.upsertPackageSet(row.copy(versionCode = 9))
        assertEquals(9L, dao.packageSet("a")?.versionCode)
        dao.deletePackageSet("a")
        assertNull(dao.packageSet("a"))
    }

    @Test fun `pruneCacheTo keeps exactly the packages of that scan with 1500 results`() = runBlocking {
        val id = dao.insertScan(scan(1))
        val pkgs = (0 until 1500).map { "p$it" }
        dao.upsertResults(pkgs.map { result(id, it) })
        dao.upsertPackageSet(PrivacyPackageSet("gone", 1, 1, 1, ""))
        pkgs.forEach { dao.upsertPackageSet(PrivacyPackageSet(it, 1, 1, 1, "")) }
        dao.pruneCacheTo(id)
        assertNull(dao.packageSet("gone"))
        assertEquals(1500, count("privacy_package_set"))
    }
}
