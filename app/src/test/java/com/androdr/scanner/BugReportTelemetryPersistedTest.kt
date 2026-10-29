package com.androdr.scanner

import android.net.Uri
import com.androdr.data.model.TelemetrySource
import com.androdr.sigma.BugReportRecordBuilders
import io.mockk.coEvery
import io.mockk.mockk
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner

/**
 * B1 part 2 (telemetry store §9): a bug-report import stores every module's telemetry — the generic
 * modules' field maps and every typed record list (A6's `TypedTelemetry`) — as observations of the
 * import, through its session. A module with telemetry that is not observed fails here.
 */
@RunWith(RobolectricTestRunner::class)
class BugReportTelemetryPersistedTest {
    private val uri = mockk<Uri>(relaxed = true)
    private val f =
        OrchestratorFixture(engine = IntrusionLogZips.engine(), bugReportAnalyzer = BugReportFixtures.analyzer())

    @After fun tearDown() = f.close()

    private fun observedPerService(scanId: Long): Map<String, Long> = f.db.openHelper.readableDatabase
        .query("SELECT service, COUNT(*) FROM scan_record WHERE scanId = $scanId GROUP BY service").use { c ->
            generateSequence { if (c.moveToNext()) c.getString(0) to c.getLong(1) else null }.toMap()
        }

    @Test
    fun `every module with telemetry is observed by the import`() = runBlocking {
        // What the analyzer produced, per service: generic modules and every typed list.
        val produced = BugReportFixtures.analyzer().analyze(uri)
        val b = produced.telemetryBundle
        val expected = (produced.moduleTelemetry.groupBy { it.service }
            .mapValues { (_, m) -> m.sumOf { it.records.size }.toLong() } + mapOf(
            BugReportRecordBuilders.TOMBSTONE_PARSER to b.tombstoneEvents.size.toLong(),
            BugReportRecordBuilders.WAKELOCK_PARSER to b.wakelockAcquisitions.size.toLong(),
            BugReportRecordBuilders.BATTERY_DAILY to b.batteryDailyEvents.size.toLong(),
            BugReportRecordBuilders.PACKAGE_INSTALL_HISTORY to b.packageInstallHistory.size.toLong(),
            BugReportRecordBuilders.PLATFORM_COMPAT to b.platformCompatChanges.size.toLong(),
            BugReportRecordBuilders.DB_INFO to b.databasePathObservations.size.toLong(),
            BugReportRecordBuilders.SYSTEM_PROPERTY to b.systemPropertySnapshots.size.toLong(),
        )).filterValues { it > 0 }
        assertTrue("the fixture exercises every typed list: $expected", expected.size >= 7)

        val result = f.orchestrator.analyzeBugReport(uri)

        val scan = f.scans().single()
        assertEquals(TelemetrySource.BUGREPORT_IMPORT, scan.source)
        assertEquals("every record of every module is one observation", expected, observedPerService(scan.id))
        assertEquals(expected.values.sum().toInt(), result.write!!.newFacts)
    }

    /** Generic modules (field maps under their own service) are observed too, module by module. */
    @Test
    fun `generic module telemetry is observed under each module's service`() = runBlocking {
        OrchestratorFixture(engine = IntrusionLogZips.engine(), bugReportAnalyzer = mockk(relaxed = true)).use { g ->
            coEvery { g.bugReportAnalyzer.analyze(any()) } returns BugReportAnalyzer.BugReportAnalysisResult(
                moduleTelemetry = listOf(
                    BugReportAnalyzer.ModuleTelemetry("receiver_audit", listOf(mapOf("package_name" to "a"),
                        mapOf("package_name" to "b"))),
                    BugReportAnalyzer.ModuleTelemetry("adb_audit", listOf(mapOf("key" to "k"))),
                    BugReportAnalyzer.ModuleTelemetry("receiver_audit", listOf(mapOf("package_name" to "c"))),
                ),
            )
            g.orchestrator.analyzeBugReport(uri)
            val scanId = g.scans().single().id
            val observed = g.db.openHelper.readableDatabase
                .query("SELECT service, COUNT(*) FROM scan_record WHERE scanId = $scanId GROUP BY service").use { c ->
                    generateSequence { if (c.moveToNext()) c.getString(0) to c.getLong(1) else null }.toMap()
                }
            assertEquals(mapOf("receiver_audit" to 3L, "adb_audit" to 1L), observed)
        }
    }

    /** #342 B1: a failed import keeps nothing and says so (it used to log and return the result). */
    @Test
    fun `a failed bug-report session keeps nothing and surfaces the failure`() = runBlocking {
        val failing = OrchestratorFixture(engine = IntrusionLogZips.engine(), bugReportAnalyzer = mockk(relaxed = true))
        failing.use { g ->
            coEvery { g.bugReportAnalyzer.analyze(any()) } returns BugReportAnalyzer.BugReportAnalysisResult(
                moduleTelemetry = listOf(BugReportAnalyzer.ModuleTelemetry("receiver_audit", listOf(mapOf("a" to 1)))),
            )
            val store = io.mockk.spyk(g.w.f.store)
            g.w.store = store
            coEvery { store.persistChunk(any(), any(), any(), any(), any(), any(), any(), any(), any()) } throws
                IllegalStateException("write failed")

            val thrown = runCatching { g.orchestrator.analyzeBugReport(uri) }.exceptionOrNull()

            assertTrue("honest failure: $thrown", thrown is ScanOrchestrator.BugReportPersistException)
            assertEquals(0L, g.count("SELECT COUNT(*) FROM ScanResult"))
            assertEquals(0L, g.count("SELECT COUNT(*) FROM scan_record"))
            assertEquals(0L, g.count("SELECT COUNT(*) FROM telemetry_record"))
        }
    }

    /** I2 (fix round 1): a finishing write that hits a full disk is a failed import, not a saved one. */
    @Test
    fun `a bug report whose finishing write is not saved fails with BugReportPersistException`() = runBlocking {
        val repo = io.mockk.spyk(f.w.repo)
        f.w.repo = repo
        coEvery { repo.finish(any(), any(), any(), any()) } throws
            android.database.sqlite.SQLiteFullException("database or disk is full")

        val thrown = runCatching { f.orchestrator.analyzeBugReport(uri) }.exceptionOrNull()

        assertTrue("not saved is a failed import: $thrown", thrown is ScanOrchestrator.BugReportPersistException)
        assertEquals(0L, f.count("SELECT COUNT(*) FROM ScanResult"))
        assertEquals(0L, f.count("SELECT COUNT(*) FROM scan_record"))
    }
}
