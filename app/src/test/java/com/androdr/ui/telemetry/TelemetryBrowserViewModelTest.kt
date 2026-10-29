package com.androdr.ui.telemetry

import androidx.lifecycle.SavedStateHandle
import androidx.paging.PagingSource
import com.androdr.data.db.ServiceSummary
import com.androdr.data.model.ScanState
import com.androdr.data.model.TelemetryState
import com.androdr.data.store.DecodedRecord
import com.androdr.data.store.StoreFixture
import com.androdr.data.store.StoreFixture.Companion.dns
import com.androdr.reporting.ReportFormatter
import com.androdr.sigma.StoreRecord
import com.androdr.sigma.TaxonomyContract
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.test.StandardTestDispatcher
import kotlinx.coroutines.test.advanceTimeBy
import kotlinx.coroutines.test.resetMain
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import kotlinx.coroutines.test.setMain
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner

/**
 * The telemetry browser (spec §8.1): services with record counts, keyset-paged records with a
 * debounced search, one fact's fields in taxonomy order, unreadable bodies, and a snapshot
 * subject's history with the changed fields marked. Only `COMPLETE` scans are browsable.
 */
@OptIn(ExperimentalCoroutinesApi::class)
@RunWith(RobolectricTestRunner::class)
class TelemetryBrowserViewModelTest {
    private val dispatcher = StandardTestDispatcher()
    private val f = StoreFixture()

    @Before fun setUp() = Dispatchers.setMain(dispatcher)

    @After fun tearDown() {
        Dispatchers.resetMain()
        f.close()
    }

    private fun vm(vararg args: Pair<String, Any?>) =
        TelemetryBrowserViewModel(f.reader, f.db.scanResultDao(), SavedStateHandle(mapOf(*args)))

    private fun app(pkg: String, label: String = pkg, system: Boolean = false, at: Long = StoreFixture.CAPTURED) =
        StoreRecord(mapOf("package_name" to pkg, "app_name" to label, "is_system_app" to system,
            "source" to "LIVE_SCAN", "captured_at" to at))

    private suspend fun completeScan(id: Long, service: String, records: List<StoreRecord>, capturedAt: Long = id) =
        f.scan(id).let {
            val r = f.persist(id, service, records, capturedAt = capturedAt)
            f.setState(id, ScanState.COMPLETE)
            r
        }

    private suspend fun TelemetryBrowserViewModel.loadAll(pageSize: Int): List<DecodedRecord> {
        val source = pagingSource(query.value)
        val out = ArrayList<DecodedRecord>()
        var page = source.load(PagingSource.LoadParams.Refresh(null, pageSize, false))
            as PagingSource.LoadResult.Page<Int, DecodedRecord>
        out += page.data
        while (page.nextKey != null) {
            page = source.load(PagingSource.LoadParams.Append(page.nextKey!!, pageSize, false))
                as PagingSource.LoadResult.Page<Int, DecodedRecord>
            out += page.data
        }
        return out
    }

    @Test
    fun `the services level lists each service of a COMPLETE scan with its record count`() = runTest(dispatcher) {
        f.scan(1L)
        f.persist(1L, "app_scanner", listOf(app("com.a"), app("com.b")))
        f.persist(1L, "dns_monitor", listOf(dns("x.example")))
        f.setState(1L, ScanState.COMPLETE)
        completeScan(2L, "dns_monitor", listOf(dns("y.example"), dns("z.example")))
        val vm = vm(TelemetryBrowserViewModel.ARG_SCAN to 1L)
        assertEquals(
            ServicesState.Loaded(listOf(ServiceSummary("app_scanner", 2), ServiceSummary("dns_monitor", 1)),
                TelemetryState.NONE),
            vm.services.first { it != ServicesState.Loading },
        )
    }

    // Final review M1: a scan whose telemetry retention removed said "This scan stored no telemetry".
    @Test
    fun `a retention-trimmed scan says retention removed its records, never that it stored none`() =
        runTest(dispatcher) {
            suspend fun loaded(id: Long, state: TelemetryState, records: List<StoreRecord>): ServicesState.Loaded {
                f.scan(id)
                if (records.isNotEmpty()) f.persist(id, "app_scanner", records)
                f.setState(id, ScanState.COMPLETE)
                f.db.scanResultDao().setTelemetryState(id, state, TelemetryState.NONE)
                return vm(TelemetryBrowserViewModel.ARG_SCAN to id).services.first { it != ServicesState.Loading }
                    as ServicesState.Loaded
            }
            val emptied = loaded(1L, TelemetryState.PARTIAL_RETENTION, emptyList())
            assertEquals(TelemetryState.PARTIAL_RETENTION, emptied.telemetryState)
            assertEquals("${ReportFormatter.TELEMETRY_PARTIAL} 0 record(s) remain.", emptied.notice)

            val trimmed = loaded(2L, TelemetryState.PARTIAL_RETENTION, listOf(app("com.a")))
            assertEquals("${ReportFormatter.TELEMETRY_PARTIAL} 1 record(s) remain.", trimmed.notice)

            val failed = loaded(3L, TelemetryState.FAILED_PARTIAL_RETENTION, emptyList())
            assertEquals("${ReportFormatter.TELEMETRY_FAILED_RETAINED} 0 record(s) remain.", failed.notice)

            assertNull("a STORED scan needs no notice", loaded(4L, TelemetryState.STORED, listOf(app("com.b"))).notice)
        }

    @Test
    fun `IN_PROGRESS and DELETING scans are not listed`() = runTest(dispatcher) {
        for ((id, state) in listOf(1L to ScanState.IN_PROGRESS, 2L to ScanState.DELETING)) {
            f.scan(id)
            f.persist(id, "app_scanner", listOf(app("com.a")))
            f.setState(id, state)
            val vm = vm(TelemetryBrowserViewModel.ARG_SCAN to id,
                TelemetryBrowserViewModel.ARG_SERVICE to "app_scanner")
            assertEquals(state.name, ServicesState.Unavailable, vm.services.first { it != ServicesState.Loading })
            assertTrue(state.name, vm.loadAll(10).isEmpty())
        }
    }

    @Test
    fun `records page by ordinal keyset across pages, without OFFSET`() = runTest(dispatcher) {
        completeScan(1L, "app_scanner", (0 until 5).map { app("com.p$it") })
        val vm = vm(TelemetryBrowserViewModel.ARG_SCAN to 1L, TelemetryBrowserViewModel.ARG_SERVICE to "app_scanner")
        f.sql.clear()
        val all = vm.loadAll(pageSize = 2)
        assertEquals((0 until 5).toList(), all.map { it.ordinal })
        assertEquals((0 until 5).map { "com.p$it" }, all.map { it.fields!!["package_name"] })
        assertTrue("three keyset reads", f.sql.count { "o.ordinal >" in it } >= 3)
        assertFalse(f.sql.any { it.contains("OFFSET", ignoreCase = true) })
    }

    @Test
    fun `a debounced search narrows the records by package, keyset-paged`() = runTest(dispatcher) {
        completeScan(1L, "app_scanner",
            listOf(app("com.alpha"), app("org.beta"), app("com.gamma"), app("net.beta.two"), app("com.delta")))
        val vm = vm(TelemetryBrowserViewModel.ARG_SCAN to 1L, TelemetryBrowserViewModel.ARG_SERVICE to "app_scanner")
        runCurrent()
        assertNull(vm.query.value)
        vm.setSearchText("al")
        advanceTimeBy(100L)
        vm.setSearchText(" BETA ")
        advanceTimeBy(250L)
        assertNull("no query before a quiet ${TelemetryBrowserViewModel.SEARCH_DEBOUNCE_MS} ms", vm.query.value)
        advanceTimeBy(SETTLE)
        assertEquals("BETA", vm.query.value)
        assertEquals(listOf("org.beta", "net.beta.two"), vm.loadAll(pageSize = 1).map { it.fields!!["package_name"] })

        vm.setSearchText("%")
        advanceTimeBy(SETTLE)
        assertTrue("LIKE wildcards match literally", vm.loadAll(10).isEmpty())

        vm.setSearchText("   ")
        advanceTimeBy(SETTLE)
        assertNull("a blank search is no search", vm.query.value)
        assertEquals(5, vm.loadAll(10).size)
    }

    @Test
    fun `an unreadable body is listed and opened as unreadable`() = runTest(dispatcher) {
        val r = completeScan(1L, "app_scanner", listOf(app("com.ok"), app("com.bad")))
        val bad = r.factIdByChunkIndex[1]
        f.db.openHelper.writableDatabase.execSQL(
            "UPDATE record_body SET rawBytes = -1 WHERE hash = (SELECT bodyHash FROM telemetry_record WHERE id = $bad)"
        )
        val list = vm(TelemetryBrowserViewModel.ARG_SCAN to 1L, TelemetryBrowserViewModel.ARG_SERVICE to "app_scanner")
            .loadAll(10)
        assertEquals(2, list.size)
        assertNull(list[1].fields)
        assertEquals(bad, list[1].factId)

        val fact = vm(TelemetryBrowserViewModel.ARG_FACT to bad).fact.first { it != FactState.Loading }
        fact as FactState.Loaded
        assertNull("unreadable: no fields", fact.fields)
        assertEquals(bad, fact.record.factId)
    }

    @Test
    fun `a fact's fields read in taxonomy order with their descriptions`() = runTest(dispatcher) {
        val rec = StoreRecord(linkedMapOf("zz_unknown" to 1, "is_system_app" to true, "app_name" to "A",
            "package_name" to "com.a", "source" to "LIVE_SCAN", "captured_at" to 1L))
        val r = completeScan(1L, "app_scanner", listOf(rec), capturedAt = 1L)
        val fact = vm(TelemetryBrowserViewModel.ARG_FACT to r.factIdByChunkIndex[0],
            TelemetryBrowserViewModel.ARG_FACT_SCAN to 1L)
            .fact.first { it != FactState.Loading } as FactState.Loaded
        val keys = fact.fields!!.map { it.key }
        val order = TaxonomyContract.fieldOrder("app_scanner")
        val known = keys.filter { it in order }
        assertEquals(known.sortedBy { order.indexOf(it) }, known)
        assertEquals("unknown keys last", "zz_unknown", keys.last())
        assertEquals(TaxonomyContract.description("app_scanner", "package_name"),
            fact.fields!!.single { it.key == "package_name" }.description)
        assertNull(fact.fields!!.single { it.key == "zz_unknown" }.description)
        assertTrue("a snapshot record offers its subject's history", fact.hasHistory)
    }

    @Test
    fun `a missing fact reads as missing, and only a snapshot record has a subject history`() = runTest(dispatcher) {
        assertEquals(FactState.Missing,
            vm(TelemetryBrowserViewModel.ARG_FACT to 999L).fact.first { it != FactState.Loading })
        // appops_audit has key fields and an event-time field: with a time it is an event, without one a snapshot.
        fun op(time: Long?) = StoreRecord(mapOf("package_name" to "com.a", "operation" to "CAMERA",
            "event_time_ms" to time))
        val r = completeScan(1L, "appops_audit", listOf(op(1_700_000_000_000L), op(null)))
        suspend fun opened(i: Int) = vm(TelemetryBrowserViewModel.ARG_FACT to r.factIdByChunkIndex[i]).fact
            .first { it != FactState.Loading } as FactState.Loaded
        assertFalse("an event record has no subject history", opened(0).hasHistory)
        assertTrue("no event time: a snapshot record", opened(1).hasHistory)
        val dns = completeScan(2L, "dns_monitor", listOf(dns("x.example")))
        assertFalse(vm(TelemetryBrowserViewModel.ARG_FACT to dns.factIdByChunkIndex[0]).fact
            .first { it != FactState.Loading }.let { (it as FactState.Loaded).hasHistory })
    }

    @Test
    fun `a fact opened from a scan reads as that scan observed it, otherwise as its newest scan did`() =
        runTest(dispatcher) {
            val first = completeScan(1L, "app_scanner", listOf(app("com.s", at = 1_000L)), capturedAt = 1_000L)
            completeScan(2L, "app_scanner", listOf(app("com.s", at = 2_000L)), capturedAt = 2_000L)
            val id = first.factIdByChunkIndex[0]
            suspend fun opened(vararg args: Pair<String, Any?>) =
                (vm(*args).fact.first { it != FactState.Loading } as FactState.Loaded).record
            assertEquals(1L to 1_000L, opened(TelemetryBrowserViewModel.ARG_FACT to id,
                TelemetryBrowserViewModel.ARG_FACT_SCAN to 1L).let { it.scanId to it.capturedAt })
            assertEquals(2L to 2_000L, opened(TelemetryBrowserViewModel.ARG_FACT to id,
                TelemetryBrowserViewModel.ARG_FACT_SCAN to TelemetryBrowserViewModel.NO_SCAN)
                .let { it.scanId to it.capturedAt })
        }

    @Test
    fun `subject history lists every scan's observation and marks the changed fields`() = runTest(dispatcher) {
        // As emitted: each scan stamps its own captured_at, so the envelope differs every scan.
        completeScan(1L, "app_scanner", listOf(app("com.h", label = "Old", at = 1_000L)), capturedAt = 1_000L)
        completeScan(2L, "app_scanner", listOf(app("com.h", label = "Old", at = 2_000L)), capturedAt = 2_000L)
        val last = completeScan(3L, "app_scanner", listOf(app("com.h", label = "New", system = true, at = 3_000L)),
            capturedAt = 3_000L)
        val vm = vm(TelemetryBrowserViewModel.ARG_FACT to last.factIdByChunkIndex[0])
        assertTrue((vm.fact.first { it != FactState.Loading } as FactState.Loaded).hasHistory)
        val history = vm.history.first { it.size == 3 }
        assertEquals(listOf(1L, 2L, 3L), history.map { it.record.scanId })
        assertEquals(listOf(1_000L, 2_000L, 3_000L), history.map { it.record.fields!!["captured_at"] })
        assertEquals("captured_at differs every scan but is provenance, not a change",
            listOf(emptySet(), emptySet(), setOf("app_name", "is_system_app")), history.map { it.changed })
    }

    @Test
    fun `subject history holds only snapshot observations, not same-key events`() = runTest(dispatcher) {
        // appops_audit keys snapshots and events alike by package_name|operation (review I1).
        fun op(time: Long?) = StoreRecord(mapOf("package_name" to "com.a", "operation" to "CAMERA",
            "event_time_ms" to time))
        f.scan(1L)
        val first = f.persist(1L, "appops_audit", listOf(op(null), op(1_700_000_000_000L), op(1_700_000_001_000L)),
            capturedAt = 1_000L)
        f.setState(1L, ScanState.COMPLETE)
        completeScan(2L, "appops_audit", listOf(op(1_700_000_002_000L), op(null)), capturedAt = 2_000L)
        val vm = vm(TelemetryBrowserViewModel.ARG_FACT to first.factIdByChunkIndex[0])
        assertTrue((vm.fact.first { it != FactState.Loading } as FactState.Loaded).hasHistory)
        val history = vm.history.first { it.isNotEmpty() }
        assertEquals("the snapshot's two observations only", listOf(1L, 2L), history.map { it.record.scanId })
        assertTrue(history.all { it.record.eventTime == null })
        assertEquals(listOf(emptySet<String>(), emptySet()), history.map { it.changed })
    }

    @Test
    fun `a fact seen only by an IN_PROGRESS scan opens as missing`() = runTest(dispatcher) {
        f.scan(1L)
        val r = f.persist(1L, "app_scanner", listOf(app("com.wip")))
        for (args in listOf(arrayOf(TelemetryBrowserViewModel.ARG_FACT to r.factIdByChunkIndex[0]),
                arrayOf(TelemetryBrowserViewModel.ARG_FACT to r.factIdByChunkIndex[0],
                    TelemetryBrowserViewModel.ARG_FACT_SCAN to 1L))) {
            assertEquals(FactState.Missing, vm(*args).fact.first { it != FactState.Loading })
        }
    }

    @Test
    fun `changed keys cover added and removed fields and skip unreadable neighbours`() {
        assertEquals(setOf("a", "b", "c"),
            changedKeys(mapOf("a" to 1, "b" to 2, "source" to "X"), mapOf("a" to 2, "c" to 3, "source" to "Y")))
        assertEquals(emptySet<String>(), changedKeys(null, mapOf("a" to 1)))
        assertEquals(emptySet<String>(), changedKeys(mapOf("a" to 1), null))
    }

    private companion object {
        const val SETTLE = TelemetryBrowserViewModel.SEARCH_DEBOUNCE_MS + 1
    }
}
