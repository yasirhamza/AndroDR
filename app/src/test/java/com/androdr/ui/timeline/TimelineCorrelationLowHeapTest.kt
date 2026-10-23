package com.androdr.ui.timeline

import com.androdr.data.db.TimelineFilter
import com.androdr.data.model.ScanResult
import com.androdr.data.model.TelemetrySource
import com.androdr.data.store.rawFile
import com.androdr.scanner.WriterFixture
import com.androdr.scanner.WriterHooks
import com.androdr.sigma.AtomRef
import com.androdr.sigma.CorrelationRule
import com.androdr.sigma.CorrelationType
import com.androdr.sigma.SigmaCorrelationEngine
import com.androdr.sigma.SigmaRuleEngine
import com.androdr.sigma.SigmaRuleParser
import com.androdr.sigma.StoreRecord
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner

/**
 * Low heap (spec §6, §9): correlation over 5,000 `permission_use` facts of one import completes within
 * a 256 MB heap, and the Timeline then pages every fact and signal and loads every signal's members.
 * Runs only in the `lowHeapTest` Gradle task (`maxHeapSize = "256m"`).
 */
@RunWith(RobolectricTestRunner::class)
class TimelineCorrelationLowHeapTest {

    private fun appOps(i: Int) = StoreRecord(mapOf(
        "package_name" to "com.spy", "operation" to "android:op${i % 7}", "last_access_time" to "",
        "last_reject_time" to "", "access_count" to 1L, "is_system_app" to false, "source" to "bugreport_import",
        "event_time_ms" to BASE + i * 400L,
    ))

    private fun engine() = SigmaRuleEngine(io.mockk.mockk(relaxed = true)).apply {
        setRemoteRules(listOf(SigmaRuleParser.parse(rawFile("sigma_androdr_atom_permission_use.yml").readText())!!))
        loadCorrelationRules(listOf(CorrelationRule(
            id = "test-burst", title = "Burst", type = CorrelationType.EVENT_COUNT,
            referencedRuleIds = listOf("androdr-atom-permission-use"), timespanMs = 3_600_000L,
            groupBy = listOf("package_name"), minEvents = 3, severity = "high", displayLabel = "Burst",
        )))
    }

    @Test
    fun `correlation over 5,000 permission_use facts completes and the Timeline pages it`() = runBlocking {
        assertTrue("run through the lowHeapTest task (max heap ${Runtime.getRuntime().maxMemory() shr 20} MB)",
            Runtime.getRuntime().maxMemory() <= HEAP_CEILING)
        WriterFixture(recordSql = false).use { w ->
            val scan = w.scan(1L, TelemetrySource.BUGREPORT_IMPORT)
            val hooks = object : WriterHooks(scan, engine(), SigmaCorrelationEngine()) {
                override fun extraRows(scan: ScanResult) = emptyList<com.androdr.data.model.ForensicTimelineEvent>()
            }
            val s = w.writer.begin(scan, liveEvents = false, hooks)
            s.appendAll("appops_audit", TelemetrySource.BUGREPORT_IMPORT, WriterFixture.IMPORT_CAPTURED,
                (0 until FACTS).asSequence().map(::appOps))
            s.finish()

            val entries = TimelineEntries(w.f.db, w.f.reader)
            val all = ArrayList<TimelineRow.Entry>()
            entries.forEachPage(TimelineFilter(), oldestFirst = false, size = 500) { all += it }
            val signals = all.filterIsInstance<TimelineRow.StoredRow>().filter { it.event.kind == "signal" }
            assertTrue("correlation produced signals", signals.isNotEmpty())
            assertEquals(FACTS, all.count { it is TimelineRow.EventRow })
            assertEquals(all.size.toLong(), entries.count(TimelineFilter()))

            val members = ClusterMembers(w.f.db.signalMemberDao(), w.f.db.forensicTimelineEventDao(), w.f.reader)
            for (signal in signals) {
                var after: AtomRef? = null
                var loaded = 0
                do {
                    val page = members.load(signal.entity.id, after)
                    loaded += page.members.size
                    assertEquals(0, page.missing)
                    after = page.next
                } while (after != null)
                assertTrue(loaded >= 3)
            }
        }
    }

    private companion object {
        const val FACTS = 5_000
        const val BASE = 1_729_600_000_000L

        /** 256 MB plus slack for how the JVM reports `-Xmx`. */
        const val HEAP_CEILING = 280L shl 20
    }
}
