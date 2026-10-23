package com.androdr.ui.timeline

import com.androdr.data.db.TimelineFilter
import com.androdr.data.model.ScanState
import com.androdr.data.model.TelemetrySource
import com.androdr.data.store.StoreFixture
import com.androdr.scanner.WriterFixture
import com.androdr.sigma.StoreRecord
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import java.io.File

/**
 * Regression guard for #342 C2 (correctness C#5 / architect #5).
 *
 * The imported adapters used to stamp dns:/net:/sec: correlation ids on every raw row, and the
 * Timeline's read-time pre-linking clustered any >= 2 rows sharing one, so N identical imported
 * events (N keyguard_dismissed security events, a domain resolved twice) formed one meaningless
 * cluster. C3 retired the adapters (imported events are store-only facts); C4 retired read-time
 * pre-linking (spec §6: no cross-page roll-up). Identical imported events therefore page as that
 * many standalone Timeline events, and no production code may write an intrusion-log raw row again.
 */
@RunWith(RobolectricTestRunner::class)
class IntrusionLogClusterRegressionTest {

    @Test
    fun `identical imported events page as standalone events, never one cluster`() = runBlocking {
        StoreFixture().use { f ->
            f.scan(1L)
            f.persist(1L, "security_log", (1L..400L).map { i ->
                val line = WriterFixture.securityLine(time = BASE + i, tag = "keyguard_dismissed")
                StoreRecord(line.fields, "210001 $i ${BASE + i}")
            }, source = TelemetrySource.INTRUSION_LOG_IMPORT)
            f.setState(1L, ScanState.COMPLETE)
            val all = ArrayList<TimelineRow.Entry>()
            TimelineEntries(f.db, f.reader).forEachPage(TimelineFilter(), oldestFirst = false, size = 100) { all += it }

            assertEquals(400, all.size)
            assertTrue("every one a standalone event", all.all { it is TimelineRow.EventRow })
        }
    }

    @Test
    fun `no production code writes an intrusion-log raw row`() {
        val root = listOf(File("src/main/java/com/androdr"), File("app/src/main/java/com/androdr"))
            .first { it.isDirectory }
        // Any `"intrusion_log"` literal (a named argument, a constant, a copy), not only `source = …`;
        // the frozen cleanup list is the one allowed mention (review m3).
        val literal = Regex(""""intrusion_log"""")
        val offenders = root.walkTopDown().filter { it.extension == "kt" && it.name != "LegacyEventRowCleanup.kt" }
            .filter { literal.containsMatchIn(it.readText()) }.map { it.name }.toList()
        assertTrue("raw intrusion-log rows are retired (C3): $offenders", offenders.isEmpty())
    }

    private companion object {
        const val BASE = 1_700_000_000_000L
    }
}
