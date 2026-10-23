package com.androdr.ui.timeline

import com.androdr.data.model.ForensicTimelineEvent
import com.androdr.data.model.TelemetrySource
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/**
 * Regression guard for #342 C2 (correctness C#5 / architect #5).
 *
 * The imported adapters used to stamp dns:/net:/sec: correlation ids on every
 * raw row. TimelineClusters Pass-2 clusters any >= 2 rows sharing an
 * effectiveCorrelationId, so N identical imported events (N keyguard_dismissed
 * security events sharing sec:$tag, a domain resolved twice sharing dns:<domain>)
 * formed one meaningless PRE_LINKED cluster. The fix stopped stamping raw rows.
 *
 * C3 retired the adapters: imported events are store-only facts and no new raw row is written.
 * Raw rows of pre-store (`NONE`) imports remain, in the shape the adapters wrote (empty
 * correlationId), so clustering is still driven over that shape the way the Timeline UI does
 * ([partitionSignals]); and no production code may write an intrusion-log raw row again.
 */
class IntrusionLogClusterRegressionTest {

    /** A legacy raw row as the retired adapters wrote it (C2: empty correlationId). */
    private fun legacyRow(id: Long, category: String, description: String) = ForensicTimelineEvent(
        id = id, startTimestamp = 1_700_000_000_000L + id, source = "intrusion_log", category = category,
        description = description, correlationId = "", scanResultId = 1L,
        telemetrySource = TelemetrySource.INTRUSION_LOG_IMPORT,
    )

    @Test
    fun `identical imported rows do not form a PRE_LINKED cluster`() {
        // Same tag / domain / destination and no package: only a stamped correlationId could cluster these.
        val rows: List<ForensicTimelineEvent> =
            (1L..400L).map { legacyRow(it, "security_event", "Security: keyguard_dismissed") } +
                (401L..410L).map { legacyRow(it, "dns_query", "DNS: cdn.example.com") } +
                (411L..420L).map { legacyRow(it, "network_connect", "Connect: 8.8.8.8:853") }

        val (clusters, standalone) = partitionSignals(rows)

        assertTrue(
            "Imported raw rows must not form a PRE_LINKED cluster, got: " +
                clusters.map { it.pattern to it.members.size },
            clusters.none { it.pattern == CorrelationPattern.PRE_LINKED },
        )
        assertTrue(
            "Expected all ${rows.size} rows standalone, got ${standalone.size}",
            standalone.size == rows.size,
        )
    }

    @Test
    fun `no production code writes an intrusion-log raw row`() {
        val root = listOf(File("src/main/java/com/androdr"), File("app/src/main/java/com/androdr"))
            .first { it.isDirectory }
        val writer = Regex("""source\s*=\s*"intrusion_log"""")
        val offenders = root.walkTopDown().filter { it.extension == "kt" }
            .filter { writer.containsMatchIn(it.readText()) }.map { it.name }.toList()
        assertTrue("raw intrusion-log rows are retired (C3): $offenders", offenders.isEmpty())
    }
}
