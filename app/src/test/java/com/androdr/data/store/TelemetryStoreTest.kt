package com.androdr.data.store

import com.androdr.data.model.NetworkTelemetry
import com.androdr.data.model.ScanState
import com.androdr.data.model.TelemetrySource
import com.androdr.data.store.StoreFixture.Companion.CAPTURED
import com.androdr.data.store.StoreFixture.Companion.app
import com.androdr.data.store.StoreFixture.Companion.dns
import com.androdr.sigma.StoreRecord
import com.androdr.sigma.TaxonomyContract
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import kotlin.random.Random

/** S1, S2, S4 (spec §9) and the delete/GC paths of [TelemetryStore] (spec §5.1). */
@RunWith(RobolectricTestRunner::class)
class TelemetryStoreTest {
    private val f = StoreFixture()

    @After fun tearDown() = f.close()

    /** A record for [service] exercising every field with a typed value (envelope keys equal to the observation). */
    private fun sample(service: String): Map<String, Any?> = TaxonomyContract.fieldOrder(service)
        .mapIndexed { i, field ->
            field to when (field) {
                TaxonomyContract.eventTimeField(service) -> 1_729_600_000_000L + i
                TaxonomyContract.precisionField(service) -> "day"
                "source" -> TelemetrySource.LIVE_SCAN.name
                "captured_at" -> CAPTURED
                else -> when (i % 7) {
                    0 -> "value-$i"
                    1 -> 5_000_000_000L + i
                    2 -> i
                    3 -> i % 2 == 0
                    4 -> listOf("a$i", "b$i")
                    5 -> null
                    else -> i + 0.5
                }
            }
        }.toMap()

    @Test
    fun `S1 - the full decoded map equals the original for every service`() = runBlocking {
        f.scan(1L)
        val services = TaxonomyContract.services.sorted()
        for (service in services) f.persist(1L, service, listOf(StoreRecord(sample(service))))
        f.setState(1L, ScanState.COMPLETE)
        for (service in services) {
            val read = mutableListOf<DecodedRecord>()
            f.reader.forEach(1L, service) { read += it }
            assertEquals(service, listOf(sample(service)), read.map { it.fields })
            assertEquals(service, TaxonomyContract.eventTimeOf(service, sample(service)), read.single().eventTime)
        }
    }

    private fun network(n: Int, capturedAt: Long): List<StoreRecord> {
        val rnd = Random(42)
        return List(n) {
            StoreRecord(NetworkTelemetry(
                destinationIp = "10.${rnd.nextInt(256)}.${rnd.nextInt(256)}.${rnd.nextInt(256)}",
                destinationPort = listOf(443, 80, 53).random(rnd), protocol = null, appUid = 10_000 + rnd.nextInt(50),
                appName = "com.app${rnd.nextInt(20)}", timestamp = 1_729_600_000_000L + rnd.nextLong(86_400_000L),
                source = TelemetrySource.INTRUSION_LOG_IMPORT, capturedAt = capturedAt,
            ).toFieldMap())
        }
    }

    @Test
    fun `S2 - two imports of 1000 network records with different capturedAt share facts`() = runBlocking {
        f.scan(1L)
        f.scan(2L)
        val src = TelemetrySource.INTRUSION_LOG_IMPORT
        val a = f.persist(1L, "network_monitor", network(1000, 111L), source = src, capturedAt = 111L)
        val b = f.persist(2L, "network_monitor", network(1000, 222L), source = src, capturedAt = 222L)
        assertEquals(1000, a.newFacts)
        assertEquals(1000, b.alreadyStored)
        assertEquals(0, b.newFacts)
        assertEquals(1000, b.observed)
        assertArrayEquals(a.factIdByChunkIndex, b.factIdByChunkIndex)
        assertEquals(1000L, f.count("SELECT COUNT(*) FROM telemetry_record"))
    }

    @Test
    fun `S2 - identical-content dns maps in one batch become two facts`() = runBlocking {
        f.scan(1L)
        val r = f.persist(1L, "dns_monitor", listOf(dns("a.example"), dns("a.example")))
        assertEquals(2, r.newFacts)
        assertEquals(2, r.observed)
        assertNotEquals(r.factIdByChunkIndex[0], r.factIdByChunkIndex[1])
        assertTrue(r.isEventByChunkIndex.all { it })
    }

    @Test
    fun `S2 - the same source key with a different app_uid becomes two facts`() = runBlocking {
        f.scan(1L)
        val r = f.persist(1L, "dns_monitor", listOf(dns("a.example", uid = 1, key = "dns:7"),
            dns("a.example", uid = 2, key = "dns:7")))
        assertEquals(2, r.newFacts)
        val bySource = f.db.telemetryFactDao().idsBySourceKey(listOf(HashKeys.h128("dns:7")))
        assertEquals(r.factIdByChunkIndex.toSet(), bySource.map { it.id }.toSet())
    }

    @Test
    fun `S2 - id-less duplicate intrusion lines become one fact and one observation`() = runBlocking {
        f.scan(1L)
        val line = StoreRecord(mapOf("timestamp" to 1_729_600_000_000L, "tag" to 210_001L,
            "tag_name" to "adb_shell_cmd",
            "security_data" to listOf("ls"), "source" to "INTRUSION_LOG_IMPORT", "captured_at" to 5L),
            "210001 ? 1729600000000")
        val r = f.persist(1L, "security_log", listOf(line, line), source = TelemetrySource.INTRUSION_LOG_IMPORT,
            capturedAt = 5L)
        assertEquals(1, r.newFacts)
        assertEquals(1, r.observed)
        assertEquals(1, r.duplicatesDropped)
        assertEquals(r.factIdByChunkIndex[0], r.factIdByChunkIndex[1])
        assertEquals(listOf(true, false), r.observedThisScanByChunkIndex.toList())
    }

    @Test
    fun `S2 - 400 apps over two live scans become 400 facts and 800 observations`() = runBlocking {
        val apps = (0 until 400).map { app("com.app$it") }
        for (scan in 1L..2L) {
            f.scan(scan)
            f.persist(scan, "app_scanner", apps, live = true)
            f.setState(scan, ScanState.COMPLETE)
        }
        assertEquals(400L, f.count("SELECT COUNT(*) FROM telemetry_record"))
        assertEquals(800L, f.count("SELECT COUNT(*) FROM scan_record"))
    }

    @Test
    fun `S2 - a re-collected live event gets no second observation`() = runBlocking {
        val event = dns("b.example", key = "dns:9")
        f.scan(1L)
        val first = f.persist(1L, "dns_monitor", listOf(event), live = true)
        f.setState(1L, ScanState.COMPLETE)
        f.scan(2L)
        val again = f.persist(2L, "dns_monitor", listOf(event), live = true)
        assertEquals(0, again.observed)
        assertEquals(1, again.alreadyStored)
        assertEquals(first.factIdByChunkIndex[0], again.factIdByChunkIndex[0])
        assertFalse(again.observedThisScanByChunkIndex[0])
        // An import always observes what it contains.
        f.scan(3L)
        val imported = f.persist(3L, "dns_monitor", listOf(event), source = TelemetrySource.BUGREPORT_IMPORT)
        assertEquals(1, imported.observed)
    }

    @Test
    fun `S4 - deleting import A keeps B's records and pinned facts`() = runBlocking {
        f.scan(1L)
        f.scan(2L)
        val a = f.persist(1L, "app_scanner", listOf(app("a0"), app("a1"), app("a2"), app("shared1"), app("shared2")))
        f.persist(2L, "app_scanner", listOf(app("shared1"), app("shared2"), app("b1")))
        f.setState(2L, ScanState.COMPLETE)
        f.pinBySignal(a.factIdByChunkIndex[0])
        f.pinByTimeline(a.factIdByChunkIndex[1])
        f.setState(1L, ScanState.DELETING)
        f.store.deleteScanTelemetry(1L)
        f.store.deleteScanTelemetry(1L) // idempotent
        val b = mutableListOf<String>()
        f.reader.forEach(2L, "app_scanner") { b += it.fields!!["package_name"] as String }
        assertEquals(listOf("shared1", "shared2", "b1"), b)
        val kept = f.reader.records(a.factIdByChunkIndex.toList()).map { it.fields!!["package_name"] }
        assertEquals(setOf("a0", "a1", "shared1", "shared2"), kept.toSet())
        assertEquals(0L, f.count("SELECT COUNT(*) FROM scan_record WHERE scanId = 1"))
        assertEquals(5L, f.count("SELECT COUNT(*) FROM telemetry_record"))
        assertEquals(5L, f.count("SELECT COUNT(*) FROM record_body"))
    }

    @Test
    fun `a delete killed between batches never leaves an unpinned orphan visible or stored`() = runBlocking {
        f.scan(1L)
        val r = f.persist(1L, "app_scanner", (0 until 10).map { app("p$it") })
        f.pinByTimeline(r.factIdByChunkIndex[1])
        f.setState(1L, ScanState.DELETING)
        assertTrue(f.store.deleteBatch(1L, 3)) // ... then the process dies
        assertEquals(0L, f.count("SELECT COUNT(*) FROM telemetry_record t WHERE NOT EXISTS (SELECT 1 FROM " +
            "scan_record o WHERE o.recordId = t.id) AND NOT EXISTS (SELECT 1 FROM forensic_timeline p " +
            "WHERE p.recordId = t.id)"))
        assertEquals(0L, f.count("SELECT COUNT(*) FROM record_body b WHERE NOT EXISTS " +
            "(SELECT 1 FROM telemetry_record t WHERE t.bodyHash = b.hash)"))
        assertEquals(listOf(r.factIdByChunkIndex[1]), f.reader.records(r.factIdByChunkIndex.toList()).map { it.factId })
        f.store.deleteScanTelemetry(1L) // the sweep resumes
        assertEquals(1L, f.count("SELECT COUNT(*) FROM telemetry_record"))
    }

    @Test
    fun `gc removes unobserved unpinned facts and clears the dirty flag`() = runBlocking {
        f.scan(1L)
        val r = f.persist(1L, "app_scanner", listOf(app("x"), app("y")))
        // A pin-removing path that did not clean up leaves an orphan behind.
        f.db.openHelper.writableDatabase.execSQL("DELETE FROM scan_record")
        f.pinBySignal(r.factIdByChunkIndex[1])
        f.dirty.set()
        f.store.gcUnobservedUnpinned()
        assertEquals(1L, f.count("SELECT COUNT(*) FROM telemetry_record"))
        assertEquals(1L, f.count("SELECT COUNT(*) FROM record_body"))
        assertFalse(f.dirty.isSet())
    }

    @Test
    fun `a delete that throws sets the dirty flag`() = runBlocking {
        f.scan(1L)
        f.persist(1L, "app_scanner", listOf(app("x")))
        f.db.openHelper.writableDatabase.execSQL("DROP TABLE record_body")
        assertTrue(runCatching { f.store.deleteScanTelemetry(1L) }.isFailure)
        assertTrue(f.dirty.isSet())
    }

    @Test
    fun `occurrence counter counts per content`() {
        val c = OccurrenceCounter()
        val h1 = HashKeys.h128("a")
        val h2 = HashKeys.h128("b")
        assertEquals(listOf(0, 1, 0, 2), listOf(c.next(h1), c.next(h1.copyOf()), c.next(h2), c.next(h1)))
    }
}
