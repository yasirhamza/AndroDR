package com.androdr.data.store

import android.content.Context
import androidx.datastore.preferences.core.PreferenceDataStoreFactory
import androidx.room.Room
import androidx.test.core.app.ApplicationProvider
import com.androdr.data.db.AppDatabase
import com.androdr.data.model.ForensicTimelineEvent
import com.androdr.data.model.ScanResult
import com.androdr.data.model.ScanState
import com.androdr.data.model.SignalMember
import com.androdr.data.model.TelemetrySource
import com.androdr.sigma.StoreRecord
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import java.io.Closeable
import java.io.File
import java.nio.file.Files
import java.util.Collections
import java.util.concurrent.Executor
import java.util.zip.Deflater

/** Reads a file under `app/src/main/res/raw/` from a unit test (cwd is `app/` or the repo root). */
internal fun rawFile(name: String): File =
    listOf(File("src/main/res/raw/$name"), File("app/src/main/res/raw/$name")).first { it.isFile }

/** An in-memory store + reader over a Robolectric Room database (callers use RobolectricTestRunner). */
internal class StoreFixture(recordSql: Boolean = true) : Closeable {
    /** Every SQL statement run, when recorded ([recordSql] false for large imports: it grows per statement). */
    val sql: MutableList<String> = Collections.synchronizedList(mutableListOf())

    /** Whether [sql] records right now (a test turns it off around a large write). */
    @Volatile var recording: Boolean = true
    val db: AppDatabase = Room.inMemoryDatabaseBuilder(
        ApplicationProvider.getApplicationContext<Context>(), AppDatabase::class.java
    ).allowMainThreadQueries().apply {
        if (recordSql) setQueryCallback({ q, _ -> if (recording) sql += q }, Executor { it.run() })
    }.build()

    private val scope = CoroutineScope(Dispatchers.IO + SupervisorJob())
    private val dir: File = Files.createTempDirectory("store-flag").toFile()
    /** The store's DataStore (the dirty flag and the signal-member backfill flag share it, as in the app). */
    val dataStore = PreferenceDataStoreFactory.create(scope = scope) { File(dir, "flag.preferences_pb") }
    val dirty = StoreDirtyFlag(dataStore)
    val codec = TelemetryRecordCodec(TelemetryDictionaries { rawFile("$it.txt").readBytes() })
    val display = EventDisplay.parse(rawFile("event_display.yml").readText())
    val store = TelemetryStore(db, codec, dirty)
    val reader = TelemetryReader(db, codec, display)
    val findings = com.androdr.data.repo.FindingsRepository(db, reader)

    suspend fun scan(id: Long, state: ScanState = ScanState.IN_PROGRESS) {
        db.scanResultDao().insert(ScanResult(id = id, timestamp = id,
            bugReportFindings = emptyList(), riskySideloadCount = 0, knownMalwareCount = 0, state = state))
    }

    fun setState(id: Long, state: ScanState) {
        db.openHelper.writableDatabase.execSQL("UPDATE ScanResult SET state = '${state.name}' WHERE id = $id")
    }

    @Suppress("LongParameterList")
    suspend fun persist(
        scanId: Long, service: String, records: List<StoreRecord>,
        source: TelemetrySource = TelemetrySource.LIVE_SCAN, capturedAt: Long = CAPTURED,
        firstOrdinal: Int = 0, counter: OccurrenceCounter = OccurrenceCounter(), live: Boolean = false,
    ): ChunkResult {
        val deflater = Deflater()
        try {
            return store.persistChunk(
                scanId, service, source, capturedAt, records, firstOrdinal, counter, deflater, live,
            )
        } finally {
            deflater.end()
        }
    }

    suspend fun pinByTimeline(factId: Long) {
        db.forensicTimelineEventDao().insert(ForensicTimelineEvent(startTimestamp = 1L, source = "test",
            category = "finding", description = "pin", recordId = factId))
    }

    suspend fun pinBySignal(factId: Long) {
        db.signalMemberDao().insertAll(
            listOf(SignalMember(signalRowId = 9L, kind = SignalMember.KIND_FACT, refId = factId))
        )
    }

    fun count(query: String): Long =
        db.openHelper.readableDatabase.query(query).use { c -> c.moveToFirst(); c.getLong(0) }

    override fun close() {
        db.close()
        scope.cancel()
        dir.deleteRecursively()
    }

    companion object {
        const val CAPTURED = 1_729_612_345_678L

        fun app(pkg: String, version: Long = 1L, source: TelemetrySource = TelemetrySource.LIVE_SCAN) =
            StoreRecord(mapOf("package_name" to pkg, "version_code" to version, "is_system_app" to false,
                "source" to source.name, "captured_at" to CAPTURED))

        fun dns(domain: String, uid: Int = 10_001, time: Long = 1_729_600_000_000L, key: String? = null) =
            StoreRecord(mapOf("domain" to domain, "app_uid" to uid, "source_package" to "com.example",
                "is_blocked" to false, "reason" to null, "timestamp" to time), key)
    }
}
