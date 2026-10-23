package com.androdr.data.db

import android.util.Log
import androidx.datastore.core.DataStore
import androidx.datastore.preferences.core.Preferences
import androidx.datastore.preferences.core.booleanPreferencesKey
import androidx.datastore.preferences.core.edit
import androidx.room.Dao
import androidx.room.Query
import androidx.room.withTransaction
import com.androdr.data.model.SignalMember
import com.androdr.data.repo.ScanLock
import com.androdr.data.repo.TimelineRowDeleter
import com.androdr.data.store.TelemetryStore
import com.androdr.di.StoreDataStore
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.sync.withLock
import javax.inject.Inject
import javax.inject.Singleton

/**
 * The one-time cleanup's reads (spec §5.3). Writer-side: it reads rows of every scan, visible or
 * not, so it is on the Q1 gate's writer allow-list. Its deletes go through [TimelineRowDeleter].
 */
@Dao
interface LegacyEventRowDao {

    /** Signal ids that members still name although their signal row is gone (orphaned refs). */
    @Query(
        "SELECT DISTINCT sm.signalRowId FROM signal_member sm WHERE NOT EXISTS " +
            "(SELECT 1 FROM forensic_timeline r WHERE r.id = sm.signalRowId) LIMIT :size"
    )
    suspend fun orphanSignalIds(size: Int): List<Long>

    /**
     * The next retired-producer rows after [afterId]: non-persistent rows whose `source` is one of
     * [sources], of a scan whose telemetry is in the store (`STORED`, `PARTIAL_RETENTION`), that no
     * signal member names. By producer, never by category.
     */
    @Query(
        "SELECT r.id FROM forensic_timeline r WHERE r.id > :afterId AND r.persistent = 0 " +
            "AND r.source IN (:sources) AND EXISTS (SELECT 1 FROM ScanResult s WHERE s.id = r.scanResultId " +
            "AND s.telemetryState IN ('STORED', 'PARTIAL_RETENTION')) AND NOT EXISTS (SELECT 1 FROM " +
            "signal_member sm WHERE sm.kind = ${SignalMember.KIND_ROW} AND sm.refId = r.id) " +
            "ORDER BY r.id LIMIT :size"
    )
    suspend fun legacyRowsAfter(afterId: Long, sources: List<String>, size: Int): List<Long>
}

/**
 * Deletes, once, the `forensic_timeline` rows the retired event adapters wrote (spec §5.3, C3):
 * their events live in the store, so the rows only duplicate them. Run by `StartupSweep` at the
 * first launch after the upgrade.
 *
 * Rows are chosen by **producer** — `source` in [RETIRED_SOURCES] — never by category, so the
 * live `package_install` / `device_admin_grant` detected-change rows, finding rows and signals
 * stay. Only scans whose `telemetryState` is `STORED` or `PARTIAL_RETENTION` are touched: a
 * pre-feature (`NONE`) scan's rows are its only record, and so are an evaluate-only (`FAILED`)
 * scan's. A row a signal still lists as a member is kept; member refs whose signal row is gone
 * (orphans) are removed first, with their fact pins released, so they protect nothing.
 *
 * Keyset by row id, [BATCH] rows per transaction, each batch under [ScanLock.mutex] taken outside
 * the transaction (StartupSweep / `SignalMemberBackfill` pattern). Deletes go through
 * [TimelineRowDeleter], which releases the facts the rows pinned. A failing batch is logged and
 * counted and ends the pass without the done flag, so the next launch retries; it never crashes
 * the launch. The DataStore flag marks completion when one pass reaches the end.
 */
@Singleton
class LegacyEventRowCleanup @Inject constructor(
    private val db: AppDatabase,
    private val rows: TimelineRowDeleter,
    private val members: SignalMemberDao,
    private val store: TelemetryStore,
    private val lock: ScanLock,
    @StoreDataStore private val dataStore: DataStore<Preferences>,
) {
    private val dao get() = db.legacyEventRowDao()

    /** What one run did; [completed] is false when the flag was already set or a batch failed. */
    data class Outcome(val deleted: Int, val orphanSignals: Int, val failed: Int, val completed: Boolean)

    suspend fun isDone(): Boolean = dataStore.data.first()[DONE] == true

    suspend fun run(): Outcome {
        if (isDone()) return Outcome(0, 0, 0, completed = false)
        var orphans = 0
        var deleted = 0
        val ok = attempt {
            while (true) {
                val n = batch { removeOrphans() }
                if (n == 0) break
                orphans += n
            }
            var after = 0L
            while (true) {
                val ids = batch {
                    // One chunk: the frozen list is far below the bound, so the keyset order holds.
                    chunkedIn(RETIRED_SOURCES) { dao.legacyRowsAfter(after, it, BATCH) }.also { rows.byIds(it) }
                }
                if (ids.isEmpty()) break
                deleted += ids.size
                after = ids.last()
            }
        }
        if (!ok) return Outcome(deleted, orphans, failed = 1, completed = false)
        dataStore.edit { it[DONE] = true }
        Log.i(TAG, "Legacy event-row cleanup removed $deleted row(s) and $orphans orphaned signal(s)' members")
        return Outcome(deleted, orphans, failed = 0, completed = true)
    }

    /** One transaction under the scan lock (taken outside it, never inside). */
    private suspend fun <T> batch(block: suspend () -> T): T = lock.mutex.withLock { db.withTransaction { block() } }

    /** Members of up to [BATCH] gone signals, and the fact pins they held. */
    private suspend fun removeOrphans(): Int {
        val signals = dao.orphanSignalIds(BATCH)
        if (signals.isEmpty()) return 0
        val pins = chunkedIn(signals) { members.factRefsOf(it) }
        chunkedEach(signals) { members.deleteForSignals(it) }
        store.releaseUnpinned(pins)
        return signals.size
    }

    @Suppress("TooGenericExceptionCaught") // a failed batch must never crash a launch
    private suspend fun attempt(block: suspend () -> Unit): Boolean = try {
        block()
        true
    } catch (c: CancellationException) {
        throw c
    } catch (e: Exception) {
        Log.w(TAG, "Legacy event-row cleanup batch failed; retried next launch", e)
        false
    }

    companion object {
        private const val TAG = "LegacyEventRowCleanup"
        const val BATCH = 200
        private val DONE = booleanPreferencesKey("legacy_event_row_cleanup_done")

        /**
         * Frozen: the `source` of every retired event adapter's rows (C3). Intrusion-log DNS,
         * connect and security rows; live usage rows; the bug-report AppOps, battery-daily,
         * ADB-keys and install-time module rows. Never extended: new producers never write rows.
         * Derived at base a258be57 from the six producer sites (reviewed in C3): the
         * `ImportedDnsEvent` / `NetworkTelemetry` / `SecurityLogEvent` adapters (`intrusion_log`),
         * the `UsageEvent` adapter (`usage_stats`), `AppOpsModule` (`appops`), `BatteryDailyModule`
         * (`battery_daily`), `AdbKeysModule.SERVICE` (`adb_audit`) and
         * `InstallTimeModule.parseSection` (`bugreport`). The adapters are deleted, so the test
         * that pins this list can only be a change detector.
         */
        val RETIRED_SOURCES: List<String> =
            listOf("intrusion_log", "usage_stats", "appops", "battery_daily", "adb_audit", "bugreport")
    }
}
