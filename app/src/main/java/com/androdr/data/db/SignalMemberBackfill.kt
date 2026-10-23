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
import com.androdr.di.StoreDataStore
import com.androdr.sigma.Row
import com.androdr.sigma.SigmaCorrelationEngine
import com.androdr.sigma.SignalIdentity
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.sync.withLock
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import javax.inject.Inject
import javax.inject.Singleton

/** A pre-Phase-C signal row that still carries its member list in `details`. */
data class LegacySignal(val id: Long, val ruleId: String, val details: String)

/**
 * The one-time backfill's reads and rewrite (spec §5.4). Writer-side: it reads every signal row,
 * visible or not, so it is on the Q1 gate's writer allow-list.
 */
@Dao
interface SignalMemberBackfillDao {

    @Query(
        "SELECT id, ruleId, details FROM forensic_timeline WHERE kind = 'signal' " +
            "AND source = 'sigma_correlation_engine' AND details LIKE '%$LEGACY_KEY%' " +
            "AND id > :afterId ORDER BY id LIMIT :size"
    )
    suspend fun legacyAfter(afterId: Long, size: Int): List<LegacySignal>

    @Query("SELECT COUNT(*) FROM forensic_timeline WHERE id = :id")
    suspend fun signalExists(id: Long): Int

    @Query("UPDATE forensic_timeline SET details = :details, correlationId = :correlationId WHERE id = :id")
    suspend fun rewrite(id: Long, details: String, correlationId: String)
}

/** The legacy details key — named only in this file (gate: `MemberIdsConsumersGateTest`). */
internal const val LEGACY_KEY = "member_event_ids"

/**
 * Moves legacy signals' member lists into `signal_member` (spec §5.4), once, run by `StartupSweep`.
 *
 * Keyset by row id, [BATCH] signals per transaction, each batch under [ScanLock.mutex] (taken
 * outside the transaction). Per signal: confirm the row still exists, parse its ids with
 * `toLongOrNull` (non-numeric entries dropped), `INSERT OR IGNORE` the members, then rewrite
 * `details` without the list (adding `member_count`) and `correlationId` to the canonical hash. A
 * row that fails is logged, counted and left untouched, so its only copy of the list is never lost.
 * The done flag is set when one keyset pass reaches the end; failed rows do not block it. Until then
 * a legacy cluster shows its members as missing; nothing blocks the Timeline.
 */
@Singleton
class SignalMemberBackfill @Inject constructor(
    private val db: AppDatabase,
    private val dao: SignalMemberBackfillDao,
    private val members: SignalMemberDao,
    private val lock: ScanLock,
    @StoreDataStore private val dataStore: DataStore<Preferences>,
) {
    /** What one run did; [completed] is false when the flag was already set (nothing ran). */
    data class Outcome(val migrated: Int, val failed: Int, val completed: Boolean)

    suspend fun isDone(): Boolean = dataStore.data.first()[DONE] == true

    suspend fun run(): Outcome {
        if (isDone()) return Outcome(0, 0, completed = false)
        var after = 0L
        var migrated = 0
        var failed = 0
        while (true) {
            val batch = lock.mutex.withLock {
                db.withTransaction {
                    val signals = dao.legacyAfter(after, BATCH)
                    var ok = 0
                    var bad = 0
                    for (signal in signals) {
                        when (migrate(signal)) {
                            Step.MIGRATED -> ok++
                            Step.FAILED -> bad++
                            Step.GONE -> Unit
                        }
                    }
                    migrated += ok
                    failed += bad
                    signals.lastOrNull()?.id
                }
            } ?: break
            after = batch
        }
        dataStore.edit { it[DONE] = true }
        if (failed > 0) Log.w(TAG, "Signal member backfill left $failed malformed signal(s) untouched")
        return Outcome(migrated, failed, completed = true)
    }

    private enum class Step { MIGRATED, FAILED, GONE }

    @Suppress("TooGenericExceptionCaught") // one bad row must never crash a launch or lose its list
    private suspend fun migrate(signal: LegacySignal): Step {
        if (dao.signalExists(signal.id) == 0) return Step.GONE
        return try {
            val obj = json.parseToJsonElement(signal.details).jsonObject
            val list = requireNotNull(obj[LEGACY_KEY]) { "no member list" }.jsonPrimitive.content
            val ids = list.split(',').mapNotNull { it.trim().toLongOrNull() }.distinct()
            members.insertAll(ids.map { SignalMember(signal.id, SignalMember.KIND_ROW, it) })
            val rewritten = JsonObject(
                obj - LEGACY_KEY + (SigmaCorrelationEngine.MEMBER_COUNT to JsonPrimitive(ids.size))
            )
            val ruleId = signal.ruleId.ifEmpty { obj["rule_id"]?.jsonPrimitive?.content.orEmpty() }
            dao.rewrite(signal.id, rewritten.toString(), SignalIdentity.correlationId(ruleId, ids.map(::Row)))
            Step.MIGRATED
        } catch (c: CancellationException) {
            throw c
        } catch (e: Exception) {
            Log.w(TAG, "Signal ${signal.id}: member list not migrated, row left untouched", e)
            Step.FAILED
        }
    }

    companion object {
        private const val TAG = "SignalMemberBackfill"
        const val BATCH = 200
        private val DONE = booleanPreferencesKey("signal_member_backfill_done")
        private val json = Json { isLenient = false }
    }
}
