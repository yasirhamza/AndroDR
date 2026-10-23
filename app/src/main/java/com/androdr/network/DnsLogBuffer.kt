package com.androdr.network

import android.util.Log
import com.androdr.data.db.FeedHealthDao
import com.androdr.data.model.DnsEvent
import com.androdr.data.model.FeedHealth
import com.androdr.ioc.FeedHealthRecorder
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch

/** Where [DnsLogBuffer] reports that it had to give up events, and that it caught up again. */
internal interface DnsBufferHealth {
    /** [count] oldest events were discarded because the buffer was full while flushes kept failing. */
    suspend fun onDropped(count: Int)

    /** A flush succeeded after one or more failures. */
    suspend fun onRecovered()
}

/**
 * Records [DnsBufferHealth] as the `dns_event_log` row of `feed_health`, so a DNS log that
 * silently lost events shows up beside the other health signals. Never throws.
 */
internal class DnsBufferHealthRecorder(
    private val dao: FeedHealthDao,
    private val now: () -> Long = System::currentTimeMillis,
) : DnsBufferHealth {

    @Suppress("TooGenericExceptionCaught")
    override suspend fun onDropped(count: Int) {
        try {
            val prior = dao.get(FeedHealthRecorder.FEED_DNS_EVENT_LOG)
            dao.upsert(
                FeedHealth(
                    feedId = FeedHealthRecorder.FEED_DNS_EVENT_LOG,
                    lastAttemptAt = now(),
                    lastSuccessAt = prior?.lastSuccessAt ?: 0L,
                    lastError = "dropped $count DNS events (database unavailable)",
                    consecutiveFailures = (prior?.consecutiveFailures ?: 0) + 1,
                ),
            )
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            Log.w(TAG, "health warning not recorded: ${e.message}")
        }
    }

    @Suppress("TooGenericExceptionCaught")
    override suspend fun onRecovered() {
        try {
            if (dao.get(FeedHealthRecorder.FEED_DNS_EVENT_LOG) == null) return
            val t = now()
            dao.upsert(FeedHealth(FeedHealthRecorder.FEED_DNS_EVENT_LOG, t, t, null, 0))
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            Log.w(TAG, "recovery not recorded: ${e.message}")
        }
    }

    private companion object {
        const val TAG = "DnsBufferHealth"
    }
}

/**
 * In-memory buffer of [DnsEvent]s flushed to the store in batches (replaces the old "one Room
 * transaction per DNS query" hot path).
 *
 * A failed flush puts its batch back in front of newer events and the next attempt waits twice as
 * long as the last ([INITIAL_BACKOFF_MS] up to [MAX_BACKOFF_MS]); a success resets the wait. While
 * flushes fail the buffer is held to [maxBuffered] events: the oldest beyond it are dropped and
 * reported to [health], so a long database outage cannot grow the heap without bound.
 *
 * Thread model: [add] is called from the VPN read loop (single-threaded). The flush runs on the
 * periodic coroutine (and on a full buffer). Buffer and failure state are guarded by `synchronized`;
 * one flush runs at a time.
 */
internal class DnsLogBuffer(
    private val scope: CoroutineScope,
    private val flush: suspend (List<DnsEvent>) -> Unit,
    private val health: DnsBufferHealth,
    private val maxSize: Int = 100,
    private val maxBuffered: Int = MAX_BUFFERED,
    private val flushIntervalMs: Long = 2_000L,
) {
    private val lock = Any()
    private val buffer = ArrayList<DnsEvent>(128)
    private var flushJob: Job? = null
    private var failures = 0
    private var flushing = false
    private var unreportedDrops = 0

    fun start() {
        flushJob = scope.launch {
            while (scope.isActive) {
                delay(nextDelayMs())
                flushNow()
            }
        }
    }

    fun stop() {
        flushJob?.cancel()
        flushJob = null
    }

    /**
     * Cancels the periodic flush job and runs one final flush *synchronously*. Called
     * from [DnsVpnService.stopVpn] inside `runBlocking { withTimeoutOrNull(...) }` so
     * the last batch of events is persisted before the service scope is cancelled.
     */
    suspend fun flushAndStop() {
        stop()
        flushNow()
    }

    fun add(event: DnsEvent) {
        val shouldFlushImmediately: Boolean
        synchronized(lock) {
            buffer.add(event)
            // A full buffer flushes at once only while flushes work; in backoff the periodic loop retries.
            shouldFlushImmediately = buffer.size >= maxSize && failures == 0
            trimLocked()
        }
        if (shouldFlushImmediately) {
            scope.launch { flushNow() }
        }
    }

    /** Events waiting to be flushed (tests and diagnostics). */
    internal fun pending(): Int = synchronized(lock) { buffer.size }

    /** The delay before the next periodic flush: the interval, or the current backoff. */
    private fun nextDelayMs(): Long = synchronized(lock) {
        if (failures == 0) flushIntervalMs else backoffMs(failures)
    }

    @Suppress("TooGenericExceptionCaught")
    private suspend fun flushNow() {
        val snapshot: List<DnsEvent>
        synchronized(lock) {
            if (flushing || buffer.isEmpty()) return
            flushing = true
            snapshot = buffer.toList()
            buffer.clear()
        }
        try {
            flush(snapshot)
            val recovered = synchronized(lock) { (failures > 0).also { failures = 0 } }
            if (recovered) health.onRecovered()
            reportDrops()
        } catch (e: CancellationException) {
            synchronized(lock) {
                buffer.addAll(0, snapshot)
                trimLocked()
            }
            throw e
        } catch (e: Exception) {
            Log.w(TAG, "flush failed: ${e.message}")
            synchronized(lock) {
                failures++
                buffer.addAll(0, snapshot)
                trimLocked()
            }
            reportDrops()
        } finally {
            synchronized(lock) { flushing = false }
        }
    }

    /** Drops the oldest events beyond [maxBuffered] and counts them for [reportDrops]. Caller holds [lock]. */
    private fun trimLocked() {
        val excess = buffer.size - maxBuffered
        if (excess <= 0) return
        buffer.subList(0, excess).clear()
        unreportedDrops += excess
    }

    /** Tells [health] about events dropped since the last report (the health write is a suspend call). */
    private suspend fun reportDrops() {
        val n = synchronized(lock) { unreportedDrops.also { unreportedDrops = 0 } }
        if (n > 0) health.onDropped(n)
    }

    companion object {
        private const val TAG = "DnsLogBuffer"

        /** Upper bound on events held while the database keeps failing. */
        const val MAX_BUFFERED = 5_000
        const val INITIAL_BACKOFF_MS = 2_000L
        const val MAX_BACKOFF_MS = 60_000L

        /** Wait after [failures] consecutive failed flushes: 2 s, 4 s, 8 s ... capped at 60 s. */
        fun backoffMs(failures: Int): Long {
            val shift = (failures - 1).coerceIn(0, MAX_SHIFT)
            return (INITIAL_BACKOFF_MS shl shift).coerceAtMost(MAX_BACKOFF_MS)
        }

        private const val MAX_SHIFT = 10
    }
}
