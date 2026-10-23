package com.androdr.network

import android.util.Log
import com.androdr.data.model.DnsEvent
import com.androdr.data.store.DnsDropLog
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.cancelAndJoin
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext

/** Where [DnsLogBuffer] reports events it gave up on. May throw: the buffer then keeps the count and retries. */
internal fun interface DnsBufferHealth {
    /** [count] events were discarded (buffer full while flushes failed, or still pending at shutdown). */
    suspend fun onDropped(count: Int)
}

/** Records drops in [DnsDropLog] (DataStore, outside the database that is likely failing). */
internal class DnsDropRecorder(
    private val log: DnsDropLog,
    private val now: () -> Long = System::currentTimeMillis,
) : DnsBufferHealth {
    override suspend fun onDropped(count: Int) = log.record(count, now())
}

/**
 * In-memory buffer of [DnsEvent]s flushed to the store in batches (replaces the old "one Room
 * transaction per DNS query" hot path).
 *
 * A failed flush puts its batch back in front of newer events and the next attempt waits twice as
 * long as the last ([INITIAL_BACKOFF_MS] up to [MAX_BACKOFF_MS]); a success resets the wait. The
 * buffer is held to [maxBuffered] events: the oldest beyond it are dropped and reported to [health]
 * (a report that fails is kept and retried after the next successful flush, so a drop made while the
 * database was down is recorded once it is back).
 *
 * One flush runs at a time, under [flushLock]; the periodic and full-buffer paths skip when one is
 * running, while [flushAndStop] waits for it and then drains what is left.
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
    private val flushLock = Mutex()
    private val buffer = ArrayList<DnsEvent>(128)
    private var flushJob: Job? = null
    private var failures = 0
    private var unreportedDrops = 0
    private var stopped = false

    fun start() {
        flushJob = scope.launch {
            while (scope.isActive) {
                delay(nextDelayMs())
                flushIfIdle()
            }
        }
    }

    fun stop() {
        flushJob?.cancel()
        flushJob = null
    }

    /**
     * Called from [DnsVpnService.stopVpn] inside `runBlocking { withTimeoutOrNull(...) }`. Stops the
     * periodic job, waits for a flush already in progress to finish, then makes one last attempt at
     * everything buffered. Whatever still cannot be stored is reported as dropped (not silently lost).
     */
    suspend fun flushAndStop() {
        synchronized(lock) { stopped = true }
        try {
            flushJob?.cancelAndJoin()
            flushJob = null
            flushLock.withLock { flushOnce() }
        } finally {
            withContext(NonCancellable) { dropRemaining() }
        }
    }

    fun add(event: DnsEvent) {
        val shouldFlushImmediately: Boolean
        synchronized(lock) {
            if (stopped) {
                unreportedDrops++
                return
            }
            buffer.add(event)
            // A full buffer flushes at once only while flushes work; in backoff the periodic loop retries.
            shouldFlushImmediately = buffer.size >= maxSize && failures == 0
            trimLocked()
        }
        if (shouldFlushImmediately) {
            scope.launch { flushIfIdle() }
        }
    }

    /** Events waiting to be flushed (tests and diagnostics). */
    internal fun pending(): Int = synchronized(lock) { buffer.size }

    /** The delay before the next periodic flush: the interval, or the current backoff. */
    private fun nextDelayMs(): Long = synchronized(lock) {
        if (failures == 0) flushIntervalMs else backoffMs(failures)
    }

    private suspend fun flushIfIdle() {
        if (!flushLock.tryLock()) return
        try {
            flushOnce()
        } finally {
            flushLock.unlock()
        }
    }

    /** One flush attempt of everything buffered. Caller holds [flushLock]. */
    @Suppress("TooGenericExceptionCaught")
    private suspend fun flushOnce() {
        val snapshot: List<DnsEvent>
        synchronized(lock) {
            if (buffer.isEmpty()) return
            snapshot = buffer.toList()
            buffer.clear()
        }
        val stored = try {
            // A batch that has started is allowed to finish: cancelling an insert halfway would
            // re-queue rows that may already be stored.
            withContext(NonCancellable) { flush(snapshot) }
            true
        } catch (e: Exception) {
            Log.w(TAG, "flush failed: ${e.message}")
            false
        }
        synchronized(lock) {
            if (stored) {
                failures = 0
            } else {
                failures++
                buffer.addAll(0, snapshot)
                trimLocked()
            }
        }
        reportDrops()
    }

    /** Discards what is still buffered after the final attempt, and reports it. */
    private suspend fun dropRemaining() {
        synchronized(lock) {
            unreportedDrops += buffer.size
            buffer.clear()
        }
        reportDrops()
    }

    /** Drops the oldest events beyond [maxBuffered] and counts them for [reportDrops]. Caller holds [lock]. */
    private fun trimLocked() {
        val excess = buffer.size - maxBuffered
        if (excess <= 0) return
        buffer.subList(0, excess).clear()
        unreportedDrops += excess
    }

    /** Tells [health] about events dropped since the last report; a failed report is kept for next time. */
    @Suppress("TooGenericExceptionCaught")
    private suspend fun reportDrops() {
        val n = synchronized(lock) { unreportedDrops.also { unreportedDrops = 0 } }
        if (n == 0) return
        try {
            health.onDropped(n)
        } catch (e: CancellationException) {
            synchronized(lock) { unreportedDrops += n }
            throw e
        } catch (e: Exception) {
            Log.w(TAG, "drop report failed, will retry: ${e.message}")
            synchronized(lock) { unreportedDrops += n }
        }
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
