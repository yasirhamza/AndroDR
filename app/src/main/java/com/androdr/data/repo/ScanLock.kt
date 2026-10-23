package com.androdr.data.repo

import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import javax.inject.Inject
import javax.inject.Singleton

/**
 * The store's single writer lock (`scanMutex`, spec §5.1–5.2).
 *
 * Only live scan and import sessions use [withWriter], which also raises [writerRunning];
 * retention, the backfill, `StartupSweep` and deletes take [mutex] directly and never set the flag.
 *
 * **Global rule:** [mutex] is acquired outside any Room transaction, never inside one.
 */
@Singleton
class ScanLock @Inject constructor() {
    val mutex = Mutex()

    private val running = MutableStateFlow(false)

    /** True only while a live scan or import session holds the lock through [withWriter]. */
    val writerRunning: StateFlow<Boolean> = running.asStateFlow()

    suspend fun <T> withWriter(block: suspend () -> T): T = mutex.withLock {
        running.value = true
        try {
            block()
        } finally {
            running.value = false
        }
    }
}
