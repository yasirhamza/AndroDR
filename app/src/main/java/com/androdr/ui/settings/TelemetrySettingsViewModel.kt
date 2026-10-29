package com.androdr.ui.settings

import android.util.Log
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.androdr.data.repo.SettingsRepository
import com.androdr.data.store.StorageSummary
import com.androdr.data.store.TelemetryReader
import com.androdr.data.store.TelemetryRetention
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.launch
import javax.inject.Inject

/** What "Delete old snapshot telemetry now" last did. */
sealed interface TelemetryCleanup {
    data object Idle : TelemetryCleanup
    data object Running : TelemetryCleanup

    /** Retention ran to the end and removed [observationsRemoved] observations. */
    data class Done(val observationsRemoved: Long) : TelemetryCleanup

    /** A scan or import held the writer lock, so retention stopped; try again when it finishes. */
    data object Busy : TelemetryCleanup
    data object Failed : TelemetryCleanup
}

/**
 * Settings' telemetry card (spec §8.2): the store's size by kind, "Keep snapshot telemetry for the
 * last N scans" ([SettingsRepository.snapshotRetentionScans], [RETENTION_RANGE], default 20), and
 * "Delete old snapshot telemetry now", which runs the same [TelemetryRetention.run] that
 * `IocUpdateWorker` runs after the IOC fetch (its batches take `scanMutex.tryLock()` outside their
 * Room transactions), then re-reads the storage figures.
 */
@HiltViewModel
class TelemetrySettingsViewModel @Inject constructor(
    private val reader: TelemetryReader,
    private val settings: SettingsRepository,
    private val retention: TelemetryRetention,
) : ViewModel() {

    private val _storage = MutableStateFlow<StorageSummary?>(null)

    /** The store's size by kind; null while it loads or when it could not be read. */
    val storage: StateFlow<StorageSummary?> = _storage.asStateFlow()

    val retentionScans: StateFlow<Int> = settings.snapshotRetentionScans
        .stateIn(viewModelScope, SharingStarted.Eagerly, SettingsRepository.DEFAULT_SNAPSHOT_RETENTION_SCANS)

    private val _cleanup = MutableStateFlow<TelemetryCleanup>(TelemetryCleanup.Idle)
    val cleanup: StateFlow<TelemetryCleanup> = _cleanup.asStateFlow()

    init {
        viewModelScope.launch { refreshStorage() }
    }

    /** Stores [scans], clamped to [RETENTION_RANGE]; the next retention run (or "Delete now") applies it. */
    fun setRetentionScans(scans: Int) {
        viewModelScope.launch {
            settings.setSnapshotRetentionScans(scans.coerceIn(RETENTION_RANGE.first, RETENTION_RANGE.last))
        }
    }

    /** Runs retention now; the outcome is reported through [cleanup], never thrown. */
    @Suppress("TooGenericExceptionCaught") // a failed run is reported, never a crash
    fun deleteOldSnapshotsNow() {
        if (_cleanup.value == TelemetryCleanup.Running) return
        _cleanup.value = TelemetryCleanup.Running
        viewModelScope.launch {
            _cleanup.value = try {
                val outcome = retention.run()
                if (outcome.completed) TelemetryCleanup.Done(outcome.observationsRemoved) else TelemetryCleanup.Busy
            } catch (e: CancellationException) {
                throw e
            } catch (e: Exception) {
                Log.w(TAG, "retention run failed", e)
                TelemetryCleanup.Failed
            }
            refreshStorage()
        }
    }

    fun dismissCleanup() {
        if (_cleanup.value != TelemetryCleanup.Running) _cleanup.value = TelemetryCleanup.Idle
    }

    @Suppress("TooGenericExceptionCaught") // unreadable figures are not shown, never a crash
    private suspend fun refreshStorage() {
        _storage.value = try {
            reader.storage()
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            Log.w(TAG, "storage read failed", e)
            null
        }
    }

    companion object {
        private const val TAG = "TelemetrySettings"

        /** The slider's range (spec §8.2): at least 5 scans, at most 100. */
        val RETENTION_RANGE = 5..100
    }
}
