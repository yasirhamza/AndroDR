package com.androdr.ui.history

import android.net.Uri
import android.util.Log
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.androdr.data.model.ScanResult
import com.androdr.data.repo.FindingsRepository
import com.androdr.data.repo.DeleteResult
import com.androdr.data.repo.ScanLock
import com.androdr.data.repo.ScanRepository
import com.androdr.reporting.ExportEstimate
import com.androdr.reporting.ExportMode
import com.androdr.reporting.ReportExporter
import com.androdr.reporting.ReportSummary
import com.androdr.scanner.ScanOrchestrator
import dagger.hilt.android.lifecycle.HiltViewModel
import androidx.paging.PagingData
import androidx.paging.cachedIn
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.mapLatest
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.launch
import javax.inject.Inject

@HiltViewModel
@Suppress("TooManyFunctions") // the sheet, export, delete and selection actions share the history state
class HistoryViewModel @Inject constructor(
    private val repository: ScanRepository,
    private val reportExporter: ReportExporter,
    private val findings: FindingsRepository,
    scanLock: ScanLock,
) : ViewModel() {

    /**
     * False while a scan or import runs ([ScanLock.writerRunning]): delete and "Clear all" would be
     * refused, so the screen disables them.
     */
    val deleteEnabled: StateFlow<Boolean> = scanLock.writerRunning.map { !it }
        .stateIn(viewModelScope, SharingStarted.Eagerly, !scanLock.writerRunning.value)

    /** Full scan history, newest first, keyset-paged (no cap, spec §5.5). */
    val scans: Flow<PagingData<ScanResult>> = repository.pagedScans().cachedIn(viewModelScope)

    /** False when no scan is listed (the empty state). */
    val hasScans: StateFlow<Boolean> = repository.hasScans
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5_000), true)

    private val _selectedScan = MutableStateFlow<ScanResult?>(null)

    /** The scan currently selected for the detail view. */
    val selectedScan: StateFlow<ScanResult?> = _selectedScan.asStateFlow()

    /**
     * The diff between [selectedScan] and the scan that immediately preceded it
     * in the history list (the next oldest COMPLETE scan, [ScanRepository.previousOf]).
     * Null when no scan is selected or the selected scan has no predecessor.
     *
     * The selected scan is the NEWER one: [ScanOrchestrator.computeDiff] takes
     * `(newer, older)` in that order. Passing them the other way round silently
     * inverts the whole section — new risks render as resolved and resolved
     * risks as new. Computed from rule counts in SQL with a bounded sample
     * ([ScanOrchestrator.boundedDiff]), so selecting a 100k-finding import reads no whole scan.
     */
    @OptIn(ExperimentalCoroutinesApi::class)
    val selectedDiff: StateFlow<ScanOrchestrator.ScanDiff?> = _selectedScan
        .mapLatest { selected -> selected?.let { diffWithPredecessor(it) } }
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5_000), null)

    @Suppress("TooGenericExceptionCaught") // a diff that cannot be read is not shown, never a crash
    private suspend fun diffWithPredecessor(selected: ScanResult): ScanOrchestrator.ScanDiff? = try {
        repository.previousOf(selected)?.let { older -> ScanOrchestrator.boundedDiff(findings, selected, older) }
    } catch (e: CancellationException) {
        throw e
    } catch (e: Exception) {
        Log.w(TAG, "diff read failed", e)
        null
    }

    /** Emits a [Uri] when a report is ready to share; null when idle or after consumption. */
    private val _shareUri = MutableStateFlow<Uri?>(null)
    val shareUri: StateFlow<Uri?> = _shareUri.asStateFlow()

    /** Whether a report export is currently in progress. */
    private val _exporting = MutableStateFlow(false)
    val exporting: StateFlow<Boolean> = _exporting.asStateFlow()

    /** True after an export failed (nothing was shared); the screen says so. */
    private val _exportFailed = MutableStateFlow(false)
    val exportFailed: StateFlow<Boolean> = _exportFailed.asStateFlow()

    fun dismissExportFailed() { _exportFailed.value = false }

    /** The scan currently shown in the detail bottom sheet; null when sheet is hidden. */
    private val _sheetScan = MutableStateFlow<ScanResult?>(null)
    val sheetScan: StateFlow<ScanResult?> = _sheetScan.asStateFlow()

    /**
     * The sheet's summary of [sheetScan] (spec §7: the History sheet shows a summary; the full
     * report is exported through [ReportExporter]). Null while it loads.
     */
    private val _sheetSummary = MutableStateFlow<ReportSummary?>(null)
    val sheetSummary: StateFlow<ReportSummary?> = _sheetSummary.asStateFlow()

    /** True when the sheet's summary could not be read. */
    private val _sheetFailed = MutableStateFlow(false)
    val sheetFailed: StateFlow<Boolean> = _sheetFailed.asStateFlow()

    /** What exporting the scan in the export dialog would carry; null while it loads. */
    private val _exportEstimate = MutableStateFlow<ExportEstimate?>(null)
    val exportEstimate: StateFlow<ExportEstimate?> = _exportEstimate.asStateFlow()

    /** True when the estimate could not be read; the dialog says the size is unknown. */
    private val _estimateFailed = MutableStateFlow(false)
    val estimateFailed: StateFlow<Boolean> = _estimateFailed.asStateFlow()

    /** The scan whose estimate the open dialog is waiting for. */
    private var estimateScanId: Long? = null

    fun selectScan(scan: ScanResult) {
        _selectedScan.value = scan
    }

    /** Opens the detail bottom sheet for [scan] and loads its summary (off the main thread). */
    @Suppress("TooGenericExceptionCaught") // any read failure is shown, never a crash
    fun openSheet(scan: ScanResult) {
        _sheetScan.value = scan
        _sheetSummary.value = null
        _sheetFailed.value = false
        viewModelScope.launch {
            try {
                val summary = reportExporter.summary(scan)
                if (_sheetScan.value?.id == scan.id) _sheetSummary.value = summary
            } catch (e: CancellationException) {
                throw e
            } catch (e: Exception) {
                Log.w(TAG, "summary read failed", e)
                if (_sheetScan.value?.id == scan.id) _sheetFailed.value = true
            }
        }
    }

    /** Closes the detail bottom sheet. */
    fun closeSheet() {
        _sheetScan.value = null
        _sheetSummary.value = null
        _sheetFailed.value = false
    }

    /** Loads what exporting [scan] would carry, for the export dialog. */
    @Suppress("TooGenericExceptionCaught") // an unknown estimate is shown as unknown
    fun loadExportEstimate(scan: ScanResult) {
        _exportEstimate.value = null
        _estimateFailed.value = false
        estimateScanId = scan.id
        viewModelScope.launch {
            try {
                val estimate = reportExporter.exportEstimate(scan)
                // A slower estimate for an earlier dialog must not land in this one.
                if (estimateScanId == scan.id) _exportEstimate.value = estimate
            } catch (e: CancellationException) {
                throw e
            } catch (e: Exception) {
                Log.w(TAG, "export estimate failed", e)
                if (estimateScanId == scan.id) _estimateFailed.value = true
            }
        }
    }

    /**
     * Exports [scan] to a cached text file and emits its [FileProvider] URI via
     * [shareUri]. The Composable observes [shareUri] and fires the share intent.
     */
    @Suppress("TooGenericExceptionCaught") // a failed export is reported, never a crash
    fun exportReport(scan: ScanResult, mode: ExportMode = ExportMode.BOTH) {
        if (_exporting.value) return
        viewModelScope.launch {
            _exporting.value = true
            try {
                _shareUri.value = reportExporter.export(scan, mode)
            } catch (e: CancellationException) {
                throw e
            } catch (e: Exception) {
                Log.w(TAG, "report export failed", e)
                _exportFailed.value = true
            } finally {
                _exporting.value = false
            }
        }
    }

    /** Call after the share intent has been launched to reset the URI state. */
    fun onShareConsumed() {
        _shareUri.value = null
    }

    private val _showDeleteConfirm = MutableStateFlow<Long?>(null)
    val showDeleteConfirm: StateFlow<Long?> = _showDeleteConfirm.asStateFlow()

    private val _showClearAllConfirm = MutableStateFlow(false)
    val showClearAllConfirm: StateFlow<Boolean> = _showClearAllConfirm.asStateFlow()

    fun requestDeleteScan(scanId: Long) { _showDeleteConfirm.value = scanId }
    fun dismissDeleteConfirm() { _showDeleteConfirm.value = null }

    /**
     * True after a delete was refused because a scan or import holds the writer lock (or the lock
     * stayed busy): nothing was deleted, and the screen says so instead of silently doing nothing.
     */
    private val _deleteRefused = MutableStateFlow(false)
    val deleteRefused: StateFlow<Boolean> = _deleteRefused.asStateFlow()

    fun dismissDeleteRefused() { _deleteRefused.value = false }

    /**
     * True after a delete or "Clear all" threw (for example a full disk): the screen says it did not
     * finish instead of the app crashing (review I1). A delete that failed after its first step leaves
     * the scan hidden (`DELETING`) and the startup sweep finishes it.
     */
    private val _deleteFailed = MutableStateFlow(false)
    val deleteFailed: StateFlow<Boolean> = _deleteFailed.asStateFlow()

    fun dismissDeleteFailed() { _deleteFailed.value = false }

    /** Runs a delete; any failure but cancellation is reported, never thrown (review I1). */
    @Suppress("TooGenericExceptionCaught")
    private suspend fun deleting(run: suspend () -> DeleteResult): DeleteResult? = try {
        run()
    } catch (e: CancellationException) {
        throw e
    } catch (e: Exception) {
        Log.w(TAG, "delete failed", e)
        _deleteFailed.value = true
        null
    }

    fun confirmDeleteScan() {
        val id = _showDeleteConfirm.value ?: return
        _showDeleteConfirm.value = null
        viewModelScope.launch {
            when (deleting { repository.deleteScan(id) }) {
                DeleteResult.ScanRunning -> _deleteRefused.value = true
                DeleteResult.Done -> if (_selectedScan.value?.id == id) _selectedScan.value = null
                null -> Unit
            }
        }
    }

    fun requestClearAll() { _showClearAllConfirm.value = true }
    fun dismissClearAll() { _showClearAllConfirm.value = false }

    fun confirmClearAll() {
        _showClearAllConfirm.value = false
        viewModelScope.launch {
            // A refused "Clear all" is handled first and leaves everything in place, the selection
            // included; only a delete that ran empties the selection.
            when (deleting { repository.deleteAllScans() }) {
                DeleteResult.ScanRunning -> _deleteRefused.value = true
                DeleteResult.Done -> _selectedScan.value = null
                null -> Unit
            }
        }
    }

    /**
     * A History row's counts: the stored findings shown (informational excluded, as the import screen
     * counts them) and how many of the scan's findings could not be saved (its `triggeredCount` minus
     * the stored ones), so the row stays honest after the import card is dismissed.
     */
    @Suppress("TooGenericExceptionCaught") // an unreadable count is not shown, never a crash
    suspend fun rowCounts(scan: ScanResult): HistoryRowCounts? = try {
        val counts = findings.rowCounts(scan.id)
        HistoryRowCounts(counts.shown, (scan.triggeredCount - counts.stored).coerceAtLeast(0))
    } catch (e: CancellationException) {
        throw e
    } catch (e: Exception) {
        Log.w(TAG, "row count read failed", e)
        null
    }

    private companion object {
        const val TAG = "HistoryViewModel"
    }
}

/** What a History row says: [shown] stored findings, and [unsaved] that could not be saved. */
data class HistoryRowCounts(val shown: Int, val unsaved: Int)
