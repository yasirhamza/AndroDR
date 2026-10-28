package com.androdr.ui.dashboard

import android.util.Log
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import androidx.paging.PagingData
import androidx.paging.cachedIn
import com.androdr.data.repo.AlertGroup
import com.androdr.data.repo.AlertGroupRef
import com.androdr.data.repo.FindingsRepository
import com.androdr.ui.security.ConfirmResult
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import javax.inject.Inject

/**
 * The Dashboard's open-alerts card (spec §5.4): the OPEN alerts grouped by rule and
 * matched value (most recent activity first, paged), multi-select, and Close / Close selected. Every
 * close asks the device credential first ([close]'s `confirm`, the screen's `ConfirmCredential`) and
 * passes its result to [FindingsRepository.closeGroups], which refuses anything but a confirmed
 * credential (or a verified missing lock screen). Alerts stay open until a person closes them.
 */
@HiltViewModel
class DashboardAlertsViewModel @Inject constructor(
    private val findings: FindingsRepository,
) : ViewModel() {

    /** OPEN alerts grouped by rule and matched value, re-surfaced by latest activity, paged. */
    val groups: Flow<PagingData<AlertGroup>> = findings.openAlertGroups().cachedIn(viewModelScope)

    private val _selected = MutableStateFlow<Set<AlertGroupRef>>(emptySet())

    /** The groups selected for "Close selected" (each bounded to the alerts seen when selected). */
    val selected: StateFlow<Set<AlertGroupRef>> = _selected.asStateFlow()

    /** The groups the close dialog is for; null when it is not shown. */
    private val _pendingClose = MutableStateFlow<List<AlertGroupRef>?>(null)
    val pendingClose: StateFlow<List<AlertGroupRef>?> = _pendingClose.asStateFlow()

    /** The outcome of the last close, for the screen's message; null once shown. */
    private val _outcome = MutableStateFlow<CloseOutcome?>(null)
    val outcome: StateFlow<CloseOutcome?> = _outcome.asStateFlow()

    private val _closing = MutableStateFlow(false)
    val closing: StateFlow<Boolean> = _closing.asStateFlow()

    /** Selects or unselects a group (by rule and matched value; the newest selection's bound wins). */
    fun toggle(group: AlertGroupRef) {
        val current = _selected.value
        val same = current.filter { it.ruleId == group.ruleId && it.matchedValue == group.matchedValue }.toSet()
        _selected.value = if (same.isNotEmpty()) current - same else current + group
    }

    /** Opens the close dialog for one group (Close on a row). */
    fun requestClose(group: AlertGroupRef) {
        _pendingClose.value = listOf(group)
    }

    /** Opens the close dialog for the selection (Close selected), all under one confirmation. */
    fun requestCloseSelected() {
        if (_selected.value.isNotEmpty()) _pendingClose.value = _selected.value.toList()
    }

    fun dismissClose() {
        _pendingClose.value = null
    }

    fun outcomeShown() {
        _outcome.value = null
    }

    /**
     * Closes the pending groups: asks [confirm] (the device credential) first, then hands its result
     * to the repository, which closes nothing unless it is confirmed. A close that ran clears those
     * groups from the selection.
     */
    @Suppress("TooGenericExceptionCaught") // a failed close is reported as nothing closed, never a crash
    fun close(note: String?, confirm: suspend () -> ConfirmResult) {
        val groups = _pendingClose.value ?: return
        _pendingClose.value = null
        if (_closing.value) return
        _closing.value = true
        viewModelScope.launch {
            try {
                val result = confirm()
                val closed = findings.closeGroups(groups, note?.trim()?.takeIf { it.isNotEmpty() }, result)
                _outcome.value = when {
                    closed > 0 && result == ConfirmResult.NoSecureLock -> CloseOutcome.ClosedWithoutLock(closed)
                    closed > 0 -> CloseOutcome.Closed(closed)
                    else -> CloseOutcome.NothingClosed
                }
                if (closed > 0) _selected.value = _selected.value - groups.toSet()
            } catch (e: CancellationException) {
                throw e
            } catch (e: Exception) {
                Log.w(TAG, "closing alerts failed", e)
                _outcome.value = CloseOutcome.NothingClosed
            } finally {
                _closing.value = false
            }
        }
    }


    private companion object {
        const val TAG = "DashboardAlerts"
    }
}

/** What a close did, for the Dashboard's message. */
sealed interface CloseOutcome {
    data class Closed(val count: Int) : CloseOutcome

    /** Closed with no credential because the device has no secure lock screen (verified). */
    data class ClosedWithoutLock(val count: Int) : CloseOutcome

    /** Nothing closed: the credential was not confirmed (or the close failed). */
    data object NothingClosed : CloseOutcome
}
