package com.androdr.ui.privacy

import android.net.Uri
import android.util.Log
import androidx.lifecycle.SavedStateHandle
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.androdr.privacy.EvidenceDetails
import com.androdr.privacy.PrivacyEvidenceReader
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import javax.inject.Inject

const val PRIVACY_EVIDENCE_ROUTE =
    "privacy/evidence/{${PrivacyEvidenceViewModel.ARG_PACKAGE}}/{${PrivacyEvidenceViewModel.ARG_TRACKER}}"

fun privacyEvidenceRoute(packageName: String, trackerId: Int): String =
    "privacy/evidence/${Uri.encode(packageName)}/$trackerId"

sealed interface EvidenceUiState {
    data object Loading : EvidenceUiState

    /** The latest completed scan no longer holds this app + tracker (replaced or deleted). */
    data object Gone : EvidenceUiState

    /** The read failed (a database error); nothing is claimed about the finding. */
    data object Unreadable : EvidenceUiState

    data class Loaded(val details: EvidenceDetails) : EvidenceUiState
}

/** The lookup times of one domain, read live from the DNS log; [domain] as recorded. [times] null = the read failed. */
data class LookupTimes(val domain: String, val times: List<Long>?)

/** Loads one finding's detail once, when the view opens; lookup times are read only when a domain is tapped. */
@HiltViewModel
class PrivacyEvidenceViewModel @Inject constructor(
    private val reader: PrivacyEvidenceReader,
    handle: SavedStateHandle,
) : ViewModel() {
    private val packageName: String = handle.get<String>(ARG_PACKAGE).orEmpty()
    private val trackerId: Int = handle.get<Int>(ARG_TRACKER) ?: NO_TRACKER

    private val _state = MutableStateFlow<EvidenceUiState>(EvidenceUiState.Loading)
    val state: StateFlow<EvidenceUiState> = _state.asStateFlow()

    private val _lookups = MutableStateFlow<LookupTimes?>(null)
    val lookups: StateFlow<LookupTimes?> = _lookups.asStateFlow()

    init {
        viewModelScope.launch {
            _state.value = try {
                reader.load(packageName, trackerId)?.let { EvidenceUiState.Loaded(it) } ?: EvidenceUiState.Gone
            } catch (c: CancellationException) {
                throw c
            } catch (e: Exception) {
                Log.w(TAG, "Privacy details unreadable: ${e.javaClass.simpleName}")
                EvidenceUiState.Unreadable
            }
        }
    }

    fun openLookups(domain: String) {
        viewModelScope.launch {
            val times = try {
                reader.recentLookups(packageName, domain)
            } catch (c: CancellationException) {
                throw c
            } catch (e: Exception) {
                Log.w(TAG, "Lookup times unreadable: ${e.javaClass.simpleName}")
                null
            }
            _lookups.value = LookupTimes(domain, times)
        }
    }

    fun closeLookups() {
        _lookups.value = null
    }

    companion object {
        private const val TAG = "PrivacyEvidence"
        const val ARG_PACKAGE = "packageName"
        const val ARG_TRACKER = "trackerId"
        private const val NO_TRACKER = -1
    }
}
