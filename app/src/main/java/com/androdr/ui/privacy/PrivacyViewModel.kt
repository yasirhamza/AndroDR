package com.androdr.ui.privacy

import androidx.annotation.StringRes
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.androdr.R
import com.androdr.data.db.PrivacyDao
import com.androdr.data.model.NetworkStatus
import com.androdr.data.model.PrivacyAppResult
import com.androdr.data.model.PrivacyScan
import com.androdr.data.model.PrivacyTrackerEvidence
import com.androdr.data.repo.SettingsRepository
import com.androdr.privacy.AppPrivacyRow
import com.androdr.privacy.PrivacyRanking
import com.androdr.privacy.PrivacyScanProgress
import com.androdr.privacy.PrivacyScanRunner
import com.androdr.privacy.RowSection
import com.androdr.privacy.TrackerGroup
import com.androdr.privacy.model.RegistryState
import com.androdr.privacy.model.TrackerCategory
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.flatMapLatest
import kotlinx.coroutines.flow.flowOf
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.launch
import javax.inject.Inject

private data class Stored(
    val scan: PrivacyScan?,
    val results: List<PrivacyAppResult>,
    val evidence: List<PrivacyTrackerEvidence>,
)

sealed interface NetworkCoverage {
    data object Hidden : NetworkCoverage
    data object NoMonitor : NetworkCoverage
    data class Days(val days: Int) : NetworkCoverage
}

data class PrivacyUiState(
    val scan: PrivacyScan? = null,
    val sections: List<Pair<RowSection, List<AppPrivacyRow>>> = emptyList(),
    val byTracker: List<TrackerGroup> = emptyList(),
    val refused: Set<TrackerCategory> = emptySet(),
    val showSystemApps: Boolean = false,
    val progress: PrivacyScanProgress = PrivacyScanProgress.Idle,
    val registrySizeAtScan: Int? = null,
    val registryState: RegistryState = RegistryState.LOADING,
) {
    /** Run is offered only with a loaded registry and no scan in progress. */
    val canRun: Boolean
        get() = registryState == RegistryState.AVAILABLE && progress !is PrivacyScanProgress.Running

    /** "Could not be loaded" is said only of a failed load, never while the registry is still loading. */
    val showRegistryUnavailable: Boolean get() = registryState == RegistryState.UNAVAILABLE

    /** A line about incomplete network evidence, or null when it is complete. */
    @get:StringRes
    val networkNotice: Int?
        get() = when (scan?.networkStatus) {
            NetworkStatus.TRUNCATED.name -> R.string.privacy_network_truncated
            NetworkStatus.FAILED.name -> R.string.privacy_network_failed
            else -> null
        }

    /**
     * The coverage line. Only a COMPLETE or TRUNCATED network step has a meaningful day count; under FAILED the
     * runner stores 0 days, which must never read as "the monitor recorded nothing".
     */
    val networkCoverage: NetworkCoverage
        get() {
            val s = scan ?: return NetworkCoverage.Hidden
            val counted = s.networkStatus in setOf(NetworkStatus.COMPLETE.name, NetworkStatus.TRUNCATED.name)
            return when {
                !counted -> NetworkCoverage.Hidden
                s.dnsCoverageDays == 0 -> NetworkCoverage.NoMonitor
                else -> NetworkCoverage.Days(s.dnsCoverageDays)
            }
        }
}

/** The privacy screen's state. It never touches the tracker registry: the runner reports its availability. */
@OptIn(ExperimentalCoroutinesApi::class)
@HiltViewModel
class PrivacyViewModel @Inject constructor(
    dao: PrivacyDao,
    private val runner: PrivacyScanRunner,
    private val settings: SettingsRepository,
) : ViewModel() {

    private val _message = MutableStateFlow<Int?>(null)

    /** A one-shot string resource to show (snackbar), cleared by [messageShown]. */
    val message: StateFlow<Int?> = _message.asStateFlow()

    private val stored: Flow<PrivacyUiState> = combine(
        dao.latestCompleted().flatMapLatest { scan ->
            if (scan == null) {
                flowOf(Stored(null, emptyList(), emptyList()))
            } else {
                combine(dao.results(scan.id), dao.evidence(scan.id)) { r, e -> Stored(scan, r, e) }
            }
        },
        settings.refusedTrackerCategories,
        settings.privacyShowSystemApps,
    ) { (scan, results, evidence), refused, showSystem ->
        val sections = if (scan == null) {
            emptyList()
        } else {
            PrivacyRanking.rows(results, evidence, refused, showSystem)
        }
        PrivacyUiState(
            scan = scan,
            sections = sections,
            byTracker = PrivacyRanking.byTracker(sections.flatMap { it.second }),
            refused = refused,
            showSystemApps = showSystem,
            registrySizeAtScan = scan?.registrySize,
        )
    }

    val state: StateFlow<PrivacyUiState> = combine(stored, runner.progress, runner.registryState) { s, p, r ->
        s.copy(progress = p, registryState = r)
    }.stateIn(
        viewModelScope, SharingStarted.WhileSubscribed(STOP_TIMEOUT_MS),
        PrivacyUiState(progress = runner.progress.value, registryState = runner.registryState.value),
    )

    fun runScan() {
        if (!runner.start()) _message.value = R.string.privacy_running_elsewhere
    }

    fun setRefused(value: Set<TrackerCategory>) {
        viewModelScope.launch { settings.setRefusedTrackerCategories(value) }
    }

    fun setShowSystemApps(value: Boolean) {
        viewModelScope.launch { settings.setPrivacyShowSystemApps(value) }
    }

    fun deleteResults() {
        viewModelScope.launch {
            if (!runner.deleteAll()) _message.value = R.string.privacy_delete_refused
        }
    }

    fun messageShown() {
        _message.value = null
    }

    private companion object {
        const val STOP_TIMEOUT_MS = 5_000L
    }
}
