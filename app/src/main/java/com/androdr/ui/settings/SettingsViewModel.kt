package com.androdr.ui.settings

import android.util.Log
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.androdr.data.db.CertHashIocEntryDao
import com.androdr.data.db.DomainIocEntryDao
import com.androdr.data.db.IocEntryDao
import com.androdr.data.repo.SettingsRepository
import com.androdr.ioc.CertHashIocDatabase
import com.androdr.ioc.CertHashIocUpdater
import com.androdr.ioc.CveDatabase
import com.androdr.ioc.DomainIocUpdater
import com.androdr.ioc.KnownAppUpdater
import com.androdr.ioc.RemoteIocUpdater
import com.androdr.sigma.SigmaRuleEngine
import com.androdr.sigma.SigmaRuleFeed
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.async
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.debounce
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.launch
import javax.inject.Inject

@Suppress("LongParameterList") // SettingsViewModel requires injection of all IOC DAOs, updaters,
// and engines to display threat database stats and trigger manual updates from one screen.
@HiltViewModel
class SettingsViewModel @Inject constructor(
    private val settingsRepository: SettingsRepository,
    private val iocEntryDao: IocEntryDao,
    private val domainIocEntryDao: DomainIocEntryDao,
    private val certHashIocEntryDao: CertHashIocEntryDao,
    private val certHashIocDatabase: CertHashIocDatabase,
    private val sigmaRuleEngine: SigmaRuleEngine,
    private val cveDatabase: CveDatabase,
    private val remoteIocUpdater: RemoteIocUpdater,
    private val domainIocUpdater: DomainIocUpdater,
    private val knownAppUpdater: KnownAppUpdater,
    private val certHashIocUpdater: CertHashIocUpdater,
    private val sigmaRuleFeed: SigmaRuleFeed
) : ViewModel() {

    val blocklistBlockMode = settingsRepository.blocklistBlockMode
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5_000), true)

    val domainIocBlockMode = settingsRepository.domainIocBlockMode
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5_000), false)

    val customRuleUrls: StateFlow<String> get() = _customRuleUrlsInput.asStateFlow()
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5_000), "")

    // Threat database stats
    private val _sigmaRuleCount = MutableStateFlow(0)
    val sigmaRuleCount: StateFlow<Int> = _sigmaRuleCount.asStateFlow()

    private val _domainIocCount = MutableStateFlow(0)
    val domainIocCount: StateFlow<Int> = _domainIocCount.asStateFlow()

    private val _packageIocCount = MutableStateFlow(0)
    val packageIocCount: StateFlow<Int> = _packageIocCount.asStateFlow()

    private val _certHashIocCount = MutableStateFlow(0)
    val certHashIocCount: StateFlow<Int> = _certHashIocCount.asStateFlow()

    private val _cveCount = MutableStateFlow(0)
    val cveCount: StateFlow<Int> = _cveCount.asStateFlow()

    private val _lastUpdated = MutableStateFlow<Long?>(null)
    val lastUpdated: StateFlow<Long?> = _lastUpdated.asStateFlow()

    private val _updating = MutableStateFlow(false)
    val updating: StateFlow<Boolean> = _updating.asStateFlow()

    init {
        refreshStats()
    }

    fun setBlocklistBlockMode(value: Boolean) {
        viewModelScope.launch { settingsRepository.setBlocklistBlockMode(value) }
    }

    fun setDomainIocBlockMode(value: Boolean) {
        viewModelScope.launch { settingsRepository.setDomainIocBlockMode(value) }
    }

    private val _customRuleUrlsInput = MutableStateFlow("")

    init {
        @Suppress("OPT_IN_USAGE")
        viewModelScope.launch {
            _customRuleUrlsInput.value = settingsRepository.customRuleUrls.first()
            @OptIn(kotlinx.coroutines.FlowPreview::class)
            _customRuleUrlsInput
                .debounce(DEBOUNCE_MS)
                .collect { settingsRepository.setCustomRuleUrls(it) }
        }
    }

    fun setCustomRuleUrls(value: String) {
        _customRuleUrlsInput.value = value
    }

    /** Triggers all feed updates, SIGMA rule refresh, and CVE refresh. */
    @Suppress("TooGenericExceptionCaught")
    fun triggerUpdate() {
        if (_updating.value) return
        viewModelScope.launch {
            _updating.value = true
            try {
                // Run all IOC updaters in parallel
                val iocJob = async { remoteIocUpdater.update() }
                val domainJob = async { domainIocUpdater.update() }
                val knownAppJob = async { knownAppUpdater.update() }
                val certJob = async { certHashIocUpdater.update() }
                iocJob.await()
                domainJob.await()
                knownAppJob.await()
                certJob.await()

                // Refresh SIGMA rules
                try {
                    val remoteRules = sigmaRuleFeed.fetch()
                    if (remoteRules.isNotEmpty()) {
                        sigmaRuleEngine.setRemoteRules(remoteRules)
                    }
                } catch (e: Exception) {
                    Log.w(TAG, "SIGMA rule refresh failed: ${e.message}")
                }

                // Refresh CVE database
                try {
                    cveDatabase.refresh()
                } catch (e: Exception) {
                    Log.w(TAG, "CVE database refresh failed: ${e.message}")
                }

                refreshStats()
            } catch (e: Exception) {
                Log.e(TAG, "Threat database update failed: ${e.message}")
            } finally {
                _updating.value = false
            }
        }
    }

    private fun refreshStats() {
        viewModelScope.launch {
            _sigmaRuleCount.value = sigmaRuleEngine.ruleCount()
            _domainIocCount.value = domainIocEntryDao.count()
            _packageIocCount.value = iocEntryDao.count()
            _certHashIocCount.value = certHashIocEntryDao.count() + certHashIocDatabase.getAllBadCerts().size
            _cveCount.value = cveDatabase.getActivelyExploitedCount()

            // Determine most recent fetch time across all IOC tables
            val times = listOfNotNull(
                iocEntryDao.mostRecentFetchTime(),
                domainIocEntryDao.mostRecentFetchTime(),
                certHashIocEntryDao.mostRecentFetchTime()
            )
            _lastUpdated.value = times.maxOrNull()
        }
    }

    companion object {
        private const val TAG = "SettingsViewModel"
        private const val DEBOUNCE_MS = 500L
    }
}
