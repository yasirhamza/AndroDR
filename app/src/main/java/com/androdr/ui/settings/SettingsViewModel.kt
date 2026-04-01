package com.androdr.ui.settings

import android.util.Log
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import android.content.Context
import android.net.Uri
import androidx.core.content.FileProvider
import com.androdr.data.db.IndicatorDao
import com.androdr.data.repo.CveRepository
import com.androdr.data.repo.SettingsRepository
import com.androdr.ioc.CertHashIocDatabase
import com.androdr.ioc.IndicatorResolver
import com.androdr.ioc.IndicatorUpdater
import com.androdr.ioc.toStixBundle
import com.androdr.ioc.KnownAppUpdater
import com.androdr.scanner.AppScanner
import com.androdr.sigma.SigmaRuleEngine
import com.androdr.sigma.SigmaRuleFeed
import dagger.hilt.android.lifecycle.HiltViewModel
import dagger.hilt.android.qualifiers.ApplicationContext
import kotlinx.coroutines.Dispatchers
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
    @ApplicationContext private val appContext: Context,
    private val settingsRepository: SettingsRepository,
    private val indicatorDao: IndicatorDao,
    private val certHashIocDatabase: CertHashIocDatabase,
    private val sigmaRuleEngine: SigmaRuleEngine,
    private val cveRepository: CveRepository,
    private val indicatorUpdater: IndicatorUpdater,
    private val knownAppUpdater: KnownAppUpdater,
    private val appScanner: AppScanner,
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

    private val _customRuleUrlsInput = MutableStateFlow("")

    init {
        refreshStats()
        viewModelScope.launch {
            _customRuleUrlsInput.value = settingsRepository.customRuleUrls.first()
            @OptIn(kotlinx.coroutines.FlowPreview::class)
            _customRuleUrlsInput
                .debounce(DEBOUNCE_MS)
                .collect { settingsRepository.setCustomRuleUrls(it) }
        }
    }

    fun setBlocklistBlockMode(value: Boolean) {
        viewModelScope.launch { settingsRepository.setBlocklistBlockMode(value) }
    }

    fun setDomainIocBlockMode(value: Boolean) {
        viewModelScope.launch { settingsRepository.setDomainIocBlockMode(value) }
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
                val indicatorJob = async { indicatorUpdater.update() }
                val knownAppJob = async { knownAppUpdater.update() }
                indicatorJob.await()
                knownAppJob.await()

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
                    cveRepository.refresh()
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
            _domainIocCount.value = indicatorDao.countByType(IndicatorResolver.TYPE_DOMAIN)
            _packageIocCount.value = indicatorDao.countByType(IndicatorResolver.TYPE_PACKAGE)
            _certHashIocCount.value = indicatorDao.countByType(IndicatorResolver.TYPE_CERT_HASH) +
                certHashIocDatabase.getAllBadCerts().size
            _cveCount.value = cveRepository.getActivelyExploitedCount()
            _lastUpdated.value = indicatorDao.lastFetchTime("stalkerware_indicators")
        }
    }

    // -- App hash export --------------------------------------------------------

    private val _hashExporting = MutableStateFlow(false)
    val hashExporting: StateFlow<Boolean> = _hashExporting.asStateFlow()

    private val _hashShareUri = MutableStateFlow<Uri?>(null)
    val hashShareUri: StateFlow<Uri?> = _hashShareUri.asStateFlow()

    @Suppress("TooGenericExceptionCaught")
    fun exportAppHashes() {
        if (_hashExporting.value) return
        viewModelScope.launch {
            _hashExporting.value = true
            try {
                val telemetry = kotlinx.coroutines.withContext(Dispatchers.IO) {
                    appScanner.collectTelemetry()
                }
                val csv = buildString {
                    appendLine("package_name,app_name,apk_sha256,cert_sha256,is_system,installer")
                    telemetry.sortedBy { it.packageName }.forEach { app ->
                        if (app.apkHash.isNullOrEmpty()) return@forEach
                        val pkg = csvEsc(app.packageName)
                        val name = csvEsc(app.appName)
                        val apk = app.apkHash ?: ""
                        val cert = app.certHash ?: ""
                        val sys = app.isSystemApp
                        val inst = csvEsc(app.installer ?: "")
                        appendLine("$pkg,$name,$apk,$cert,$sys,$inst")
                    }
                }
                _hashShareUri.value = kotlinx.coroutines.withContext(Dispatchers.IO) {
                    val dir = java.io.File(appContext.cacheDir, "reports").apply { mkdirs() }
                    val ts = java.text.SimpleDateFormat(
                        "yyyyMMdd_HHmmss", java.util.Locale.US
                    ).format(java.util.Date())
                    val file = java.io.File(dir, "androdr_app_hashes_$ts.csv")
                    file.writeText(csv, Charsets.UTF_8)
                    FileProvider.getUriForFile(appContext, "${appContext.packageName}.fileprovider", file)
                }
            } catch (e: Exception) {
                android.util.Log.e(TAG, "Hash export failed: ${e.message}", e)
            } finally {
                _hashExporting.value = false
            }
        }
    }

    fun onHashShareConsumed() { _hashShareUri.value = null }

    private fun csvEsc(v: String): String {
        // Prevent CSV formula injection (cells starting with =, +, -, @, \t, \r)
        val sanitized = if (v.isNotEmpty() && v[0] in setOf('=', '+', '-', '@', '\t', '\r')) {
            "'" + v
        } else v
        return if (sanitized.contains(',') || sanitized.contains('"') || sanitized.contains('\n')) {
            "\"${sanitized.replace("\"", "\"\"")}\""
        } else sanitized
    }

    // -- STIX2 export -------------------------------------------------------------

    private val _stixExporting = MutableStateFlow(false)
    val stixExporting: StateFlow<Boolean> = _stixExporting.asStateFlow()

    private val _stixShareUri = MutableStateFlow<Uri?>(null)
    val stixShareUri: StateFlow<Uri?> = _stixShareUri.asStateFlow()

    @Suppress("TooGenericExceptionCaught")
    fun exportStix2() {
        if (_stixExporting.value) return
        viewModelScope.launch {
            _stixExporting.value = true
            try {
                val indicators = kotlinx.coroutines.withContext(Dispatchers.IO) {
                    indicatorDao.getAll()
                }
                val json = indicators.toStixBundle()
                _stixShareUri.value = kotlinx.coroutines.withContext(Dispatchers.IO) {
                    val dir = java.io.File(appContext.cacheDir, "reports").apply { mkdirs() }
                    val ts = java.text.SimpleDateFormat(
                        "yyyyMMdd_HHmmss", java.util.Locale.US
                    ).format(java.util.Date())
                    val file = java.io.File(dir, "androdr_indicators_$ts.stix2.json")
                    file.writeText(json, Charsets.UTF_8)
                    FileProvider.getUriForFile(appContext, "${appContext.packageName}.fileprovider", file)
                }
            } catch (e: Exception) {
                android.util.Log.e(TAG, "STIX2 export failed: ${e.message}", e)
            } finally {
                _stixExporting.value = false
            }
        }
    }

    fun onStixShareConsumed() { _stixShareUri.value = null }

    companion object {
        private const val TAG = "SettingsViewModel"
        private const val DEBOUNCE_MS = 500L
    }
}
