package com.androdr.ui.settings

import androidx.annotation.StringRes
import android.util.Log
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import android.content.Context
import android.net.Uri
import androidx.core.content.FileProvider
import com.androdr.R
import com.androdr.data.db.FeedHealthDao
import com.androdr.data.db.ForensicTimelineEventDao
import com.androdr.data.db.IndicatorDao
import com.androdr.data.repo.CveRepository
import com.androdr.data.repo.SettingsRepository
import com.androdr.ioc.CertHashIocDatabase
import com.androdr.data.model.ForensicTimelineEvent
import com.androdr.data.model.Indicator
import com.androdr.ioc.FeedHealthRecorder
import com.androdr.ioc.IndicatorResolver
import com.androdr.ioc.IntelRefresher
import com.androdr.ioc.toStixBundle
import com.androdr.scanner.AppScanner
import com.androdr.sigma.SigmaRuleEngine
import com.androdr.ui.theme.ThemeMode
import dagger.hilt.android.lifecycle.HiltViewModel
import dagger.hilt.android.qualifiers.ApplicationContext
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.debounce
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.launch
import javax.inject.Inject

data class UpdateResult(
    val indicators: String = "",
    val knownApps: String = "",
    val sigmaRules: String = "",
    val cveDatabase: String = "",
    val oemPrefixes: String = "",
    val brandRegistry: String = ""
)

/** One feed's health for the Settings "Threat Database" card (#236). */
data class FeedHealthUi(
    val label: String,
    val lastSuccessAt: Long,
    val isCritical: Boolean,
    val isStale: Boolean,
)

@HiltViewModel
class SettingsViewModel @Inject constructor(
    @ApplicationContext private val appContext: Context,
    private val settingsRepository: SettingsRepository,
    private val indicatorDao: IndicatorDao,
    private val certHashIocDatabase: CertHashIocDatabase,
    private val sigmaRuleEngine: SigmaRuleEngine,
    private val cveRepository: CveRepository,
    private val intelRefresher: IntelRefresher,
    private val appScanner: AppScanner,
    private val forensicTimelineEventDao: ForensicTimelineEventDao,
    private val feedHealthDao: FeedHealthDao
) : ViewModel() {

    val blocklistBlockMode = settingsRepository.blocklistBlockMode
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5_000), true)

    val domainIocBlockMode = settingsRepository.domainIocBlockMode
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5_000), false)

    val themeMode = settingsRepository.themeMode
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5_000), ThemeMode.AUTO)

    fun setThemeMode(mode: ThemeMode) {
        viewModelScope.launch { settingsRepository.setThemeMode(mode) }
    }

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

    private val _feedHealth = MutableStateFlow<List<FeedHealthUi>>(emptyList())
    val feedHealth: StateFlow<List<FeedHealthUi>> = _feedHealth.asStateFlow()

    private val _updating = MutableStateFlow(false)
    val updating: StateFlow<Boolean> = _updating.asStateFlow()

    private val _updateResult = MutableStateFlow<UpdateResult?>(null)
    val updateResult: StateFlow<UpdateResult?> = _updateResult.asStateFlow()

    fun dismissUpdateResult() { _updateResult.value = null }

    /** Where each IOC type's indicators came from; the screen resolves the label. */
    private val _iocSourceLabel = MutableStateFlow<Map<String, ThreatDataSource>>(emptyMap())
    val iocSourceLabel: StateFlow<Map<String, ThreatDataSource>> = _iocSourceLabel.asStateFlow()

    private val _sigmaRuleSource = MutableStateFlow(ThreatDataSource.BUNDLED)
    val sigmaRuleSource: StateFlow<ThreatDataSource> = _sigmaRuleSource.asStateFlow()

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
    @Suppress("TooGenericExceptionCaught") // refreshAll is fault-tolerant; catch guards the rare non-feed error
    fun triggerUpdate() {
        if (_updating.value) return
        viewModelScope.launch {
            _updating.value = true
            try {
                // Route through the shared refresher (skip window 0 = always run)
                // so the manual path records feed_health exactly like the periodic
                // worker and pre-scan refresh do — a direct call to the updaters
                // wrote no health row, so the health list in this very card read
                // stale right after a successful manual update (#244). This also
                // picks up the curated public-repo IOC feed + known-app cache
                // refresh the old manual path skipped entirely.
                val report = intelRefresher.refreshAll(skipIfRefreshedWithinMs = 0L)
                _updateResult.value = report.toUpdateResult()
                refreshStats()
            } catch (e: Exception) {
                // refreshAll swallows per-feed failures, so reaching here means an
                // unexpected non-feed error (e.g. a DB read). Still surface a result
                // dialog rather than leaving the spinner with no outcome.
                Log.e(TAG, "Threat database update failed: ${e.message}")
                _updateResult.value = ALL_FEEDS_FAILED
            } finally {
                _updating.value = false
            }
        }
    }

    // Per-feed status strings for the manual dialog. Counts are the recorded
    // this-run signals; a 0 count is a failure ("empty is failure", #236) and
    // renders as such so every feed presents success/failure the same way. No
    // exception text is surfaced (the health list below the dialog carries the
    // authoritative per-feed stale/failed state, and #236 deliberately keeps
    // attacker-influenceable error strings out of the UI). Assumes a non-skipped
    // report — the manual path always passes skipIfRefreshedWithinMs = 0.
    private fun IntelRefresher.RefreshReport.toUpdateResult(): UpdateResult = UpdateResult(
        indicators = if (indicators > 0) "$indicators indicators" else UPDATE_FAILED,
        knownApps = if (knownApps > 0) "$knownApps apps" else UPDATE_FAILED,
        sigmaRules = if (sigmaRemoteRules > 0) "${sigmaRuleEngine.ruleCount()} rules" else UPDATE_FAILED,
        cveDatabase = if (cveReachable > 0) "Updated" else UPDATE_FAILED,
        oemPrefixes = if (oemPrefixes > 0) "Updated" else UPDATE_FAILED,
        brandRegistry = if (brandRegistry > 0) "Updated" else UPDATE_FAILED,
    )

    private fun refreshStats() {
        viewModelScope.launch {
            _sigmaRuleCount.value = sigmaRuleEngine.ruleCount()
            _domainIocCount.value = indicatorDao.countByType(IndicatorResolver.TYPE_DOMAIN)
            _packageIocCount.value = indicatorDao.countByType(IndicatorResolver.TYPE_PACKAGE)
            _certHashIocCount.value = indicatorDao.countByType(IndicatorResolver.TYPE_CERT_HASH) +
                certHashIocDatabase.getAllBadCerts().size
            _cveCount.value = cveRepository.getActivelyExploitedCount()
            _lastUpdated.value = indicatorDao.lastFetchTimeGlobal()
            _feedHealth.value = loadFeedHealth()

            // Determine downloaded vs bundled per type
            val labels = mutableMapOf<String, ThreatDataSource>()
            for (type in listOf(
                IndicatorResolver.TYPE_DOMAIN,
                IndicatorResolver.TYPE_PACKAGE,
                IndicatorResolver.TYPE_CERT_HASH,
                IndicatorResolver.TYPE_APK_HASH
            )) {
                val count = indicatorDao.countByType(type)
                labels[type] = if (count > 0) ThreatDataSource.DOWNLOADED else ThreatDataSource.BUNDLED
            }
            _iocSourceLabel.value = labels

            _sigmaRuleSource.value =
                if (sigmaRuleEngine.hasRemoteRules()) ThreatDataSource.DOWNLOADED else ThreatDataSource.BUNDLED
        }
    }

    /**
     * Maps the persisted per-feed health rows into UI models, sorted critical
     * feeds first then most-stale first. Staleness is a per-feed check (never a
     * global MAX, so one healthy feed can't mask the rest — the failure mode
     * behind the 2026-07-03 outage, #236), tighter for critical detection-content
     * feeds, and also triggered by a hard-failure streak — see
     * [FeedHealthRecorder.isStale]. lastError is intentionally NOT surfaced here
     * (it can carry attacker-influenced exception text; keep it out of the UI).
     */
    private suspend fun loadFeedHealth(): List<FeedHealthUi> {
        val now = System.currentTimeMillis()
        return feedHealthDao.getAll()
            .map { h ->
                FeedHealthUi(
                    label = FeedHealthRecorder.FEED_LABELS[h.feedId] ?: h.feedId,
                    lastSuccessAt = h.lastSuccessAt,
                    isCritical = h.feedId in FeedHealthRecorder.CRITICAL_FEEDS,
                    isStale = FeedHealthRecorder.isStale(h.feedId, h.lastSuccessAt, h.consecutiveFailures, now),
                )
            }
            .sortedWith(compareByDescending<FeedHealthUi> { it.isCritical }.thenBy { it.lastSuccessAt })
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
                // Export device-specific findings as STIX2 indicators: every visible timeline row,
                // streamed by keyset (no row cap, spec §5.5), keeping one row per distinct indicator.
                val events = kotlinx.coroutines.withContext(Dispatchers.IO) {
                    forensicTimelineEventDao.distinctIndicatorRows()
                }
                // Convert timeline events with IOC/package data to Indicator for STIX2
                val indicators = events
                    .map { event ->
                        val type = when {
                            event.apkHash.isNotEmpty() -> IndicatorResolver.TYPE_APK_HASH
                            event.iocType == "domain" -> IndicatorResolver.TYPE_DOMAIN
                            event.packageName.isNotEmpty() -> IndicatorResolver.TYPE_PACKAGE
                            else -> IndicatorResolver.TYPE_PACKAGE
                        }
                        val value = when (type) {
                            IndicatorResolver.TYPE_APK_HASH -> event.apkHash
                            IndicatorResolver.TYPE_DOMAIN -> event.iocIndicator
                            else -> event.packageName
                        }
                        event.toExportIndicator(type, value)
                    }
                android.util.Log.i(TAG, "STIX2 export: ${indicators.size} findings")
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

        // Manual-update dialog sentinel. UpdateStatusRow renders any status
        // containing "failed" in the error color, so this word must stay in it.
        private const val UPDATE_FAILED = "Update failed"
        private val ALL_FEEDS_FAILED = UpdateResult(
            indicators = UPDATE_FAILED,
            knownApps = UPDATE_FAILED,
            sigmaRules = UPDATE_FAILED,
            cveDatabase = UPDATE_FAILED,
            oemPrefixes = UPDATE_FAILED,
            brandRegistry = UPDATE_FAILED,
        )
    }
}

/** STIX export mapping for a scan finding: the label goes to `family`, never into a category column. */
internal fun ForensicTimelineEvent.toExportIndicator(type: String, value: String): Indicator = Indicator(
    type = type, value = value,
    family = campaignName.ifEmpty { appName.ifEmpty { description } },
    category = "",
    description = details,
    source = "androdr_scan",
    fetchedAt = startTimestamp
)

private const val STIX_BATCH = 500

/** The first visible row of each distinct package/IOC/hash, read [STIX_BATCH] rows at a time (keyset). */
private suspend fun com.androdr.data.db.ForensicTimelineEventDao.distinctIndicatorRows():
    List<com.androdr.data.model.ForensicTimelineEvent> {
    val byIndicator = LinkedHashMap<String, com.androdr.data.model.ForensicTimelineEvent>()
    var after = 0L
    while (true) {
        val rows = visibleAfter(after, STIX_BATCH)
        rows.filter { it.packageName.isNotEmpty() || it.iocIndicator.isNotEmpty() }
            .forEach { byIndicator.putIfAbsent("${it.packageName}|${it.iocIndicator}|${it.apkHash}", it) }
        if (rows.size < STIX_BATCH) return byIndicator.values.toList()
        after = rows.last().id
    }
}

/** Where a threat-data set came from, shown as "<count> (<source>)" in Settings. */
enum class ThreatDataSource(@StringRes val label: Int) {
    BUNDLED(R.string.settings_threat_db_source_bundled),
    DOWNLOADED(R.string.settings_threat_db_source_downloaded),
}
