package com.androdr.ui.timeline

import android.content.Context
import android.net.Uri
import androidx.core.content.FileProvider
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.androdr.data.db.ForensicTimelineEventDao
import com.androdr.data.model.ForensicTimelineEvent
import com.androdr.reporting.TimelineExporter
import dagger.hilt.android.lifecycle.HiltViewModel
import dagger.hilt.android.qualifiers.ApplicationContext
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.flatMapLatest
import kotlinx.coroutines.flow.flowOn
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.io.File
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import com.androdr.ioc.KnownAppResolver
import javax.inject.Inject

enum class TimelineGroupMode { DATE, SCAN }

data class ScanGroup(
    val scanId: Long,
    val timestamp: Long,
    val isFromBugreport: Boolean,
    val eventCount: Int,
    val maxSeverity: String,
    val clusters: List<EventCluster>,
    val standaloneEvents: List<ForensicTimelineEvent>
)

@Suppress("TooManyFunctions") // ViewModel exposes filter setters, export methods, and report
// generation — splitting would fragment the timeline feature's cohesive state management.
@HiltViewModel
class TimelineViewModel @Inject constructor(
    @ApplicationContext private val appContext: Context,
    private val dao: ForensicTimelineEventDao,
    private val knownAppResolver: KnownAppResolver,
    private val sigmaRuleEngine: com.androdr.sigma.SigmaRuleEngine
) : ViewModel() {

    private val _groupMode = MutableStateFlow(TimelineGroupMode.DATE)
    val groupMode: StateFlow<TimelineGroupMode> = _groupMode.asStateFlow()

    fun setGroupMode(mode: TimelineGroupMode) {
        _groupMode.value = mode
    }

    private val _severityFilter = MutableStateFlow<String?>(null)
    val severityFilter: StateFlow<String?> = _severityFilter.asStateFlow()

    private val _sourceFilter = MutableStateFlow<String?>(null)
    val sourceFilter: StateFlow<String?> = _sourceFilter.asStateFlow()

    private val _packageFilter = MutableStateFlow<String?>(null)
    val packageFilter: StateFlow<String?> = _packageFilter.asStateFlow()

    private val _dateRange = MutableStateFlow<Pair<Long, Long>?>(null)
    val dateRange: StateFlow<Pair<Long, Long>?> = _dateRange.asStateFlow()

    private data class FilterState(
        val sev: String?, val src: String?, val pkg: String?, val dateRange: Pair<Long, Long>?
    )

    @OptIn(ExperimentalCoroutinesApi::class)
    val events: StateFlow<List<ForensicTimelineEvent>> = combine(
        _severityFilter, _sourceFilter, _packageFilter, _dateRange
    ) { sev, src, pkg, range -> FilterState(sev, src, pkg, range) }
        .flatMapLatest { filter ->
            when {
                filter.dateRange != null -> dao.getEventsInRange(filter.dateRange.first, filter.dateRange.second)
                filter.pkg != null -> dao.getEventsByPackage(filter.pkg)
                filter.src != null -> dao.getEventsBySource(filter.src)
                filter.sev != null -> dao.getEventsBySeverity(listOf(filter.sev))
                else -> dao.getRecentEvents()
            }
        }
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5000), emptyList())

    // StateFlow already guarantees distinctUntilChanged semantics, so no explicit call needed.
    // Only compute the partition when DATE mode is active to avoid redundant work in SCAN mode.
    val partitionedEvents: StateFlow<Pair<List<EventCluster>, List<ForensicTimelineEvent>>> =
        combine(events, _groupMode) { eventList, mode ->
            if (mode != TimelineGroupMode.DATE || eventList.isEmpty()) {
                emptyList<EventCluster>() to emptyList<ForensicTimelineEvent>()
            } else {
                partitionSignals(eventList)
            }
        }.flowOn(Dispatchers.Default).stateIn(
            viewModelScope,
            SharingStarted.WhileSubscribed(5000),
            emptyList<EventCluster>() to emptyList()
        )

    val scanGroupedEvents: StateFlow<List<ScanGroup>> = combine(events, _groupMode) { eventList, mode ->
        if (mode != TimelineGroupMode.SCAN || eventList.isEmpty()) return@combine emptyList()
        val groups = eventList.filter { it.scanResultId != -1L }
            .groupBy { it.scanResultId }
            .map { (scanId, scanEvents) ->
                val (clusters, standalone) = partitionSignals(scanEvents)
                ScanGroup(
                    scanId = scanId,
                    // The group header must show when the SCAN was RUN, not
                    // the earliest event's time. For bug-report scans the
                    // events include AppOps records with real last-access
                    // timestamps from the bug-report content (potentially
                    // weeks old), so the previous
                    // `scanEvents.minOf { it.timestamp }` labelled the
                    // group with that ancient time instead of when the
                    // user actually ran the analysis. The History list
                    // already shows the correct time because it reads
                    // `scanResult.timestamp` directly.
                    //
                    // Crucial invariant we exploit: ScanOrchestrator sets
                    // BOTH `ScanResult.id = now` and `ScanResult.timestamp
                    // = now` to the same `System.currentTimeMillis()` at
                    // scan creation (see runFullScan:180 and
                    // analyzeBugReport:278), and ForensicTimelineEvent
                    // rows are persisted with `scanResultId = scanResult.id`.
                    // So the `scanId` we already have in this lambda IS
                    // the scan run time in milliseconds — we can use it
                    // directly without going back to the ScanResult table.
                    timestamp = scanId,
                    isFromBugreport = scanEvents.any { it.isFromBugreport },
                    eventCount = scanEvents.size,
                    maxSeverity = scanEvents.maxOf { severityOrdinal(it.severity) }.let {
                        when (it) {
                            3 -> "CRITICAL"; 2 -> "HIGH"; 1 -> "MEDIUM"; else -> "INFO"
                        }
                    },
                    clusters = clusters,
                    standaloneEvents = standalone
                )
            }
            .sortedByDescending { it.timestamp }
            .toMutableList()
        val ungrouped = eventList.filter { it.scanResultId == -1L }
        if (ungrouped.isNotEmpty()) {
            val (ungroupedClusters, ungroupedStandalone) = partitionSignals(ungrouped)
            groups.add(ScanGroup(
                scanId = -1,
                // Same invalid-timestamp filter as the per-scan groups above.
                timestamp = ungrouped.filter { it.startTimestamp > 0L }
                    .minOfOrNull { it.startTimestamp }
                    ?: 0L,
                isFromBugreport = false,
                eventCount = ungrouped.size,
                maxSeverity = ungrouped.maxOf { severityOrdinal(it.severity) }.let {
                    when (it) { 3 -> "CRITICAL"; 2 -> "HIGH"; 1 -> "MEDIUM"; else -> "INFO" }
                },
                clusters = ungroupedClusters,
                standaloneEvents = ungroupedStandalone
            ))
        }
        groups
    }.flowOn(Dispatchers.Default)
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5000), emptyList())

    private val _availableSources = MutableStateFlow<List<String>>(emptyList())
    val availableSources: StateFlow<List<String>> = _availableSources.asStateFlow()

    private val _availablePackages = MutableStateFlow<List<String>>(emptyList())
    val availablePackages: StateFlow<List<String>> = _availablePackages.asStateFlow()

    private val _shareUri = MutableStateFlow<Uri?>(null)
    val shareUri: StateFlow<Uri?> = _shareUri.asStateFlow()

    private val _exporting = MutableStateFlow(false)
    val exporting: StateFlow<Boolean> = _exporting.asStateFlow()

    init {
        // Refresh available filter options whenever events change
        viewModelScope.launch {
            events.collect {
                _availableSources.value = dao.getDistinctSources()
                _availablePackages.value = dao.getDistinctPackages()
            }
        }
    }

    fun setSeverityFilter(severity: String?) {
        _packageFilter.value = null
        _sourceFilter.value = null
        _dateRange.value = null
        _severityFilter.value = severity
    }

    fun setSourceFilter(source: String?) {
        _packageFilter.value = null
        _severityFilter.value = null
        _dateRange.value = null
        _sourceFilter.value = source
    }

    fun setPackageFilter(pkg: String?) {
        _severityFilter.value = null
        _sourceFilter.value = null
        _dateRange.value = null
        _packageFilter.value = pkg
    }

    fun setDateRange(start: Long, end: Long) {
        _severityFilter.value = null
        _sourceFilter.value = null
        _packageFilter.value = null
        _dateRange.value = start to end
    }

    fun clearDateRange() {
        _dateRange.value = null
    }

    fun clearFilters() {
        _severityFilter.value = null
        _sourceFilter.value = null
        _packageFilter.value = null
        _dateRange.value = null
    }

    /** Generated plaintext report for viewing/copying. Populated on demand. */
    private val _reportText = MutableStateFlow("")
    val reportText: StateFlow<String> = _reportText.asStateFlow()

    /** Clears the generated report text (e.g. when the report sheet is dismissed). */
    fun clearReport() {
        _reportText.value = ""
    }

    /** Generates the plaintext report for the view/copy sheet. */
    fun generateReport() {
        viewModelScope.launch {
            val allEvents = withContext(Dispatchers.IO) { dao.getAllForExport() }
            _reportText.value = withContext(Dispatchers.Default) {
                TimelineExporter.formatPlaintext(allEvents, buildDisplayNames(allEvents), buildRuleGuidance())
            }
        }
    }

    fun exportPlaintext() = export("txt") {
        TimelineExporter.formatPlaintext(it, buildDisplayNames(it), buildRuleGuidance())
    }
    fun exportCsv() = export("csv") { TimelineExporter.formatCsv(it) }

    @Suppress("TooGenericExceptionCaught") // Export can throw IOException (disk full, no
    // permission) or SecurityException (FileProvider misconfiguration) — catching Exception
    // ensures the exporting flag is always reset and the error is logged regardless of type.
    private fun export(extension: String, formatter: (List<ForensicTimelineEvent>) -> String) {
        if (_exporting.value) return
        viewModelScope.launch {
            _exporting.value = true
            try {
                val allEvents = withContext(Dispatchers.IO) { dao.getAllForExport() }
                val text = withContext(Dispatchers.Default) { formatter(allEvents) }
                _shareUri.value = withContext(Dispatchers.IO) {
                    val reportsDir = File(appContext.cacheDir, "reports").apply { mkdirs() }
                    val ts = SimpleDateFormat("yyyyMMdd_HHmmss", Locale.US).format(Date())
                    val file = File(reportsDir, "androdr_timeline_$ts.$extension")
                    file.writeText(text, Charsets.UTF_8)
                    FileProvider.getUriForFile(appContext, "${appContext.packageName}.fileprovider", file)
                }
            } catch (e: Exception) {
                android.util.Log.e("TimelineViewModel", "Export failed: ${e.message}", e)
            } finally {
                _exporting.value = false
            }
        }
    }

    fun onShareConsumed() { _shareUri.value = null }

    private fun buildDisplayNames(events: List<ForensicTimelineEvent>): Map<String, String> {
        val fromEvents = events
            .filter { it.appName.isNotEmpty() && it.appName != it.packageName }
            .associateBy({ it.packageName }, { it.appName })
        val needLookup = events
            .map { it.packageName }
            .filter { it.isNotEmpty() && it !in fromEvents }
            .distinct()
        val fromResolver = needLookup.mapNotNull { pkg ->
            knownAppResolver.lookup(pkg)?.let { pkg to it.displayName }
        }.toMap()
        return fromResolver + fromEvents
    }

    private fun buildRuleGuidance(): Map<String, String> =
        sigmaRuleEngine.getRules()
            .filter { it.display.guidance.isNotEmpty() }
            .associate { it.id to it.display.guidance }
}
