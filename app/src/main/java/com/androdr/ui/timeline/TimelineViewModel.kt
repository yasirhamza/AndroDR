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
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.io.File
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import javax.inject.Inject

@HiltViewModel
class TimelineViewModel @Inject constructor(
    @ApplicationContext private val appContext: Context,
    private val dao: ForensicTimelineEventDao,
    private val correlationEngine: CorrelationEngine
) : ViewModel() {

    private val _severityFilter = MutableStateFlow<String?>(null)
    val severityFilter: StateFlow<String?> = _severityFilter.asStateFlow()

    private val _sourceFilter = MutableStateFlow<String?>(null)
    val sourceFilter: StateFlow<String?> = _sourceFilter.asStateFlow()

    private val _packageFilter = MutableStateFlow<String?>(null)
    val packageFilter: StateFlow<String?> = _packageFilter.asStateFlow()

    @OptIn(ExperimentalCoroutinesApi::class)
    val events: StateFlow<List<ForensicTimelineEvent>> = combine(
        _severityFilter, _sourceFilter, _packageFilter
    ) { sev, src, pkg -> Triple(sev, src, pkg) }
        .flatMapLatest { (sev, src, pkg) ->
            when {
                pkg != null -> dao.getEventsByPackage(pkg)
                src != null -> dao.getEventsBySource(src)
                sev != null -> dao.getEventsBySeverity(listOf(sev))
                else -> dao.getRecentEvents()
            }
        }
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5000), emptyList())

    val partitionedEvents: StateFlow<Pair<List<EventCluster>, List<ForensicTimelineEvent>>> =
        events.map { eventList ->
            if (eventList.isEmpty()) emptyList<EventCluster>() to emptyList()
            else correlationEngine.partition(eventList)
        }.stateIn(
            viewModelScope,
            SharingStarted.WhileSubscribed(5000),
            emptyList<EventCluster>() to emptyList()
        )

    private val _availableSources = MutableStateFlow<List<String>>(emptyList())
    val availableSources: StateFlow<List<String>> = _availableSources.asStateFlow()

    private val _availablePackages = MutableStateFlow<List<String>>(emptyList())
    val availablePackages: StateFlow<List<String>> = _availablePackages.asStateFlow()

    private val _shareUri = MutableStateFlow<Uri?>(null)
    val shareUri: StateFlow<Uri?> = _shareUri.asStateFlow()

    private val _exporting = MutableStateFlow(false)
    val exporting: StateFlow<Boolean> = _exporting.asStateFlow()

    init {
        viewModelScope.launch {
            _availableSources.value = dao.getDistinctSources()
            _availablePackages.value = dao.getDistinctPackages()
        }
    }

    fun setSeverityFilter(severity: String?) {
        _packageFilter.value = null
        _sourceFilter.value = null
        _severityFilter.value = severity
    }

    fun setSourceFilter(source: String?) {
        _packageFilter.value = null
        _severityFilter.value = null
        _sourceFilter.value = source
    }

    fun setPackageFilter(pkg: String?) {
        _severityFilter.value = null
        _sourceFilter.value = null
        _packageFilter.value = pkg
    }

    fun clearFilters() {
        _severityFilter.value = null
        _sourceFilter.value = null
        _packageFilter.value = null
    }

    /** Generated plaintext report for viewing/copying. Populated on demand. */
    private val _reportText = MutableStateFlow("")
    val reportText: StateFlow<String> = _reportText.asStateFlow()

    /** Generates the plaintext report for the view/copy sheet. */
    fun generateReport() {
        viewModelScope.launch {
            val allEvents = withContext(Dispatchers.IO) { dao.getAllForExport() }
            _reportText.value = TimelineExporter.formatPlaintext(allEvents)
        }
    }

    fun exportPlaintext() = export("txt") { TimelineExporter.formatPlaintext(it) }
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
                val text = formatter(allEvents)
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
}
