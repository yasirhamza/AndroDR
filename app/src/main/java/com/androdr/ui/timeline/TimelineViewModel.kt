package com.androdr.ui.timeline

import android.content.Context
import android.net.Uri
import androidx.core.content.FileProvider
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import androidx.paging.Pager
import androidx.paging.PagingConfig
import androidx.paging.PagingData
import androidx.paging.cachedIn
import androidx.paging.insertSeparators
import com.androdr.data.db.AppDatabase
import com.androdr.data.db.TimelineFilter
import com.androdr.data.db.chunkedIn
import com.androdr.data.model.ForensicTimelineEvent
import com.androdr.data.model.ScanResult
import com.androdr.data.model.TelemetrySource
import com.androdr.data.repo.ScanRepository
import com.androdr.data.store.KeysetPagingSource
import com.androdr.data.store.tableChanges
import com.androdr.ioc.KnownAppResolver
import com.androdr.reporting.TimelineExporter
import com.androdr.sigma.Finding
import com.androdr.util.appVersion
import dagger.hilt.android.lifecycle.HiltViewModel
import dagger.hilt.android.qualifiers.ApplicationContext
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.flatMapLatest
import kotlinx.coroutines.flow.flowOn
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.flow.mapLatest
import kotlinx.coroutines.flow.runningFold
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.io.File
import java.io.Writer
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import javax.inject.Inject

enum class TimelineGroupMode { DATE, SCAN }

/** A scan's header in the "By scan" view; its count loads through [TimelineViewModel.count]. */
data class ScanGroup(
    val scanId: Long,
    val timestamp: Long,
    val importSource: TelemetrySource?,
    val maxSeverity: String,
)

/** The report sheet's text: the first [TimelineViewModel.PREVIEW_CHARS] of the report, whole or not. */
data class ReportPreview(val text: String, val truncated: Boolean) {
    companion object {
        val EMPTY = ReportPreview("", false)
    }
}

/**
 * The Timeline (spec §6): one keyset-paged union of visible event facts and visible
 * `forensic_timeline` rows ([TimelinePagingSource]), with date headers, counts on every header and
 * on the filter bar, and streaming exports. Nothing is capped and no read holds the whole Timeline.
 */
@Suppress("TooManyFunctions") // filter setters, export methods and report generation share the filter state
@HiltViewModel
class TimelineViewModel @Inject constructor(
    @ApplicationContext private val appContext: Context,
    private val db: AppDatabase,
    private val entries: TimelineEntries,
    private val knownAppResolver: KnownAppResolver,
    private val sigmaRuleEngine: com.androdr.sigma.SigmaRuleEngine,
    private val scanRepository: ScanRepository,
    private val reportExporter: com.androdr.reporting.ReportExporter,
    private val clusterMembers: ClusterMembers,
    private val signalMembers: com.androdr.data.db.SignalMemberDao,
) : ViewModel() {

    /** One page of a correlation signal's members, loaded when its card is expanded (spec §5.4). */
    suspend fun loadClusterPage(signalRowId: Long, after: com.androdr.sigma.AtomRef?): ClusterPage =
        withContext(Dispatchers.IO) { clusterMembers.load(signalRowId, after) }

    private val _groupMode = MutableStateFlow(TimelineGroupMode.DATE)
    val groupMode: StateFlow<TimelineGroupMode> = _groupMode.asStateFlow()

    fun setGroupMode(mode: TimelineGroupMode) {
        _groupMode.value = mode
    }

    private val _filter = MutableStateFlow(TimelineFilter())

    /** What the list, the counts and the exports read. */
    val filter: StateFlow<TimelineFilter> = _filter.asStateFlow()

    fun setFindingsAndEvidenceOnly(only: Boolean) = _filter.update { it.copy(findingsAndEvidenceOnly = only) }

    fun toggleSeverity(level: String) = _filter.update {
        it.copy(levels = if (level in it.levels) it.levels - level else it.levels + level)
    }

    fun setSourceFilter(source: String?) = _filter.update { it.copy(source = source) }

    fun setPackageFilter(pkg: String?) = _filter.update { it.copy(packageName = pkg) }

    fun setDateRange(start: Long, end: Long) = _filter.update { it.copy(from = start, to = end) }

    fun clearDateRange() = _filter.update { it.copy(from = null, to = null) }

    /** Shows only [scanId]'s rows and the facts it observed (null: every scan). */
    fun setScanFilter(scanId: Long?) = _filter.update { it.copy(scanId = scanId) }

    fun clearFilters() = _filter.update { TimelineFilter(zone = it.zone) }

    /** Bumps whenever a scan completes or is deleted, or a Timeline row changes (what changes counts). */
    private val tableVersion: StateFlow<Int> = db.tableChanges(KeysetPagingSource.OBSERVED_TABLES)
        .runningFold(0) { n, _ -> n + 1 }
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5000), 0)

    /** The paged list: the union under [filter], a [TimelineRow.DayHeader] before each day. */
    @OptIn(ExperimentalCoroutinesApi::class)
    val rows: Flow<PagingData<TimelineRow>> = _filter.flatMapLatest { filter ->
        Pager(PagingConfig(pageSize = PAGE_SIZE, enablePlaceholders = false)) {
            TimelinePagingSource(db, filter, entries)
        }.flow.map { data ->
            data.insertSeparators<TimelineRow.Entry, TimelineRow> { before, after ->
                val next = after?.let { filter.dayOf(it.timestamp) }
                val prev = before?.let { filter.dayOf(it.timestamp) }
                if (next != null && next != prev) TimelineRow.DayHeader(next) else null
            }
        }
    }.cachedIn(viewModelScope)

    /** How many entries [filter] matches (the filter bar); null while counting. */
    @OptIn(ExperimentalCoroutinesApi::class)
    val totalCount: StateFlow<Long?> = combine(_filter, tableVersion) { f, _ -> f }
        .mapLatest { count(it) }
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5000), null)

    /** Counts re-read after [tableVersion] changes; headers key their count on it. */
    val countsVersion: StateFlow<Int> get() = tableVersion

    /** Entries [filter] matches, off the main thread. */
    suspend fun count(filter: TimelineFilter): Long = withContext(Dispatchers.IO) { entries.count(filter) }

    /** A date header's count: the current filter narrowed to [day]. */
    suspend fun dayCount(day: Long): Long = count(_filter.value.forDay(day))

    /** A scan header's count: the current filter narrowed to [scanId]. */
    suspend fun scanCount(scanId: Long): Long = count(_filter.value.copy(scanId = scanId))

    private val latestFindings: StateFlow<List<Finding>> = scanRepository.allScans
        .map { scans -> timelineFindingRows(scans.firstOrNull()?.findings.orEmpty()) }
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5000), emptyList())

    /** The pinned section: the latest scan's triggered findings (current findings). */
    val findings: StateFlow<List<Finding>> = latestFindings

    /** "By scan": one header per completed scan, newest first. */
    val scanGroups: StateFlow<List<ScanGroup>> = scanRepository.allScans
        .map { scans -> scans.map(::scanGroup) }
        .flowOn(Dispatchers.Default)
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5000), emptyList())

    private fun scanGroup(scan: ScanResult): ScanGroup = ScanGroup(
        scanId = scan.id,
        timestamp = scan.timestamp,
        importSource = scan.source.takeIf { it != TelemetrySource.LIVE_SCAN },
        maxSeverity = scan.findings.filter { it.triggered }.maxByOrNull { severityOrdinal(it.level) }
            ?.level?.uppercase() ?: "INFO",
    )

    /** Package chips: packages named by visible timeline rows. */
    @OptIn(ExperimentalCoroutinesApi::class)
    val availablePackages: StateFlow<List<String>> = tableVersion
        .mapLatest { withContext(Dispatchers.IO) { db.forensicTimelineEventDao().getDistinctPackages() } }
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5000), emptyList())

    private val _shareUri = MutableStateFlow<Uri?>(null)
    val shareUri: StateFlow<Uri?> = _shareUri.asStateFlow()

    private val _exporting = MutableStateFlow(false)
    val exporting: StateFlow<Boolean> = _exporting.asStateFlow()

    private val _report = MutableStateFlow(ReportPreview.EMPTY)

    /** The report sheet's text (filled on demand); see [ReportPreview]. */
    val report: StateFlow<ReportPreview> = _report.asStateFlow()

    /** The file the last [generateReport] wrote, shared by the report sheet. */
    private var reportFile: File? = null

    fun clearReport() {
        _report.value = ReportPreview.EMPTY
    }

    /**
     * Writes the plaintext report of the current filter to a file (streaming) and shows its first
     * [PREVIEW_CHARS] characters in the sheet; a longer report is shared as the file.
     */
    @Suppress("TooGenericExceptionCaught") // IO or decoding failures must not crash the sheet
    fun generateReport() {
        viewModelScope.launch {
            try {
                val file = withContext(Dispatchers.IO) { newReportFile("txt").also { writePlaintext(it) } }
                reportFile = file
                _report.value = withContext(Dispatchers.IO) { preview(file) }
            } catch (e: Exception) {
                android.util.Log.e(TAG, "Report failed: ${e.message}", e)
            }
        }
    }

    /** Shares the last generated report file. */
    fun shareReport() {
        val file = reportFile ?: return
        viewModelScope.launch { _shareUri.value = withContext(Dispatchers.IO) { uriOf(file) } }
    }

    fun exportPlaintext() = export("txt", ::writePlaintext)

    fun exportCsv() = export("csv", ::writeCsv)

    @Suppress("TooGenericExceptionCaught") // Export can throw IOException (disk full, no
    // permission) or SecurityException (FileProvider misconfiguration) — catching Exception
    // ensures the exporting flag is always reset and the error is logged regardless of type.
    private fun export(extension: String, write: suspend (File) -> Unit) {
        if (_exporting.value) return
        viewModelScope.launch {
            _exporting.value = true
            try {
                _shareUri.value = withContext(Dispatchers.IO) { uriOf(newReportFile(extension).also { write(it) }) }
            } catch (e: Exception) {
                android.util.Log.e(TAG, "Export failed: ${e.message}", e)
            } finally {
                _exporting.value = false
            }
        }
    }

    /** Streams the current filter's Timeline as CSV, oldest first, one page at a time. */
    private suspend fun writeCsv(file: File) {
        val filter = _filter.value
        file.bufferedWriter(Charsets.UTF_8).use { out ->
            TimelineExporter.writeCsvHeader(out)
            entries.forEachPage(filter, oldestFirst = true, size = EXPORT_PAGE) { page ->
                val events = page.map { it.asExportEvent() }
                val refs = memberRefs(events)
                events.forEach { TimelineExporter.writeCsvRow(out, it, refs[it.id].orEmpty()) }
            }
        }
    }

    /** Streams the current filter's Timeline as plaintext, newest first: one pass for the header, one to write. */
    private suspend fun writePlaintext(file: File) {
        val filter = _filter.value
        val stats = TimelineExporter.PlaintextStats(buildRuleGuidance())
        entries.forEachPage(filter, oldestFirst = false, size = EXPORT_PAGE) { page ->
            page.forEach { stats.add(it.asExportEvent()) }
        }
        val names = HashMap<String, String?>()
        file.bufferedWriter(Charsets.UTF_8).use { out: Writer ->
            val writer = TimelineExporter.PlaintextWriter(out) { pkg ->
                names.getOrPut(pkg) { knownAppResolver.lookup(pkg)?.displayName }
            }
            writer.header(stats, appContext.appVersion().name)
            entries.forEachPage(filter, oldestFirst = false, size = EXPORT_PAGE) { page ->
                page.forEach { writer.event(it.asExportEvent()) }
            }
            writer.footer()
        }
    }

    /** Each exported signal's members that still exist, as `kind:id` (the CSV `member_refs` column). */
    private suspend fun memberRefs(events: List<ForensicTimelineEvent>): Map<Long, List<String>> {
        val signalIds = events.filter { it.kind == "signal" }.map { it.id }
        if (signalIds.isEmpty()) return emptyMap()
        return chunkedIn(signalIds) { signalMembers.existingRefs(it) }
            .groupBy({ it.signalRowId }, { "${it.kind}:${it.refId}" })
    }

    private fun newReportFile(extension: String): File {
        val reportsDir = File(appContext.cacheDir, "reports").apply { mkdirs() }
        val ts = SimpleDateFormat("yyyyMMdd_HHmmss", Locale.US).format(Date())
        return File(reportsDir, "androdr_timeline_$ts.$extension")
    }

    private fun uriOf(file: File): Uri =
        FileProvider.getUriForFile(appContext, "${appContext.packageName}.fileprovider", file)

    private fun preview(file: File): ReportPreview = file.bufferedReader(Charsets.UTF_8).use { reader ->
        val buf = CharArray(PREVIEW_CHARS + 1)
        var n = 0
        while (n < buf.size) {
            val read = reader.read(buf, n, buf.size - n)
            if (read < 0) break
            n += read
        }
        ReportPreview(String(buf, 0, minOf(n, PREVIEW_CHARS)), truncated = n > PREVIEW_CHARS)
    }

    fun onShareConsumed() { _shareUri.value = null }

    /**
     * Exports the latest scan as a full report (with telemetry/findings/both
     * mode). Uses [reportExporter] for the same format as the History screen
     * export, not the timeline-specific TXT/CSV.
     */
    @Suppress("TooGenericExceptionCaught") // export can fail for IO, permissions, or serialization
    fun exportFullReport(mode: com.androdr.reporting.ExportMode) {
        viewModelScope.launch {
            _exporting.value = true
            try {
                val scans = scanRepository.allScans.first()
                val scan = scans.firstOrNull() ?: return@launch
                val uri = reportExporter.export(scan, mode)
                _shareUri.value = uri
            } catch (e: Exception) {
                android.util.Log.e(TAG, "Full report export failed: ${e.message}", e)
            } finally {
                _exporting.value = false
            }
        }
    }

    private fun buildRuleGuidance(): Map<String, String> =
        sigmaRuleEngine.getRules()
            .filter { it.display.guidance.isNotEmpty() }
            .associate { it.id to it.display.guidance }

    companion object {
        private const val TAG = "TimelineViewModel"
        private const val PAGE_SIZE = 100
        private const val EXPORT_PAGE = 500

        /** The report sheet shows (and Copy copies) at most this much; a longer report is shared as a file. */
        const val PREVIEW_CHARS = 200_000
    }
}

/**
 * A Timeline entry as the exporters write it: a row as stored, a fact as an `event` row of its
 * service (its display summary as the description, its fact id as `recordId`). The fact's row id
 * is 0, so it never collides with a signal row's member refs.
 */
internal fun TimelineRow.Entry.asExportEvent(): ForensicTimelineEvent = when (this) {
    is TimelineRow.StoredRow -> event
    is TimelineRow.EventRow -> ForensicTimelineEvent(
        startTimestamp = entity.time,
        kind = "event",
        source = record.service,
        category = entity.category.ifEmpty { record.service },
        description = record.summary.orEmpty(),
        packageName = entity.packageName,
        scanResultId = if (entity.scanId >= 0) entity.scanId else record.scanId,
        telemetrySource = record.source,
        createdAt = record.capturedAt,
        recordId = record.factId,
    )
}
