package com.androdr.ui.timeline

import android.content.Context
import android.net.Uri
import androidx.core.content.FileProvider
import androidx.lifecycle.SavedStateHandle
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import androidx.paging.Pager
import androidx.paging.PagingConfig
import androidx.paging.PagingData
import androidx.paging.cachedIn
import androidx.paging.insertSeparators
import androidx.paging.map
import com.androdr.data.db.AppDatabase
import com.androdr.data.db.TimelineFilter
import com.androdr.data.db.chunkedIn
import com.androdr.data.model.ForensicTimelineEvent
import com.androdr.ui.security.ConfirmResult
import com.androdr.data.model.ScanResult
import com.androdr.data.model.TelemetrySource
import com.androdr.data.repo.ScanRepository
import com.androdr.data.store.DecodedRecord
import com.androdr.data.store.KeysetPagingSource
import com.androdr.data.store.tableChanges
import com.androdr.ioc.KnownAppResolver
import com.androdr.reporting.TimelineExporter
import com.androdr.reporting.writeReportFile
import com.androdr.sigma.Finding
import com.androdr.sigma.TimePrecision
import com.androdr.util.appVersion
import dagger.hilt.android.lifecycle.HiltViewModel
import dagger.hilt.android.qualifiers.ApplicationContext
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.FlowPreview
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.flow.buffer
import kotlinx.coroutines.flow.debounce
import kotlinx.coroutines.flow.flow
import kotlinx.coroutines.flow.produceIn
import kotlinx.coroutines.withTimeoutOrNull
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.flatMapLatest
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.flow.mapLatest
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
    private val findingsRepository: com.androdr.data.repo.FindingsRepository,
    /** This navigation entry's saved state: survives rotation and process death (deep links, I1). */
    private val savedState: SavedStateHandle,
) : ViewModel() {

    /** Where reads run; a test swaps in its own dispatcher. */
    internal var io: CoroutineDispatcher = Dispatchers.IO

    /** The OPEN alerts of a finding row (its rule on its fact): non-empty when the row offers Close. */
    suspend fun openAlertIdsFor(event: ForensicTimelineEvent): List<Long> =
        if (event.persistent || event.ruleId.isEmpty() || event.recordId == null) {
            emptyList()
        } else {
            withContext(io) { findingsRepository.openAlertIdsFor(event.ruleId, event.recordId) }
        }

    /**
     * Closes [ids] after the device credential: [confirm] runs first, and the repository closes
     * nothing unless its result is confirmed (spec §5.4). Returns how many closed.
     */
    suspend fun closeAlerts(ids: List<Long>, note: String?, confirm: suspend () -> ConfirmResult): Int =
        findingsRepository.close(ids, note, confirm())

    /** One page of a correlation signal's members, loaded when its card is expanded (spec §5.4). */
    suspend fun loadClusterPage(signalRowId: Long, after: com.androdr.sigma.AtomRef?): ClusterPage =
        withContext(Dispatchers.IO) { clusterMembers.load(signalRowId, after) }

    private val _groupMode = MutableStateFlow(TimelineGroupMode.DATE)
    val groupMode: StateFlow<TimelineGroupMode> = _groupMode.asStateFlow()

    fun setGroupMode(mode: TimelineGroupMode) {
        _groupMode.value = mode
    }

    // The deep-linkable filters are saved per navigation entry, so recreation restores them as the
    // user left them (a dismissed deep-link chip stays dismissed).
    private val _filter = MutableStateFlow(
        TimelineFilter(packageName = savedState[KEY_PACKAGE], scanId = savedState[KEY_SCAN])
    )

    /** What the list, the counts and the exports read. */
    val filter: StateFlow<TimelineFilter> = _filter.asStateFlow()

    fun setFindingsAndEvidenceOnly(only: Boolean) = _filter.update { it.copy(findingsAndEvidenceOnly = only) }

    fun toggleSeverity(level: String) = _filter.update {
        it.copy(levels = if (level in it.levels) it.levels - level else it.levels + level)
    }

    fun setSourceFilter(source: TelemetrySource?) = _filter.update { it.copy(source = source) }

    fun setPackageFilter(pkg: String?) = _filter.update { it.copy(packageName = pkg) }

    fun setDateRange(start: Long, end: Long) = _filter.update { it.copy(from = start, to = end) }

    fun clearDateRange() = _filter.update { it.copy(from = null, to = null) }

    /** The last [hours] hours up to now (a Filters-sheet preset); null clears the range. */
    fun setRecentHours(hours: Int?) {
        if (hours == null) return clearDateRange()
        val now = System.currentTimeMillis()
        setDateRange(now - hours * HOUR_MS, now)
    }

    /** Shows only [scanId]'s rows and the facts it observed (null: every scan). */
    fun setScanFilter(scanId: Long?) = _filter.update { it.copy(scanId = scanId) }

    /**
     * Applies a navigation entry's deep link (the Apps screen's package, the import screen's scan)
     * once per entry (I1): recreation (rotation, theme or locale change, process death) delivers the
     * same arguments again, and re-applying them would undo a chip the user dismissed. A blank
     * [packageName] means "no real package" and clears the package filter.
     */
    fun applyDeepLink(packageName: String?, scanId: Long?) {
        if (savedState.get<Boolean>(KEY_DEEP_LINK_APPLIED) == true) return
        savedState[KEY_DEEP_LINK_APPLIED] = true
        if (packageName != null) setPackageFilter(packageName.ifBlank { null })
        if (scanId != null) setScanFilter(scanId)
    }

    /** "Show only this app" from a detail sheet (ruling R33): an exact package filter, shown as a chip. */
    fun showOnlyApp(packageName: String) = setPackageFilter(packageName)

    fun clearFilters() = _filter.update { TimelineFilter(zone = it.zone, query = it.query) }

    /** Clears exactly the filter [chip] stands for (the filter bar's dismissible chips). */
    fun dismiss(chip: ActiveFilter) = _filter.update {
        when (chip) {
            is ActiveFilter.Scan -> it.copy(scanId = null)
            is ActiveFilter.Package -> it.copy(packageName = null)
            is ActiveFilter.Source -> it.copy(source = null)
            is ActiveFilter.Severity -> it.copy(levels = it.levels - chip.level)
            is ActiveFilter.DateRange -> it.copy(from = null, to = null)
            ActiveFilter.FindingsOnly -> it.copy(findingsAndEvidenceOnly = false)
        }
    }

    /** The filter bar's chips, one per active filter ([activeFiltersOf]). */
    val activeFilters: StateFlow<List<ActiveFilter>> = _filter.map(::activeFiltersOf)
        .stateIn(viewModelScope, SharingStarted.Eagerly, emptyList())

    private val _searchText = MutableStateFlow("")

    /** The search field's text as typed; it reaches [filter] after [SEARCH_DEBOUNCE_MS] of quiet. */
    val searchText: StateFlow<String> = _searchText.asStateFlow()

    fun setSearchText(text: String) {
        _searchText.value = text
    }

    /** Empties the search field and drops the search at once (closing the search bar). */
    fun clearSearch() {
        _searchText.value = ""
        _filter.update { it.copy(query = null) }
    }

    init {
        viewModelScope.launch {
            _filter.collect {
                savedState[KEY_PACKAGE] = it.packageName
                savedState[KEY_SCAN] = it.scanId
            }
        }
        // Typing re-queries once per pause, not per keystroke; the read itself runs on IO (the pager).
        viewModelScope.launch {
            _searchText.debounce(SEARCH_DEBOUNCE_MS).collect { text ->
                _filter.update { it.copy(query = text.trim().ifEmpty { null }) }
            }
        }
    }

    /**
     * Bumps when a scan completes or is deleted, or Timeline rows change (what changes counts),
     * coalesced over [COUNT_DEBOUNCE_MS] (but at least every [COUNT_MAX_WAIT_MS] under a steady
     * stream) so a burst of row inserts (live DNS IOC matches, a scan's
     * finish) re-counts once, not once per change.
     */
    private val tableVersion: StateFlow<Int> = db.tableChanges(KeysetPagingSource.OBSERVED_TABLES)
        .coalescedVersions(COUNT_DEBOUNCE_MS, COUNT_MAX_WAIT_MS)
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5000), 0)

    /** The paged list: the union under [filter], a [TimelineRow.DayHeader] before each day. */
    @OptIn(ExperimentalCoroutinesApi::class)
    val rows: Flow<PagingData<TimelineRow>> = _filter.flatMapLatest { filter ->
        Pager(PagingConfig(pageSize = PAGE_SIZE, enablePlaceholders = false)) {
            TimelinePagingSource(db, filter, entries)
        }.flow.map { data ->
            data.insertSeparators<TimelineRow.Entry, TimelineRow> { before, after ->
                val next = after?.let { filter.dayOf(it.timestamp, it.entity.isDay) }
                val prev = before?.let { filter.dayOf(it.timestamp, it.entity.isDay) }
                if (next != null && next != prev) TimelineRow.DayHeader(next, after.key) else null
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
    /**
     * Entries [filter] matches, off the main thread; null when the count fails (I3): a count is
     * informational, so a failing statement shows no count rather than crashing the screen.
     */
    @Suppress("TooGenericExceptionCaught") // any SQLite or Room failure; cancellation is rethrown
    suspend fun count(filter: TimelineFilter): Long? = try {
        withContext(io) { entries.count(filter) }
    } catch (e: CancellationException) {
        throw e
    } catch (e: Exception) {
        android.util.Log.e(TAG, "Timeline count failed: ${e.message}", e)
        null
    }

    /** Where a fact came from (the fact detail sheet, I4); null when it is no longer visible. */
    suspend fun provenance(factId: Long): FactProvenance? = withContext(io) { entries.provenance(factId) }

    /** A date header's count: the current filter narrowed to [day]. */
    suspend fun dayCount(day: Long): Long? = count(_filter.value.forDay(day))

    /** A scan header's count: the current filter narrowed to [scanId]. */
    suspend fun scanCount(scanId: Long): Long? = count(_filter.value.copy(scanId = scanId))

    /**
     * The pinned section (C5, ruling R34): the current findings' triggered state findings — the
     * latest live scan's ([FindingsRepository.current]; imports never displace live state).
     */
    val findings: StateFlow<List<Finding>> = findingsRepository.current()
        .map { timelineFindingRows(it.stateFindings) }
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5000), emptyList())

    /** "By scan": one header per completed scan, newest first, keyset-paged (no cap, spec §5.5). */
    val scanGroups: Flow<PagingData<ScanGroup>> = scanRepository.pagedScans()
        .map { page -> page.map(::scanGroup) }
        .cachedIn(viewModelScope)

    private fun scanGroup(scan: ScanResult): ScanGroup = ScanGroup(
        scanId = scan.id,
        timestamp = scan.timestamp,
        importSource = scan.source.takeIf { it != TelemetrySource.LIVE_SCAN },
        maxSeverity = scan.maxLevel?.uppercase() ?: "INFO",
    )

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
                val filter = _filter.value
                val file = withContext(Dispatchers.IO) {
                    newReportFile("txt", filter).also { writePlaintext(it, filter) }
                }
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
    private fun export(extension: String, write: suspend (File, TimelineFilter) -> Unit) {
        if (_exporting.value) return
        // One filter for the whole export: the file name's label and the content can never disagree.
        val filter = _filter.value
        viewModelScope.launch {
            _exporting.value = true
            try {
                _shareUri.value = withContext(io) {
                    uriOf(newReportFile(extension, filter).also { write(it, filter) })
                }
            } catch (e: Exception) {
                android.util.Log.e(TAG, "Export failed: ${e.message}", e)
            } finally {
                _exporting.value = false
            }
        }
    }

    /**
     * Streams the current filter's Timeline as CSV, oldest first, one page at a time, through
     * [writeReportFile]: a failure partway (a full disk) leaves no truncated file behind.
     */
    private suspend fun writeCsv(file: File, filter: TimelineFilter) {
        writeReportFile(file) { out ->
            TimelineExporter.writeCsvHeader(out)
            entries.forEachPage(filter, oldestFirst = true, size = EXPORT_PAGE) { page ->
                val events = page.flatMap { it.exportEvents() }
                val refs = memberRefs(events)
                events.forEach { TimelineExporter.writeCsvRow(out, it, refs[it.id].orEmpty()) }
            }
        }
    }

    /**
     * Streams the current filter's Timeline as plaintext, newest first: one pass for the header, one
     * to write. The two passes are separate reads, so a scan completing between them can make the
     * header's totals differ slightly from the body; neither pass holds the whole Timeline. Written
     * through [writeReportFile], so a failure partway leaves no truncated file behind.
     */
    private suspend fun writePlaintext(file: File, filter: TimelineFilter) {
        val stats = TimelineExporter.PlaintextStats(buildRuleGuidance())
        entries.forEachPage(filter, oldestFirst = false, size = EXPORT_PAGE) { page ->
            page.forEach { entry -> entry.exportEvents().forEach(stats::add) }
        }
        val names = HashMap<String, String?>()
        writeReportFile(file) { out: Writer ->
            val writer = TimelineExporter.PlaintextWriter(out) { pkg ->
                names.getOrPut(pkg) { knownAppResolver.lookup(pkg)?.displayName }
            }
            writer.header(stats, appContext.appVersion().name, filter.describe())
            entries.forEachPage(filter, oldestFirst = false, size = EXPORT_PAGE) { page ->
                page.forEach(writer::entry)
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

    private fun newReportFile(extension: String, filter: TimelineFilter): File {
        val reportsDir = File(appContext.cacheDir, "reports").apply { mkdirs() }
        val ts = SimpleDateFormat("yyyyMMdd_HHmmss", Locale.US).format(Date())
        val suffix = if (filter.describe() != null) "_filtered" else ""
        return File(reportsDir, "androdr_timeline_$ts$suffix.$extension")
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
                val scan = scanRepository.latestTwo.first().firstOrNull() ?: return@launch
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
        private const val COUNT_DEBOUNCE_MS = 300L
        private const val COUNT_MAX_WAIT_MS = 3_000L
        private const val SEARCH_DEBOUNCE_MS = 300L
        private const val HOUR_MS = 3_600_000L
        private const val KEY_DEEP_LINK_APPLIED = "timeline.deepLinkApplied"
        private const val KEY_PACKAGE = "timeline.packageFilter"
        private const val KEY_SCAN = "timeline.scanFilter"

        /** The report sheet shows (and Copy copies) at most this much; a longer report is shared as a file. */
        const val PREVIEW_CHARS = 200_000
    }
}

/**
 * A Timeline entry as the exporters write it, in display order: a row as stored, then its nested
 * evidence fact (so every `record_id` resolves within the file and the export's total is the
 * on-screen count); a fact as an `event` row of its service.
 */
internal fun TimelineRow.Entry.exportEvents(): List<ForensicTimelineEvent> = when (this) {
    is TimelineRow.StoredRow -> listOfNotNull(event, evidence?.asExportEvent(event.scanResultId))
    is TimelineRow.EventRow -> listOf(record.asExportEvent(entity.scanId, entity.packageName))
}

/**
 * Writes one Timeline entry: the entry itself, then (for a row) its nested evidence inside the
 * row's date section (re-review n5: evidence of another day never repeats a date header).
 */
internal fun TimelineExporter.PlaintextWriter.entry(entry: TimelineRow.Entry) {
    val lines = entry.exportEvents()
    event(lines.first())
    lines.drop(1).forEach(::evidence)
}

/**
 * A stored fact as an exported `event` row: its display summary as the description, its fact id as
 * `recordId`, and row id 0 (never colliding with a signal row's member refs). [scanId] is the scan
 * the Timeline read it under, when known (≥ 0); [packageName] the fact's computed package, when the
 * caller has it (else the record's `package_name` field).
 */
internal fun DecodedRecord.asExportEvent(
    scanId: Long,
    packageName: String = (fields?.get("package_name") as? String).orEmpty(),
): ForensicTimelineEvent = ForensicTimelineEvent(
    startTimestamp = eventTime ?: capturedAt,
    kind = "event",
    timestampPrecision = if (precision == TimePrecision.DAY) TimelineExporter.DAY_PRECISION else "exact",
    source = service,
    category = category?.ifEmpty { null } ?: service,
    description = summary.orEmpty(),
    packageName = packageName,
    scanResultId = if (scanId >= 0) scanId else this.scanId,
    telemetrySource = source,
    createdAt = capturedAt,
    recordId = factId,
)

/**
 * A version number that bumps once per burst of changes: a change followed by quiet for [quietMs]
 * bumps it once, however many changes the burst held (counts re-run per burst, not per change). A
 * burst that never goes quiet still bumps once every [maxWaitMs] from its first change (#418: a
 * plain debounce starved the counts under a continuous stream). Starts at 0.
 */
internal fun Flow<Unit>.coalescedVersions(quietMs: Long, maxWaitMs: Long = quietMs * DEFAULT_MAX_WAIT_FACTOR): Flow<Int> =
    flow {
        var version = 0
        emit(version)
        coroutineScope {
            val changes = this@coalescedVersions.buffer(Channel.CONFLATED).produceIn(this)
            var open = true
            while (open && changes.receiveCatching().isSuccess) {
                // In a burst: wait for quiet, an end of stream, or the burst's max wait, then bump.
                withTimeoutOrNull(maxWaitMs) {
                    while (true) {
                        val next = withTimeoutOrNull(quietMs) { changes.receiveCatching() } ?: break
                        if (!next.isSuccess) {
                            open = false
                            break
                        }
                    }
                }
                emit(++version)
            }
        }
    }

private const val DEFAULT_MAX_WAIT_FACTOR = 10

/** The active filter in words for an export header, or null when nothing is filtered. */
internal fun TimelineFilter.describe(): String? = buildList {
    scanId?.let { add("scan $it") }
    packageName?.let { add("package $it") }
    source?.let { add("source $it") }
    if (from != null || to != null) {
        fun iso(ms: Long?) =
            ms?.let { java.time.Instant.ofEpochMilli(it).atZone(zone).toLocalDateTime().toString() } ?: "-"
        add("time ${iso(from)}..${iso(to)} ($zone)")
    }
    if (levels.isNotEmpty()) add("severity ${levels.sorted().joinToString("/")}")
    if (findingsAndEvidenceOnly) add("findings and their evidence only")
    searchText?.let { add("search \"$it\"") }
}.takeIf { it.isNotEmpty() }?.joinToString(", ")

/** One active filter, shown as a dismissible chip on the filter bar ([activeFiltersOf]). */
sealed interface ActiveFilter {
    data class Scan(val scanId: Long) : ActiveFilter
    data class Package(val packageName: String) : ActiveFilter
    data class Source(val source: TelemetrySource) : ActiveFilter
    data class Severity(val level: String) : ActiveFilter
    data class DateRange(val from: Long?, val to: Long?) : ActiveFilter
    data object FindingsOnly : ActiveFilter
}

/** Severity chips' order: most severe first. */
private val SEVERITY_ORDER = listOf("CRITICAL", "HIGH", "MEDIUM", "LOW")

/**
 * The filter bar's chips for [filter], in bar order: scan, package, source, each severity (most
 * severe first), date range, findings only. The Filters button shows how many. The search query is
 * not a chip: the search field shows it.
 */
internal fun activeFiltersOf(filter: TimelineFilter): List<ActiveFilter> = buildList {
    filter.scanId?.let { add(ActiveFilter.Scan(it)) }
    filter.packageName?.let { add(ActiveFilter.Package(it)) }
    filter.source?.let { add(ActiveFilter.Source(it)) }
    filter.levels.sortedWith(compareBy<String>({ lvl ->
        SEVERITY_ORDER.indexOf(lvl.uppercase()).let { if (it < 0) SEVERITY_ORDER.size else it }
    }, { it })).forEach { add(ActiveFilter.Severity(it)) }
    if (filter.from != null || filter.to != null) add(ActiveFilter.DateRange(filter.from, filter.to))
    if (filter.findingsAndEvidenceOnly) add(ActiveFilter.FindingsOnly)
}
