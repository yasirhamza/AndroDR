package com.androdr.ui.telemetry

import androidx.lifecycle.SavedStateHandle
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import androidx.paging.Pager
import androidx.paging.PagingConfig
import androidx.paging.PagingData
import androidx.paging.cachedIn
import com.androdr.data.db.ScanResultDao
import com.androdr.data.db.chunkedIn
import com.androdr.data.db.ServiceSummary
import com.androdr.data.store.DecodedRecord
import com.androdr.data.store.TelemetryReader
import com.androdr.sigma.TaxonomyContract
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.FlowPreview
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.debounce
import kotlinx.coroutines.flow.flatMapLatest
import kotlinx.coroutines.flow.flowOf
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.launch
import javax.inject.Inject

/** The services level: loading, the scan is not browsable (not `COMPLETE`, or gone), or its services. */
sealed interface ServicesState {
    data object Loading : ServicesState
    data object Unavailable : ServicesState
    data class Loaded(val services: List<ServiceSummary>) : ServicesState
}

/** One field of a fact: its taxonomy [description], null for a key the taxonomy does not declare. */
data class FieldRow(val key: String, val value: Any?, val description: String?)

/** The fact level: loading, not visible (deleted, or never stored), or the fact. */
sealed interface FactState {
    data object Loading : FactState
    data object Missing : FactState

    /**
     * [fields] in taxonomy order, null when the body is unreadable. [hasHistory]: a snapshot record
     * (no event time) with a subject key, whose subject can be followed across scans.
     */
    data class Loaded(val record: DecodedRecord, val fields: List<FieldRow>?, val hasHistory: Boolean) : FactState
}

/** One observation in a subject's history and the fields that differ from the observation before it. */
data class HistoryEntry(val record: DecodedRecord, val changed: Set<String>)

/**
 * The telemetry browser (spec §8.1), one instance per navigation entry. Its route's arguments pick
 * the level: [ARG_SCAN] alone, the services of that scan; with [ARG_SERVICE], that service's
 * records, keyset-paged, narrowed by a search debounced over [SEARCH_DEBOUNCE_MS]; [ARG_FACT] (with
 * an optional [ARG_FACT_SCAN]), one fact's fields and, for a snapshot record, its subject's history.
 * Every read goes through [TelemetryReader], so only `COMPLETE` scans (and pinned facts) are shown.
 */
@OptIn(ExperimentalCoroutinesApi::class, FlowPreview::class)
@HiltViewModel
class TelemetryBrowserViewModel @Inject constructor(
    private val reader: TelemetryReader,
    private val scans: ScanResultDao,
    savedState: SavedStateHandle,
) : ViewModel() {

    val scanId: Long? = savedState.get<Long>(ARG_SCAN)
    val service: String? = savedState.get<String>(ARG_SERVICE)
    private val factId: Long? = savedState.get<Long>(ARG_FACT)
    private val factScan: Long? = savedState.get<Long>(ARG_FACT_SCAN)?.takeIf { it != NO_SCAN }

    private val _services = MutableStateFlow<ServicesState>(ServicesState.Loading)
    val services: StateFlow<ServicesState> = _services.asStateFlow()

    private val _searchText = MutableStateFlow("")
    /** What the search field shows, updated per keystroke. */
    val searchText: StateFlow<String> = _searchText.asStateFlow()

    private val _query = MutableStateFlow<String?>(null)
    /** The search the records are narrowed by: [searchText] trimmed, after a quiet [SEARCH_DEBOUNCE_MS]. */
    val query: StateFlow<String?> = _query.asStateFlow()

    private val _fact = MutableStateFlow<FactState>(FactState.Loading)
    val fact: StateFlow<FactState> = _fact.asStateFlow()

    init {
        scanId?.let { id ->
            viewModelScope.launch {
                _services.value = if (scans.completeById(id) == null) {
                    ServicesState.Unavailable
                } else {
                    ServicesState.Loaded(reader.services(id))
                }
            }
        }
        viewModelScope.launch {
            _searchText.debounce(SEARCH_DEBOUNCE_MS).collect { text -> _query.value = text.trim().ifEmpty { null } }
        }
        factId?.let { id ->
            viewModelScope.launch {
                val ids = listOf(id)
                // reader.records chunks internally; the outer chunkedIn satisfies SqlCompatibilityGateTest.
                val record = (factScan?.let { reader.recordsInScan(it, ids) }
                    ?: chunkedIn(ids) { reader.records(it) }).firstOrNull()
                _fact.value = record?.let {
                    FactState.Loaded(it, it.fields?.let { f -> fieldRows(it.service, f) }, hasHistory(it))
                } ?: FactState.Missing
            }
        }
    }

    fun setSearchText(text: String) {
        _searchText.value = text
    }

    /** One page source over this entry's scan and service under [search]; the records list pages through it. */
    internal fun pagingSource(search: String?) = reader.pagingSource(scanId ?: NO_SCAN, service.orEmpty(), search)

    /** The records level: re-queried (from the top) whenever [query] changes. */
    val records: Flow<PagingData<DecodedRecord>> = _query.flatMapLatest { q ->
        Pager(PagingConfig(pageSize = PAGE_SIZE, enablePlaceholders = false)) { pagingSource(q) }.flow
    }.cachedIn(viewModelScope)

    /**
     * The opened snapshot record's subject across scans, oldest first, each with the fields changed
     * since the observation before it; empty for an event record or one without a subject key.
     */
    val history: StateFlow<List<HistoryEntry>> = _fact.flatMapLatest { state ->
        val record = (state as? FactState.Loaded)?.record?.takeIf { state.hasHistory }
        val key = record?.subjectKey
        if (record == null || key == null) {
            flowOf(emptyList())
        } else {
            reader.history(record.service, key, snapshotsOnly = true).map(::historyOf)
        }
    }.stateIn(viewModelScope, SharingStarted.WhileSubscribed(STOP_TIMEOUT_MS), emptyList())

    companion object {
        const val ARG_SCAN = "scanId"
        const val ARG_SERVICE = "service"
        const val ARG_FACT = "factId"
        const val ARG_FACT_SCAN = "scan"

        /** [ARG_FACT_SCAN] when the fact is not opened from a scan (a nav Long argument cannot be null). */
        const val NO_SCAN = -1L
        const val SEARCH_DEBOUNCE_MS = 300L
        private const val PAGE_SIZE = 100
        private const val STOP_TIMEOUT_MS = 5_000L
    }
}

/** Envelope keys: provenance of an observation, not state of its subject, so never a change. */
private val ENVELOPE_KEYS = setOf("source", "captured_at")

private fun hasHistory(record: DecodedRecord): Boolean = record.eventTime == null && record.subjectKey != null

/** [fields] in the service's taxonomy order with their descriptions, then undeclared keys by name. */
internal fun fieldRows(service: String, fields: Map<String, Any?>): List<FieldRow> {
    val order = TaxonomyContract.fieldOrder(service)
    val declared = order.filter { it in fields }
    val rest = fields.keys.filter { it !in order }.sorted()
    return (declared + rest).map { FieldRow(it, fields[it], TaxonomyContract.description(service, it)) }
}

/** Each entry marked with the fields changed since the entry before it (none for the first). */
internal fun historyOf(records: List<DecodedRecord>): List<HistoryEntry> =
    records.mapIndexed { i, r ->
        HistoryEntry(r, if (i == 0) emptySet() else changedKeys(records[i - 1].fields, r.fields))
    }

/**
 * The keys whose value differs between [before] and [after], including keys only one has; envelope
 * keys excluded. Empty when either body is unreadable: nothing can be compared.
 */
internal fun changedKeys(before: Map<String, Any?>?, after: Map<String, Any?>?): Set<String> {
    if (before == null || after == null) return emptySet()
    return (before.keys + after.keys).filterTo(LinkedHashSet()) { it !in ENVELOPE_KEYS && before[it] != after[it] }
}
