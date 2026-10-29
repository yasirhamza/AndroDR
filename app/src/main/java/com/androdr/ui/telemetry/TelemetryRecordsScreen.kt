package com.androdr.ui.telemetry

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.text.KeyboardActions
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Clear
import androidx.compose.material.icons.filled.Search
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalSoftwareKeyboardController
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.paging.LoadState
import androidx.paging.compose.collectAsLazyPagingItems
import androidx.paging.compose.itemKey
import com.androdr.R
import com.androdr.data.store.DecodedRecord
import com.androdr.reporting.escapeForReport
import com.androdr.ui.timeline.factDate
import com.androdr.ui.timeline.factTime

/**
 * The browser's second level (spec §8.1): one scan's records of one service in emitted order,
 * keyset-paged, with a debounced search over the package name and subject key. A record whose
 * body cannot be decoded is listed as unreadable.
 */
@Composable
fun TelemetryRecordsScreen(
    onOpenFact: (factId: Long, scanId: Long) -> Unit,
    onBack: () -> Unit,
    viewModel: TelemetryBrowserViewModel = hiltViewModel(),
) {
    val records = viewModel.records.collectAsLazyPagingItems()
    val searchText by viewModel.searchText.collectAsStateWithLifecycle()
    val query by viewModel.query.collectAsStateWithLifecycle()
    val keyboard = LocalSoftwareKeyboardController.current
    Column(modifier = Modifier.fillMaxSize()) {
        TelemetryTopBar(viewModel.service.orEmpty(), onBack)
        OutlinedTextField(
            value = searchText,
            onValueChange = viewModel::setSearchText,
            modifier = Modifier.fillMaxWidth().padding(horizontal = 16.dp),
            singleLine = true,
            leadingIcon = { Icon(Icons.Filled.Search, contentDescription = null) },
            placeholder = { Text(stringResource(R.string.telemetry_search_hint), maxLines = 1) },
            trailingIcon = {
                if (searchText.isNotEmpty()) {
                    IconButton(onClick = { viewModel.setSearchText("") }) {
                        Icon(Icons.Filled.Clear, contentDescription = stringResource(R.string.telemetry_search_clear))
                    }
                }
            },
            keyboardOptions = KeyboardOptions(imeAction = ImeAction.Search),
            keyboardActions = KeyboardActions(onSearch = { keyboard?.hide() }),
        )
        val refreshed = records.loadState.refresh is LoadState.NotLoading
        if (refreshed && records.itemCount == 0) {
            CenteredMessage(
                query?.let { stringResource(R.string.telemetry_search_no_matches, escapeForReport(it)) }
                    ?: stringResource(R.string.telemetry_records_empty)
            )
            return@Column
        }
        LazyColumn(
            modifier = Modifier.fillMaxSize(),
            contentPadding = PaddingValues(16.dp),
            verticalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            items(count = records.itemCount, key = records.itemKey { it.ordinal }) { index ->
                val record = records[index] ?: return@items
                RecordCard(record) { onOpenFact(record.factId, record.scanId) }
            }
        }
    }
}

/** One record: its time (event time, else capture time) and display summary, or "unreadable". */
@Composable
private fun RecordCard(record: DecodedRecord, onClick: () -> Unit) {
    val time = record.eventTime ?: record.capturedAt
    Card(
        modifier = Modifier.fillMaxWidth().clickable(onClick = onClick),
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceContainer),
    ) {
        Column(modifier = Modifier.padding(12.dp)) {
            Text(
                "${factDate(record, time)}  ${factTime(record, time)}",
                style = MaterialTheme.typography.labelSmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            Text(
                recordLine(record) ?: stringResource(R.string.telemetry_record_unreadable),
                style = MaterialTheme.typography.bodySmall,
                maxLines = 2,
                overflow = TextOverflow.Ellipsis,
                color = if (record.fields == null) MaterialTheme.colorScheme.error
                else MaterialTheme.colorScheme.onSurface,
            )
        }
    }
}

/**
 * A record's one-line text: its display summary, else its subject key, else its first fields; null
 * when the body is unreadable. Device-controlled text, so escaped.
 */
internal fun recordLine(record: DecodedRecord): String? {
    val fields = record.fields ?: return null
    val text = record.summary ?: record.subjectKey
        ?: fields.entries.take(PREVIEW_FIELDS).joinToString(", ") { "${it.key}=${it.value}" }
    return escapeForReport(text)
}

private const val PREVIEW_FIELDS = 3
