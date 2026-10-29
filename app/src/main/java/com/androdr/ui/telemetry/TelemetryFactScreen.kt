package com.androdr.ui.telemetry

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.androdr.R
import com.androdr.data.store.DecodedRecord
import com.androdr.reporting.escapeForReport
import com.androdr.ui.timeline.factDate
import com.androdr.ui.timeline.factTime
import com.androdr.ui.timeline.telemetrySourceLabel

/**
 * The browser's third level (spec §8.1), also "Matched record" (spec §6): one fact's provenance and
 * fields in taxonomy order with their descriptions. A snapshot record offers its subject's history
 * across scans ([SubjectHistorySheet]). An unreadable body is shown as unreadable.
 */
@Composable
fun TelemetryFactScreen(
    onBack: () -> Unit,
    viewModel: TelemetryBrowserViewModel = hiltViewModel(),
) {
    val state by viewModel.fact.collectAsStateWithLifecycle()
    var showHistory by rememberSaveable { mutableStateOf(false) }
    Column(modifier = Modifier.fillMaxSize()) {
        when (val s = state) {
            FactState.Loading -> {
                TelemetryTopBar(stringResource(R.string.telemetry_title), onBack)
                CenteredProgress()
            }
            FactState.Missing -> {
                TelemetryTopBar(stringResource(R.string.telemetry_title), onBack)
                CenteredMessage(stringResource(R.string.telemetry_fact_missing))
            }
            is FactState.Loaded -> {
                TelemetryTopBar(s.record.service, onBack)
                FactBody(s, onShowHistory = { showHistory = true })
            }
        }
    }
    if (showHistory) {
        val history by viewModel.history.collectAsStateWithLifecycle()
        val service = (state as? FactState.Loaded)?.record?.service.orEmpty()
        SubjectHistorySheet(service = service, entries = history, onDismiss = { showHistory = false })
    }
}

@Composable
private fun FactBody(state: FactState.Loaded, onShowHistory: () -> Unit) {
    val record = state.record
    LazyColumn(
        modifier = Modifier.fillMaxSize(),
        contentPadding = PaddingValues(16.dp),
        verticalArrangement = Arrangement.spacedBy(10.dp),
    ) {
        item(key = "header") {
            Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
                Text(record.category ?: record.service, style = MaterialTheme.typography.titleMedium,
                    fontWeight = FontWeight.Bold)
                Text(observedLine(record), style = MaterialTheme.typography.labelMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant)
                if (state.hasHistory) {
                    OutlinedButton(onClick = onShowHistory) { Text(stringResource(R.string.telemetry_subject_history)) }
                }
                HorizontalDivider()
            }
        }
        val fields = state.fields
        if (fields == null) {
            item(key = "unreadable") {
                Text(stringResource(R.string.telemetry_record_unreadable), color = MaterialTheme.colorScheme.error)
            }
        } else {
            items(fields, key = { it.key }) { FieldItem(it, changed = false) }
        }
    }
}

/** A record's time and provenance: "<date> <time> · <source>". */
@Composable
internal fun observedLine(record: DecodedRecord): String {
    val time = record.eventTime ?: record.capturedAt
    val source = stringResource(telemetrySourceLabel(record.source))
    return "${factDate(record, time)}  ${factTime(record, time)} · $source"
}

/** One field: its key, value and (when [showDescription]) taxonomy description; a [changed] field is highlighted. */
@Composable
internal fun FieldItem(row: FieldRow, changed: Boolean, showDescription: Boolean = true) {
    val accent = if (changed) MaterialTheme.colorScheme.primary else Color.Unspecified
    Column(modifier = Modifier.fillMaxWidth()) {
        Text(
            if (changed) stringResource(R.string.telemetry_field_changed, escapeForReport(row.key))
            else escapeForReport(row.key),
            style = MaterialTheme.typography.labelMedium,
            fontWeight = if (changed) FontWeight.Bold else FontWeight.SemiBold,
            color = if (changed) accent else MaterialTheme.colorScheme.onSurfaceVariant,
        )
        Text(escapeForReport(row.value.toString()), style = MaterialTheme.typography.bodyMedium,
            fontWeight = if (changed) FontWeight.Bold else null, color = accent)
        row.description?.takeIf { showDescription }?.let {
            Text(it, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
        }
    }
}
