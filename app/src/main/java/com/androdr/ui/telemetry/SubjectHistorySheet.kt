package com.androdr.ui.telemetry

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.itemsIndexed
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.ModalBottomSheet
import androidx.compose.material3.Text
import androidx.compose.material3.rememberModalBottomSheetState
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.pluralStringResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.androdr.R

/**
 * A snapshot record's subject across scans (spec §8.1): every visible observation, oldest first,
 * each with its fields in taxonomy order and the fields that changed since the observation before
 * it highlighted. An unreadable observation is shown as unreadable.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun SubjectHistorySheet(service: String, entries: List<HistoryEntry>, onDismiss: () -> Unit) {
    ModalBottomSheet(
        onDismissRequest = onDismiss,
        sheetState = rememberModalBottomSheetState(skipPartiallyExpanded = true),
    ) {
        LazyColumn(
            contentPadding = PaddingValues(start = 16.dp, end = 16.dp, bottom = 32.dp),
            verticalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            item(key = "title") {
                Text(stringResource(R.string.telemetry_subject_history), style = MaterialTheme.typography.titleMedium,
                    fontWeight = FontWeight.Bold)
            }
            itemsIndexed(entries, key = { i, e -> "${e.record.scanId}_${e.record.factId}_$i" }) { i, entry ->
                HistoryCard(service, entry, first = i == 0)
            }
        }
    }
}

@Composable
private fun HistoryCard(service: String, entry: HistoryEntry, first: Boolean) {
    Card(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceContainer),
    ) {
        Column(modifier = Modifier.fillMaxWidth().padding(12.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
            Text(observedLine(entry.record), style = MaterialTheme.typography.labelMedium,
                fontWeight = FontWeight.SemiBold)
            Text(
                when {
                    first -> stringResource(R.string.telemetry_history_first)
                    entry.changed.isEmpty() -> stringResource(R.string.telemetry_history_unchanged)
                    else -> pluralStringResource(R.plurals.telemetry_history_changed, entry.changed.size,
                        entry.changed.size)
                },
                style = MaterialTheme.typography.labelSmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            val fields = entry.record.fields
            if (fields == null) {
                Text(stringResource(R.string.telemetry_record_unreadable), color = MaterialTheme.colorScheme.error)
            } else {
                fieldRows(service, fields).forEach {
                    FieldItem(it, changed = it.key in entry.changed, showDescription = false)
                }
            }
        }
    }
}
