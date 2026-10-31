package com.androdr.ui.settings

import android.content.res.Resources
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.Remove
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Slider
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableFloatStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.androdr.R
import com.androdr.data.store.BodyStats
import com.androdr.data.store.StorageSummary
import com.androdr.reporting.groupedCount
import com.androdr.reporting.humanBytes
import kotlin.math.roundToInt

/**
 * Settings' telemetry section (spec §8.2): storage size by kind, "Keep snapshot telemetry for the
 * last N scans", and "Delete old snapshot telemetry now" (the existing retention run).
 */
@Suppress("LongMethod") // one section: figures, slider, delete button and its two dialogs
@Composable
fun TelemetryStorageSection(viewModel: TelemetrySettingsViewModel = hiltViewModel()) {
    val storage by viewModel.storage.collectAsStateWithLifecycle()
    val keep by viewModel.retentionScans.collectAsStateWithLifecycle()
    val cleanup by viewModel.cleanup.collectAsStateWithLifecycle()
    var confirm by remember { mutableStateOf(false) }

    Text(text = stringResource(R.string.telemetry_storage_title), style = MaterialTheme.typography.titleMedium)
    StorageFigures(storage)
    RetentionControl(keep = keep, onCommit = viewModel::setRetentionScans)
    OutlinedButton(
        onClick = { confirm = true },
        modifier = Modifier.fillMaxWidth(),
        enabled = cleanup != TelemetryCleanup.Running,
    ) {
        val label = if (cleanup == TelemetryCleanup.Running) {
            R.string.telemetry_cleanup_running
        } else {
            R.string.telemetry_cleanup_action
        }
        Text(stringResource(label))
    }

    if (confirm) {
        AlertDialog(
            onDismissRequest = { confirm = false },
            title = { Text(stringResource(R.string.telemetry_cleanup_confirm_title)) },
            text = { Text(stringResource(R.string.telemetry_cleanup_confirm_body, keep)) },
            confirmButton = {
                TextButton(onClick = {
                    confirm = false
                    viewModel.deleteOldSnapshotsNow()
                }) { Text(stringResource(R.string.telemetry_cleanup_confirm), color = MaterialTheme.colorScheme.error) }
            },
            dismissButton = {
                TextButton(onClick = { confirm = false }) { Text(stringResource(android.R.string.cancel)) }
            },
        )
    }

    cleanupMessage(LocalContext.current.resources, cleanup)?.let { message ->
        AlertDialog(
            onDismissRequest = { viewModel.dismissCleanup() },
            text = { Text(message) },
            confirmButton = {
                TextButton(onClick = { viewModel.dismissCleanup() }) { Text(stringResource(android.R.string.ok)) }
            },
        )
    }
}

/**
 * The storage card: each retention kind, what is kept only for findings and alerts (pinned orphans)
 * and the alert evidence, then a Total of all of them (#418: the Total used to cover only the three
 * kinds, under a label that read as the whole store).
 */
@Composable
internal fun StorageFigures(storage: StorageSummary?) {
    Card(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceContainer),
    ) {
        Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
            if (storage == null) {
                Text(stringResource(R.string.telemetry_storage_unavailable), style = MaterialTheme.typography.bodySmall)
            } else {
                val res = LocalContext.current.resources
                StatRow(stringResource(R.string.telemetry_storage_snapshots), stats(res, storage.snapshots))
                StatRow(stringResource(R.string.telemetry_storage_live_events), stats(res, storage.liveEvents))
                StatRow(stringResource(R.string.telemetry_storage_imports), stats(res, storage.imports))
                StatRow(stringResource(R.string.telemetry_storage_pinned), stats(res, storage.pinnedOrphans))
                StatRow(
                    stringResource(R.string.telemetry_storage_alert_evidence), humanBytes(storage.alertEvidenceBytes),
                )
                StatRow(
                    stringResource(R.string.telemetry_storage_total),
                    stats(res, storage.allRecords, storage.allStoredBytes),
                )
            }
        }
    }
}

/**
 * "Keep snapshot telemetry for the last N scans" (battery B3): a continuous slider (a stepped one drew
 * 96 tick marks and made an exact value hard to hit) rounded to whole scans, with "one fewer" / "one
 * more" buttons for an exact value. The slider moves locally; the setting is stored when a drag ends
 * or a button is pressed.
 */
@Composable
internal fun RetentionControl(keep: Int, onCommit: (Int) -> Unit) {
    var position by remember(keep) { mutableFloatStateOf(keep.toFloat()) }
    val shown = retentionFromSlider(position)
    val range = TelemetrySettingsViewModel.RETENTION_RANGE
    fun step(delta: Int) {
        val next = retentionStep(shown, delta)
        position = next.toFloat()
        onCommit(next)
    }
    Text(
        text = stringResource(R.string.telemetry_retention_label, shown),
        style = MaterialTheme.typography.bodyMedium,
    )
    Row(verticalAlignment = Alignment.CenterVertically) {
        IconButton(onClick = { step(-1) }, enabled = shown > range.first) {
            Icon(Icons.Filled.Remove, contentDescription = stringResource(R.string.telemetry_retention_fewer))
        }
        Slider(
            value = position,
            onValueChange = { position = it },
            onValueChangeFinished = { onCommit(retentionFromSlider(position)) },
            valueRange = range.first.toFloat()..range.last.toFloat(),
            modifier = Modifier.weight(1f),
        )
        IconButton(onClick = { step(1) }, enabled = shown < range.last) {
            Icon(Icons.Filled.Add, contentDescription = stringResource(R.string.telemetry_retention_more))
        }
    }
}

/** The whole number of scans a slider [position] stands for, within the retention range. */
internal fun retentionFromSlider(position: Float): Int = clampRetention(position.roundToInt())

/** The retention one "fewer" (-1) or "more" (+1) step from [current], within the retention range. */
internal fun retentionStep(current: Int, delta: Int): Int = clampRetention(current + delta)

private fun clampRetention(scans: Int): Int =
    scans.coerceIn(TelemetrySettingsViewModel.RETENTION_RANGE.first, TelemetrySettingsViewModel.RETENTION_RANGE.last)

internal fun stats(res: Resources, b: BodyStats): String = stats(res, b.bodies, b.storedBytes)

private fun stats(res: Resources, records: Long, storedBytes: Long): String =
    res.getString(R.string.telemetry_storage_stats, groupedCount(records), humanBytes(storedBytes))

internal fun cleanupMessage(res: Resources, cleanup: TelemetryCleanup): String? = when (cleanup) {
    is TelemetryCleanup.Done -> res.getQuantityString(
        R.plurals.telemetry_cleanup_done,
        quantityOf(cleanup.observationsRemoved),
        groupedCount(cleanup.observationsRemoved),
    )
    TelemetryCleanup.Busy -> res.getString(R.string.telemetry_cleanup_busy)
    TelemetryCleanup.Failed -> res.getString(R.string.telemetry_cleanup_failed)
    TelemetryCleanup.Idle, TelemetryCleanup.Running -> null
}

private fun quantityOf(n: Long): Int = n.coerceAtMost(Int.MAX_VALUE.toLong()).toInt()
