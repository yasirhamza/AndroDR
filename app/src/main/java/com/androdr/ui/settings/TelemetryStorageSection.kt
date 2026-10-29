package com.androdr.ui.settings

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
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.androdr.data.store.BodyStats
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

    Text(text = "Telemetry storage", style = MaterialTheme.typography.titleMedium)
    Card(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceContainer),
    ) {
        Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
            val s = storage
            if (s == null) {
                Text("Storage size unavailable", style = MaterialTheme.typography.bodySmall)
            } else {
                StatRow("Snapshots", stats(s.snapshots))
                StatRow("Live events", stats(s.liveEvents))
                StatRow("Imports", stats(s.imports))
                StatRow("Total", stats(s.total))
            }
        }
    }
    RetentionControl(keep = keep, onCommit = viewModel::setRetentionScans)
    OutlinedButton(
        onClick = { confirm = true },
        modifier = Modifier.fillMaxWidth(),
        enabled = cleanup != TelemetryCleanup.Running,
    ) {
        Text(if (cleanup == TelemetryCleanup.Running) "Deleting…" else "Delete old snapshot telemetry now")
    }

    if (confirm) {
        AlertDialog(
            onDismissRequest = { confirm = false },
            title = { Text("Delete old snapshot telemetry?") },
            text = {
                Text(
                    "Removes snapshot telemetry of live scans older than the newest $keep, and live events " +
                        "older than 30 days. Imports and records behind findings or alerts are kept."
                )
            },
            confirmButton = {
                TextButton(onClick = {
                    confirm = false
                    viewModel.deleteOldSnapshotsNow()
                }) { Text("Delete", color = MaterialTheme.colorScheme.error) }
            },
            dismissButton = { TextButton(onClick = { confirm = false }) { Text("Cancel") } },
        )
    }

    cleanupMessage(cleanup)?.let { message ->
        AlertDialog(
            onDismissRequest = { viewModel.dismissCleanup() },
            text = { Text(message) },
            confirmButton = { TextButton(onClick = { viewModel.dismissCleanup() }) { Text("OK") } },
        )
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
        text = "Keep snapshot telemetry for the last $shown scans",
        style = MaterialTheme.typography.bodyMedium,
    )
    Row(verticalAlignment = Alignment.CenterVertically) {
        IconButton(onClick = { step(-1) }, enabled = shown > range.first) {
            Icon(Icons.Filled.Remove, contentDescription = "Keep one scan fewer")
        }
        Slider(
            value = position,
            onValueChange = { position = it },
            onValueChangeFinished = { onCommit(retentionFromSlider(position)) },
            valueRange = range.first.toFloat()..range.last.toFloat(),
            modifier = Modifier.weight(1f),
        )
        IconButton(onClick = { step(1) }, enabled = shown < range.last) {
            Icon(Icons.Filled.Add, contentDescription = "Keep one scan more")
        }
    }
}

/** The whole number of scans a slider [position] stands for, within the retention range. */
internal fun retentionFromSlider(position: Float): Int = clampRetention(position.roundToInt())

/** The retention one "fewer" (-1) or "more" (+1) step from [current], within the retention range. */
internal fun retentionStep(current: Int, delta: Int): Int = clampRetention(current + delta)

private fun clampRetention(scans: Int): Int =
    scans.coerceIn(TelemetrySettingsViewModel.RETENTION_RANGE.first, TelemetrySettingsViewModel.RETENTION_RANGE.last)

internal fun stats(b: BodyStats): String = "${groupedCount(b.bodies)} distinct records · ${humanBytes(b.storedBytes)}"

internal fun cleanupMessage(cleanup: TelemetryCleanup): String? = when (cleanup) {
    is TelemetryCleanup.Done -> "Removed ${groupedCount(cleanup.observationsRemoved)} old telemetry record(s)."
    TelemetryCleanup.Busy -> "Another storage task is running. Try again shortly."
    TelemetryCleanup.Failed -> "Old telemetry could not be deleted."
    TelemetryCleanup.Idle, TelemetryCleanup.Running -> null
}
