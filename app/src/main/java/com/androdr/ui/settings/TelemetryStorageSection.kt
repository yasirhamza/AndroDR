package com.androdr.ui.settings

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
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
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.androdr.data.store.BodyStats
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
    // The slider moves locally; the setting is stored once, when the drag ends.
    var dragging by remember(keep) { mutableFloatStateOf(keep.toFloat()) }
    val range = TelemetrySettingsViewModel.RETENTION_RANGE

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
            }
        }
    }
    Text(
        text = "Keep snapshot telemetry for the last ${dragging.roundToInt()} scans",
        style = MaterialTheme.typography.bodyMedium,
    )
    Slider(
        value = dragging,
        onValueChange = { dragging = it },
        onValueChangeFinished = { viewModel.setRetentionScans(dragging.roundToInt()) },
        valueRange = range.first.toFloat()..range.last.toFloat(),
        steps = range.last - range.first - 1,
    )
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

private fun stats(b: BodyStats): String = "${b.bodies} distinct records · ${humanBytes(b.storedBytes)}"

private fun cleanupMessage(cleanup: TelemetryCleanup): String? = when (cleanup) {
    is TelemetryCleanup.Done -> "Removed ${cleanup.observationsRemoved} old telemetry record(s)."
    TelemetryCleanup.Busy -> "A scan is running — try again when it finishes."
    TelemetryCleanup.Failed -> "Old telemetry could not be deleted."
    TelemetryCleanup.Idle, TelemetryCleanup.Running -> null
}
