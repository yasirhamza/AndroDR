package com.androdr.ui.privacy

import android.content.res.Resources
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.ModalBottomSheet
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.rememberModalBottomSheetState
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalUriHandler
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.androdr.R
import com.androdr.privacy.AppPrivacyRow
import com.androdr.privacy.InspectOutcome
import com.androdr.privacy.RowSection
import com.androdr.privacy.TrackerGroup
import com.androdr.privacy.TrackerRow
import com.androdr.util.reportSafe

private const val TEXT_MAX = 80

/** Untrusted text (app labels, registry strings) reaches the screen only through [reportSafe]. */
internal fun safe(text: String) = reportSafe(text, TEXT_MAX)

internal fun sectionTitle(s: RowSection): Int = when (s) {
    RowSection.NEEDS_ATTENTION -> R.string.privacy_section_attention
    RowSection.CROSSING -> R.string.privacy_section_crossing
    RowSection.OTHER -> R.string.privacy_section_other
}

@Composable
internal fun AppRow(row: AppPrivacyRow, registrySize: Int, res: Resources, onClick: () -> Unit) {
    Column(
        modifier = Modifier.fillMaxWidth().clickable(onClick = onClick).padding(vertical = 10.dp),
        verticalArrangement = Arrangement.spacedBy(2.dp),
    ) {
        Text(PrivacyEvidenceText.appName(row), style = MaterialTheme.typography.titleSmall)
        Text(
            PrivacyEvidenceText.appStatus(row, registrySize, res),
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        if (row.refusedCategories.isNotEmpty()) {
            val cats = row.refusedCategories.joinToString(", ") { res.getString(categoryLabel(it)) }
            val tag = if (row.outcome == InspectOutcome.PARTIAL) {
                " (${res.getString(R.string.privacy_partly_inspected_tag)})"
            } else {
                ""
            }
            Text("$cats$tag", style = MaterialTheme.typography.bodySmall)
        }
    }
}

@Composable
internal fun TrackerCard(group: TrackerGroup, res: Resources, onOpenEvidence: (String, Int) -> Unit) {
    Card(
        modifier = Modifier.fillMaxWidth().padding(top = 12.dp),
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceContainer),
    ) {
        Column(modifier = Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(2.dp)) {
            val title = PrivacyEvidenceText.trackerName(group.name, group.website, group.trackerId)
            Text(title, style = MaterialTheme.typography.titleSmall, fontWeight = FontWeight.Bold)
            Website(group.website)
            Text(
                group.categories.joinToString(", ") { res.getString(categoryLabel(it)) },
                style = MaterialTheme.typography.bodySmall,
            )
            for ((app, tracker) in group.apps) {
                Text(
                    "${PrivacyEvidenceText.appName(app)}: ${PrivacyEvidenceText.line(tracker, res)}",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    modifier = Modifier.fillMaxWidth()
                        .clickable { onOpenEvidence(app.packageName, tracker.trackerId) }
                        .padding(vertical = 6.dp),
                )
            }
        }
    }
}

/** The parsed, lower-cased host only; tappable only for an https address (see [PrivacyEvidenceText.websiteLink]). */
@Composable
internal fun Website(raw: String) {
    val host = PrivacyEvidenceText.websiteHost(raw) ?: return
    val link = PrivacyEvidenceText.websiteLink(raw)
    val uri = LocalUriHandler.current
    if (link != null) {
        TextButton(onClick = { uri.openUri(link) }) { Text(safe(host)) }
    } else {
        Text(safe(host), style = MaterialTheme.typography.bodySmall)
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
internal fun AppDetailSheet(
    row: AppPrivacyRow,
    registrySize: Int,
    onDismiss: () -> Unit,
    onOpenEvidence: (String, Int) -> Unit,
) {
    val res = LocalContext.current.resources
    ModalBottomSheet(onDismissRequest = onDismiss, sheetState = rememberModalBottomSheetState()) {
        Column(
            modifier = Modifier.verticalScroll(rememberScrollState()).padding(horizontal = 24.dp, vertical = 8.dp),
            verticalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            Text(
                PrivacyEvidenceText.appName(row),
                style = MaterialTheme.typography.titleMedium,
                fontWeight = FontWeight.Bold,
            )
            Text(PrivacyEvidenceText.appStatus(row, registrySize, res), style = MaterialTheme.typography.bodyMedium)
            for (t in row.trackers) TrackerDetail(t, res) { onOpenEvidence(row.packageName, t.trackerId) }
        }
    }
}

/** One tracker in an app's sheet; tapping it opens what the scan matched ([onOpen]). */
@Composable
internal fun TrackerDetail(t: TrackerRow, res: Resources, onOpen: () -> Unit) {
    Column(
        verticalArrangement = Arrangement.spacedBy(2.dp),
        modifier = Modifier.fillMaxWidth().clickable(onClick = onOpen).padding(vertical = 4.dp),
    ) {
        val title = PrivacyEvidenceText.trackerName(t.name, t.website, t.trackerId)
        Text(title, style = MaterialTheme.typography.titleSmall)
        Website(t.website)
        Text(
            t.categories.joinToString(", ") { res.getString(categoryLabel(it)) },
            style = MaterialTheme.typography.bodySmall,
        )
        Text(PrivacyEvidenceText.line(t, res), style = MaterialTheme.typography.bodySmall)
        if (t.newSinceLastScan) {
            Text(stringResource(R.string.privacy_new_tag), style = MaterialTheme.typography.labelSmall)
        }
    }
}

@Composable
internal fun DeleteResultsDialog(onConfirm: () -> Unit, onDismiss: () -> Unit) {
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(stringResource(R.string.privacy_delete)) },
        text = { Text(stringResource(R.string.privacy_delete_confirm)) },
        confirmButton = { TextButton(onClick = onConfirm) { Text(stringResource(R.string.privacy_delete)) } },
        dismissButton = { TextButton(onClick = onDismiss) { Text(stringResource(R.string.privacy_delete_cancel)) } },
    )
}
