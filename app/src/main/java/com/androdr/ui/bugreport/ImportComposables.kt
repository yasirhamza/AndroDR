package com.androdr.ui.bugreport

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyListScope
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.pluralStringResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.androdr.R

// The import preflight dialog and the import card (A7c), split from BugReportScreen.

internal fun LazyListScope.importCardItem(card: ImportCard?) {
    card?.let { item { ImportCardView(it) } }
}

/** Shows the preflight dialog while the ViewModel waits for the user's choice. */
@Composable
internal fun PreflightDialogHost(viewModel: BugReportViewModel) {
    val prompt by viewModel.preflightPrompt.collectAsStateWithLifecycle()
    prompt?.let {
        PreflightDialog(it, onImportAnyway = viewModel::confirmImportAnyway, onCancel = viewModel::dismissPreflight)
    }
}

@Composable
internal fun preflightBody(estimate: Long?, free: String?, format: (Long) -> String): String = when {
    estimate != null && free != null -> stringResource(R.string.import_preflight_body_estimate, format(estimate), free)
    free != null -> stringResource(R.string.import_preflight_body_unknown, free)
    else -> stringResource(R.string.import_preflight_body_unknown_nofree)
}

/** The storage preflight: how much the import is expected to need (or that it is unknown) and what is free. */
@Composable
internal fun PreflightDialog(prompt: PreflightPrompt, onImportAnyway: () -> Unit, onCancel: () -> Unit) {
    val context = LocalContext.current
    val free = prompt.freeBytes?.let { android.text.format.Formatter.formatShortFileSize(context, it) }
    val body = preflightBody(prompt.estimateBytes, free) {
        android.text.format.Formatter.formatShortFileSize(context, it)
    }
    AlertDialog(
        onDismissRequest = onCancel,
        title = {
            Text(
                stringResource(
                    if (prompt.sizeUnknown) R.string.import_preflight_title_unknown else R.string.import_preflight_title
                )
            )
        },
        text = { Text(body) },
        confirmButton = {
            TextButton(onClick = onImportAnyway) { Text(stringResource(R.string.import_preflight_anyway)) }
        },
        dismissButton = {
            TextButton(onClick = onCancel) { Text(stringResource(R.string.import_preflight_cancel)) }
        },
    )
}

@Composable
internal fun noticeText(notice: ImportNotice, size: (Long) -> String): String? = when (notice) {
    ImportNotice.None -> null
    is ImportNotice.LowSpace -> lowSpaceText(notice, size)
    is ImportNotice.NotFullyStored -> stringResource(
        if (notice.storedFacts > 0) R.string.import_card_not_stored_some else R.string.import_card_not_stored_none,
        notice.storedFacts
    )
}

@Composable
internal fun lowSpaceText(n: ImportNotice.LowSpace, size: (Long) -> String): String {
    val what = if (n.storedFacts > 0) {
        stringResource(R.string.import_card_low_space_some, n.storedFacts)
    } else {
        stringResource(R.string.import_card_low_space_none)
    }
    val atLeast = size(n.freeAtLeastBytes)
    val advice = if (n.wholeImportBytes != null) {
        stringResource(R.string.import_card_free_at_least_estimate, atLeast, size(n.wholeImportBytes))
    } else {
        stringResource(R.string.import_card_free_at_least_unknown, atLeast)
    }
    return "$what $advice"
}

/** What the import stored, and why not all of it when it was not. */
@Suppress("LongMethod") // one card: counts, notes, bounds, the storage notice and the findings line
@Composable
internal fun ImportCardView(card: ImportCard) {
    val context = LocalContext.current
    Card(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceContainerHighest)
    ) {
        Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
            Text(
                text = stringResource(R.string.import_card_title),
                style = MaterialTheme.typography.titleSmall,
                fontWeight = FontWeight.SemiBold,
                color = MaterialTheme.colorScheme.onSurface
            )
            Text(
                text = stringResource(
                    R.string.import_card_counts, card.newFacts, card.alreadyStored, card.duplicatesDropped
                ),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
            card.notes.forEach { note ->
                Text(
                    text = note,
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
            card.trippedBounds.forEach { bound ->
                Text(
                    text = stringResource(R.string.import_card_bound, bound),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
            val size = { b: Long -> android.text.format.Formatter.formatShortFileSize(context, b) }
            val notice = noticeText(card.notice, size)
            notice?.let {
                Text(
                    text = it,
                    style = MaterialTheme.typography.bodySmall,
                    fontWeight = FontWeight.SemiBold,
                    color = MaterialTheme.colorScheme.error
                )
            }
            val findingsLine = when {
                !card.findingsComplete -> pluralStringResource(R.plurals.import_card_findings_unsaved,
                    card.unsavedFindings.coerceAtMost(Int.MAX_VALUE.toLong()).toInt(), card.unsavedFindings,
                    size(card.freeBytes))
                notice != null -> stringResource(R.string.import_card_findings_complete)
                else -> null
            }
            findingsLine?.let {
                Text(
                    text = it,
                    style = MaterialTheme.typography.bodySmall,
                    fontWeight = FontWeight.SemiBold,
                    color = MaterialTheme.colorScheme.error
                )
            }
        }
    }
}
