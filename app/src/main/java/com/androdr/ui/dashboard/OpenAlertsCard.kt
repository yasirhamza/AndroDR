package com.androdr.ui.dashboard

import android.app.KeyguardManager
import androidx.annotation.StringRes
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.Checkbox
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.pluralStringResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.paging.compose.LazyPagingItems
import androidx.paging.compose.collectAsLazyPagingItems
import androidx.paging.compose.itemKey
import com.androdr.R
import com.androdr.data.repo.AlertGroup
import com.androdr.data.repo.AlertGroupRef
import com.androdr.data.repo.CurrentFindingsSummary
import com.androdr.ui.common.SeverityChip
import com.androdr.ui.security.DeviceSecurity
import com.androdr.ui.security.ProtectedButton
import com.androdr.ui.security.rememberConfirmCredential
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/**
 * The open-alerts card (spec §5.4): the current-findings count, then the OPEN alerts grouped by rule
 * and matched value, most recent activity first, in a bounded-height paged list. Each group can be
 * selected; Close (one group) and Close selected (bulk, one confirmation) open a dialog whose Close
 * button is a [ProtectedButton] and asks the device credential before anything is closed.
 */
@Composable
fun OpenAlertsCard(
    viewModel: DashboardAlertsViewModel,
    current: CurrentFindingsSummary,
    onMessage: (String) -> Unit,
) {
    val groups = viewModel.groups.collectAsLazyPagingItems()
    val selected by viewModel.selected.collectAsStateWithLifecycle()
    val pending by viewModel.pendingClose.collectAsStateWithLifecycle()
    val outcome by viewModel.outcome.collectAsStateWithLifecycle()
    val closing by viewModel.closing.collectAsStateWithLifecycle()
    val context = LocalContext.current

    LaunchedEffect(outcome) {
        val o = outcome ?: return@LaunchedEffect
        onMessage(
            when (o) {
                is CloseOutcome.Closed -> context.getString(R.string.alerts_close_done, o.count)
                is CloseOutcome.ClosedWithoutLock -> context.getString(R.string.alerts_close_no_lock)
                CloseOutcome.NotConfirmed -> context.getString(R.string.alerts_close_cancelled)
                CloseOutcome.NothingToClose -> context.getString(R.string.alerts_close_nothing_to_close)
                CloseOutcome.Failed -> context.getString(R.string.alerts_close_failed)
            }
        )
        viewModel.outcomeShown()
    }

    Card(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceContainer),
    ) {
        Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            AlertsHeader(current)
            if (current.openAlertCount == 0 && groups.itemCount == 0) {
                Text(stringResource(R.string.alerts_card_none), style = MaterialTheme.typography.bodyMedium)
                return@Column
            }
            val open = current.openAlertCount
            Text(
                text = pluralStringResource(R.plurals.alerts_card_count, open, open),
                style = MaterialTheme.typography.bodyMedium,
            )
            AlertGroupList(groups, selected, viewModel)
            if (selected.isNotEmpty()) {
                ProtectedButton(
                    onClick = { viewModel.requestCloseSelected() },
                    enabled = !closing,
                    modifier = Modifier.fillMaxWidth(),
                ) {
                    Text(stringResource(R.string.alerts_close_selected, selected.size))
                }
            }
        }
    }

    pending?.let { refs -> CloseAlertsDialog(viewModel, refs, groups.itemSnapshotList.items) }
}

@Composable
private fun AlertsHeader(current: CurrentFindingsSummary) {
    Text(
        text = stringResource(R.string.alerts_card_title),
        style = MaterialTheme.typography.titleMedium,
        fontWeight = FontWeight.Bold,
    )
    Text(
        text = stringResource(
            R.string.alerts_current_findings, current.count, current.stateFindings.size, current.openAlertCount,
        ),
        style = MaterialTheme.typography.bodySmall,
        color = MaterialTheme.colorScheme.onSurfaceVariant,
    )
}

/** Bounded height: the Dashboard scrolls as a whole; this list pages inside it. */
@Composable
private fun AlertGroupList(
    groups: LazyPagingItems<AlertGroup>, selected: Set<AlertGroupRef>, viewModel: DashboardAlertsViewModel,
) {
    LazyColumn(modifier = Modifier.fillMaxWidth().heightIn(max = LIST_MAX_HEIGHT.dp)) {
        items(count = groups.itemCount, key = groups.itemKey { "${it.ruleId}\u0000${it.matchedValue}" }) { i ->
            groups[i]?.let { group ->
                AlertGroupRow(
                    group = group,
                    checked = selected.any { it.ruleId == group.ruleId && it.matchedValue == group.matchedValue },
                    onToggle = { viewModel.toggle(group.ref) },
                    onClose = { viewModel.requestClose(group.ref) },
                )
                HorizontalDivider()
            }
        }
    }
}

@Composable
private fun AlertGroupRow(group: AlertGroup, checked: Boolean, onToggle: () -> Unit, onClose: () -> Unit) {
    Row(
        modifier = Modifier.fillMaxWidth().padding(vertical = 6.dp),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        Checkbox(checked = checked, onCheckedChange = { onToggle() })
        Column(modifier = Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(2.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                SeverityChip(level = group.sample?.level ?: "", active = true)
                Text(
                    text = group.sample?.evidence?.title?.takeIf { it.isNotBlank() } ?: group.ruleId,
                    style = MaterialTheme.typography.titleSmall,
                    maxLines = 1, overflow = TextOverflow.Ellipsis,
                )
            }
            if (group.matchedValue.isNotEmpty()) {
                Text(
                    text = group.matchedValue,
                    style = MaterialTheme.typography.bodySmall,
                    maxLines = 1, overflow = TextOverflow.Ellipsis,
                )
            }
            Text(
                text = pluralStringResource(R.plurals.alerts_group_count, group.count, group.count) + " · " +
                    stringResource(R.string.alerts_group_last_activity, formatTime(group.lastActivityAt)),
                style = MaterialTheme.typography.labelSmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
        // Opens the confirmation dialog only; the dialog's Close is the protected control.
        TextButton(onClick = onClose) { Text(stringResource(R.string.alerts_close)) }
    }
}

@Composable
private fun CloseAlertsDialog(viewModel: DashboardAlertsViewModel, refs: List<AlertGroupRef>, shown: List<AlertGroup>) {
    var note by rememberSaveable { mutableStateOf("") }
    val confirm = rememberConfirmCredential()
    val context = LocalContext.current
    // What the close will do: ask for the screen lock, or close without one (final review M2).
    val secure = remember {
        DeviceSecurity.of(context.getSystemService(KeyguardManager::class.java)).isDeviceSecure()
    }
    val title = stringResource(R.string.alerts_credential_title)
    val description = stringResource(R.string.alerts_credential_description)
    // The count the close will act on: the alerts seen when each group was chosen (up to its maxId).
    val count = refs.sumOf { ref ->
        shown.firstOrNull { it.ruleId == ref.ruleId && it.matchedValue == ref.matchedValue }
            ?.takeIf { it.maxId == ref.maxId }?.count ?: 1
    }
    AlertDialog(
        onDismissRequest = { viewModel.dismissClose() },
        title = { Text(stringResource(R.string.alerts_close_dialog_title)) },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Text(pluralStringResource(R.plurals.alerts_close_dialog_body, count, count))
                Text(stringResource(closeLockSentence(secure)))
                OutlinedTextField(
                    value = note,
                    onValueChange = { note = it.take(NOTE_MAX) },
                    label = { Text(stringResource(R.string.alerts_close_note)) },
                    singleLine = false,
                    maxLines = 3,
                )
            }
        },
        confirmButton = {
            ProtectedButton(onClick = { viewModel.close(note) { confirm(title, description) } }) {
                Text(stringResource(R.string.alerts_close_confirm))
            }
        },
        dismissButton = {
            TextButton(onClick = { viewModel.dismissClose() }) { Text(stringResource(R.string.alerts_close_cancel)) }
        },
    )
}

/**
 * The close dialog's sentence about the screen lock: a prompt is promised only when the device has
 * a secure lock ([secure]); without one, the close goes through unprotected and the dialog says so.
 */
@StringRes
internal fun closeLockSentence(secure: Boolean): Int =
    if (secure) R.string.alerts_close_dialog_lock else R.string.alerts_close_dialog_no_lock

private fun formatTime(ts: Long): String = SimpleDateFormat("MMM d, HH:mm", Locale.getDefault()).format(Date(ts))

private const val LIST_MAX_HEIGHT = 360
private const val NOTE_MAX = 500
