package com.androdr.ui.privacy

import android.content.res.Resources
import android.text.format.DateFormat
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.LazyListScope
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.selection.toggleable
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.MoreVert
import androidx.compose.material3.Button
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Switch
import androidx.compose.material3.Tab
import androidx.compose.material3.TabRow
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
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
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.androdr.R
import com.androdr.data.model.PrivacyScan
import com.androdr.privacy.PrivacyScanProgress
import java.util.Date

/**
 * The privacy screen (one tap from the Dashboard): last-scan header, Run / progress, By app and By tracker tabs,
 * the "What I refuse" sheet, a footer stating the limits and the Exodus attribution, and a confirmed Delete.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun PrivacyScreen(
    onBack: () -> Unit,
    /** An app whose sheet to open (the Timeline's "Open in privacy results"), applied once per entry. */
    initialPackage: String? = null,
    onOpenEvidence: (packageName: String, trackerId: Int) -> Unit,
    viewModel: PrivacyViewModel = hiltViewModel(),
) {
    val state by viewModel.state.collectAsStateWithLifecycle()
    val message by viewModel.message.collectAsStateWithLifecycle()
    val snackbar = remember { SnackbarHostState() }
    val context = LocalContext.current
    var showThreshold by rememberSaveable { mutableStateOf(false) }
    var confirmDelete by rememberSaveable { mutableStateOf(false) }
    var menuOpen by remember { mutableStateOf(false) }
    var detail by rememberOpenApp(initialPackage)

    LaunchedEffect(message) {
        message?.let { snackbar.showSnackbar(context.getString(it)); viewModel.messageShown() }
    }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.privacy_title)) },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, stringResource(R.string.privacy_back))
                    }
                },
                actions = {
                    IconButton(onClick = { menuOpen = true }) {
                        Icon(Icons.Filled.MoreVert, stringResource(R.string.privacy_more))
                    }
                    DropdownMenu(expanded = menuOpen, onDismissRequest = { menuOpen = false }) {
                        DropdownMenuItem(
                            text = { Text(stringResource(R.string.privacy_delete)) },
                            onClick = { menuOpen = false; confirmDelete = true },
                        )
                    }
                },
            )
        },
        snackbarHost = { SnackbarHost(snackbar) },
    ) { padding ->
        PrivacyBody(
            state = state,
            modifier = Modifier.padding(padding),
            onRun = viewModel::runScan,
            onShowThreshold = { showThreshold = true },
            onShowSystem = viewModel::setShowSystemApps,
            onOpenApp = { detail = it },
            onOpenEvidence = onOpenEvidence,
        )
    }

    if (showThreshold) {
        PrivacyThresholdSheet(state.refused, viewModel::setRefused) { showThreshold = false }
    }
    detail?.let { pkg -> AppSheet(state, pkg, onDismiss = { detail = null }, onOpenEvidence) }
    if (confirmDelete) {
        DeleteResultsDialog(
            onConfirm = { confirmDelete = false; viewModel.deleteResults() },
            onDismiss = { confirmDelete = false },
        )
    }
}

@Composable
private fun PrivacyBody(
    state: PrivacyUiState,
    modifier: Modifier,
    onRun: () -> Unit,
    onShowThreshold: () -> Unit,
    onShowSystem: (Boolean) -> Unit,
    onOpenApp: (String) -> Unit,
    onOpenEvidence: (String, Int) -> Unit,
) {
    var tab by rememberSaveable { mutableStateOf(0) }
    val res = LocalContext.current.resources
    LazyColumn(modifier = modifier.fillMaxSize(), contentPadding = PaddingValues(16.dp)) {
        item { Header(state, onRun) }
        item { Controls(state, onShowThreshold, onShowSystem) }
        item {
            TabRow(selectedTabIndex = tab) {
                Tab(tab == 0, { tab = 0 }, text = { Text(stringResource(R.string.privacy_tab_by_app)) })
                Tab(tab == 1, { tab = 1 }, text = { Text(stringResource(R.string.privacy_tab_by_tracker)) })
            }
        }
        if (tab == 0) {
            byApp(state, res, onOpenApp)
        } else {
            byTracker(state, res, onOpenEvidence)
        }
        item { Footer() }
    }
}

@Composable
private fun Header(state: PrivacyUiState, onRun: () -> Unit) {
    Column(verticalArrangement = Arrangement.spacedBy(8.dp), modifier = Modifier.padding(bottom = 8.dp)) {
        val scan = state.scan
        Text(
            text = scan?.let { stringResource(R.string.privacy_last_scan, formatDate(it)) }
                ?: stringResource(R.string.privacy_never_scanned),
            style = MaterialTheme.typography.bodyMedium,
        )
        val coverageText = when (val c = state.networkCoverage) {
            NetworkCoverage.Hidden -> null
            NetworkCoverage.NoMonitor -> stringResource(R.string.privacy_no_monitor)
            is NetworkCoverage.Days ->
                LocalContext.current.resources.getQuantityString(R.plurals.privacy_network_coverage, c.days, c.days)
        }
        coverageText?.let {
            Text(it, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
        }
        state.networkNotice?.let { Text(stringResource(it), style = MaterialTheme.typography.bodySmall) }
        RunControl(state, onRun)
        if (state.showRegistryUnavailable) {
            Text(stringResource(R.string.privacy_registry_unavailable), style = MaterialTheme.typography.bodySmall)
        }
    }
}

@Composable
private fun RunControl(state: PrivacyUiState, onRun: () -> Unit) {
    when (val p = state.progress) {
        is PrivacyScanProgress.Running -> {
            if (p.total > 0) {
                Text(
                    stringResource(R.string.privacy_progress, p.done, p.total),
                    style = MaterialTheme.typography.bodyMedium,
                )
                LinearProgressIndicator(progress = { p.done.toFloat() / p.total }, modifier = Modifier.fillMaxWidth())
            } else {
                LinearProgressIndicator(modifier = Modifier.fillMaxWidth())
            }
        }
        else -> {
            if (p is PrivacyScanProgress.Failed) Text(stringResource(R.string.privacy_scan_failed))
            Button(onClick = onRun, enabled = state.canRun, modifier = Modifier.fillMaxWidth()) {
                Text(stringResource(R.string.privacy_run))
            }
        }
    }
}

@Composable
private fun Controls(state: PrivacyUiState, onShowThreshold: () -> Unit, onShowSystem: (Boolean) -> Unit) {
    Column(modifier = Modifier.padding(bottom = 8.dp)) {
        TextButton(onClick = onShowThreshold) { Text(stringResource(R.string.privacy_threshold_open)) }
        Row(
            modifier = Modifier.fillMaxWidth().toggleable(
                value = state.showSystemApps, role = Role.Switch, onValueChange = onShowSystem,
            ),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            Text(
                stringResource(R.string.privacy_system_toggle),
                style = MaterialTheme.typography.bodyMedium,
                modifier = Modifier.weight(1f),
            )
            Switch(checked = state.showSystemApps, onCheckedChange = null)
        }
    }
}

private fun LazyListScope.byApp(state: PrivacyUiState, res: Resources, onOpenApp: (String) -> Unit) {
    for ((section, rows) in state.sections) {
        if (rows.isEmpty()) continue
        item(key = "h-$section") {
            Text(
                stringResource(sectionTitle(section)),
                style = MaterialTheme.typography.titleSmall,
                fontWeight = FontWeight.Bold,
                modifier = Modifier.padding(top = 16.dp, bottom = 4.dp),
            )
        }
        items(rows, key = { "a-${it.packageName}" }) { row ->
            AppRow(row, state.registrySizeAtScan ?: 0, res) { onOpenApp(row.packageName) }
            HorizontalDivider()
        }
    }
}

private fun LazyListScope.byTracker(state: PrivacyUiState, res: Resources, onOpenEvidence: (String, Int) -> Unit) {
    if (state.byTracker.isEmpty()) {
        item { Text(stringResource(R.string.privacy_empty_tracker_list), modifier = Modifier.padding(top = 16.dp)) }
    }
    items(state.byTracker, key = { "t-${it.trackerId}" }) { group -> TrackerCard(group, res, onOpenEvidence) }
}

@Composable
private fun Footer() {
    Column(verticalArrangement = Arrangement.spacedBy(8.dp), modifier = Modifier.padding(top = 24.dp)) {
        Text(
            stringResource(R.string.privacy_network_caveat),
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        Text(
            stringResource(R.string.privacy_limits),
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        Text(
            stringResource(R.string.privacy_attribution),
            style = MaterialTheme.typography.labelSmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
    }
}

@Composable
private fun formatDate(scan: PrivacyScan): String {
    val at = scan.finishedAt ?: scan.startedAt
    return DateFormat.getMediumDateFormat(LocalContext.current).format(Date(at)) + " " +
        DateFormat.getTimeFormat(LocalContext.current).format(Date(at))
}
