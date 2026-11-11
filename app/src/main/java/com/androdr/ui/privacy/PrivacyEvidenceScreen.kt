package com.androdr.ui.privacy

import android.content.res.Resources
import android.text.format.DateFormat
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalUriHandler
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.androdr.R
import com.androdr.privacy.CodeSignature
import com.androdr.privacy.EvidenceDetails
import com.androdr.privacy.InspectOutcome
import com.androdr.privacy.PrivacyRanking
import java.util.Date

/** The details of one tracker in one app (spec §4.1): what the scan matched, as recorded. Back returns. */
@Composable
fun PrivacyEvidenceScreen(onBack: () -> Unit, viewModel: PrivacyEvidenceViewModel = hiltViewModel()) {
    val state by viewModel.state.collectAsStateWithLifecycle()
    val lookups by viewModel.lookups.collectAsStateWithLifecycle()
    EvidenceContent(state, lookups, viewModel::openLookups, viewModel::closeLookups, onBack)
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
internal fun EvidenceContent(
    state: EvidenceUiState,
    lookups: LookupTimes?,
    onOpenLookups: (String) -> Unit,
    onCloseLookups: () -> Unit,
    onBack: () -> Unit,
    formatTime: (Long) -> String = dateTimeFormatter(),
) {
    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.privacy_evidence_title)) },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, stringResource(R.string.privacy_back))
                    }
                },
            )
        },
    ) { padding ->
        Column(
            modifier = Modifier.padding(padding).fillMaxSize().verticalScroll(rememberScrollState())
                .padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            when (state) {
                EvidenceUiState.Loading -> Text(stringResource(R.string.privacy_evidence_loading))
                EvidenceUiState.Gone -> Text(stringResource(R.string.privacy_evidence_gone))
                EvidenceUiState.Unreadable -> Text(stringResource(R.string.privacy_evidence_unreadable))
                is EvidenceUiState.Loaded -> Details(state.details, onOpenLookups, formatTime)
            }
        }
    }
    lookups?.let { LookupTimesDialog(it, formatTime, onCloseLookups) }
}

@Composable
private fun dateTimeFormatter(): (Long) -> String {
    val context = LocalContext.current
    val date = DateFormat.getMediumDateFormat(context)
    val time = DateFormat.getTimeFormat(context)
    return { at -> date.format(Date(at)) + " " + time.format(Date(at)) }
}

@Composable
private fun Details(d: EvidenceDetails, onOpenLookups: (String) -> Unit, formatTime: (Long) -> String) {
    val res = LocalContext.current.resources
    Header(d, res)
    val totals = PrivacyEvidenceText.line(PrivacyRanking.trackerRow(d.evidence), res)
    Text(totals, style = MaterialTheme.typography.bodyMedium)
    if (!d.scan.hasDetails) {
        Text(stringResource(R.string.privacy_evidence_run_new_scan), style = MaterialTheme.typography.bodyMedium)
    } else {
        if (d.evidence.inCode) FoundInCode(d, res)
        if (d.domains.isNotEmpty() || PrivacyEvidenceDetailText.networkIncomplete(d.scan)) {
            LookedUp(d, res, onOpenLookups, formatTime)
        }
    }
    HorizontalDivider(modifier = Modifier.padding(top = 8.dp))
    Text(
        PrivacyEvidenceDetailText.footer(d.scan, res, formatTime),
        style = MaterialTheme.typography.labelSmall,
        color = MaterialTheme.colorScheme.onSurfaceVariant,
    )
    Text(
        stringResource(R.string.privacy_attribution),
        style = MaterialTheme.typography.labelSmall,
        color = MaterialTheme.colorScheme.onSurfaceVariant,
    )
}

@Composable
private fun Header(d: EvidenceDetails, res: Resources) {
    val e = d.evidence
    Text(
        PrivacyEvidenceText.trackerName(e.trackerName, e.website, e.trackerId),
        style = MaterialTheme.typography.titleLarge,
        fontWeight = FontWeight.Bold,
    )
    Website(e.website)
    Text(
        PrivacyRanking.trackerRow(e).categories.joinToString(", ") { res.getString(categoryLabel(it)) },
        style = MaterialTheme.typography.bodySmall,
    )
    Text(
        stringResource(
            R.string.privacy_evidence_in_app,
            PrivacyEvidenceText.appName(d.app.appLabel, d.app.packageName),
            PrivacyEvidenceDetailText.shown(d.app.packageName),
        ),
        style = MaterialTheme.typography.bodyMedium,
    )
    val entry = stringResource(R.string.privacy_evidence_list_entry, e.trackerId)
    val link = PrivacyEvidenceDetailText.exodusLink(e.trackerId)
    val uri = LocalUriHandler.current
    if (link != null) {
        TextButton(onClick = { uri.openUri(link) }) { Text(entry) }
    } else {
        Text(entry, style = MaterialTheme.typography.bodySmall)
    }
}

@Composable
private fun FoundInCode(d: EvidenceDetails, res: Resources) {
    SectionTitle(stringResource(R.string.privacy_evidence_found_in_code))
    val partial = PrivacyRanking.outcomeOf(d.app.outcome) == InspectOutcome.PARTIAL
    val inspected = stringResource(
        if (partial) R.string.privacy_partly_inspected_tag else R.string.privacy_evidence_fully_inspected,
    )
    val small = MaterialTheme.typography.bodySmall
    Text(stringResource(R.string.privacy_evidence_version, d.app.versionCode.toString(), inspected), style = small)
    if (partial) Text(stringResource(R.string.privacy_evidence_partial_note), style = small)
    for (s in d.code) CodeSignatureBlock(s, res)
}

@Composable
private fun CodeSignatureBlock(s: CodeSignature, res: Resources) {
    Column(modifier = Modifier.padding(top = 4.dp), verticalArrangement = Arrangement.spacedBy(2.dp)) {
        Text(
            PrivacyEvidenceDetailText.signatureLine(s.kind, s.signature, res),
            style = MaterialTheme.typography.bodyMedium,
        )
        for (p in s.packages) {
            Text(
                PrivacyEvidenceDetailText.shown(p),
                style = MaterialTheme.typography.bodySmall,
                fontFamily = FontFamily.Monospace,
                modifier = Modifier.padding(start = 12.dp),
            )
        }
        PrivacyEvidenceDetailText.more(s.packages.size, s.total, res)?.let {
            Text(it, style = MaterialTheme.typography.bodySmall, modifier = Modifier.padding(start = 12.dp))
        }
    }
}

@Composable
internal fun SectionTitle(text: String) {
    Text(
        text,
        style = MaterialTheme.typography.titleSmall,
        fontWeight = FontWeight.Bold,
        modifier = Modifier.padding(top = 12.dp),
    )
}
