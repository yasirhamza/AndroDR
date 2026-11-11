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
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import com.androdr.R
import com.androdr.privacy.DomainLine
import com.androdr.privacy.EvidenceDetails

/**
 * The "Looked up domains of this tracker" section of the details view, and the dialog with one domain's
 * most recent lookups. Shown when a domain was recorded, or when the network step was cut short or
 * failed (so a missing domain list is never read as "none").
 */
@Composable
internal fun LookedUp(
    d: EvidenceDetails,
    res: Resources,
    onOpenLookups: (String) -> Unit,
    formatTime: (Long) -> String,
) {
    SectionTitle(stringResource(R.string.privacy_evidence_lookups_title))
    val small = MaterialTheme.typography.bodySmall
    Text(PrivacyEvidenceDetailText.window(d.scan, res, formatTime), style = small)
    PrivacyEvidenceDetailText.coverage(d.scan, res)?.let { Text(it, style = small) }
    PrivacyEvidenceDetailText.networkNotice(d.scan)?.let {
        Text(stringResource(it), style = small)
        Text(stringResource(R.string.privacy_evidence_lookups_incomplete), style = small)
    }
    Text(
        stringResource(R.string.privacy_network_caveat),
        style = small,
        color = MaterialTheme.colorScheme.onSurfaceVariant,
    )
    if (d.domains.isNotEmpty()) Text(stringResource(R.string.privacy_evidence_lookup_times_hint), style = small)
    for (line in d.domains) DomainBlock(line, res, onOpenLookups, formatTime)
}

@Composable
private fun DomainBlock(
    line: DomainLine,
    res: Resources,
    onOpenLookups: (String) -> Unit,
    formatTime: (Long) -> String,
) {
    Column(
        modifier = Modifier.fillMaxWidth().clickable { onOpenLookups(line.domain) }.padding(vertical = 6.dp),
        verticalArrangement = Arrangement.spacedBy(2.dp),
    ) {
        Text(
            PrivacyEvidenceDetailText.shown(line.domain),
            style = MaterialTheme.typography.bodyMedium,
            fontFamily = FontFamily.Monospace,
        )
        Text(
            PrivacyEvidenceDetailText.matchedLine(line.kind, line.signature, res),
            style = MaterialTheme.typography.bodySmall,
        )
        Text(PrivacyEvidenceDetailText.domainCounts(line, res, formatTime), style = MaterialTheme.typography.bodySmall)
    }
}

/** One domain's most recent lookups, read from the DNS log when opened; a failed read says so. */
@Composable
internal fun LookupTimesDialog(lookups: LookupTimes, formatTime: (Long) -> String, onClose: () -> Unit) {
    AlertDialog(
        onDismissRequest = onClose,
        title = { Text(PrivacyEvidenceDetailText.shown(lookups.domain), fontFamily = FontFamily.Monospace) },
        text = {
            Column(
                modifier = Modifier.verticalScroll(rememberScrollState()),
                verticalArrangement = Arrangement.spacedBy(4.dp),
            ) {
                val times = lookups.times
                when {
                    times == null -> Text(stringResource(R.string.privacy_evidence_unreadable))
                    times.isEmpty() -> Text(stringResource(R.string.privacy_evidence_lookup_times_none))
                    else -> {
                        Text(
                            stringResource(R.string.privacy_evidence_lookup_times_note),
                            style = MaterialTheme.typography.bodySmall,
                        )
                        for (t in times) Text(formatTime(t), style = MaterialTheme.typography.bodySmall)
                    }
                }
            }
        },
        confirmButton = { TextButton(onClick = onClose) { Text(stringResource(R.string.privacy_evidence_close)) } },
    )
}
