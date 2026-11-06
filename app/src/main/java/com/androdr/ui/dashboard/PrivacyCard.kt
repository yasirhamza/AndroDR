package com.androdr.ui.dashboard

import android.content.res.Resources
import android.text.format.DateUtils
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.androdr.R
import com.androdr.data.db.PrivacyDao
import com.androdr.data.repo.SettingsRepository
import com.androdr.privacy.PrivacyRanking
import com.androdr.privacy.PrivacySummary
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.flatMapLatest
import kotlinx.coroutines.flow.flowOf

/**
 * The Dashboard's privacy summary: the same [PrivacyRanking.summary] the privacy screen's rows come from, under
 * the user's current threshold and system-app setting, so the card and the screen cannot disagree. Null when no
 * privacy scan has completed.
 */
@OptIn(ExperimentalCoroutinesApi::class)
internal fun privacySummaryFlow(dao: PrivacyDao, settings: SettingsRepository): Flow<PrivacySummary?> =
    dao.latestCompleted().flatMapLatest { scan ->
        if (scan == null) {
            flowOf(null)
        } else {
            combine(
                dao.results(scan.id), dao.evidence(scan.id),
                settings.refusedTrackerCategories, settings.privacyShowSystemApps,
            ) { results, evidence, refused, showSystem ->
                PrivacyRanking.summary(scan, results, evidence, refused, showSystem)
            }
        }
    }

private const val CLAUSE_SEPARATOR = " · "

/**
 * The card's one status line. The "could not be fully inspected" clause is present whenever any app was not
 * fully inspected, so the card can never look clean when inspection failed.
 */
internal fun privacyCardText(summary: PrivacySummary?, res: Resources, now: Long = System.currentTimeMillis()): String {
    if (summary == null) return res.getString(R.string.privacy_card_never)
    val clauses = mutableListOf(
        res.getQuantityString(R.plurals.privacy_card_crossing, summary.crossing, summary.crossing),
    )
    if (summary.newCrossing > 0) clauses += res.getString(R.string.privacy_card_new, summary.newCrossing)
    if (summary.notInspected > 0) {
        clauses += res.getQuantityString(R.plurals.privacy_card_failed, summary.notInspected, summary.notInspected)
    }
    val ago = DateUtils.getRelativeTimeSpanString(summary.scannedAt, now, DateUtils.MINUTE_IN_MILLIS).toString()
    clauses += res.getString(R.string.privacy_card_scanned, ago)
    return clauses.joinToString(CLAUSE_SEPARATOR)
}

/** One tap to the privacy screen (the bottom bar keeps its five tabs). */
@Composable
fun PrivacyCard(summary: PrivacySummary?, onNavigate: (String) -> Unit) {
    val res = LocalContext.current.resources
    Card(
        modifier = Modifier.fillMaxWidth().clickable { onNavigate("privacy") },
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceContainer),
    ) {
        Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
            Text(
                text = stringResource(R.string.privacy_title),
                style = MaterialTheme.typography.titleMedium,
                fontWeight = FontWeight.Bold,
            )
            Text(text = privacyCardText(summary, res), style = MaterialTheme.typography.bodyMedium)
        }
    }
}
