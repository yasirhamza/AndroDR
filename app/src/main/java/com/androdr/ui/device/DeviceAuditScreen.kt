package com.androdr.ui.device

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.CheckCircle
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.androdr.R
import com.androdr.sigma.Finding
import com.androdr.ui.common.EvidenceSheet
import com.androdr.ui.common.FindingCard

@Suppress("LongMethod") // Device audit screen renders a summary header plus a grouped list of
// device findings; co-location of triggered/clean sections avoids threading count state externally.
@Composable
fun DeviceAuditScreen(
    viewModel: DeviceAuditViewModel = hiltViewModel()
) {
    val deviceFindings by viewModel.deviceFindings.collectAsStateWithLifecycle()
    val triggeredCount by viewModel.triggeredCount.collectAsStateWithLifecycle()

    var selectedFinding by remember { mutableStateOf<Finding?>(null) }

    val totalCount = deviceFindings.size
    val passedCount = totalCount - triggeredCount

    val triggeredFindings = deviceFindings
        .filter { it.triggered }
        .sortedByDescending { severityOrdinal(it.level) }
    val passedFindings = deviceFindings.filter { !it.triggered }

    Column(modifier = Modifier.fillMaxSize()) {
        // Header summary
        Card(
            modifier = Modifier
                .fillMaxWidth()
                .padding(16.dp),
            colors = CardDefaults.cardColors(
                containerColor = MaterialTheme.colorScheme.surfaceContainer
            )
        ) {
            Row(
                modifier = Modifier.padding(20.dp),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(12.dp)
            ) {
                Icon(
                    imageVector = Icons.Filled.CheckCircle,
                    contentDescription = null,
                    tint = MaterialTheme.colorScheme.primary,
                    modifier = Modifier.size(32.dp)
                )
                Column {
                    Text(
                        text = "$passedCount / $totalCount checks passed",
                        style = MaterialTheme.typography.titleMedium,
                        fontWeight = FontWeight.Bold
                    )
                    if (triggeredCount > 0) {
                        Text(
                            text = "$triggeredCount issue(s) require attention",
                            style = MaterialTheme.typography.bodySmall,
                            color = Color(0xFFCF6679)
                        )
                    } else if (totalCount > 0) {
                        Text(
                            text = stringResource(R.string.device_all_clear),
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.primary
                        )
                    }
                }
            }
        }

        if (deviceFindings.isEmpty()) {
            Box(
                modifier = Modifier.fillMaxSize(),
                contentAlignment = Alignment.Center
            ) {
                Text(
                    text = stringResource(R.string.no_scan_yet),
                    style = MaterialTheme.typography.bodyLarge,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
            return
        }

        LazyColumn(
            modifier = Modifier.fillMaxSize(),
            contentPadding = androidx.compose.foundation.layout.PaddingValues(
                start = 16.dp, end = 16.dp, bottom = 16.dp
            ),
            verticalArrangement = Arrangement.spacedBy(8.dp)
        ) {
            if (triggeredFindings.isNotEmpty()) {
                item {
                    SectionHeader(
                        text = stringResource(R.string.section_issues_found),
                        color = Color(0xFFCF6679)
                    )
                }
                items(triggeredFindings) { finding ->
                    FindingCard(
                        finding = finding,
                        onEvidenceTap = { selectedFinding = it }
                    )
                }
            }

            if (passedFindings.isNotEmpty()) {
                item {
                    SectionHeader(
                        text = stringResource(R.string.section_checks_passed),
                        color = MaterialTheme.colorScheme.primary
                    )
                }
                items(passedFindings) { finding ->
                    FindingCard(finding = finding)
                }
            }
        }
    }

    selectedFinding?.let { finding ->
        EvidenceSheet(
            finding = finding,
            onDismiss = { selectedFinding = null }
        )
    }
}

@Composable
private fun SectionHeader(text: String, color: Color) {
    Text(
        text = text,
        style = MaterialTheme.typography.labelLarge,
        fontWeight = FontWeight.Bold,
        color = color,
        modifier = Modifier.padding(vertical = 8.dp)
    )
}

private fun severityOrdinal(level: String): Int = when (level.lowercase()) {
    "critical" -> 3
    "high" -> 2
    "medium" -> 1
    else -> 0
}
