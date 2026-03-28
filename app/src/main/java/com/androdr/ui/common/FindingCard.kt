package com.androdr.ui.common

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Cancel
import androidx.compose.material.icons.filled.CheckCircle
import androidx.compose.material.icons.filled.ChevronRight
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.androdr.sigma.Evidence
import com.androdr.sigma.Finding

// Compose composable rendering a finding card with evidence summary; splitting would fragment UI logic
@Suppress("LongMethod")
@Composable
fun FindingCard(finding: Finding, onEvidenceTap: ((Finding) -> Unit)? = null) {
    val hasEvidence = finding.evidence !is Evidence.None && finding.triggered
    Card(
        modifier = Modifier.fillMaxWidth().then(
            if (hasEvidence && onEvidenceTap != null) Modifier.clickable { onEvidenceTap(finding) } else Modifier
        ),
        colors = CardDefaults.cardColors(
            containerColor = if (finding.triggered) Color(0xFFCF6679).copy(alpha = 0.08f)
            else MaterialTheme.colorScheme.surfaceContainerHigh
        )
    ) {
        Row(modifier = Modifier.padding(16.dp), horizontalArrangement = Arrangement.spacedBy(12.dp)) {
            Icon(
                imageVector = if (finding.triggered) Icons.Filled.Cancel else Icons.Filled.CheckCircle,
                contentDescription = if (finding.triggered) "Triggered" else "Passed",
                tint = if (finding.triggered) Color(0xFFCF6679) else MaterialTheme.colorScheme.primary,
                modifier = Modifier.size(24.dp)
            )
            Column(modifier = Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(4.dp)) {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Text(
                        text = finding.title,
                        style = MaterialTheme.typography.titleSmall,
                        fontWeight = FontWeight.SemiBold,
                        modifier = Modifier.weight(1f)
                    )
                    Spacer(modifier = Modifier.width(8.dp))
                    SeverityChip(level = finding.level, active = finding.triggered)
                }
                if (finding.triggered && finding.description.isNotEmpty()) {
                    Text(
                        text = finding.description,
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }
                if (hasEvidence) {
                    val summary = evidenceSummary(finding.evidence)
                    if (summary.isNotEmpty()) {
                        Row(
                            verticalAlignment = Alignment.CenterVertically,
                            horizontalArrangement = Arrangement.spacedBy(4.dp)
                        ) {
                            Text(
                                text = summary,
                                style = MaterialTheme.typography.labelSmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant
                            )
                            Icon(
                                imageVector = Icons.Filled.ChevronRight,
                                contentDescription = "View details",
                                modifier = Modifier.size(16.dp),
                                tint = MaterialTheme.colorScheme.onSurfaceVariant
                            )
                        }
                    }
                }
            }
        }
    }
}

private fun evidenceSummary(evidence: Evidence): String = when (evidence) {
    is Evidence.None -> ""
    is Evidence.CveList -> {
        val parts = mutableListOf("${evidence.cves.size} CVEs")
        if (evidence.campaignCount > 0) parts.add("${evidence.campaignCount} linked to spyware")
        parts.joinToString(" \u00b7 ")
    }
    is Evidence.IocMatch -> "Matched: ${evidence.matchedIndicator}"
    is Evidence.PermissionCluster -> "${evidence.surveillanceCount} surveillance permissions"
}
