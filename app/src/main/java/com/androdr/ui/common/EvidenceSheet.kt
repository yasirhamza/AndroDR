package com.androdr.ui.common

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ExperimentalLayoutApi
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.ModalBottomSheet
import androidx.compose.material3.SuggestionChip
import androidx.compose.material3.SuggestionChipDefaults
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.rememberModalBottomSheetState
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import com.androdr.sigma.CveEvidence
import com.androdr.sigma.Evidence
import com.androdr.sigma.Finding

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun EvidenceSheet(finding: Finding, onDismiss: () -> Unit) {
    val sheetState = rememberModalBottomSheetState(skipPartiallyExpanded = true)

    ModalBottomSheet(
        onDismissRequest = onDismiss,
        sheetState = sheetState,
        containerColor = MaterialTheme.colorScheme.surfaceContainerHigh
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 24.dp)
                .padding(bottom = 16.dp)
        ) {
            // Title
            Text(
                text = finding.title,
                style = MaterialTheme.typography.titleMedium,
                fontWeight = FontWeight.Bold
            )
            Spacer(modifier = Modifier.height(4.dp))
            SeverityChip(level = finding.level, active = finding.triggered)
            Spacer(modifier = Modifier.height(12.dp))
            HorizontalDivider()
            Spacer(modifier = Modifier.height(12.dp))

            // Evidence content
            Column(
                modifier = Modifier
                    .weight(1f, fill = false)
                    .verticalScroll(rememberScrollState()),
                verticalArrangement = Arrangement.spacedBy(12.dp)
            ) {
                when (val evidence = finding.evidence) {
                    is Evidence.CveList -> CveListContent(
                        evidence = evidence,
                        remediation = finding.remediation
                    )
                    is Evidence.IocMatch -> IocMatchContent(evidence = evidence)
                    is Evidence.PermissionCluster -> PermissionClusterContent(evidence = evidence)
                    is Evidence.None -> {
                        // Nothing to show
                    }
                }
            }

            Spacer(modifier = Modifier.height(16.dp))

            // Dismiss
            TextButton(
                onClick = onDismiss,
                modifier = Modifier.fillMaxWidth()
            ) {
                Text("Dismiss")
            }
        }
    }
}

@Composable
private fun CveListContent(evidence: Evidence.CveList, remediation: List<String>) {
    Text(
        text = "Unpatched CVEs (${evidence.cves.size})",
        style = MaterialTheme.typography.titleSmall,
        fontWeight = FontWeight.SemiBold
    )

    if (evidence.campaignCount > 0) {
        Text(
            text = "${evidence.campaignCount} CVE(s) linked to known spyware campaigns",
            style = MaterialTheme.typography.bodySmall,
            color = Color(0xFFCF6679)
        )
    }

    if (evidence.targetPatchLevel.isNotEmpty()) {
        Text(
            text = "Target patch level: ${evidence.targetPatchLevel}",
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant
        )
    }

    Spacer(modifier = Modifier.height(8.dp))

    // Sort: campaign-linked first, then by severity descending
    val sortedCves = evidence.cves.sortedWith(
        compareByDescending<CveEvidence> { it.campaigns.isNotEmpty() }
            .thenByDescending { severityOrdinal(it.severity) }
    )

    sortedCves.forEach { cve ->
        CveCard(cve = cve)
    }

    if (remediation.isNotEmpty()) {
        Spacer(modifier = Modifier.height(8.dp))
        Text(
            text = "Remediation",
            style = MaterialTheme.typography.titleSmall,
            fontWeight = FontWeight.SemiBold
        )
        remediation.forEach { step ->
            Text(
                text = "\u2022 $step",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurface
            )
        }
    }
}

// Compose composable rendering CVE card details; splitting would fragment cohesive UI logic
@Suppress("LongMethod")
@OptIn(ExperimentalLayoutApi::class)
@Composable
private fun CveCard(cve: CveEvidence) {
    Card(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(
            containerColor = if (cve.campaigns.isNotEmpty())
                Color(0xFFCF6679).copy(alpha = 0.06f)
            else
                MaterialTheme.colorScheme.surfaceContainer
        )
    ) {
        Column(
            modifier = Modifier.padding(12.dp),
            verticalArrangement = Arrangement.spacedBy(6.dp)
        ) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween
            ) {
                Text(
                    text = cve.cveId,
                    style = MaterialTheme.typography.titleSmall,
                    fontWeight = FontWeight.Bold,
                    modifier = Modifier.weight(1f)
                )
                SeverityChip(level = cve.severity, active = true)
            }

            if (cve.description.isNotEmpty()) {
                Text(
                    text = cve.description,
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    maxLines = 3,
                    overflow = TextOverflow.Ellipsis
                )
            }

            if (cve.campaigns.isNotEmpty()) {
                FlowRow(
                    horizontalArrangement = Arrangement.spacedBy(6.dp),
                    verticalArrangement = Arrangement.spacedBy(4.dp)
                ) {
                    cve.campaigns.forEach { campaign ->
                        SuggestionChip(
                            onClick = {},
                            label = {
                                Text(
                                    text = campaign,
                                    style = MaterialTheme.typography.labelSmall
                                )
                            },
                            colors = SuggestionChipDefaults.suggestionChipColors(
                                containerColor = Color(0xFFCF6679).copy(alpha = 0.2f),
                                labelColor = Color(0xFFCF6679)
                            )
                        )
                    }
                }
            }

            if (cve.patchLevel.isNotEmpty()) {
                Text(
                    text = "Fixed in: ${cve.patchLevel}",
                    style = MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
        }
    }
}

@Composable
private fun IocMatchContent(evidence: Evidence.IocMatch) {
    Text(
        text = "IOC Match Details",
        style = MaterialTheme.typography.titleSmall,
        fontWeight = FontWeight.SemiBold
    )

    Card(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(
            containerColor = MaterialTheme.colorScheme.surfaceContainer
        )
    ) {
        Column(
            modifier = Modifier.padding(12.dp),
            verticalArrangement = Arrangement.spacedBy(8.dp)
        ) {
            DetailRow(label = "Matched indicator", value = evidence.matchedIndicator)
            DetailRow(label = "IOC type", value = evidence.iocType)
            DetailRow(label = "Source", value = evidence.source)
        }
    }
}

@OptIn(ExperimentalLayoutApi::class)
@Composable
private fun PermissionClusterContent(evidence: Evidence.PermissionCluster) {
    Text(
        text = "Surveillance Permissions",
        style = MaterialTheme.typography.titleSmall,
        fontWeight = FontWeight.SemiBold
    )

    Text(
        text = "${evidence.surveillanceCount} of ${evidence.permissions.size} permissions are surveillance-capable",
        style = MaterialTheme.typography.bodySmall,
        color = Color(0xFFCF6679)
    )

    Spacer(modifier = Modifier.height(4.dp))

    FlowRow(
        horizontalArrangement = Arrangement.spacedBy(6.dp),
        verticalArrangement = Arrangement.spacedBy(4.dp)
    ) {
        evidence.permissions.forEach { perm ->
            val shortPerm = perm.substringAfterLast('.')
            SuggestionChip(
                onClick = {},
                label = {
                    Text(
                        text = shortPerm,
                        style = MaterialTheme.typography.labelSmall
                    )
                },
                colors = SuggestionChipDefaults.suggestionChipColors(
                    containerColor = Color(0xFFFF9800).copy(alpha = 0.15f),
                    labelColor = Color(0xFFFF9800)
                )
            )
        }
    }
}

@Composable
private fun DetailRow(label: String, value: String) {
    Column {
        Text(
            text = label,
            style = MaterialTheme.typography.labelSmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant
        )
        Text(
            text = value,
            style = MaterialTheme.typography.bodyMedium,
            fontWeight = FontWeight.SemiBold
        )
    }
}

private fun severityOrdinal(severity: String): Int = when (severity.lowercase()) {
    "critical" -> 3
    "high" -> 2
    "medium" -> 1
    else -> 0
}
