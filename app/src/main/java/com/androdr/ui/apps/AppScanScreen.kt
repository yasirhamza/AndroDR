package com.androdr.ui.apps

import androidx.compose.animation.AnimatedVisibility
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ExperimentalLayoutApi
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.LazyRow
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.CheckCircle
import androidx.compose.material.icons.filled.ExpandLess
import androidx.compose.material.icons.filled.ExpandMore
import androidx.compose.material3.AssistChip
import androidx.compose.material3.AssistChipDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FilterChip
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.SuggestionChip
import androidx.compose.material3.SuggestionChipDefaults
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
import com.androdr.data.model.AppRisk
import com.androdr.data.model.RiskLevel

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun AppScanScreen(
    viewModel: AppScanViewModel = hiltViewModel()
) {
    val filteredRisks by viewModel.filteredRisks.collectAsStateWithLifecycle()
    val filterLevel by viewModel.filterLevel.collectAsStateWithLifecycle()

    Column(modifier = Modifier.fillMaxSize()) {
        // Filter chips row
        LazyRow(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 16.dp, vertical = 8.dp),
            horizontalArrangement = Arrangement.spacedBy(8.dp)
        ) {
            item {
                FilterChip(
                    selected = filterLevel == null,
                    onClick = { viewModel.setFilter(null) },
                    label = { Text(stringResource(R.string.filter_all)) }
                )
            }
            items(RiskLevel.values()) { level ->
                FilterChip(
                    selected = filterLevel == level,
                    onClick = { viewModel.setFilter(level) },
                    label = { Text(level.name) }
                )
            }
        }

        if (filteredRisks.isEmpty()) {
            // Empty state
            Box(
                modifier = Modifier.fillMaxSize(),
                contentAlignment = Alignment.Center
            ) {
                Column(
                    horizontalAlignment = Alignment.CenterHorizontally,
                    verticalArrangement = Arrangement.spacedBy(12.dp)
                ) {
                    Icon(
                        imageVector = Icons.Filled.CheckCircle,
                        contentDescription = null,
                        tint = MaterialTheme.colorScheme.primary,
                        modifier = Modifier.size(64.dp)
                    )
                    Text(
                        text = stringResource(R.string.no_risks_found),
                        style = MaterialTheme.typography.titleMedium,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }
            }
        } else {
            LazyColumn(
                modifier = Modifier.fillMaxSize(),
                contentPadding = androidx.compose.foundation.layout.PaddingValues(16.dp),
                verticalArrangement = Arrangement.spacedBy(12.dp)
            ) {
                items(filteredRisks) { appRisk ->
                    AppRiskCard(appRisk = appRisk)
                }
            }
        }
    }
}

@OptIn(ExperimentalLayoutApi::class)
@Composable
private fun AppRiskCard(appRisk: AppRisk) {
    var expanded by remember { mutableStateOf(false) }

    Card(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(
            containerColor = MaterialTheme.colorScheme.surfaceContainer
        )
    ) {
        Column(
            modifier = Modifier.padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(8.dp)
        ) {
            // App header row
            Row(
                modifier = Modifier.fillMaxWidth(),
                verticalAlignment = Alignment.CenterVertically
            ) {
                // App icon placeholder with first letter
                Box(
                    modifier = Modifier
                        .size(44.dp)
                        .background(
                            color = riskLevelColor(appRisk.riskLevel).copy(alpha = 0.25f),
                            shape = CircleShape
                        ),
                    contentAlignment = Alignment.Center
                ) {
                    Text(
                        text = appRisk.appName.firstOrNull()?.uppercase() ?: "?",
                        style = MaterialTheme.typography.titleMedium,
                        fontWeight = FontWeight.Bold,
                        color = riskLevelColor(appRisk.riskLevel)
                    )
                }

                Spacer(modifier = Modifier.width(12.dp))

                Column(modifier = Modifier.weight(1f)) {
                    Text(
                        text = appRisk.appName,
                        style = MaterialTheme.typography.titleSmall,
                        fontWeight = FontWeight.SemiBold
                    )
                    Text(
                        text = appRisk.packageName,
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }

                // Risk level chip
                RiskChip(riskLevel = appRisk.riskLevel)
            }

            // Badges row
            if (appRisk.isKnownMalware || appRisk.isSideloaded) {
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    if (appRisk.isKnownMalware) {
                        SuggestionChip(
                            onClick = {},
                            label = { Text(stringResource(R.string.badge_known_malware)) },
                            colors = SuggestionChipDefaults.suggestionChipColors(
                                containerColor = Color(0xFFCF6679).copy(alpha = 0.2f),
                                labelColor = Color(0xFFCF6679)
                            )
                        )
                    }
                    if (appRisk.isSideloaded) {
                        SuggestionChip(
                            onClick = {},
                            label = { Text(stringResource(R.string.badge_sideloaded)) },
                            colors = SuggestionChipDefaults.suggestionChipColors(
                                containerColor = Color(0xFFFF9800).copy(alpha = 0.2f),
                                labelColor = Color(0xFFFF9800)
                            )
                        )
                    }
                }
            }

            // Expand/collapse toggle
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Text(
                    text = "${appRisk.reasons.size} reason(s)",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
                IconButton(onClick = { expanded = !expanded }) {
                    Icon(
                        imageVector = if (expanded) Icons.Filled.ExpandLess else Icons.Filled.ExpandMore,
                        contentDescription = if (expanded) "Collapse" else "Expand"
                    )
                }
            }

            // Expandable section
            AnimatedVisibility(visible = expanded) {
                Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    if (appRisk.reasons.isNotEmpty()) {
                        Text(
                            text = stringResource(R.string.label_reasons),
                            style = MaterialTheme.typography.labelMedium,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                        appRisk.reasons.forEach { reason ->
                            Text(
                                text = "• $reason",
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.onSurface
                            )
                        }
                    }

                    if (appRisk.dangerousPermissions.isNotEmpty()) {
                        Spacer(modifier = Modifier.height(4.dp))
                        Text(
                            text = stringResource(R.string.label_dangerous_permissions),
                            style = MaterialTheme.typography.labelMedium,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                        FlowRow(
                            horizontalArrangement = Arrangement.spacedBy(6.dp),
                            verticalArrangement = Arrangement.spacedBy(4.dp)
                        ) {
                            appRisk.dangerousPermissions.forEach { perm ->
                                val shortPerm = perm.substringAfterLast('.')
                                AssistChip(
                                    onClick = {},
                                    label = { Text(shortPerm, style = MaterialTheme.typography.labelSmall) },
                                    colors = AssistChipDefaults.assistChipColors(
                                        containerColor = Color(0xFFFF9800).copy(alpha = 0.15f),
                                        labelColor = Color(0xFFFF9800)
                                    )
                                )
                            }
                        }
                    }
                }
            }
        }
    }
}

@Composable
fun RiskChip(riskLevel: RiskLevel, modifier: Modifier = Modifier) {
    val color = riskLevelColor(riskLevel)
    SuggestionChip(
        onClick = {},
        label = {
            Text(
                text = riskLevel.name,
                style = MaterialTheme.typography.labelSmall,
                fontWeight = FontWeight.Bold
            )
        },
        colors = SuggestionChipDefaults.suggestionChipColors(
            containerColor = color.copy(alpha = 0.2f),
            labelColor = color
        ),
        modifier = modifier
    )
}

fun riskLevelColor(riskLevel: RiskLevel): Color = when (riskLevel) {
    RiskLevel.CRITICAL -> Color(0xFFCF6679)
    RiskLevel.HIGH -> Color(0xFFFF9800)
    RiskLevel.MEDIUM -> Color(0xFFFFD600)
    RiskLevel.LOW -> Color(0xFF00D4AA)
}
