package com.androdr.ui.apps

import android.content.Intent
import android.net.Uri
import android.provider.Settings
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ExperimentalLayoutApi
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
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
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material.icons.filled.Warning
import androidx.compose.material3.AssistChip
import androidx.compose.material3.AssistChipDefaults
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FilterChip
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.ModalBottomSheet
import androidx.compose.material3.SuggestionChip
import androidx.compose.material3.SuggestionChipDefaults
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.rememberModalBottomSheetState
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.androdr.R
import com.androdr.data.model.AppRisk
import com.androdr.data.model.RiskLevel

@Suppress("LongMethod")
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun AppScanScreen(
    viewModel: AppScanViewModel = hiltViewModel()
) {
    val filteredRisks by viewModel.filteredRisks.collectAsStateWithLifecycle()
    val filterLevel by viewModel.filterLevel.collectAsStateWithLifecycle()
    var selectedRisk by remember { mutableStateOf<AppRisk?>(null) }

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
                    AppRiskCard(
                        appRisk = appRisk,
                        onClick = { selectedRisk = appRisk }
                    )
                }
            }
        }
    }

    selectedRisk?.let { risk ->
        AppRiskDetailSheet(
            risk = risk,
            onDismiss = { selectedRisk = null }
        )
    }
}

@Suppress("LongMethod")
@OptIn(ExperimentalLayoutApi::class)
@Composable
private fun AppRiskCard(appRisk: AppRisk, onClick: () -> Unit) {
    Card(
        modifier = Modifier
            .fillMaxWidth()
            .clickable(onClick = onClick),
        colors = CardDefaults.cardColors(
            containerColor = MaterialTheme.colorScheme.surfaceContainer
        )
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(16.dp),
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
                if (appRisk.isKnownMalware || appRisk.isSideloaded) {
                    Spacer(modifier = Modifier.height(4.dp))
                    FlowRow(
                        horizontalArrangement = Arrangement.spacedBy(6.dp),
                        verticalArrangement = Arrangement.spacedBy(4.dp)
                    ) {
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
            }

            Spacer(modifier = Modifier.width(8.dp))

            // Risk level chip
            RiskChip(riskLevel = appRisk.riskLevel)
        }
    }
}

@Suppress("LongMethod")
@OptIn(ExperimentalMaterial3Api::class, ExperimentalLayoutApi::class)
@Composable
private fun AppRiskDetailSheet(risk: AppRisk, onDismiss: () -> Unit) {
    val sheetState = rememberModalBottomSheetState(skipPartiallyExpanded = true)
    val context = LocalContext.current
    val steps = remember(risk) { remediationSteps(risk) }

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
         // Scrollable content
         Column(
            modifier = Modifier
                .weight(1f, fill = false)
                .verticalScroll(rememberScrollState()),
            verticalArrangement = Arrangement.spacedBy(16.dp)
         ) {
            // Header: icon + app name + package + RiskChip
            Row(
                modifier = Modifier.fillMaxWidth(),
                verticalAlignment = Alignment.CenterVertically
            ) {
                Box(
                    modifier = Modifier
                        .size(48.dp)
                        .background(
                            color = riskLevelColor(risk.riskLevel).copy(alpha = 0.25f),
                            shape = CircleShape
                        ),
                    contentAlignment = Alignment.Center
                ) {
                    Text(
                        text = risk.appName.firstOrNull()?.uppercase() ?: "?",
                        style = MaterialTheme.typography.titleMedium,
                        fontWeight = FontWeight.Bold,
                        color = riskLevelColor(risk.riskLevel)
                    )
                }

                Spacer(modifier = Modifier.width(12.dp))

                Column(modifier = Modifier.weight(1f)) {
                    Text(
                        text = risk.appName,
                        style = MaterialTheme.typography.titleMedium,
                        fontWeight = FontWeight.SemiBold
                    )
                    Text(
                        text = risk.packageName,
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }

                RiskChip(riskLevel = risk.riskLevel)
            }

            HorizontalDivider()

            // "Why it's flagged" section
            if (risk.reasons.isNotEmpty()) {
                Text(
                    text = stringResource(R.string.label_reasons),
                    style = MaterialTheme.typography.titleSmall,
                    fontWeight = FontWeight.SemiBold
                )
                risk.reasons.forEach { reason ->
                    Row(
                        horizontalArrangement = Arrangement.spacedBy(8.dp),
                        verticalAlignment = Alignment.Top
                    ) {
                        Icon(
                            imageVector = Icons.Filled.Warning,
                            contentDescription = null,
                            tint = riskLevelColor(risk.riskLevel),
                            modifier = Modifier.size(18.dp)
                        )
                        Text(
                            text = reason,
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurface
                        )
                    }
                }
            }

            HorizontalDivider()

            // "What to do" section
            Text(
                text = "What to do",
                style = MaterialTheme.typography.titleSmall,
                fontWeight = FontWeight.SemiBold
            )
            steps.forEachIndexed { index, step ->
                Text(
                    text = "${index + 1}. $step",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurface
                )
            }

            // Permissions section
            if (risk.dangerousPermissions.isNotEmpty()) {
                Text(
                    text = stringResource(R.string.label_dangerous_permissions),
                    style = MaterialTheme.typography.titleSmall,
                    fontWeight = FontWeight.SemiBold
                )
                FlowRow(
                    horizontalArrangement = Arrangement.spacedBy(6.dp),
                    verticalArrangement = Arrangement.spacedBy(4.dp)
                ) {
                    risk.dangerousPermissions.forEach { perm ->
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

         } // end scrollable column

            Spacer(modifier = Modifier.height(16.dp))

            // Uninstall button (pinned at bottom)
            Button(
                onClick = {
                    val intent = Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS).apply {
                        data = Uri.parse("package:${risk.packageName}")
                    }
                    context.startActivity(intent)
                },
                modifier = Modifier.fillMaxWidth(),
                colors = ButtonDefaults.buttonColors(
                    containerColor = MaterialTheme.colorScheme.error
                )
            ) {
                Icon(
                    imageVector = Icons.Filled.Delete,
                    contentDescription = null,
                    modifier = Modifier.size(18.dp)
                )
                Spacer(modifier = Modifier.width(8.dp))
                Text("Uninstall App")
            }

            // Dismiss button
            TextButton(
                onClick = onDismiss,
                modifier = Modifier.fillMaxWidth()
            ) {
                Text("Dismiss")
            }

            Spacer(modifier = Modifier.height(8.dp))
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

/** Derives actionable remediation steps from an [AppRisk]'s flags and reasons. */
internal fun remediationSteps(risk: AppRisk): List<String> {
    val steps = mutableListOf<String>()
    val reasonsJoined = risk.reasons.joinToString(" ")

    if (risk.isKnownMalware) {
        steps.add("Uninstall this app immediately \u2014 it matches a known malware database entry.")
    }

    if ("signing certificate" in reasonsJoined) {
        steps.add(
            "This app is signed by a known malware developer. " +
                "Uninstall it even if the app name looks legitimate."
        )
    }

    if ("accessibility service" in reasonsJoined.lowercase()) {
        steps.add(
            "This app can read your screen content. Go to Settings \u2192 " +
                "Accessibility and disable its service before uninstalling."
        )
    }

    if ("device administrator" in reasonsJoined.lowercase()) {
        steps.add(
            "This app has prevented its own uninstallation. Go to Settings \u2192 " +
                "Security \u2192 Device Admin Apps and remove it first."
        )
    }

    if ("surveillance-capable permissions" in reasonsJoined) {
        steps.add(
            "This app has extensive surveillance capabilities. " +
                "If you did not install it intentionally, uninstall it."
        )
    }

    if (risk.isSideloaded && steps.isEmpty()) {
        steps.add("This app was not installed from a trusted app store. Verify you intended to install it.")
    }

    if (steps.isEmpty()) {
        steps.add("Review this app and decide whether to keep it.")
    }

    steps.add("Run another scan after taking action to confirm the threat is resolved.")
    return steps
}
