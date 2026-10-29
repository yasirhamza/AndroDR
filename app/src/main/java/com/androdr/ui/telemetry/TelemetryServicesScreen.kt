package com.androdr.ui.telemetry

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.pluralStringResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.androdr.R

/**
 * The telemetry browser's first level (spec §8.1): the services one `COMPLETE` scan stored, each
 * with its record count. A scan that is not `COMPLETE` (still running, being deleted, or gone)
 * shows as not available.
 */
@Composable
fun TelemetryServicesScreen(
    onOpenService: (scanId: Long, service: String) -> Unit,
    onBack: () -> Unit,
    viewModel: TelemetryBrowserViewModel = hiltViewModel(),
) {
    val state by viewModel.services.collectAsStateWithLifecycle()
    Column(modifier = Modifier.fillMaxSize()) {
        TelemetryTopBar(stringResource(R.string.telemetry_title), onBack)
        when (val s = state) {
            ServicesState.Loading -> CenteredProgress()
            ServicesState.Unavailable -> CenteredMessage(stringResource(R.string.telemetry_scan_unavailable))
            is ServicesState.Loaded -> if (s.services.isEmpty()) {
                CenteredMessage(stringResource(R.string.telemetry_scan_empty))
            } else {
                LazyColumn(
                    modifier = Modifier.fillMaxSize(),
                    contentPadding = PaddingValues(16.dp),
                    verticalArrangement = Arrangement.spacedBy(8.dp),
                ) {
                    items(s.services, key = { it.service }) { summary ->
                        Card(
                            modifier = Modifier.fillMaxWidth().clickable {
                                viewModel.scanId?.let { onOpenService(it, summary.service) }
                            },
                            colors = CardDefaults.cardColors(
                                containerColor = MaterialTheme.colorScheme.surfaceContainer,
                            ),
                        ) {
                            Row(
                                modifier = Modifier.fillMaxWidth().padding(16.dp),
                                horizontalArrangement = Arrangement.SpaceBetween,
                                verticalAlignment = Alignment.CenterVertically,
                            ) {
                                Text(summary.service, style = MaterialTheme.typography.titleSmall,
                                    fontWeight = FontWeight.SemiBold)
                                Text(
                                    pluralStringResource(R.plurals.telemetry_record_count, summary.records,
                                        summary.records),
                                    style = MaterialTheme.typography.labelMedium,
                                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                                )
                            }
                        }
                    }
                }
            }
        }
    }
}

/** The browser's top bar: [title] and a back arrow. */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
internal fun TelemetryTopBar(title: String, onBack: () -> Unit, actions: @Composable () -> Unit = {}) {
    TopAppBar(
        title = { Text(title) },
        navigationIcon = {
            IconButton(onClick = onBack) {
                Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = stringResource(R.string.telemetry_back))
            }
        },
        actions = { actions() },
    )
}

@Composable
internal fun CenteredProgress() {
    Box(modifier = Modifier.fillMaxSize(), contentAlignment = Alignment.Center) { CircularProgressIndicator() }
}

@Composable
internal fun CenteredMessage(text: String) {
    Box(modifier = Modifier.fillMaxSize().padding(24.dp), contentAlignment = Alignment.Center) {
        Text(text, style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
    }
}
