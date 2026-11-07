package com.androdr.ui.privacy

import androidx.annotation.StringRes
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.selection.toggleable
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Checkbox
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.ModalBottomSheet
import androidx.compose.material3.Text
import androidx.compose.material3.rememberModalBottomSheetState
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.androdr.R
import com.androdr.privacy.model.TrackerCategory

@StringRes
internal fun categoryLabel(c: TrackerCategory): Int = when (c) {
    TrackerCategory.ADVERTISEMENT -> R.string.privacy_cat_advertisement
    TrackerCategory.PROFILING -> R.string.privacy_cat_profiling
    TrackerCategory.IDENTIFICATION -> R.string.privacy_cat_identification
    TrackerCategory.LOCATION -> R.string.privacy_cat_location
    TrackerCategory.ANALYTICS -> R.string.privacy_cat_analytics
    TrackerCategory.CRASH_REPORTING -> R.string.privacy_cat_crash_reporting
    TrackerCategory.UNCATEGORISED -> R.string.privacy_cat_uncategorised
    TrackerCategory.OTHER -> R.string.privacy_cat_other
}

@StringRes
internal fun categoryInfo(c: TrackerCategory): Int = when (c) {
    TrackerCategory.ADVERTISEMENT -> R.string.privacy_cat_advertisement_info
    TrackerCategory.PROFILING -> R.string.privacy_cat_profiling_info
    TrackerCategory.IDENTIFICATION -> R.string.privacy_cat_identification_info
    TrackerCategory.LOCATION -> R.string.privacy_cat_location_info
    TrackerCategory.ANALYTICS -> R.string.privacy_cat_analytics_info
    TrackerCategory.CRASH_REPORTING -> R.string.privacy_cat_crash_reporting_info
    TrackerCategory.UNCATEGORISED -> R.string.privacy_cat_uncategorised_info
    TrackerCategory.OTHER -> R.string.privacy_cat_other_info
}

/** "What I refuse": one checkbox per category (six purposes, Uncategorised, Other). */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun PrivacyThresholdSheet(
    refused: Set<TrackerCategory>,
    onChange: (Set<TrackerCategory>) -> Unit,
    onDismiss: () -> Unit,
) {
    ModalBottomSheet(onDismissRequest = onDismiss, sheetState = rememberModalBottomSheetState()) {
        Column(
            modifier = Modifier.verticalScroll(rememberScrollState()).padding(horizontal = 24.dp, vertical = 8.dp),
            verticalArrangement = Arrangement.spacedBy(4.dp),
        ) {
            Text(
                stringResource(R.string.privacy_threshold_title),
                style = MaterialTheme.typography.titleMedium,
                fontWeight = FontWeight.Bold,
            )
            for (category in TrackerCategory.entries) {
                val checked = category in refused
                Row(
                    modifier = Modifier.fillMaxWidth().toggleable(
                        value = checked, role = Role.Checkbox,
                        onValueChange = { on -> onChange(if (on) refused + category else refused - category) },
                    ).padding(vertical = 6.dp),
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.spacedBy(12.dp),
                ) {
                    Checkbox(checked = checked, onCheckedChange = null)
                    Column(modifier = Modifier.weight(1f)) {
                        Text(stringResource(categoryLabel(category)), style = MaterialTheme.typography.bodyLarge)
                        Text(
                            stringResource(categoryInfo(category)),
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                    }
                }
            }
        }
    }
}
