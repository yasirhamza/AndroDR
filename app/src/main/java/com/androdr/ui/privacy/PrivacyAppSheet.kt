package com.androdr.ui.privacy

import androidx.compose.runtime.Composable
import androidx.compose.runtime.MutableState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import com.androdr.privacy.AppPrivacyRow

/**
 * Which app's sheet is open (saved across recreation), starting on [initialPackage] once per navigation entry
 * (the Timeline's "Open in privacy results"): recreation must not reopen a sheet the user closed.
 */
@Composable
internal fun rememberOpenApp(initialPackage: String?): MutableState<String?> {
    val open = rememberSaveable { mutableStateOf<String?>(null) }
    var applied by rememberSaveable { mutableStateOf(false) }
    if (!applied) {
        applied = true
        if (initialPackage != null) open.value = initialPackage
    }
    return open
}

/** What an app's sheet shows: nothing yet (results still loading), the app, or nothing because it is gone. */
internal sealed interface AppSheetState {
    data object Waiting : AppSheetState
    data class Open(val row: AppPrivacyRow) : AppSheetState
    data object Gone : AppSheetState
}

/** [packageName]'s sheet in [state]: it waits while the results load, so a sheet opened early is not lost. */
internal fun appSheetState(state: PrivacyUiState, packageName: String): AppSheetState {
    if (!state.loaded) return AppSheetState.Waiting
    val row = state.sections.flatMap { it.second }.firstOrNull { it.packageName == packageName }
    return if (row == null) AppSheetState.Gone else AppSheetState.Open(row)
}

/** The app's sheet; [onDismiss] when the loaded results no longer list the app. */
@Composable
internal fun AppSheet(
    state: PrivacyUiState,
    packageName: String,
    onDismiss: () -> Unit,
    onOpenEvidence: (String, Int) -> Unit,
) {
    when (val s = appSheetState(state, packageName)) {
        AppSheetState.Waiting -> Unit
        AppSheetState.Gone -> onDismiss()
        is AppSheetState.Open -> AppDetailSheet(s.row, state.registrySizeAtScan ?: 0, onDismiss, onOpenEvidence)
    }
}
