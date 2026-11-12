package com.androdr.ui.privacy

import com.androdr.privacy.AppPrivacyRow
import com.androdr.privacy.InspectOutcome
import com.androdr.privacy.RowSection
import org.junit.Assert.assertEquals
import org.junit.Test

/**
 * An app's sheet opened from outside the screen (the Timeline's "Open in privacy results", spec 2026-11-10
 * §5.1): it waits for the results to load, opens once they have, and closes only when the app is not there.
 */
class PrivacyAppSheetTest {
    private fun row(pkg: String) = AppPrivacyRow(
        packageName = pkg, versionCode = 1, appLabel = pkg, isSystemApp = false, outcome = InspectOutcome.INSPECTED,
        reason = null, trackers = emptyList(), refusedInCode = 0, refusedCategories = emptySet(), newCrossing = false,
    )

    private val loaded = PrivacyUiState(sections = listOf(RowSection.OTHER to listOf(row("com.game"))), loaded = true)

    @Test fun `the app sheet opens once the results load`() {
        assertEquals(AppSheetState.Waiting, appSheetState(PrivacyUiState(), "com.game"))
        assertEquals(AppSheetState.Open(row("com.game")), appSheetState(loaded, "com.game"))
    }

    @Test fun `an app no longer in the results opens no sheet`() {
        assertEquals(AppSheetState.Gone, appSheetState(loaded, "com.removed"))
    }

    @Test fun `the screen's state says when the results have loaded`() {
        assertEquals(false, PrivacyUiState().loaded)
    }
}
