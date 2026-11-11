package com.androdr.ui.privacy

import android.content.Context
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import androidx.test.core.app.ApplicationProvider
import com.androdr.privacy.AppPrivacyRow
import com.androdr.privacy.InspectOutcome
import com.androdr.privacy.TrackerGroup
import com.androdr.privacy.TrackerRow
import com.androdr.privacy.model.TrackerCategory
import com.androdr.ui.registerHostActivity
import org.junit.Assert.assertEquals
import org.junit.Rule
import org.junit.Test
import org.junit.rules.RuleChain
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner

/** Every tracker listed for an app opens its details: in the app's sheet and on each app line of a tracker card. */
@RunWith(RobolectricTestRunner::class)
class PrivacyEvidenceTapTest {
    private val composeRule = createComposeRule()

    @get:Rule val chain: RuleChain = RuleChain.outerRule(registerHostActivity()).around(composeRule)

    private val res = ApplicationProvider.getApplicationContext<Context>().resources

    private val tracker = TrackerRow(
        trackerId = 12, name = "Flurry", website = "https://www.flurry.com", categories = setOf(TrackerCategory.ANALYTICS),
        rawCategories = listOf("Analytics"), inCode = true, lookups = 0, lookupDays = 0, background = null,
        firstSeen = null, lastSeen = null, newSinceLastScan = false,
    )

    private fun app(pkg: String, label: String) = AppPrivacyRow(
        packageName = pkg, versionCode = 1, appLabel = label, isSystemApp = false, outcome = InspectOutcome.INSPECTED,
        reason = null, trackers = listOf(tracker), refusedInCode = 0, refusedCategories = emptySet(), newCrossing = false,
    )

    @Test fun `tapping an app line of a tracker card opens that app's details`() {
        val opened = ArrayList<Pair<String, Int>>()
        val group = TrackerGroup(12, "Flurry", "https://www.flurry.com", setOf(TrackerCategory.ANALYTICS),
            listOf(app("com.one", "One App") to tracker, app("com.two", "Two App") to tracker))
        composeRule.setContent { TrackerCard(group, res) { pkg, id -> opened += pkg to id } }
        composeRule.onNodeWithText("Two App", substring = true).performClick()
        assertEquals(listOf("com.two" to 12), opened)
    }

    @Test fun `tapping a tracker in an app's sheet opens its details`() {
        var calls = 0
        composeRule.setContent { TrackerDetail(tracker, res) { calls++ } }
        composeRule.onNodeWithText("Flurry").performClick()
        assertEquals(1, calls)
    }
}
