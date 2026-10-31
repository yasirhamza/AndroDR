package com.androdr.ui.settings

import android.app.Application
import android.content.ComponentName
import androidx.activity.ComponentActivity
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onNodeWithText
import androidx.test.core.app.ApplicationProvider
import com.androdr.data.store.BodyStats
import com.androdr.data.store.StorageSummary
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.RuleChain
import org.junit.rules.TestRule
import org.junit.runner.RunWith
import org.junit.runners.model.Statement
import org.robolectric.RobolectricTestRunner
import org.robolectric.Shadows.shadowOf
import java.io.File

/**
 * #418: Settings' storage card showed only the three retention kinds, under a "Total" that read as the
 * whole store; the bodies kept only for findings and alerts (pinned orphans) and the alert evidence
 * were in [StorageSummary] but never shown. The card now lists both, and Total covers everything.
 */
@RunWith(RobolectricTestRunner::class)
class StorageFiguresTest {
    private val composeRule = createComposeRule()

    private val registerHostActivity = TestRule { base, _ ->
        object : Statement() {
            override fun evaluate() {
                val app = ApplicationProvider.getApplicationContext<Application>()
                shadowOf(app.packageManager)
                    .addActivityIfNotPresent(ComponentName(app.packageName, ComponentActivity::class.java.name))
                base.evaluate()
            }
        }
    }

    @get:Rule val chain: RuleChain = RuleChain.outerRule(registerHostActivity).around(composeRule)

    private val summary = StorageSummary(
        snapshots = BodyStats(10, 1_000, 2_000),
        liveEvents = BodyStats(20, 2_000, 4_000),
        imports = BodyStats(30, 3_000, 6_000),
        pinnedOrphans = BodyStats(4, 500, 900),
        alertEvidenceBytes = 2_048,
    )

    @Test
    fun `pinned orphans and alert evidence are shown, and Total covers them`() {
        composeRule.setContent { StorageFigures(summary) }
        composeRule.onNodeWithText("Snapshots").assertExists()
        composeRule.onNodeWithText("10 distinct records · 1000 bytes").assertExists()
        composeRule.onNodeWithText("Kept for findings and alerts").assertExists()
        composeRule.onNodeWithText("4 distinct records · 500 bytes").assertExists()
        composeRule.onNodeWithText("Alert evidence").assertExists()
        composeRule.onNodeWithText("2.0 KB").assertExists()
        composeRule.onNodeWithText("Total").assertExists()
        // 10 + 20 + 30 + 4 records; 1000 + 2000 + 3000 + 500 + 2048 bytes = 8548 bytes = 8.3 KB.
        composeRule.onNodeWithText("64 distinct records · 8.3 KB").assertExists()
    }

    @Test
    fun `an unavailable summary says so`() {
        composeRule.setContent { StorageFigures(null) }
        composeRule.onNodeWithText("Storage size unavailable").assertExists()
    }

    /** The Settings screens' copy lives in strings.xml (#418), not in Text("…") literals. */
    @Test
    fun `settings copy is not hard-coded`() {
        val dir = listOf(File("src/main/java"), File("app/src/main/java")).first { it.isDirectory }
            .resolve("com/androdr/ui/settings")
        val literal = Regex(
            """(Text\(\s*(text\s*=\s*)?"|(contentDescription|label|subtitle|title|value)\s*=\s*"|StatRow\(\s*"|""" +
                """UpdateStatusRow\(\s*"|createChooser\([^,]+,\s*"|\bto\s+")""",
        )
        for (name in listOf("SettingsScreen.kt", "TelemetryStorageSection.kt")) {
            val hits = dir.resolve(name).readLines().filter { literal.containsMatchIn(it) }
            assertTrue("$name has hard-coded copy: $hits", hits.isEmpty())
        }
    }
}
