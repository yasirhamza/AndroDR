package com.androdr.ui.telemetry

import android.os.Looper
import androidx.compose.ui.test.ExperimentalTestApi
import androidx.compose.ui.test.hasText
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onNodeWithContentDescription
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performScrollToNode
import androidx.compose.ui.test.hasScrollAction
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.lifecycle.SavedStateHandle
import com.androdr.ui.registerHostActivity
import com.androdr.data.model.ScanState
import com.androdr.data.store.StoreFixture
import com.androdr.sigma.StoreRecord
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Rule
import org.junit.Test
import org.junit.rules.RuleChain
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.Shadows.shadowOf
import java.time.Duration

/**
 * #418: the telemetry browser's screens and their Pager wiring, rendered over a real store: the
 * services level lists a COMPLETE scan's services and opens one; the records level pages through
 * [TelemetryBrowserViewModel.records] (Pager → keyset source → LazyColumn) past its first page,
 * re-queries on a search and says when nothing matches; the fact level shows fields or "unreadable".
 */
@OptIn(ExperimentalTestApi::class)
@RunWith(RobolectricTestRunner::class)
class TelemetryBrowserScreensTest {
    private val composeRule = createComposeRule()

    @get:Rule val chain: RuleChain = RuleChain.outerRule(registerHostActivity()).around(composeRule)

    private val f = StoreFixture()

    @After fun tearDown() = f.close()

    private fun vm(vararg args: Pair<String, Any?>) =
        TelemetryBrowserViewModel(f.reader, f.db.scanResultDao(), SavedStateHandle(mapOf(*args)))

    private fun app(pkg: String) = StoreRecord(mapOf("package_name" to pkg, "app_name" to "App $pkg",
        "is_system_app" to false, "source" to "LIVE_SCAN", "captured_at" to StoreFixture.CAPTURED))

    private fun completeScan(id: Long, service: String, records: List<StoreRecord>) = runBlocking {
        f.scan(id)
        val r = f.persist(id, service, records)
        f.setState(id, ScanState.COMPLETE)
        r
    }

    private fun awaitText(text: String) = awaitTicking {
        composeRule.onAllNodes(hasText(text, substring = true)).fetchSemanticsNodes().isNotEmpty()
    }

    /**
     * Waits for [condition], moving the main looper's clock along as it polls: the search debounce
     * is a delay on the view model's main dispatcher, which a paused Robolectric looper never reaches.
     */
    private fun awaitTicking(condition: () -> Boolean) = composeRule.waitUntil(TIMEOUT_MS) {
        shadowOf(Looper.getMainLooper()).idleFor(Duration.ofMillis(TICK_MS))
        condition()
    }

    @Test
    fun `the services level lists each service with its count and opens one`() {
        completeScan(1L, "app_scanner", (0 until 3).map { app("com.p$it") })
        val opened = mutableListOf<Pair<Long, String>>()
        val model = vm(TelemetryBrowserViewModel.ARG_SCAN to 1L)
        composeRule.setContent {
            TelemetryServicesScreen(onOpenService = { s, svc -> opened += s to svc }, onBack = {}, viewModel = model)
        }
        awaitText("app_scanner")
        composeRule.onNodeWithText("3 records").assertExists()
        composeRule.onNodeWithText("app_scanner").performClick()
        assertEquals(listOf(1L to "app_scanner"), opened)
    }

    @Test
    fun `a scan that is not COMPLETE is not available`() {
        runBlocking { f.scan(2L) } // IN_PROGRESS
        val model = vm(TelemetryBrowserViewModel.ARG_SCAN to 2L)
        composeRule.setContent { TelemetryServicesScreen(onOpenService = { _, _ -> }, onBack = {}, viewModel = model) }
        awaitText("not available")
    }

    @Test
    fun `the records list pages past its first page and opens a record`() {
        val pageSize = 100 // TelemetryBrowserViewModel.PAGE_SIZE
        val written = completeScan(1L, "app_scanner", (0 until pageSize * 2 + 5).map { app("com.p%03d".format(it)) })
        val opened = mutableListOf<Pair<Long, Long>>()
        val model = vm(TelemetryBrowserViewModel.ARG_SCAN to 1L, TelemetryBrowserViewModel.ARG_SERVICE to "app_scanner")
        composeRule.setContent {
            TelemetryRecordsScreen(
                onOpenFact = { fact, scan -> opened += fact to scan }, onBack = {}, viewModel = model,
            )
        }
        awaitText("com.p000")
        // Scrolling to the last record makes the Pager append through the keyset source twice.
        val last = "com.p%03d".format(pageSize * 2 + 4)
        composeRule.waitUntil(TIMEOUT_MS) {
            runCatching { composeRule.onNode(hasScrollAction()).performScrollToNode(hasText(last, substring = true)) }
                .isSuccess
        }
        composeRule.onNodeWithText(last, substring = true).performClick()
        assertEquals(listOf(written.factIdByChunkIndex[pageSize * 2 + 4] to 1L), opened)
    }

    @Test
    fun `a search re-queries the records and says when nothing matches`() {
        completeScan(1L, "app_scanner", listOf(app("com.alpha"), app("org.beta"), app("com.gamma")))
        val model = vm(TelemetryBrowserViewModel.ARG_SCAN to 1L, TelemetryBrowserViewModel.ARG_SERVICE to "app_scanner")
        composeRule.setContent { TelemetryRecordsScreen(onOpenFact = { _, _ -> }, onBack = {}, viewModel = model) }
        awaitText("com.alpha")
        model.setSearchText("beta")
        awaitTicking {
            composeRule.onAllNodes(hasText("com.alpha", substring = true)).fetchSemanticsNodes().isEmpty()
        }
        composeRule.onNodeWithText("org.beta", substring = true).assertExists()
        model.setSearchText("zzz")
        awaitText("No records match")
        composeRule.onNodeWithContentDescription("Clear search").performClick()
        awaitText("com.gamma")
    }

    @Test
    fun `a fact shows its fields, and an unreadable body says so`() {
        val r = completeScan(1L, "app_scanner", listOf(app("com.ok"), app("com.bad")))
        val ok = r.factIdByChunkIndex[0]
        val bad = r.factIdByChunkIndex[1]
        f.db.openHelper.writableDatabase.execSQL(
            "UPDATE record_body SET rawBytes = -1 WHERE hash = (SELECT bodyHash FROM telemetry_record WHERE id = $bad)"
        )
        val good = vm(TelemetryBrowserViewModel.ARG_FACT to ok)
        val broken = vm(TelemetryBrowserViewModel.ARG_FACT to bad)
        var showBroken by mutableStateOf(false)
        composeRule.setContent {
            if (showBroken) TelemetryFactScreen(onBack = {}, viewModel = broken)
            else TelemetryFactScreen(onBack = {}, viewModel = good)
        }
        awaitText("package_name")
        composeRule.onNodeWithText("com.ok").assertExists()
        showBroken = true
        awaitText("Unreadable")
    }

    @Test
    fun `a fact no longer stored reads as missing`() {
        val model = vm(TelemetryBrowserViewModel.ARG_FACT to 999L)
        composeRule.setContent { TelemetryFactScreen(onBack = {}, viewModel = model) }
        awaitText("no longer stored")
    }

    private companion object {
        const val TIMEOUT_MS = 10_000L
        const val TICK_MS = 50L
    }
}
