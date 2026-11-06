package com.androdr.ui.dashboard

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import com.androdr.privacy.PrivacySummary
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.test.UnconfinedTestDispatcher
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner

@OptIn(ExperimentalCoroutinesApi::class)
@RunWith(RobolectricTestRunner::class)
class PrivacyCardTextTest {
    private val res = ApplicationProvider.getApplicationContext<Context>().resources
    private val now = 10_000_000_000L
    private val scannedAt = now - 3 * 86_400_000L

    private fun summary(crossing: Int = 2, new: Int = 0, notInspected: Int = 0) =
        PrivacySummary(crossing, new, notInspected, scannedAt)

    @Test fun `the failure clause is present when notInspected is above zero and absent at zero`() {
        val with = privacyCardText(summary(notInspected = 3), res, now)
        assertTrue(with, with.contains("3 could not be fully inspected"))
        val without = privacyCardText(summary(notInspected = 0), res, now)
        assertFalse(without, without.contains("could not be fully inspected"))
    }

    @Test fun `the separator joins only the clauses that are present`() {
        val minimal = privacyCardText(summary(crossing = 1), res, now)
        assertTrue(minimal, minimal.startsWith("1 app crosses your threshold · scanned "))
        assertEquals(minimal, 1, minimal.split(" · ").size - 1)
        val full = privacyCardText(summary(crossing = 6, new = 2, notInspected = 3), res, now)
        assertEquals(
            full, listOf("6 apps cross your threshold", "2 new since last scan", "3 could not be fully inspected"),
            full.split(" · ").take(3),
        )
        assertTrue(full, full.split(" · ").last().startsWith("scanned "))
        assertEquals(full, 3, full.split(" · ").size - 1)
    }

    @Test fun `the never-scanned text appears when the summary is null`() {
        assertEquals("Privacy scan not run yet", privacyCardText(null, res, now))
        assertEquals("Privacy scan not run yet", privacyCardText(PrivacyCardState.NeverScanned, res, now))
    }

    @Test fun `before the first emission the card is Loading and never NeverScanned`() = runTest {
        val source = MutableSharedFlow<PrivacySummary?>()
        val state = source.asCardState(backgroundScope)
        assertEquals(PrivacyCardState.Loading, state.value)
        assertEquals("", privacyCardText(state.value, res, now))
        // Once subscribed and emitted, the real answer replaces Loading.
        val job = backgroundScope.launch(UnconfinedTestDispatcher(testScheduler)) { state.collect { } }
        runCurrent()
        source.emit(null)
        runCurrent()
        assertEquals(PrivacyCardState.NeverScanned, state.value)
        job.cancel()
    }
}
