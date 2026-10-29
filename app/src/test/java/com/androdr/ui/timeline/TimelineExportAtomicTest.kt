package com.androdr.ui.timeline

import android.content.Context
import androidx.lifecycle.SavedStateHandle
import androidx.test.core.app.ApplicationProvider
import io.mockk.coEvery
import io.mockk.mockk
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.test.StandardTestDispatcher
import kotlinx.coroutines.test.advanceUntilIdle
import kotlinx.coroutines.test.resetMain
import kotlinx.coroutines.test.runTest
import kotlinx.coroutines.test.setMain
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import java.io.File
import java.io.IOException

/**
 * Final review M7: the Timeline export wrote straight to its final `androdr_timeline_*` file, so a
 * failure partway (a full disk) left a truncated export in `cache/reports/`. It now writes through
 * the report export's `.part`-then-rename helper: a failed export leaves no file, a finished one
 * leaves only the final file.
 */
@OptIn(ExperimentalCoroutinesApi::class)
@RunWith(RobolectricTestRunner::class)
class TimelineExportAtomicTest {
    private val dispatcher = StandardTestDispatcher()
    private val context: Context = ApplicationProvider.getApplicationContext()
    private val reportsDir = File(context.cacheDir, "reports")

    @Before fun setUp() {
        Dispatchers.setMain(dispatcher)
        reportsDir.deleteRecursively()
    }

    @After fun tearDown() = Dispatchers.resetMain()

    /** Timeline entries whose page walk throws on call number [failOnCall] (1-based); 0 never throws. */
    private fun entries(failOnCall: Int): TimelineEntries {
        var calls = 0
        return mockk(relaxed = true) {
            coEvery { forEachPage(any(), any(), any(), any()) } coAnswers {
                if (++calls == failOnCall) throw IOException("No space left on device")
            }
        }
    }

    private fun vm(entries: TimelineEntries) = TimelineViewModel(
        appContext = context,
        db = mockk(relaxed = true),
        entries = entries,
        knownAppResolver = mockk(relaxed = true),
        sigmaRuleEngine = mockk(relaxed = true),
        scanRepository = mockk(relaxed = true),
        reportExporter = mockk(relaxed = true),
        clusterMembers = mockk(relaxed = true),
        signalMembers = mockk(relaxed = true),
        findingsRepository = mockk(relaxed = true),
        savedState = SavedStateHandle(),
    ).also { it.io = dispatcher }

    private fun files(): List<String> = reportsDir.list()?.toList().orEmpty()

    @Test
    fun `a CSV export that fails after its header leaves no file behind`() = runTest(dispatcher) {
        val vm = vm(entries(failOnCall = 1))
        vm.exportCsv()
        advanceUntilIdle()
        assertEquals("no truncated or partial file", emptyList<String>(), files())
        assertNull("nothing to share", vm.shareUri.value)
        assertFalse(vm.exporting.value)
    }

    @Test
    fun `a plaintext export that fails after its header leaves no file behind`() = runTest(dispatcher) {
        // Call 1 is the totals pass, before the file is opened; call 2 runs after the header is written.
        val vm = vm(entries(failOnCall = 2))
        vm.exportPlaintext()
        advanceUntilIdle()
        assertEquals("no truncated or partial file", emptyList<String>(), files())
        assertNull(vm.shareUri.value)
    }

    @Test
    fun `a finished export leaves only the final file, never a part file`() = runTest(dispatcher) {
        val vm = vm(entries(failOnCall = 0))
        vm.exportCsv()
        advanceUntilIdle()
        val names = files()
        assertEquals(names.toString(), 1, names.size)
        assertTrue(names.single(), names.single().startsWith("androdr_timeline_") && names.single().endsWith(".csv"))
        assertTrue("the header was written", File(reportsDir, names.single()).readText().isNotEmpty())
    }
}
