package com.androdr.cellular

import android.content.Context
import android.telephony.CellInfo
import android.util.Log
import com.androdr.data.model.CaptureContext
import com.androdr.data.model.CaptureOrigin
import com.androdr.data.model.CellularSnapshot
import com.androdr.data.model.ServiceContext
import com.androdr.data.repo.ScanRepository
import com.androdr.sigma.Finding
import com.androdr.sigma.SigmaRuleEngine
import io.mockk.Call
import io.mockk.MockKAnswerScope
import io.mockk.Runs
import io.mockk.coEvery
import io.mockk.every
import io.mockk.just
import io.mockk.mockk
import io.mockk.mockkStatic
import io.mockk.unmockkStatic
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import org.junit.After
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

/**
 * The privacy gate that sees what actually reaches logcat.
 *
 * [CellularSourceInvariantsTest] bans the string shapes that leaked once;
 * a differently-shaped leak (`"$snapshot"`, a helper that formats the
 * tuple, a neighbour list) passes it. This test drives `handle()` through
 * every branch that logs — a registered read, a tracking-area change, a
 * finding whose title names the tower, an unregistered read, an empty
 * delivery, a failing evaluator — with distinctive identity values, and
 * asserts that no message carries any of them.
 *
 * The banned set is taken from the recorded snapshots' own
 * [CellularSnapshot.identityValues], so a field added to that method
 * widens this gate without anyone remembering to.
 */
class CellularMonitorLogPrivacyTest {

    private val engine = mockk<SigmaRuleEngine>()
    private val repository = mockk<ScanRepository>()
    private val messages = mutableListOf<String>()
    private var now = 1_000L

    private val deviceContext = object : DeviceContextSource {
        override fun capture(origin: CaptureOrigin, rawRecordCount: Int) = CaptureContext(
            origin = origin,
            appForeground = false,
            screenInteractive = true,
            dataActivity = "NONE",
            rawRecordCount = rawRecordCount,
        )

        override fun movement(now: Long) = Movement(movedMetersLast5m = 640, fixAgeSeconds = 12)

        override fun sim() = SimIdentity(mcc = "262", mnc = "01", operatorName = "Ooredoo")

        override fun service() = ServiceContext(state = "IN_SERVICE", isRoaming = false, dataNetworkType = "LTE")
    }

    private fun monitor() = CellularMonitor(
        context = mockk<Context>(relaxed = true),
        engine = engine,
        repository = repository,
        scope = CoroutineScope(Dispatchers.Unconfined),
        clock = { now },
        deviceContext = deviceContext,
    )

    private fun neighbours(): List<CellInfo> =
        List(3) { i -> CellInfoFixtures.lte(registered = false, pci = 501 + i, earfcn = 1600, rsrp = -95) }

    private fun serving(tac: Int) = CellInfoFixtures.lte(
        tac = tac, ci = 192816407, pci = 167, operatorName = "Telekom-Testnetz",
    )

    @Before
    fun setUp() {
        CellularState.reset()
        mockkStatic(Log::class)
        val capture: MockKAnswerScope<Int, Int>.(Call) -> Int = { messages += secondArg<String>(); 0 }
        every { Log.v(any(), any<String>()) } answers capture
        every { Log.d(any(), any<String>()) } answers capture
        every { Log.i(any(), any<String>()) } answers capture
        every { Log.w(any(), any<String>()) } answers capture
        every { Log.e(any(), any<String>()) } answers capture
        every { Log.v(any(), any<String>(), any()) } answers capture
        every { Log.d(any(), any<String>(), any()) } answers capture
        every { Log.i(any(), any<String>(), any()) } answers capture
        every { Log.w(any(), any<String>(), any()) } answers capture
        every { Log.e(any(), any<String>(), any()) } answers capture
        coEvery { repository.logCellularTimelineEvents(any()) } just Runs
        every { engine.getRules() } returns emptyList()
    }

    @After
    fun tearDown() {
        unmockkStatic(Log::class)
        CellularState.reset()
    }

    @Test
    fun `nothing that identifies a cell reaches a log line`() {
        // A finding whose title names the tower, as a remote rule could.
        every { engine.evaluateCellular(any()) } returns listOf(
            Finding(ruleId = "androdr-999", title = "Serving cell 1437 on 42701 lost its neighbours", level = "low"),
        )
        val m = monitor()
        m.handle(listOf(serving(tac = 1437)) + neighbours(), CaptureOrigin.PRIME)
        now += 30_000
        m.handle(listOf(serving(tac = 1438)) + neighbours(), CaptureOrigin.CALLBACK)
        now += 30_000
        m.handle(neighbours(), CaptureOrigin.CALLBACK)
        now += 30_000
        m.handle(emptyList(), CaptureOrigin.CALLBACK)
        now += 30_000
        every { engine.evaluateCellular(any()) } throws IllegalStateException("evaluator failed")
        m.handle(listOf(serving(tac = 1439)) + neighbours(), CaptureOrigin.CALLBACK)

        val recorded = CellularState.history.value
        assertTrue("the monitor must have recorded observations for this test to mean anything", recorded.size >= 3)
        assertTrue("the monitor must have logged for this test to mean anything", messages.size >= 5)

        val identity = recorded.flatMap { it.identityValues() }.toSet() +
            setOf("1437", "1438", "1439", "192816407", "167", "501", "502", "503", "Telekom-Testnetz", "Ooredoo")
        val leaks = messages.flatMap { msg -> identity.filter { msg.contains(it) }.map { "\"$it\" in: $msg" } }
        assertTrue("cell identity reached a log line:\n${leaks.joinToString("\n")}", leaks.isEmpty())
    }

    @Test
    fun `the log still says whether identity fields arrived`() {
        // The redaction must not go so far that the diagnostic is lost: an
        // operator that blanks TAC on a device is exactly what these lines
        // exist to show.
        every { engine.evaluateCellular(any()) } returns emptyList()
        monitor().handle(listOf(serving(tac = 1437)) + neighbours(), CaptureOrigin.PRIME)

        assertTrue(
            "the snapshot line must report the SHAPE of the identity fields",
            messages.any { it.contains("tac=set") && it.contains("ci=set") && it.contains("plmn=set") },
        )
    }
}
