package com.androdr.cellular

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/**
 * Source- and manifest-level invariants for the cellular feature. Each one
 * pins a defect that actually shipped on this branch and was found by hand;
 * pinning them makes the next occurrence a build failure instead of a
 * discovery.
 *
 * These are deliberately source-inspection tests. The behaviours involved —
 * what reaches logcat, what the manifest grants — are not reachable from a JVM
 * unit test, and a gap that only an instrumented run or a security review
 * catches is not a gate.
 */
class CellularSourceInvariantsTest {

    private fun repoFile(vararg candidates: String): File =
        candidates.map(::File).firstOrNull { it.isFile }
            ?: error("not found; tried: ${candidates.toList()}")

    private fun monitorSource(): String = repoFile(
        "app/src/main/java/com/androdr/cellular/CellularMonitor.kt",
        "src/main/java/com/androdr/cellular/CellularMonitor.kt",
    ).readText()

    private fun manifest(): String = repoFile(
        "app/src/main/AndroidManifest.xml",
        "src/main/AndroidManifest.xml",
    ).readText()

    /**
     * A security review caught the monitor logging (mcc, mnc, tac, ci) on every
     * delivery — a timestamped location trail in logcat, readable over adb and
     * captured in bugreports, on a device whose threat model is that it may be
     * targeted.
     *
     * Interpolating an identity field into a string is how that happened, so
     * that exact shape is banned. Log lines report SHAPE (`present(...)`), not
     * values.
     */
    @Test
    fun `the monitor never interpolates cell identity into a string`() {
        val src = monitorSource()
        listOf(
            "\${snapshot.tac}", "\${snapshot.ci}", "\${snapshot.pci}",
            "\${snapshot.mcc}", "\${snapshot.mnc}",
            "\${snapshot.operatorAlphaLong}", "\${snapshot.previousTac}",
        ).forEach {
            assertFalse(
                "cell identity interpolated into a string in CellularMonitor: $it — " +
                    "log shape via present(), never values",
                src.contains(it),
            )
        }
    }

    /**
     * getAllCellInfo() returns an EMPTY LIST — not an error — when the caller
     * is not foreground. A foreground service only confers location access if
     * it declares the `location` type, so without this the monitor collects
     * nothing and reports nothing wrong: a silent, invisible failure.
     */
    @Test
    fun `the VPN service declares the location foreground-service type`() {
        val m = manifest()
        assertTrue(
            "DnsVpnService must declare foregroundServiceType including `location`, " +
                "or cell info silently comes back empty",
            Regex("""foregroundServiceType="[^"]*location[^"]*"""").containsMatchIn(m),
        )
        assertTrue(
            "FOREGROUND_SERVICE_LOCATION is required on Android 14+ to declare that type",
            m.contains("android.permission.FOREGROUND_SERVICE_LOCATION"),
        )
    }

    /**
     * Android 12+ refuses FINE on its own: the runtime dialog lets the user
     * grant approximate-only. Lint catches this, but lint findings can be
     * baselined or suppressed, and this one silently disables the feature.
     */
    @Test
    fun `fine location is never declared without coarse`() {
        val m = manifest()
        if (m.contains("android.permission.ACCESS_FINE_LOCATION")) {
            assertTrue(
                "ACCESS_FINE_LOCATION requires ACCESS_COARSE_LOCATION alongside it on Android 12+",
                m.contains("android.permission.ACCESS_COARSE_LOCATION"),
            )
        }
    }

    /**
     * `network_monitor` is dead on-device because it has a field map and no
     * evaluate method, so nothing ever reaches the evaluator with its service
     * string. Cellular needs all three legs: field map, evaluate method, and a
     * LIVE CALLER. The first two are covered by the taxonomy cross-check and
     * CellularEvaluationTest; this pins the third.
     */
    @Test
    fun `the monitor actually calls the rule engine`() {
        assertTrue(
            "CellularMonitor must invoke evaluateCellular, or the rules can never fire " +
                "(this is exactly why network_monitor is unwired)",
            monitorSource().contains("engine.evaluateCellular("),
        )
    }

    /**
     * Findings were originally only logged. Without persistence they cannot
     * reach the timeline or any export, and the field methodology — which
     * adjudicates Tier 1 flags against Tier 2 ground truth after the fact —
     * is impossible.
     */
    @Test
    fun `triggered findings are persisted, not just logged`() {
        val src = monitorSource()
        assertTrue(
            "CellularMonitor must persist findings via the repository; " +
                "in-memory state dies with the process",
            src.contains("logCellularTimelineEvents("),
        )
    }

    private fun screenSource(): String = repoFile(
        "app/src/main/java/com/androdr/ui/network/DnsMonitorScreen.kt",
        "src/main/java/com/androdr/ui/network/DnsMonitorScreen.kt",
    ).readText()

    /**
     * The Cellular tab rendered its "waiting for a radio update" paragraph
     * twice: CellularSummary already shows it when there is no snapshot, and a
     * separate empty-state item showed it again underneath.
     *
     * Pinned by call-site count rather than by rendering, because the duplicate
     * was structural — two independent branches choosing to draw the same
     * thing — and that is visible in the source.
     */
    @Test
    fun `the waiting text has exactly one call site`() {
        // Exclude the declaration ("fun CellularWaitingText()"); count invocations.
        val calls = Regex("""(?<!fun )CellularWaitingText\(\)""")
            .findAll(screenSource()).count()
        assertTrue(
            "CellularWaitingText() should be invoked once (found $calls). Two call sites " +
                "print the same paragraph twice when there is no data.",
            calls == 1,
        )
    }

    /**
     * onCellInfoChanged fires on CHANGE, so a stationary device may not produce
     * a callback for a long time and the view sits on "waiting for a radio
     * update" — indistinguishable from a monitor that is not working. Some
     * devices deliver an immediate callback on registration and some do not, so
     * startup must not depend on that.
     */
    @Test
    fun `the monitor reads current cell state at startup`() {
        val src = monitorSource()
        // Must be CALLED, not merely declared. An earlier version of this test
        // matched the `fun primeFromCurrentState(` declaration, so deleting the
        // call site still passed — caught by mutation-testing the gate.
        val callSites = Regex("""(?<!fun )primeFromCurrentState\(""")
            .findAll(src).count()
        assertTrue(
            "CellularMonitor.start() must CALL primeFromCurrentState (found " +
                "$callSites call sites), or the UI stays empty until the serving " +
                "cell happens to change",
            callSites >= 1,
        )
        assertTrue(
            "priming must actually read cell info",
            Regex("""primeFromCurrentState[\s\S]{0,600}?allCellInfo""").containsMatchIn(src),
        )
    }
}
