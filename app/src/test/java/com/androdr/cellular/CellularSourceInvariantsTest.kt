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
     * values. Whole-object interpolation (`"$snapshot"`, `"$id"`) is banned
     * with it: a data class's toString() prints every field.
     *
     * This is the shape-level backstop; [CellularMonitorLogPrivacyTest] is
     * the behavioural gate that sees what actually reaches the log.
     */
    @Test
    fun `the monitor never interpolates cell identity into a string`() {
        val src = monitorSource()
        listOf(
            "\${snapshot.tac}", "\${snapshot.ci}", "\${snapshot.pci}",
            "\${snapshot.mcc}", "\${snapshot.mnc}", "\${snapshot.additionalPlmns}",
            "\${snapshot.operatorAlphaLong}", "\${snapshot.operatorAlphaShort}",
            "\${snapshot.previousTac}",
            "\${snapshot.neighbors.pcis}", "\${snapshot.neighbors.earfcns}", "\${snapshot.neighbors}",
            "\${snapshot.sim.mcc}", "\${snapshot.sim.mnc}", "\${snapshot.sim.operatorName}", "\${snapshot.sim}",
            "\${snapshot}", "\${id}",
        ).forEach {
            assertFalse(
                "cell identity interpolated into a string in CellularMonitor: $it — " +
                    "log shape via present(), never values",
                src.contains(it),
            )
        }
        listOf(
            Regex("""${'$'}snapshot(?![\w.])"""),
            Regex("""${'$'}id(?![\w.])"""),
            Regex("""\$\{id\.(mcc|mnc|tac|ci|pci|operatorAlphaLong|operatorAlphaShort|additionalPlmns)}"""),
        ).forEach { pattern ->
            assertFalse(
                "a whole identity object, or one of its fields, interpolated into a string in " +
                    "CellularMonitor (${pattern.pattern}) — its toString() prints the tuple",
                pattern.containsMatchIn(src),
            )
        }
    }

    private fun cellularSources(): List<File> =
        listOf("app/src/main/java/com/androdr/cellular", "src/main/java/com/androdr/cellular")
            .map(::File).firstOrNull { it.isDirectory }
            ?.listFiles { f -> f.extension == "kt" }?.toList()
            ?: error("cellular source directory not found")

    /**
     * The movement reader borrows passive location fixes. The coordinates
     * exist to be reduced to a distance and an age; a coordinate in a log
     * line, a timeline row or a field map would be the location trail the
     * cell-identity redaction exists to prevent — at higher resolution.
     *
     * Two shapes are banned across the whole package: interpolating or
     * appending `latitude`/`longitude`, and any `Log.` call whose line
     * mentions them.
     */
    @Test
    fun `coordinates are never logged, interpolated or emitted`() {
        val banned = listOf(
            Regex("""\$\{[^}]*(latitude|longitude)[^}]*}"""),
            Regex("""\$(latitude|longitude)\b"""),
            Regex("""append\([^)]*(latitude|longitude)"""),
            Regex("""Log\.[a-z]\([^\n]*(latitude|longitude)"""),
            Regex("""to\s+[a-zA-Z.]*(latitude|longitude)"""),
        )
        cellularSources().forEach { file ->
            val src = file.readText()
            banned.forEach { pattern ->
                assertFalse(
                    "${file.name}: a coordinate reaches a string, log or field map (${pattern.pattern}); " +
                        "only the derived distance and fix age may leave LocationTrail",
                    pattern.containsMatchIn(src),
                )
            }
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
        // Any invocation, not just empty parens — the composable takes a status
        // argument now, and pinning the exact call shape made this brittle.
        val calls = Regex("""(?<!fun )CellularWaitingText\(""")
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

    /**
     * Six conditions leave the monitor inert. Each previously reported only to
     * logcat, so all six rendered as the same empty "waiting" card — which made
     * the difference between "the VPN is off" and "the platform refused the
     * read" invisible on any device that cannot be attached to a debugger.
     *
     * Every inert path must set a distinct status.
     */
    @Test
    fun `every inert path reports a distinct status`() {
        val src = monitorSource()
        listOf(
            "Status.UNSUPPORTED_API",
            "Status.MISSING_PERMISSION",
            "Status.NO_TELEPHONY",
            "Status.AWAITING_FIRST_UPDATE",
            "Status.READ_REFUSED",
        ).forEach {
            assertTrue(
                "CellularMonitor must report $it — otherwise this failure mode is " +
                    "indistinguishable from every other empty-card cause",
                src.contains(it),
            )
        }
    }

    /**
     * The UI must render the reason, not a single generic sentence. A status
     * the monitor sets but the screen never reads is no better than a log line.
     */
    @Test
    fun `the cellular card renders every status`() {
        val screen = screenSource()
        listOf(
            "Status.NOT_STARTED",
            "Status.UNSUPPORTED_API",
            "Status.MISSING_PERMISSION",
            "Status.NO_TELEPHONY",
            "Status.READ_REFUSED",
            "Status.AWAITING_FIRST_UPDATE",
        ).forEach {
            assertTrue("the card must handle $it", screen.contains(it))
        }
    }

    /**
     * The app declared location in the manifest but never asked for it at
     * runtime, so on any normal install the cellular monitor was permanently
     * inert. It only ever appeared to work on a development device where the
     * grant had been forced with `adb shell pm grant` — which is exactly how
     * the gap survived: every test device had been primed by hand.
     */
    @Test
    fun `the app requests location at runtime`() {
        val screen = screenSource()
        assertTrue(
            "the cellular UI must request location at runtime; a manifest " +
                "declaration alone never prompts the user",
            screen.contains("RequestMultiplePermissions()"),
        )
        // WHICH permissions is deliberately NOT asserted here. This gate broke
        // when the inline array was replaced by CellularMonitor.REQUESTED_
        // PERMISSIONS — a refactor that improved the code. Literal source
        // matching is the wrong tool for that question;
        // CellularPermissionContractTest answers it by reading the real arrays,
        // which cannot drift from what the app actually requests.
        assertTrue(
            "must offer the user a way to trigger the request",
            screen.contains("Grant location permission"),
        )
    }

    /**
     * The monitor checks permission once, when it starts. Granting location
     * afterwards leaves it inert until something re-arms it, so the grant flow
     * must poke the running service rather than silently doing nothing.
     */
    @Test
    fun `granting location re-arms the running monitor`() {
        assertTrue(
            "the grant callback must re-arm the monitor via ACTION_RETRY_CELLULAR",
            screenSource().contains("ACTION_RETRY_CELLULAR"),
        )
        assertTrue(
            "the service must handle the re-arm action",
            repoFile(
                "app/src/main/java/com/androdr/network/DnsVpnService.kt",
                "src/main/java/com/androdr/network/DnsVpnService.kt",
            ).readText().contains("ACTION_RETRY_CELLULAR ->"),
        )
    }

    /**
     * A started service that never calls startForeground() is killed by the
     * platform after a few seconds — and on Android 12+ throws in the
     * process. The retry action is sent from the UI whenever the user grants
     * location, including when the VPN is OFF; with no monitor to re-arm, the
     * service must stop itself rather than sit started-but-not-foreground.
     */
    @Test
    fun `the retry action stops the service when there is no monitor to re-arm`() {
        val src = repoFile(
            "app/src/main/java/com/androdr/network/DnsVpnService.kt",
            "src/main/java/com/androdr/network/DnsVpnService.kt",
        ).readText()
        val branch = Regex("""ACTION_RETRY_CELLULAR\s*->[\s\S]*?(?=\n\s*else\s*->)""")
            .find(src)?.value
        assertTrue("ACTION_RETRY_CELLULAR branch not found in onStartCommand", branch != null)
        assertTrue(
            "the retry branch must stopSelf(startId) when cellularMonitor is null; " +
                "otherwise the service lingers started-but-not-foreground",
            branch!!.contains("stopSelf(startId)"),
        )
    }
}
