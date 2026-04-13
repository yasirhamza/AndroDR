package com.androdr.scanner.bugreport

import com.androdr.data.model.TelemetrySource
import com.androdr.data.model.TombstoneEvent
import java.text.SimpleDateFormat
import java.util.Locale
import java.util.TimeZone
import javax.inject.Inject
import javax.inject.Singleton

/**
 * Parses the tombstone section of an Android bugreport into [TombstoneEvent]
 * telemetry. A tombstone is a process crash record; multiple crashes for the
 * same package within a time window indicate potential exploit-then-crash
 * behavior (evaluated by plan 6's crash-loop rule).
 *
 * Tombstone format (typical):
 *   Timestamp: 2020-02-14 09:23:45+0000
 *   pid: 1234, tid: 1234, name: com.example.app  >>> com.example.app <<<
 *   signal 11 (SIGSEGV), code 1 (SEGV_MAPERR), fault addr 0x1234
 *
 * Abort messages may appear for non-signal tombstones via an `Abort message:` line.
 *
 * No consumers exist in plan 5 — plan 6 wires this into BugReportAnalyzer
 * alongside the SIGMA crash-loop rule.
 */
@Singleton
class TombstoneParser @Inject constructor() {

    private val timestampFormat = SimpleDateFormat("yyyy-MM-dd HH:mm:ssZ", Locale.US).apply {
        timeZone = TimeZone.getTimeZone("UTC")
    }

    /**
     * Parses tombstone records from a sequence of bugreport lines. Each
     * record begins with a `Timestamp:` line and contains subsequent fields
     * until the next Timestamp or section boundary.
     */
    @Suppress("TooGenericExceptionCaught")
    fun parse(lines: Sequence<String>, capturedAt: Long): List<TombstoneEvent> {
        val events = mutableListOf<TombstoneEvent>()
        var currentTimestamp: Long? = null
        var currentProcessName: String? = null
        var currentPackageName: String? = null
        var currentSignal: Int? = null
        var currentAbort: String? = null

        fun flush() {
            val ts = currentTimestamp ?: return
            val process = currentProcessName ?: return
            events += TombstoneEvent(
                processName = process,
                packageName = currentPackageName,
                signalNumber = currentSignal,
                abortMessage = currentAbort,
                crashTimestamp = ts,
                source = TelemetrySource.BUGREPORT_IMPORT,
                capturedAt = capturedAt,
            )
            currentTimestamp = null
            currentProcessName = null
            currentPackageName = null
            currentSignal = null
            currentAbort = null
        }

        for (line in lines) {
            when {
                line.startsWith("Timestamp:") -> {
                    flush()
                    val tsStr = line.removePrefix("Timestamp:").trim()
                    currentTimestamp = try {
                        timestampFormat.parse(tsStr)?.time
                    } catch (_: Exception) {
                        null
                    }
                }
                line.startsWith("pid:") -> {
                    val nameMarker = ">>>"
                    if (line.contains(nameMarker)) {
                        currentPackageName = line.substringAfter(nameMarker).substringBefore("<<<").trim()
                    }
                    val nameField = Regex("name: ([^\\s]+)").find(line)
                    currentProcessName = nameField?.groupValues?.get(1)
                }
                line.startsWith("signal ") -> {
                    val signalMatch = Regex("^signal (\\d+)").find(line)
                    currentSignal = signalMatch?.groupValues?.get(1)?.toIntOrNull()
                }
                line.startsWith("Abort message:") -> {
                    currentAbort = line.removePrefix("Abort message:").trim().trim('\'', '"')
                }
            }
        }
        flush()
        return events
    }
}
