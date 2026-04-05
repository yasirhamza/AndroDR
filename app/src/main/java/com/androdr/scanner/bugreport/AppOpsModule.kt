package com.androdr.scanner.bugreport

import android.util.Log
import com.androdr.data.model.TimelineEvent
import com.androdr.ioc.IndicatorResolver
import java.text.SimpleDateFormat
import java.util.Locale
import javax.inject.Inject
import javax.inject.Singleton

@Singleton
class AppOpsModule @Inject constructor() : BugreportModule {

    override val targetSections: List<String> = listOf("appops")

    private val dangerousOps = setOf(
        "CAMERA", "RECORD_AUDIO", "READ_SMS", "RECEIVE_SMS", "SEND_SMS",
        "READ_CONTACTS", "READ_CALL_LOG", "ACCESS_FINE_LOCATION",
        "READ_EXTERNAL_STORAGE", "REQUEST_INSTALL_PACKAGES"
    )

    // Line-level patterns — only applied to individual lines, not the full section
    private val uidLineRegex = Regex("""^\s*Uid\s+(u\d+(?:ai|[ais])\d+|\d+):""")
    private val packageLineRegex = Regex("""^\s+Package\s+(\S+):""")
    private val opLineRegex = Regex("""^\s+(\w+)\s+\(\w+\):""")
    private val accessLineRegex = Regex(
        """Access:\s+\[\S+]\s+(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}(?:\.\d+)?)"""
    )
    private val rejectLineRegex = Regex(
        """Reject:\s+\[\S+]\s+(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}(?:\.\d+)?)"""
    )

    /**
     * Parses the appops section line-by-line using a state machine.
     * Avoids holding the full section + regex copies in memory (previous approach OOM'd on 4MB+).
     */
    // Line-by-line state machine with emit-on-transition logic — the method is a single
    // sequential pass through UID→Package→Op→Access/Reject states; splitting would fragment
    // the state transitions across functions without reducing real complexity.
    @Suppress("LongMethod")
    override suspend fun analyze(sectionText: String, iocResolver: IndicatorResolver): ModuleResult {
        val telemetry = mutableListOf<Map<String, Any?>>()
        val timeline = mutableListOf<TimelineEvent>()

        var currentUid = -1
        var isSystemUid = true
        var currentPackage: String? = null
        var currentOp: String? = null
        var isDangerousOp = false
        var lastAccessTime: String? = null
        var lastRejectTime: String? = null

        fun emitCurrentOp() {
            val pkg = currentPackage ?: return
            val op = currentOp ?: return
            if (!isDangerousOp) return

            val normalizedOp = "android:${op.lowercase()}"
            telemetry.add(mapOf(
                "package_name" to pkg,
                "operation" to normalizedOp,
                "last_access_time" to (lastAccessTime ?: ""),
                "last_reject_time" to (lastRejectTime ?: ""),
                "access_count" to 1,
                "is_system_app" to isSystemUid
            ))

            if (!isSystemUid) {
                val accessTimestamp = lastAccessTime?.let { parseTimestamp(it) } ?: -1L
                timeline.add(TimelineEvent(
                    timestamp = accessTimestamp,
                    source = "appops",
                    category = "permission_use",
                    description = "$pkg used $op" +
                        (lastAccessTime?.let { " at $it" } ?: ""),
                    severity = if (op == "REQUEST_INSTALL_PACKAGES") "HIGH" else "INFO"
                ))
            }
        }

        var lineCount = 0
        sectionText.lineSequence().forEach { line ->
            lineCount++

            // Check for UID line
            val uidMatch = uidLineRegex.find(line)
            if (uidMatch != null) {
                emitCurrentOp()
                currentUid = parseUidString(uidMatch.groupValues[1])
                isSystemUid = currentUid < FIRST_APPLICATION_UID
                currentPackage = null
                currentOp = null
                isDangerousOp = false
                lastAccessTime = null
                lastRejectTime = null
                return@forEach
            }

            // Check for Package line
            val pkgMatch = packageLineRegex.find(line)
            if (pkgMatch != null) {
                emitCurrentOp()
                currentPackage = pkgMatch.groupValues[1]
                currentOp = null
                isDangerousOp = false
                lastAccessTime = null
                lastRejectTime = null
                return@forEach
            }

            // Check for Op line (only if we have a package)
            if (currentPackage != null) {
                val opMatch = opLineRegex.find(line)
                if (opMatch != null) {
                    emitCurrentOp()
                    currentOp = opMatch.groupValues[1]
                    isDangerousOp = currentOp in dangerousOps
                    lastAccessTime = null
                    lastRejectTime = null
                    return@forEach
                }
            }

            // Check for Access/Reject lines (only if we're tracking a dangerous op)
            if (isDangerousOp) {
                if (lastAccessTime == null && line.contains("Access:")) {
                    lastAccessTime = accessLineRegex.find(line)?.groupValues?.get(1)
                }
                if (lastRejectTime == null && line.contains("Reject:")) {
                    lastRejectTime = rejectLineRegex.find(line)?.groupValues?.get(1)
                }
            }
        }
        // Emit the last op if any
        emitCurrentOp()

        Log.d(TAG, "AppOps: $lineCount lines, ${telemetry.size} telemetry, " +
            "${timeline.size} timeline events")

        return ModuleResult(
            telemetry = telemetry,
            telemetryService = "appops_audit",
            timeline = timeline
        )
    }

    /**
     * Parses AOSP UID strings to numeric UIDs. Mirrors [android.os.UserHandle.formatUid] inverse.
     * Formats: "1000" (numeric), "u0a398" (app), "u0i5" (isolated),
     *          "u0ai3" (app-zygote isolated), "u0s1000" (shared/system).
     */
    @Suppress("ReturnCount") // Early returns for invalid input keep the happy path readable
    private fun parseUidString(raw: String): Int {
        raw.toIntOrNull()?.let { return it }
        val m = uidStringRegex.find(raw) ?: return UNKNOWN_UID
        val userId = m.groupValues[1].toIntOrNull() ?: return UNKNOWN_UID
        val type = m.groupValues[2]        // "a", "i", "ai", or "s"
        val offset = m.groupValues[3].toIntOrNull() ?: return UNKNOWN_UID
        val appId = when (type) {
            "a"  -> FIRST_APPLICATION_UID + offset
            "i"  -> FIRST_ISOLATED_UID + offset
            "ai" -> FIRST_APP_ZYGOTE_ISOLATED_UID + offset
            "s"  -> offset                 // shared/system — appId is literal
            else -> return UNKNOWN_UID
        }
        return userId * PER_USER_RANGE + appId
    }

    private val uidStringRegex = Regex("""u(\d+)(ai|[ais])(\d+)""")

    /** Parses "2026-03-27 14:30:00" or "2026-03-27 14:30:00.692" to epoch millis. */
    @Suppress("TooGenericExceptionCaught")
    private fun parseTimestamp(ts: String): Long = try {
        val normalized = ts.substringBefore(".")
        val base = SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.US).parse(normalized)?.time
        when {
            base == null || base < 0 -> -1L
            ts.contains(".") -> {
                val frac = ts.substringAfter(".")
                base + frac.take(3).padEnd(3, '0').toLong()
            }
            else -> base
        }
    } catch (e: Exception) {
        Log.w(TAG, "Failed to parse timestamp: $ts", e)
        -1L
    }

    // AOSP constants from android.os.Process / android.os.UserHandle
    private companion object {
        private const val TAG = "AppOpsModule"
        private const val PER_USER_RANGE = 100000
        private const val FIRST_APPLICATION_UID = 10000
        private const val FIRST_ISOLATED_UID = 90000
        private const val FIRST_APP_ZYGOTE_ISOLATED_UID = 89000
        private const val UNKNOWN_UID = 99999
    }
}
