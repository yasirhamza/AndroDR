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

    private val packageLineRegex = Regex("""^\s+Package\s+(\S+):""", RegexOption.MULTILINE)
    private val opLineRegex = Regex("""^\s+(\w+)\s+\((\w+)\):""", RegexOption.MULTILINE)
    private val accessLineRegex = Regex(
        """Access:\s+\[\S+]\s+(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})"""
    )
    private val rejectLineRegex = Regex(
        """Reject:\s+\[\S+]\s+(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})"""
    )
    private val uidLineRegex = Regex("""^\s*Uid\s+(\d+):""", RegexOption.MULTILINE)

    // Multi-step analysis with UID splitting, package iteration, op checking, and timeline
    // generation — splitting into sub-functions would fragment tightly coupled analysis logic.
    @Suppress("LongMethod")
    override suspend fun analyze(sectionText: String, iocResolver: IndicatorResolver): ModuleResult {
        val telemetry = mutableListOf<Map<String, Any?>>()
        val timeline = mutableListOf<TimelineEvent>()

        val uidBlocks = splitByUid(sectionText)

        for ((uid, block) in uidBlocks) {
            val isSystemUid = uid < 10000

            packageLineRegex.findAll(block).forEach pkgLoop@{ pkgMatch ->
                val packageName = pkgMatch.groupValues[1]
                val pkgStart = pkgMatch.range.last
                val pkgEnd = findNextPackageOrEnd(block, pkgStart)
                val pkgBlock = block.substring(pkgStart, pkgEnd)

                opLineRegex.findAll(pkgBlock).forEach { opMatch ->
                    val opName = opMatch.groupValues[1]

                    if (opName in dangerousOps) {
                        val opStart = opMatch.range.last
                        val nextOp = opLineRegex.find(pkgBlock, opStart + 1)
                        val opEnd = nextOp?.range?.first ?: pkgBlock.length
                        val opBlock = pkgBlock.substring(opStart, opEnd)

                        val accessMatch = accessLineRegex.find(opBlock)
                        val rejectMatch = rejectLineRegex.find(opBlock)

                        // Normalize to "android:<op>" format to match SIGMA rule conventions
                        val normalizedOp = "android:${opName.lowercase()}"
                        telemetry.add(mapOf(
                            "package_name" to packageName,
                            "operation" to normalizedOp,
                            "last_access_time" to (accessMatch?.groupValues?.get(1) ?: ""),
                            "last_reject_time" to (rejectMatch?.groupValues?.get(1) ?: ""),
                            "access_count" to 1,
                            "is_system_app" to isSystemUid
                        ))

                        // Parse access timestamp to epoch millis
                        val accessTimestamp = accessMatch?.groupValues?.get(1)?.let {
                            parseTimestamp(it)
                        } ?: -1L

                        // Only add non-system apps to the timeline — system app ops are noise
                        if (!isSystemUid) {
                            timeline.add(TimelineEvent(
                                timestamp = accessTimestamp,
                                source = "appops",
                                category = "permission_use",
                                description = "$packageName used $opName" +
                                    (accessMatch?.let { " at ${it.groupValues[1]}" } ?: ""),
                                severity = if (opName == "REQUEST_INSTALL_PACKAGES") "HIGH" else "INFO"
                            ))
                        }
                    }
                }
            }
        }

        return ModuleResult(
            telemetry = telemetry,
            telemetryService = "appops_audit",
            timeline = timeline
        )
    }

    private fun splitByUid(text: String): List<Pair<Int, String>> {
        val matches = uidLineRegex.findAll(text).toList()
        if (matches.isEmpty()) return emptyList()

        return matches.mapIndexed { index, match ->
            val uid = match.groupValues[1].toIntOrNull() ?: 99999
            val start = match.range.first
            val end = if (index + 1 < matches.size) matches[index + 1].range.first else text.length
            uid to text.substring(start, end)
        }
    }

    private fun findNextPackageOrEnd(block: String, fromIndex: Int): Int {
        val next = packageLineRegex.find(block, fromIndex + 1)
        return next?.range?.first ?: block.length
    }

    /** Parses "2026-03-27 14:30:00" to epoch millis. Returns -1 on failure. */
    @Suppress("TooGenericExceptionCaught")
    private fun parseTimestamp(ts: String): Long = try {
        SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.US).parse(ts)?.time ?: -1L
    } catch (e: Exception) {
        Log.w("AppOpsModule", "Failed to parse timestamp: $ts")
        -1L
    }
}
