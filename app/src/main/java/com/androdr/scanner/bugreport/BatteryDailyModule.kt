package com.androdr.scanner.bugreport

import com.androdr.data.model.TimelineEvent
import com.androdr.ioc.IndicatorResolver
import javax.inject.Inject
import javax.inject.Singleton

@Singleton
class BatteryDailyModule @Inject constructor() : BugreportModule {

    override val targetSections: List<String> = listOf("batterystats")

    private val packageChangeRegex = Regex(
        """^\s+([+-])pkg=(\S+)\s+vers=(\d+)""",
        RegexOption.MULTILINE
    )

    @Suppress("LongMethod") // Multi-phase analysis: parse changes, detect downgrades, IOC check, dedup
    override suspend fun analyze(sectionText: String, iocResolver: IndicatorResolver): ModuleResult {
        val telemetry = mutableListOf<Map<String, Any?>>()
        val timeline = mutableListOf<TimelineEvent>()

        // Track version history per package to detect downgrades
        val versionHistory = mutableMapOf<String, MutableList<Long>>()

        // Find all Package changes: blocks
        var searchFrom = 0
        while (true) {
            val blockStart = sectionText.indexOf("Package changes:", searchFrom)
            if (blockStart < 0) break
            searchFrom = blockStart + 16

            // Find end of this block (next section or end)
            val blockEnd = findBlockEnd(sectionText, blockStart + 16)
            val block = sectionText.substring(blockStart, blockEnd)

            packageChangeRegex.findAll(block).forEach { match ->
                val sign = match.groupValues[1]
                val packageName = match.groupValues[2]
                val version = match.groupValues[3].toLongOrNull() ?: 0

                versionHistory.getOrPut(packageName) { mutableListOf() }.add(version)

                when (sign) {
                    "-" -> {
                        // Uninstall
                        timeline.add(TimelineEvent(
                            timestamp = -1,
                            source = "battery_daily",
                            category = "package_uninstall",
                            description = "App uninstalled: $packageName",
                            severity = "INFO"
                        ))

                        // Check IOC
                        val iocHit = iocResolver.isKnownBadPackage(packageName)
                        if (iocHit != null) {
                            timeline.add(TimelineEvent(
                                timestamp = -1,
                                source = "battery_daily",
                                category = "package_uninstall",
                                description = "Known ${iocHit.category} package '$packageName' " +
                                    "(${iocHit.name}) was uninstalled — possible anti-forensics",
                                // Severity is assigned by SIGMA rules downstream (plan 6), not here.
                                severity = "INFO"
                            ))
                        }
                    }
                    else -> {
                        // Install/update — check for IOC match
                        val iocHit = iocResolver.isKnownBadPackage(packageName)
                        if (iocHit != null) {
                            telemetry.add(mapOf(
                                "package_name" to packageName,
                                "version" to version,
                                "event_type" to "package_install",
                                "is_system_app" to false,
                                "source" to "bugreport_import"
                            ))
                        }

                        timeline.add(TimelineEvent(
                            timestamp = -1,
                            source = "battery_daily",
                            category = "package_update",
                            description = "App updated: $packageName (version $version)",
                            severity = "INFO"
                        ))
                    }
                }
            }
        }

        // Detect version downgrades
        for ((pkg, versions) in versionHistory) {
            val nonZero = versions.filter { it > 0 }
            if (nonZero.size >= 2) {
                for (i in 1 until nonZero.size) {
                    if (nonZero[i] < nonZero[i - 1]) {
                        timeline.add(TimelineEvent(
                            timestamp = -1,
                            source = "battery_daily",
                            category = "package_downgrade",
                            description = "Version downgrade: $pkg " +
                                "(${nonZero[i - 1]} → ${nonZero[i]}) — " +
                                "possible exploit re-application",
                            // Severity is assigned by SIGMA rules downstream (plan 6), not here.
                                severity = "INFO"
                        ))
                    }
                }
            }
        }

        // Deduplicate timeline by description
        val dedupedTimeline = timeline.distinctBy { it.description }

        return ModuleResult(
            telemetry = telemetry,
            telemetryService = "battery_daily",
            timeline = dedupedTimeline
        )
    }

    private fun findBlockEnd(text: String, fromIndex: Int): Int {
        // Block ends at next "Daily stats:" or "Current start time:" or end of section
        val nextDaily = text.indexOf("Daily stats:", fromIndex)
        val nextCurrent = text.indexOf("Current start time:", fromIndex)
        val candidates = listOfNotNull(
            if (nextDaily != -1) nextDaily else null,
            if (nextCurrent != -1) nextCurrent else null,
            text.length
        )
        return candidates.min()
    }
}
