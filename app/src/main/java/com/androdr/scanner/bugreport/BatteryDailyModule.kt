package com.androdr.scanner.bugreport

import com.androdr.data.model.BatteryDailyEvent
import com.androdr.data.model.CivilDay
import com.androdr.data.model.TelemetrySource
import com.androdr.ioc.IndicatorResolver
import java.time.LocalDate
import javax.inject.Inject
import javax.inject.Singleton

@Singleton
class BatteryDailyModule internal constructor(private val maxRecords: Int) : BugreportModule {

    @Inject constructor() : this(BugreportModule.MAX_RECORDS_PER_MODULE)

    override val targetSections: List<String> = listOf("batterystats")

    private val packageChangeRegex = Regex(
        """^\s+([+-])pkg=(\S+)\s+vers=(\d+)""",
        RegexOption.MULTILINE
    )

    // "Current start time: 2026-03-28-01-00-01" heads a daily-stats entry.
    private val startTimeRegex =
        Regex("""Current start time:\s*(\d{4})-(\d{2})-(\d{2})-\d{2}-\d{2}-\d{2}""")

    /** One parsed `+pkg=`/`-pkg=` entry, before it becomes a typed record. */
    private data class Change(
        val packageName: String,
        val version: Long,
        val uninstall: Boolean,
        val dayIndex: Int,
        val day: Long?,
    )

    override suspend fun analyze(
        sectionText: String,
        iocResolver: IndicatorResolver,
        device: com.androdr.ioc.DeviceIdentity,
    ): ModuleResult = analyze(sectionText, iocResolver, device, DumpsysClock.ASSUMED_UTC)

    /**
     * Battery days are calendar dates: each is stored as the report's printed date
     * ([CivilDay], ruling R32), so [clock] (the import's instant base, R27) does not apply to them.
     */
    override suspend fun analyze(
        sectionText: String,
        iocResolver: IndicatorResolver,
        device: com.androdr.ioc.DeviceIdentity,
        clock: DumpsysClock,
    ): ModuleResult {
        val events = mutableListOf<BatteryDailyEvent>()
        val now = System.currentTimeMillis()
        var truncatedAt: Int? = null

        fun add(c: Change, eventType: String, description: String): Boolean {
            if (events.size >= maxRecords) {
                truncatedAt = maxRecords
                return false
            }
            events.add(BatteryDailyEvent(
                dayIndex = c.dayIndex,
                eventType = eventType,
                packageName = c.packageName,
                description = description,
                version = c.version,
                timestamp = c.day,
                timestampPrecision = c.day?.let { DAY_PRECISION },
                source = TelemetrySource.BUGREPORT_IMPORT,
                capturedAt = now,
            ))
            return true
        }

        val changes = parseChanges(sectionText)
        val versionHistory = mutableMapOf<String, MutableList<Change>>()
        for (c in changes) {
            versionHistory.getOrPut(c.packageName) { mutableListOf() }.add(c)
            val ok = if (c.uninstall) {
                add(c, "package_uninstall", "App uninstalled: ${c.packageName}")
            } else {
                add(c, "package_update", "App updated: ${c.packageName} (version ${c.version})")
            }
            if (!ok) break
        }

        // Detect version downgrades
        downgrades@ for ((pkg, history) in versionHistory) {
            val nonZero = history.filter { it.version > 0 }
            for (i in 1 until nonZero.size) {
                if (nonZero[i].version < nonZero[i - 1].version) {
                    val description = "Version downgrade: $pkg " +
                        "(${nonZero[i - 1].version} → ${nonZero[i].version}) — " +
                        "possible exploit re-application"
                    if (!add(nonZero[i], "package_downgrade", description)) break@downgrades
                }
            }
        }

        return ModuleResult(
            typed = TypedTelemetry(batteryDailyEvents = events),
            truncatedAt = truncatedAt,
        )
    }

    private fun parseChanges(sectionText: String): List<Change> {
        val starts = startTimeRegex.findAll(sectionText).toList()
        val firstDay = starts.firstOrNull()?.let { dayMillis(it) }
        val out = mutableListOf<Change>()
        var searchFrom = 0
        var dayIndex = 0
        while (true) {
            val blockStart = sectionText.indexOf("Package changes:", searchFrom)
            if (blockStart < 0) break
            searchFrom = blockStart + PACKAGE_CHANGES_LEN

            // Date of this block: nearest "Current start time" above it, else the section's first.
            val day = starts.lastOrNull { it.range.first < blockStart }?.let { dayMillis(it) } ?: firstDay
            val block = sectionText.substring(blockStart, findBlockEnd(sectionText, searchFrom))
            packageChangeRegex.findAll(block).forEach { match ->
                out.add(Change(
                    packageName = match.groupValues[2],
                    version = match.groupValues[3].toLongOrNull() ?: 0,
                    uninstall = match.groupValues[1] == "-",
                    dayIndex = dayIndex,
                    day = day,
                ))
            }
            dayIndex++
        }
        return out
    }

    /** The printed date of a "Current start time" line, as its stored day-precision time (R32). */
    private fun dayMillis(m: MatchResult): Long? = runCatching {
        CivilDay.epochMs(LocalDate.of(m.groupValues[1].toInt(), m.groupValues[2].toInt(), m.groupValues[3].toInt()))
    }.getOrNull()

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

    private companion object {
        const val DAY_PRECISION = "day"
        const val PACKAGE_CHANGES_LEN = 16
    }
}
