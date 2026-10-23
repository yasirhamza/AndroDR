package com.androdr.scanner.bugreport

import com.androdr.data.model.PlatformCompatChange
import com.androdr.data.model.TelemetrySource
import com.androdr.ioc.IndicatorResolver
import javax.inject.Inject
import javax.inject.Singleton

/**
 * Parses `dumpsys platform_compat` for compatibility override entries.
 * Apps with DOWNSCALED (ChangeId 168419799) overrides may be using
 * compatibility workarounds as an anti-analysis technique.
 */
@Singleton
class PlatformCompatModule internal constructor(private val maxRecords: Int) : BugreportModule {

    @Inject constructor() : this(BugreportModule.MAX_RECORDS_PER_MODULE)

    override val targetSections: List<String> = listOf("platform_compat")

    private val enabledRegex = Regex("""enabled=(true|false)""")

    private val compatOverrideRegex = Regex(
        """^\s+(\d+),\s*\{(.*packageName=([a-zA-Z][a-zA-Z0-9._]+).*)$""",
        RegexOption.MULTILINE
    )

    override suspend fun analyze(
        sectionText: String,
        iocResolver: IndicatorResolver,
        device: com.androdr.ioc.DeviceIdentity,
    ): ModuleResult {
        val changes = mutableListOf<PlatformCompatChange>()
        val now = System.currentTimeMillis()
        var truncatedAt: Int? = null

        val compatStart = sectionText.indexOf("Compat overrides:")
            .takeIf { it >= 0 }
            ?: sectionText.indexOf("ChangeId").takeIf { it >= 0 }
            ?: return ModuleResult()

        // Emit every compat override observed. SIGMA rules (plan 6) decide
        // which ChangeIds matter (e.g. DOWNSCALED=168419799 for anti-analysis).
        // No hardcoded ChangeId filter in this module.
        for (match in compatOverrideRegex.findAll(sectionText, compatStart)) {
            if (changes.size >= maxRecords) {
                truncatedAt = maxRecords
                break
            }
            // null when the line does not state `enabled=`; never guessed.
            val enabled = enabledRegex.find(match.groupValues[2])?.groupValues?.get(1)?.toBooleanStrict()
            changes.add(PlatformCompatChange(
                changeId = match.groupValues[1],
                packageName = match.groupValues[3],
                enabled = enabled,
                source = TelemetrySource.BUGREPORT_IMPORT,
                capturedAt = now,
            ))
        }

        return ModuleResult(
            typed = TypedTelemetry(platformCompatChanges = changes),
            truncatedAt = truncatedAt,
        )
    }
}
