package com.androdr.scanner.bugreport

import com.androdr.data.model.TimelineEvent
import com.androdr.ioc.DeviceIdentity
import com.androdr.ioc.IndicatorResolver
import java.io.InputStream

/**
 * Result returned by a [BugreportModule]. Modules produce structured telemetry
 * (records matching SIGMA rule logsource fields) plus optional timeline events.
 *
 * Plan 6 deleted the `legacyFindings: List<BugReportFinding>` field — findings
 * are now produced exclusively by `SigmaRuleEngine` via telemetry evaluation.
 */
data class ModuleResult(
    val telemetry: List<Map<String, Any?>> = emptyList(),
    val telemetryService: String = "",
    val timeline: List<TimelineEvent> = emptyList()
)

interface BugreportModule {
    /** Dumpsys service names this module needs, or null for raw ZIP entries. */
    val targetSections: List<String>?

    /**
     * Analyze a dumpsys section. Override for section-targeted modules.
     *
     * [device] is the identity of the source device (extracted from the
     * bugreport's getprop section). Modules that classify packages via
     * [com.androdr.ioc.OemPrefixResolver] must pass this through so the
     * device-conditional allowlist (#90) evaluates against the source
     * device, not the device running AndroDR.
     */
    suspend fun analyze(
        sectionText: String,
        iocResolver: IndicatorResolver,
        device: DeviceIdentity = DeviceIdentity.UNKNOWN,
    ): ModuleResult = ModuleResult()

    /** Analyze raw ZIP entries. Override for modules with targetSections == null. */
    suspend fun analyzeRaw(
        entries: Sequence<Pair<String, InputStream>>,
        iocResolver: IndicatorResolver,
        device: DeviceIdentity = DeviceIdentity.UNKNOWN,
    ): ModuleResult = ModuleResult()
}
