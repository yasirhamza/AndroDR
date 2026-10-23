package com.androdr.scanner.bugreport

import com.androdr.ioc.DeviceIdentity
import com.androdr.ioc.IndicatorResolver
import java.io.InputStream

/**
 * Result returned by a [BugreportModule]. Modules produce structured telemetry (records matching
 * SIGMA rule logsource fields) and typed records; both are stored by the import session, and the
 * Timeline reads them from the store (spec §5.3: the hand-built timeline rows are retired).
 *
 * Plan 6 deleted the `legacyFindings: List<BugReportFinding>` field — findings
 * are now produced exclusively by `SigmaRuleEngine` via telemetry evaluation.
 */
data class ModuleResult(
    val telemetry: List<Map<String, Any?>> = emptyList(),
    val telemetryService: String = "",
    /** Typed records this module produced; the analyzer folds them into the telemetry bundle. */
    val typed: TypedTelemetry = TypedTelemetry(),
    /**
     * Set when the module hit [BugreportModule.MAX_RECORDS_PER_MODULE] (or its test override)
     * and stopped adding records: the bound that tripped. The analyzer reports it; never silent.
     */
    val truncatedAt: Int? = null,
)

interface BugreportModule {
    companion object {
        /** Per-module record bound; modules still materialise their lists in memory. */
        const val MAX_RECORDS_PER_MODULE = 200_000
    }

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

    /**
     * As [analyze], reading every dumpsys wall-clock time with the import's one [clock] (ruling
     * R27). The analyzer always calls this; modules that read wall-clock times override it, the
     * others inherit this delegation to the three-argument form.
     */
    suspend fun analyze(
        sectionText: String,
        iocResolver: IndicatorResolver,
        device: DeviceIdentity,
        clock: DumpsysClock,
    ): ModuleResult = analyze(sectionText, iocResolver, device)

    /** Analyze raw ZIP entries. Override for modules with targetSections == null. */
    suspend fun analyzeRaw(
        entries: Sequence<Pair<String, InputStream>>,
        iocResolver: IndicatorResolver,
        device: DeviceIdentity = DeviceIdentity.UNKNOWN,
    ): ModuleResult = ModuleResult()
}
