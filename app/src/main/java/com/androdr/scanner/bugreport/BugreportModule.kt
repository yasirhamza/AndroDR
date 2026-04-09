package com.androdr.scanner.bugreport

import com.androdr.data.model.TimelineEvent
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

    /** Analyze a dumpsys section. Override for section-targeted modules. */
    suspend fun analyze(
        sectionText: String,
        iocResolver: IndicatorResolver
    ): ModuleResult = ModuleResult()

    /** Analyze raw ZIP entries. Override for modules with targetSections == null. */
    suspend fun analyzeRaw(
        entries: Sequence<Pair<String, InputStream>>,
        iocResolver: IndicatorResolver
    ): ModuleResult = ModuleResult()
}
