package com.androdr.scanner.bugreport

import com.androdr.data.model.TimelineEvent
import com.androdr.ioc.IndicatorResolver
import com.androdr.scanner.BugReportAnalyzer.BugReportFinding
import java.io.InputStream

data class ModuleResult(
    val telemetry: List<Map<String, Any?>> = emptyList(),
    val telemetryService: String = "",
    val legacyFindings: List<BugReportFinding> = emptyList(),
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
