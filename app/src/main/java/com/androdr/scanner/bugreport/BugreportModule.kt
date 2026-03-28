package com.androdr.scanner.bugreport

import com.androdr.data.model.TimelineEvent
import com.androdr.ioc.IocResolver
import com.androdr.scanner.BugReportAnalyzer.BugReportFinding
import java.io.InputStream

data class ModuleResult(
    val findings: List<BugReportFinding>,
    val timeline: List<TimelineEvent>
)

interface BugreportModule {
    /** Dumpsys service names this module needs, or null for raw ZIP entries. */
    val targetSections: List<String>?

    /** Analyze a dumpsys section. Override for section-targeted modules. */
    suspend fun analyze(
        sectionText: String,
        iocResolver: IocResolver
    ): ModuleResult = ModuleResult(emptyList(), emptyList())

    /** Analyze raw ZIP entries. Override for modules with targetSections == null. */
    suspend fun analyzeRaw(
        entries: Sequence<Pair<String, InputStream>>,
        iocResolver: IocResolver
    ): ModuleResult = ModuleResult(emptyList(), emptyList())
}
