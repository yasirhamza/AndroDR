package com.androdr.scanner.bugreport

import com.androdr.ioc.IocResolver
import com.androdr.scanner.BugReportAnalyzer.BugReportFinding
import javax.inject.Inject
import javax.inject.Singleton

@Singleton
class AccessibilityModule @Inject constructor() : BugreportModule {

    override val targetSections: List<String> = listOf("accessibility")

    private val systemServicePrefixes = listOf(
        "com.google.android.marvin.talkback",
        "com.google.android.accessibility",
        "com.android.talkback",
        "com.samsung.accessibility",
        "com.samsung.android.accessibility",
        "com.android.switchaccess",
        "com.google.android.apps.accessibility"
    )

    private val enabledServiceRegex = Regex(
        """^\s+([a-zA-Z][a-zA-Z0-9._]+)/(\.\w+)""",
        RegexOption.MULTILINE
    )

    override suspend fun analyze(sectionText: String, iocResolver: IocResolver): ModuleResult {
        val findings = mutableListOf<BugReportFinding>()

        enabledServiceRegex.findAll(sectionText).forEach { match ->
            val packageName = match.groupValues[1]
            val serviceName = match.groupValues[2]

            val iocHit = iocResolver.isKnownBadPackage(packageName)
            if (iocHit != null) {
                findings.add(BugReportFinding(
                    severity = iocHit.severity,
                    category = "AccessibilityAbuse",
                    description = "Known ${iocHit.category} package '$packageName' " +
                        "(${iocHit.name}) has an active accessibility service " +
                        "'$serviceName' — ${iocHit.description}"
                ))
                return@forEach
            }

            if (systemServicePrefixes.any { packageName.startsWith(it) }) {
                return@forEach
            }

            findings.add(BugReportFinding(
                severity = "HIGH",
                category = "AccessibilityAbuse",
                description = "Non-system accessibility service enabled: " +
                    "$packageName/$serviceName — accessibility services can read " +
                    "screen content and perform actions on behalf of the user"
            ))
        }

        return ModuleResult(findings = findings, timeline = emptyList())
    }
}
