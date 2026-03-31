package com.androdr.scanner.bugreport

import com.androdr.ioc.IndicatorResolver
import javax.inject.Inject
import javax.inject.Singleton

@Singleton
class AccessibilityModule @Inject constructor() : BugreportModule {

    override val targetSections: List<String> = listOf("accessibility")

    private val systemPackagePrefixes = listOf(
        "com.google.android.marvin.talkback",
        "com.google.android.accessibility",
        "com.android.talkback",
        "com.samsung.accessibility",
        "com.samsung.android.accessibility",
        "com.android.switchaccess",
        "com.google.android.apps.accessibility"
    )

    private val enabledServiceRegex = Regex(
        """^\s+([a-zA-Z][a-zA-Z0-9._]+)/([.\w]+)""",
        RegexOption.MULTILINE
    )

    override suspend fun analyze(sectionText: String, iocResolver: IndicatorResolver): ModuleResult {
        val telemetry = mutableListOf<Map<String, Any?>>()

        enabledServiceRegex.findAll(sectionText).forEach { match ->
            val packageName = match.groupValues[1]
            val serviceName = match.groupValues[2]
            val isSystemApp = systemPackagePrefixes.any { packageName.startsWith(it) }

            telemetry.add(mapOf(
                "package_name" to packageName,
                "service_name" to serviceName,
                "is_system_app" to isSystemApp,
                "is_enabled" to true
            ))
        }

        return ModuleResult(
            telemetry = telemetry,
            telemetryService = "accessibility_audit"
        )
    }
}
