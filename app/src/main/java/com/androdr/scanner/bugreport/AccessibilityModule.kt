package com.androdr.scanner.bugreport

import com.androdr.ioc.IndicatorResolver
import com.androdr.ioc.OemPrefixResolver
import javax.inject.Inject
import javax.inject.Singleton

@Singleton
class AccessibilityModule @Inject constructor(
    private val oemPrefixResolver: OemPrefixResolver,
) : BugreportModule {

    override val targetSections: List<String> = listOf("accessibility")

    // Known-good accessibility service allowlist removed from this module.
    // Allowlist / severity decisions move to SIGMA rule YAML (plan 6).
    // `is_system_app` now derives from generic OEM prefixes; the rule can
    // additionally consult an accessibility-specific allowlist if needed.

    private val enabledServiceRegex = Regex(
        """^\s+([a-zA-Z][a-zA-Z0-9._]+)/([.\w]+)""",
        RegexOption.MULTILINE
    )

    override suspend fun analyze(sectionText: String, iocResolver: IndicatorResolver): ModuleResult {
        val telemetry = mutableListOf<Map<String, Any?>>()

        enabledServiceRegex.findAll(sectionText).forEach { match ->
            val packageName = match.groupValues[1]
            val serviceName = match.groupValues[2]
            val isSystemApp = oemPrefixResolver.isOemPrefix(packageName)

            telemetry.add(mapOf(
                "package_name" to packageName,
                "service_name" to serviceName,
                "is_system_app" to isSystemApp,
                "is_enabled" to true,
                "source" to "bugreport_import"
            ))
        }

        return ModuleResult(
            telemetry = telemetry,
            telemetryService = "accessibility_audit"
        )
    }
}
