package com.androdr.scanner.bugreport

import com.androdr.ioc.IndicatorResolver
import javax.inject.Inject
import javax.inject.Singleton

/**
 * Parses `dumpsys platform_compat` for compatibility override entries.
 * Apps with DOWNSCALED (ChangeId 168419799) overrides may be using
 * compatibility workarounds as an anti-analysis technique.
 */
@Singleton
class PlatformCompatModule @Inject constructor() : BugreportModule {

    override val targetSections: List<String> = listOf("platform_compat")

    private val compatOverrideRegex = Regex(
        """^\s+(\d+),\s*\{.*packageName=([a-zA-Z][a-zA-Z0-9._]+)""",
        RegexOption.MULTILINE
    )

    override suspend fun analyze(sectionText: String, iocResolver: IndicatorResolver): ModuleResult {
        val telemetry = mutableListOf<Map<String, Any?>>()

        val compatStart = sectionText.indexOf("Compat overrides:")
            .takeIf { it >= 0 }
            ?: sectionText.indexOf("ChangeId").takeIf { it >= 0 }
            ?: return ModuleResult(telemetryService = SERVICE)

        // Emit every compat override observed. SIGMA rules (plan 6) decide
        // which ChangeIds matter (e.g. DOWNSCALED=168419799 for anti-analysis).
        // No hardcoded ChangeId filter in this module.
        compatOverrideRegex.findAll(sectionText, compatStart).forEach { match ->
            val changeId = match.groupValues[1]
            val packageName = match.groupValues[2]
            val isIoc = iocResolver.isKnownBadPackage(packageName)
            telemetry.add(mapOf(
                "source" to "bugreport_import",
                "service" to "platform_compat",
                "package_name" to packageName,
                "change_id" to changeId,
                "is_ioc" to (isIoc != null)
            ))
        }

        return ModuleResult(telemetry = telemetry, telemetryService = SERVICE)
    }

    companion object {
        private const val SERVICE = "platform_compat_audit"
    }
}
