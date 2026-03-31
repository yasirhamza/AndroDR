package com.androdr.scanner.bugreport

import com.androdr.ioc.IocResolver
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

    override suspend fun analyze(sectionText: String, iocResolver: IocResolver): ModuleResult {
        val telemetry = mutableListOf<Map<String, Any?>>()

        val compatStart = sectionText.indexOf("Compat overrides:")
            .takeIf { it >= 0 }
            ?: sectionText.indexOf("ChangeId").takeIf { it >= 0 }
            ?: return ModuleResult(telemetryService = SERVICE)

        compatOverrideRegex.findAll(sectionText, compatStart).forEach { match ->
            val changeId = match.groupValues[1]
            val packageName = match.groupValues[2]

            if (changeId == CHANGE_ID_DOWNSCALED) {
                val isIoc = iocResolver.isKnownBadPackage(packageName)
                telemetry.add(mapOf(
                    "source" to "platform_compat",
                    "package_name" to packageName,
                    "change_id" to changeId,
                    "is_downscaled" to true,
                    "is_ioc" to (isIoc != null)
                ))
            }
        }

        return ModuleResult(telemetry = telemetry, telemetryService = SERVICE)
    }

    companion object {
        private const val SERVICE = "platform_compat_audit"
        private const val CHANGE_ID_DOWNSCALED = "168419799"
    }
}
