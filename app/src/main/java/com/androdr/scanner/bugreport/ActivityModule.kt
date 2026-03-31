package com.androdr.scanner.bugreport

import com.androdr.ioc.IndicatorResolver
import javax.inject.Inject
import javax.inject.Singleton

/**
 * Parses the Activity Resolver Table from `dumpsys package` to detect
 * intent hijacking — malicious apps registering handlers for browser
 * URLs, file opens, or other sensitive intents.
 */
@Singleton
class ActivityModule @Inject constructor() : BugreportModule {

    override val targetSections: List<String> = listOf("package")

    private val sensitiveSchemes = setOf(
        "http:", "https:", "content:", "file:", "tel:", "sms:", "mailto:"
    )

    private val systemPackagePrefixes = listOf(
        "com.android.", "com.google.android.", "com.samsung.android.",
        "com.sec.android.", "com.qualcomm.", "com.mediatek."
    )

    private val activityEntryRegex = Regex(
        """^\s+\d+\s+([a-zA-Z][a-zA-Z0-9._]+)/([.\w]+)""",
        RegexOption.MULTILINE
    )

    override suspend fun analyze(sectionText: String, iocResolver: IndicatorResolver): ModuleResult {
        val telemetry = mutableListOf<Map<String, Any?>>()
        val seen = mutableSetOf<Pair<String, String>>()

        val activityTableStart = sectionText.indexOf("Activity Resolver Table:")
        if (activityTableStart < 0) return ModuleResult(telemetryService = SERVICE)

        // Look for scheme-based handlers (e.g., http:, content:, file:)
        val schemeStart = sectionText.indexOf("Schemes:", activityTableStart)
        if (schemeStart < 0) return ModuleResult(telemetryService = SERVICE)

        val nextSectionRegex = Regex("""^\s{0,4}\S.*:$""", RegexOption.MULTILINE)
        val nextSection = nextSectionRegex.find(sectionText, schemeStart + "Schemes:".length)
        val schemesEnd = nextSection?.range?.first ?: sectionText.length
        val schemesBlock = sectionText.substring(schemeStart, schemesEnd)

        for (scheme in sensitiveSchemes) {
            val schemeIdx = schemesBlock.indexOf("$scheme\n")
                .takeIf { it >= 0 } ?: schemesBlock.indexOf("$scheme\r")
                    .takeIf { it >= 0 } ?: continue

            // Find the block for this scheme until the next scheme or section
            val nextSchemeRegex = Regex("""^\s{18,}\S+.*:$""", RegexOption.MULTILINE)
            val nextScheme = nextSchemeRegex.find(schemesBlock, schemeIdx + scheme.length + 1)
            val blockEnd = nextScheme?.range?.first ?: schemesBlock.length
            val block = schemesBlock.substring(schemeIdx, blockEnd)

            activityEntryRegex.findAll(block).forEach { match ->
                val packageName = match.groupValues[1]
                val componentName = match.groupValues[2]
                if (!seen.add(packageName to scheme)) return@forEach
                val isSystemApp = systemPackagePrefixes.any { packageName.startsWith(it) }
                val isIoc = iocResolver.isKnownBadPackage(packageName)

                telemetry.add(mapOf(
                    "package_name" to packageName,
                    "handled_scheme" to scheme.removeSuffix(":"),
                    "component_name" to componentName,
                    "is_system_app" to isSystemApp,
                    "is_ioc" to (isIoc != null)
                ))
            }
        }

        return ModuleResult(telemetry = telemetry, telemetryService = SERVICE)
    }

    companion object {
        private const val SERVICE = "activity_audit"
    }
}
