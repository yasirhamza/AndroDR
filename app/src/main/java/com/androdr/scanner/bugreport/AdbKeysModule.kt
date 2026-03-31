package com.androdr.scanner.bugreport

import com.androdr.data.model.TimelineEvent
import com.androdr.ioc.IocResolver
import javax.inject.Inject
import javax.inject.Singleton

/**
 * Parses `dumpsys adb` for trusted ADB public keys and `dumpsys platform_compat`
 * for compatibility override entries. Provides forensic visibility into which
 * computers had debug access and which apps use compatibility workarounds.
 */
@Singleton
class AdbKeysModule @Inject constructor() : BugreportModule {

    override val targetSections: List<String> = listOf("adb", "platform_compat")

    private val keyLineRegex = Regex(
        """^\s*([\w+/=]{20,})\s+(\S+@\S+)?""",
        RegexOption.MULTILINE
    )

    private val compatOverrideRegex = Regex(
        """^\s+(\d+),\s*\{.*packageName=([a-zA-Z][a-zA-Z0-9._]+)""",
        RegexOption.MULTILINE
    )

    override suspend fun analyze(sectionText: String, iocResolver: IocResolver): ModuleResult {
        val telemetry = mutableListOf<Map<String, Any?>>()
        val timeline = mutableListOf<TimelineEvent>()

        // --- ADB trusted keys ---
        val trustKeysStart = sectionText.indexOf("USB debugging")
            .takeIf { it >= 0 } ?: sectionText.indexOf("Trusted keys:")
        if (trustKeysStart != null && trustKeysStart >= 0) {
            keyLineRegex.findAll(sectionText, trustKeysStart).forEach { match ->
                val keyFragment = match.groupValues[1].take(32) + "..."
                val host = match.groupValues[2].ifEmpty { "unknown" }

                telemetry.add(mapOf(
                    "source" to "adb_trusted_key",
                    "key_fragment" to keyFragment,
                    "host" to host
                ))
                timeline.add(TimelineEvent(
                    timestamp = 0,
                    source = "adb_audit",
                    category = "adb_trusted_key",
                    description = "ADB trusted key: $host ($keyFragment)",
                    severity = "INFO"
                ))
            }
        }

        // --- Platform compatibility overrides ---
        val compatStart = sectionText.indexOf("Compat overrides:")
            .takeIf { it >= 0 } ?: sectionText.indexOf("ChangeId")
        if (compatStart != null && compatStart >= 0) {
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
        }

        return ModuleResult(
            telemetry = telemetry,
            telemetryService = "adb_audit",
            timeline = timeline
        )
    }

    companion object {
        // ChangeId 168419799 = DOWNSCALED — apps using this may be evading display-size detection
        private const val CHANGE_ID_DOWNSCALED = "168419799"
    }
}
