package com.androdr.scanner.bugreport

import com.androdr.data.model.TimelineEvent
import com.androdr.ioc.IndicatorResolver
import javax.inject.Inject
import javax.inject.Singleton

/**
 * Parses `dumpsys adb` for trusted ADB public keys. Provides forensic
 * visibility into which computers had debug access to the device.
 */
@Singleton
class AdbKeysModule @Inject constructor() : BugreportModule {

    override val targetSections: List<String> = listOf("adb")

    private val keyLineRegex = Regex(
        """^\s*([\w+/=]{20,})(?:\s+(\S+@\S+))?""",
        RegexOption.MULTILINE
    )

    override suspend fun analyze(sectionText: String, iocResolver: IndicatorResolver): ModuleResult {
        val telemetry = mutableListOf<Map<String, Any?>>()
        val timeline = mutableListOf<TimelineEvent>()

        val trustKeysStart = sectionText.indexOf("USB debugging")
            .takeIf { it >= 0 }
            ?: sectionText.indexOf("Trusted keys:").takeIf { it >= 0 }
            ?: return ModuleResult(telemetryService = SERVICE)

        // Stop scanning at the next section header to avoid false positives
        val nextHeader = Regex("""^-{3,}""", RegexOption.MULTILINE)
            .find(sectionText, trustKeysStart)
        val blockEnd = nextHeader?.range?.first ?: sectionText.length
        val block = sectionText.substring(trustKeysStart, blockEnd)

        keyLineRegex.findAll(block).forEach { match ->
            val keyFragment = match.groupValues[1].take(32) + "..."
            val host = match.groupValues[2].ifEmpty { "unknown" }

            telemetry.add(mapOf(
                "source" to "adb_trusted_key",
                "key_fragment" to keyFragment,
                "host" to host
            ))
            timeline.add(TimelineEvent(
                timestamp = 0,
                source = SERVICE,
                category = "adb_trusted_key",
                description = "ADB trusted key: $host ($keyFragment)",
                severity = "INFO"
            ))
        }

        return ModuleResult(
            telemetry = telemetry,
            telemetryService = SERVICE,
            timeline = timeline
        )
    }

    companion object {
        private const val SERVICE = "adb_audit"
    }
}
