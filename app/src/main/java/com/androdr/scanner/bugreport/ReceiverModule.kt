package com.androdr.scanner.bugreport

import com.androdr.ioc.IndicatorResolver
import javax.inject.Inject
import javax.inject.Singleton

@Singleton
class ReceiverModule @Inject constructor() : BugreportModule {

    override val targetSections: List<String> = listOf("package")

    private val sensitiveIntents = setOf(
        "android.provider.Telephony.SMS_RECEIVED",
        "android.provider.Telephony.NEW_OUTGOING_SMS",
        "android.intent.action.DATA_SMS_RECEIVED",
        "android.intent.action.PHONE_STATE",
        "android.intent.action.NEW_OUTGOING_CALL"
    )

    private val systemPackagePrefixes = listOf(
        "com.android.",
        "com.google.android.",
        "com.samsung.android.",
        "com.sec.android.",
        "com.qualcomm.",
        "com.mediatek."
    )

    private val receiverEntryRegex = Regex(
        """^\s+\d+\s+([a-zA-Z][a-zA-Z0-9._]+)/([.\w]+)""",
        RegexOption.MULTILINE
    )

    override suspend fun analyze(sectionText: String, iocResolver: IndicatorResolver): ModuleResult {
        val telemetry = mutableListOf<Map<String, Any?>>()
        val seen = mutableSetOf<Pair<String, String>>() // (packageName, intentAction)

        val receiverTableStart = sectionText.indexOf("Receiver Resolver Table:")
        if (receiverTableStart < 0) return ModuleResult(telemetryService = "receiver_audit")

        val nonDataStart = sectionText.indexOf("Non-Data Actions:", receiverTableStart)
        if (nonDataStart < 0) return ModuleResult(telemetryService = "receiver_audit")

        for (intent in sensitiveIntents) {
            val intentStart = sectionText.indexOf("$intent:", nonDataStart)
            if (intentStart < 0) continue

            val nextHeaderRegex = Regex("""^\s{18,}\S+.*:$""", RegexOption.MULTILINE)
            val nextHeader = nextHeaderRegex.find(sectionText, intentStart + intent.length + 1)
            val blockEnd = nextHeader?.range?.first ?: sectionText.length
            val block = sectionText.substring(intentStart, blockEnd)

            receiverEntryRegex.findAll(block).forEach { match ->
                val packageName = match.groupValues[1]
                val componentName = match.groupValues[2]
                if (!seen.add(packageName to intent)) return@forEach
                val isSystemApp = systemPackagePrefixes.any { packageName.startsWith(it) }

                telemetry.add(mapOf(
                    "package_name" to packageName,
                    "intent_action" to intent,
                    "component_name" to componentName,
                    "is_system_app" to isSystemApp
                ))
            }
        }

        return ModuleResult(
            telemetry = telemetry,
            telemetryService = "receiver_audit"
        )
    }
}
