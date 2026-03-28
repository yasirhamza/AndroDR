package com.androdr.scanner.bugreport

import com.androdr.ioc.IocResolver
import com.androdr.scanner.BugReportAnalyzer.BugReportFinding
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

    override suspend fun analyze(sectionText: String, iocResolver: IocResolver): ModuleResult {
        val findings = mutableListOf<BugReportFinding>()

        val receiverTableStart = sectionText.indexOf("Receiver Resolver Table:")
        if (receiverTableStart < 0) return ModuleResult(findings, emptyList())

        val nonDataStart = sectionText.indexOf("Non-Data Actions:", receiverTableStart)
        if (nonDataStart < 0) return ModuleResult(findings, emptyList())

        for (intent in sensitiveIntents) {
            val intentStart = sectionText.indexOf("$intent:", nonDataStart)
            if (intentStart < 0) continue

            // Find next intent header (any intent, not just sensitive ones)
            val nextHeaderRegex = Regex("""^\s{18,}\S+.*:$""", RegexOption.MULTILINE)
            val nextHeader = nextHeaderRegex.find(sectionText, intentStart + intent.length + 1)
            val blockEnd = nextHeader?.range?.first ?: sectionText.length
            val block = sectionText.substring(intentStart, blockEnd)

            receiverEntryRegex.findAll(block).forEach { match ->
                val packageName = match.groupValues[1]
                val componentName = match.groupValues[2]

                val iocHit = iocResolver.isKnownBadPackage(packageName)
                if (iocHit != null) {
                    findings.add(BugReportFinding(
                        severity = iocHit.severity,
                        category = "ReceiverAbuse",
                        description = "Known ${iocHit.category} package '$packageName' " +
                            "(${iocHit.name}) registered for $intent broadcast — " +
                            iocHit.description
                    ))
                    return@forEach
                }

                if (systemPackagePrefixes.any { packageName.startsWith(it) }) {
                    return@forEach
                }

                findings.add(BugReportFinding(
                    severity = "CRITICAL",
                    category = "ReceiverAbuse",
                    description = "Non-system app '$packageName/$componentName' " +
                        "registered for $intent broadcast — this is a strong " +
                        "stalkerware indicator"
                ))
            }
        }

        return ModuleResult(findings = findings, timeline = emptyList())
    }
}
