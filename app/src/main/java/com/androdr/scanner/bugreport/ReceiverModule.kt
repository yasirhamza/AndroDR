package com.androdr.scanner.bugreport

import com.androdr.ioc.DeviceIdentity
import com.androdr.ioc.IndicatorResolver
import com.androdr.ioc.OemPrefixResolver
import javax.inject.Inject
import javax.inject.Singleton

@Singleton
class ReceiverModule @Inject constructor(
    private val oemPrefixResolver: OemPrefixResolver,
) : BugreportModule {

    override val targetSections: List<String> = listOf("package")

    // Rule-driven filter: the set of intents considered "sensitive" lives in
    // the SIGMA rule YAML (plan 6), not here. Plan 5 tracks a minimal set of
    // broadcast actions worth enumerating from dumpsys; rules downstream
    // decide which of those warrant a finding. No severity/filter constants.
    private val enumeratedIntents = setOf(
        "android.provider.Telephony.SMS_RECEIVED",
        "android.provider.Telephony.NEW_OUTGOING_SMS",
        "android.intent.action.DATA_SMS_RECEIVED",
        "android.intent.action.PHONE_STATE",
        "android.intent.action.NEW_OUTGOING_CALL",
        "android.intent.action.BOOT_COMPLETED",
        "android.intent.action.LOCKED_BOOT_COMPLETED"
    )

    private val receiverEntryRegex = Regex(
        """^\s+\d+\s+([a-zA-Z][a-zA-Z0-9._]+)/([.\w]+)""",
        RegexOption.MULTILINE
    )

    /**
     * Safety cap on how much text we read past the LAST sensitive intent's
     * header when building its per-intent block. Intermediate intents are
     * naturally bounded by the next intent's start position, so this cap
     * only applies to the final one in the list. Chosen large enough to
     * hold thousands of receiver entries (the biggest realistic intent
     * block is ~tens of KB on any device), small enough to prevent a
     * degenerate bug report from making us substring most of a 16+ MB
     * package section.
     */
    private val lastIntentBlockCap = 256 * 1024

    override suspend fun analyze(
        sectionText: String,
        iocResolver: IndicatorResolver,
        device: DeviceIdentity,
    ): ModuleResult {
        val telemetry = mutableListOf<Map<String, Any?>>()
        val seen = mutableSetOf<Pair<String, String>>() // (packageName, intentAction)

        val receiverTableStart = sectionText.indexOf("Receiver Resolver Table:")
        if (receiverTableStart < 0) return ModuleResult(telemetryService = "receiver_audit")

        val nonDataStart = sectionText.indexOf("Non-Data Actions:", receiverTableStart)
        if (nonDataStart < 0) return ModuleResult(telemetryService = "receiver_audit")

        // Pre-compute the position of every sensitive intent header in ONE
        // pass, then walk the sorted list in linear order. Each intent's
        // block is naturally bounded by the next intent's start position,
        // so no regex scans over the full 16+ MB package section are
        // needed at all.
        //
        // Why this matters: the previous implementation called
        // `nextHeaderRegex.find(sectionText, intentStart + ...)` inside
        // the per-intent loop. That `.find()` linearly scans from
        // `intentStart` to the end of the whole section (or until a
        // match). For 7 intents on a 16 MB package section, that was
        // roughly 7 × 16 MB = ~110 MB of MULTILINE regex scanning and
        // ~31 seconds of wall time on a real Galaxy S25 Ultra bug report.
        //
        // An earlier version of this fix tried to slice a bounded
        // "Non-Data Actions" block up-front and do all the per-intent
        // work inside it, but the chosen delimiter was wrong (it matched
        // intent headers themselves) AND the 512 KB cap truncated the
        // block on real devices, causing a correctness regression from
        // 545 telemetry records down to 63 — silently dropping ~88% of
        // the data. See commit history for detail. The intent-positions
        // approach below avoids that class of bug entirely: each intent's
        // block ends at a position that is ALREADY known to be another
        // intent's start, so we can never accidentally cut off receiver
        // entries that belong to the current intent.
        val intentPositions: List<Pair<String, Int>> = enumeratedIntents
            .mapNotNull { intent ->
                val idx = sectionText.indexOf("$intent:", nonDataStart)
                if (idx >= 0) intent to idx else null
            }
            .sortedBy { it.second }

        for ((i, pair) in intentPositions.withIndex()) {
            val (intent, intentStart) = pair
            // The block for this intent extends from its header up to the
            // next intent's header (or a bounded safety cap for the last
            // intent in the list).
            val blockEnd = if (i + 1 < intentPositions.size) {
                intentPositions[i + 1].second
            } else {
                minOf(intentStart + lastIntentBlockCap, sectionText.length)
            }
            val block = sectionText.substring(intentStart, blockEnd)

            receiverEntryRegex.findAll(block).forEach { match ->
                val packageName = match.groupValues[1]
                val componentName = match.groupValues[2]
                if (!seen.add(packageName to intent)) return@forEach
                val isSystemApp = oemPrefixResolver.isOemPrefix(packageName, device)

                telemetry.add(mapOf(
                    "package_name" to packageName,
                    "intent_action" to intent,
                    "component_name" to componentName,
                    "is_system_app" to isSystemApp,
                    "source" to "bugreport_import"
                ))
            }
        }

        return ModuleResult(
            telemetry = telemetry,
            telemetryService = "receiver_audit"
        )
    }
}
