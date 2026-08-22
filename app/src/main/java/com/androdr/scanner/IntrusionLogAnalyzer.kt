package com.androdr.scanner

import android.content.Context
import android.content.pm.PackageManager
import android.net.Uri
import android.util.Log
import com.androdr.data.model.NetworkTelemetry
import com.androdr.data.model.SecurityLogEvent
import com.androdr.scanner.intrusionlog.ImportedDnsEvent
import com.androdr.scanner.intrusionlog.IntrusionLogParser
import com.androdr.sigma.Finding
import com.androdr.sigma.SigmaRuleEngine
import dagger.hilt.android.qualifiers.ApplicationContext
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.InputStream
import java.util.zip.ZipInputStream
import javax.inject.Inject
import javax.inject.Singleton

data class IntrusionLogStats(
    val dnsEventCount: Int,
    val connectEventCount: Int,
    val securityEventCount: Int,
    val duplicatesCollapsed: Int,
    val malformedLines: Int,
    val earliestEventMs: Long?,
    val latestEventMs: Long?
)

data class IntrusionLogAnalysisResult(
    val findings: List<Finding>,
    val dnsEvents: List<ImportedDnsEvent>,
    val networkEvents: List<NetworkTelemetry>,
    val securityEvents: List<SecurityLogEvent>,
    val stats: IntrusionLogStats
)

/**
 * Coordinator for Advanced Protection Intrusion Logging imports (#342).
 * Streams per-day JSONL entries out of the export ZIP, parses them into
 * typed telemetry (pure emitters), and evaluates SIGMA rules over the
 * COMPLETE parsed stream — persistence caps are applied later by the
 * orchestrator, never here (spec §7: detection sees everything).
 */
@Singleton
class IntrusionLogAnalyzer @Inject constructor(
    @ApplicationContext private val context: Context,
    private val sigmaRuleEngine: SigmaRuleEngine
) {
    // JVM unit tests construct this with a relaxed MockK Context — only
    // analyze(uri) touches it; analyzeEntries() is context-free by design.

    suspend fun analyze(uri: Uri): IntrusionLogAnalysisResult = withContext(Dispatchers.IO) {
        val uidCache = HashMap<String, Int>()
        // Unresolvable package -> -1 is the expected/intentional outcome for
        // an app no longer installed, not a bug to surface (see DeviceAuditor,
        // SigmaRuleFeed for the same established convention).
        @Suppress("SwallowedException")
        val uidResolver: (String) -> Int = { pkg ->
            uidCache.getOrPut(pkg) {
                try {
                    context.packageManager.getPackageUid(pkg, 0)
                } catch (e: PackageManager.NameNotFoundException) {
                    -1
                }
            }
        }
        val stream = context.contentResolver.openInputStream(uri)
            ?: return@withContext emptyResult()
        stream.use { s ->
            ZipInputStream(s.buffered()).use { zip ->
                val entrySequence = sequence {
                    var entry = zip.nextEntry
                    while (entry != null) {
                        if (!entry.isDirectory) yield(entry.name to (zip as InputStream))
                        try { zip.closeEntry() } catch (_: Exception) { /* ignore */ }
                        entry = try { zip.nextEntry } catch (_: Exception) { null }
                    }
                }
                analyzeEntries(entrySequence, uidResolver, System.currentTimeMillis())
            }
        }
    }

    internal fun analyzeEntries(
        entries: Sequence<Pair<String, InputStream>>,
        uidResolver: (String) -> Int,
        capturedAt: Long
    ): IntrusionLogAnalysisResult {
        // One concatenated line sequence across all matching entries makes
        // cross-file event_id dedup inherent to a single parse() call.
        val lines = sequence {
            for ((name, input) in entries) {
                val base = name.substringAfterLast('/').lowercase()
                val matches = PER_DAY_ENTRY.matches(base) && name.count { it == '/' } <= 1
                if (!matches) continue
                // The ZipInputStream positions the shared stream at this
                // entry; consume it fully before the caller advances.
                input.bufferedReader().lineSequence().forEach { yield(it) }
            }
        }
        val parsed = IntrusionLogParser().parse(lines, uidResolver, capturedAt)

        val findings = buildList {
            addAll(sigmaRuleEngine.evaluateDns(parsed.dnsEvents.map { it.event }))
            addAll(sigmaRuleEngine.evaluateNetwork(parsed.networkEvents))
            addAll(sigmaRuleEngine.evaluateSecurityLog(parsed.securityEvents))
        }

        val allTimestamps = parsed.dnsEvents.asSequence().map { it.event.timestamp } +
            parsed.networkEvents.asSequence().map { it.timestamp } +
            parsed.securityEvents.asSequence().map { it.timestamp }
        val tsList = allTimestamps.toList()

        Log.d(
            TAG,
            "Parsed ${parsed.dnsEvents.size} dns / ${parsed.networkEvents.size} connect / " +
                "${parsed.securityEvents.size} security events " +
                "(${parsed.duplicatesCollapsed} dupes, ${parsed.malformedLines} malformed); " +
                "${findings.count { it.triggered }} findings"
        )

        return IntrusionLogAnalysisResult(
            findings = findings,
            dnsEvents = parsed.dnsEvents,
            networkEvents = parsed.networkEvents,
            securityEvents = parsed.securityEvents,
            stats = IntrusionLogStats(
                dnsEventCount = parsed.dnsEvents.size,
                connectEventCount = parsed.networkEvents.size,
                securityEventCount = parsed.securityEvents.size,
                duplicatesCollapsed = parsed.duplicatesCollapsed,
                malformedLines = parsed.malformedLines,
                earliestEventMs = tsList.minOrNull(),
                latestEventMs = tsList.maxOrNull()
            )
        )
    }

    private fun emptyResult() = IntrusionLogAnalysisResult(
        findings = emptyList(), dnsEvents = emptyList(), networkEvents = emptyList(),
        securityEvents = emptyList(),
        stats = IntrusionLogStats(0, 0, 0, 0, 0, null, null)
    )

    private companion object {
        private const val TAG = "IntrusionLogAnalyzer"
        private val PER_DAY_ENTRY = Regex("""\d{4}-\d{2}-\d{2}\.txt""")
    }
}
