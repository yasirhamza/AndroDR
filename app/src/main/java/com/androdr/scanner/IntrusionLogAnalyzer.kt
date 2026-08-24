package com.androdr.scanner

import android.content.Context
import android.content.pm.PackageManager
import android.net.Uri
import android.util.Log
import com.androdr.data.model.ImportedDnsEvent
import com.androdr.data.model.NetworkTelemetry
import com.androdr.data.model.SecurityLogEvent
import com.androdr.scanner.intrusionlog.IntrusionLogParser
import com.androdr.sigma.Finding
import com.androdr.sigma.SigmaRuleEngine
import dagger.hilt.android.qualifiers.ApplicationContext
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.withContext
import java.io.InputStream
import java.io.Reader
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
    val latestEventMs: Long?,
    /**
     * True when a line-length or per-type record cap dropped at least one
     * record during parsing (#342 hardening). Surfaced so callers never
     * silently assume detection saw the complete stream for a pathological file.
     */
    val truncated: Boolean = false,
    /**
     * Total number of TRIGGERED findings the analysis produced, before the
     * persistence cap ([ScanOrchestrator.FINDINGS_PERSIST_CAP], #342 B3). The
     * UI/report derive "kept N of M" from this and the cap constant — mirroring
     * how the DNS/connect capped line is derived from the total event counts —
     * so a truncated finding set is never silently hidden.
     */
    val triggeredFindingCount: Int = 0
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

    // Catching Throwable at the import boundary is deliberate (finding 3c): a
    // crafted ZIP can raise an Error, which must not crash the process.
    @Suppress("TooGenericExceptionCaught")
    suspend fun analyze(uri: Uri): IntrusionLogAnalysisResult = withContext(Dispatchers.IO) {
        val analysisScope: CoroutineScope = this
        // Bounded, validating package -> uid resolver (security M3): rejects
        // junk names without a PackageManager binder call, caps the cache, and
        // stops resolving after too many misses so a crafted export cannot flood
        // memory or spam binder transactions.
        @Suppress("SwallowedException") // unresolvable package -> -1 is the intended outcome
        val uidResolver = boundedUidResolver({ pkg ->
            try {
                context.packageManager.getPackageUid(pkg, 0)
            } catch (e: PackageManager.NameNotFoundException) {
                -1
            }
        })
        try {
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
                    analyzeEntries(
                        entrySequence,
                        uidResolver,
                        System.currentTimeMillis(),
                        onLine = { analysisScope.ensureActive() }
                    )
                }
            }
        } catch (c: CancellationException) {
            // Cooperative cancellation must not be swallowed as a failed import.
            throw c
        } catch (t: Throwable) {
            // A crafted ZIP can trigger OutOfMemoryError / StackOverflowError,
            // which are Errors (not Exceptions); catching Throwable here turns a
            // would-be process crash into a graceful empty import (security M1).
            Log.w(TAG, "Intrusion log import failed; returning empty result", t)
            emptyResult()
        }
    }

    internal fun analyzeEntries(
        entries: Sequence<Pair<String, InputStream>>,
        uidResolver: (String) -> Int,
        capturedAt: Long,
        onLine: () -> Unit = {}
    ): IntrusionLogAnalysisResult {
        // One concatenated line sequence across all matching entries makes
        // cross-file event dedup inherent to a single parse() call.
        val lines = sequence {
            for ((name, input) in entries) {
                // Shared with the sniffer (#356) so a ZIP the sniffer accepts can
                // never be one this loop then reads nothing out of — the two
                // copies of this rule had already drifted on "(N)" chunks.
                if (!ArtifactSniffer.isPerDayLogEntry(name)) continue
                // The ZipInputStream positions the shared stream at this
                // entry; consume it fully before the caller advances. A bounded
                // reader guarantees a crafted unterminated "line" is never
                // materialized whole (security M1 / C#7).
                boundedLines(input.bufferedReader(), LINE_READ_CAP).forEach { yield(it) }
            }
        }
        val parsed = IntrusionLogParser().parse(lines, uidResolver, capturedAt, onLine)

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
                "(${parsed.duplicatesCollapsed} dupes, ${parsed.malformedLines} malformed, " +
                "truncated=${parsed.truncated}); ${findings.count { it.triggered }} findings"
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
                latestEventMs = tsList.maxOrNull(),
                truncated = parsed.truncated,
                triggeredFindingCount = findings.count { it.triggered }
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
    }
}

/** Max chars buffered per line by [boundedLines]; matches the parser's line cap. */
private const val LINE_READ_CAP = 1_048_576

private const val MIN_PACKAGE_NAME_LENGTH = 3
private const val MAX_PACKAGE_NAME_LENGTH = 255
private const val UID_CACHE_MAX = 10_000
private const val UID_MISS_THRESHOLD = 2_000

/** Two-plus dot-separated Java-identifier segments — the Android package shape. */
private val PACKAGE_NAME_REGEX = Regex("^[A-Za-z][A-Za-z0-9_]*(\\.[A-Za-z][A-Za-z0-9_]*)+$")

/**
 * True only for strings that look like a real Android package name. Used to skip
 * PackageManager lookups (which cost a binder call + a NameNotFoundException) for
 * attacker-chosen junk (security M3).
 */
internal fun isPlausiblePackageName(pkg: String): Boolean =
    pkg.length in MIN_PACKAGE_NAME_LENGTH..MAX_PACKAGE_NAME_LENGTH &&
        PACKAGE_NAME_REGEX.matches(pkg)

/**
 * Wraps a raw package -> uid resolver with three DoS guards (security M3):
 *  - package-name-shape validation: junk resolves to -1 with no [rawResolve] call;
 *  - a bounded access-order LRU cache (default [UID_CACHE_MAX]) so an unbounded
 *    set of unique names cannot grow the map without limit;
 *  - a miss threshold: after [missThreshold] unresolved lookups, further unknown
 *    names short-circuit to -1 (the same value an uninstalled package yields)
 *    instead of issuing more binder calls.
 */
internal fun boundedUidResolver(
    rawResolve: (String) -> Int,
    maxCacheSize: Int = UID_CACHE_MAX,
    missThreshold: Int = UID_MISS_THRESHOLD
): (String) -> Int {
    val cache = object : LinkedHashMap<String, Int>(16, 0.75f, true) {
        override fun removeEldestEntry(eldest: MutableMap.MutableEntry<String, Int>): Boolean =
            size > maxCacheSize
    }
    var misses = 0
    return resolve@{ pkg ->
        if (!isPlausiblePackageName(pkg)) return@resolve -1
        cache[pkg]?.let { return@resolve it }
        if (misses >= missThreshold) return@resolve -1
        val uid = rawResolve(pkg)
        if (uid < 0) misses++
        cache[pkg] = uid
        uid
    }
}

/**
 * Reads [reader] into lines while guaranteeing no single line is buffered beyond
 * [maxLen] + 1 chars: a crafted unterminated multi-MB "line" yields a bounded
 * (maxLen + 1)-length marker string — which the parser then counts as one
 * malformed line — rather than being materialized whole (security M1 / C#7).
 * Handles LF and CRLF; a trailing CR is dropped.
 */
private fun boundedLines(reader: Reader, maxLen: Int): Sequence<String> = sequence {
    // NOTE: the reader is NOT closed here — it wraps the shared ZipInputStream
    // that must stay open across entries; analyze() closes the stream via `use`.
    val sb = StringBuilder()
    var started = false
    while (true) {
        val code = reader.read()
        if (code == -1) {
            if (started) yield(sb.toString())
            break
        }
        started = true
        when (val c = code.toChar()) {
            '\n' -> {
                yield(sb.toString())
                sb.setLength(0)
                started = false
            }
            '\r' -> Unit // swallow CR (CRLF handling)
            else -> if (sb.length <= maxLen) sb.append(c) // cap at maxLen + 1 chars
        }
    }
}
