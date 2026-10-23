package com.androdr.scanner

import android.content.Context
import android.content.pm.PackageManager
import android.net.Uri
import android.util.Log
import com.androdr.data.model.ImportedDnsEvent
import com.androdr.data.model.NetworkTelemetry
import com.androdr.data.model.ScannerFailure
import com.androdr.data.model.SecurityLogEvent
import com.androdr.ioc.IndicatorResolver
import com.androdr.reporting.ATTRIBUTION_SCANNER
import com.androdr.scanner.intrusionlog.IntrusionLogParser
import com.androdr.scanner.intrusionlog.IntrusionLogSink
import com.androdr.sigma.Finding
import com.androdr.sigma.IntrusionLogRecordBuilders
import com.androdr.sigma.StoreRecord
import dagger.hilt.android.qualifiers.ApplicationContext
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.withContext
import java.io.IOException
import java.io.InputStream
import java.io.Reader
import java.util.zip.ZipInputStream
import javax.inject.Inject
import javax.inject.Singleton

data class IntrusionLogStats(
    /** Distinct DNS records stored by this import (exact duplicates excluded). */
    val dnsEventCount: Int,
    val connectEventCount: Int,
    val securityEventCount: Int,
    /** Exact duplicate records the store dropped (one observation per fact and import). */
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

/**
 * What an intrusion-log import showed the user: the findings it kept (capped at
 * [ScanOrchestrator.FINDINGS_PERSIST_CAP]) and its stats. The records themselves are in the store.
 */
data class IntrusionLogAnalysisResult(
    val findings: List<Finding>,
    val stats: IntrusionLogStats,
    /** Non-fatal problems during analysis (e.g. attribution unavailable); persisted on the import's scan. */
    val scannerErrors: List<ScannerFailure> = emptyList(),
    /**
     * What the import session wrote (new facts, already-stored facts, dropped duplicates, telemetry
     * state, space to free) for the import card; null only for results not produced by a session.
     */
    val write: WriteResult? = null,
)

/**
 * Receives an import's records one full per-type chunk (at most [ChunkedScanWriter.CHUNK_SIZE])
 * at a time — the typed records and the [StoreRecord]s they project to, index for index. The
 * orchestrator appends each chunk to its writer session; nothing else holds the whole import.
 */
interface IntrusionLogChunks {
    suspend fun dns(events: List<ImportedDnsEvent>, records: List<StoreRecord>)
    suspend fun connect(events: List<NetworkTelemetry>, records: List<StoreRecord>)
    suspend fun security(events: List<SecurityLogEvent>, records: List<StoreRecord>)
}

/** What [IntrusionLogAnalyzer] saw while streaming an import; per-type counts are records parsed. */
data class IntrusionLogScan(val stats: IntrusionLogStats, val scannerErrors: List<ScannerFailure>)

/**
 * Coordinator for Advanced Protection Intrusion Logging imports (#342).
 * Streams per-day JSONL entries out of the export ZIP, parses them into
 * typed telemetry (pure emitters), and hands each type's records to
 * [IntrusionLogChunks] in chunks, in one pass: the writer session evaluates the
 * rules over every chunk (spec §7: detection sees everything) and stores it.
 */
@Singleton
class IntrusionLogAnalyzer @Inject constructor(
    @ApplicationContext private val context: Context,
    private val indicatorResolver: IndicatorResolver
) {
    // JVM unit tests construct this with a relaxed MockK Context — only
    // analyze(uri) touches it; analyzeEntries() is context-free by design.

    /**
     * Thrown by [analyze] when the export could not be analyzed at all (#356).
     *
     * The Throwable catch below still exists to stop a crafted ZIP's
     * OutOfMemoryError / StackOverflowError from killing the process (#342
     * security M1) — but it no longer answers with an EMPTY RESULT. An empty
     * result is indistinguishable from a genuinely empty log, so
     * [com.androdr.scanner.ScanOrchestrator.analyzeIntrusionLog] went on to
     * persist an empty import AND run its replace-on-reimport sweep, wiping the
     * previous import's rows while the UI reported success: a failed read
     * destroyed good evidence and said nothing. A failure is now loud, and
     * because it propagates out of the writer session, the session is aborted
     * and the prior import survives untouched.
     */
    class IntrusionLogAnalysisException(cause: Throwable) : Exception(
        "Intrusion log analysis failed — nothing was imported.",
        cause
    )

    // Catching Throwable at the import boundary is deliberate (finding 3c): a
    // crafted ZIP can raise an Error, which must not crash the process.
    @Suppress("TooGenericExceptionCaught")
    suspend fun analyze(uri: Uri, chunks: IntrusionLogChunks): IntrusionLogScan = withContext(Dispatchers.IO) {
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
            // A null stream means "could not read the selected file", which is a
            // failed import, not an empty one — same loud treatment (#356).
            val stream = context.contentResolver.openInputStream(uri)
                ?: throw IOException("content resolver returned no stream for the selected file")
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
                    val scope = currentCoroutineContext()
                    analyzeEntries(entrySequence, uidResolver, System.currentTimeMillis(), chunks) {
                        scope.ensureActive()
                    }
                }
            }
        } catch (c: CancellationException) {
            // Cooperative cancellation must not be swallowed as a failed import.
            throw c
        } catch (t: Throwable) {
            // A crafted ZIP can trigger OutOfMemoryError / StackOverflowError,
            // which are Errors (not Exceptions); catching Throwable here still
            // turns a would-be process crash into a handled failure (security
            // M1) — but it is now reported as one, never as an empty import
            // (#356; see IntrusionLogAnalysisException).
            Log.w(TAG, "Intrusion log import failed", t)
            throw IntrusionLogAnalysisException(t)
        }
    }

    /** One pass over [entries]: parse, buffer each type up to a chunk, hand full chunks to [chunks]. */
    internal suspend fun analyzeEntries(
        entries: Sequence<Pair<String, InputStream>>,
        uidResolver: (String) -> Int,
        capturedAt: Long,
        chunks: IntrusionLogChunks,
        onLine: () -> Unit = {},
    ): IntrusionLogScan {
        // One concatenated line sequence across all matching entries, so cross-file
        // duplicates reach the store in one import (where they collapse).
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
        val buffer = ChunkBuffer(chunks)
        val counts = IntrusionLogParser().parse(lines, uidResolver, capturedAt, buffer, onLine)
        buffer.flushAll()

        Log.d(
            TAG,
            "Parsed ${counts.dnsRecords} dns / ${counts.connectRecords} connect / " +
                "${counts.securityRecords} security records " +
                "(${counts.malformedLines} malformed, truncated=${counts.truncated})"
        )
        return IntrusionLogScan(
            stats = IntrusionLogStats(
                dnsEventCount = counts.dnsRecords,
                connectEventCount = counts.connectRecords,
                securityEventCount = counts.securityRecords,
                duplicatesCollapsed = 0,
                malformedLines = counts.malformedLines,
                earliestEventMs = buffer.earliest,
                latestEventMs = buffer.latest,
                truncated = counts.truncated,
            ),
            scannerErrors = buffer.errors.toList(),
        )
    }

    /**
     * Buffers each record type up to one chunk and tracks the running event-time min/max (no
     * per-record list survives a chunk). Before each DNS chunk it prefetches the rows behind domain
     * hits, so ioc_match findings name their family; a failure costs the attribution only — findings
     * still fire, and the import says what it lacked (recorded once; later chunks skip the prefetch).
     */
    private inner class ChunkBuffer(private val chunks: IntrusionLogChunks) : IntrusionLogSink {
        private val dns = ArrayList<ImportedDnsEvent>()
        private val dnsKeys = ArrayList<String>()
        private val net = ArrayList<NetworkTelemetry>()
        private val netKeys = ArrayList<String>()
        private val sec = ArrayList<SecurityLogEvent>()
        private val secKeys = ArrayList<String>()
        val errors = mutableListOf<ScannerFailure>()
        var earliest: Long? = null
        var latest: Long? = null
        private var prefetchFailed = false

        override suspend fun dns(event: ImportedDnsEvent, key: String) {
            seen(event.event.timestamp)
            dns += event; dnsKeys += key
            if (dns.size >= ChunkedScanWriter.CHUNK_SIZE) flushDns()
        }

        override suspend fun connect(event: NetworkTelemetry, key: String) {
            seen(event.timestamp)
            net += event; netKeys += key
            if (net.size >= ChunkedScanWriter.CHUNK_SIZE) flushNet()
        }

        override suspend fun security(event: SecurityLogEvent, key: String) {
            seen(event.timestamp)
            sec += event; secKeys += key
            if (sec.size >= ChunkedScanWriter.CHUNK_SIZE) flushSec()
        }

        suspend fun flushAll() {
            flushDns(); flushNet(); flushSec()
        }

        private fun seen(time: Long) {
            earliest = minOf(earliest ?: time, time)
            latest = maxOf(latest ?: time, time)
        }

        @Suppress("TooGenericExceptionCaught")
        private suspend fun prefetch(events: List<ImportedDnsEvent>) {
            if (prefetchFailed) return
            try {
                indicatorResolver.prefetchDomainIndicators(events.map { it.event.domain })
            } catch (c: CancellationException) {
                throw c
            } catch (e: Exception) {
                Log.w(TAG, "Domain attribution prefetch failed; findings keep no family", e)
                prefetchFailed = true
                errors += ScannerFailure(
                    scanner = ATTRIBUTION_SCANNER,
                    exception = e.javaClass.simpleName,
                    message = "family unavailable: domain prefetch failed"
                )
            }
        }

        private suspend fun flushDns() {
            if (dns.isEmpty()) return
            prefetch(dns)
            chunks.dns(dns.toList(), IntrusionLogRecordBuilders.importedDns(dns, dnsKeys))
            dns.clear(); dnsKeys.clear()
        }

        private suspend fun flushNet() {
            if (net.isEmpty()) return
            chunks.connect(net.toList(), IntrusionLogRecordBuilders.network(net, netKeys))
            net.clear(); netKeys.clear()
        }

        private suspend fun flushSec() {
            if (sec.isEmpty()) return
            chunks.security(sec.toList(), IntrusionLogRecordBuilders.securityLog(sec, secKeys))
            sec.clear(); secKeys.clear()
        }
    }

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
