package com.androdr.ioc.feeds

import android.util.Log
import com.androdr.data.model.DomainIocEntry
import com.androdr.ioc.DomainIocFeed
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.json.JSONObject
import java.net.HttpURLConnection
import java.net.URL

/**
 * Fetches Android-related domain IOCs from ThreatFox (abuse.ch).
 *
 * Reads the public recent-IOCs JSON export and filters for entries tagged as
 * Android-related or whose malware field references Android/APK.
 */
class ThreatFoxDomainFeed : DomainIocFeed {

    override val sourceId = SOURCE_ID

    @Suppress("TooGenericExceptionCaught")
    override suspend fun fetch(): List<DomainIocEntry> = withContext(Dispatchers.IO) {
        try {
            val body = httpGet(RECENT_URL) ?: return@withContext emptyList()
            val now = System.currentTimeMillis()
            parseRecentJson(body, now)
        } catch (e: Exception) {
            Log.e(TAG, "ThreatFoxDomainFeed.fetch failed: ${e.message}")
            emptyList()
        }
    }

    /**
     * Parses the ThreatFox recent JSON export.
     *
     * Two schemas are tolerated (AndroDR #174 — abuse.ch changed the live
     * /export/json/recent/ shape some time before 2026-05-15):
     *
     * **Current schema (2026-05-15+):** a flat dict keyed by numeric ID strings,
     * with `ioc_value` as the IOC field and `tags` as a comma-separated string.
     * ```json
     * {
     *   "1814938": [ { "ioc_type": "domain", "ioc_value": "...", "malware": "...", "tags": "android,banking" } ],
     *   ...
     * }
     * ```
     *
     * **Legacy schema:** date-keyed dict under a `data` wrapper, with `ioc` as
     * the IOC field and `tags` as a JSON array. Tolerated in case abuse.ch
     * reverts; not expected to be served today.
     * ```json
     * { "query_status": "ok", "data": { "2024-01-01": [ { "ioc_type": "domain", "ioc": "...", "tags": [...] } ] } }
     * ```
     *
     * Filters for entries where `ioc_type` is `"domain"` and the entry is
     * Android-related (see [isAndroidRelated]).
     */
    @Suppress("TooGenericExceptionCaught", "NestedBlockDepth", "ReturnCount")
    internal fun parseRecentJson(json: String, fetchedAt: Long): List<DomainIocEntry> {
        return try {
            val root = JSONObject(json)
            // Schema detection. Two known shapes are valid:
            //   - Legacy: root has a "data" key holding a JSONObject of arrays.
            //   - Current: top-level is itself a JSONObject of arrays (numeric-id keys).
            // Anything else (e.g., data-as-string, list at root) is unrecognized
            // and must NOT silently degrade to zero — the silent-zero failure
            // mode is exactly what caused #174.
            val entriesContainer: JSONObject = when {
                root.optJSONObject("data") != null -> root.optJSONObject("data")!!
                hasArrayValuedKeys(root) -> root
                else -> {
                    Log.w(
                        TAG,
                        "parseRecentJson: unrecognized schema (no `data` object, " +
                            "no array-valued top-level keys) — returning empty list. " +
                            "Top-level keys: ${root.keys().asSequence().take(KEY_PREVIEW).toList()}"
                    )
                    return emptyList()
                }
            }
            val results = mutableListOf<DomainIocEntry>()
            var entriesSeen = 0

            for (key in entriesContainer.keys()) {
                val dayEntries = entriesContainer.optJSONArray(key) ?: continue
                entriesSeen += dayEntries.length()
                @Suppress("LoopWithTooManyJumpStatements")
                for (i in 0 until dayEntries.length()) {
                    val entry = dayEntries.optJSONObject(i) ?: continue
                    if (entry.optString("ioc_type") != "domain") continue
                    if (!isAndroidRelated(entry)) continue

                    // Field renamed `ioc` -> `ioc_value` in the current schema;
                    // tolerate both for backward-compat.
                    val rawIoc = entry.optString("ioc_value")
                        .ifEmpty { entry.optString("ioc") }
                        .trim()
                    val domain = stripProtocol(rawIoc).lowercase()
                    if (domain.isEmpty()) continue

                    val malware = entry.optString("malware", "Unknown")
                    results.add(
                        DomainIocEntry(
                            domain = domain,
                            campaignName = malware,
                            severity = "CRITICAL",
                            source = SOURCE_ID,
                            fetchedAt = fetchedAt
                        )
                    )
                }
            }
            // M2 from review: log non-zero counts so a developer can tell
            // "feed worked, zero Android today" apart from "feed silently
            // broke again" without re-reading the upstream API.
            Log.i(
                TAG,
                "parseRecentJson: ${results.size} Android domain(s) extracted " +
                    "from $entriesSeen ThreatFox IOC entries"
            )
            results
        } catch (e: Exception) {
            Log.w(TAG, "parseRecentJson failed: ${e.message}")
            emptyList()
        }
    }

    /**
     * Returns true if the JSONObject has at least one key whose value is a
     * JSONArray. Used as a schema-shape heuristic for the current ThreatFox
     * response (numeric-id keys mapping to single-element arrays).
     */
    private fun hasArrayValuedKeys(obj: JSONObject): Boolean {
        for (key in obj.keys()) {
            if (obj.optJSONArray(key) != null) return true
        }
        return false
    }

    /**
     * Checks if a ThreatFox entry is Android-related by inspecting tags and
     * malware fields.
     *
     * In the current ThreatFox schema (AndroDR #174) `tags` is a comma-separated
     * string. The legacy shape was a JSON array. Both are handled.
     */
    internal fun isAndroidRelated(entry: JSONObject): Boolean {
        val tagsArray = entry.optJSONArray("tags")
        if (tagsArray != null) {
            for (i in 0 until tagsArray.length()) {
                val tag = tagsArray.optString(i, "")
                if (tag.contains("android", ignoreCase = true)) return true
            }
        } else {
            val tagsString = entry.optString("tags", "")
            if (tagsString.contains("android", ignoreCase = true)) return true
        }
        val malware = entry.optString("malware", "")
        return malware.contains("android", ignoreCase = true) ||
            malware.contains("apk", ignoreCase = true)
    }

    /**
     * Strips protocol prefixes (http://, https://) and trailing paths from a domain string.
     */
    internal fun stripProtocol(raw: String): String {
        var domain = raw
        if (domain.startsWith("http://")) domain = domain.removePrefix("http://")
        if (domain.startsWith("https://")) domain = domain.removePrefix("https://")
        // Remove trailing path
        val slashIdx = domain.indexOf('/')
        if (slashIdx > 0) domain = domain.substring(0, slashIdx)
        // Remove port
        val colonIdx = domain.indexOf(':')
        if (colonIdx > 0) domain = domain.substring(0, colonIdx)
        return domain.trim()
    }

    @Suppress("TooGenericExceptionCaught", "SwallowedException")
    private fun httpGet(url: String): String? = try {
        (URL(url).openConnection() as HttpURLConnection).run {
            connectTimeout = TIMEOUT_MS; readTimeout = TIMEOUT_MS
            requestMethod = "GET"
            setRequestProperty("User-Agent", USER_AGENT)
            try {
                if (responseCode != HttpURLConnection.HTTP_OK) {
                    Log.w(TAG, "HTTP $responseCode from $url"); null
                } else {
                    inputStream.bufferedReader().readText()
                }
            } finally { disconnect() }
        }
    } catch (e: Exception) {
        Log.w(TAG, "httpGet failed for $url: ${e.message}"); null
    }

    companion object {
        private const val TAG = "ThreatFoxDomainFeed"
        const val SOURCE_ID = "threatfox"
        private const val RECENT_URL = "https://threatfox.abuse.ch/export/json/recent/"
        private const val TIMEOUT_MS = 15_000
        private const val USER_AGENT = "AndroDR/1.0"
        private const val KEY_PREVIEW = 5
    }
}
