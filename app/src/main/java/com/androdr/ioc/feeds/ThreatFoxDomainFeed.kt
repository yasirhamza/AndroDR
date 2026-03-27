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
     * The response structure is:
     * ```json
     * {
     *   "query_status": "ok",
     *   "data": {
     *     "2024-01-01": [ { "ioc_type": "domain", "ioc": "...", "malware": "...", "tags": [...] }, ... ],
     *     ...
     *   }
     * }
     * ```
     *
     * Filters for entries where `ioc_type` is `"domain"` and the entry is Android-related
     * (tags contain "android"/"Android" or malware field contains "android"/"apk" case-insensitive).
     */
    @Suppress("TooGenericExceptionCaught", "NestedBlockDepth")
    internal fun parseRecentJson(json: String, fetchedAt: Long): List<DomainIocEntry> {
        return try {
            val root = JSONObject(json)
            val data = root.optJSONObject("data") ?: return emptyList()
            val results = mutableListOf<DomainIocEntry>()

            for (dateKey in data.keys()) {
                val dayEntries = data.optJSONArray(dateKey) ?: continue
                @Suppress("LoopWithTooManyJumpStatements")
                for (i in 0 until dayEntries.length()) {
                    val entry = dayEntries.optJSONObject(i) ?: continue
                    if (entry.optString("ioc_type") != "domain") continue
                    if (!isAndroidRelated(entry)) continue

                    val rawIoc = entry.optString("ioc").trim()
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
            results
        } catch (e: Exception) {
            Log.w(TAG, "parseRecentJson failed: ${e.message}")
            emptyList()
        }
    }

    /**
     * Checks if a ThreatFox entry is Android-related by inspecting tags and malware fields.
     */
    internal fun isAndroidRelated(entry: JSONObject): Boolean {
        val tags = entry.optJSONArray("tags")
        if (tags != null) {
            for (i in 0 until tags.length()) {
                val tag = tags.optString(i, "")
                if (tag.contains("android", ignoreCase = true)) return true
            }
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
    }
}
