package com.androdr.ioc.feeds

import android.util.Log
import com.androdr.data.model.DomainIocEntry
import com.androdr.ioc.DomainIocFeed
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.net.HttpURLConnection
import java.net.URL

/**
 * Fetches threat intelligence domains from the HaGeZi TIF (Threat Intelligence Feeds)
 * medium blocklist — a curated list of domains associated with malware, phishing,
 * and other threats, maintained at github.com/hagezi/dns-blocklists.
 */
class HaGeZiTifFeed : DomainIocFeed {

    override val sourceId = SOURCE_ID

    @Suppress("TooGenericExceptionCaught")
    override suspend fun fetch(): List<DomainIocEntry> = withContext(Dispatchers.IO) {
        try {
            val body = httpGet(TIF_URL) ?: return@withContext emptyList()
            val now = System.currentTimeMillis()
            parseDomainList(body, now)
        } catch (e: Exception) {
            Log.e(TAG, "HaGeZiTifFeed.fetch failed: ${e.message}")
            emptyList()
        }
    }

    /**
     * Parses Adblock Plus format: extracts domains from `||domain^` lines.
     * Skips comments (! lines), metadata, and non-domain entries.
     */
    internal fun parseDomainList(text: String, fetchedAt: Long): List<DomainIocEntry> {
        return text.lines()
            .map { it.trim() }
            .filter { it.startsWith("||") && it.endsWith("^") }
            .map { line -> line.removePrefix("||").removeSuffix("^") }
            .filter { it.isNotEmpty() && !it.contains("*") }
            .map { domain ->
                DomainIocEntry(
                    domain = domain.lowercase(),
                    campaignName = CAMPAIGN_NAME,
                    severity = "HIGH",
                    source = SOURCE_ID,
                    fetchedAt = fetchedAt
                )
            }
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
        private const val TAG = "HaGeZiTifFeed"
        const val SOURCE_ID = "hagezi_tif"
        private const val CAMPAIGN_NAME = "HaGeZi TIF"
        private const val TIF_URL =
            "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/tif.medium.txt"
        private const val TIMEOUT_MS = 15_000
        private const val USER_AGENT = "AndroDR/1.0"
    }
}
