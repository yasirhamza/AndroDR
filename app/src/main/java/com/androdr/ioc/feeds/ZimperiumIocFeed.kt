package com.androdr.ioc.feeds

import android.util.Log
import com.androdr.data.model.DomainIocEntry
import com.androdr.ioc.DomainIocFeed
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.withContext
import java.net.HttpURLConnection
import java.net.URL

/**
 * Fetches mobile malware C2 domain indicators from Zimperium's IOC repository.
 *
 * Each campaign directory contains a `C2.txt` file with one domain/IP per line.
 * Known campaigns are hardcoded to avoid GitHub API rate limits.
 */
class ZimperiumIocFeed : DomainIocFeed {

    override val sourceId = SOURCE_ID

    @Suppress("TooGenericExceptionCaught")
    override suspend fun fetch(): List<DomainIocEntry> = withContext(Dispatchers.IO) {
        try {
            val now = System.currentTimeMillis()
            coroutineScope {
                campaigns.map { campaign ->
                    async {
                        try {
                            val url = "$RAW_BASE_URL$campaign/C2.txt"
                            val body = httpGet(url) ?: return@async emptyList()
                            parseC2(body, campaign, now)
                        } catch (e: Exception) {
                            Log.w(TAG, "Failed to fetch campaign '$campaign': ${e.message}")
                            emptyList()
                        }
                    }
                }.flatMap { it.await() }
            }
        } catch (e: Exception) {
            Log.e(TAG, "ZimperiumIocFeed.fetch failed: ${e.message}")
            emptyList()
        }
    }

    /**
     * Parses a C2.txt file: one domain or IP per line, skipping comments and blanks.
     */
    internal fun parseC2(text: String, campaign: String, fetchedAt: Long): List<DomainIocEntry> {
        return text.lines()
            .map { it.trim() }
            .filter { it.isNotEmpty() && !it.startsWith("#") }
            .map { domain ->
                DomainIocEntry(
                    domain = domain.lowercase(),
                    campaignName = campaign,
                    severity = "CRITICAL",
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
        private const val TAG = "ZimperiumIocFeed"
        const val SOURCE_ID = "zimperium"
        private const val RAW_BASE_URL =
            "https://raw.githubusercontent.com/AlfredoRR/IOC/main/"
        private const val TIMEOUT_MS = 15_000
        private const val USER_AGENT = "AndroDR/1.0"

        internal val campaigns = listOf(
            "Banking-Heist", "FakeCall", "TrickMo", "AppLite",
            "Crocodilus", "BTMOB-RAT", "NFCStealer", "DroidLock"
        )
    }
}
