package com.androdr.ioc.feeds

import android.util.Log
import com.androdr.data.model.KnownAppCategory
import com.androdr.data.model.KnownAppEntry
import com.androdr.ioc.KnownAppFeed
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.json.JSONObject
import java.net.HttpURLConnection
import java.net.URL

class PlexusKnownAppFeed : KnownAppFeed {

    override val sourceId = SOURCE_ID

    data class PlexusMeta(val currentPage: Int, val totalPages: Int)

    @Suppress("TooGenericExceptionCaught")
    override suspend fun fetch(): List<KnownAppEntry> = withContext(Dispatchers.IO) {
        val collected = mutableListOf<KnownAppEntry>()
        var page = 1
        try {
            @Suppress("LoopWithTooManyJumpStatements")
            do {
                val raw = httpGet("$PLEXUS_BASE_URL&page=$page")
                    ?: break
                val parsed = parsePlexusPage(raw) ?: break
                collected.addAll(parsed.first)
                val meta = parsed.second
                if (meta.currentPage >= meta.totalPages) break
                page++
            } while (true)
        } catch (e: Exception) {
            Log.w(TAG, "PlexusKnownAppFeed.fetch failed on page $page: ${e.message}")
        }
        Log.i(TAG, "Plexus: collected ${collected.size} entries across $page page(s)")
        collected
    }

    @Suppress("TooGenericExceptionCaught", "SwallowedException")
    internal fun parsePlexusPage(raw: String): Pair<List<KnownAppEntry>, PlexusMeta>? {
        return try {
            val root = JSONObject(raw)
            val dataArray = root.optJSONArray("data") ?: return null
            val metaObj   = root.optJSONObject("meta") ?: return null
            val now = System.currentTimeMillis()
            val entries = mutableListOf<KnownAppEntry>()
            for (i in 0 until dataArray.length()) {
                val app = dataArray.getJSONObject(i)
                val pkg = app.optString("package")
                if (pkg.isBlank()) continue
                val name = app.optString("name").ifBlank { pkg }
                entries.add(
                    KnownAppEntry(
                        packageName = pkg,
                        displayName = name,
                        category    = KnownAppCategory.USER_APP,
                        sourceId    = SOURCE_ID,
                        fetchedAt   = now
                    )
                )
            }
            val meta = PlexusMeta(
                currentPage = metaObj.optInt("current_page", 1),
                totalPages  = metaObj.optInt("total_pages", 1)
            )
            Pair(entries, meta)
        } catch (e: Exception) {
            Log.w(TAG, "parsePlexusPage failed: ${e.message}")
            null
        }
    }

    @Suppress("TooGenericExceptionCaught", "SwallowedException")
    private fun httpGet(url: String): String? = try {
        (URL(url).openConnection() as HttpURLConnection).run {
            connectTimeout = 15_000; readTimeout = 30_000
            requestMethod = "GET"
            setRequestProperty("User-Agent", "AndroDR/1.0")
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
        private const val TAG = "PlexusKnownAppFeed"
        const val SOURCE_ID = "plexus"
        private const val PLEXUS_BASE_URL = "https://plexus.techlore.tech/api/v1/apps?limit=500"
    }
}
