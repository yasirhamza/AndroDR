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

class UadKnownAppFeed : KnownAppFeed {

    override val sourceId = SOURCE_ID

    @Suppress("TooGenericExceptionCaught")
    override suspend fun fetch(): List<KnownAppEntry> = withContext(Dispatchers.IO) {
        try {
            val raw = httpGet(UAD_URL) ?: return@withContext emptyList()
            parseUadJson(raw)
        } catch (e: Exception) {
            Log.w(TAG, "UadKnownAppFeed.fetch failed: ${e.message}")
            emptyList()
        }
    }

    @Suppress("TooGenericExceptionCaught", "SwallowedException")
    internal fun parseUadJson(raw: String): List<KnownAppEntry> {
        return try {
            val root = JSONObject(raw)
            val now = System.currentTimeMillis()
            val results = mutableListOf<KnownAppEntry>()
            root.keys().forEach { packageName ->
                val obj = root.optJSONObject(packageName) ?: return@forEach
                // UAD-ng upstream JSON emits title-case list values.
                // See uad_lists.json: values are "Oem", "Aosp", "Carrier", "Misc", "Google".
                // Earlier revisions checked "OEM"/"AOSP" which silently dropped ~83% of
                // UAD entries, causing Samsung-preloaded apps (Netflix, Facebook, etc.) to
                // fall back to Plexus's USER_APP classification and trip App Impersonation FPs.
                val listField = obj.optString("list")
                val category = when (listField) {
                    "Oem", "Carrier", "Misc" -> KnownAppCategory.OEM
                    "Aosp"                   -> KnownAppCategory.AOSP
                    "Google"                 -> KnownAppCategory.GOOGLE
                    else                     -> return@forEach
                }
                val displayName = obj.optString("description").ifBlank { packageName }
                results.add(
                    KnownAppEntry(
                        packageName = packageName,
                        displayName = displayName,
                        category    = category,
                        sourceId    = SOURCE_ID,
                        fetchedAt   = now
                    )
                )
            }
            results
        } catch (e: Exception) {
            Log.w(TAG, "parseUadJson failed: ${e.message}")
            emptyList()
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
        private const val TAG = "UadKnownAppFeed"
        const val SOURCE_ID = "uad_ng"
        private const val UAD_URL =
            "https://raw.githubusercontent.com/Universal-Debloater-Alliance/" +
            "universal-android-debloater-next-generation/main/resources/assets/uad_lists.json"
    }
}
