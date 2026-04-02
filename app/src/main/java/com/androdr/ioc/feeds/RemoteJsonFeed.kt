package com.androdr.ioc.feeds

import android.util.Log
import com.androdr.data.model.IocEntry
import com.androdr.ioc.IocFeed
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import java.net.HttpURLConnection
import java.net.URL

/**
 * Fetches IOC entries from any URL returning a JSON array whose objects have the
 * same shape as the bundled known_bad_packages.json (packageName, name, category,
 * severity, description).
 *
 * Intended for community-maintained or self-hosted feed endpoints.
 */
class RemoteJsonFeed(
    override val sourceId: String,
    private val url: String,
    private val timeoutMs: Int = 15_000
) : IocFeed {

    @Serializable
    private data class RemoteEntry(
        val packageName: String,
        val name: String,
        val category: String,
        val severity: String,
        val description: String
    )

    private val json = Json { ignoreUnknownKeys = true }

    @Suppress("TooGenericExceptionCaught") // Network/JSON operations can throw IOException,
    // SSLException, or SerializationException; all are logged and result in empty list.
    override suspend fun fetch(): List<IocEntry> = withContext(Dispatchers.IO) {
        try {
            val connection = (URL(url).openConnection() as HttpURLConnection).apply {
                connectTimeout = timeoutMs
                readTimeout = timeoutMs
                requestMethod = "GET"
                setRequestProperty("Accept", "application/json")
                setRequestProperty("User-Agent", "AndroDR/1.0")
            }
            try {
                if (connection.responseCode != HttpURLConnection.HTTP_OK) {
                    Log.w(TAG, "Feed $sourceId returned HTTP ${connection.responseCode}")
                    return@withContext emptyList()
                }
                val body = connection.inputStream.bufferedReader().use { it.readText() }
                val now = System.currentTimeMillis()
                json.decodeFromString<List<RemoteEntry>>(body).mapNotNull { entry ->
                    if (entry.packageName.isBlank()) null
                    else IocEntry(
                        packageName = entry.packageName,
                        name = entry.name,
                        category = entry.category,
                        severity = entry.severity,
                        description = entry.description,
                        source = sourceId,
                        fetchedAt = now
                    )
                }
            } finally {
                connection.disconnect()
            }
        } catch (e: Exception) {
            Log.e(TAG, "Failed to fetch feed $sourceId from $url: ${e.message}")
            emptyList()
        }
    }

    companion object {
        private const val TAG = "RemoteJsonFeed"

        /**
         * URL for the community-maintained IOC list hosted alongside this project.
         * Update this once the file exists in the repository.
         */
        const val COMMUNITY_SOURCE_ID = "community_json"
        const val COMMUNITY_URL =
            "https://raw.githubusercontent.com/android-sigma-rules/rules/main/ioc-data/package-names.yml"
    }
}
