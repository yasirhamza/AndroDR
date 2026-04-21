package com.androdr.ioc.feeds

import android.util.Log
import com.androdr.data.model.IocEntry
import com.androdr.ioc.IocFeed
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.net.HttpURLConnection
import java.net.URL

/**
 * Fetches stalkerware package-name indicators from the community-maintained
 * AssoEchap/stalkerware-indicators GitHub repository.
 *
 * Parses the top-level ioc.yaml file. Each entry is a YAML mapping with a
 * `type` field and a `packages` list:
 *
 *   - name: TheTruthSpy
 *     type: stalkerware
 *     packages:
 *     - com.apspy.app
 *     - com.fone
 */
class StalkerwareIndicatorsFeed : IocFeed {

    override val sourceId = SOURCE_ID

    @Suppress("TooGenericExceptionCaught") // Network operations can throw IOException, SSLException;
    // all are logged and result in an empty list rather than crashing the update flow.
    override suspend fun fetch(): List<IocEntry> = withContext(Dispatchers.IO) {
        try {
            val connection = (URL(YAML_URL).openConnection() as HttpURLConnection).apply {
                connectTimeout = 15_000
                readTimeout = 15_000
                requestMethod = "GET"
                setRequestProperty("User-Agent", "AndroDR/1.0")
            }
            try {
                if (connection.responseCode != HttpURLConnection.HTTP_OK) {
                    Log.w(TAG, "HTTP ${connection.responseCode} from stalkerware-indicators")
                    return@withContext emptyList()
                }
                val now = System.currentTimeMillis()
                parseYaml(connection.inputStream.bufferedReader().readText(), now)
            } finally {
                connection.disconnect()
            }
        } catch (e: Exception) {
            Log.e(TAG, "Failed to fetch stalkerware indicators: ${e.message}")
            emptyList()
        }
    }

    /**
     * Delegates YAML walking to [StalkerwareYamlParser] and emits one
     * [IocEntry] per package name per family. The cert half of the same
     * feed is consumed by [StalkerwareCertHashFeed].
     */
    internal fun parseYaml(yaml: String, fetchedAt: Long): List<IocEntry> {
        val results = mutableListOf<IocEntry>()
        for (family in StalkerwareYamlParser.parse(yaml)) {
            val category = when {
                family.type.contains("stalker", ignoreCase = true) -> "STALKERWARE"
                family.type.contains("spy", ignoreCase = true)     -> "SPYWARE"
                family.type.contains("monitor", ignoreCase = true) -> "MONITORING"
                else -> "STALKERWARE"
            }
            for (pkg in family.packages) {
                val displayName = family.name.ifBlank {
                    pkg.substringAfterLast('.').replaceFirstChar { it.uppercase() }
                }
                results += IocEntry(
                    packageName = pkg,
                    name = displayName,
                    category = category,
                    severity = "CRITICAL",
                    description = "Listed in the community stalkerware-indicators " +
                        "database (type: ${family.type}). " +
                        "See https://github.com/AssoEchap/stalkerware-indicators",
                    source = sourceId,
                    fetchedAt = fetchedAt,
                )
            }
        }
        return results
    }

    companion object {
        private const val TAG = "StalkerwareIndicatorsFeed"
        const val SOURCE_ID = "stalkerware_indicators"
        private const val YAML_URL =
            "https://raw.githubusercontent.com/AssoEchap/stalkerware-indicators/master/ioc.yaml"
    }
}
