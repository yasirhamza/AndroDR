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
 * Expected CSV format (first row is a header):
 *   Package name,Classification,Version,SHA256
 *   com.example.spy,stalkerware,,
 */
class StalkerwareIndicatorsFeed : IocFeed {

    override val sourceId = SOURCE_ID

    override suspend fun fetch(): List<IocEntry> = withContext(Dispatchers.IO) {
        try {
            val connection = (URL(CSV_URL).openConnection() as HttpURLConnection).apply {
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
                connection.inputStream.bufferedReader().use { reader ->
                    reader.lineSequence()
                        .drop(1) // skip header row
                        .mapNotNull { line -> parseLine(line, now) }
                        .toList()
                }
            } finally {
                connection.disconnect()
            }
        } catch (e: Exception) {
            Log.e(TAG, "Failed to fetch stalkerware indicators: ${e.message}")
            emptyList()
        }
    }

    private fun parseLine(line: String, fetchedAt: Long): IocEntry? {
        val cols = line.split(",")
        if (cols.size < 2) return null
        val packageName = cols[0].trim()
        val classificationRaw = cols[1].trim()
        // Require at least two dots to filter out header artifacts and short strings
        if (packageName.count { it == '.' } < 1 || !packageName.contains('.')) return null
        val classificationUpper = classificationRaw.uppercase()
        val category = when {
            classificationUpper.contains("STALKER") -> "STALKERWARE"
            classificationUpper.contains("SPYWARE") -> "SPYWARE"
            classificationUpper.contains("MONITOR") -> "MONITORING"
            else -> "STALKERWARE"
        }
        val displayName = packageName.substringAfterLast('.').replaceFirstChar { it.uppercase() }
        return IocEntry(
            packageName = packageName,
            name = displayName,
            category = category,
            severity = "CRITICAL",
            description = "Listed in the community stalkerware-indicators database " +
                "(classification: $classificationRaw). " +
                "See https://github.com/AssoEchap/stalkerware-indicators",
            source = sourceId,
            fetchedAt = fetchedAt
        )
    }

    companion object {
        private const val TAG = "StalkerwareIndicatorsFeed"
        const val SOURCE_ID = "stalkerware_indicators"
        private const val CSV_URL =
            "https://raw.githubusercontent.com/AssoEchap/stalkerware-indicators/master/generated/ioc.csv"
    }
}
