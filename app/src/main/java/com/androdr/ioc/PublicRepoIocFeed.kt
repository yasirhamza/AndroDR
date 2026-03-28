// app/src/main/java/com/androdr/ioc/PublicRepoIocFeed.kt
package com.androdr.ioc

import android.util.Log
import com.androdr.data.db.CertHashIocEntryDao
import com.androdr.data.db.DomainIocEntryDao
import com.androdr.data.db.IocEntryDao
import com.androdr.data.model.CertHashIocEntry
import com.androdr.data.model.DomainIocEntry
import com.androdr.data.model.IocEntry
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.snakeyaml.engine.v2.api.Load
import org.snakeyaml.engine.v2.api.LoadSettings
import java.net.HttpURLConnection
import java.net.URL
import javax.inject.Inject
import javax.inject.Singleton

/**
 * Fetches IOC data from the public android-sigma-rules repo's ioc-data/ directory.
 * Parses YAML entries and upserts into Room IOC tables alongside other feeds.
 */
@Singleton
class PublicRepoIocFeed @Inject constructor(
    private val iocEntryDao: IocEntryDao,
    private val domainIocEntryDao: DomainIocEntryDao,
    private val certHashIocEntryDao: CertHashIocEntryDao
) {

    @Suppress("TooGenericExceptionCaught")
    suspend fun update(): Int = withContext(Dispatchers.IO) {
        var total = 0
        val now = System.currentTimeMillis()

        try {
            total += fetchAndUpsertPackages(now)
            total += fetchAndUpsertDomains(now)
            total += fetchAndUpsertCertHashes(now)
            Log.i(TAG, "Public repo IOC feed: $total entries upserted")
        } catch (e: Exception) {
            Log.w(TAG, "Public repo IOC feed failed: ${e.message}")
        }

        total
    }

    @Suppress("TooGenericExceptionCaught", "SwallowedException")
    private suspend fun fetchAndUpsertPackages(fetchedAt: Long): Int {
        val yaml = fetchUrl("${BASE_URL}ioc-data/package-names.yml") ?: return 0
        val entries = parseIocYaml(yaml)
        if (entries.isEmpty()) return 0

        val iocEntries = entries.map { entry ->
            IocEntry(
                packageName = entry["indicator"]?.toString() ?: return@map null,
                name = entry["family"]?.toString() ?: "",
                category = entry["category"]?.toString() ?: "MALWARE",
                severity = entry["severity"]?.toString() ?: "CRITICAL",
                description = entry["description"]?.toString() ?: "",
                source = SOURCE_ID,
                fetchedAt = fetchedAt
            )
        }.filterNotNull()

        if (iocEntries.isNotEmpty()) {
            iocEntryDao.upsertAll(iocEntries)
            iocEntryDao.deleteStaleEntries(SOURCE_ID, fetchedAt - 1)
        }
        return iocEntries.size
    }

    @Suppress("TooGenericExceptionCaught", "SwallowedException")
    private suspend fun fetchAndUpsertDomains(fetchedAt: Long): Int {
        val yaml = fetchUrl("${BASE_URL}ioc-data/c2-domains.yml") ?: return 0
        val entries = parseIocYaml(yaml)
        if (entries.isEmpty()) return 0

        val domainEntries = entries.map { entry ->
            DomainIocEntry(
                domain = entry["indicator"]?.toString()?.lowercase() ?: return@map null,
                campaignName = entry["family"]?.toString() ?: "",
                severity = entry["severity"]?.toString() ?: "CRITICAL",
                source = SOURCE_ID,
                fetchedAt = fetchedAt
            )
        }.filterNotNull()

        if (domainEntries.isNotEmpty()) {
            domainIocEntryDao.upsertAll(domainEntries)
            domainIocEntryDao.deleteStaleEntries(SOURCE_ID, fetchedAt - 1)
        }
        return domainEntries.size
    }

    @Suppress("TooGenericExceptionCaught", "SwallowedException")
    private suspend fun fetchAndUpsertCertHashes(fetchedAt: Long): Int {
        val yaml = fetchUrl("${BASE_URL}ioc-data/cert-hashes.yml") ?: return 0
        val entries = parseIocYaml(yaml)
        if (entries.isEmpty()) return 0

        val certEntries = entries.map { entry ->
            CertHashIocEntry(
                certHash = entry["indicator"]?.toString()?.lowercase() ?: return@map null,
                familyName = entry["family"]?.toString() ?: "",
                category = entry["category"]?.toString() ?: "MALWARE",
                severity = entry["severity"]?.toString() ?: "CRITICAL",
                description = entry["description"]?.toString() ?: "",
                source = SOURCE_ID,
                fetchedAt = fetchedAt
            )
        }.filterNotNull()

        if (certEntries.isNotEmpty()) {
            certHashIocEntryDao.upsertAll(certEntries)
            certHashIocEntryDao.deleteStaleEntries(SOURCE_ID, fetchedAt - 1)
        }
        return certEntries.size
    }

    @Suppress("UNCHECKED_CAST", "TooGenericExceptionCaught", "SwallowedException")
    internal fun parseIocYaml(yamlContent: String): List<Map<String, Any>> {
        return try {
            val load = Load(LoadSettings.builder().build())
            val doc = load.loadFromString(yamlContent) as? Map<String, Any> ?: return emptyList()
            (doc["entries"] as? List<Map<String, Any>>) ?: emptyList()
        } catch (e: Exception) {
            Log.w(TAG, "Failed to parse IOC YAML: ${e.message}")
            emptyList()
        }
    }

    @Suppress("TooGenericExceptionCaught", "SwallowedException")
    private fun fetchUrl(url: String): String? {
        return try {
            val conn = URL(url).openConnection() as HttpURLConnection
            conn.connectTimeout = TIMEOUT_MS
            conn.readTimeout = TIMEOUT_MS
            conn.setRequestProperty("User-Agent", "AndroDR/1.0")
            if (conn.responseCode == HttpURLConnection.HTTP_OK) {
                conn.inputStream.bufferedReader().use { it.readText() }
            } else {
                null
            }
        } catch (e: Exception) {
            Log.w(TAG, "HTTP fetch failed for $url: ${e.message}")
            null
        }
    }

    companion object {
        private const val TAG = "PublicRepoIocFeed"
        const val SOURCE_ID = "androdr_public_repo"
        private const val BASE_URL =
            "https://raw.githubusercontent.com/android-sigma-rules/rules/main/"
        private const val TIMEOUT_MS = 15_000
    }
}
