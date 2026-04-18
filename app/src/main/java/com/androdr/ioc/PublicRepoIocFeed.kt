package com.androdr.ioc

import android.util.Log
import com.androdr.data.db.IndicatorDao
import com.androdr.data.db.KnownAppDbEntry
import com.androdr.data.db.KnownAppEntryDao
import com.androdr.data.model.Indicator
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.snakeyaml.engine.v2.api.Load
import org.snakeyaml.engine.v2.api.LoadSettings
import javax.inject.Inject
import javax.inject.Singleton

/**
 * Fetches IOC data from the public android-sigma-rules repo's ioc-data/ directory.
 * Parses YAML entries and upserts into the unified indicators table.
 */
@Singleton
class PublicRepoIocFeed @Inject constructor(
    private val indicatorDao: IndicatorDao,
    private val knownAppEntryDao: KnownAppEntryDao
) {

    @Suppress("TooGenericExceptionCaught")
    suspend fun update(): Int = withContext(Dispatchers.IO) {
        var total = 0
        val now = System.currentTimeMillis()

        try {
            total += fetchAndUpsertPackages(now)
            total += fetchAndUpsertDomains(now)
            total += fetchAndUpsertCertHashes(now)
            total += fetchAndUpsertApkHashes(now)
            total += fetchAndUpsertPopularApps(now)
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

        val indicators = entries.mapNotNull { entry ->
            val indicator = entry["indicator"]?.toString() ?: return@mapNotNull null
            Indicator(
                type = IndicatorResolver.TYPE_PACKAGE, value = indicator,
                name = entry["family"]?.toString() ?: "",
                campaign = entry["category"]?.toString() ?: "MALWARE",
                severity = entry["severity"]?.toString() ?: "CRITICAL",
                description = entry["description"]?.toString() ?: "",
                source = SOURCE_ID, fetchedAt = fetchedAt
            )
        }

        if (indicators.isNotEmpty()) {
            indicatorDao.upsertAll(indicators)
            indicatorDao.deleteStaleEntries(SOURCE_ID, fetchedAt - 1)
        }
        return indicators.size
    }

    @Suppress("TooGenericExceptionCaught", "SwallowedException")
    private suspend fun fetchAndUpsertDomains(fetchedAt: Long): Int {
        val yaml = fetchUrl("${BASE_URL}ioc-data/c2-domains.yml") ?: return 0
        val entries = parseIocYaml(yaml)

        val indicators = entries.mapNotNull { entry ->
            val domain = entry["indicator"]?.toString()?.lowercase() ?: return@mapNotNull null
            Indicator(
                type = IndicatorResolver.TYPE_DOMAIN, value = domain,
                name = "", campaign = entry["family"]?.toString() ?: "",
                severity = entry["severity"]?.toString() ?: "CRITICAL",
                description = "", source = SOURCE_ID, fetchedAt = fetchedAt
            )
        }

        if (indicators.isNotEmpty()) {
            indicatorDao.upsertAll(indicators)
        }
        return indicators.size
    }

    @Suppress("TooGenericExceptionCaught", "SwallowedException")
    private suspend fun fetchAndUpsertCertHashes(fetchedAt: Long): Int {
        val yaml = fetchUrl("${BASE_URL}ioc-data/cert-hashes.yml") ?: return 0
        val entries = parseIocYaml(yaml)

        val indicators = entries.mapNotNull { entry ->
            val hash = entry["indicator"]?.toString()?.lowercase() ?: return@mapNotNull null
            Indicator(
                type = IndicatorResolver.TYPE_CERT_HASH, value = hash,
                name = entry["family"]?.toString() ?: "",
                campaign = entry["category"]?.toString() ?: "MALWARE",
                severity = entry["severity"]?.toString() ?: "CRITICAL",
                description = entry["description"]?.toString() ?: "",
                source = SOURCE_ID, fetchedAt = fetchedAt
            )
        }

        if (indicators.isNotEmpty()) {
            indicatorDao.upsertAll(indicators)
        }
        return indicators.size
    }

    @Suppress("TooGenericExceptionCaught", "SwallowedException")
    private suspend fun fetchAndUpsertApkHashes(fetchedAt: Long): Int {
        val yaml = fetchUrl("${BASE_URL}ioc-data/malware-hashes.yml") ?: return 0
        val entries = parseIocYaml(yaml)

        val indicators = entries.mapNotNull { entry ->
            val hash = entry["indicator"]?.toString()?.lowercase() ?: return@mapNotNull null
            Indicator(
                type = IndicatorResolver.TYPE_APK_HASH, value = hash,
                name = entry["family"]?.toString() ?: "",
                campaign = entry["category"]?.toString() ?: "MALWARE",
                severity = entry["severity"]?.toString() ?: "CRITICAL",
                description = entry["description"]?.toString() ?: "",
                source = SOURCE_ID, fetchedAt = fetchedAt
            )
        }

        if (indicators.isNotEmpty()) {
            indicatorDao.upsertAll(indicators)
        }
        return indicators.size
    }

    @Suppress("TooGenericExceptionCaught", "SwallowedException")
    private suspend fun fetchAndUpsertPopularApps(fetchedAt: Long): Int {
        val yaml = fetchUrl("${BASE_URL}ioc-data/popular-apps.yml") ?: return 0
        val entries = parsePopularAppsYaml(yaml)

        val knownAppEntries = entries.mapNotNull { entry ->
            KnownAppDbEntry(
                packageName = entry["packageName"]?.toString() ?: return@mapNotNull null,
                displayName = entry["displayName"]?.toString() ?: "",
                category = "POPULAR",
                sourceId = SOURCE_ID,
                fetchedAt = fetchedAt
            )
        }

        if (knownAppEntries.isNotEmpty()) {
            knownAppEntryDao.upsertAll(knownAppEntries)
        }
        return knownAppEntries.size
    }

    @Suppress("UNCHECKED_CAST", "TooGenericExceptionCaught", "SwallowedException")
    internal fun parsePopularAppsYaml(yamlContent: String): List<Map<String, Any>> {
        return try {
            val settings = LoadSettings.builder()
                .setAllowDuplicateKeys(false)
                .setMaxAliasesForCollections(10)
                .build()
            val load = Load(settings)
            val doc = load.loadFromString(yamlContent) as? Map<*, *> ?: return emptyList()
            val entries = doc["entries"] as? List<*> ?: return emptyList()
            entries.mapNotNull { it as? Map<String, Any> }
        } catch (e: Exception) {
            Log.w(TAG, "Failed to parse popular apps YAML: ${e.message}")
            emptyList()
        }
    }

    @Suppress("UNCHECKED_CAST", "TooGenericExceptionCaught", "SwallowedException")
    internal fun parseIocYaml(yamlContent: String): List<Map<String, Any>> {
        return try {
            val settings = LoadSettings.builder()
                .setAllowDuplicateKeys(false)
                .setMaxAliasesForCollections(10)
                .build()
            val load = Load(settings)
            val doc = load.loadFromString(yamlContent) as? Map<*, *> ?: return emptyList()
            val entries = doc["entries"] as? List<*> ?: return emptyList()
            entries.mapNotNull { it as? Map<String, Any> }
        } catch (e: Exception) {
            Log.w(TAG, "Failed to parse IOC YAML: ${e.message}")
            emptyList()
        }
    }

    private fun fetchUrl(url: String): String? =
        SafeHttpFetch.fetch(url, maxBytes = 1_000_000, timeoutMs = TIMEOUT_MS)

    companion object {
        private const val TAG = "PublicRepoIocFeed"
        const val SOURCE_ID = "androdr_public_repo"
        private const val BASE_URL =
            "https://raw.githubusercontent.com/android-sigma-rules/rules/main/"
        private const val TIMEOUT_MS = 15_000
    }
}
