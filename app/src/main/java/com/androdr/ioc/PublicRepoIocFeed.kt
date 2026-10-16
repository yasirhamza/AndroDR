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
    private val knownAppEntryDao: KnownAppEntryDao,
    private val manifest: IocDataManifest = IocDataManifest(),
    /** Null only in tests that do not exercise the campaign vocabulary. */
    private val campaignRegistry: CampaignRegistry? = null,
) {

    /** One ioc-data file feeding one indicator type. */
    private data class IocFile(
        val path: String,
        val type: String,
        val lowercase: Boolean,
        val defaultCategory: String,
        val keepDescription: Boolean,
    )

    @Suppress("TooGenericExceptionCaught")
    suspend fun update(): UpdateResult = withContext(Dispatchers.IO) {
        var total = 0
        var evicted = 0
        val now = System.currentTimeMillis()

        try {
            for (file in IOC_FILES) {
                val (written, gone) = fetchAndUpsert(file, now)
                total += written
                evicted += gone
            }
            total += fetchAndUpsertPopularApps(now)
            Log.i(TAG, "Public repo IOC feed: $total entries upserted, $evicted evicted")
        } catch (e: Exception) {
            Log.w(TAG, "Public repo IOC feed failed: ${e.message}")
        }

        // Its own try: a failed indicator or popular-apps step must not skip the vocabulary.
        try {
            fetchCampaigns()
        } catch (c: kotlinx.coroutines.CancellationException) {
            throw c
        } catch (e: Exception) {
            Log.w(TAG, "campaigns.yml update failed: ${e.message}")
        }

        UpdateResult(written = total, evicted = evicted)
    }

    /**
     * Fetches one verified file and upserts it. Stale rows of THIS type are evicted only after
     * the file verified and parsed non-empty, so one failed or unverified file never evicts
     * another type's rows (and a bad fetch never wipes its own).
     */
    private suspend fun fetchAndUpsert(file: IocFile, fetchedAt: Long): Pair<Int, Int> {
        val yaml = manifest.verified(file.path, MAX_FILE_CHARS) ?: return 0 to 0
        val indicators = parseIocYaml(yaml).mapNotNull { entry ->
            val raw = entry["indicator"]?.toString() ?: return@mapNotNull null
            Indicator(
                type = file.type, value = if (file.lowercase) raw.lowercase() else raw,
                family = entry["family"]?.toString() ?: "",
                category = entry["category"]?.toString() ?: file.defaultCategory,
                campaignKey = entry["campaign"]?.toString() ?: "",
                severity = entry["severity"]?.toString() ?: "CRITICAL",
                description = if (file.keepDescription) entry["description"]?.toString() ?: "" else "",
                reference = entry["reference"]?.toString() ?: "",
                source = SOURCE_ID, fetchedAt = fetchedAt
            ).let(IocSanitizer::sanitize)
        }
        if (indicators.isEmpty()) return 0 to 0
        indicatorDao.upsertAll(indicators)
        val gone = indicatorDao.deleteStaleEntriesOfType(SOURCE_ID, file.type, fetchedAt - 1)
        return indicators.size to gone
    }

    /**
     * Caches `campaigns.yml` for [CampaignRegistry] only when it verifies against the manifest
     * (fail-closed, B9); otherwise the registry keeps its last good copy or the bundled list.
     */
    private suspend fun fetchCampaigns() {
        val registry = campaignRegistry ?: return
        val yaml = manifest.verified(CAMPAIGNS_PATH, MAX_FILE_CHARS) ?: return
        if (!registry.storeVerified(yaml)) Log.w(TAG, "campaigns.yml verified but held no valid campaigns")
    }

    @Suppress("TooGenericExceptionCaught", "SwallowedException")
    private suspend fun fetchAndUpsertPopularApps(fetchedAt: Long): Int {
        val yaml = manifest.verified("ioc-data/popular-apps.yml", MAX_FILE_CHARS) ?: return 0
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

    companion object {
        private const val TAG = "PublicRepoIocFeed"
        const val SOURCE_ID = "androdr_public_repo"
        private const val MAX_FILE_CHARS = 1_000_000
        private const val CAMPAIGNS_PATH = "ioc-data/campaigns.yml"
        private val IOC_FILES = listOf(
            IocFile("ioc-data/package-names.yml", IndicatorResolver.TYPE_PACKAGE, false, "MALWARE", true),
            IocFile("ioc-data/c2-domains.yml", IndicatorResolver.TYPE_DOMAIN, true, "", false),
            IocFile("ioc-data/cert-hashes.yml", IndicatorResolver.TYPE_CERT_HASH, true, "MALWARE", true),
            IocFile("ioc-data/malware-hashes.yml", IndicatorResolver.TYPE_APK_HASH, true, "MALWARE", true),
        )
    }
}

/** Outcome of one rules-repo feed run: rows written and rows evicted. */
data class UpdateResult(val written: Int, val evicted: Int)
