package com.androdr.ioc

import android.content.Context
import android.util.Log
import com.androdr.R
import dagger.hilt.android.qualifiers.ApplicationContext
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import org.snakeyaml.engine.v2.api.Load
import org.snakeyaml.engine.v2.api.LoadSettings
import java.io.File
import javax.inject.Inject
import javax.inject.Singleton

/**
 * One mercenary-check row: a `campaigns.yml` key, its display label, the aliases that fold into it,
 * and the rule services that can make it DETECTED (#394). [detectedBy] null = the source predates
 * the field (render today's row); empty = patch level only, no infection check exists.
 */
data class Campaign(
    val key: String,
    val label: String,
    val aliases: List<String> = emptyList(),
    val detectedBy: List<String>? = null,
)

/**
 * The campaign vocabulary (spec section 3.1a): `ioc-data/campaigns.yml`, cached in
 * `filesDir/campaigns.yml` by [PublicRepoIocFeed] only after it verified against
 * `ioc-data.sha256`, else the bundled `known_campaigns.json` (generated from the same
 * file, Task B3). Keys are re-validated and labels sanitised on every load, whatever
 * the source.
 */
@Singleton
class CampaignRegistry internal constructor(
    private val cacheFile: File,
    private val bundledJson: () -> String,
) {
    @Inject constructor(@ApplicationContext context: Context) : this(
        File(context.filesDir, CACHE_FILE_NAME),
        { context.resources.openRawResource(R.raw.known_campaigns).bufferedReader().use { it.readText() } },
    )

    /** Cached vocabulary if present and valid, else the bundled one. Never empty unless the bundle is. */
    fun campaigns(): List<Campaign> = cached().ifEmpty { parseBundled(bundledJson()) }

    /** The key a campaign name or alias belongs to, or null if the vocabulary does not know it. */
    fun keyFor(nameOrAlias: String): String? {
        val name = nameOrAlias.lowercase()
        return campaigns().firstOrNull { name == it.key || name in it.aliases }?.key
    }

    /**
     * Caches [yaml] — content that already verified against the manifest — for later loads.
     * Returns false, leaving any previous cache in place, when it parses to no campaigns.
     */
    @Suppress("TooGenericExceptionCaught")
    fun storeVerified(yaml: String): Boolean {
        if (parseYaml(yaml).isEmpty()) return false
        return try {
            val tmp = File(cacheFile.parentFile, "${cacheFile.name}.tmp")
            tmp.writeText(yaml, Charsets.UTF_8)
            tmp.renameTo(cacheFile) || run { tmp.delete(); false }
        } catch (e: Exception) {
            Log.w(TAG, "Could not cache campaigns.yml: ${e.message}")
            false
        }
    }

    @Suppress("TooGenericExceptionCaught")
    private fun cached(): List<Campaign> = try {
        if (cacheFile.isFile) parseYaml(cacheFile.readText(Charsets.UTF_8)) else emptyList()
    } catch (e: Exception) {
        Log.w(TAG, "Unreadable cached campaigns.yml, using the bundled list: ${e.message}")
        emptyList()
    }

    companion object {
        private const val TAG = "CampaignRegistry"
        const val CACHE_FILE_NAME = "campaigns.yml"
        private val KEY = Regex("^[a-z0-9_-]{1,32}$")
        private val SERVICE = Regex("^[a-z_]{1,32}$")
        private const val MAX_LABEL = 40

        /**
         * What an invalid `detected_by` value becomes. It matches [SERVICE] but names no service this
         * build knows, so the row reads "not checked" instead of the list silently narrowing (#394).
         */
        internal const val UNKNOWN_SERVICE = "unknown"

        private data class RawCampaign(
            val key: String?, val label: String?, val aliases: List<String>, val detectedBy: List<String>?,
        )

        /** Parses the bundled `known_campaigns.json` (`[{key, label, aliases, detected_by}]`). Empty on any error. */
        @Suppress("TooGenericExceptionCaught", "SwallowedException")
        internal fun parseBundled(json: String): List<Campaign> = try {
            val entries = Json.parseToJsonElement(json) as? JsonArray ?: JsonArray(emptyList())
            validated(entries.mapNotNull { el ->
                val o = el as? JsonObject ?: return@mapNotNull null
                RawCampaign(
                    (o["key"] as? JsonPrimitive)?.content,
                    (o["label"] as? JsonPrimitive)?.content,
                    (o["aliases"] as? JsonArray)?.mapNotNull { (it as? JsonPrimitive)?.content }.orEmpty(),
                    detectedBy = (o["detected_by"] as? JsonArray)?.map { v ->
                        (v as? JsonPrimitive)?.takeIf { it.isString }?.content ?: UNKNOWN_SERVICE
                    },
                )
            })
        } catch (e: Exception) {
            Log.w(TAG, "Invalid bundled campaign list: ${e.message}")
            emptyList()
        }

        /** Parses `campaigns.yml` (`campaigns: [{key, label, aliases, detected_by}]`). Empty on any error. */
        @Suppress("TooGenericExceptionCaught", "SwallowedException")
        internal fun parseYaml(yaml: String): List<Campaign> = try {
            val settings = LoadSettings.builder().setAllowDuplicateKeys(false).setMaxAliasesForCollections(10).build()
            val doc = Load(settings).loadFromString(yaml) as? Map<*, *>
            val entries = doc?.get("campaigns") as? List<*> ?: emptyList<Any>()
            validated(entries.mapNotNull { el ->
                val m = el as? Map<*, *> ?: return@mapNotNull null
                RawCampaign(
                    m["key"]?.toString(),
                    m["label"]?.toString(),
                    (m["aliases"] as? List<*>)?.mapNotNull { it?.toString() }.orEmpty(),
                    detectedBy = (m["detected_by"] as? List<*>)?.map { it as? String ?: UNKNOWN_SERVICE },
                )
            })
        } catch (e: Exception) {
            Log.w(TAG, "Invalid campaigns.yml: ${e.message}")
            emptyList()
        }

        private fun validated(raw: List<RawCampaign>): List<Campaign> =
            raw.mapNotNull { r ->
                val key = r.key
                if (key == null || !KEY.matches(key)) return@mapNotNull null
                val clean = IocSanitizer.clean(r.label.orEmpty()).takeCodePoints(MAX_LABEL).trim()
                Campaign(
                    key = key,
                    label = clean.ifEmpty { key.replaceFirstChar { it.uppercase() } },
                    aliases = r.aliases.filter { KEY.matches(it) && it != key }.distinct().sorted(),
                    detectedBy = r.detectedBy?.map { if (SERVICE.matches(it)) it else UNKNOWN_SERVICE }
                        ?.distinct()?.sorted(),
                )
            }.distinctBy { it.key }.sortedBy { it.key } // same row order whichever source loaded

        private fun String.takeCodePoints(n: Int): String =
            if (codePointCount(0, length) <= n) this else substring(0, offsetByCodePoints(0, n))
    }
}
