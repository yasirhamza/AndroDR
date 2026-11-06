package com.androdr.ioc.feeds

import android.util.Log
import com.androdr.data.model.DomainIocEntry
import com.androdr.ioc.DomainIocFeed
import com.androdr.ioc.MvtCampaigns
import com.androdr.util.readTextCapped
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.withContext
import org.json.JSONArray
import org.json.JSONObject
import java.net.HttpURLConnection
import java.net.URL

/**
 * Fetches mercenary spyware domain indicators from the MVT project's indicators.yaml index,
 * which references multiple STIX2 files (Pegasus, Predator, RCS Lab, etc.).
 *
 * Both [parseIndicatorsYaml] and [parseStix2] are `internal` so unit tests can reach them
 * directly from the `test` source set without reflection.
 */
class MvtIndicatorsFeed : DomainIocFeed {

    override val sourceId = SOURCE_ID

    @Suppress("TooGenericExceptionCaught")
    override suspend fun fetch(): List<DomainIocEntry> = withContext(Dispatchers.IO) {
        try {
            val yaml = httpGet(INDICATORS_YAML_URL) ?: return@withContext emptyList()
            val campaigns = allowedCampaigns(parseIndicatorsYaml(yaml))
            if (campaigns.isEmpty()) return@withContext emptyList()

            val now = System.currentTimeMillis()
            coroutineScope {
                campaigns.map { campaign ->
                    async {
                        try {
                            val stix2 = httpGet(campaign.url) ?: return@async emptyList()
                            entriesFor(campaign, stix2, now)
                        } catch (e: Exception) {
                            Log.w(TAG, "Failed to fetch campaign '${campaign.name}': ${e.message}")
                            emptyList()
                        }
                    }
                }.flatMap { it.await() }
            }
        } catch (e: Exception) {
            Log.e(TAG, "MvtIndicatorsFeed.fetch failed: ${e.message}")
            emptyList()
        }
    }

    // ── Parsers (internal for testability) ────────────────────────────────────

    internal data class CampaignRef(val name: String, val url: String)

    /**
     * Parses `indicators.yaml` line-by-line and returns one [CampaignRef] per
     * `type: github` entry, with the raw GitHub URL constructed from the `github:` block.
     */
    internal fun parseIndicatorsYaml(yaml: String): List<CampaignRef> {
        val results = mutableListOf<CampaignRef>()
        var isGithubType = false
        var currentName = ""
        var owner = ""; var repo = ""; var branch = ""; var path = ""

        fun flush() {
            if (isGithubType && currentName.isNotEmpty() &&
                owner.isNotEmpty() && repo.isNotEmpty() && branch.isNotEmpty() && path.isNotEmpty()
            ) {
                results.add(CampaignRef(
                    name = currentName,
                    url = "https://raw.githubusercontent.com/$owner/$repo/$branch/$path"
                ))
            }
            isGithubType = false; currentName = ""; owner = ""; repo = ""; branch = ""; path = ""
        }

        for (line in yaml.lines()) {
            val trimmed = line.trim()
            when {
                trimmed == "-" -> flush()
                trimmed.startsWith("type:") -> {
                    val v = trimmed.removePrefix("type:").trim()
                    if (v == "github") isGithubType = true
                }
                trimmed.startsWith("name:") -> currentName = trimmed.removePrefix("name:").trim()
                trimmed.startsWith("owner:") -> owner = trimmed.removePrefix("owner:").trim()
                trimmed.startsWith("repo:")  -> repo  = trimmed.removePrefix("repo:").trim()
                trimmed.startsWith("branch:")-> branch= trimmed.removePrefix("branch:").trim()
                trimmed.startsWith("path:")  -> path  = trimmed.removePrefix("path:").trim()
            }
        }
        flush()
        return results
    }

    /**
     * The refs whose URL lives in one of the repos the upstream registry is known
     * to point at (PASTA F-004). The SPKI pin vouches for the TLS host, not for
     * which owner/repo a fetched `indicators.yaml` names, so a poisoned registry
     * must not turn this feed into a fetcher of arbitrary repositories. Kept out
     * of [parseIndicatorsYaml] so the parser stays a pure function of the yaml.
     */
    internal fun allowedCampaigns(refs: List<CampaignRef>): List<CampaignRef> =
        refs.filter { ref -> ALLOWED_CAMPAIGN_PREFIXES.any { ref.url.startsWith(it) } }
            .also { kept -> if (kept.size < refs.size) Log.w(TAG, "Dropped ${refs.size - kept.size} campaign ref(s) outside the allowed repos") }

    /** Rows for one collection, stamped with its compiled campaign key (or none). */
    internal fun entriesFor(ref: CampaignRef, stix: String, now: Long): List<DomainIocEntry> =
        parseStix2(stix, ref.name, toSlug(ref.name), now,
            campaignKey = MvtCampaigns.keyFor(ref.name, ref.url).orEmpty())

    /**
     * Parses a STIX2 bundle JSON string and returns one [DomainIocEntry] per domain found
     * in `indicator` objects with `pattern_type == "stix"`.
     *
     * Handles both single-domain patterns `[domain-name:value = 'foo.com']`
     * and compound OR patterns `[... OR domain-name:value = 'bar.com']` via `findAll`.
     */
    @Suppress("TooGenericExceptionCaught", "SwallowedException")
    internal fun parseStix2(
        json: String,
        campaignName: String,
        source: String,
        fetchedAt: Long,
        campaignKey: String = ""
    ): List<DomainIocEntry> {
        return try {
            val objects: JSONArray = JSONObject(json).optJSONArray("objects") ?: return emptyList()
            val results = mutableListOf<DomainIocEntry>()
            @Suppress("LoopWithTooManyJumpStatements")
            for (i in 0 until objects.length()) {
                val obj = objects.getJSONObject(i)
                if (obj.optString("type") != "indicator") continue
                if (obj.optString("pattern_type") != "stix") continue
                val pattern = obj.optString("pattern")
                DOMAIN_REGEX.findAll(pattern).forEach { match ->
                    results.add(DomainIocEntry(
                        domain = match.groupValues[1].lowercase(),
                        campaignName = campaignName,
                        campaignKey = campaignKey,
                        severity = "CRITICAL",
                        source = source,
                        fetchedAt = fetchedAt
                    ))
                }
            }
            results
        } catch (e: Exception) {
            Log.w(TAG, "parseStix2 failed: ${e.message}")
            emptyList()
        }
    }

    // ── Private helpers ────────────────────────────────────────────────────────

    @Suppress("TooGenericExceptionCaught", "SwallowedException")
    private fun httpGet(url: String): String? = try {
        (URL(url).openConnection() as HttpURLConnection).run {
            connectTimeout = 15_000; readTimeout = 15_000
            requestMethod = "GET"
            setRequestProperty("User-Agent", "AndroDR/1.0")
            try {
                if (responseCode != HttpURLConnection.HTTP_OK) {
                    Log.w(TAG, "HTTP $responseCode from $url"); null
                } else {
                    // Capped: the largest live collection is ~4.7 MB (stalkerware.stix2,
                    // 2026-11); a body past the cap is dropped, not buffered (F-004).
                    inputStream.bufferedReader().readTextCapped(MAX_RESPONSE_CHARS)
                }
            } finally { disconnect() }
        }
    } catch (e: Exception) {
        Log.w(TAG, "httpGet failed for $url: ${e.message}"); null
    }

    private fun toSlug(name: String) =
        "mvt_" + name.lowercase().replace(Regex("[^a-z0-9]+"), "_").trim('_')

    companion object {
        private const val TAG = "MvtIndicatorsFeed"
        const val SOURCE_ID = "mvt_indicators"
        private const val INDICATORS_YAML_URL =
            "https://raw.githubusercontent.com/mvt-project/mvt-indicators/main/indicators.yaml"
        private const val MAX_RESPONSE_CHARS = 16 * 1024 * 1024

        /**
         * Repos a campaign ref may point at: exactly the owners the live registry
         * referenced when this was measured (mvt-project 14, AmnestyTech 4,
         * AssoEchap 1 — 2026-11-06). Trailing slash so `mvt-indicators-evil` does
         * not pass as `mvt-indicators`.
         */
        internal val ALLOWED_CAMPAIGN_PREFIXES = listOf(
            "https://raw.githubusercontent.com/mvt-project/mvt-indicators/",
            "https://raw.githubusercontent.com/AmnestyTech/investigations/",
            "https://raw.githubusercontent.com/AssoEchap/stalkerware-indicators/",
        )
        private val DOMAIN_REGEX = Regex("""domain-name:value\s*=\s*'([^']+)'""")
    }
}
