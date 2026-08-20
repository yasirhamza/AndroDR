package com.androdr.ioc

import android.content.Context
import android.util.Log
import com.androdr.R
import dagger.hilt.android.qualifiers.ApplicationContext
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.snakeyaml.engine.v2.api.Load
import org.snakeyaml.engine.v2.api.LoadSettings
import java.net.URI
import java.util.Locale
import java.util.concurrent.atomic.AtomicReference
import javax.inject.Inject
import javax.inject.Singleton

/**
 * Brand impersonation registry (#299): display-name variants and official
 * domains of impersonation-protected brands (financial/payment).
 *
 * Backs the `brand_name_db` and `brand_domain_db` SIGMA lookups. Follows the
 * OemPrefixResolver delivery model: bundled res/raw seeds for cold start, a
 * direct remote refresh of the two ioc-data files on the 12h intel cycle,
 * and an in-memory AtomicReference swap — no Room.
 *
 * Matching semantics (spec docs/superpowers/specs/2026-08-20-299):
 *  - names: word-boundary, case-insensitive containment of a variant in the
 *    emitted app label ("Chase Bank" matches "Chase Bank Login", never
 *    "Purchase Tracker");
 *  - domains: host of the scope URL, label-boundary suffix walk
 *    ("paypal.com" matches "www.paypal.com", never "notpaypal.com").
 */
@Singleton
class BrandImpersonationResolver @Inject constructor(
    @ApplicationContext private val context: Context,
) {

    /** Pure matching core — constructible without a Context for tests. */
    class BrandMatcher(nameVariants: List<String>, private val domains: Set<String>) {

        private val variantPatterns: List<Regex> = nameVariants
            .filter { it.isNotBlank() }
            .take(MAX_NAME_VARIANTS)
            .map {
                Regex(
                    "(?<![\\p{L}\\p{N}])" + Regex.escape(it) + "(?![\\p{L}\\p{N}])",
                    RegexOption.IGNORE_CASE
                )
            }

        fun matchesName(label: String): Boolean {
            if (label.isBlank()) return false
            return variantPatterns.any { it.containsMatchIn(label) }
        }

        @Suppress("SwallowedException", "TooGenericExceptionCaught")
        fun matchesDomain(scopeUrl: String): Boolean {
            val host = if (scopeUrl.isBlank()) {
                null
            } else {
                try {
                    URI(scopeUrl.trim()).host
                } catch (e: Exception) {
                    null
                }
            } ?: return false
            // Label-boundary suffix walk (same semantics as BlocklistManager):
            // strip the leftmost label until a listed domain is hit.
            var candidate = host.trimEnd('.').lowercase(Locale.ROOT)
            while (candidate.isNotEmpty()) {
                if (candidate in domains) return true
                val dot = candidate.indexOf('.')
                if (dot < 0) break
                candidate = candidate.substring(dot + 1)
            }
            return false
        }
    }

    private val bundled: BrandMatcher by lazy {
        BrandMatcher(
            nameVariants = parseBrandYaml(readRawResource(R.raw.brand_names), KEY_NAMES),
            domains = parseBrandYaml(readRawResource(R.raw.brand_domains), KEY_DOMAINS)
                .map { it.lowercase(Locale.ROOT) }.toSet(),
        )
    }

    private val remote = AtomicReference<BrandMatcher?>(null)

    private fun effective(): BrandMatcher = remote.get() ?: bundled

    fun matchesBrandName(label: String): Boolean = effective().matchesName(label)

    fun matchesBrandDomain(scopeUrl: String): Boolean = effective().matchesDomain(scopeUrl)

    /**
     * Fetch the two ioc-data files from rules main and swap them in. Either
     * fetch failing (or yielding an empty parse) keeps the previous state —
     * a partial registry must never replace a fuller one.
     *
     * @return name variants accepted this run, 0 on any failure — a real
     * success signal for feed-health recording (the "empty is failure"
     * contract, cf. OemPrefixResolver.refresh).
     */
    suspend fun refresh(): Int = withContext(Dispatchers.IO) {
        val namesYaml =
            SafeHttpFetch.fetch(NAMES_URL, maxBytes = MAX_FETCH_BYTES, timeoutMs = TIMEOUT_MS)
        val domainsYaml =
            SafeHttpFetch.fetch(DOMAINS_URL, maxBytes = MAX_FETCH_BYTES, timeoutMs = TIMEOUT_MS)
        if (namesYaml == null || domainsYaml == null) {
            Log.w(
                TAG,
                "refresh: fetch failed (names=${namesYaml != null}, domains=${domainsYaml != null})"
            )
            return@withContext 0
        }
        val names = parseBrandYaml(namesYaml, KEY_NAMES)
        val domains = parseBrandYaml(domainsYaml, KEY_DOMAINS)
            .map { it.lowercase(Locale.ROOT) }.toSet()
        if (names.isEmpty() || domains.isEmpty()) {
            Log.w(
                TAG,
                "refresh: empty parse (names=${names.size}, domains=${domains.size}) — keeping previous state"
            )
            return@withContext 0
        }
        remote.set(BrandMatcher(names, domains))
        Log.i(TAG, "refresh: ${names.size} name variants, ${domains.size} domains")
        names.size
    }

    @Suppress("SwallowedException", "TooGenericExceptionCaught")
    private fun readRawResource(resId: Int): String = try {
        context.resources.openRawResource(resId).bufferedReader().use { it.readText() }
    } catch (e: Exception) {
        Log.w(TAG, "readRawResource failed: ${e.message}")
        ""
    }

    companion object {
        private const val TAG = "BrandImpersonation"
        private const val KEY_NAMES = "display_names"
        private const val KEY_DOMAINS = "domains"
        private const val MAX_NAME_VARIANTS = 500
        private const val MAX_LIST_VALUES = 2000
        private const val MAX_FETCH_BYTES = 262_144
        private const val TIMEOUT_MS = 15_000
        private const val NAMES_URL =
            "https://raw.githubusercontent.com/android-sigma-rules/rules/main/ioc-data/brand-names.yml"
        private const val DOMAINS_URL =
            "https://raw.githubusercontent.com/android-sigma-rules/rules/main/ioc-data/brand-domains.yml"

        /**
         * Parse the structural `brands:` shape shared by both files and
         * collect every string under [listKey] across all brands.
         */
        @Suppress("SwallowedException", "TooGenericExceptionCaught")
        internal fun parseBrandYaml(yaml: String, listKey: String): List<String> = try {
            val settings = LoadSettings.builder()
                .setAllowDuplicateKeys(false)
                .setMaxAliasesForCollections(10)
                .build()
            val doc = Load(settings).loadFromString(yaml) as? Map<*, *> ?: emptyMap<Any, Any>()
            val brands = doc["brands"] as? Map<*, *> ?: emptyMap<Any, Any>()
            brands.values.asSequence()
                .mapNotNull { it as? Map<*, *> }
                .flatMap { (it[listKey] as? List<*>).orEmpty().asSequence() }
                .mapNotNull { v -> v?.toString()?.trim()?.takeIf(String::isNotEmpty) }
                .take(MAX_LIST_VALUES)
                .toList()
        } catch (e: Exception) {
            emptyList()
        }
    }
}
