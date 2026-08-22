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
import java.text.Normalizer
import java.util.Locale
import java.util.concurrent.atomic.AtomicReference
import javax.inject.Inject
import javax.inject.Singleton

/**
 * Brand impersonation registry (#299): display-name variants and official
 * domains of impersonation-protected brands (financial/payment).
 *
 * Backs the `brand_name_db` and `brand_domain_db` SIGMA lookups. Follows the
 * OemPrefixResolver delivery model — bundled res/raw seeds for cold start, a
 * direct remote refresh of the two ioc-data files on the 12h intel cycle, and
 * an in-memory AtomicReference swap, no Room — AND its validation model: a
 * fetch that violates the sanity bounds is rejected wholesale, never merged or
 * truncated. This matters because `brand_domain_db` is the fleet's first
 * remote input that SUPPRESSES a finding (092's `not scope_legit`): an
 * over-broad domain like `com` would blind detection globally, and ioc-data is
 * not covered by the rules.sha256 manifest, so these guards are the only
 * on-device backstop.
 *
 * Matching semantics (spec docs/superpowers/specs/2026-08-20-299):
 *  - names: word-boundary, Unicode-case-insensitive containment of a variant
 *    in the emitted app label, after stripping default-ignorable format
 *    characters and NFKC-normalising both sides ("Chase Bank" matches "Chase
 *    Bank Login" and "Pay​Pal" cannot hide from "PayPal", never
 *    "Purchase Tracker");
 *  - domains: host of the scope URL, label-boundary suffix walk ("paypal.com"
 *    matches "www.paypal.com", never "notpaypal.com").
 */
@Singleton
class BrandImpersonationResolver @Inject constructor(
    @ApplicationContext private val context: Context,
) {

    /** Pure matching core — constructible without a Context for tests. */
    internal class BrandMatcher(nameVariants: List<String>, domains: Set<String>) {

        private val variantPatterns: List<Regex> = nameVariants
            .asSequence()
            .map { normalizeLabel(it) }
            .filter { it.isNotBlank() }
            .map {
                // (?iu): Unicode-aware case folding — RegexOption.IGNORE_CASE
                // alone is ASCII-only on the JVM. \p{L}\p{N} lookarounds give
                // Unicode word boundaries. Regex.escape neutralises any regex
                // metacharacter in the (remote) variant, so no injection and
                // no catastrophic backtracking is reachable.
                Regex("(?iu)(?<![\\p{L}\\p{N}])" + Regex.escape(it) + "(?![\\p{L}\\p{N}])")
            }
            .toList()

        private val domains: Set<String> = domains.map { it.lowercase(Locale.ROOT) }.toSet()

        fun matchesName(label: String): Boolean {
            if (label.isBlank()) return false
            val normalized = normalizeLabel(label)
            return variantPatterns.any { it.containsMatchIn(normalized) }
        }

        fun matchesDomain(scopeUrl: String): Boolean {
            val host = hostOf(scopeUrl) ?: return false
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
        buildMatcher(
            parseBrandYaml(readRawResource(R.raw.brand_names), KEY_NAMES),
            parseBrandYaml(readRawResource(R.raw.brand_domains), KEY_DOMAINS),
        ) ?: BrandMatcher(emptyList(), emptySet())
    }

    private val remote = AtomicReference<BrandMatcher?>(null)

    private fun effective(): BrandMatcher = remote.get() ?: bundled

    /** True if [label] contains a protected brand variant. Null-safe: blank → false. */
    fun matchesBrandName(label: String): Boolean = effective().matchesName(label)

    /** True if [scopeUrl]'s host is inside a protected brand's official domain. Null/non-URL → false. */
    fun matchesBrandDomain(scopeUrl: String): Boolean = effective().matchesDomain(scopeUrl)

    /**
     * Fetch the two ioc-data files from rules main and swap them in. The fetch
     * is rejected wholesale (previous state kept) on any failure — a fetch
     * error, an empty parse, or a sanity violation (see [buildMatcher]). A
     * partial or malformed registry must never replace a fuller one.
     *
     * @return name variants accepted this run, 0 on any failure — a real
     * success signal for feed-health recording (the "empty is failure"
     * contract, cf. OemPrefixResolver.refresh).
     */
    suspend fun refresh(): Int = withContext(Dispatchers.IO) {
        val namesYaml = SafeHttpFetch.fetch(NAMES_URL, maxBytes = MAX_FETCH_BYTES, timeoutMs = TIMEOUT_MS)
        val domainsYaml = SafeHttpFetch.fetch(DOMAINS_URL, maxBytes = MAX_FETCH_BYTES, timeoutMs = TIMEOUT_MS)
        if (namesYaml == null || domainsYaml == null) {
            Log.w(
                TAG,
                "refresh: fetch failed (names=${namesYaml != null}, domains=${domainsYaml != null})"
            )
            return@withContext 0
        }
        val names = parseBrandYaml(namesYaml, KEY_NAMES)
        val domains = parseBrandYaml(domainsYaml, KEY_DOMAINS)
        val matcher = buildMatcher(names, domains)
        if (matcher == null) {
            Log.w(TAG, "refresh: rejected — failed sanity bounds, keeping previous state")
            return@withContext 0
        }
        remote.set(matcher)
        Log.i(TAG, "refresh: ${names.size} name variants, ${domains.size} domains")
        names.size
    }

    @Suppress("TooGenericExceptionCaught", "SwallowedException")
    private fun readRawResource(resId: Int): String = try {
        context.resources.openRawResource(resId).bufferedReader().use { it.readText() }
    } catch (e: Exception) {
        Log.w(TAG, "readRawResource failed: ${e.message}")
        ""
    }

    companion object {
        private const val TAG = "BrandImpersonationResolver"
        private const val KEY_NAMES = "display_names"
        private const val KEY_DOMAINS = "domains"
        private const val MAX_NAME_VARIANTS = 500
        private const val MAX_DOMAINS = 500
        private const val MAX_LIST_VALUES = 2000
        private const val MIN_NAME_VARIANT_LEN = 2
        private const val MAX_NAME_VARIANT_LEN = 128
        private const val MAX_FETCH_BYTES = 262_144
        private const val TIMEOUT_MS = 15_000
        private const val NAMES_URL =
            "https://raw.githubusercontent.com/android-sigma-rules/rules/main/ioc-data/brand-names.yml"
        private const val DOMAINS_URL =
            "https://raw.githubusercontent.com/android-sigma-rules/rules/main/ioc-data/brand-domains.yml"

        private val CF_REGEX = Regex("\\p{Cf}")

        /**
         * Domain values that must never enter `brand_domain_db`: a bare TLD or
         * a public suffix would, via the label-boundary suffix walk, exempt an
         * unbounded set of scopes from androdr-092. Best-effort backstop, NOT a
         * full Public Suffix List — it covers the common global TLDs and the
         * second-level registries of the ccTLDs a brand registry realistically
         * touches (single-label entries are redundant with the no-dot check and
         * kept only belt-and-suspenders). The primary integrity controls are
         * the per-entry HitL gate and the rules-repo branch protection; this
         * and the CI validator (kept in lockstep) are defence in depth on the
         * un-hashed ioc-data channel. Keep in sync with
         * validate-ioc-data.py:BRAND_PUBLIC_SUFFIX_DENYLIST.
         */
        private val PUBLIC_SUFFIX_DENYLIST = setOf(
            // Single-label TLDs (redundant with the no-dot check).
            "com", "org", "net", "io", "app", "co", "info", "biz", "dev", "me",
            "uk", "pl", "pt", "es", "mx", "nl", "br", "de", "be", "fr", "it",
            "ar", "hk", "cz", "pe", "cn", "tw", "sg", "my", "ph", "vn", "id",
            "th", "kr", "za", "in", "tr", "au", "nz", "jp", "ca", "us",
            // Multi-label public suffixes (second-level registries).
            "co.uk", "org.uk", "me.uk", "net.uk", "ltd.uk", "plc.uk",
            "com.au", "net.au", "org.au", "co.jp", "ne.jp", "or.jp",
            "com.br", "net.br", "org.br", "com.mx", "com.ar", "com.co",
            "com.pe", "com.ve", "com.cl", "com.hk", "com.cn", "net.cn",
            "org.cn", "com.tw", "com.sg", "com.my", "com.ph", "com.vn",
            "co.id", "co.th", "co.kr", "co.za", "co.nz", "co.in", "co.il",
            "com.tr", "com.sa", "com.eg", "com.ng", "com.pk", "com.bd",
            "com.pl", "com.ua", "com.ru",
        )

        /**
         * Normalise a label or variant for matching: strip default-ignorable
         * FORMAT characters (\p{Cf}: zero-width space/joiner, soft hyphen,
         * RTL/LTR overrides) then NFKC-fold. Closes the pixel-identical
         * zero-width *format-character* insertion evasion ("Pay​Pal"). It
         * does NOT close invisible-LETTER tricks (e.g. U+3164 Hangul filler,
         * category Lo) — those are Unicode confusables, an explicit non-goal
         * (spec §7), not this format-character class.
         */
        internal fun normalizeLabel(s: String): String =
            Normalizer.normalize(CF_REGEX.replace(s, ""), Normalizer.Form.NFKC)

        /** Host of a scope URL, lower-cased implicitly by callers; null if unparseable/blank. */
        @Suppress("SwallowedException", "TooGenericExceptionCaught")
        internal fun hostOf(scopeUrl: String): String? {
            if (scopeUrl.isBlank()) return null
            return try {
                URI(scopeUrl.trim()).host
            } catch (e: Exception) {
                null
            }
        }

        /**
         * Build a matcher, or null if the data violates the sanity bounds
         * (reject-wholesale, per the OemPrefixResolver idiom). Applied to the
         * bundled seed and every remote fetch alike, so a curation slip is
         * caught the same way on both channels.
         */
        internal fun buildMatcher(names: List<String>, domains: List<String>): BrandMatcher? {
            // Length-bound the NORMALISED variant, not the raw one: BrandMatcher
            // matches on the normalised form, so a raw "​​A" (raw len
            // 3, normalised "A") would otherwise slip a 1-char over-matching
            // pattern past the min-length guard.
            val normNames = names.map { normalizeLabel(it) }
            val cleanDomains = domains.map { it.trim().lowercase(Locale.ROOT) }
            val valid = normNames.isNotEmpty() && cleanDomains.isNotEmpty() &&
                normNames.size <= MAX_NAME_VARIANTS && cleanDomains.size <= MAX_DOMAINS &&
                normNames.none { it.length < MIN_NAME_VARIANT_LEN || it.length > MAX_NAME_VARIANT_LEN } &&
                cleanDomains.none { !it.contains('.') || it in PUBLIC_SUFFIX_DENYLIST }
            return if (valid) BrandMatcher(names, cleanDomains.toSet()) else null
        }

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
