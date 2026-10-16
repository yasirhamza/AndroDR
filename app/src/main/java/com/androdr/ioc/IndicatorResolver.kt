package com.androdr.ioc

import android.util.Log
import com.androdr.data.db.IndicatorDao
import com.androdr.data.model.Indicator
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.withContext
import java.util.Locale
import java.util.concurrent.atomic.AtomicReference
import javax.inject.Inject
import javax.inject.Singleton

/**
 * Unified IOC resolver backed by the `indicators` table.
 *
 * Non-domain indicators (packages, certs, APK hashes) are cached in a HashMap —
 * these are small sets (hundreds to low thousands).
 *
 * Domain indicators are indexed by [DomainBloomIndex] — a bloom filter + sorted
 * 64-bit hash array built in memory at refresh time. This replaces the previous
 * "LRU + `runBlocking(Dispatchers.IO)` to Room on miss" approach, which stalled
 * the VPN packet-read thread for 5–50 ms whenever the Room write lock was
 * contended by the DNS-event batch writer or [IocUpdateWorker]. The new path
 * never touches Room from the read thread, so tail latency under contention is
 * reduced to the ~150 ns bloom-negative fast path.
 */
@Singleton
class IndicatorResolver @Inject constructor(
    private val dao: IndicatorDao,
    private val bundledPackages: IocDatabase,
    private val bundledCerts: CertHashIocDatabase,
    private val bundledApkHashes: ApkHashIocDatabase,
    private val bundledDomains: BundledDomainDatabase
) {
    private val cache = AtomicReference<IndicatorCache?>(null)
    private val domainIndex = AtomicReference<DomainBloomIndex>(DomainBloomIndex.empty())

    /**
     * Full rows behind domain hits, keyed by the MATCHED indicator value (the bloom
     * candidate or the bundled key), never by the queried hostname -- so the cache is
     * bounded by the number of indicators however many distinct subdomains an imported
     * log queries. See [prefetchDomainIndicators] and [cachedDomainIndicator].
     */
    private val domainRows = AtomicReference<Map<String, Indicator>>(emptyMap())

    /**
     * Hostnames that matched live during a DNS evaluation but had no prefetched row,
     * so their findings could not name a family. Recorded by the scan's ioc_match
     * lookup, read-and-cleared by the scan (reported as a ScannerFailure), and
     * cleared by [prefetchDomainIndicators].
     */
    val attributionMisses = AtomicReference<Set<String>>(emptySet())

    suspend fun refreshCache() = withContext(Dispatchers.IO) {
        val nonDomain = dao.getAllByType(TYPE_PACKAGE) +
            dao.getAllByType(TYPE_CERT_HASH) +
            dao.getAllByType(TYPE_APK_HASH)
        val byTypeValue = HashMap<String, Indicator>(nonDomain.size * 2)
        for (ind in nonDomain) {
            byTypeValue["${ind.type}:${ind.value}"] = ind
        }
        cache.set(IndicatorCache(byTypeValue))

        // Build the domain bloom index from the lightweight value-only projection.
        // Streaming only the `value` column avoids materializing ~371k full
        // Indicator rows (each with its name/campaign/severity/description strings).
        val domainValues = dao.getValuesByType(TYPE_DOMAIN)
        val newIndex = DomainBloomIndex.build(domainValues)
        domainIndex.set(newIndex)

        Log.i(
            TAG,
            "Indicator cache: ${nonDomain.size} non-domain, " +
                "${newIndex.size} domains indexed (bloom + hash array)"
        )
    }

    fun isKnownBadPackage(packageName: String): BadPackageInfo? {
        val hit = cache.get()?.lookup(TYPE_PACKAGE, packageName)
        if (hit != null) return hit.toBadPackageInfo()
        return bundledPackages.isKnownBadPackage(packageName)
    }

    /**
     * Test whether [domain] (or any of its parent labels) is in the IOC set.
     *
     * Walks the label hierarchy so that a query for `c2.evil.com` matches an
     * entry keyed on `evil.com`. Each candidate is probed against the in-memory
     * [DomainBloomIndex]; no Room access occurs on this call path, so it is
     * safe to invoke from the VPN packet-read thread without blocking.
     *
     * Returns a synthetic [Indicator] on hit: only `value` (the matched domain)
     * is authoritative. Other fields are placeholders:
     *   - `family` is empty — callers should not depend on it for branching,
     *     but may log it via the matched-domain `value` instead.
     *   - `severity` is `UNKNOWN` rather than a guessed `HIGH`, so downstream
     *     severity rollups are not poisoned by synthetic hits. If a caller
     *     needs real metadata, it can do an async `dao.lookup(TYPE_DOMAIN, v)`
     *     off the hot path.
     */
    @Suppress("ReturnCount")
    fun isKnownBadDomain(domain: String): Indicator? {
        if (domain.isBlank()) return null
        val index = domainIndex.get()
        var candidate = domain.trim().trimEnd('.').lowercase(Locale.ROOT)
        while (candidate.isNotEmpty()) {
            if (index.contains(candidate)) {
                return Indicator(
                    type = TYPE_DOMAIN,
                    value = candidate,
                    severity = "UNKNOWN",
                    description = "",
                    source = "bloom",
                    fetchedAt = 0L
                )
            }
            val dot = candidate.indexOf('.')
            if (dot < 0) break
            candidate = candidate.substring(dot + 1)
        }
        return null
    }

    fun packageIndicator(packageName: String): Indicator? {
        cache.get()?.lookup(TYPE_PACKAGE, packageName)?.let { return it }
        val b = bundledPackages.isKnownBadPackage(packageName) ?: return null
        return IocSanitizer.sanitize(
            Indicator(TYPE_PACKAGE, b.packageName, family = b.name, category = b.category,
                campaignKey = b.campaign, severity = b.severity, description = b.description,
                source = "bundled", reference = b.reference, fetchedAt = 0L)
        )
    }

    /**
     * Load the stored rows behind domain hits so findings can name the family.
     * [isKnownBadDomain] answers from the bloom index on the VPN packet thread and
     * must stay off Room (#71); attribution is only needed when a scan or import
     * evaluates DNS events, so callers resolve the matched hostnames here first.
     * Falls back to the bundled entry when the feeds have not loaded (cold start).
     */
    suspend fun prefetchDomainIndicators(domains: Collection<String>) = withContext(Dispatchers.IO) {
        attributionMisses.set(emptySet())
        val rows = HashMap<String, Indicator>()
        // One DAO lookup per distinct matched value, however many hosts share it.
        val stored = HashMap<String, Indicator?>()
        for (domain in domains.toSet()) {
            ensureActive() // an imported log can hold 200k hosts; leaving the screen stops it
            val (key, row) = resolveDomainMatch(domain) { k ->
                if (k in stored) stored[k] else dao.lookup(TYPE_DOMAIN, k).also { stored[k] = it }
            } ?: continue
            if (row != null) rows[key] = row
        }
        // A bloom key whose stored row is gone (and has no bundled entry) is dropped, so
        // a stale row can never be read back as evidence.
        val gone = stored.filterValues { it == null }.keys - rows.keys
        // Merge, never replace: a scan and an intrusion-log import can prefetch
        // concurrently; replacing would wipe the other caller's rows mid-evaluation.
        // Not cleared by refreshCache() either, for the same reason.
        domainRows.updateAndGet { (it - gone) + rows }
    }

    /**
     * The one label-walk from a queried hostname to its full row: the stored row
     * behind the bloom hit, else the bundled entry (cold start). Touches Room, so
     * never call it on the VPN packet thread (#71); used by [prefetchDomainIndicators]
     * and by the timeline enrichment in ScanRepository.logDnsEventsBatch.
     */
    suspend fun resolveDomainRow(domain: String): Indicator? = withContext(Dispatchers.IO) {
        resolveDomainMatch(domain) { dao.lookup(TYPE_DOMAIN, it) }?.second
    }

    /**
     * (matched key, row) for [domain]: the bloom candidate with its stored row, else the
     * bundled key with its entry. A bloom key whose row is gone and has no bundled
     * fallback comes back as (key, null). Null when nothing matches.
     */
    private suspend fun resolveDomainMatch(
        domain: String,
        storedRow: suspend (String) -> Indicator?
    ): Pair<String, Indicator?>? {
        val bloomKey = isKnownBadDomain(domain)?.value
        val stored = bloomKey?.let { storedRow(it) }
        return when {
            stored != null -> bloomKey to stored
            else -> bundledDomainMatch(domain) ?: bloomKey?.let { it to null }
        }
    }

    /**
     * The prefetched row for [domain]: walks its labels in memory and returns the row of
     * the first label that is cached AND still matches live (bloom or bundle). A cached
     * row whose key no longer matches is never returned (B2 carry-over). No Room access.
     */
    @Suppress("ReturnCount")
    fun cachedDomainIndicator(domain: String): Indicator? {
        val rows = domainRows.get()
        if (rows.isEmpty() || domain.isBlank()) return null
        val index = domainIndex.get()
        var c = domain.trim().trimEnd('.').lowercase(Locale.ROOT)
        while (c.isNotEmpty()) {
            val row = rows[c]
            if (row != null && (index.contains(c) || bundledDomains.lookup(c) != null)) return row
            val dot = c.indexOf('.')
            if (dot < 0) break
            c = c.substring(dot + 1)
        }
        return null
    }

    /** Keys currently held by the domain-row cache (tests: the cache stays bounded). */
    @androidx.annotation.VisibleForTesting
    internal fun domainCacheKeys(): Set<String> = domainRows.get().keys

    /**
     * Cold start: before the first feed sync the bloom index is empty, so a bundled
     * domain would never match androdr-003. Fall back to the bundled list — an
     * in-memory HashMap, safe on the VPN packet thread (#71) once loaded. The first
     * bundled lookup of the process reads the raw resource (one-off; on the VPN path
     * BlocklistManager.isBlocked(), which shares the same BundledDomainDatabase, runs
     * first for every packet and pays that cost). Detection only; what the VPN blocks
     * is still BlocklistManager's blockedDomains() set.
     */
    fun isKnownBadDomainWithBundle(domain: String): Indicator? =
        isKnownBadDomain(domain) ?: bundledDomainMatch(domain)?.second

    /** (bundled key, sanitised entry) for the first label of [domain] in the bundled list. */
    private fun bundledDomainMatch(domain: String): Pair<String, Indicator>? {
        var c = domain.trim().trimEnd('.').lowercase(Locale.ROOT)
        while (c.isNotEmpty()) {
            bundledDomains.lookup(c)?.let { return c to IocSanitizer.sanitize(it) }
            val dot = c.indexOf('.')
            if (dot < 0) break
            c = c.substring(dot + 1)
        }
        return null
    }

    fun isKnownBadCert(certHash: String): Indicator? {
        val normalized = certHash.lowercase()
        val hit = cache.get()?.lookup(TYPE_CERT_HASH, normalized)
        if (hit != null) return hit
        val bundledHit = bundledCerts.isKnownBadCert(normalized) ?: return null
        return IocSanitizer.sanitize(Indicator(
            type = TYPE_CERT_HASH, value = bundledHit.certHash,
            family = bundledHit.familyName, category = bundledHit.category,
            campaignKey = bundledHit.campaign, severity = bundledHit.severity,
            description = bundledHit.description, source = "bundled",
            reference = bundledHit.reference, fetchedAt = 0L
        ))
    }

    fun isKnownBadApkHash(hash: String): Indicator? {
        val normalized = hash.lowercase()
        val hit = cache.get()?.lookup(TYPE_APK_HASH, normalized)
        if (hit != null) return hit
        val bundledHit = bundledApkHashes.isKnownBadApkHash(normalized) ?: return null
        return IocSanitizer.sanitize(Indicator(
            type = TYPE_APK_HASH, value = bundledHit.apkHash,
            family = bundledHit.familyName, category = bundledHit.category,
            campaignKey = bundledHit.campaign, severity = bundledHit.severity,
            description = bundledHit.description, source = "bundled",
            reference = bundledHit.reference, fetchedAt = 0L
        ))
    }

    suspend fun count(): Int = dao.count()

    private class IndicatorCache(private val map: Map<String, Indicator>) {
        fun lookup(type: String, value: String): Indicator? = map["$type:$value"]
    }

    companion object {
        private const val TAG = "IndicatorResolver"
        const val TYPE_PACKAGE = "package"
        const val TYPE_DOMAIN = "domain"
        const val TYPE_CERT_HASH = "cert_hash"
        const val TYPE_APK_HASH = "apk_hash"
    }
}

private fun Indicator.toBadPackageInfo() = BadPackageInfo(
    packageName = value, name = family, category = category.ifEmpty { "MALWARE" },
    severity = severity, description = description
)
