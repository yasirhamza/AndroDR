package com.androdr.ioc

import android.util.Log
import com.androdr.data.db.IndicatorDao
import com.androdr.data.model.Indicator
import kotlinx.coroutines.Dispatchers
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
    private val bundledApkHashes: ApkHashIocDatabase
) {
    private val cache = AtomicReference<IndicatorCache?>(null)
    private val domainIndex = AtomicReference<DomainBloomIndex>(DomainBloomIndex.empty())

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
     *   - `campaign` is empty — callers should not depend on it for branching,
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
                    name = "",
                    campaign = "",
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

    fun isKnownBadCert(certHash: String): Indicator? {
        val normalized = certHash.lowercase()
        val hit = cache.get()?.lookup(TYPE_CERT_HASH, normalized)
        if (hit != null) return hit
        val bundledHit = bundledCerts.isKnownBadCert(normalized) ?: return null
        return Indicator(
            type = TYPE_CERT_HASH, value = bundledHit.certHash,
            name = bundledHit.familyName, campaign = "",
            severity = bundledHit.severity, description = bundledHit.description,
            source = "bundled", fetchedAt = 0L
        )
    }

    fun isKnownBadApkHash(hash: String): Indicator? {
        val normalized = hash.lowercase()
        val hit = cache.get()?.lookup(TYPE_APK_HASH, normalized)
        if (hit != null) return hit
        val bundledHit = bundledApkHashes.isKnownBadApkHash(normalized) ?: return null
        return Indicator(
            type = TYPE_APK_HASH, value = bundledHit.apkHash,
            name = bundledHit.familyName, campaign = bundledHit.category,
            severity = bundledHit.severity, description = bundledHit.description,
            source = "bundled", fetchedAt = 0L
        )
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
    packageName = value, name = name, category = campaign.ifEmpty { "MALWARE" },
    severity = severity, description = description
)
