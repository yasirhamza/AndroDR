package com.androdr.ioc

import android.util.Log
import com.androdr.data.db.IndicatorDao
import com.androdr.data.model.Indicator
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.util.concurrent.atomic.AtomicReference
import javax.inject.Inject
import javax.inject.Singleton

/**
 * Unified IOC resolver backed by the `indicators` table.
 *
 * Non-domain indicators (packages, certs, APK hashes) are cached in a HashMap.
 * Domain indicators use a lightweight HashSet for O(1) membership checks to
 * avoid OOM from 371K+ blocklist entries — full Indicator objects are fetched
 * from Room only on confirmed hits.
 */
@Singleton
class IndicatorResolver @Inject constructor(
    private val dao: IndicatorDao,
    private val bundledPackages: IocDatabase,
    private val bundledCerts: CertHashIocDatabase
) {
    private val cache = AtomicReference<IndicatorCache?>(null)
    private val domainSet = AtomicReference<Set<String>>(emptySet())

    @Suppress("TooGenericExceptionCaught")
    suspend fun refreshCache() = withContext(Dispatchers.IO) {
        // Non-domain indicators: full objects in HashMap (small set)
        val nonDomain = dao.getAllByType(TYPE_PACKAGE) +
            dao.getAllByType(TYPE_CERT_HASH) +
            dao.getAllByType(TYPE_APK_HASH)
        val byTypeValue = HashMap<String, Indicator>(nonDomain.size * 2)
        for (ind in nonDomain) {
            byTypeValue["${ind.type}:${ind.value}"] = ind
        }
        cache.set(IndicatorCache(byTypeValue))

        // Domain indicators: lightweight HashSet of values only (~15MB for 371K strings)
        val domains = dao.getAllByType(TYPE_DOMAIN).map { it.value }.toHashSet()
        domainSet.set(domains)

        Log.i(TAG, "Indicator cache: ${nonDomain.size} non-domain + ${domains.size} domains")
    }

    fun isKnownBadPackage(packageName: String): BadPackageInfo? {
        val hit = cache.get()?.lookup(TYPE_PACKAGE, packageName)
        if (hit != null) return hit.toBadPackageInfo()
        return bundledPackages.isKnownBadPackage(packageName)
    }

    @Suppress("ReturnCount")
    fun isKnownBadDomain(domain: String): Indicator? {
        if (domain.isBlank()) return null
        val domains = domainSet.get()
        if (domains.isEmpty()) return null
        var candidate = domain.trimEnd('.').lowercase()
        while (candidate.isNotEmpty()) {
            if (candidate in domains) {
                // Return a lightweight Indicator without querying Room
                return Indicator(
                    type = TYPE_DOMAIN, value = candidate,
                    name = "", campaign = "", severity = "HIGH",
                    description = "", source = "cached", fetchedAt = 0L
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

    fun isKnownBadApkHash(hash: String): Indicator? =
        cache.get()?.lookup(TYPE_APK_HASH, hash.lowercase())

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
