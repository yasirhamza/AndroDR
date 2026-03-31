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
 * Unified IOC resolver backed by the `indicators` table. Replaces the
 * per-type resolvers (IocResolver, DomainIocResolver, CertHashIocResolver).
 *
 * Loads all indicators into an in-memory cache on [refreshCache], then
 * provides O(1) lookups by type+value. Domain lookups include label-stripping
 * for subdomain matching.
 */
@Singleton
class IndicatorResolver @Inject constructor(
    private val dao: IndicatorDao,
    private val bundledPackages: IocDatabase,
    private val bundledCerts: CertHashIocDatabase
) {
    private val cache = AtomicReference<IndicatorCache?>(null)

    suspend fun refreshCache() = withContext(Dispatchers.IO) {
        val all = dao.getAll()
        val byTypeValue = HashMap<String, Indicator>(all.size * 2)
        for (ind in all) {
            byTypeValue["${ind.type}:${ind.value}"] = ind
        }
        cache.set(IndicatorCache(byTypeValue))
        Log.i(TAG, "Indicator cache refreshed: ${all.size} entries")
    }

    fun isKnownBadPackage(packageName: String): BadPackageInfo? {
        val hit = cache.get()?.lookup(TYPE_PACKAGE, packageName)
        if (hit != null) return hit.toBadPackageInfo()
        return bundledPackages.isKnownBadPackage(packageName)
    }

    @Suppress("ReturnCount")
    fun isKnownBadDomain(domain: String): Indicator? {
        val snapshot = cache.get() ?: return null
        if (domain.isBlank()) return null
        var candidate = domain.trimEnd('.').lowercase()
        while (candidate.isNotEmpty()) {
            snapshot.lookup(TYPE_DOMAIN, candidate)?.let { return it }
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
