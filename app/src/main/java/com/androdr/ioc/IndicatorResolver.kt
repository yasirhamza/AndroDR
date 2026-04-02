package com.androdr.ioc

import android.util.Log
import com.androdr.data.db.IndicatorDao
import com.androdr.data.model.Indicator
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withContext
import java.util.concurrent.atomic.AtomicReference
import javax.inject.Inject
import javax.inject.Singleton

/**
 * Unified IOC resolver backed by the `indicators` table.
 *
 * Non-domain indicators (packages, certs, APK hashes) are cached in a
 * HashMap — these are small sets (hundreds to low thousands).
 *
 * Domain indicators are NOT cached in memory — the 371K+ blocklist entries
 * would consume ~15MB and cause OOM on low-RAM devices. Instead, domains
 * are looked up directly from Room with an LRU cache for recent hits.
 */
@Singleton
class IndicatorResolver @Inject constructor(
    private val dao: IndicatorDao,
    private val bundledPackages: IocDatabase,
    private val bundledCerts: CertHashIocDatabase,
    private val bundledApkHashes: ApkHashIocDatabase
) {
    private val cache = AtomicReference<IndicatorCache?>(null)

    // LRU cache for domain lookups — avoids repeated Room queries for the same domain
    private val domainLru = java.util.Collections.synchronizedMap(
        object : LinkedHashMap<String, Boolean>(LRU_MAX_SIZE, 0.75f, true) {
            override fun removeEldestEntry(eldest: MutableMap.MutableEntry<String, Boolean>?): Boolean =
                size > LRU_MAX_SIZE
        }
    )

    suspend fun refreshCache() = withContext(Dispatchers.IO) {
        val nonDomain = dao.getAllByType(TYPE_PACKAGE) +
            dao.getAllByType(TYPE_CERT_HASH) +
            dao.getAllByType(TYPE_APK_HASH)
        val byTypeValue = HashMap<String, Indicator>(nonDomain.size * 2)
        for (ind in nonDomain) {
            byTypeValue["${ind.type}:${ind.value}"] = ind
        }
        cache.set(IndicatorCache(byTypeValue))
        domainLru.clear()
        Log.i(TAG, "Indicator cache: ${nonDomain.size} non-domain (domains queried from DB)")
    }

    fun isKnownBadPackage(packageName: String): BadPackageInfo? {
        val hit = cache.get()?.lookup(TYPE_PACKAGE, packageName)
        if (hit != null) return hit.toBadPackageInfo()
        return bundledPackages.isKnownBadPackage(packageName)
    }

    @Suppress("ReturnCount")
    fun isKnownBadDomain(domain: String): Indicator? {
        if (domain.isBlank()) return null
        var candidate = domain.trimEnd('.').lowercase()
        while (candidate.isNotEmpty()) {
            // Check LRU cache first
            val cached = domainLru[candidate]
            if (cached == true) {
                return Indicator(
                    type = TYPE_DOMAIN, value = candidate,
                    name = "", campaign = "", severity = "HIGH",
                    description = "", source = "cached", fetchedAt = 0L
                )
            }
            if (cached == null) {
                // Not in LRU — query Room
                val hit = runBlocking(Dispatchers.IO) {
                    dao.lookup(TYPE_DOMAIN, candidate)
                }
                if (hit != null) {
                    domainLru[candidate] = true
                    return hit
                }
                domainLru[candidate] = false
            }
            // cached == false means we already checked and it's not there
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
        private const val LRU_MAX_SIZE = 1024
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
