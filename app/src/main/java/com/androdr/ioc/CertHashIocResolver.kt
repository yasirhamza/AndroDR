package com.androdr.ioc

import com.androdr.data.db.CertHashIocEntryDao
import com.androdr.data.model.CertHashIocEntry
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.util.concurrent.atomic.AtomicReference
import javax.inject.Inject
import javax.inject.Singleton

@Singleton
class CertHashIocResolver @Inject constructor(
    private val dao: CertHashIocEntryDao,
    private val bundled: CertHashIocDatabase
) {
    private val remoteCache = AtomicReference<Map<String, CertHashIocEntry>?>(null)

    suspend fun refreshCache() = withContext(Dispatchers.IO) {
        val map = buildMap<String, CertHashIocEntry> {
            dao.getAll().forEach { entry -> put(entry.certHash, entry) }
        }
        remoteCache.set(map)
    }

    fun isKnownBadCert(certHash: String): CertHashIocEntry? {
        val normalized = certHash.lowercase()
        val remoteHit = remoteCache.get()?.get(normalized)
        if (remoteHit != null) return remoteHit

        val bundledHit = bundled.isKnownBadCert(normalized) ?: return null
        return CertHashIocEntry(
            certHash = bundledHit.certHash,
            familyName = bundledHit.familyName,
            category = bundledHit.category,
            severity = bundledHit.severity,
            description = bundledHit.description,
            source = "bundled",
            fetchedAt = 0L
        )
    }

    suspend fun remoteEntryCount(): Int = dao.count()
}
