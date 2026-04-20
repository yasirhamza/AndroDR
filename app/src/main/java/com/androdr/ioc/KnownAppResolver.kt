package com.androdr.ioc

import android.util.Log
import com.androdr.data.db.KnownAppDbEntry
import com.androdr.data.db.KnownAppEntryDao
import com.androdr.data.model.KnownAppCategory
import com.androdr.data.model.KnownAppEntry
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.util.concurrent.atomic.AtomicReference
import javax.inject.Inject
import javax.inject.Singleton

@Singleton
class KnownAppResolver @Inject constructor(
    private val dao: KnownAppEntryDao,
    private val bundled: KnownAppDatabase
) {
    private val cache = AtomicReference<Map<String, KnownAppEntry>?>(null)

    suspend fun refreshCache() = withContext(Dispatchers.IO) {
        cache.set(dao.getAll().associate { it.packageName to it.toDomain() })
    }

    fun lookup(packageName: String): KnownAppEntry? {
        val direct = resolveFromSources(packageName)
        if (direct != null) return direct
        val basePkg = packageName.replaceFirst(RRO_SUFFIX_REGEX, "")
        if (basePkg != packageName && basePkg.isNotEmpty()) {
            return resolveFromSources(basePkg)
        }
        return null
    }

    // Plexus (cache source) writes every entry as USER_APP; UAD and bundled classify
    // preloads as OEM/AOSP/GOOGLE. Room upsert race conditions let Plexus overwrite
    // UAD occasionally, so at lookup time we prefer the more authoritative
    // classification when both sources have the same package.
    private fun resolveFromSources(packageName: String): KnownAppEntry? {
        val cached = cache.get()?.get(packageName)
        val bundledEntry = bundled.lookup(packageName)
        if (cached == null) return bundledEntry
        if (bundledEntry == null) return cached
        val cachedRank = authority(cached.category)
        val bundledRank = authority(bundledEntry.category)
        if (cachedRank != bundledRank) {
            // Feed-drift signal: upstream sources disagree on classification.
            // Log once-per-lookup at debug to surface data-quality issues without
            // silently masking them (see #147 regression-prevention reviewer note).
            Log.d(
                TAG,
                "Feed conflict for $packageName: cache=${cached.category}/${cached.sourceId} " +
                    "bundled=${bundledEntry.category}/${bundledEntry.sourceId}; " +
                    "preferring ${if (cachedRank > bundledRank) "cache" else "bundled"}",
            )
        }
        return if (cachedRank >= bundledRank) cached else bundledEntry
    }

    private fun authority(category: KnownAppCategory): Int = when (category) {
        // Firmware-bundling categories — strongest classification.
        KnownAppCategory.OEM,
        KnownAppCategory.AOSP,
        KnownAppCategory.GOOGLE -> 2
        // User-facing app registries (Plexus, popular-apps lists) — weaker signal;
        // should not override firmware classifications from UAD/bundled.
        KnownAppCategory.USER_APP,
        KnownAppCategory.POPULAR -> 1
    }

    companion object {
        private const val TAG = "KnownAppResolver"
        private val RRO_SUFFIX_REGEX = Regex("""\.auto_generated_rro_[\w-]+___$""")
    }
}

private fun KnownAppDbEntry.toDomain() = KnownAppEntry(
    packageName = packageName,
    displayName = displayName,
    category    = KnownAppCategory.valueOf(category),
    sourceId    = sourceId,
    fetchedAt   = fetchedAt
)
