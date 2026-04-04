package com.androdr.ioc

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
        val direct = cache.get()?.get(packageName) ?: bundled.lookup(packageName)
        if (direct != null) return direct
        val basePkg = packageName.replaceFirst(RRO_SUFFIX_REGEX, "")
        return if (basePkg != packageName) lookup(basePkg) else null
    }

    companion object {
        private val RRO_SUFFIX_REGEX = Regex("""\\.auto_generated_rro_[\w-]+___$""")
    }
}

private fun KnownAppDbEntry.toDomain() = KnownAppEntry(
    packageName = packageName,
    displayName = displayName,
    category    = KnownAppCategory.valueOf(category),
    sourceId    = sourceId,
    fetchedAt   = fetchedAt
)
