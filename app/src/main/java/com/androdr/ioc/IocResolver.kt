package com.androdr.ioc

import com.androdr.data.db.IocEntryDao
import com.androdr.data.model.IocEntry
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.util.concurrent.atomic.AtomicReference
import javax.inject.Inject
import javax.inject.Singleton

/**
 * Single lookup point for IOC package-name checks.
 *
 * Priority:
 *  1. Dynamic entries fetched from remote feeds and stored in Room (most up-to-date).
 *  2. Bundled [IocDatabase] (always available, used as fallback).
 *
 * The dynamic entries are kept in an [AtomicReference] in-memory map so that
 * [isKnownBadPackage] stays synchronous and can be called from non-coroutine contexts.
 * Call [refreshCache] after each remote update (and on app startup) to populate the map.
 */
@Singleton
class IocResolver @Inject constructor(
    private val iocEntryDao: IocEntryDao,
    private val bundled: IocDatabase
) {
    private val remoteCache = AtomicReference<Map<String, BadPackageInfo>?>(null)

    /**
     * Loads all remote IOC entries from Room into the in-memory cache.
     * Safe to call multiple times; subsequent calls replace the cache atomically.
     */
    suspend fun refreshCache() = withContext(Dispatchers.IO) {
        val map = buildMap<String, BadPackageInfo> {
            iocEntryDao.getAll().forEach { entry -> put(entry.packageName, entry.toBadPackageInfo()) }
        }
        remoteCache.set(map)
    }

    /**
     * Returns [BadPackageInfo] for [packageName] if it appears in any known-bad source,
     * or `null` if the package is clean.
     *
     * Remote cache is checked first; if the cache has not been loaded yet (null),
     * falls through to the bundled database only.
     */
    fun isKnownBadPackage(packageName: String): BadPackageInfo? =
        remoteCache.get()?.get(packageName) ?: bundled.isKnownBadPackage(packageName)

    /** Total number of dynamically fetched IOC entries currently stored in Room. */
    suspend fun remoteEntryCount(): Int = iocEntryDao.count()
}

private fun IocEntry.toBadPackageInfo() = BadPackageInfo(
    packageName = packageName,
    name = name,
    category = category,
    severity = severity,
    description = description
)
