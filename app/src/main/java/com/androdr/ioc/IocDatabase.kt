package com.androdr.ioc

import android.content.Context
import com.androdr.R
import dagger.hilt.android.qualifiers.ApplicationContext
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import javax.inject.Inject
import javax.inject.Singleton

@Serializable
data class BadPackageInfo(
    val packageName: String,
    val name: String,
    val category: String,
    val severity: String,
    val description: String,
)

@Singleton
class IocDatabase @Inject constructor(
    @ApplicationContext private val context: Context,
) {
    private val json = Json { ignoreUnknownKeys = true }

    /**
     * Lazily parsed list of all known-bad packages loaded from
     * [R.raw.known_bad_packages] on first access.
     */
    private val badPackageList: List<BadPackageInfo> by lazy {
        val raw = context.resources
            .openRawResource(R.raw.known_bad_packages)
            .bufferedReader()
            .use { it.readText() }
        json.decodeFromString(raw)
    }

    /**
     * O(1) lookup map keyed by package name. Built once from [badPackageList]
     * on first access.
     */
    private val badPackageMap: HashMap<String, BadPackageInfo> by lazy {
        HashMap<String, BadPackageInfo>(badPackageList.size * 2).also { map ->
            badPackageList.forEach { entry -> map[entry.packageName] = entry }
        }
    }

    /**
     * Returns [BadPackageInfo] for the given [packageName] if it is in the
     * known-bad package list, or `null` otherwise.
     *
     * Lookup is O(1) via an internal [HashMap].
     */
    fun isKnownBadPackage(packageName: String): BadPackageInfo? =
        badPackageMap[packageName]

    /**
     * Returns the threat category string (e.g. "STALKERWARE", "BANKING_TROJAN")
     * for the given [packageName], or `null` if the package is not known-bad.
     */
    fun getCategory(packageName: String): String? =
        badPackageMap[packageName]?.category

    /**
     * Returns the full list of all known-bad package entries.
     *
     * The list is loaded lazily on first call and cached for subsequent calls.
     */
    fun getAllBadPackages(): List<BadPackageInfo> = badPackageList
}
