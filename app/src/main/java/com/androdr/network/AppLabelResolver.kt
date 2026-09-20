package com.androdr.network

import android.content.Context
import android.util.Log

/** The display name of an installed package, or null when the platform has none. */
fun interface PackageLabelLookup {
    fun labelFor(packageName: String): String?
}

/**
 * Package name -> the name a person recognises, for surfaces that list live
 * events by app.
 *
 * Attribution gives the Network Monitor a package; a package is not yet an
 * answer to "which app is this?" for most readers. The report already resolved
 * display names from the scan inventory, so the same DNS query could read
 * `Chrome (com.android.chrome)` on the report and `com.android.chrome` on the
 * screen. This resolver is the screen's equivalent source.
 *
 * Every answer is cached, the misses too: the event list re-renders on every
 * query the tunnel sees, and the platform lookup is a binder call per package.
 * A package the platform cannot name keeps its package name -- a missing label
 * is never filled with a guess.
 */
open class AppLabelResolver(private val lookup: PackageLabelLookup) {

    private val cache = HashMap<String, String?>()

    /** Display names for [packages]; a package with no usable label is absent from the result. */
    open fun labels(packages: Collection<String>): Map<String, String> {
        val resolved = LinkedHashMap<String, String>()
        synchronized(cache) {
            for (pkg in packages) {
                val label = if (cache.containsKey(pkg)) cache[pkg] else resolve(pkg).also { cache[pkg] = it }
                if (label != null) resolved[pkg] = label
            }
        }
        return resolved
    }

    @Suppress("TooGenericExceptionCaught") // a missing or broken package must cost one label, not the list
    private fun resolve(packageName: String): String? = try {
        lookup.labelFor(packageName)?.trim()?.takeIf { it.isNotEmpty() && it != packageName }
    } catch (e: Exception) {
        Log.w(TAG, "label lookup failed for $packageName: ${e.message}")
        null
    }

    companion object {
        private const val TAG = "AppLabelResolver"

        /** The real thing: labels from the package manager. */
        fun fromSystem(context: Context): AppLabelResolver {
            val pm = context.packageManager
            return AppLabelResolver { packageName ->
                pm.getApplicationLabel(pm.getApplicationInfo(packageName, 0)).toString()
            }
        }
    }
}
