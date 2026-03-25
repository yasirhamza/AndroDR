package com.androdr.network

import android.content.Context
import android.util.Log
import com.androdr.R
import dagger.hilt.android.qualifiers.ApplicationContext
import java.io.BufferedReader
import java.io.InputStreamReader
import javax.inject.Inject
import javax.inject.Singleton

/**
 * Loads and queries a domain blocklist bundled as a raw resource (`R.raw.domain_blocklist`).
 *
 * The list is read lazily on the first call to [isBlocked] or [blockedCount].  Each line in the
 * resource file is treated as a single domain entry (blank lines and lines starting with `#` are
 * ignored).  Lookups are O(k) where k is the number of domain labels, because parent-domain
 * matching walks up the label hierarchy until a hit is found or the root is reached.
 */
@Singleton
class BlocklistManager @Inject constructor(
    @ApplicationContext private val context: Context
) {

    companion object {
        private const val TAG = "BlocklistManager"
    }

    /**
     * The loaded blocklist.  Initialized at most once via [loadBlocklist].
     * All entries are stored lowercase without a trailing dot.
     */
    private val blocklist: HashSet<String> by lazy { loadBlocklist() }

    /**
     * Returns `true` if [domain] or any of its parent domains appears in the blocklist.
     *
     * Examples (assuming `evil.com` is blocked):
     * - `isBlocked("evil.com")` → `true`
     * - `isBlocked("sub.evil.com")` → `true`
     * - `isBlocked("sub.sub.evil.com")` → `true`
     * - `isBlocked("good.com")` → `false`
     *
     * @param domain The fully-qualified domain name to test.  A trailing dot is stripped before
     *               the lookup (common in DNS wire-format representations).
     */
    @Suppress("ReturnCount") // Domain hierarchy walk uses early returns on hit and TLD boundary;
    // flattening into a single expression would obscure the label-stripping loop logic.
    fun isBlocked(domain: String): Boolean {
        if (domain.isBlank()) return false

        // Normalise: strip trailing dot, lower-case
        var candidate = domain.trimEnd('.').lowercase()

        // Walk up the domain hierarchy
        while (candidate.isNotEmpty()) {
            if (candidate in blocklist) return true
            val dotIndex = candidate.indexOf('.')
            if (dotIndex < 0) break                       // reached the TLD — stop
            candidate = candidate.substring(dotIndex + 1) // strip leftmost label
        }

        return false
    }

    /** Returns the number of entries in the blocklist. */
    fun blockedCount(): Int = blocklist.size

    // ── Private ───────────────────────────────────────────────────────────────

    /**
     * Reads `R.raw.domain_blocklist` line-by-line into a [HashSet].
     * Lines are trimmed; blank lines and comment lines (starting with `#`) are skipped.
     * All entries are lowercased and trailing dots are removed for consistency.
     */
    private fun loadBlocklist(): HashSet<String> {
        val set = HashSet<String>(8192)
        @Suppress("TooGenericExceptionCaught", "SwallowedException") // openRawResource can throw
        // NotFoundException if the resource is absent (e.g. during tests); empty set = pass all.
        try {
            context.resources.openRawResource(R.raw.domain_blocklist).use { stream ->
                BufferedReader(InputStreamReader(stream, Charsets.UTF_8)).forEachLine { raw ->
                    val line = raw.trim()
                    if (line.isNotEmpty() && !line.startsWith('#')) {
                        set.add(line.trimEnd('.').lowercase())
                    }
                }
            }
        } catch (e: Exception) {
            Log.w(TAG, "BlocklistManager: blocklist load failed: ${e.message}")
            // Resource missing or IO error — return empty set so the rest of the app keeps
            // working; the VPN service will pass all traffic through when the list is absent.
        }
        return set
    }
}
