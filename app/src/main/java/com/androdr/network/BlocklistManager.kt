package com.androdr.network

import com.androdr.ioc.BundledDomainDatabase
import javax.inject.Inject
import javax.inject.Singleton

/**
 * Queries the default-blocked subset of the bundled domain list
 * ([BundledDomainDatabase.blockedDomains], entries with `blockByDefault == true`).
 * Every other bundled domain is for attribution and cold start only, never blocked.
 *
 * The set is read lazily on the first call to [isBlocked] or [blockedCount].  Lookups are O(k)
 * where k is the number of domain labels, because parent-domain matching walks up the label
 * hierarchy until a hit is found or the root is reached.
 */
@Singleton
class BlocklistManager @Inject constructor(
    private val bundledDomains: BundledDomainDatabase
) {

    /**
     * The loaded blocklist.  Initialized at most once.
     * All entries are stored lowercase without a trailing dot.
     */
    private val blocklist: HashSet<String> by lazy { HashSet(bundledDomains.blockedDomains()) }

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
}
