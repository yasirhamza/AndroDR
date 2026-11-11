package com.androdr.privacy.model

import java.util.Arrays
import java.util.TreeSet

/** One tracker SDK from the registry, with its code and network signatures. */
data class Tracker(
    val id: Int,
    val name: String,
    val website: String,
    val categories: Set<TrackerCategory>,
    val rawCategories: List<String>,
    val codePrefixes: List<String>,
    val codeSegments: List<String>,
    val domainSuffixes: List<String>,
    val domainLabels: List<String>,
    val domainPatterns: List<Regex>,
)

/** Which kind of list signature tied a package or a domain to a tracker. */
enum class SignatureKind { CODE_PREFIX, CODE_SEGMENT, DOMAIN_SUFFIX, DOMAIN_LABEL, DOMAIN_PATTERN }

/** One code signature of [tracker] that matched, with the app's packages it matched. */
data class CodeMatch(val tracker: Tracker, val kind: SignatureKind, val signature: String, val packages: List<String>)

/** The signature of [tracker] that matched a domain. A pattern's signature is its `Regex.pattern`. */
data class DomainMatch(val tracker: Tracker, val kind: SignatureKind, val signature: String)

/** An immutable, indexed tracker registry snapshot. */
class TrackerSet(val trackers: List<Tracker>, val sourceSha256: String) {
    val size: Int get() = trackers.size

    // Sorted prefixes + binary search (parallel arrays).
    private val prefixKeys: Array<String>
    private val prefixOwners: Array<List<Tracker>>
    private val segmentIndex: Map<String, List<Tracker>>
    private val suffixIndex: Map<String, List<Tracker>>
    private val labelIndex: Map<String, List<Tracker>>
    private val patterns: List<Pair<Regex, Tracker>>

    init {
        val byPrefix = sortedMapOf<String, MutableList<Tracker>>()
        val bySegment = HashMap<String, MutableList<Tracker>>()
        val bySuffix = HashMap<String, MutableList<Tracker>>()
        val byLabel = HashMap<String, MutableList<Tracker>>()
        val pats = ArrayList<Pair<Regex, Tracker>>()
        for (t in trackers) {
            t.codePrefixes.forEach { byPrefix.getOrPut(it) { ArrayList() }.add(t) }
            t.codeSegments.forEach { bySegment.getOrPut(it) { ArrayList() }.add(t) }
            t.domainSuffixes.forEach { bySuffix.getOrPut(it) { ArrayList() }.add(t) }
            t.domainLabels.forEach { byLabel.getOrPut(it) { ArrayList() }.add(t) }
            t.domainPatterns.forEach { pats.add(it to t) }
        }
        prefixKeys = byPrefix.keys.toTypedArray()
        prefixOwners = byPrefix.values.map { it.toList() }.toTypedArray()
        segmentIndex = bySegment
        suffixIndex = bySuffix
        labelIndex = byLabel
        patterns = pats
    }

    private fun ownersOfPrefix(candidate: String): List<Tracker> {
        val idx = Arrays.binarySearch(prefixKeys, candidate)
        return if (idx >= 0) prefixOwners[idx] else emptyList()
    }

    /**
     * Calls [hit] once per (package, signature, owning tracker) that matches: a code prefix that is
     * a dotted-path prefix of the package (`com.a` matches `com.a.b`, not `com.ab`), or a code
     * segment equal to one of its dotted segments. The one traversal behind both code matchers.
     */
    private inline fun forEachCodeHit(
        packages: Collection<String>,
        hit: (pkg: String, kind: SignatureKind, signature: String, tracker: Tracker) -> Unit,
    ) {
        for (pkg in packages) {
            var end = pkg.indexOf('.')
            while (end >= 0) {
                val candidate = pkg.substring(0, end)
                for (t in ownersOfPrefix(candidate)) hit(pkg, SignatureKind.CODE_PREFIX, candidate, t)
                end = pkg.indexOf('.', end + 1)
            }
            for (t in ownersOfPrefix(pkg)) hit(pkg, SignatureKind.CODE_PREFIX, pkg, t)
            for (segment in pkg.split('.')) {
                segmentIndex[segment]?.forEach { hit(pkg, SignatureKind.CODE_SEGMENT, segment, it) }
            }
        }
    }

    /**
     * Calls [hit] for every signature that matches [host], in matcher order: the longest tail
     * first, and at one tail its suffix, then its first label, then each pattern. The one traversal
     * behind both domain matchers. [host] longer than [MAX_HOST_CHARS], or empty, gives no hit.
     */
    private inline fun forEachDomainHit(
        host: String,
        hit: (kind: SignatureKind, signature: String, tracker: Tracker) -> Unit,
    ) {
        if (host.isEmpty() || host.length > MAX_HOST_CHARS) return
        var start = 0
        for (label in host.split('.')) {
            val tail = host.substring(start)
            suffixIndex[tail]?.forEach { hit(SignatureKind.DOMAIN_SUFFIX, tail, it) }
            labelIndex[label]?.forEach { hit(SignatureKind.DOMAIN_LABEL, label, it) }
            for ((rx, t) in patterns) if (rx.matches(tail)) hit(SignatureKind.DOMAIN_PATTERN, rx.pattern, t)
            start += label.length + 1
        }
    }

    /**
     * Trackers with a code prefix that is a dotted-path prefix of some package (`com.a` matches
     * `com.a.b`, not `com.ab`), or a code segment equal to some dotted segment of some package.
     */
    fun matchPackages(packages: Collection<String>): Set<Tracker> {
        val out = LinkedHashSet<Tracker>()
        forEachCodeHit(packages) { _, _, _, t -> out.add(t) }
        return out
    }

    /**
     * What [matchPackages] found, signature by signature: one entry per (tracker, kind, signature)
     * that matched, with the matching packages distinct and sorted. A package under two signatures
     * is listed under each. Sorted by tracker id, then kind, then signature.
     */
    fun matchPackagesDetailed(packages: Collection<String>): List<CodeMatch> {
        val byId = HashMap<Int, Tracker>()
        val hits = HashMap<Triple<Int, SignatureKind, String>, TreeSet<String>>()
        forEachCodeHit(packages) { pkg, kind, signature, t ->
            byId[t.id] = t
            hits.getOrPut(Triple(t.id, kind, signature)) { TreeSet() }.add(pkg)
        }
        return hits.entries
            .sortedWith(compareBy({ it.key.first }, { it.key.second.ordinal }, { it.key.third }))
            .map { (key, pkgs) -> CodeMatch(byId.getValue(key.first), key.second, key.third, pkgs.toList()) }
    }

    /**
     * Every tracker with a suffix equal to [host] or a `.`-bounded suffix of it, a label equal to
     * one of its labels, or a pattern that matches the host or one of its label-bounded suffixes.
     * [host] is lower-cased with the trailing dot removed; longer than [MAX_HOST_CHARS] gives empty.
     */
    fun matchDomain(host: String): Set<Tracker> {
        val out = LinkedHashSet<Tracker>()
        forEachDomainHit(host) { _, _, t -> out.add(t) }
        return out
    }

    /**
     * What [matchDomain] found, one entry per tracker: the first signature of that tracker to
     * match in matcher order (the longest tail first; at one tail suffix, then label, then pattern).
     */
    fun matchDomainDetailed(host: String): List<DomainMatch> {
        val out = LinkedHashMap<Int, DomainMatch>()
        forEachDomainHit(host) { kind, signature, t ->
            if (t.id !in out) out[t.id] = DomainMatch(t, kind, signature)
        }
        return out.values.toList()
    }

    companion object {
        const val MAX_HOST_CHARS = 253
    }
}
