package com.androdr.privacy.model

import java.util.Arrays

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
     * Trackers with a code prefix that is a dotted-path prefix of some package (`com.a` matches
     * `com.a.b`, not `com.ab`), or a code segment equal to some dotted segment of some package.
     */
    fun matchPackages(packages: Collection<String>): Set<Tracker> {
        val out = LinkedHashSet<Tracker>()
        for (pkg in packages) {
            var end = pkg.indexOf('.')
            while (end >= 0) {
                out.addAll(ownersOfPrefix(pkg.substring(0, end)))
                end = pkg.indexOf('.', end + 1)
            }
            out.addAll(ownersOfPrefix(pkg))
            for (segment in pkg.split('.')) segmentIndex[segment]?.let { out.addAll(it) }
        }
        return out
    }

    /**
     * Every tracker with a suffix equal to [host] or a `.`-bounded suffix of it, a label equal to
     * one of its labels, or a pattern that matches the host or one of its label-bounded suffixes.
     * [host] is lower-cased with the trailing dot removed; longer than [MAX_HOST_CHARS] gives empty.
     */
    fun matchDomain(host: String): Set<Tracker> {
        if (host.isEmpty() || host.length > MAX_HOST_CHARS) return emptySet()
        val out = LinkedHashSet<Tracker>()
        var start = 0
        for (label in host.split('.')) {
            val tail = host.substring(start)
            suffixIndex[tail]?.let { out.addAll(it) }
            labelIndex[label]?.let { out.addAll(it) }
            for ((rx, t) in patterns) if (rx.matches(tail)) out.add(t)
            start += label.length + 1
        }
        return out
    }

    companion object {
        const val MAX_HOST_CHARS = 253
    }
}
