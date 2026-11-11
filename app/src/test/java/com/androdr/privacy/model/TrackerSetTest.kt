package com.androdr.privacy.model

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class TrackerSetTest {

    private fun tracker(
        id: Int,
        prefixes: List<String> = emptyList(),
        segments: List<String> = emptyList(),
        suffixes: List<String> = emptyList(),
        labels: List<String> = emptyList(),
        patterns: List<String> = emptyList(),
    ) = Tracker(
        id = id, name = "T$id", website = "", categories = setOf(TrackerCategory.ANALYTICS),
        rawCategories = listOf("Analytics"), codePrefixes = prefixes, codeSegments = segments,
        domainSuffixes = suffixes, domainLabels = labels,
        domainPatterns = patterns.map { requireNotNull(DomainGrammar.compilePattern(it)) },
    )

    private fun reg(vararg t: Tracker) = TrackerSet(t.toList(), "sha")

    @Test
    fun `matchPackages respects dotted boundaries`() {
        val t = tracker(1, prefixes = listOf("com.a"))
        val s = reg(t)
        assertEquals(emptySet<Tracker>(), s.matchPackages(listOf("com.ab")))
        assertEquals(setOf(t), s.matchPackages(listOf("com.a")))
        assertEquals(setOf(t), s.matchPackages(listOf("com.a.b.c")))
    }

    @Test
    fun `matchPackages returns every tracker whose prefix matches`() {
        val t1 = tracker(1, prefixes = listOf("com.a"))
        val t2 = tracker(2, prefixes = listOf("com.a.b"))
        assertEquals(setOf(t1, t2), reg(t1, t2).matchPackages(listOf("com.a.b.c")))
    }

    @Test
    fun `a code segment matches a package containing it`() {
        val t = tracker(1, segments = listOf("sizmek"))
        val s = reg(t)
        assertEquals(setOf(t), s.matchPackages(listOf("net.sizmek.sdk")))
        assertEquals(emptySet<Tracker>(), s.matchPackages(listOf("net.sizmekx")))
    }

    @Test
    fun `matchDomain matches suffixes on label boundaries and returns all owners`() {
        val t1 = tracker(1, suffixes = listOf("doubleclick.net"))
        val t2 = tracker(2, suffixes = listOf("doubleclick.net"))
        val s = reg(t1, t2)
        assertEquals(s.trackers.toSet(), s.matchDomain("ad.doubleclick.net"))
        assertEquals(s.trackers.toSet(), s.matchDomain("doubleclick.net"))
        assertEquals(emptySet<Tracker>(), s.matchDomain("notdoubleclick.net"))
    }

    @Test
    fun `a domain label matches only a whole label`() {
        val t = tracker(1, labels = listOf("alimama"))
        val s = reg(t)
        assertEquals(s.trackers.toSet(), s.matchDomain("x.alimama.com"))
        assertEquals(emptySet<Tracker>(), s.matchDomain("xalimama.com"))
    }

    @Test
    fun `a pattern matches the host or a label-bounded suffix`() {
        val t = tracker(1, patterns = listOf("mst[0-9]*\\.is\\.autonavi\\.com"))
        val s = reg(t)
        assertEquals(s.trackers.toSet(), s.matchDomain("mst3.is.autonavi.com"))
        assertEquals(s.trackers.toSet(), s.matchDomain("a.mst3.is.autonavi.com"))
        assertEquals(emptySet<Tracker>(), s.matchDomain("xmst3.is.autonavi.com"))
    }

    @Test
    fun `a host longer than 253 chars matches nothing`() {
        val t = tracker(1, suffixes = listOf("doubleclick.net"))
        val s = reg(t)
        val host = "a".repeat(250) + ".doubleclick.net"
        assertTrue(host.length > TrackerSet.MAX_HOST_CHARS)
        assertEquals(emptySet<Tracker>(), s.matchDomain(host))
    }

    @Test
    fun `detailed code matching names the prefix and the packages under it`() {
        val t = tracker(1, prefixes = listOf("com.a"))
        assertEquals(
            listOf(CodeMatch(t, SignatureKind.CODE_PREFIX, "com.a", listOf("com.a.x", "com.a.y"))),
            reg(t).matchPackagesDetailed(listOf("com.a.y", "com.a.x", "com.ab")),
        )
    }

    @Test
    fun `detailed code matching names a package-name segment`() {
        val t = tracker(1, segments = listOf("sizmek"))
        assertEquals(
            listOf(CodeMatch(t, SignatureKind.CODE_SEGMENT, "sizmek", listOf("net.sizmek.sdk"))),
            reg(t).matchPackagesDetailed(listOf("net.sizmek.sdk", "net.sizmekx")),
        )
    }

    @Test
    fun `a package under two signatures of one tracker is listed under each`() {
        val t = tracker(1, prefixes = listOf("com.a", "com.a.b"))
        assertEquals(
            listOf(
                CodeMatch(t, SignatureKind.CODE_PREFIX, "com.a", listOf("com.a.b.c")),
                CodeMatch(t, SignatureKind.CODE_PREFIX, "com.a.b", listOf("com.a.b.c")),
            ),
            reg(t).matchPackagesDetailed(listOf("com.a.b.c")),
        )
    }

    @Test
    fun `detailed code matching is sorted by tracker then kind then signature`() {
        val t2 = tracker(2, prefixes = listOf("com.z"), segments = listOf("a"))
        val t1 = tracker(1, prefixes = listOf("com.y"))
        val got = reg(t2, t1).matchPackagesDetailed(listOf("com.z.a", "com.y.q"))
        assertEquals(
            listOf(1 to "com.y", 2 to "com.z", 2 to "a"),
            got.map { it.tracker.id to it.signature },
        )
    }

    @Test
    fun `detailed domain matching names the suffix, the label and the pattern`() {
        val suffix = tracker(1, suffixes = listOf("doubleclick.net"))
        val label = tracker(2, labels = listOf("alimama"))
        val pattern = tracker(3, patterns = listOf("mst[0-9]*\\.is\\.autonavi\\.com"))
        val s = reg(suffix, label, pattern)
        assertEquals(
            listOf(DomainMatch(suffix, SignatureKind.DOMAIN_SUFFIX, "doubleclick.net")),
            s.matchDomainDetailed("x.doubleclick.net"),
        )
        assertEquals(
            listOf(DomainMatch(label, SignatureKind.DOMAIN_LABEL, "alimama")),
            s.matchDomainDetailed("alimama.example"),
        )
        assertEquals(
            listOf(DomainMatch(pattern, SignatureKind.DOMAIN_PATTERN, pattern.domainPatterns.single().pattern)),
            s.matchDomainDetailed("mst01.is.autonavi.com"),
        )
    }

    @Test
    fun `a host gives one detailed match per tracker, the longest tail first`() {
        val t = tracker(1, suffixes = listOf("b.a.com", "a.com"))
        assertEquals(
            listOf(DomainMatch(t, SignatureKind.DOMAIN_SUFFIX, "b.a.com")),
            reg(t).matchDomainDetailed("x.b.a.com"),
        )
    }

    @Test
    fun `a host longer than 253 characters gives no detailed match`() {
        val t = tracker(1, suffixes = listOf("doubleclick.net"))
        assertEquals(emptyList<DomainMatch>(), reg(t).matchDomainDetailed("a".repeat(250) + ".doubleclick.net"))
        assertEquals(emptyList<DomainMatch>(), reg(t).matchDomainDetailed(""))
    }
}
