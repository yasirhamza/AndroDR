package com.androdr.privacy

import com.androdr.data.db.DomainLookupCount
import com.androdr.ioc.TrackerRegistry
import com.androdr.privacy.NetworkEvidenceCorrelator.Correlation
import com.androdr.privacy.NetworkEvidenceCorrelator.DnsSource
import com.androdr.privacy.NetworkEvidenceCorrelator.DomainEvidence
import com.androdr.privacy.NetworkEvidenceCorrelator.Key
import com.androdr.privacy.NetworkEvidenceCorrelator.MAX_DOMAINS_PER_APP
import com.androdr.privacy.NetworkEvidenceCorrelator.MAX_MATCHED_PAIRS
import com.androdr.privacy.NetworkEvidenceCorrelator.MAX_MATCHED_PER_APP
import com.androdr.privacy.NetworkEvidenceCorrelator.MAX_MEMO
import com.androdr.privacy.NetworkEvidenceCorrelator.MAX_TIMED_PAIRS
import com.androdr.privacy.NetworkEvidenceCorrelator.MAX_TIMES_PER_PAIR
import com.androdr.privacy.NetworkEvidenceCorrelator.PAGE_SIZE
import com.androdr.privacy.model.SignatureKind
import com.androdr.privacy.model.Tracker
import com.androdr.privacy.model.TrackerCategory
import com.androdr.privacy.model.TrackerSet
import io.mockk.every
import io.mockk.spyk
import io.mockk.verify
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

class NetworkEvidenceCorrelatorTest {

    private companion object {
        const val DAY = 86_400_000L
        const val FLURRY = 1
        const val DOUBLECLICK = 2
        const val SHARED_A = 3
        const val SHARED_B = 4
    }

    private fun tracker(id: Int, vararg suffixes: String) = Tracker(
        id = id, name = "T$id", website = "", categories = setOf(TrackerCategory.ANALYTICS),
        rawCategories = listOf("Analytics"), codePrefixes = emptyList(), codeSegments = emptyList(),
        domainSuffixes = suffixes.toList(), domainLabels = emptyList(), domainPatterns = emptyList(),
    )

    private val small = TrackerSet(
        listOf(
            tracker(FLURRY, "flurry.com"),
            tracker(DOUBLECLICK, "doubleclick.net"),
            tracker(SHARED_A, "shared.example"),
            tracker(SHARED_B, "shared.example"),
        ),
        "sha",
    )

    /** A fake DNS log. [domainsOf] must return each app's distinct raw domains in ascending order. */
    private class FakeSource(
        private val domainsOf: (String) -> List<String>,
        private val countOf: (String, String) -> DomainLookupCount,
        private val timesOf: (String, String, Int) -> List<Long>,
    ) : DnsSource {
        val pages = ArrayList<Triple<String, String, Int>>()
        val counts = ArrayList<Pair<String, String>>()
        val times = ArrayList<Triple<String, String, Int>>()

        override suspend fun domainsAfter(app: String, afterDomain: String, limit: Int): List<String> {
            pages += Triple(app, afterDomain, limit)
            val all = domainsOf(app)
            val found = all.binarySearch(afterDomain)
            val from = if (found >= 0) found + 1 else -found - 1
            return all.subList(from, minOf(all.size, from + limit)).toList()
        }

        override suspend fun count(app: String, rawDomain: String): DomainLookupCount {
            counts += app to rawDomain
            return countOf(app, rawDomain)
        }

        override suspend fun times(app: String, rawDomain: String, limit: Int): List<Long> {
            times += Triple(app, rawDomain, limit)
            return timesOf(app, rawDomain, limit)
        }

        companion object {
            /** From (app, raw domain, time) rows, computed the way the DAO computes them. */
            fun of(rows: List<Triple<String, String, Long>>): FakeSource {
                val byApp = rows.groupBy { it.first }
                return FakeSource(
                    domainsOf = { app -> byApp[app].orEmpty().map { it.second }.distinct().sorted() },
                    countOf = { app, raw ->
                        countRows(byApp[app].orEmpty().filter { it.second == raw }.map { it.third })
                    },
                    timesOf = { app, raw, limit ->
                        byApp[app].orEmpty().filter { it.second == raw }.map { it.third }.sorted().take(limit)
                    },
                )
            }

            fun countRows(times: List<Long>) = DomainLookupCount(
                lookups = times.size,
                dayList = times.map { it / DAY }.distinct().joinToString(",").ifEmpty { null },
                firstAt = times.minOrNull(),
                lastAt = times.maxOrNull(),
            )
        }
    }

    private fun correlate(
        source: DnsSource,
        installed: Set<String>,
        usage: UsageIntervals? = null,
        registry: TrackerSet = small,
        expired: () -> Boolean = { false },
    ): Correlation = runBlocking { NetworkEvidenceCorrelator.correlate(source, registry, installed, usage, expired) }

    private fun padded(prefix: String, n: Int, suffix: String) = List(n) { "$prefix${"%06d".format(it)}$suffix" }

    @Suppress("MaxLineLength") // name quoted from the security review
    @Test fun `50,001 junk pairs with high counts from one app plus one real tracker pair of another app still yield evidence for the real pair`() {
        val junk = padded("junk", 50_001, ".example.org")
        val source = FakeSource(
            domainsOf = { app -> if (app == "a.flood") junk else listOf("x.flurry.com") },
            countOf = { app, _ -> if (app == "a.flood") DomainLookupCount(1_000_000, "1", 1, 2) else
                FakeSource.countRows(listOf(5 * DAY)) },
            timesOf = { _, _, _ -> listOf(5 * DAY) },
        )
        val out = correlate(source, setOf("a.flood", "b.real"))
        assertEquals(1, out.evidence[Key("b.real", FLURRY)]?.lookups)
        assertEquals(listOf("b.real" to "x.flurry.com"), source.counts)
        assertTrue("the flooding app's own evidence is cut short", out.truncated)
        assertTrue(source.pages.filter { it.first == "a.flood" }.sumOf { it.third } <= MAX_DOMAINS_PER_APP + 1)
    }

    @Suppress("MaxLineLength") // name quoted from the security review
    @Test fun `an app sorting first with more than 20,000 tracker-matching subdomains does not stop a later app's real pair`() {
        val subs = padded("s", 20_001, ".flurry.com")
        val source = FakeSource(
            domainsOf = { app -> if (app == "a.flood") subs else listOf("ads.doubleclick.net") },
            countOf = { _, _ -> FakeSource.countRows(listOf(5 * DAY)) },
            timesOf = { _, _, _ -> listOf(5 * DAY) },
        )
        val out = correlate(source, setOf("a.flood", "b.real"))
        assertNotNull(out.evidence[Key("b.real", DOUBLECLICK)])
        assertEquals(MAX_MATCHED_PER_APP, source.counts.count { it.first == "a.flood" })
        assertEquals(MAX_MATCHED_PER_APP, out.evidence[Key("a.flood", FLURRY)]?.lookups)
        assertTrue(out.truncated)
    }

    @Test fun `pages are requested per app with the last domain of the previous page as the key`() {
        val many = padded("d", 2_500, ".example.org")
        val source = FakeSource(
            domainsOf = { app -> if (app == "a") many else listOf("x.flurry.com") },
            countOf = { _, _ -> FakeSource.countRows(listOf(5 * DAY)) },
            timesOf = { _, _, _ -> emptyList() },
        )
        val out = correlate(source, setOf("b", "a"))
        assertEquals(
            listOf(
                Triple("a", "", PAGE_SIZE),
                Triple("a", many[999], PAGE_SIZE),
                Triple("a", many[1_999], PAGE_SIZE),
                Triple("b", "", PAGE_SIZE),
            ),
            source.pages,
        )
        assertFalse(out.truncated)
    }

    @Test fun `a counted pair with zero lookups is skipped`() {
        val source = FakeSource(
            domainsOf = { listOf("x.flurry.com") },
            countOf = { _, _ -> DomainLookupCount(0, null, null, null) },
            timesOf = { _, _, _ -> emptyList() },
        )
        val out = correlate(source, setOf("a"), usage = UsageIntervals(0, emptyMap()))
        assertEquals(emptyMap<Key, Any>(), out.evidence)
        assertEquals(1, source.counts.size)
        assertEquals(0, source.times.size)
    }

    @Test fun `past MAX_MEMO, domains are still matched`() {
        val apps = List(21) { "app%02d".format(it) }
        val perApp = MAX_DOMAINS_PER_APP
        assertTrue(perApp * 20 >= MAX_MEMO)
        val source = FakeSource(
            domainsOf = { app ->
                val i = apps.indexOf(app)
                if (i < 20) padded("j$i-", perApp, ".example.org")
                else padded("j$i-", perApp - 1, ".example.org") + "x.flurry.com"
            },
            countOf = { _, _ -> FakeSource.countRows(listOf(5 * DAY)) },
            timesOf = { _, _, _ -> emptyList() },
        )
        val out = correlate(source, apps.toSet())
        assertEquals(1, out.evidence[Key("app20", FLURRY)]?.lookups)
        assertEquals(listOf("app20" to "x.flurry.com"), source.counts)
    }

    @Test fun `count is called only for matched pairs`() {
        val source = FakeSource.of(
            listOf(
                Triple("a", "x.flurry.com", 5 * DAY), Triple("a", "www.example.org", 5 * DAY),
                Triple("a", "ads.doubleclick.net", 6 * DAY),
            ),
        )
        correlate(source, setOf("a"))
        assertEquals(listOf("a" to "ads.doubleclick.net", "a" to "x.flurry.com"), source.counts)
    }

    @Test fun `an expired deadline mid-paging returns truncated with the evidence so far`() {
        val many = padded("d", 3_000, ".example.org")
        val source = FakeSource(
            domainsOf = { app -> if (app == "b") many else listOf("x.flurry.com") },
            countOf = { _, _ -> FakeSource.countRows(listOf(5 * DAY)) },
            timesOf = { _, _, _ -> emptyList() },
        )
        val out = correlate(source, setOf("a", "b"), expired = { source.pages.count { it.first == "b" } >= 2 })
        assertTrue(out.truncated)
        assertEquals(1, out.evidence[Key("a", FLURRY)]?.lookups)
        assertEquals(2, source.pages.count { it.first == "b" })
    }

    @Test fun `a deadline that expires mid-page stops within 64 domains, truncated with the evidence so far`() {
        val many = padded("d", PAGE_SIZE, ".example.org")
        val source = FakeSource(
            domainsOf = { app -> if (app == "b") many else listOf("x.flurry.com") },
            countOf = { _, _ -> FakeSource.countRows(listOf(5 * DAY)) },
            timesOf = { _, _, _ -> emptyList() },
        )
        val registry = spyk(small)
        val matched = ArrayList<String>()
        every { registry.matchDomainDetailed(any()) } answers {
            matched += firstArg<String>()
            callOriginal()
        }
        // Passes the moment b's first page has been served: everything after is past the deadline.
        val out = correlate(source, setOf("a", "b"), registry = registry,
            expired = { source.pages.any { it.first == "b" } })
        assertTrue(out.truncated)
        assertEquals(1, out.evidence[Key("a", FLURRY)]?.lookups)
        assertEquals(1, source.pages.count { it.first == "b" })
        assertEquals(64, matched.count { it.startsWith("d") })
    }

    @Test fun `more than MAX_MATCHED_PAIRS matches is truncated`() {
        val apps = List(MAX_MATCHED_PAIRS / MAX_MATCHED_PER_APP + 1) { "p%04d".format(it) }
        val subs = padded("s", MAX_MATCHED_PER_APP, ".flurry.com")
        val source = FakeSource(
            domainsOf = { subs },
            countOf = { _, _ -> FakeSource.countRows(listOf(5 * DAY)) },
            timesOf = { _, _, _ -> emptyList() },
        )
        val out = correlate(source, apps.toSet())
        assertTrue(out.truncated)
        assertEquals(MAX_MATCHED_PAIRS, source.counts.size)
        assertNull(out.evidence[Key(apps.last(), FLURRY)])
        assertEquals(MAX_MATCHED_PER_APP, out.evidence[Key(apps.first(), FLURRY)]?.lookups)
    }

    @Test fun `exactly MAX_MATCHED_PER_APP matches in one app is not truncated`() {
        val source = FakeSource(
            domainsOf = { padded("s", MAX_MATCHED_PER_APP, ".flurry.com") },
            countOf = { _, _ -> FakeSource.countRows(listOf(5 * DAY)) },
            timesOf = { _, _, _ -> emptyList() },
        )
        assertFalse(correlate(source, setOf("a")).truncated)
    }

    @Test fun `each distinct domain is matched once`() {
        val spy = spyk(small)
        val source = FakeSource.of(
            listOf(
                Triple("a", "x.flurry.com", 5 * DAY), Triple("a", "X.Flurry.com.", 5 * DAY),
                Triple("b", "x.flurry.com", 6 * DAY), Triple("b", "www.example.org", 6 * DAY),
                Triple("c", "www.example.org", 6 * DAY),
            ),
        )
        correlate(source, setOf("a", "b", "c"), registry = spy)
        verify(exactly = 1) { spy.matchDomainDetailed("x.flurry.com") }
        verify(exactly = 1) { spy.matchDomainDetailed("www.example.org") }
        verify(exactly = 2) { spy.matchDomainDetailed(any()) }
    }

    @Test fun `timestamps are fetched only for matched pairs`() {
        val source = FakeSource.of(
            listOf(Triple("a", "x.flurry.com", 5 * DAY), Triple("a", "www.example.org", 5 * DAY)),
        )
        correlate(source, setOf("a"), usage = UsageIntervals(0, emptyMap()))
        assertEquals(listOf(Triple("a", "x.flurry.com", MAX_TIMES_PER_PAIR + 1)), source.times)
    }

    @Test fun `a domain owned by two trackers yields two evidence rows`() {
        val source = FakeSource.of(listOf(Triple("a", "cdn.shared.example", 5 * DAY)))
        val out = correlate(source, setOf("a"))
        assertEquals(1, out.evidence[Key("a", SHARED_A)]?.lookups)
        assertEquals(1, out.evidence[Key("a", SHARED_B)]?.lookups)
        assertEquals(2, out.evidence.size)
        assertEquals(1, source.counts.size)
    }

    @Test fun `www google com yields no evidence with the bundled registry`() {
        val file = listOf(File("src/main/res/raw/trackers.yml"), File("app/src/main/res/raw/trackers.yml"))
            .first { it.isFile }
        val bundled = requireNotNull(TrackerRegistry.parse(file.readText()))
        val source = FakeSource.of(
            listOf(Triple("a", "www.google.com", 5 * DAY), Triple("a", "googleads.g.doubleclick.net", 5 * DAY)),
        )
        val out = correlate(source, setOf("a"), registry = bundled)
        assertEquals(listOf("a" to "googleads.g.doubleclick.net"), source.counts)
        assertTrue(out.evidence.isNotEmpty())
    }

    @Test fun `uninstalled apps are ignored`() {
        val source = FakeSource.of(
            listOf(Triple("a", "x.flurry.com", 5 * DAY), Triple("gone", "x.flurry.com", 5 * DAY)),
        )
        val out = correlate(source, setOf("a"))
        assertEquals(setOf(Key("a", FLURRY)), out.evidence.keys)
        assertTrue(source.pages.none { it.first == "gone" })
    }

    @Test fun `background is null without usage`() {
        val source = FakeSource.of(listOf(Triple("a", "x.flurry.com", 5 * DAY)))
        val out = correlate(source, setOf("a"), usage = null)
        assertNull(out.evidence.getValue(Key("a", FLURRY)).background)
        assertEquals(0, source.times.size)
    }

    @Test fun `background is null for lookups older than usage coverage`() {
        val source = FakeSource.of(listOf(Triple("a", "x.flurry.com", 500), Triple("a", "x.flurry.com", 1_500)))
        val out = correlate(source, setOf("a"), usage = UsageIntervals(1_000, emptyMap()))
        assertNull(out.evidence.getValue(Key("a", FLURRY)).background)
    }

    @Test fun `background counts lookups outside foreground intervals within coverage`() {
        val source = FakeSource.of(
            listOf(150L, 250L, 300L, 100L, 200L).map { Triple("a", "x.flurry.com", it) },
        )
        val out = correlate(source, setOf("a"), usage = UsageIntervals(0, mapOf("a" to listOf(100L..200L))))
        val ev = out.evidence.getValue(Key("a", FLURRY))
        assertEquals(5, ev.lookups)
        assertEquals(2, ev.background)
    }

    @Test fun `lookups after a shutdown that lost the app's pause count as background`() {
        val intervals = ForegroundIntervals.build(
            listOf(
                ActivityTransition("a", "Main", 100, ActivityTransition.Kind.RESUMED),
                ActivityTransition("android", null, 200, ActivityTransition.Kind.DEVICE_RESET),
            ),
            until = 1_000,
        )
        val source = FakeSource.of(listOf(150L, 250L, 300L).map { Triple("a", "x.flurry.com", it) })
        val out = correlate(source, setOf("a"), usage = UsageIntervals(0, intervals))
        assertEquals(2, out.evidence.getValue(Key("a", FLURRY)).background)
    }

    @Test fun `an app never in the foreground within coverage has every lookup in the background`() {
        val source = FakeSource.of(listOf(150L, 250L).map { Triple("a", "x.flurry.com", it) })
        val out = correlate(source, setOf("a"), usage = UsageIntervals(0, mapOf("other" to listOf(0L..1_000L))))
        assertEquals(2, out.evidence.getValue(Key("a", FLURRY)).background)
    }

    @Test fun `a system app's foreground use is honoured`() {
        val pkg = "com.android.chrome"
        val source = FakeSource.of(listOf(150L, 160L).map { Triple(pkg, "x.flurry.com", it) })
        val out = correlate(source, setOf(pkg), usage = UsageIntervals(0, mapOf(pkg to listOf(100L..200L))))
        assertEquals(0, out.evidence.getValue(Key(pkg, FLURRY)).background)
    }

    @Test fun `beyond MAX_TIMED_PAIRS, background is null and counts are still exact`() {
        val trackers = List(MAX_MATCHED_PER_APP) { tracker(100 + it, "t$it.example") }
        val registry = TrackerSet(trackers, "sha")
        val apps = List(MAX_TIMED_PAIRS / MAX_MATCHED_PER_APP + 1) { "a%02d".format(it) }
        val domains = List(MAX_MATCHED_PER_APP) { "d.t$it.example" }.sorted()
        fun lookupsOf(app: String, raw: String): Int =
            apps.indexOf(app) * MAX_MATCHED_PER_APP + raw.removePrefix("d.t").removeSuffix(".example").toInt() + 1
        val source = FakeSource(
            domainsOf = { domains },
            countOf = { app, raw -> DomainLookupCount(lookupsOf(app, raw), "5", 5 * DAY, 5 * DAY) },
            timesOf = { _, _, _ -> listOf(5 * DAY) },
        )
        val out = correlate(source, apps.toSet(), usage = UsageIntervals(0, emptyMap()), registry = registry)
        val total = apps.size * MAX_MATCHED_PER_APP
        assertEquals(total, out.evidence.size)
        assertEquals(MAX_TIMED_PAIRS, source.times.size)
        assertEquals(total - MAX_TIMED_PAIRS, out.evidence.values.count { it.background == null })
        for ((key, ev) in out.evidence) {
            val raw = "d.t${key.trackerId - 100}.example"
            assertEquals(lookupsOf(key.packageName, raw), ev.lookups)
            if (ev.lookups > total - MAX_TIMED_PAIRS) assertEquals(1, ev.background) else assertNull(ev.background)
        }
    }

    @Test fun `a pair with more than MAX_TIMES_PER_PAIR lookups gets background null without loading them all`() {
        val source = FakeSource(
            domainsOf = { listOf("x.flurry.com") },
            countOf = { app, _ ->
                // "b" grows between counting and timing: its count is small, its times are not.
                if (app == "a") DomainLookupCount(MAX_TIMES_PER_PAIR + 1, "5", 5 * DAY, 5 * DAY)
                else DomainLookupCount(3, "5", 5 * DAY, 5 * DAY)
            },
            timesOf = { _, _, limit ->
                assertEquals(MAX_TIMES_PER_PAIR + 1, limit)
                List(limit) { 5 * DAY + it }
            },
        )
        val out = correlate(source, setOf("a", "b"), usage = UsageIntervals(0, emptyMap()))
        assertEquals(MAX_TIMES_PER_PAIR + 1, out.evidence.getValue(Key("a", FLURRY)).lookups)
        assertNull(out.evidence.getValue(Key("a", FLURRY)).background)
        assertNull(out.evidence.getValue(Key("b", FLURRY)).background)
        assertTrue(source.times.all { it.third == MAX_TIMES_PER_PAIR + 1 })
    }

    @Test fun `three domains of one tracker on the same day give days = 1`() {
        val source = FakeSource.of(
            listOf("a.flurry.com", "b.flurry.com", "c.flurry.com").map { Triple("app", it, 5 * DAY + 10) },
        )
        val ev = correlate(source, setOf("app")).evidence.getValue(Key("app", FLURRY))
        assertEquals(3, ev.lookups)
        assertEquals(1, ev.days)
    }

    @Suppress("MaxLineLength") // name quoted from the spec
    @Test fun `Foo_com and foo_com pairs merge, are matched once, and count and times are called with each raw domain`() {
        val spy = spyk(small)
        val source = FakeSource.of(
            listOf(
                Triple("a", "X.Flurry.com", 5 * DAY), Triple("a", "x.flurry.com.", 6 * DAY),
                Triple("a", "x.flurry.com", 7 * DAY),
            ),
        )
        val out = correlate(source, setOf("a"), usage = UsageIntervals(0, emptyMap()), registry = spy)
        verify(exactly = 1) { spy.matchDomainDetailed("x.flurry.com") }
        val raws = setOf("X.Flurry.com", "x.flurry.com.", "x.flurry.com")
        assertEquals(raws, source.counts.map { it.second }.toSet())
        assertEquals(raws, source.times.map { it.second }.toSet())
        val ev = out.evidence.getValue(Key("a", FLURRY))
        assertEquals(3, ev.lookups)
        assertEquals(3, ev.days)
        assertEquals(3, ev.background)
        assertEquals(1, out.evidence.size)
    }

    @Test fun `days is the union of dayList sets across a tracker's domains`() {
        val source = FakeSource.of(
            listOf(
                Triple("a", "a.flurry.com", 1 * DAY + 5), Triple("a", "a.flurry.com", 2 * DAY),
                Triple("a", "b.flurry.com", 2 * DAY + 7), Triple("a", "b.flurry.com", 3 * DAY + 9),
            ),
        )
        val ev = correlate(source, setOf("a")).evidence.getValue(Key("a", FLURRY))
        assertEquals(4, ev.lookups)
        assertEquals(3, ev.days)
        assertEquals(1 * DAY + 5, ev.first)
        assertEquals(3 * DAY + 9, ev.last)
    }

    @Test fun `each counted domain is reported with the signature that matched it`() {
        val source = FakeSource.of(
            listOf(
                Triple("a", "x.flurry.com", 1 * DAY + 5), Triple("a", "x.flurry.com", 2 * DAY + 7),
                Triple("a", "y.flurry.com", 3 * DAY + 9),
            ),
        )
        val out = correlate(source, setOf("a"))
        assertEquals(
            listOf(
                DomainEvidence(Key("a", FLURRY), "x.flurry.com", SignatureKind.DOMAIN_SUFFIX, "flurry.com", 2, 2, null,
                    1 * DAY + 5, 2 * DAY + 7),
                DomainEvidence(Key("a", FLURRY), "y.flurry.com", SignatureKind.DOMAIN_SUFFIX, "flurry.com", 1, 1, null,
                    3 * DAY + 9, 3 * DAY + 9),
            ),
            out.domains.sortedBy { it.domain },
        )
    }

    @Test fun `a domain owned by two trackers is reported under each`() {
        val source = FakeSource.of(listOf(Triple("a", "cdn.shared.example", 5 * DAY)))
        val out = correlate(source, setOf("a"))
        assertEquals(setOf(SHARED_A, SHARED_B), out.domains.map { it.key.trackerId }.toSet())
        assertTrue(out.domains.all { it.domain == "cdn.shared.example" && it.lookups == 1 })
        assertEquals(2, out.domains.size)
    }

    @Test fun `the lookups of a key's domains add up to its total`() {
        val rows = listOf(
            Triple("a", "x.flurry.com", 1 * DAY), Triple("a", "y.flurry.com", 2 * DAY),
            Triple("a", "y.flurry.com", 4 * DAY), Triple("a", "ads.doubleclick.net", 3 * DAY),
            Triple("b", "cdn.shared.example", 5 * DAY), Triple("b", "img.shared.example", 6 * DAY),
            Triple("b", "x.flurry.com", 7 * DAY),
        )
        val out = correlate(FakeSource.of(rows), setOf("a", "b"))
        assertEquals(out.evidence.keys, out.domains.map { it.key }.toSet())
        for ((key, total) in out.evidence) {
            val mine = out.domains.filter { it.key == key }
            assertEquals(key.toString(), total.lookups, mine.sumOf { it.lookups })
            assertEquals(key.toString(), total.first, mine.minOf { it.first })
            assertEquals(key.toString(), total.last, mine.maxOf { it.last })
        }
    }

    @Test fun `a domain is reported as recorded`() {
        val source = FakeSource.of(listOf(Triple("a", "T.Flurry.com.", 5 * DAY)))
        val out = correlate(source, setOf("a"))
        assertEquals(listOf("T.Flurry.com."), out.domains.map { it.domain })
    }

    @Test fun `per-domain background is a number only where it was timed`() {
        val rows = listOf(150L, 250L, 300L).map { Triple("a", "x.flurry.com", it) }
        val usage = UsageIntervals(0, mapOf("a" to listOf(100L..200L)))
        val timed = correlate(FakeSource.of(rows), setOf("a"), usage = usage)
        assertEquals(listOf(2), timed.domains.map { it.background })
        val untimed = correlate(FakeSource.of(rows), setOf("a"), usage = null)
        assertEquals(listOf<Int?>(null), untimed.domains.map { it.background })
    }

    @Test fun `a flood of junk subdomains cannot displace a real domain from the detail`() {
        val subs = padded("s", 20_001, ".flurry.com")
        val source = FakeSource(
            domainsOf = { app -> if (app == "a.flood") subs else listOf("ads.doubleclick.net") },
            countOf = { _, _ -> FakeSource.countRows(listOf(5 * DAY)) },
            timesOf = { _, _, _ -> listOf(5 * DAY) },
        )
        val out = correlate(source, setOf("a.flood", "b.real"))
        val real = out.domains.filter { it.key.packageName == "b.real" }.map { it.domain }
        assertEquals(listOf("ads.doubleclick.net"), real)
        assertEquals(MAX_MATCHED_PER_APP, out.domains.count { it.key.packageName == "a.flood" })
    }
}
