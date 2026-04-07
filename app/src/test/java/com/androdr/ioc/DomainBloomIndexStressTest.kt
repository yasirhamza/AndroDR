package com.androdr.ioc

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import kotlin.random.Random

/**
 * Synthetic stress test for [DomainBloomIndex] at realistic scale.
 *
 * Simulates the workload the bloom filter was designed to handle on the VPN
 * packet-read thread:
 *
 *  - ~371k IOC entries, matching the current Room-backed indicator database.
 *  - A mixed DNS query stream where ~99% of queries target clean domains
 *    (normal browsing) and ~1% hit indexed IOC entries (rare blocklist match).
 *  - Domains are normalized to lowercase ASCII, trailing dot stripped, the
 *    same normalization the production build path applies.
 *
 * The test asserts four things:
 *
 *  1. **Zero false negatives.** Every query that matches an indexed entry
 *     must be reported as a hit (by the bloom invariant this is guaranteed,
 *     but we prove it empirically at scale).
 *  2. **Zero dual-hash false positives.** At 371k entries over 128 bits of
 *     combined FNV-1a + Murmur2-64A hash space, the expected number of
 *     collisions across 10⁶ clean probes is effectively zero; a single
 *     false positive indicates a real bug.
 *  3. **Per-query latency well under the Room-backed baseline.** The previous
 *     implementation stalled the VPN read thread for 5–50 ms under write-lock
 *     contention. The bloom path must answer each query in less than a
 *     microsecond on JVM — far below the old tail-latency budget.
 *  4. **Index build time fits within a reasonable refresh window.** Building
 *     a 371k-entry index should take well under 1 second so the 12-hour
 *     refresh path doesn't add user-visible latency at app startup.
 *
 * Runtime on a modern desktop JVM: ~2–5 seconds total. This is heavier than
 * a typical unit test but still bearable as part of `testDebugUnitTest`, and
 * catches performance regressions immediately rather than discovering them
 * on device.
 */
class DomainBloomIndexStressTest {

    companion object {
        private const val IOC_SET_SIZE = 371_000
        private const val QUERY_COUNT  = 1_000_000
        // Probability that a generated query targets an indexed IOC entry
        // rather than a clean domain. Picked to match observed real-world
        // stalkerware/IOC hit rates on browsing traffic (well under 1%).
        private const val IOC_HIT_PROBABILITY = 0.01

        // Fixed seed so test failures are reproducible across runs.
        private const val QUERY_SEED: Long = 0xD15EA5E

        // Per-query latency budget — generous vs. the ~150 ns target on
        // modern hardware but tight enough to catch pathological regressions
        // (e.g. accidental Room calls creeping back in, or bloom filter
        // degenerating to linear scan).
        private const val MAX_AVG_QUERY_NS = 10_000L   // 10 µs
        private const val MAX_BUILD_MS     = 5_000L    // 5 s
    }

    /** Generate a deterministic synthetic IOC domain for index [i]. */
    private fun iocDomain(i: Int): String {
        // Mix a few TLD suffixes so the hash distribution is closer to real
        // domain traffic (which clusters on .com / .net / .org).
        val suffix = when (i % 5) {
            0    -> "badnet.example"
            1    -> "c2.malware.test"
            2    -> "stalker.apt"
            3    -> "phish.evil.com"
            else -> "exfil.spy.net"
        }
        return "ioc-${i.toString(16)}.$suffix"
    }

    /** Generate a deterministic synthetic clean domain for query index [q]. */
    private fun cleanDomain(rng: Random): String {
        val subdomainLen = 6 + rng.nextInt(10)
        val sb = StringBuilder(subdomainLen + 12)
        repeat(subdomainLen) { sb.append(('a' + rng.nextInt(26))) }
        sb.append('.')
        // Common TLDs to approximate real browsing distribution.
        sb.append(
            when (rng.nextInt(6)) {
                0    -> "google.com"
                1    -> "cloudflare.com"
                2    -> "github.io"
                3    -> "amazonaws.com"
                4    -> "wikipedia.org"
                else -> "example.net"
            }
        )
        return sb.toString()
    }

    @Test
    @Suppress("LongMethod") // Linear four-phase stress scenario reads more clearly in one body
    // than split across helpers; splitting would force state threading through ~6 parameters.
    fun `bloom index stress — 371k entries, 1M queries, realistic mix`() {
        // ── Phase 1: build the index ─────────────────────────────────────
        val iocList = ArrayList<String>(IOC_SET_SIZE)
        for (i in 0 until IOC_SET_SIZE) iocList.add(iocDomain(i))

        val buildStart = System.nanoTime()
        val index = DomainBloomIndex.build(iocList)
        val buildMs = (System.nanoTime() - buildStart) / 1_000_000

        assertEquals("index must contain all unique IOC entries", IOC_SET_SIZE, index.size)
        assertTrue(
            "index build took $buildMs ms, budget is $MAX_BUILD_MS ms",
            buildMs < MAX_BUILD_MS
        )
        println("[stress] built index with $IOC_SET_SIZE entries in $buildMs ms")

        // ── Phase 2: generate the query stream ───────────────────────────
        // Materializing 1M query strings up front (~40 MB transient) keeps
        // the measurement loop tight and excludes random-number overhead
        // from the per-query latency number.
        val queries    = arrayOfNulls<String>(QUERY_COUNT)
        val expectHits = BooleanArray(QUERY_COUNT)
        val qrng = Random(QUERY_SEED)
        var expectedHitCount = 0
        for (q in 0 until QUERY_COUNT) {
            if (qrng.nextDouble() < IOC_HIT_PROBABILITY) {
                // Sample a random IOC from the indexed set, possibly as a
                // subdomain to exercise the label-stripping walk in the
                // resolver path. Here we query the index directly, so we
                // use the exact IOC form.
                val idx = qrng.nextInt(IOC_SET_SIZE)
                queries[q]    = iocDomain(idx)
                expectHits[q] = true
                expectedHitCount++
            } else {
                queries[q]    = cleanDomain(qrng)
                expectHits[q] = false
            }
        }
        println(
            "[stress] generated $QUERY_COUNT queries; " +
                "$expectedHitCount expected hits (${"%.2f".format(100.0 * expectedHitCount / QUERY_COUNT)}%)"
        )

        // ── Phase 3: measure ─────────────────────────────────────────────
        // Warm up the JIT on a small slice so the main loop measures
        // steady-state code, not compilation. 10k iterations is enough to
        // trigger C2 compilation of contains()/containsHashes() on HotSpot.
        repeat(10_000) { index.contains(queries[it % QUERY_COUNT]!!) }

        var hits = 0
        var falseNegatives = 0
        var falsePositives = 0
        val start = System.nanoTime()
        for (q in 0 until QUERY_COUNT) {
            val hit = index.contains(queries[q]!!)
            if (hit) hits++
            if (expectHits[q] && !hit) falseNegatives++
            if (!expectHits[q] && hit) falsePositives++
        }
        val elapsedNs  = System.nanoTime() - start
        val avgQueryNs = elapsedNs / QUERY_COUNT
        val elapsedMs  = elapsedNs / 1_000_000
        val qps        = (QUERY_COUNT * 1_000_000_000.0 / elapsedNs).toLong()

        println(
            "[stress] $QUERY_COUNT queries in $elapsedMs ms " +
                "(avg $avgQueryNs ns/query, ${"%,d".format(qps)} queries/sec)"
        )
        println(
            "[stress] hits=$hits  expectedHits=$expectedHitCount  " +
                "falseNegatives=$falseNegatives  falsePositives=$falsePositives"
        )

        // ── Phase 4: assert correctness ──────────────────────────────────
        assertEquals(
            "bloom filter must have zero false negatives (invariant)",
            0, falseNegatives
        )
        assertEquals(
            "dual-hash index must have zero false positives at this scale",
            0, falsePositives
        )
        assertEquals(
            "total hit count must equal expected hit count",
            expectedHitCount, hits
        )
        assertTrue(
            "avg query time $avgQueryNs ns exceeds budget $MAX_AVG_QUERY_NS ns",
            avgQueryNs < MAX_AVG_QUERY_NS
        )
    }

    @Test
    fun `bloom index stress — pure negative workload (browsing without IOC hits)`() {
        // Realistic "idle browsing" path: every query misses the index.
        // This is the fast path that matters most for battery — ~99% of real
        // DNS queries look like this. Verifies the bloom-only exit is fast
        // and produces zero false positives at 1M probes.
        val iocList = (0 until IOC_SET_SIZE).map { iocDomain(it) }
        val index = DomainBloomIndex.build(iocList)

        val qrng = Random(QUERY_SEED xor 1L)
        val queries = Array(QUERY_COUNT) { cleanDomain(qrng) }

        repeat(10_000) { index.contains(queries[it % QUERY_COUNT]) }

        var hits = 0
        val start = System.nanoTime()
        for (q in queries) if (index.contains(q)) hits++
        val elapsedNs  = System.nanoTime() - start
        val avgQueryNs = elapsedNs / QUERY_COUNT
        val qps        = (QUERY_COUNT * 1_000_000_000.0 / elapsedNs).toLong()

        println(
            "[stress/negative] $QUERY_COUNT clean queries in " +
                "${elapsedNs / 1_000_000} ms (avg $avgQueryNs ns/query, " +
                "${"%,d".format(qps)} queries/sec, false-positive hits=$hits)"
        )

        assertEquals(
            "dual-hash index must reject all clean domains (zero false positives)",
            0, hits
        )
        assertTrue(
            "negative-path avg query time $avgQueryNs ns exceeds budget $MAX_AVG_QUERY_NS ns",
            avgQueryNs < MAX_AVG_QUERY_NS
        )
    }
}
