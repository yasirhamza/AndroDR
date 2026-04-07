package com.androdr.ioc

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Unit tests for [DomainBloomIndex]. Validates the bloom-gate + exact-hash
 * pipeline, normalization, empty-index behavior, and a representative
 * false-positive budget on random inputs.
 */
class DomainBloomIndexTest {

    @Test
    fun `empty index matches nothing`() {
        val index = DomainBloomIndex.empty()
        assertFalse(index.contains("evil.com"))
        assertFalse(index.contains(""))
        assertEquals(0, index.size)
    }

    @Test
    fun `known domains are matched`() {
        val index = DomainBloomIndex.build(listOf("evil.com", "bad.example", "c2.apt.net"))
        assertTrue(index.contains("evil.com"))
        assertTrue(index.contains("bad.example"))
        assertTrue(index.contains("c2.apt.net"))
    }

    @Test
    fun `unknown domains are not matched`() {
        val index = DomainBloomIndex.build(listOf("evil.com"))
        assertFalse(index.contains("good.com"))
        assertFalse(index.contains("safe.example"))
    }

    @Test
    fun `normalization strips trailing dot and lowercases`() {
        val index = DomainBloomIndex.build(listOf("Evil.COM.", "MIXED.Case"))
        assertTrue(index.contains("evil.com"))
        assertTrue(index.contains("mixed.case"))
    }

    @Test
    fun `blank inputs are skipped during build`() {
        val index = DomainBloomIndex.build(listOf("", "   ", "evil.com"))
        assertEquals(1, index.size)
        assertTrue(index.contains("evil.com"))
    }

    @Test
    fun `duplicates are collapsed`() {
        val index = DomainBloomIndex.build(listOf("evil.com", "evil.com", "evil.com."))
        assertEquals(1, index.size)
    }

    @Test
    fun `label-stripping walk is caller's responsibility — index does exact match`() {
        // The index itself is exact-match only; subdomain walking is done in
        // IndicatorResolver.isKnownBadDomain(). Verify that exact-match
        // semantics are preserved (no accidental prefix matching).
        val index = DomainBloomIndex.build(listOf("evil.com"))
        assertFalse(index.contains("sub.evil.com"))
        assertFalse(index.contains("notevil.com"))
        assertFalse(index.contains("evil.co"))
    }

    @Test
    fun `false-positive rate stays near target on random load`() {
        // Build an index with 1000 known domains, then query 20,000 random
        // non-members. Target FP rate is 1%; allow 3% for statistical slack.
        val known = (0 until 1000).map { "known-$it.example" }
        val index = DomainBloomIndex.build(known)
        var falsePositives = 0
        val trials = 20_000
        for (i in 0 until trials) {
            if (index.contains("probe-$i.notaknown")) falsePositives++
        }
        val observedRate = falsePositives.toDouble() / trials
        assertTrue(
            "Observed FP rate $observedRate exceeded budget (target ${DomainBloomIndex.TARGET_FP_RATE})",
            observedRate < 0.03
        )
    }

    @Test
    fun `bloom filter handles large input without errors`() {
        // Smoke test on a realistic-order-of-magnitude input. We don't assert
        // on memory here; we just verify the build completes and hits work.
        val large = (0 until 50_000).map { "host-$it.evil.example" }
        val index = DomainBloomIndex.build(large)
        assertEquals(50_000, index.size)
        assertTrue(index.contains("host-0.evil.example"))
        assertTrue(index.contains("host-49999.evil.example"))
        assertFalse(index.contains("not-in-set.example"))
    }

    @Test
    fun `fnv64 is deterministic and sensitive to input`() {
        val a = DomainBloomIndex.fnv64("evil.com")
        val b = DomainBloomIndex.fnv64("evil.com")
        val c = DomainBloomIndex.fnv64("evil.net")
        assertEquals(a, b)
        assertFalse("different inputs should produce different hashes", a == c)
    }

    @Test
    fun `murmur64 is deterministic and differs from fnv64 on same input`() {
        val s = "evil.com"
        val a = DomainBloomIndex.murmur64(s)
        val b = DomainBloomIndex.murmur64(s)
        assertEquals(a, b)
        // Structural independence check: at least one input must hash to
        // different values under the two mixers. If this ever fires it means
        // the dual-hash scheme has degenerated to a single-hash scheme.
        assertFalse(
            "FNV and Murmur should not produce identical hashes for all inputs",
            DomainBloomIndex.fnv64(s) == a
        )
    }

    @Test
    fun `dual-hash blocks a collision on primary alone`() {
        // We can't easily construct a real FNV collision, so simulate the
        // scenario by checking that an unrelated string (whose primary hash
        // almost certainly doesn't match any IOC) is rejected even after
        // passing the bloom filter. Tighten the FP budget to near-zero to
        // demonstrate the secondary hash is doing work.
        val known = (0 until 5000).map { "known-$it.example" }
        val index = DomainBloomIndex.build(known)
        // Probe 100k random non-members. With the previous single-hash
        // design, at 5000 entries and 100k probes the expected false-hit
        // rate was ~2.7×10⁻¹¹ (essentially zero), so this test wouldn't
        // have distinguished the two designs at this scale. The point of
        // this test is instead to confirm that the dual-hash path *never*
        // returns true for a clean probe — if it ever does, something is
        // structurally wrong (e.g. secondary hash ignored).
        var hits = 0
        for (i in 0 until 100_000) {
            if (index.contains("probe-$i.unrelated.net")) hits++
        }
        assertEquals("dual-hash must produce zero false hits at this scale", 0, hits)
    }
}
