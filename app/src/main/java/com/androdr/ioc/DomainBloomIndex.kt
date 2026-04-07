package com.androdr.ioc

import java.util.Locale

/**
 * Two-stage in-memory set-membership index for domain IOCs.
 *
 * ## Why
 *
 * The VPN packet-read thread calls [IndicatorResolver.isKnownBadDomain] for every
 * DNS query. Previously the LRU-miss path did `runBlocking(Dispatchers.IO)` against
 * a ~371k-row Room table, which stalled the read thread for 5–50 ms whenever the
 * Room write lock was contended by the DNS-event batch writer or [IocUpdateWorker].
 * Those stalls were the largest remaining tail-latency drain source once per-query
 * coroutine fan-out and unbatched inserts were fixed in the previous PR.
 *
 * ## How
 *
 * The index holds two parallel structures built once per refresh:
 *
 *  1. **Bloom filter** — cheap probabilistic "definitely not / maybe" gate.
 *     Parameters are tuned for ~1% false-positive rate at the configured capacity,
 *     which at 371k entries is ~460 KB and ~150 ns per negative lookup.
 *  2. **Sorted 64-bit hash array** — exact fallback for bloom-positive hits.
 *     At ~3 MB for 371k entries it fits in a single `LongArray` and answers
 *     bloom-positive queries in ~1 µs via `Arrays.binarySearch`.
 *
 * False negatives are impossible by bloom invariant. False positives in stage 1
 * are almost always resolved by stage 2, with one accepted residual risk: if a
 * *non-IOC* domain's 64-bit FNV-1a hash happens to collide with the hash of a
 * real IOC entry, the non-IOC will be reported as a hit (because stage 2's
 * binary search matches on hash, not string). At 371k entries over 2^64 slots,
 * the birthday probability of any such collision is ~3.7 × 10⁻⁹ — accepted at
 * this scale. If the IOC set ever exceeds a few million entries, switch to a
 * stronger mixer (xxHash64 or Murmur3-128 truncated) and/or store `(hash,
 * secondaryHash)` pairs so equality requires both to match.
 *
 * ## Thread-safety
 *
 * Immutable after construction. [IndicatorResolver] holds a volatile reference
 * that is replaced atomically on refresh, so readers see either the old or new
 * index but never a torn state.
 */
internal class DomainBloomIndex private constructor(
    private val bloom: BloomFilter,
    private val sortedHashes: LongArray
) {

    /** `true` iff [domain] is present in the indexed IOC set. */
    fun contains(domain: String): Boolean {
        if (!bloom.mightContain(domain)) return false        // ~99% of negatives exit here
        val h = fnv64(domain)
        return sortedHashes.binarySearch(h) >= 0
    }

    /** Number of distinct domains indexed. */
    val size: Int get() = sortedHashes.size

    companion object {
        /** Expected false-positive rate for the bloom filter stage (post-build). */
        const val TARGET_FP_RATE = 0.01

        /**
         * Build an index from the given domain strings. Duplicates are collapsed.
         * Empty and blank inputs are skipped. Domains are normalized to lowercase
         * + trailing-dot-stripped so the index is query-side trivial.
         */
        fun build(domains: Collection<String>): DomainBloomIndex {
            // Deduplicate and normalize in one pass. LinkedHashSet for predictable
            // iteration order (tests care; production doesn't).
            val normalized = LinkedHashSet<String>(domains.size.coerceAtLeast(16))
            for (raw in domains) {
                if (raw.isBlank()) continue
                // Locale.ROOT avoids locale-sensitive lowercase collapses
                // (e.g. Turkish 'I' → 'ı') that would cause build-time and
                // query-time normalization to diverge on a non-ROOT default locale.
                val n = raw.trim().trimEnd('.').lowercase(Locale.ROOT)
                if (n.isNotEmpty()) normalized.add(n)
            }

            val bloom = BloomFilter.create(
                expectedInsertions = normalized.size.coerceAtLeast(1),
                fpRate = TARGET_FP_RATE
            )
            val hashes = LongArray(normalized.size)
            var i = 0
            for (d in normalized) {
                bloom.put(d)
                hashes[i++] = fnv64(d)
            }
            hashes.sort()
            return DomainBloomIndex(bloom, hashes)
        }

        /** Empty index — used before the first refresh completes. */
        fun empty(): DomainBloomIndex = build(emptyList())

        /**
         * 64-bit FNV-1a hash. Chosen for simplicity and zero dependencies; the
         * collision risk at our set size is negligible (see class KDoc).
         */
        internal fun fnv64(s: String): Long {
            var h = FNV_OFFSET_64
            for (i in s.indices) {
                h = h xor (s[i].code.toLong() and 0xFFL)
                h *= FNV_PRIME_64
            }
            return h
        }

        private const val FNV_OFFSET_64: Long = -3750763034362895579L  // 0xcbf29ce484222325
        private const val FNV_PRIME_64: Long  = 1099511628211L          // 0x100000001b3
    }
}

/**
 * Bit-array bloom filter with k hash functions derived via double-hashing from
 * two independent FNV variants. No external dependency; ~80 LOC; tuned for the
 * parameters documented in [DomainBloomIndex].
 */
internal class BloomFilter private constructor(
    private val bits: LongArray,
    private val mBits: Int,
    private val k: Int
) {
    fun put(s: String) {
        val (h1, h2) = hashPair(s)
        var combined = h1
        repeat(k) {
            setBit(bitIndex(combined))
            combined += h2
        }
    }

    fun mightContain(s: String): Boolean {
        val (h1, h2) = hashPair(s)
        var combined = h1
        repeat(k) {
            if (!getBit(bitIndex(combined))) return false
            combined += h2
        }
        return true
    }

    /** Map a 64-bit hash to a non-negative bit index in `[0, mBits)`. */
    private fun bitIndex(hash: Long): Int =
        ((hash and Long.MAX_VALUE) % mBits).toInt()

    private fun setBit(index: Int) {
        bits[index ushr LONG_SHIFT] = bits[index ushr LONG_SHIFT] or (1L shl (index and LONG_MASK))
    }

    private fun getBit(index: Int): Boolean =
        (bits[index ushr LONG_SHIFT] and (1L shl (index and LONG_MASK))) != 0L

    /** Double-hashing scheme: derive k positions from two independent seeds. */
    private fun hashPair(s: String): Pair<Long, Long> {
        var h1 = FNV_OFFSET_64_A
        var h2 = FNV_OFFSET_64_B
        for (i in s.indices) {
            val c = s[i].code.toLong() and 0xFFL
            h1 = (h1 xor c) * FNV_PRIME_64_A
            h2 = (h2 xor c) * FNV_PRIME_64_B
        }
        return h1 to h2
    }

    companion object {
        private const val LONG_SHIFT = 6     // log2(64)
        private const val LONG_MASK  = 0x3F  // 64 - 1

        // Two independent FNV-style constants for double-hashing. Using different
        // offsets and primes gives us two independent hash functions without
        // pulling in a crypto dependency.
        private const val FNV_OFFSET_64_A: Long = -3750763034362895579L
        private const val FNV_PRIME_64_A:  Long = 1099511628211L
        // Use ULong literals for constants with the top bit set and cast to Long,
        // since Kotlin Long literals are signed and 0x8_ values are out of range.
        private val FNV_OFFSET_64_B: Long = 0xcbf29ce484222326UL.toLong()
        private val FNV_PRIME_64_B:  Long = 0x880355f21e6d1965UL.toLong()

        fun create(expectedInsertions: Int, fpRate: Double): BloomFilter {
            val n = expectedInsertions.coerceAtLeast(1)
            // Optimal parameters for a standard bloom filter:
            //   m = -n * ln(p) / (ln(2))^2
            //   k = (m / n) * ln(2)
            val ln2 = Math.log(2.0)
            val m = Math.ceil(-n * Math.log(fpRate) / (ln2 * ln2)).toInt().coerceAtLeast(64)
            val k = Math.max(1, Math.round((m.toDouble() / n) * ln2).toInt())
            val words = (m + 63) ushr LONG_SHIFT
            return BloomFilter(LongArray(words), m, k)
        }
    }
}
