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
 * False negatives are impossible by bloom invariant. Stage 2 uses **two
 * independent 64-bit hash functions** (FNV-1a and Murmur2-64A) stored in
 * co-sorted parallel arrays, and a query is only considered a hit if both
 * hashes match. This drops the collision probability from ~10⁻⁹ (single
 * 64-bit hash at 371k entries, the birthday bound) to ~10⁻¹⁸ — effectively
 * zero, and crucially independent of any clustering bias in either hash
 * function individually. The two hashes are structurally distinct (FNV is
 * a byte-at-a-time multiply-xor, Murmur2 is an 8-byte-at-a-time
 * multiply-shift-xor), so a collision would require a simultaneous
 * preimage-hit in two unrelated mixers on the same input pair.
 *
 * ## Thread-safety
 *
 * Immutable after construction. [IndicatorResolver] holds a volatile reference
 * that is replaced atomically on refresh, so readers see either the old or new
 * index but never a torn state.
 */
internal class DomainBloomIndex private constructor(
    private val bloom: BloomFilter,
    // Co-sorted parallel arrays: primaryHashes[i] and secondaryHashes[i] always
    // refer to the same indexed domain. A query is a hit iff both hashes match.
    private val primaryHashes: LongArray,
    private val secondaryHashes: LongArray
) {

    /** `true` iff [domain] is present in the indexed IOC set. */
    @Suppress("ReturnCount") // dual-hash walk uses early returns at each collision-adjacent probe
    fun contains(domain: String): Boolean {
        if (!bloom.mightContain(domain)) return false        // ~99% of negatives exit here
        val p = fnv64(domain)
        val idx = primaryHashes.binarySearch(p)
        if (idx < 0) return false
        val s = murmur64(domain)
        // Dual-hash check: require matching secondary at the same index. If
        // primary hash collisions ever occur between two distinct IOC entries
        // (~10⁻⁹ at 371k entries), `binarySearch` returns *some* matching
        // index; walk adjacent entries whose primary matches and test their
        // secondary too. This loop terminates in O(1) under normal conditions
        // and is bounded by the (tiny) expected number of primary duplicates.
        if (secondaryHashes[idx] == s) return true
        var left = idx - 1
        while (left >= 0 && primaryHashes[left] == p) {
            if (secondaryHashes[left] == s) return true
            left--
        }
        var right = idx + 1
        while (right < primaryHashes.size && primaryHashes[right] == p) {
            if (secondaryHashes[right] == s) return true
            right++
        }
        return false
    }

    /** Number of distinct domains indexed. */
    val size: Int get() = primaryHashes.size

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
            val n = normalized.size
            val rawPrimary   = LongArray(n)
            val rawSecondary = LongArray(n)
            var i = 0
            for (d in normalized) {
                bloom.put(d)
                rawPrimary[i]   = fnv64(d)
                rawSecondary[i] = murmur64(d)
                i++
            }
            // Co-sort the two parallel arrays by primary hash. We sort an
            // Integer[] of indices and then materialize both output arrays
            // from the permutation. The transient boxed-Integer array is
            // allocated once per 12 h refresh — negligible for the memory
            // safety win this buys.
            val order = Array(n) { it }
            java.util.Arrays.sort(order) { a, b -> rawPrimary[a].compareTo(rawPrimary[b]) }
            val primary   = LongArray(n) { rawPrimary[order[it]] }
            val secondary = LongArray(n) { rawSecondary[order[it]] }
            return DomainBloomIndex(bloom, primary, secondary)
        }

        /** Empty index — used before the first refresh completes. */
        fun empty(): DomainBloomIndex = build(emptyList())

        /**
         * Primary hash: 64-bit FNV-1a. Byte-at-a-time multiply-xor.
         */
        internal fun fnv64(s: String): Long {
            var h = FNV_OFFSET_64
            for (i in s.indices) {
                h = h xor (s[i].code.toLong() and 0xFFL)
                h *= FNV_PRIME_64
            }
            return h
        }

        /**
         * Secondary hash: Murmur2-64A. 8-byte-at-a-time multiply-shift-xor.
         * Structurally distinct from FNV-1a, so a collision in both hashes on
         * the same input pair requires two unrelated mixers to agree, which is
         * cryptographically negligible. Used as the exact-match confirmation
         * stage alongside [fnv64].
         */
        internal fun murmur64(s: String): Long {
            var h = MURMUR_SEED xor (s.length.toLong() * MURMUR_M)
            var i = 0
            // Process 8 characters at a time, treating each char's low byte as
            // one byte of the input. (Domain names are ASCII; no UTF-16
            // surrogate handling needed.)
            while (i + CHUNK_BYTES <= s.length) {
                var k = 0L
                for (j in 0 until CHUNK_BYTES) {
                    k = k or ((s[i + j].code.toLong() and 0xFFL) shl (j * BITS_PER_BYTE))
                }
                k *= MURMUR_M
                k = k xor (k ushr MURMUR_R)
                k *= MURMUR_M
                h = h xor k
                h *= MURMUR_M
                i += CHUNK_BYTES
            }
            // Tail
            val tailLen = s.length - i
            if (tailLen > 0) {
                var tail = 0L
                for (j in 0 until tailLen) {
                    tail = tail or ((s[i + j].code.toLong() and 0xFFL) shl (j * BITS_PER_BYTE))
                }
                h = h xor tail
                h *= MURMUR_M
            }
            // Finalization mix — avalanche
            h = h xor (h ushr MURMUR_R)
            h *= MURMUR_M
            h = h xor (h ushr MURMUR_R)
            return h
        }

        private const val FNV_OFFSET_64: Long = -3750763034362895579L  // 0xcbf29ce484222325
        private const val FNV_PRIME_64: Long  = 1099511628211L          // 0x100000001b3

        // Murmur2-64A constants (Austin Appleby, public domain).
        private const val MURMUR_SEED: Long = -0x3c5a1b2c4d6e7f01L       // arbitrary non-zero seed
        private const val MURMUR_M:    Long = -0x395b586ca42e166bL       // 0xc6a4a7935bd1e995
        private const val MURMUR_R:    Int  = 47
        private const val CHUNK_BYTES:    Int = 8
        private const val BITS_PER_BYTE:  Int = 8
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
