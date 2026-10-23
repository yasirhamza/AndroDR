package com.androdr.data.store

import androidx.collection.MutableLongIntMap
import java.nio.ByteBuffer

/**
 * Occurrence index of each body within one service's emitted list (spec §5.1 fact identity):
 * the n-th identical body without a source key becomes fact `H(bodyHash + "#" + n)`. Counted in
 * a primitive long → int map on the hash's first 8 bytes; a prefix collision between two
 * different bodies only bumps a counter (their fact keys still differ by body hash).
 * One counter per writer session and service, shared across that service's chunks.
 */
class OccurrenceCounter {
    private val seen = MutableLongIntMap()

    /** Returns 0 for the first occurrence of [hash]'s 64-bit prefix, then 1, 2, … */
    fun next(hash: ByteArray): Int {
        require(hash.size >= Long.SIZE_BYTES) { "hash must have at least 8 bytes" }
        val prefix = ByteBuffer.wrap(hash, 0, Long.SIZE_BYTES).long
        val n = seen.getOrDefault(prefix, 0)
        seen[prefix] = n + 1
        return n
    }
}
