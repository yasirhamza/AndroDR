package com.androdr.data.store

import android.os.StatFs

/** What the import preflight found (spec §5.2 Storage protection). */
sealed interface Preflight {
    data object Ok : Preflight

    /**
     * Free space after the import would be below `2 × estimate + 200 MB`, or the size is unknown
     * ([estimate] null). The user may cancel or import anyway; the per-chunk reserve still applies.
     */
    data class Tight(val estimate: Long?, val free: Long) : Preflight
}

/**
 * Free-space checks on the database's partition: the import preflight ([check]) and the fixed
 * per-chunk reserve ([reserveOk]) that nothing overrides.
 */
class StoragePreflight(private val statFs: () -> StatFs) {

    /** Free bytes available to the app on the database's partition. */
    fun freeBytes(): Long = statFs().availableBytes

    /**
     * [decompressedBytes] is the archive's summed decompressed entry sizes; null (or negative)
     * when any entry's size is unknown, which always yields [Preflight.Tight] with no estimate.
     */
    fun check(decompressedBytes: Long?): Preflight {
        val free = freeBytes()
        if (decompressedBytes == null || decompressedBytes < 0) return Preflight.Tight(null, free)
        val estimate = (decompressedBytes * STORED_SIZE_FACTOR).toLong()
        return if (free - estimate < 2 * estimate + HEADROOM_BYTES) Preflight.Tight(estimate, free) else Preflight.Ok
    }

    /** False when free space is below [CHUNK_RESERVE_BYTES]; checked before every import append and before finish. */
    fun reserveOk(): Boolean = freeBytes() >= CHUNK_RESERVE_BYTES

    /** How much to free so the reserve holds again (0 when it holds). */
    fun shortfall(): Long = (CHUNK_RESERVE_BYTES - freeBytes()).coerceAtLeast(0L)

    companion object {
        /** Measured stored bytes per decompressed input byte (initial value). */
        const val STORED_SIZE_FACTOR = 0.6

        /** The fixed per-chunk reserve. */
        const val CHUNK_RESERVE_BYTES = 150L * 1024 * 1024

        /** The `+ 200 MB` of the preflight rule. */
        const val HEADROOM_BYTES = 200L * 1024 * 1024
    }
}
