package com.androdr.data.store

import java.nio.ByteBuffer
import java.security.MessageDigest

/**
 * 128-bit content hashes (SHA-256 truncated to 16 bytes) used as BLOB keys by the
 * telemetry store. A raw `ByteArray` compares by identity, so every map or set keyed on a
 * hash must go through [key].
 */
object HashKeys {
    const val SIZE = 16

    fun h128(bytes: ByteArray): ByteArray =
        MessageDigest.getInstance("SHA-256").digest(bytes).copyOf(SIZE)

    fun h128(s: String): ByteArray = h128(s.toByteArray(Charsets.UTF_8))

    /** A content-comparing, hashable wrapper for use as a map key. */
    fun key(b: ByteArray): ByteBuffer = ByteBuffer.wrap(b)
}
