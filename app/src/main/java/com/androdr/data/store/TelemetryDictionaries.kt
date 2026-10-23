package com.androdr.data.store

import com.androdr.sigma.TaxonomyContract
import java.security.MessageDigest
import java.util.concurrent.ConcurrentHashMap

/**
 * The immutable, versioned Deflate preset dictionaries for event bodies (spec §5.1).
 *
 * A stored body is only readable with the exact dictionary bytes it was compressed against,
 * so a version's bytes never change: [PINNED_SHA256] pins each, loading verifies the pin, and
 * `scripts/build_telemetry_dictionaries.py` regenerates candidates that
 * TelemetryDictionariesTest compares to the pins (a changed candidate must ship as a new
 * version). Version 1 is one shared dictionary covering every event service.
 *
 * @param load returns the bytes of a raw resource by name (e.g. `telemetry_dict_events_v1`).
 */
class TelemetryDictionaries(private val load: (String) -> ByteArray) {
    private val cache = ConcurrentHashMap<Int, ByteArray>()

    /** The newest dictionary version for [service] and its bytes. */
    fun current(service: String): Pair<Int, ByteArray> {
        require(service in TaxonomyContract.eventServices) { "no dictionary for non-event service $service" }
        val version = PINNED_SHA256.keys.max()
        return version to byVersion(version)
    }

    /** The bytes of [v], verified against [PINNED_SHA256]. Throws for an unknown or altered version. */
    fun byVersion(v: Int): ByteArray {
        cache[v]?.let { return it }
        val name = RESOURCE_NAMES[v] ?: throw IllegalArgumentException("unknown dictionary version $v")
        val bytes = load(name)
        check(sha256Hex(bytes) == PINNED_SHA256.getValue(v)) { "dictionary v$v does not match its pinned hash" }
        cache[v] = bytes
        return bytes
    }

    companion object {
        /** SHA-256 (hex) of each version's bytes. Add a new entry for a new version; never edit one. */
        val PINNED_SHA256: Map<Int, String> = mapOf(
            1 to "088b5cf418f95419daeebc98ac36b92331abe499622fb7a9b27813c6021fccca",
        )

        private val RESOURCE_NAMES: Map<Int, String> = mapOf(
            1 to "telemetry_dict_events_v1",
        )

        private fun sha256Hex(b: ByteArray): String =
            MessageDigest.getInstance("SHA-256").digest(b).joinToString("") { "%02x".format(it) }
    }
}
