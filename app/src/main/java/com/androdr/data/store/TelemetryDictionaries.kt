package com.androdr.data.store

import java.security.MessageDigest
import java.util.concurrent.ConcurrentHashMap

/**
 * The immutable, versioned per-family Deflate preset dictionaries for event bodies (spec §5.1).
 *
 * A stored body is only readable with the exact dictionary bytes it was compressed against,
 * so a version's bytes never change: [PINNED_SHA256] pins each, loading verifies the pin, and
 * `scripts/build_telemetry_dictionaries.py` regenerates candidates that
 * TelemetryDictionariesTest compares to the pins (a changed candidate must ship as a new
 * version). Version numbers are globally unique and each belongs to exactly one family, so
 * [byVersion] needs only the number. Each dictionary is <= 4 KiB.
 *
 * Service -> family table ([FAMILY_OF_SERVICE]; covers every `TaxonomyContract.eventServices`):
 * - `network`: network_monitor
 * - `dns`: dns_monitor
 * - `activity`: package_install_history, usage_stats, appops_audit, wakelock_parser,
 *   tombstone_parser, battery_daily (shared package-centred vocabulary)
 * - `security`: security_log
 *
 * @param load returns the bytes of a raw resource by name (e.g. `telemetry_dict_network_v1`).
 */
class TelemetryDictionaries(private val load: (String) -> ByteArray) {
    private val cache = ConcurrentHashMap<Int, ByteArray>()

    /** The newest dictionary version of [service]'s family and its bytes. */
    fun current(service: String): Pair<Int, ByteArray> {
        val family = requireNotNull(FAMILY_OF_SERVICE[service]) { "no dictionary family for service $service" }
        val version = VERSIONS.filterValues { it.first == family }.keys.max()
        return version to byVersion(version)
    }

    /** The bytes of [v], verified against [PINNED_SHA256]. Throws for an unknown or altered version. */
    fun byVersion(v: Int): ByteArray {
        cache[v]?.let { return it }
        val (_, name) = VERSIONS[v] ?: throw IllegalArgumentException("unknown dictionary version $v")
        val bytes = load(name)
        check(sha256Hex(bytes) == PINNED_SHA256.getValue(v)) { "dictionary v$v does not match its pinned hash" }
        cache[v] = bytes
        return bytes
    }

    companion object {
        /** SHA-256 (hex) of each version's bytes. Add a new entry for a new version; never edit one. */
        val PINNED_SHA256: Map<Int, String> = mapOf(
            1 to "0d10916454d4ad553a7eff869662f8c4e16eb2fe66005a5fbbc041d31be6d996",
            2 to "5b053f8053554b834785636bbce9867294353b3801ed40e2025ffeb2597deffb",
            3 to "a075ca720081faf7b05da4077cc7a11435f9cbf67ce498eb6e145993081026ad",
            4 to "7915fd3ead495a9ecfe32bf45f7b5670a78c97e2ad86e0cbcb2f20da8248d524",
        )

        /** version -> (family, raw resource name). */
        internal val VERSIONS: Map<Int, Pair<String, String>> = mapOf(
            1 to ("network" to "telemetry_dict_network_v1"),
            2 to ("dns" to "telemetry_dict_dns_v2"),
            3 to ("activity" to "telemetry_dict_activity_v3"),
            4 to ("security" to "telemetry_dict_security_v4"),
        )

        /** service -> family. Every event service must appear (checked by TelemetryDictionariesTest). */
        internal val FAMILY_OF_SERVICE: Map<String, String> = mapOf(
            "network_monitor" to "network",
            "dns_monitor" to "dns",
            "package_install_history" to "activity",
            "usage_stats" to "activity",
            "appops_audit" to "activity",
            "wakelock_parser" to "activity",
            "tombstone_parser" to "activity",
            "battery_daily" to "activity",
            "security_log" to "security",
        )

        private fun sha256Hex(b: ByteArray): String =
            MessageDigest.getInstance("SHA-256").digest(b).joinToString("") { "%02x".format(it) }
    }
}
