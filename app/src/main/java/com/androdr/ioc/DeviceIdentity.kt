package com.androdr.ioc

import android.os.Build

/**
 * Device identity used by [OemPrefixResolver] to decide which conditional
 * OEM prefix blocks apply. The allowlist is keyed on manufacturer and brand
 * so that, for example, Samsung prefixes only suppress findings on Samsung
 * devices — an attacker cannot hide malware under `com.samsung.*` on a Pixel
 * and have it classified as OEM.
 *
 * **Normalization:** manufacturer and brand are stored lowercase, trimmed.
 * The YAML `manufacturer_match` / `brand_match` lists are compared against
 * these normalized values. See #90 for the full attack model and design.
 *
 * Two factories:
 * - [local] reads `Build.MANUFACTURER` and `Build.BRAND` — used by every
 *   runtime scanner for live-device evaluation.
 * - [fromSystemProperties] reads the same fields from a parsed bugreport
 *   `getprop` dump — used by every bugreport module so imported scans
 *   evaluate against the source device's identity, not the local one.
 */
data class DeviceIdentity(
    val manufacturer: String,
    val brand: String,
) {
    companion object {
        /**
         * The identity of the device AndroDR is currently running on.
         * Reads `Build.MANUFACTURER` and `Build.BRAND`, lowercases and trims
         * both. Safe to call from any thread.
         */
        fun local(): DeviceIdentity = DeviceIdentity(
            manufacturer = Build.MANUFACTURER.orEmpty().trim().lowercase(),
            brand = Build.BRAND.orEmpty().trim().lowercase(),
        )

        /**
         * The identity extracted from a bugreport's parsed system properties.
         * Reads `ro.product.manufacturer` and `ro.product.brand` from the
         * given map. Missing keys default to empty strings, which will
         * match nothing in the conditional allowlist — the safe default
         * (only unconditional prefixes apply).
         *
         * @param properties a map of `getprop` key → value from the bugreport
         */
        fun fromSystemProperties(properties: Map<String, String>): DeviceIdentity =
            DeviceIdentity(
                manufacturer = properties["ro.product.manufacturer"]
                    .orEmpty().trim().lowercase(),
                brand = properties["ro.product.brand"]
                    .orEmpty().trim().lowercase(),
            )

        /**
         * An identity that matches no conditional blocks. Useful for tests
         * and for degraded paths where the source device cannot be
         * determined. Only unconditional prefixes apply.
         */
        val UNKNOWN: DeviceIdentity = DeviceIdentity(manufacturer = "", brand = "")
    }
}
