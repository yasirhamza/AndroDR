package com.androdr.debug

import com.androdr.data.model.Indicator
import com.androdr.ioc.IndicatorResolver

/**
 * Debug builds only: the indicator row the adversary harness asks for (`test-adversary/run.sh`,
 * scenario `mercenary_cert_hash`). The harness sends [ACTION_SEED_CERT] with the fixture APK's signing
 * cert hash; [ScanBroadcastReceiver] stores this row through the app's own DAO and reloads the indicator
 * cache. It replaces a `sqlite3` INSERT run on the device, which broke on a schema change and cannot run
 * at all on images without `sqlite3` (#424). The row looks like a feed row, so the scan treats it as one.
 */
internal object AdversarySeed {
    const val ACTION_SEED_CERT = "com.androdr.ACTION_SEED_CERT"
    const val EXTRA_CERT_HASH = "cert_hash"
    const val SOURCE = "adversary-test"

    private val SHA256_HEX = Regex("^[0-9a-f]{64}$")

    /**
     * The seed row for [hash], a SHA-256 signing cert hash as hex (keytool's upper case and colons are
     * accepted); null for anything else, so a malformed broadcast stores nothing.
     */
    fun certIndicator(hash: String?, now: Long): Indicator? {
        val value = hash.orEmpty().replace(":", "").lowercase()
        if (!SHA256_HEX.matches(value)) return null
        return Indicator(
            type = IndicatorResolver.TYPE_CERT_HASH,
            value = value,
            family = "Test Fixture",
            category = "MALWARE",
            campaignKey = "",
            severity = "CRITICAL",
            description = "Adversary simulation test cert",
            source = SOURCE,
            reference = "",
            fetchedAt = now,
        )
    }
}
