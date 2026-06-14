package com.androdr.security

import org.junit.Assert.assertTrue
import org.junit.Test
import org.w3c.dom.Element
import java.io.File
import java.text.SimpleDateFormat
import java.util.Locale
import java.util.TimeZone
import javax.xml.parsers.DocumentBuilderFactory

/**
 * Lightweight guard for the certificate-pinning config.
 *
 * This cannot verify pins against live certificate chains offline (that failure
 * mode — Google rotating storage.googleapis.com from GTS Root R1/WR2 to R4/WE2 —
 * silently disabled OSV CVE enrichment). But it does catch the two static
 * mistakes that turn pinning into an outage:
 *  - an expiration date that has already passed (pins stop being enforced, or
 *    worse, all traffic to the domain breaks depending on OS behaviour), and
 *  - a single-pin set, which bricks the domain the moment that one cert rotates
 *    (the standard guidance is to always ship a backup pin).
 */
class NetworkSecurityConfigTest {

    private fun configFile(): File = listOf(
        File("app/src/main/res/xml/network_security_config.xml"),
        File("src/main/res/xml/network_security_config.xml"),
        File("/home/yasir/AndroDR/app/src/main/res/xml/network_security_config.xml"),
    ).firstOrNull { it.isFile }
        ?: error("network_security_config.xml not found")

    @Test
    fun `every pin-set is future-dated and has a backup pin`() {
        val doc = DocumentBuilderFactory.newInstance()
            .newDocumentBuilder()
            .parse(configFile())

        val dateFormat = SimpleDateFormat("yyyy-MM-dd", Locale.US).apply {
            timeZone = TimeZone.getTimeZone("UTC")
        }
        val now = System.currentTimeMillis()

        val pinSets = doc.getElementsByTagName("pin-set")
        assertTrue("expected at least one <pin-set>", pinSets.length > 0)

        for (i in 0 until pinSets.length) {
            val pinSet = pinSets.item(i) as Element
            val domain = (pinSet.parentNode as? Element)
                ?.getElementsByTagName("domain")?.item(0)?.textContent?.trim()
                ?: "pin-set[$i]"

            val expiration = pinSet.getAttribute("expiration")
            assertTrue("$domain: <pin-set> is missing an expiration", expiration.isNotBlank())
            val expiresAt = dateFormat.parse(expiration)?.time
                ?: error("$domain: unparseable expiration '$expiration'")
            assertTrue(
                "$domain: pin-set expired on $expiration — pinning is no longer enforced",
                expiresAt > now,
            )

            val pinCount = pinSet.getElementsByTagName("pin").length
            assertTrue(
                "$domain: only $pinCount pin(s) — ship at least 2 (a backup) so cert " +
                    "rotation cannot brick the domain",
                pinCount >= 2,
            )
        }
    }
}
