package com.androdr.security

import org.junit.Assert.assertEquals
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

    private companion object {
        const val NINETY_DAYS_MS = 90L * 24 * 60 * 60 * 1000

        /**
         * Domain-agnostic catalog mapping each allowed CA root's SPKI pin
         * (base64 SHA-256) → the root's common name + provenance URL. Deliberately
         * a superset of any single domain's pins (all ISRG + all listed DigiCert +
         * both USERTrust, regardless of which host currently uses which). Every
         * `<pin>` in the config must be a KEY here.
         *
         * This enforces the "root pins only, never leaf or intermediate" POLICY
         * mechanically — the pattern behind both the 2026-07-03 GitHub outage and
         * the cisa.gov leaf expiry. It does NOT verify CORRECTNESS: offline, it
         * cannot confirm a listed base64 is genuinely that root's SPKI or matches
         * a live chain (a wrong-but-32-byte value curated into both the XML and
         * this map would pass). Provenance (the source URL per entry) is the guard
         * against that — recompute before trusting:
         *   openssl x509 -pubkey -noout | openssl pkey -pubin -outform der \
         *     | openssl dgst -sha256 -binary | base64
         *
         * Provenance URLs (all under the CA's own domain):
         *   ISRG Root YR: letsencrypt.org/certs/gen-y/root-yr.pem
         *   ISRG Root YE: letsencrypt.org/certs/gen-y/root-ye.pem
         *   ISRG Root X1: letsencrypt.org/certs/isrgrootx1.pem
         *   ISRG Root X2: letsencrypt.org/certs/isrg-root-x2.pem
         *   DigiCert Global Root CA/G2/G3: cacerts.digicert.com/DigiCertGlobalRoot{CA,G2,G3}.crt
         *   USERTrust RSA/ECC: crt.usertrust.com
         */
        val KNOWN_CA_ROOT_SPKI: Map<String, String> = mapOf(
            "fk6IOKit1ild5647BH06ujSIq5XbCgqlbYl6ANhhi88=" to "ISRG Root YR",
            "sCkq5UWXjg+7mKu9lMhhYF5bGLsy7VI/UNW3tccdR7w=" to "ISRG Root YE",
            "C5+lpZ7tcVwmwQIMcRtPbsQtWLABXhQzejna0wHFr8M=" to "ISRG Root X1",
            "diGVwiVYbubAI3RW4hB9xU8e/CH2GnkuvVFZE8zmgzI=" to "ISRG Root X2",
            "r/mIkG3eEpVdm+u/ko/cwxzOMo1bk4TyHIlByibiA5E=" to "DigiCert Global Root CA",
            "i7WTqTvh0OioIruIfFR4kMPnBqrS2rdiVPl/s2uC/CY=" to "DigiCert Global Root G2",
            "uUwZgwDOxcBXrQcntwu+kYFpkiVkOaezL0WYEZ3anJc=" to "DigiCert Global Root G3",
            "x4QzPSC810K5/cMjb05Qm4k3Bw5zBn4lTdO/nEW/Td4=" to "USERTrust RSA Certification Authority",
            "ICGRfpgmOUXIWcQ/HXPLQTkFPEFPoDyjvH7ohhQpjzs=" to "USERTrust ECC Certification Authority",
        )
    }

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
            // Lead-time, not just expiry: Android FAIL-OPENS on an expired pin-set
            // (pins silently stop being enforced), so a test that only fails after
            // the date has passed fires when protection is already gone. 90 days
            // gives a release cycle to remeasure roots and extend.
            assertTrue(
                "$domain: pin-set expires $expiration — within 90 days. Remeasure the " +
                    "roots (recipe in network_security_config.xml) and extend the date " +
                    "BEFORE devices fail open to unpinned TLS",
                expiresAt > now + NINETY_DAYS_MS,
            )

            val pins = pinSet.getElementsByTagName("pin")
            assertTrue(
                "$domain: only ${pins.length} pin(s) — ship at least 2 (a backup) so cert " +
                    "rotation cannot brick the domain",
                pins.length >= 2,
            )
            // A malformed pin doesn't fail gracefully: Android rejects the whole
            // config at runtime. Catch truncated/typo'd digests at build time.
            for (p in 0 until pins.length) {
                val value = pins.item(p).textContent.trim()
                val decoded = try {
                    java.util.Base64.getDecoder().decode(value)
                } catch (e: IllegalArgumentException) {
                    throw AssertionError("$domain: pin '$value' is not valid base64", e)
                }
                assertEquals(
                    "$domain: pin '$value' decodes to ${decoded.size} bytes — a SHA-256 " +
                        "SPKI pin must be exactly 32",
                    32,
                    decoded.size,
                )
            }
        }
    }

    /**
     * Enforces "root SPKI pins only" across every pinned domain: each `<pin>`
     * digest must be a named member of [KNOWN_CA_ROOT_SPKI]. A leaf or
     * intermediate pin — the rotation time-bomb behind the 2026-07-03 GitHub
     * outage and the cisa.gov leaf expiry — has an SPKI that isn't in the
     * allowlist and fails here, forcing a conscious edit with provenance.
     */
    @Test
    fun `every pin is a known CA root SPKI`() {
        val doc = DocumentBuilderFactory.newInstance()
            .newDocumentBuilder()
            .parse(configFile())

        val pins = doc.getElementsByTagName("pin")
        assertTrue("expected at least one <pin>", pins.length > 0)

        for (p in 0 until pins.length) {
            val value = pins.item(p).textContent.trim()
            val domain = ((pins.item(p).parentNode.parentNode) as? Element)
                ?.getElementsByTagName("domain")?.item(0)?.textContent?.trim()
                ?: "unknown-domain"
            assertTrue(
                "$domain: pin '$value' is not a known CA-root SPKI. Root pins only — " +
                    "never leaf or intermediate (they rotate and cause silent " +
                    "fail-closed outages). If this is genuinely a CA root, add it to " +
                    "KNOWN_CA_ROOT_SPKI with its name and provenance URL, verified " +
                    "with the openssl recipe in that map's doc.",
                KNOWN_CA_ROOT_SPKI.containsKey(value),
            )
        }
    }

    /**
     * Negative case for the roots-only guard: a leaf/intermediate SPKI (anything
     * not in the catalog) must be rejected. Documents that the guard is a real
     * filter, not a tautology that would pass any 32-byte value.
     */
    @Test
    fun `roots-only guard rejects a non-root SPKI`() {
        // Old cisa.gov leaf pin (www.homelandsecurity.gov) — a real 32-byte,
        // valid-base64 pin that is NOT a CA root; the migration removed it.
        val leafPin = "aMs+EaUklWPQX1BUlfn0NuPZZfgh+zL3/zVKxWtfNfo="
        assertEquals(32, java.util.Base64.getDecoder().decode(leafPin).size)
        assertTrue(
            "guard would accept a leaf pin — it must only accept catalogued roots",
            !KNOWN_CA_ROOT_SPKI.containsKey(leafPin),
        )
    }

    /**
     * Guards the deliberate decision to NOT pin storage.googleapis.com: Google
     * serves it from many POPs with varying cert chains, so any pin breaks
     * per-device and silently disables OSV CVE enrichment. This makes that
     * decision enforced rather than merely documented in a comment — a
     * re-added Google pin fails the build.
     */
    @Test
    fun `storage_googleapis_com is not pinned`() {
        val doc = DocumentBuilderFactory.newInstance()
            .newDocumentBuilder()
            .parse(configFile())

        val domainConfigs = doc.getElementsByTagName("domain-config")
        for (i in 0 until domainConfigs.length) {
            val dc = domainConfigs.item(i) as Element
            val domains = dc.getElementsByTagName("domain")
            val coversGoogleStorage = (0 until domains.length).any {
                domains.item(it).textContent.trim().contains("storage.googleapis.com")
            }
            if (coversGoogleStorage) {
                assertEquals(
                    "storage.googleapis.com must not be pinned (Google rotates CAs per-POP; " +
                        "pinning it silently breaks OSV CVE enrichment)",
                    0,
                    dc.getElementsByTagName("pin-set").length,
                )
            }
        }
    }
}
