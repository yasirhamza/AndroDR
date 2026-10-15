package com.androdr.ioc

import org.json.JSONArray
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/**
 * Regression gate: invented indicators must not ship.
 *
 * The initial scaffolding seeded the bundled IOC lists with plausible-looking
 * entries that no threat-intelligence source ever published (`candiru-c2.xyz`,
 * `com.candiru.spyware`, ~200 `<family>-c2.<tld>` style domains, 84 package
 * names), later given back-filled `source` labels. A 2026-10-15 audit against
 * stalkerware-indicators, MVT, HaGeZi TIF, ThreatFox, URLhaus and the original
 * reports removed every entry with no public source.
 *
 * Two checks, over the bundled res/raw lists and the pinned android-sigma-rules
 * ioc-data (which devices also fetch):
 *  1. No entry listed in `removed-fabricated-iocs.txt` may come back.
 *  2. No new entry may use the template shapes the invented entries used.
 */
class BundledIocPlaceholderTest {

    private val placeholderDomainShape = Regex(
        """(^|[.-])c2([.-])|-(panel|spyware|malware|stalkerware|exploit|implant|dropper|botnet)\d*\.[a-z]+$"""
    )
    private val placeholderPackageShape = Regex(
        """^com\.[a-z0-9]+\.(spyware|stalkerware|malware|trojan|rat|rootkit)$"""
    )

    private fun firstDirectory(vararg paths: String): File =
        paths.map(::File).firstOrNull { it.isDirectory }
            ?: error("Could not locate any of: ${paths.toList()}")

    private val rawDir by lazy { firstDirectory("app/src/main/res/raw", "src/main/res/raw") }
    private val iocDataDir by lazy {
        firstDirectory("third-party/android-sigma-rules/ioc-data", "../third-party/android-sigma-rules/ioc-data")
    }

    private val removed: Map<String, Set<String>> by lazy {
        val stream = javaClass.classLoader!!.getResourceAsStream("removed-fabricated-iocs.txt")
            ?: error("removed-fabricated-iocs.txt missing from test resources")
        val sections = mutableMapOf<String, MutableSet<String>>()
        var current: String? = null
        stream.bufferedReader().forEachLine { raw ->
            val line = raw.trim()
            when {
                line.isEmpty() || line.startsWith("#") -> Unit
                line.startsWith("[") -> current = line.trim('[', ']')
                else -> sections.getOrPut(checkNotNull(current) { "entry before section: $line" }) {
                    mutableSetOf()
                }.add(line.lowercase())
            }
        }
        sections
    }

    private fun bundledDomains(): Set<String> =
        File(rawDir, "domain_blocklist.txt").readLines()
            .map { it.trim().lowercase() }
            .filter { it.isNotEmpty() && !it.startsWith("#") }
            .toSet()

    private fun bundledJsonField(file: String, field: String): Set<String> {
        val entries = JSONArray(File(rawDir, file).readText())
        return (0 until entries.length()).map { entries.getJSONObject(it).getString(field).lowercase() }.toSet()
    }

    private fun iocDataIndicators(file: String): Set<String> =
        Regex("""indicator:\s*"?([^"\s]+)""")
            .findAll(File(iocDataDir, file).readText())
            .map { it.groupValues[1].lowercase() }
            .toSet()

    private fun assertNoneRemoved(section: String, actual: Set<String>, where: String) {
        val expected = removed[section] ?: error("removed-fabricated-iocs.txt has no [$section] section")
        val reintroduced = expected intersect actual
        assertTrue("Removed $section reintroduced in $where: $reintroduced", reintroduced.isEmpty())
    }

    @Test
    fun `removed domains stay out of the blocklist and ioc-data`() {
        assertNoneRemoved("domains", bundledDomains(), "domain_blocklist.txt")
        assertNoneRemoved("domains", iocDataIndicators("c2-domains.yml"), "ioc-data/c2-domains.yml")
    }

    @Test
    fun `removed packages stay out of the bundle and ioc-data`() {
        assertNoneRemoved(
            "packages",
            bundledJsonField("known_bad_packages.json", "packageName"),
            "known_bad_packages.json",
        )
        assertNoneRemoved("packages", iocDataIndicators("package-names.yml"), "ioc-data/package-names.yml")
    }

    @Test
    fun `removed cert hashes stay out of the bundle and ioc-data`() {
        assertNoneRemoved("certs", bundledJsonField("known_bad_certs.json", "certHash"), "known_bad_certs.json")
        assertNoneRemoved("certs", iocDataIndicators("cert-hashes.yml"), "ioc-data/cert-hashes.yml")
    }

    @Test
    fun `removed apk hashes stay out of the bundle and ioc-data`() {
        assertNoneRemoved(
            "apk_hashes",
            bundledJsonField("known_bad_apk_hashes.json", "apkHash"),
            "known_bad_apk_hashes.json",
        )
        assertNoneRemoved("apk_hashes", iocDataIndicators("malware-hashes.yml"), "ioc-data/malware-hashes.yml")
    }

    @Test
    fun `no domain uses an invented placeholder shape`() {
        val offenders = (bundledDomains() + iocDataIndicators("c2-domains.yml"))
            .filter { placeholderDomainShape.containsMatchIn(it) }
        assertTrue("Placeholder-shaped domains (cite a public source or remove): $offenders", offenders.isEmpty())
    }

    @Test
    fun `no package uses an invented placeholder shape`() {
        val offenders = (bundledJsonField("known_bad_packages.json", "packageName") +
            iocDataIndicators("package-names.yml"))
            .filter { placeholderPackageShape.matches(it) }
        assertTrue("Placeholder-shaped packages (cite a public source or remove): $offenders", offenders.isEmpty())
    }
}
