package com.androdr.ioc

import com.androdr.data.model.Indicator
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.snakeyaml.engine.v2.api.Load
import org.snakeyaml.engine.v2.api.LoadSettings
import java.io.File

/**
 * Regression gate for #465: the Bright SDK residential-proxy domains stay on the threat list
 * under the PROXYWARE category, the look-alike domains that would false-alarm stay off it, and
 * androdr-003 (the one rule every threat-list domain fires) keeps telling a proxy SDK apart
 * from a C2 server. Reads the pinned submodule, like [IocDataManifestIntegrityTest].
 */
class ProxywareBrightSdkIocTest {

    private fun file(rel: String): File = listOf(File(rel), File("../$rel")).first { it.isFile }

    @Suppress("UNCHECKED_CAST")
    private fun yaml(f: File): Map<String, Any?> =
        Load(LoadSettings.builder().build()).loadFromString(f.readText()) as Map<String, Any?>

    @Suppress("UNCHECKED_CAST")
    private val entries: Map<String, Map<String, Any?>> by lazy {
        (yaml(file("third-party/android-sigma-rules/ioc-data/c2-domains.yml"))["entries"] as List<Map<String, Any?>>)
            .associateBy { it["indicator"].toString().lowercase() }
    }

    private val submoduleRule = file("third-party/android-sigma-rules/dns_monitor/androdr_003_domain_ioc.yml")
    private val bundledRule = file("app/src/main/res/raw/sigma_androdr_003_domain_ioc.yml")

    @Test
    fun `bright sdk domains are listed as proxyware`() {
        for (domain in BRIGHT_SDK) {
            val e = entries[domain]
            assertTrue("$domain is missing from c2-domains.yml", e != null)
            requireNotNull(e)
            assertEquals(domain, "PROXYWARE", e["category"])
            // The family carries the kind: builds older than PROXYWARE drop the category.
            assertEquals(domain, "Bright SDK (residential proxy)", e["family"])
            assertEquals(domain, "HIGH", e["severity"])
        }
    }

    @Test
    fun `corporate, shared-cdn and parent domains are not listed`() {
        for (domain in MUST_NOT_LIST) {
            assertFalse("$domain must not be a threat-list indicator", entries.containsKey(domain))
        }
    }

    @Test
    fun `sanitizer keeps the proxyware category`() {
        val out = IocSanitizer.sanitize(
            Indicator(type = "domain", value = "brdtnet.com", family = "F", category = "PROXYWARE",
                description = "", reference = "", source = "s", fetchedAt = 0L)
        )
        assertEquals("PROXYWARE", out.category)
    }

    @Test
    @Suppress("UNCHECKED_CAST")
    fun `androdr-003 tells a proxy sdk apart from a c2 server`() {
        val rule = yaml(submoduleRule)
        val remediation = (rule["remediation"] as List<String>)
        assertTrue(
            "androdr-003 remediation lost the residential-proxy line",
            remediation.any { it.contains("Residential-proxy SDK") && it.contains("Uninstall that app") },
        )
        val guidance = (rule["display"] as Map<String, Any?>)["guidance"].toString()
        assertFalse("androdr-003 guidance calls every threat-list domain a C2 server", guidance.contains("known C2 server"))
        assertEquals("level must stay critical", "critical", rule["level"])
    }

    @Test
    fun `bundled androdr-003 equals the pinned rule`() {
        assertEquals(submoduleRule.readText(), bundledRule.readText())
    }

    private companion object {
        val BRIGHT_SDK = listOf(
            "brdtnet.com", "bright-sdk.com", "luminatinet.com", "luminati-china.io", "brdtest.com",
            "l-err.biz", "cdn-cloud.b-cdn.net", "perr.l-agent.me", "p.l-conn.net",
            "zagent108.l-cdn.com", "zagent110.l-cdn.com", "zagent111.l-cdn.com",
            "zagent112.l-cdn.com", "zagent113.l-cdn.com",
        )
        // A browser visit to the vendor's site is not SDK presence; b-cdn.net is a CDN shared by
        // many tenants; the three parents are listed only by the exact hosts the SDK config names.
        val MUST_NOT_LIST = listOf(
            "brightdata.com", "luminati.io", "b-cdn.net", "l-agent.me", "l-conn.net", "l-cdn.com",
        )
    }
}
