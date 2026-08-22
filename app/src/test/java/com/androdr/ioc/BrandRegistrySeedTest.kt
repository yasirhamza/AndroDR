package com.androdr.ioc

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/**
 * Anti-vacuity gate for the SHIPPED brand registry seeds (#299).
 *
 * `parseBrandYaml` swallows every exception to `emptyList()` and the bundled
 * matcher swallows a resource-read failure to `""`, so a malformed or
 * key-renamed `res/raw/brand_*.yml` would produce a zero-pattern matcher →
 * `brand_name_db` false for every app → androdr-092/093 silently never fire,
 * with byte-parity and all rule tests still green (they use stub lookups).
 * This is the #203 silent-content-loss class. This test parses the actual
 * bundled files and asserts a sane floor, so a curation slip fails CI here.
 */
class BrandRegistrySeedTest {

    private fun raw(name: String): String {
        val f = listOf(
            File("app/src/main/res/raw/$name"),
            File("src/main/res/raw/$name"),
        ).firstOrNull { it.isFile }
            ?: error("$name not found from ${File(".").absolutePath}")
        return f.readText()
    }

    private fun brandKeys(yaml: String): Set<String> {
        val settings = org.snakeyaml.engine.v2.api.LoadSettings.builder().build()
        val doc = org.snakeyaml.engine.v2.api.Load(settings)
            .loadFromString(yaml) as? Map<*, *> ?: emptyMap<Any, Any>()
        val brands = doc["brands"] as? Map<*, *> ?: emptyMap<Any, Any>()
        return brands.keys.map { it.toString() }.toSet()
    }

    @Test
    fun `shipped seeds build a non-empty matcher`() {
        val names = BrandImpersonationResolver.parseBrandYaml(raw("brand_names.yml"), "display_names")
        val domains = BrandImpersonationResolver.parseBrandYaml(raw("brand_domains.yml"), "domains")
        assertTrue("name variants below floor: ${names.size}", names.size >= 20)
        assertTrue("domains below floor: ${domains.size}", domains.size >= 20)
        // Must survive the same sanity bounds the resolver enforces on device.
        assertNotNull(
            "shipped seeds fail buildMatcher sanity bounds",
            BrandImpersonationResolver.buildMatcher(names, domains),
        )
    }

    @Test
    fun `every shipped domain is a plausible registrable domain`() {
        val domains = BrandImpersonationResolver.parseBrandYaml(raw("brand_domains.yml"), "domains")
        for (d in domains) {
            assertTrue("domain '$d' has no dot", d.contains('.'))
            assertTrue("domain '$d' not lowercase", d == d.lowercase())
            assertTrue("domain '$d' has scheme/path/space", !d.contains('/') && !d.contains(':') && !d.contains(' '))
        }
    }

    @Test
    fun `every shipped name variant meets the minimum length`() {
        val names = BrandImpersonationResolver.parseBrandYaml(raw("brand_names.yml"), "display_names")
        for (n in names) assertTrue("name variant '$n' too short", n.length >= 2)
    }

    @Test
    fun `brand keys agree between the two seed files`() =
        // brand-domains.yml's header asserts "Brand keys mirror
        // brand-names.yml"; a name without domains is a guaranteed 092 FP.
        assertEquals(brandKeys(raw("brand_names.yml")), brandKeys(raw("brand_domains.yml")))

    @Test
    fun `resolver fetch URLs match the ioc-lookup-definitions files entries`() {
        // A rename upstream would move the definitions file + parity test with
        // it but leave the resolver's hardcoded URL 404ing forever against a
        // frozen bundled seed. Pin the two together.
        val src = listOf(
            File("app/src/main/java/com/androdr/ioc/BrandImpersonationResolver.kt"),
            File("src/main/java/com/androdr/ioc/BrandImpersonationResolver.kt"),
        ).firstOrNull { it.isFile }?.readText() ?: error("BrandImpersonationResolver.kt not found")

        val defs = listOf(
            File("third-party/android-sigma-rules/validation/ioc-lookup-definitions.yml"),
            File("../third-party/android-sigma-rules/validation/ioc-lookup-definitions.yml"),
        ).firstOrNull { it.isFile }?.readText() ?: return // submodule absent → skip (CI checks out with it)

        for (path in listOf("ioc-data/brand-names.yml", "ioc-data/brand-domains.yml")) {
            assertTrue("resolver does not fetch $path", src.contains(path))
            assertTrue("ioc-lookup-definitions.yml does not declare $path", defs.contains(path))
        }
    }
}
