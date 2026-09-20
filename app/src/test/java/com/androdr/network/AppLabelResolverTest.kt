package com.androdr.network

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Test

/**
 * Package name -> the name a person recognises. The Network Monitor lists live
 * DNS queries by the app that made them; a row reading `com.android.chrome`
 * asks the reader to know Android package naming, which is exactly the burden
 * attribution was supposed to remove.
 *
 * The resolver asks the platform once per package and keeps every answer,
 * including the misses -- the list re-renders on every query and the platform
 * lookup is not free. A package that has no usable label keeps its package
 * name rather than gaining a fake one.
 */
class AppLabelResolverTest {

    /** Stands in for `PackageManager.NameNotFoundException`, unavailable in a plain unit test. */
    private class LookupFailure(message: String) : RuntimeException(message)

    private class FakeLookup(
        private val table: Map<String, String?>,
        private val throwFor: Set<String> = emptySet(),
    ) : PackageLabelLookup {
        var calls = 0
        override fun labelFor(packageName: String): String? {
            calls++
            if (packageName in throwFor) throw LookupFailure("no such package")
            return table[packageName]
        }
    }

    @Test
    fun `resolves a package to its app label`() {
        val resolver = AppLabelResolver(FakeLookup(mapOf("com.android.chrome" to "Chrome")))

        assertEquals(
            mapOf("com.android.chrome" to "Chrome"),
            resolver.labels(listOf("com.android.chrome")),
        )
    }

    @Test
    fun `a package the platform cannot name is left out, never given a placeholder`() {
        val resolver = AppLabelResolver(
            FakeLookup(mapOf("com.unknown.one" to null, "com.unknown.two" to "   ")),
        )

        assertEquals(emptyMap<String, String>(), resolver.labels(listOf("com.unknown.one", "com.unknown.two")))
    }

    @Test
    fun `a label that merely repeats the package name is left out`() {
        // Android returns the package name itself when an app declares no label.
        // Keeping it would render "com.foo.bar (com.foo.bar)" on every row.
        val resolver = AppLabelResolver(FakeLookup(mapOf("com.foo.bar" to "com.foo.bar")))

        assertEquals(emptyMap<String, String>(), resolver.labels(listOf("com.foo.bar")))
    }

    @Test
    fun `each package is asked once however often it is seen, misses included`() {
        val lookup = FakeLookup(mapOf("com.android.chrome" to "Chrome", "com.nameless" to null))
        val resolver = AppLabelResolver(lookup)

        repeat(5) { resolver.labels(listOf("com.android.chrome", "com.nameless", "com.android.chrome")) }

        assertEquals(2, lookup.calls)
    }

    @Test
    fun `a lookup that throws costs that package its label, not the whole list`() {
        val resolver = AppLabelResolver(
            FakeLookup(mapOf("com.android.chrome" to "Chrome"), throwFor = setOf("com.gone")),
        )

        val labels = resolver.labels(listOf("com.gone", "com.android.chrome"))

        assertEquals("Chrome", labels["com.android.chrome"])
        assertFalse(labels.containsKey("com.gone"))
    }
}
