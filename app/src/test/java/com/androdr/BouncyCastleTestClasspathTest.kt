package com.androdr

import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/**
 * Robolectric pulls `org.bouncycastle:bcprov-jdk18on` onto the unit-test classpath; 1.78.1 carries
 * GHSA-574f-3g2m-x479, GHSA-9pwp-9qqc-pr26 (critical) and GHSA-qp49-qgx5-5m26 (high), fixed in 1.85.
 * `app/build.gradle.kts` pins it strictly; this fails if the resolved jar ever drops below 1.85
 * (e.g. the constraint is removed), so dependency-review cannot regress silently.
 */
class BouncyCastleTestClasspathTest {

    @Test
    fun `bcprov-jdk18on on the test runtime classpath is at least 1_85`() {
        val jar = File(BouncyCastleProvider::class.java.protectionDomain.codeSource.location.toURI()).name
        val version = Regex("""^bcprov-jdk18on-(\d+(?:\.\d+)*)\.jar$""").find(jar)?.groupValues?.get(1)
            ?: error("unexpected bcprov jar name: $jar")
        assertTrue("bcprov-jdk18on $version (from $jar) is below 1.85", atLeast(version, listOf(1, 85)))
    }

    @Test
    fun `the version comparison rejects the vulnerable releases`() {
        assertTrue(!atLeast("1.78.1", listOf(1, 85)))
        assertTrue(!atLeast("1.84", listOf(1, 85)))
        assertTrue(atLeast("1.85", listOf(1, 85)))
        assertTrue(atLeast("1.86", listOf(1, 85)))
        assertTrue(atLeast("2.0", listOf(1, 85)))
    }

    private fun atLeast(version: String, min: List<Int>): Boolean {
        val parts = version.split('.').map { it.toInt() }
        for (i in 0 until maxOf(parts.size, min.size)) {
            val a = parts.getOrElse(i) { 0 }
            val b = min.getOrElse(i) { 0 }
            if (a != b) return a > b
        }
        return true
    }
}
