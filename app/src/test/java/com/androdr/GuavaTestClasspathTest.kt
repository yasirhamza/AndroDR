package com.androdr

import com.google.common.collect.ImmutableList
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/**
 * Robolectric pulls `com.google.guava:guava` onto the unit-test classpath; 33.3.1-jre carries
 * GHSA-xxph-c9ww-hj94 (high), fixed in 33.7.2. `app/build.gradle.kts` pins it strictly; this fails
 * if the resolved jar ever drops below 33.7.2 (e.g. the constraint is removed), so
 * dependency-review cannot regress silently. The APK ships only `listenablefuture:1.0`.
 */
class GuavaTestClasspathTest {

    @Test
    fun `guava on the test runtime classpath is at least 33_7_2`() {
        val jar = File(ImmutableList::class.java.protectionDomain.codeSource.location.toURI()).name
        val version = Regex("""^guava-(\d+(?:\.\d+)*)-(?:jre|android)\.jar$""").find(jar)?.groupValues?.get(1)
            ?: error("unexpected guava jar name: $jar")
        assertTrue("guava $version (from $jar) is below 33.7.2", atLeast(version, MIN))
    }

    @Test
    fun `the version comparison rejects the vulnerable releases`() {
        assertTrue(!atLeast("33.3.1", MIN))
        assertTrue(!atLeast("33.7.1", MIN))
        assertTrue(atLeast("33.7.2", MIN))
        assertTrue(atLeast("34.0", MIN))
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

    private companion object {
        val MIN = listOf(33, 7, 2)
    }
}
