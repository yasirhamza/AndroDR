package com.androdr.privacy

import com.androdr.data.repo.SettingsRepository
import com.androdr.ioc.TrackerRegistry
import com.androdr.privacy.model.ANDRODR_TRACKER_ID_MIN
import com.androdr.privacy.model.TrackerCategory
import com.androdr.privacy.model.TrackerSet
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/**
 * #470: the privacy scan names residential-proxy SDKs. The entry is AndroDR's own (the rules
 * repository's `validation/tracker-supplement.yml`, merged into `ioc-data/trackers.yml` by the
 * mirror). These tests fail if the entry, its code packages or the category go missing from the
 * pinned list, or if the app stops refusing the category by default.
 */
class ProxywareTrackerTest {

    private val set: TrackerSet = requireNotNull(
        TrackerRegistry.parse(
            listOf(
                File("../third-party/android-sigma-rules/ioc-data/trackers.yml"),
                File("third-party/android-sigma-rules/ioc-data/trackers.yml"),
            ).first { it.isFile }.readText()
        )
    )

    private fun namesFor(vararg packages: String) = set.matchPackages(packages.toList()).map { it.name }

    @Test
    fun `bright sdk is on the pinned list as proxyware`() {
        val bright = set.trackers.single { it.id == BRIGHT_ID }
        assertEquals("Bright SDK (residential proxy)", bright.name)
        assertEquals(setOf(TrackerCategory.PROXYWARE), bright.categories)
        assertEquals(
            listOf("brdat.sdk", "com.android.eapx", "io.lum.sdk", "io.topvpn.vpn_api", "org.hola.peer"),
            bright.codePrefixes,
        )
    }

    @Test
    fun `an app with bright sdk code is named, by each of its packages`() {
        for (pkg in listOf("io.lum.sdk", "io.lum.sdk.api", "io.topvpn.vpn_api", "org.hola.peer.svc",
            "brdat.sdk.core", "com.android.eapx")) {
            assertEquals(pkg, listOf("Bright SDK (residential proxy)"), namesFor(pkg))
        }
    }

    @Test
    fun `packages that only resemble bright sdk are not named`() {
        // The same lookalikes androdr-113's fixture uses, plus Hola's own non-peer code.
        assertEquals(
            emptyList<String>(),
            namesFor("io.lum.sdkx", "io.lum", "com.android.eapxtra", "com.example.io.lum.sdk", "org.hola", "brdat"),
        )
    }

    @Test
    fun `a lookup of a bright sdk host counts as network evidence, the corporate site does not`() {
        assertEquals(listOf(BRIGHT_ID), set.matchDomain("proxyjs.bright-sdk.com").map { it.id })
        assertEquals(listOf(BRIGHT_ID), set.matchDomain("zagent110.l-cdn.com").map { it.id })
        assertFalse(set.matchDomain("www.brightdata.com").any { it.id == BRIGHT_ID })
        assertFalse(set.matchDomain("other.b-cdn.net").any { it.id == BRIGHT_ID })
        assertFalse(set.matchDomain("zagent999.l-cdn.com").any { it.id == BRIGHT_ID })
    }

    @Test
    fun `the category is known to the app and refused by default`() {
        assertEquals(TrackerCategory.PROXYWARE, TrackerCategory.fromLabel("Proxyware"))
        assertTrue(TrackerCategory.PROXYWARE in SettingsRepository.DEFAULT_REFUSED_CATEGORIES)
    }

    @Test
    fun `only androdr's own entries carry the category`() {
        val proxyware = set.trackers.filter { TrackerCategory.PROXYWARE in it.categories }
        assertTrue(proxyware.isNotEmpty())
        assertTrue(proxyware.all { it.id >= ANDRODR_TRACKER_ID_MIN })
    }

    @Test
    fun `the app and the rules repository agree where androdr's own ids start`() {
        val guards = listOf(
            File("../third-party/android-sigma-rules/validation/tracker_guards.py"),
            File("third-party/android-sigma-rules/validation/tracker_guards.py"),
        ).first { it.isFile }.readText()
        val min = Regex("""^SUPPLEMENT_ID_MIN = ([0-9_]+)$""", RegexOption.MULTILINE).find(guards)
        assertEquals(ANDRODR_TRACKER_ID_MIN, min?.groupValues?.get(1)?.replace("_", "")?.toInt())
    }

    private companion object {
        const val BRIGHT_ID = ANDRODR_TRACKER_ID_MIN
    }
}
