package com.androdr.ui.privacy

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/** Source scan of the privacy copy and wiring: wording and navigation are part of the spec. */
class PrivacyCopyTest {

    private fun appRoot(): File =
        listOf(File("src/main"), File("app/src/main")).firstOrNull { it.isDirectory }
            ?: error("cannot find src/main from ${File(".").absolutePath}")

    private fun source(path: String): String {
        val file = File(appRoot(), path)
        assertTrue("missing $path", file.isFile)
        return file.readText()
    }

    private val strings get() = source("res/values/strings.xml")

    private fun privacyStringBodies(): Map<String, String> =
        Regex("""<(string|plurals) name="(privacy_[a-z_]+)"[^>]*>(.*?)</\1>""", RegexOption.DOT_MATCHES_ALL)
            .findAll(strings).associate { it.groupValues[2] to it.groupValues[3] }

    @Test fun `strings contain no 'no trackers' and no 'carries' in network strings`() {
        val all = privacyStringBodies()
        assertTrue("privacy strings not found", all.size > 50)
        for ((name, body) in all) {
            assertTrue("$name says no trackers: $body", !body.contains("no trackers", ignoreCase = true))
        }
        for ((name, body) in all.filterKeys { it.contains("network") || it.contains("lookup") }) {
            assertTrue("$name says carries: $body", !body.contains("carries", ignoreCase = true))
        }
    }

    @Test fun `PrivacyScreen references privacy_limits, privacy_network_caveat and privacy_attribution`() {
        val screen = source("java/com/androdr/ui/privacy/PrivacyScreen.kt")
        val names = listOf("R.string.privacy_limits", "R.string.privacy_network_caveat", "R.string.privacy_attribution")
        for (s in names) {
            assertTrue("PrivacyScreen does not reference $s", screen.contains(s))
        }
    }

    @Test fun `MainActivity has the privacy route and five bottom destinations`() {
        val main = source("java/com/androdr/MainActivity.kt")
        assertTrue(main.contains("""composable("privacy")"""))
        val list = main.substringAfter("private val bottomNavDestinations").substringBefore("\n)")
        assertEquals(5, Regex("""NavDestination\("""").findAll(list).count())
        assertTrue("privacy must not be a bottom destination", !list.contains("\"privacy\""))
    }

    @Test fun `the Dashboard card navigates to the privacy route`() {
        assertTrue(source("java/com/androdr/ui/dashboard/PrivacyCard.kt").contains("""onNavigate("privacy")"""))
        assertTrue(source("java/com/androdr/ui/dashboard/DashboardScreen.kt").contains("PrivacyCard("))
    }

    @Test fun `history clear-all text mentions that privacy results are kept`() {
        val body = Regex("""name="history_clear_credential_description">(.*?)</string>""").find(strings)!!.groupValues[1]
        assertTrue(body, body.contains("Privacy scan results are kept; delete them from the privacy screen."))
    }

    @Test fun `app labels and tracker names are rendered through reportSafe`() {
        val ui = source("java/com/androdr/ui/privacy/PrivacyScreen.kt") +
            source("java/com/androdr/ui/privacy/PrivacyDetails.kt")
        assertTrue(ui.contains("reportSafe("))
        assertTrue("a label bypasses safe()", !Regex("""Text\(\s*\w+\.(appLabel|name)\b""").containsMatchIn(ui))
    }
}
