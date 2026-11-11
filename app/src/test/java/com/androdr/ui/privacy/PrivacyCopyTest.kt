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

    @Test fun `the truncated notice names the size of the DNS log, not only the time limit`() {
        // TRUNCATED also comes from the per-app quotas and caps, so the copy must not blame the time limit alone.
        val body = privacyStringBodies().getValue("privacy_network_truncated")
        assertEquals("Network evidence is incomplete: the DNS log was too large to read in full.", body)
    }

    @Test fun `PrivacyScreen shows registry-unavailable only for the UNAVAILABLE state`() {
        val screen = source("java/com/androdr/ui/privacy/PrivacyScreen.kt")
        val gate = screen.substringBefore("R.string.privacy_registry_unavailable").takeLast(80)
        assertTrue(gate, gate.contains("state.showRegistryUnavailable"))
        assertTrue(!screen.contains("registryAvailable"))
    }

    @Test fun `the Apps-tab line goes through TrackerCrossoverText and its network strings never say in code`() {
        val apps = source("java/com/androdr/ui/apps/AppScanScreen.kt")
        assertTrue(apps.contains("TrackerCrossoverText.line("))
        assertTrue(!apps.contains("R.string.apps_tracker_line") && !apps.contains("R.plurals.apps_tracker_line"))
        val network = Regex("""<(string|plurals) name="(apps_tracker_network_[a-z_]+)"[^>]*>(.*?)</\1>""",
            RegexOption.DOT_MATCHES_ALL).findAll(strings).map { it.groupValues[3] }.toList()
        assertEquals(2, network.size)
        for (body in network) {
            assertTrue(body, !body.contains("in code") && !body.contains("carries", ignoreCase = true))
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

    @Test fun `the details view keeps the standing lookup note and the spec's wording for older results`() {
        val screen = source("java/com/androdr/ui/privacy/PrivacyEvidenceScreen.kt") +
            source("java/com/androdr/ui/privacy/PrivacyEvidenceLookups.kt")
        assertTrue(screen.contains("R.string.privacy_network_caveat"))
        assertTrue(screen.contains("R.string.privacy_evidence_run_new_scan"))
        assertEquals(
            "Run a new privacy scan to record the matching packages and domains.",
            privacyStringBodies().getValue("privacy_evidence_run_new_scan"),
        )
        assertTrue(!Regex("""Text\(\s*\w+\.(appLabel|name|packageName|domain|signature)\b""").containsMatchIn(screen))
    }

    @Test fun `Delete privacy results names the looked-up domains it deletes`() {
        assertTrue(privacyStringBodies().getValue("privacy_delete_confirm").contains("looked-up tracker domains"))
    }

    @Test fun `MainActivity has the privacy details route`() {
        assertTrue(source("java/com/androdr/MainActivity.kt").contains("PRIVACY_EVIDENCE_ROUTE"))
    }

    @Test fun `app labels and tracker names are rendered through reportSafe`() {
        val ui = source("java/com/androdr/ui/privacy/PrivacyScreen.kt") +
            source("java/com/androdr/ui/privacy/PrivacyDetails.kt")
        assertTrue(ui.contains("reportSafe("))
        assertTrue("a label bypasses safe()", !Regex("""Text\(\s*\w+\.(appLabel|name)\b""").containsMatchIn(ui))
    }
}
