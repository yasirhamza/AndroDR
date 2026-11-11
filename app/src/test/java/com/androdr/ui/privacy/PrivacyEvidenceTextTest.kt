package com.androdr.ui.privacy

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import com.androdr.privacy.AppPrivacyRow
import com.androdr.privacy.InspectOutcome
import com.androdr.privacy.TrackerRow
import com.androdr.privacy.model.TrackerCategory
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner

@RunWith(RobolectricTestRunner::class)
class PrivacyEvidenceTextTest {
    private val res = ApplicationProvider.getApplicationContext<Context>().resources
    private val now = 1_000_000_000L

    private fun tracker(
        inCode: Boolean, lookups: Int, background: Int? = null, lookupDays: Int = if (lookups > 0) 3 else 0,
    ) = TrackerRow(
        trackerId = 1, name = "T", website = "https://t.example", categories = setOf(TrackerCategory.ANALYTICS),
        rawCategories = listOf("Analytics"), inCode = inCode, lookups = lookups, lookupDays = lookupDays,
        background = background, firstSeen = null, lastSeen = now - 2 * 3_600_000L, newSinceLastScan = false,
    )

    private fun app(outcome: InspectOutcome, trackers: List<TrackerRow> = emptyList(), reason: String? = null) =
        AppPrivacyRow("p", 1, "App", false, outcome, reason, trackers, 0, emptySet(), false)

    @Test fun `a network-only row never says carries or found in code`() {
        val line = PrivacyEvidenceText.line(tracker(inCode = false, lookups = 14, background = 3), res, now)
        assertTrue(line, line.startsWith("looked up domains of this tracker"))
        assertFalse(line, line.contains("carries", ignoreCase = true))
        assertFalse(line, line.contains("found in code"))
        assertTrue(line, line.contains("14 lookups on 3 days"))
        assertTrue(line, line.contains("3 in background"))
    }

    @Test fun `both shows code and the network detail`() {
        val line = PrivacyEvidenceText.line(tracker(inCode = true, lookups = 1, background = 0), res, now)
        assertTrue(line, line.startsWith("found in code; also looked up its domains"))
        assertTrue(line, line.contains("1 lookup on 3 days"))
    }

    @Test fun `code only row says found in code`() {
        assertEquals("found in code", PrivacyEvidenceText.line(tracker(inCode = true, lookups = 0), res, now))
    }

    @Test fun `background null renders unknown`() {
        val line = PrivacyEvidenceText.line(tracker(inCode = false, lookups = 2, background = null), res, now)
        assertTrue(line, line.contains("background use unknown"))
        assertFalse(line, line.contains("in background"))
    }

    @Test fun `an INSPECTED app with no trackers renders none-from-registry with the scan's registry size`() {
        val s = PrivacyEvidenceText.appStatus(app(InspectOutcome.INSPECTED), 428, res)
        assertEquals("None of the 428 trackers in the registry were found in its code", s)
    }

    @Test fun `PARTIAL and COULD_NOT_INSPECT never render none-from-registry`() {
        val partial = PrivacyEvidenceText.appStatus(app(InspectOutcome.PARTIAL, reason = "dex too large"), 428, res)
        val unreadable = app(InspectOutcome.COULD_NOT_INSPECT, reason = "unreadable")
        val failed = PrivacyEvidenceText.appStatus(unreadable, 428, res)
        assertEquals("Partly inspected: dex too large", partial)
        assertEquals("Could not inspect: unreadable", failed)
        for (s in listOf(partial, failed)) assertFalse(s, s.contains("None of the"))
        // a missing reason must not fall back to reassurance either
        val noReason = PrivacyEvidenceText.appStatus(app(InspectOutcome.PARTIAL), 428, res)
        assertFalse(noReason, noReason.contains("None of the"))
    }

    @Test fun `a hostile reason is reduced to printable ASCII`() {
        val s = PrivacyEvidenceText.appStatus(app(InspectOutcome.PARTIAL, reason = "a\nb\u202Ec"), 1, res)
        assertEquals("Partly inspected: abc", s)
    }

    private fun labelled(label: String) = AppPrivacyRow(
        "com.example.bank", 1, label, false, InspectOutcome.INSPECTED, null, emptyList(), 0, emptySet(), false,
    )

    @Test fun `non-ASCII app labels keep their letters (R15)`() {
        assertEquals("Résumé", PrivacyEvidenceText.appName(labelled("Résumé")))
        assertEquals("تطبيق البنك", PrivacyEvidenceText.appName(labelled("تطبيق البنك")))
        assertEquals("App", PrivacyEvidenceText.appName(app(InspectOutcome.INSPECTED)))
    }

    @Test fun `bidi overrides and controls are stripped from an app label`() {
        assertEquals("Bankevil.apk", PrivacyEvidenceText.appName(labelled("Bank\u202Eevil.apk")))
        assertEquals("a b", PrivacyEvidenceText.appName(labelled("  a\n\r\t b\u200F ")))
    }

    @Test fun `a label of only control and format characters falls back to the package name`() {
        assertEquals("com.example.bank", PrivacyEvidenceText.appName(labelled("\u0000\u202E\n\u2066\u200B")))
        assertEquals("com.example.bank", PrivacyEvidenceText.appName(labelled("")))
    }

    @Test fun `a non-ASCII tracker name is kept, a blank one falls back to the host, then to Tracker id`() {
        assertEquals("追踪", PrivacyEvidenceText.trackerName("追踪", "https://Tracker.Example/x", 7))
        val blank = "\u202E\u0007"
        assertEquals("tracker.example", PrivacyEvidenceText.trackerName(blank, "https://Tracker.Example/x", 7))
        assertEquals("Tracker #7", PrivacyEvidenceText.trackerName(blank, "javascript:x", 7))
        assertEquals("Tracker #7", PrivacyEvidenceText.trackerName(blank, "", 7))
        assertEquals("AdCo", PrivacyEvidenceText.trackerName("AdCo", "https://x.example", 7))
    }

    @Test fun `websiteLink accepts https with a host and rejects http, javascript and userinfo`() {
        assertNotNull(PrivacyEvidenceText.websiteLink("https://firebase.google.com"))
        assertNull(PrivacyEvidenceText.websiteLink("http://firebase.google.com"))
        assertNull(PrivacyEvidenceText.websiteLink("javascript:alert(1)"))
        assertNull(PrivacyEvidenceText.websiteLink("https://firebase.google.com@evil.example"))
        assertNull(PrivacyEvidenceText.websiteLink("https://"))
        assertNull(PrivacyEvidenceText.websiteLink("not a url"))
        assertNull(PrivacyEvidenceText.websiteLink(""))
    }

    @Test fun `the website is shown as a lower-cased host only`() {
        assertEquals("firebase.google.com", PrivacyEvidenceText.websiteHost("HTTPS://Firebase.Google.com/path?q=1"))
        assertEquals("example.org", PrivacyEvidenceText.websiteHost("http://Example.org/x"))
        assertNull(PrivacyEvidenceText.websiteHost("javascript:alert(1)"))
        assertNull(PrivacyEvidenceText.websiteHost(""))
    }
}
