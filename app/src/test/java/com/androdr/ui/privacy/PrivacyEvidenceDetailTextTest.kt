package com.androdr.ui.privacy

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import com.androdr.privacy.DomainLine
import com.androdr.privacy.model.SignatureKind
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner

@RunWith(RobolectricTestRunner::class)
class PrivacyEvidenceDetailTextTest {
    private val res = ApplicationProvider.getApplicationContext<Context>().resources
    private val fmt: (Long) -> String = { "t$it" }

    @Test fun `each signature kind has its own words`() {
        assertEquals(
            listOf("package prefix", "package-name segment", "domain suffix", "label", "pattern"),
            SignatureKind.entries.map { res.getString(PrivacyEvidenceDetailText.kindLabel(it)) },
        )
    }

    @Test fun `the list hash is shown short`() {
        assertEquals("a41c…9e", PrivacyEvidenceDetailText.shortHash("a41c" + "0".repeat(58) + "9e"))
        assertNull(PrivacyEvidenceDetailText.shortHash(""))
        assertNull(PrivacyEvidenceDetailText.shortHash("abc"))
    }

    @Test fun `packages beyond the stored ones are counted`() {
        assertEquals("… and 9 more", PrivacyEvidenceDetailText.more(stored = 200, total = 209, res = res))
        assertNull(PrivacyEvidenceDetailText.more(stored = 2, total = 2, res = res))
    }

    @Test fun `unknown background is said, never shown as zero`() {
        val line = PrivacyEvidenceDetailText.domainCounts(
            DomainLine("x.flurry.com", SignatureKind.DOMAIN_SUFFIX, "flurry.com", 3, 2, null, 10, 20), res, fmt,
        )
        assertTrue(line, line.contains("background use unknown"))
        assertFalse(line, line.contains("0 in background"))
        assertTrue(line, line.contains("3 lookups") && line.contains("t10") && line.contains("t20"))
    }

    @Test fun `a timed background count is shown`() {
        val line = PrivacyEvidenceDetailText.domainCounts(
            DomainLine("x.flurry.com", SignatureKind.DOMAIN_SUFFIX, "flurry.com", 3, 1, 2, 10, 20), res, fmt,
        )
        assertTrue(line, line.contains("2 in background"))
    }

    @Test fun `package and domain text loses bidi controls and keeps a visible cut`() {
        assertEquals("com.evil.txt", PrivacyEvidenceDetailText.shown("com.\u202Eevil.txt"))
        val stored = "a".repeat(254) + "…"
        assertEquals(stored, PrivacyEvidenceDetailText.shown(stored))
    }

    @Test fun `the Exodus page is linked only for a list entry number`() {
        assertEquals("https://reports.exodus-privacy.eu.org/en/trackers/12/", PrivacyEvidenceDetailText.exodusLink(12))
        assertNull(PrivacyEvidenceDetailText.exodusLink(0))
    }
}
