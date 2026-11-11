package com.androdr.ui.privacy

import androidx.compose.ui.test.hasText
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performScrollTo
import com.androdr.data.model.NetworkStatus
import com.androdr.data.model.PrivacyAppResult
import com.androdr.data.model.PrivacyScan
import com.androdr.data.model.PrivacyTrackerEvidence
import com.androdr.privacy.CodeSignature
import com.androdr.privacy.DomainLine
import com.androdr.privacy.EvidenceDetails
import com.androdr.privacy.InspectOutcome
import com.androdr.privacy.model.SignatureKind
import com.androdr.ui.registerHostActivity
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.RuleChain
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner

/** The details view of one tracker in one app (spec §4.1), rendered from the stateless content. */
@RunWith(RobolectricTestRunner::class)
class PrivacyEvidenceScreenTest {
    private val composeRule = createComposeRule()

    @get:Rule val chain: RuleChain = RuleChain.outerRule(registerHostActivity()).around(composeRule)

    private val sha = "a41c" + "0".repeat(58) + "9e"

    private fun scan(
        hasDetails: Boolean = true,
        status: NetworkStatus = NetworkStatus.COMPLETE,
    ) = PrivacyScan(
        id = 1, startedAt = 1_000, finishedAt = 2_000, appsTotal = 1, appsInspected = 1, appsPartial = 0,
        appsFailed = 0, registrySize = 428, registrySha256 = sha, dnsWindowStart = 0, dnsCoverageDays = 3,
        usageCoverageFrom = null, networkStatus = status.name, hasDetails = hasDetails,
    )

    private fun app(outcome: InspectOutcome = InspectOutcome.INSPECTED, pkg: String = "com.example") =
        PrivacyAppResult(1, pkg, 42, "Example App", false, outcome.name, null)

    private fun evidence(lookups: Int = 5) = PrivacyTrackerEvidence(
        1, "com.example", 12, "Flurry", "https://www.flurry.com", "Analytics", true, lookups, 2, null, 10, 20, false,
    )

    private fun details(
        scan: PrivacyScan = scan(),
        app: PrivacyAppResult = app(),
        code: List<CodeSignature> = listOf(
            CodeSignature(SignatureKind.CODE_PREFIX, "com.flurry", listOf("com.flurry.android", "com.flurry.sdk"), 2),
        ),
        domains: List<DomainLine> = listOf(
            DomainLine("T.Flurry.com.", SignatureKind.DOMAIN_SUFFIX, "flurry.com", 5, 2, null, 10, 20),
        ),
        lookups: Int = 5,
    ) = EvidenceDetails(scan, app, evidence(lookups), code, domains)

    private fun show(
        state: EvidenceUiState,
        lookups: LookupTimes? = null,
        onOpenLookups: (String) -> Unit = {},
    ) = composeRule.setContent {
        EvidenceContent(state, lookups, onOpenLookups, onCloseLookups = {}, onBack = {}, formatTime = { "t$it" })
    }

    private fun exists(text: String) = composeRule.onAllNodes(hasText(text, substring = true))
        .fetchSemanticsNodes().isNotEmpty()

    @Test fun `a finding with details shows the signature, its packages and its domains`() {
        show(EvidenceUiState.Loaded(details()))
        for (text in listOf(
            "Flurry", "Example App (com.example)", "Tracker list entry 12", "Found in code",
            "Signature com.flurry (package prefix)", "com.flurry.android", "com.flurry.sdk",
            "Version inspected: 42", "Looked up domains of this tracker", "T.Flurry.com.",
            "matched flurry.com (domain suffix)", "background use unknown",
            "Lookups can be caused by links, web pages or emails the app displays",
            "Privacy scan of t2000 · tracker list: 428 trackers (a41c…9e)",
        )) {
            assertTrue("missing: $text", exists(text))
        }
    }

    @Test fun `packages beyond the stored ones are counted, not hidden`() {
        show(
            EvidenceUiState.Loaded(
                details(code = listOf(CodeSignature(SignatureKind.CODE_PREFIX, "com.flurry", listOf("com.flurry.a"), 260))),
            ),
        )
        assertTrue(exists("… and 259 more"))
    }

    @Test fun `a result from before details were recorded says to run a new scan`() {
        show(EvidenceUiState.Loaded(details(scan = scan(hasDetails = false), code = emptyList(), domains = emptyList())))
        assertTrue(exists("Run a new privacy scan to record the matching packages and domains."))
        assertTrue(!exists("Found in code"))
        assertTrue(!exists("Looked up domains of this tracker"))
    }

    @Test fun `a partly inspected app says the list may be incomplete`() {
        show(EvidenceUiState.Loaded(details(app = app(InspectOutcome.PARTIAL))))
        assertTrue(exists("Only part of this app's code could be read, so this list may be incomplete."))
        assertTrue(exists("partly inspected"))
    }

    @Test fun `a failed network step is stated even when no domain was recorded`() {
        show(EvidenceUiState.Loaded(details(scan = scan(status = NetworkStatus.FAILED), domains = emptyList(), lookups = 0)))
        assertTrue(exists("Looked up domains of this tracker"))
        assertTrue(exists("Network evidence could not be read this time"))
        assertTrue(exists("This list of domains may be incomplete."))
    }

    @Test fun `a code-only finding with a complete network step shows no domain section`() {
        show(EvidenceUiState.Loaded(details(domains = emptyList(), lookups = 0)))
        assertTrue(exists("Found in code"))
        assertTrue(!exists("Looked up domains of this tracker"))
    }

    @Test fun `a result that is no longer stored says so`() {
        show(EvidenceUiState.Gone)
        assertTrue(exists("This result is no longer stored. Run a new privacy scan."))
    }

    @Test fun `tapping a domain asks for its lookup times by the recorded spelling`() {
        var asked: String? = null
        show(EvidenceUiState.Loaded(details()), onOpenLookups = { asked = it })
        composeRule.onNodeWithText("T.Flurry.com.").performScrollTo().performClick()
        assertEquals("T.Flurry.com.", asked)
    }

    @Test fun `lookup times are labelled as read from the DNS log now`() {
        show(EvidenceUiState.Loaded(details()), lookups = LookupTimes("T.Flurry.com.", listOf(77L, 55L)))
        assertTrue(exists("read from the DNS log as it is now"))
        assertTrue(exists("t77"))
        assertTrue(exists("t55"))
    }

    @Test fun `no current lookups are said, not shown as an empty list`() {
        show(EvidenceUiState.Loaded(details()), lookups = LookupTimes("T.Flurry.com.", emptyList()))
        assertTrue(exists("The DNS log holds no lookups of this domain by this app now."))
    }

    @Test fun `hostile package text is shown without its bidi controls`() {
        show(
            EvidenceUiState.Loaded(
                details(code = listOf(CodeSignature(SignatureKind.CODE_SEGMENT, "x", listOf("com.‮evil.x"), 1))),
            ),
        )
        assertTrue(exists("com.evil.x"))
        assertTrue(!exists("‮"))
    }
}
