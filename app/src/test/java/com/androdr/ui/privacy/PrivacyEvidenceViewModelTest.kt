package com.androdr.ui.privacy

import androidx.lifecycle.SavedStateHandle
import com.androdr.data.model.NetworkStatus
import com.androdr.data.model.PrivacyAppResult
import com.androdr.data.model.PrivacyScan
import com.androdr.data.model.PrivacyTrackerEvidence
import com.androdr.privacy.EvidenceDetails
import com.androdr.privacy.PrivacyEvidenceReader
import io.mockk.coEvery
import io.mockk.coVerify
import io.mockk.mockk
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.test.UnconfinedTestDispatcher
import kotlinx.coroutines.test.resetMain
import kotlinx.coroutines.test.setMain
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Before
import org.junit.Test

@OptIn(ExperimentalCoroutinesApi::class)
class PrivacyEvidenceViewModelTest {
    @Before fun setUp() = Dispatchers.setMain(UnconfinedTestDispatcher())

    @After fun tearDown() = Dispatchers.resetMain()

    private val details = EvidenceDetails(
        PrivacyScan(
            id = 1, startedAt = 1, finishedAt = 2, appsTotal = 1, appsInspected = 1, appsPartial = 0, appsFailed = 0,
            registrySize = 428, registrySha256 = "", dnsWindowStart = 0, dnsCoverageDays = 0, usageCoverageFrom = null,
            networkStatus = NetworkStatus.COMPLETE.name, hasDetails = true,
        ),
        PrivacyAppResult(1, "com.x", 1, "X", false, "INSPECTED", null),
        PrivacyTrackerEvidence(1, "com.x", 12, "Flurry", "", "Analytics", true, 0, 0, null, null, null, false),
        emptyList(),
        emptyList(),
    )

    private fun vm(reader: PrivacyEvidenceReader) = PrivacyEvidenceViewModel(
        reader,
        SavedStateHandle(
            mapOf(PrivacyEvidenceViewModel.ARG_PACKAGE to "com.x", PrivacyEvidenceViewModel.ARG_TRACKER to 12),
        ),
    )

    @Test fun `loads the route's app and tracker when created`() {
        val reader = mockk<PrivacyEvidenceReader> { coEvery { load("com.x", 12) } returns details }
        assertEquals(EvidenceUiState.Loaded(details), vm(reader).state.value)
        coVerify(exactly = 1) { reader.load("com.x", 12) }
    }

    @Test fun `a result that is no longer stored is Gone`() {
        val reader = mockk<PrivacyEvidenceReader> { coEvery { load(any(), any()) } returns null }
        assertEquals(EvidenceUiState.Gone, vm(reader).state.value)
    }

    @Test fun `a read that fails says so and does not crash`() {
        val reader = mockk<PrivacyEvidenceReader> { coEvery { load(any(), any()) } throws IllegalStateException("db") }
        assertEquals(EvidenceUiState.Unreadable, vm(reader).state.value)
    }

    @Test fun `opening a domain publishes its recent lookups and closing clears them`() {
        val reader = mockk<PrivacyEvidenceReader> {
            coEvery { load(any(), any()) } returns details
            coEvery { recentLookups("com.x", "T.Flurry.com.") } returns listOf(9L, 3L)
        }
        val model = vm(reader)
        model.openLookups("T.Flurry.com.")
        assertEquals(LookupTimes("T.Flurry.com.", listOf(9L, 3L)), model.lookups.value)
        model.closeLookups()
        assertNull(model.lookups.value)
    }
}
