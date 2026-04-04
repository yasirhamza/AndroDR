package com.androdr.scanner

import android.app.usage.UsageStatsManager
import android.content.Context
import android.content.res.Resources
import com.androdr.R
import com.androdr.ioc.OemPrefixResolver
import io.mockk.every
import io.mockk.mockk
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertTrue
import org.junit.Test

class UsageStatsScannerTest {

    private val mockContext: Context = mockk(relaxed = true)
    private val oemPrefixResolver: OemPrefixResolver

    init {
        val oemContext: Context = mockk(relaxed = true)
        val resources: Resources = mockk(relaxed = true)
        every { oemContext.resources } returns resources
        val yamlStream = javaClass.classLoader!!
            .getResourceAsStream("raw/known_oem_prefixes.yml")!!
        every { resources.openRawResource(R.raw.known_oem_prefixes) } returns yamlStream
        oemPrefixResolver = OemPrefixResolver(oemContext)
    }

    @Test
    fun `returns empty when UsageStatsManager unavailable`() = runTest {
        every { mockContext.getSystemService(Context.USAGE_STATS_SERVICE) } returns null
        val scanner = UsageStatsScanner(mockContext, oemPrefixResolver)
        assertTrue(scanner.collectTimelineEvents().isEmpty())
    }

    @Test
    fun `returns empty when permission not granted`() = runTest {
        val mockUsm: UsageStatsManager = mockk()
        every { mockContext.getSystemService(Context.USAGE_STATS_SERVICE) } returns mockUsm
        every { mockUsm.queryEvents(any(), any()) } throws SecurityException("Not granted")
        val scanner = UsageStatsScanner(mockContext, oemPrefixResolver)
        assertTrue(scanner.collectTimelineEvents().isEmpty())
    }
}
