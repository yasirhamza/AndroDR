package com.androdr.scanner

import android.app.usage.UsageStatsManager
import android.content.Context
import android.content.res.Resources
import com.androdr.R
import com.androdr.ioc.OemPrefixResolver
import io.mockk.every
import io.mockk.mockk
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class UsageStatsScannerTest {

    private val mockContext: Context = mockk(relaxed = true)
    private val oemPrefixResolver: OemPrefixResolver
    private val granted: UsageAccess = mockk { every { granted() } returns true }

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
    fun `an unavailable UsageStatsManager is a failed collection`() = runTest {
        every { mockContext.getSystemService(Context.USAGE_STATS_SERVICE) } returns null
        val scanner = UsageStatsScanner(mockContext, oemPrefixResolver, granted)
        assertTrue(scanner.collectEvents(0L, 1L) is UsageCollection.Failed)
    }

    @Test
    fun `a SecurityException from the query means no access`() = runTest {
        val mockUsm: UsageStatsManager = mockk()
        every { mockContext.getSystemService(Context.USAGE_STATS_SERVICE) } returns mockUsm
        every { mockUsm.queryEvents(any(), any()) } throws SecurityException("Not granted")
        val scanner = UsageStatsScanner(mockContext, oemPrefixResolver, granted)
        assertEquals(UsageCollection.NoAccess, scanner.collectEvents(0L, 1L))
    }

    @Test
    fun `usage access is checked before any query`() = runTest {
        val mockUsm: UsageStatsManager = mockk()
        every { mockContext.getSystemService(Context.USAGE_STATS_SERVICE) } returns mockUsm
        val denied: UsageAccess = mockk { every { granted() } returns false }
        val scanner = UsageStatsScanner(mockContext, oemPrefixResolver, denied)
        assertEquals(UsageCollection.NoAccess, scanner.collectEvents(0L, 1L))
        io.mockk.verify(exactly = 0) { mockUsm.queryEvents(any(), any()) }
    }

    @Test
    fun `a query error is a failed collection`() = runTest {
        val mockUsm: UsageStatsManager = mockk()
        every { mockContext.getSystemService(Context.USAGE_STATS_SERVICE) } returns mockUsm
        every { mockUsm.queryEvents(any(), any()) } throws IllegalStateException("binder died")
        val result = UsageStatsScanner(mockContext, oemPrefixResolver, granted).collectEvents(0L, 1L)
        assertEquals("binder died", (result as UsageCollection.Failed).e.message)
    }
}
