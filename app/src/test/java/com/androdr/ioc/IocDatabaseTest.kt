package com.androdr.ioc

import android.content.Context
import android.content.res.Resources
import io.mockk.every
import io.mockk.mockk
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Before
import org.junit.Test
import java.io.ByteArrayInputStream

class IocDatabaseTest {

    private val mockContext: Context = mockk(relaxed = true)
    private val mockResources: Resources = mockk()

    private val testJson = """
        [
          {
            "packageName": "com.flexispy.android",
            "name": "FlexiSPY",
            "category": "STALKERWARE",
            "severity": "CRITICAL",
            "description": "Commercial stalkerware with deep device surveillance."
          },
          {
            "packageName": "com.mspy.android",
            "name": "mSpy",
            "category": "STALKERWARE",
            "severity": "CRITICAL",
            "description": "Commercial stalkerware marketed for parental monitoring."
          },
          {
            "packageName": "com.badbank.trojan",
            "name": "BankBot",
            "category": "BANKING_TROJAN",
            "severity": "HIGH",
            "description": "Banking trojan that overlays login screens."
          }
        ]
    """.trimIndent()

    private lateinit var iocDatabase: IocDatabase

    @Before
    fun setUp() {
        every { mockContext.resources } returns mockResources
        every { mockResources.openRawResource(any()) } returns
            ByteArrayInputStream(testJson.toByteArray(Charsets.UTF_8))
        iocDatabase = IocDatabase(mockContext)
    }

    @Test
    fun `isKnownBadPackage returns BadPackageInfo for a known package`() {
        val result = iocDatabase.isKnownBadPackage("com.flexispy.android")
        assertNotNull(result)
        assertEquals("com.flexispy.android", result!!.packageName)
        assertEquals("FlexiSPY", result.name)
        assertEquals("STALKERWARE", result.category)
        assertEquals("CRITICAL", result.severity)
    }

    @Test
    fun `isKnownBadPackage returns null for an unknown package`() {
        val result = iocDatabase.isKnownBadPackage("com.legitimate.app")
        assertNull(result)
    }

    @Test
    fun `isKnownBadPackage returns null for empty string`() {
        val result = iocDatabase.isKnownBadPackage("")
        assertNull(result)
    }

    @Test
    fun `getCategory returns correct category for known package`() {
        assertEquals("STALKERWARE", iocDatabase.getCategory("com.mspy.android"))
        assertEquals("BANKING_TROJAN", iocDatabase.getCategory("com.badbank.trojan"))
    }

    @Test
    fun `getCategory returns null for unknown package`() {
        assertNull(iocDatabase.getCategory("com.safe.app"))
    }

    @Test
    fun `getAllBadPackages returns all entries from JSON`() {
        val all = iocDatabase.getAllBadPackages()
        assertEquals(3, all.size)
    }

    @Test
    fun `getAllBadPackages returns entries with correct fields`() {
        val all = iocDatabase.getAllBadPackages()
        val names = all.map { it.packageName }.toSet()
        assert("com.flexispy.android" in names)
        assert("com.mspy.android" in names)
        assert("com.badbank.trojan" in names)
    }
}
