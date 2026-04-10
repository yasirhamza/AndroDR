package com.androdr.ioc

import org.junit.Assert.assertEquals
import org.junit.Test

class DeviceIdentityTest {

    @Test
    fun `fromSystemProperties extracts manufacturer and brand`() {
        val props = mapOf(
            "ro.product.manufacturer" to "Samsung",
            "ro.product.brand" to "samsung",
            "ro.build.fingerprint" to "samsung/a51/a51:11/...",
        )
        val identity = DeviceIdentity.fromSystemProperties(props)
        assertEquals("samsung", identity.manufacturer)
        assertEquals("samsung", identity.brand)
    }

    @Test
    fun `fromSystemProperties lowercases and trims values`() {
        val props = mapOf(
            "ro.product.manufacturer" to "  SAMSUNG  ",
            "ro.product.brand" to " SAMSUNG\n",
        )
        val identity = DeviceIdentity.fromSystemProperties(props)
        assertEquals("samsung", identity.manufacturer)
        assertEquals("samsung", identity.brand)
    }

    @Test
    fun `fromSystemProperties returns empty strings when keys are missing`() {
        val props = mapOf("ro.build.fingerprint" to "some value")
        val identity = DeviceIdentity.fromSystemProperties(props)
        assertEquals("", identity.manufacturer)
        assertEquals("", identity.brand)
    }

    @Test
    fun `fromSystemProperties handles brand different from manufacturer (Redmi Xiaomi case)`() {
        val props = mapOf(
            "ro.product.manufacturer" to "Xiaomi",
            "ro.product.brand" to "Redmi",
        )
        val identity = DeviceIdentity.fromSystemProperties(props)
        assertEquals("xiaomi", identity.manufacturer)
        assertEquals("redmi", identity.brand)
    }

    @Test
    fun `UNKNOWN identity has empty manufacturer and brand`() {
        assertEquals("", DeviceIdentity.UNKNOWN.manufacturer)
        assertEquals("", DeviceIdentity.UNKNOWN.brand)
    }

    @Test
    fun `equal identities are data-class equal`() {
        val a = DeviceIdentity(manufacturer = "samsung", brand = "samsung")
        val b = DeviceIdentity(manufacturer = "samsung", brand = "samsung")
        assertEquals(a, b)
        assertEquals(a.hashCode(), b.hashCode())
    }
}
