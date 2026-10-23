package com.androdr.ioc

import com.androdr.data.model.DomainIocEntry
import com.androdr.data.model.Indicator
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

/** One layout for every type: family = label, category = threat category. */
class IocAttributionTest {
    @Test
    fun `package row attribution`() {
        val a = Indicator("package", "com.serv.services", family = "NoviSpy",
            category = "NATION_STATE_SPYWARE", source = "androdr_public_repo", fetchedAt = 0L).attribution()!!
        assertEquals("NoviSpy", a.family)
        assertEquals("NATION_STATE_SPYWARE", a.category)
    }

    @Test
    fun `mirror-feed domain entry stores its label as the family`() {
        val row = DomainIocEntry("2y4nothing.xyz", "Predator Spyware Indicators of Compromise",
            "CRITICAL", "mvt_predator", 0L).toIndicator()
        assertEquals("Predator Spyware Indicators of Compromise", row.family)
        assertEquals("", row.category)
        assertEquals("", row.reference)
        assertEquals("feed:mvt_predator#Predator Spyware Indicators of Compromise", row.attribution()!!.reference)
    }

    @Test
    fun `bloom placeholder has no attribution`() {
        assertNull(Indicator("domain", "x.com", source = "bloom", fetchedAt = 0L).attribution())
    }

    @Test
    fun `package and cert writers populate family and category`() {
        val pkg = com.androdr.data.model.IocEntry("com.x", "Fam", "STALKERWARE", "HIGH", "d", "src", 0L).toIndicator()
        assertEquals("Fam", pkg.family)
        assertEquals("STALKERWARE", pkg.category)
        assertEquals("feed:src#Fam", pkg.attribution()!!.reference)
        val cert = com.androdr.data.model.CertHashIocEntry("ab", "CFam", "SPYWARE", "HIGH", "d", "src", 0L)
            .toIndicator()
        assertEquals("CFam", cert.family)
        assertEquals("SPYWARE", cert.category)
        assertEquals("feed:src#CFam", cert.attribution()!!.reference)
    }
}
