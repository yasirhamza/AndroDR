package com.androdr.data.db

import com.androdr.sigma.Evidence
import org.junit.Assert.assertEquals
import org.junit.Test

/**
 * Review focus 3: a scan stored before IocMatch named the family (v18-shape JSON,
 * no `family` key) must still decode -- through the same Json [Converters] uses.
 */
class StoredIocMatchDecodeTest {
    @Test
    fun `v18 IocMatch without family decodes with empty attribution`() {
        val stored = """[{"ruleId":"androdr-003","title":"Malicious Domain","level":"critical",""" +
            """"category":"APP_RISK","evidence":{"type":"ioc_match","matchedIndicator":"x.com",""" +
            """"iocType":"domain","source":"s"}}]"""
        val e = Converters.toFindingList(stored).single().evidence as Evidence.IocMatch
        assertEquals("x.com", e.matchedIndicator)
        assertEquals("", e.family)
        assertEquals("", e.campaign)
        assertEquals(0L, e.observedAt)
    }
}
