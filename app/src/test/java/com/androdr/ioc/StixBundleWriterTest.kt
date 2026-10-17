package com.androdr.ioc

import org.junit.Assert.assertEquals
import org.junit.Test

class StixBundleWriterTest {
    @Test
    fun `imported STIX indicator stores its name as family, no category`() {
        val json = """{"type":"bundle","id":"bundle--1","objects":[
            {"type":"indicator","id":"indicator--1","name":"Pegasus C2",
             "pattern":"[domain-name:value = 'evil.example.com']","pattern_type":"stix"}]}"""
        val row = parseStixBundle(json, "user_import").single()
        assertEquals("Pegasus C2", row.family)
        assertEquals("", row.category)
        assertEquals("feed:user_import#Pegasus C2", row.attribution()!!.reference)
    }
}
