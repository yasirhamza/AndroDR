package com.androdr.di

import com.androdr.data.store.TelemetryDictionaries
import org.junit.Assert.assertEquals
import org.junit.Test

class StoreModuleTest {
    @Test
    fun `every dictionary version has a raw resource mapping`() {
        assertEquals(TelemetryDictionaries.VERSIONS.values.map { it.second }.toSet(), DICTIONARY_RESOURCES.keys)
    }
}
