package com.androdr.data.model

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.lang.reflect.Constructor

/**
 * [ForensicTimelineEvent] is a data class with hand-written `equals`/`hashCode` (it holds a
 * `ByteArray`), so a new constructor property is silently ignored by equality unless it is
 * added there too. This builds instances differing in exactly one constructor property at a
 * time and requires each to be unequal, with a different hash.
 */
class ForensicTimelineEventEqualityTest {

    private val ctor: Constructor<*> = ForensicTimelineEvent::class.java.declaredConstructors
        .filter { c -> !c.isSynthetic && c.parameterTypes.none { it.name.endsWith("DefaultConstructorMarker") } }
        .maxBy { it.parameterCount }

    private fun base(type: Class<*>): Any? = when (type) {
        java.lang.Long.TYPE -> 1L
        java.lang.Integer.TYPE -> 1
        java.lang.Boolean.TYPE -> false
        java.lang.Long::class.java -> 1L
        String::class.java -> "a"
        ByteArray::class.java -> byteArrayOf(1, 2)
        TelemetrySource::class.java -> TelemetrySource.LIVE_SCAN
        else -> error("add a base value for constructor parameter type $type")
    }

    private fun other(type: Class<*>): Any? = when (type) {
        java.lang.Long.TYPE -> 2L
        java.lang.Integer.TYPE -> 2
        java.lang.Boolean.TYPE -> true
        java.lang.Long::class.java -> 2L
        String::class.java -> "b"
        ByteArray::class.java -> byteArrayOf(1, 3)
        TelemetrySource::class.java -> TelemetrySource.BUGREPORT_IMPORT
        else -> error("add a differing value for constructor parameter type $type")
    }

    private fun build(args: List<Any?>) = ctor.newInstance(*args.toTypedArray()) as ForensicTimelineEvent

    @Test
    fun `constructor covers every stored property`() {
        val fields = ForensicTimelineEvent::class.java.declaredFields.filter {
            !java.lang.reflect.Modifier.isStatic(it.modifiers)
        }
        assertEquals("constructor parameters vs fields", fields.size, ctor.parameterCount)
    }

    @Test
    fun `equals and hashCode cover every constructor property`() {
        val types = ctor.parameterTypes.toList()
        val baseArgs = types.map(::base)
        val a = build(baseArgs)
        // Content equality for the ByteArray, not identity.
        assertEquals(a, build(types.map(::base)))
        assertEquals(a.hashCode(), build(types.map(::base)).hashCode())
        for (i in types.indices) {
            val b = build(baseArgs.toMutableList().also { it[i] = other(types[i]) })
            assertNotEquals("equals ignores constructor parameter #$i (${types[i].simpleName})", a, b)
            assertTrue(
                "hashCode ignores constructor parameter #$i (${types[i].simpleName})",
                a.hashCode() != b.hashCode(),
            )
        }
    }
}
