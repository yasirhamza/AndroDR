package com.androdr.data.model

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File
import java.lang.reflect.Constructor
import java.lang.reflect.Modifier

/**
 * Gate E2: a field map carries every fact its data class holds (spec §4.1).
 *
 * Records are stored as their `toFieldMap()` projection, so a constructor
 * property the map drops is a fact lost at write time. Each class's
 * constructor properties (camelCase -> snake_case) must appear as map keys,
 * unless [ALLOWED] says why not.
 *
 * The classes are derived, not hand-listed: every `toFieldMap()` declared in the
 * main sources (a member of a data class, or an extension `Type.toFieldMap()`) is
 * found, and one instance of its class is built by reflection with a non-null value
 * for every constructor parameter, so optional keys (`listOfNotNull`) appear too.
 */
class FieldMapCompletenessTest {

    private fun root(): File = listOf(File("src/main/java/com/androdr"), File("app/src/main/java/com/androdr"))
        .first { it.isDirectory }

    /** A class declaring (or extended with) `toFieldMap()`, and whether it is an extension. */
    private data class Projection(val className: String, val extensionFile: String?)

    /**
     * Every `toFieldMap()` in [src] (one source file named [fileName] in [pkg]): an extension
     * `fun Type.toFieldMap(` names its receiver; a member names the nearest enclosing `class`.
     */
    private fun projections(src: String, fileName: String, pkg: String): List<Projection> =
        Regex("fun\\s+(?:(\\w+)\\.)?toFieldMap\\s*\\(").findAll(src).map { m ->
            val receiver = m.groupValues[1]
            if (receiver.isNotEmpty()) {
                Projection(receiver, "$pkg.${fileName.removeSuffix(".kt")}Kt")
            } else {
                val owner = Regex("\\bclass\\s+(\\w+)").findAll(src.substring(0, m.range.first)).last()
                Projection(owner.groupValues[1], null)
            }
        }.toList()

    private fun allProjections(): List<Projection> = root().walkTopDown().filter { it.extension == "kt" }
        .flatMap { f ->
            val pkg = Regex("^package\\s+([\\w.]+)", RegexOption.MULTILINE).find(f.readText())!!.groupValues[1]
            projections(f.readText(), f.name, pkg)
        }.toList()

    /** One sample per telemetry class, paired with its field map. */
    private fun samples(): List<Pair<Any, Map<String, Any?>>> = allProjections().map { p ->
        val cls = Class.forName("$MODEL_PACKAGE.${p.className}")
        val instance = build(cls)
        val map = if (p.extensionFile == null) {
            cls.getMethod("toFieldMap").invoke(instance)
        } else {
            Class.forName(p.extensionFile).getDeclaredMethod("toFieldMap", cls)
                .apply { isAccessible = true }.invoke(null, instance)
        }
        @Suppress("UNCHECKED_CAST")
        (instance to map as Map<String, Any?>)
    }

    /** An instance of [cls] through its primary constructor, every argument non-null. */
    private fun build(cls: Class<*>): Any {
        val ctor: Constructor<*> = cls.declaredConstructors
            .filter { c -> !c.isSynthetic && c.parameterTypes.none { it.name.endsWith("DefaultConstructorMarker") } }
            .maxBy { it.parameterCount }
        return ctor.newInstance(*ctor.parameterTypes.map(::sampleValue).toTypedArray())
    }

    private fun sampleValue(type: Class<*>): Any = when {
        type == String::class.java -> "x"
        type == Int::class.javaPrimitiveType || type == Int::class.javaObjectType -> 1
        type == Long::class.javaPrimitiveType || type == Long::class.javaObjectType -> 1L
        type == Boolean::class.javaPrimitiveType || type == Boolean::class.javaObjectType -> true
        type == Double::class.javaPrimitiveType || type == Double::class.javaObjectType -> 1.0
        type == Float::class.javaPrimitiveType || type == Float::class.javaObjectType -> 1f
        List::class.java.isAssignableFrom(type) -> emptyList<Any>()
        Set::class.java.isAssignableFrom(type) -> emptySet<Any>()
        Map::class.java.isAssignableFrom(type) -> emptyMap<Any, Any>()
        type.isEnum -> type.enumConstants.first()
        else -> build(type)
    }

    @Test
    fun `samples are derived from every toFieldMap in the sources`() {
        val names = samples().map { it.first.javaClass.simpleName }
        assertEquals("one sample per class", names.size, names.toSet().size)
        // The 19 classes the hand-kept list held when it was replaced; a derivation may only add.
        assertTrue(names.containsAll(listOf(
            "AppTelemetry", "DeviceTelemetry", "DnsEvent", "ImportedDnsEvent", "ProcessTelemetry",
            "FileArtifactTelemetry", "ReceiverTelemetry", "AccessibilityTelemetry", "AppOpsTelemetry",
            "NetworkTelemetry", "UsageEvent", "TombstoneEvent", "WakelockAcquisition", "BatteryDailyEvent",
            "PackageInstallHistoryEntry", "PlatformCompatChange", "DatabasePathObservation", "SecurityLogEvent",
            "SystemPropertySnapshot",
        )))
    }

    @Test
    fun `derivation finds member and extension projections`() {
        // A class the old hand-kept list never named would have gone unchecked.
        val src = "package p\ndata class NewEvent(val a: Int) {\n" +
            "    fun toFieldMap(): Map<String, Any?> = mapOf()\n}\n" +
            "internal fun OtherEvent.toFieldMap(): Map<String, Any?> = mapOf()\n"
        assertEquals(
            listOf(Projection("NewEvent", null), Projection("OtherEvent", "p.NewEventKt")),
            projections(src, "NewEvent.kt", "p"),
        )
    }

    private fun constructorProperties(instance: Any): List<String> =
        instance.javaClass.declaredFields
            .filter { !Modifier.isStatic(it.modifiers) && !it.isSynthetic }
            .map { it.name }

    private fun snakeCase(name: String): String =
        name.replace(Regex("([a-z0-9])([A-Z])"), "$1_$2").lowercase()

    @Test
    fun `every constructor property reaches the field map`() {
        val failures = mutableListOf<String>()
        for ((instance, fieldMap) in samples()) {
            val cls = instance.javaClass.simpleName
            for (property in constructorProperties(instance)) {
                val qualified = "$cls.$property"
                if (qualified in ALLOWED) continue
                if (snakeCase(property) !in fieldMap.keys) {
                    failures += "$qualified -> \"${snakeCase(property)}\" missing from toFieldMap()"
                }
            }
        }
        assertTrue(
            "Field maps drop facts their class holds:\n" + failures.joinToString("\n") { "  - $it" },
            failures.isEmpty(),
        )
    }

    @Test
    fun `allow-list entries name real properties`() {
        val known = samples().flatMap { (instance, _) ->
            constructorProperties(instance).map { "${instance.javaClass.simpleName}.$it" }
        }.toSet()
        val stale = ALLOWED.keys - known
        assertTrue("Stale allow-list entries (property gone): $stale", stale.isEmpty())
    }

    private companion object {
        const val MODEL_PACKAGE = "com.androdr.data.model"

        /**
         * Properties deliberately absent from the snake_case key, and why.
         * Keep each entry justified; a new gap needs a reason here or a key.
         */
        val ALLOWED = mapOf(
            // Room primary key, assigned on insert; not an observed fact.
            "DnsEvent.id" to "row id",
            // Published under the taxonomy key `source_package`.
            "DnsEvent.appName" to "source_package",
            // Flattened: ImportedDnsEvent's map is event.toFieldMap() + resolved_ips.
            "ImportedDnsEvent.event" to "flattened",
            // Published under the taxonomy keys embedded_component_class / embedded_native_lib.
            "AppTelemetry.embeddedComponentClasses" to "embedded_component_class",
            "AppTelemetry.embeddedNativeLibs" to "embedded_native_lib",
            // Live-scan provenance. ASSUMPTION: every producer of these classes
            // passes TelemetrySource.LIVE_SCAN (bug-report and intrusion imports use
            // generic maps or other classes), so the observation's own source carries
            // it (spec §4.1 envelope keys). A non-live producer of one of these
            // classes must add "source" to its field map and drop its entry here.
            "AppTelemetry.source" to "envelope",
            "DeviceTelemetry.source" to "envelope",
            "ProcessTelemetry.source" to "envelope",
            "FileArtifactTelemetry.source" to "envelope",
            "ReceiverTelemetry.source" to "envelope",
            "AccessibilityTelemetry.source" to "envelope",
            "AppOpsTelemetry.source" to "envelope",
        )
    }
}
