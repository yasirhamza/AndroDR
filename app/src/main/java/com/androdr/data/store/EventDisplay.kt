package com.androdr.data.store

import org.snakeyaml.engine.v2.api.Load
import org.snakeyaml.engine.v2.api.LoadSettings

/**
 * One-line summaries of event records, from `res/raw/event_display.yml`: service → template
 * whose `{field}` placeholders name that service's fields. Absent or null fields render as
 * nothing and the result is whitespace-normalised. Snapshot services have no template.
 */
class EventDisplay(private val templates: Map<String, String>) {

    val services: Set<String> get() = templates.keys

    /** The field names [service]'s template refers to. */
    fun placeholders(service: String): List<String> =
        templates[service]?.let { t -> PLACEHOLDER.findAll(t).map { it.groupValues[1] }.toList() }.orEmpty()

    /** The summary of one [service] record, or null when the service has no template. */
    fun summary(service: String, fields: Map<String, Any?>): String? {
        val template = templates[service] ?: return null
        val text = PLACEHOLDER.replace(template) { m -> fields[m.groupValues[1]]?.let(::render).orEmpty() }
        return text.replace(WHITESPACE, " ").trim()
    }

    private fun render(value: Any): String = when (value) {
        is Collection<*> -> value.joinToString(",")
        else -> value.toString()
    }

    companion object {
        private val PLACEHOLDER = Regex("\\{([a-z0-9_]+)\\}")
        private val WHITESPACE = Regex("\\s+")

        /** Parses the YAML mapping; throws if it is not a map of strings to strings. */
        fun parse(yaml: String): EventDisplay {
            val root = Load(LoadSettings.builder().build()).loadFromString(yaml)
            require(root is Map<*, *>) { "event_display.yml must be a mapping" }
            val templates = root.entries.associate { (k, v) ->
                require(k is String && v is String) { "event_display.yml entry $k must map a service to a string" }
                k to v
            }
            return EventDisplay(templates)
        }
    }
}
