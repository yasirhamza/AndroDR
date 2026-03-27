package com.androdr.sigma

object TemplateResolver {

    private val VARIABLE_PATTERN = Regex("""\{(\w+)\}""")

    fun resolve(template: String, vars: Map<String, String>): String {
        if (template.isEmpty() || vars.isEmpty()) return template
        return VARIABLE_PATTERN.replace(template) { match ->
            vars[match.groupValues[1]] ?: match.value
        }
    }

    fun resolveAll(templates: List<String>, vars: Map<String, String>): List<String> =
        templates.map { resolve(it, vars) }
}
