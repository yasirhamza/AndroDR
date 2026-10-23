package com.androdr.sigma

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.booleanOrNull
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.longOrNull
import org.junit.Assert.assertTrue
import java.io.File

/**
 * The fixed corpus of sample records (`src/test/resources/contract-corpus/`) the
 * X1 contract hash and the K1 category gate run over. Each file is a JSON array
 * of `{ "service": ..., "fields": {...} }`; files are read in name order and
 * records in file order, so the corpus has one stable sequence.
 *
 * JSON integers become [Long], as the field maps carry epoch-ms values.
 */
internal object ContractCorpus {

    /** Floor: fewer records than this means the corpus did not load. */
    private const val MIN_RECORDS = 15

    fun records(): List<Pair<String, Map<String, Any?>>> {
        val url = javaClass.classLoader?.getResource("contract-corpus")
            ?: error("contract-corpus test resource directory not found")
        val files = File(url.toURI()).listFiles { f -> f.extension == "json" }
            ?.sortedBy { it.name }
            .orEmpty()
        val records = files.flatMap { file ->
            Json.parseToJsonElement(file.readText()).jsonArray.map { element ->
                val obj = element.jsonObject
                val service = obj.getValue("service").jsonPrimitive.content
                @Suppress("UNCHECKED_CAST")
                service to (toValue(obj.getValue("fields")) as Map<String, Any?>)
            }
        }
        assertTrue(
            "Expected at least $MIN_RECORDS corpus records, found ${records.size}",
            records.size >= MIN_RECORDS,
        )
        return records
    }

    private fun toValue(element: JsonElement): Any? = when (element) {
        is JsonNull -> null
        is JsonObject -> element.mapValues { (_, v) -> toValue(v) }
        is JsonArray -> element.map { toValue(it) }
        is JsonPrimitive -> when {
            element.isString -> element.content
            element.booleanOrNull != null -> element.booleanOrNull
            element.longOrNull != null -> element.longOrNull
            else -> element.content.toDouble()
        }
    }
}
