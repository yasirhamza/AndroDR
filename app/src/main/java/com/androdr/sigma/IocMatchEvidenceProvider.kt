package com.androdr.sigma

import com.androdr.data.model.Indicator
import com.androdr.ioc.attribution

/**
 * Names the threat behind an IOC-lookup match (`evidence_type: ioc_match`).
 * For each `field|ioc_lookup: <db>` matcher, [lookup] returns the stored row for
 * the record's value; the first row that names a family becomes the evidence.
 */
class IocMatchEvidenceProvider(
    private val lookup: (lookupDb: String, value: String) -> Indicator?
) : EvidenceProvider {
    override fun provide(rule: SigmaRule, record: Map<String, Any?>): List<EvidenceResult> {
        // Lazy, in matcher-then-lookup order: the first row that names a family wins.
        // (Sequence form of the nested for/continue loops; detekt LoopWithTooManyJumpStatements.)
        val (value, row) = rule.detection.selections.values.asSequence()
            .flatMap { it.fieldMatchers }
            .filter { it.modifier == SigmaModifier.IOC_LOOKUP }
            .flatMap { m ->
                val value = record[m.fieldName]?.toString()?.takeIf { it.isNotBlank() }
                if (value == null) emptySequence() else m.values.asSequence().map { db -> value to db.toString() }
            }
            .mapNotNull { (value, db) -> lookup(db, value)?.let { value to it } }
            .firstOrNull { (_, row) -> row.attribution() != null }
            ?: return emptyList()
        val a = checkNotNull(row.attribution())
        val observedAt = (record["timestamp"] as? Number)?.toLong() ?: 0L
        val ev = Evidence.IocMatch(value, row.type, a.source, a.family, a.category, a.campaignKey,
            a.reference, observedAt)
        return listOf(EvidenceResult(ev, mapOf("family" to a.family), mapOf("family" to a.family)))
    }
}
