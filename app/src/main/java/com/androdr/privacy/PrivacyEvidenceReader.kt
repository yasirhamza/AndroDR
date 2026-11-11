package com.androdr.privacy

import com.androdr.data.db.DnsEventDao
import com.androdr.data.db.PrivacyDao
import com.androdr.data.model.PrivacyAppResult
import com.androdr.data.model.PrivacyScan
import com.androdr.data.model.PrivacyTrackerEvidence
import com.androdr.privacy.model.SignatureKind
import javax.inject.Inject
import javax.inject.Singleton

/** One code signature that matched, with the stored package names and the true number that matched. */
data class CodeSignature(val kind: SignatureKind, val signature: String, val packages: List<String>, val total: Int)

/** One looked-up domain as recorded in the DNS log. [background] null = unknown. */
data class DomainLine(
    val domain: String,
    val kind: SignatureKind,
    val signature: String,
    val lookups: Int,
    val days: Int,
    val background: Int?,
    val first: Long,
    val last: Long,
)

/**
 * What the latest completed privacy scan recorded about one tracker in one app. [code] and [domains]
 * are empty when the scan was made before details were recorded: check [PrivacyScan.hasDetails]
 * before reading an empty list as "nothing matched".
 */
data class EvidenceDetails(
    val scan: PrivacyScan,
    val app: PrivacyAppResult,
    val evidence: PrivacyTrackerEvidence,
    val code: List<CodeSignature>,
    val domains: List<DomainLine>,
)

/**
 * Reads one finding's detail when the details view opens, and the live lookup times of one of its
 * domains. The UI's only way to the detail tables and the DNS log for this view.
 */
@Singleton
class PrivacyEvidenceReader @Inject constructor(
    private val dao: PrivacyDao,
    private val dns: DnsEventDao,
) {
    /** null when there is no completed scan, or it holds no evidence for [packageName] + [trackerId]. */
    suspend fun load(packageName: String, trackerId: Int): EvidenceDetails? {
        val scan = dao.latestCompletedOnce() ?: return null
        val evidence = dao.evidenceFor(scan.id, packageName, trackerId)
        val app = dao.resultFor(scan.id, packageName)
        if (evidence == null || app == null) return null
        val code = dao.codeDetail(scan.id, packageName, trackerId).mapNotNull { row ->
            val kind = kindOf(row.kind) ?: return@mapNotNull null
            CodeSignature(kind, row.signature, PrivacyDetailRows.packagesOf(row), row.packageCount)
        }
        val domains = dao.domainDetail(scan.id, packageName, trackerId).mapNotNull { row ->
            val kind = kindOf(row.kind) ?: return@mapNotNull null
            DomainLine(row.domain, kind, row.signature, row.lookups, row.lookupDays, row.background, row.firstSeen,
                row.lastSeen)
        }
        return EvidenceDetails(scan, app, evidence, code, domains)
    }

    /** The newest [MAX_RECENT_LOOKUPS] lookups of [domain] (as recorded) by [packageName], newest first. */
    suspend fun recentLookups(packageName: String, domain: String): List<Long> =
        dns.recentLookupTimes(packageName, domain, MAX_RECENT_LOOKUPS)

    /** A kind this build does not know (a row from a newer build) is left out, never guessed. */
    private fun kindOf(name: String): SignatureKind? = SignatureKind.entries.firstOrNull { it.name == name }

    companion object {
        const val MAX_RECENT_LOOKUPS = 50
    }
}
