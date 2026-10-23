package com.androdr.data.model

/**
 * An observation that a known-sensitive database path was referenced in a
 * bugreport (e.g. `contacts2.db`, `mmssms.db`, `telephony.db`). Plan 6
 * introduces a rule that flags unusual database access patterns from
 * non-system processes.
 *
 * The sensitive path list lives in a YAML resource (not hardcoded in
 * Kotlin) per the policy that detection data stays in rules.
 *
 * @property filePath the observed database file path
 * @property processName the process that referenced it, if known
 * @property packageName the owning package, if derivable
 * @property observationTimestamp epoch milliseconds of the reference
 * @property dbPath the database path as referenced in the bug report (typed bug-report records
 *   only; same value as [filePath])
 * @property recentQueryCount how many recently executed SQL statements the dbinfo pool lists
 *   (typed bug-report records only)
 * @property source where this row came from
 * @property capturedAt epoch milliseconds when the scan/import produced this row
 */
data class DatabasePathObservation(
    val filePath: String,
    val processName: String?,
    val packageName: String?,
    val observationTimestamp: Long,
    val dbPath: String? = null,
    val recentQueryCount: Int? = null,
    val source: TelemetrySource,
    val capturedAt: Long,
)
