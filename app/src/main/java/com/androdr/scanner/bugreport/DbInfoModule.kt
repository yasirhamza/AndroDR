package com.androdr.scanner.bugreport

import com.androdr.ioc.IndicatorResolver
import javax.inject.Inject
import javax.inject.Singleton

/**
 * Parses `dumpsys dbinfo` for database connection pools. Can reveal bulk
 * data exfiltration patterns (mass SELECT on contacts/SMS) and map database
 * paths to package names for IOC matching.
 */
@Singleton
class DbInfoModule @Inject constructor() : BugreportModule {

    override val targetSections: List<String> = listOf("dbinfo")

    // Connection pool header: "Connection pool for /data/user/0/com.example/databases/app.db:"
    private val poolHeaderRegex = Regex(
        """Connection pool for (/data/[^:]+/([a-zA-Z][a-zA-Z0-9._]+)/databases/[^:]+):""",
        RegexOption.MULTILINE
    )

    // Most recent SQL: "  Most recently executed SQL:" followed by indented query lines
    private val recentSqlRegex = Regex(
        """^\s+\d+:\s+(.+)$""",
        RegexOption.MULTILINE
    )

    // The list of "sensitive" database filenames (contacts2.db, mmssms.db, etc.)
    // used to live in this module as a hardcoded Kotlin constant. It has been
    // removed: SIGMA rules in plan 6 match on `db_path` via their own
    // rule-driven pattern list. Telemetry emits every observed pool.

    override suspend fun analyze(sectionText: String, iocResolver: IndicatorResolver): ModuleResult {
        val telemetry = mutableListOf<Map<String, Any?>>()

        // Materialize all pool-header matches once so adjacent-pair boundary
        // lookup is O(1). The previous implementation called
        // `poolHeaderRegex.find(sectionText, poolStart + 1)` inside the
        // `findAll { ... }` loop, which is **O(N²) in section size**: each
        // match re-scanned the whole remainder of the dbinfo section
        // looking for the next header. On a 6.55 MB real-device dbinfo
        // section with ~394 database pools that came to roughly 1.2 GB of
        // regex text scanning and took ~24 seconds of wall time. This
        // rewrite does a single `findAll` pass, then walks the resulting
        // list in linear time — measured ~24 s → ~0.3 s on the same input.
        val allPools = poolHeaderRegex.findAll(sectionText).toList()

        for ((i, match) in allPools.withIndex()) {
            val dbPath = match.groupValues[1]
            val packageName = match.groupValues[2]
            val isIoc = iocResolver.isKnownBadPackage(packageName)

            // Bounded block from end-of-this-header to start-of-next-header
            // (or EOF if this is the last pool).
            val poolStart = match.range.last
            val poolEnd = if (i + 1 < allPools.size) allPools[i + 1].range.first else sectionText.length
            val poolBlock = sectionText.substring(poolStart, poolEnd)

            val sqlSection = poolBlock.indexOf("Most recently executed SQL:")
            val queryCount = if (sqlSection >= 0) {
                recentSqlRegex.findAll(poolBlock, sqlSection).count()
            } else 0

            telemetry.add(mapOf(
                "package_name" to packageName,
                "db_path" to dbPath,
                "recent_query_count" to queryCount,
                "is_ioc" to (isIoc != null),
                "source" to "bugreport_import"
            ))
        }

        return ModuleResult(telemetry = telemetry, telemetryService = "dbinfo_audit")
    }
}
