package com.androdr.scanner.bugreport

import com.androdr.ioc.IocResolver
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

    private val sensitiveDbPaths = listOf(
        "contacts2.db", "mmssms.db", "telephony.db", "calllog.db",
        "external.db", "calendar.db"
    )

    override suspend fun analyze(sectionText: String, iocResolver: IocResolver): ModuleResult {
        val telemetry = mutableListOf<Map<String, Any?>>()

        poolHeaderRegex.findAll(sectionText).forEach { match ->
            val dbPath = match.groupValues[1]
            val packageName = match.groupValues[2]
            val isIoc = iocResolver.isKnownBadPackage(packageName)
            val isSensitiveDb = sensitiveDbPaths.any { dbPath.endsWith(it) }

            // Extract SQL queries following this pool header
            val poolStart = match.range.last
            val nextPool = poolHeaderRegex.find(sectionText, poolStart + 1)
            val poolEnd = nextPool?.range?.first ?: sectionText.length
            val poolBlock = sectionText.substring(poolStart, poolEnd)

            val sqlSection = poolBlock.indexOf("Most recently executed SQL:")
            val queryCount = if (sqlSection >= 0) {
                recentSqlRegex.findAll(poolBlock, sqlSection).count()
            } else 0

            telemetry.add(mapOf(
                "package_name" to packageName,
                "db_path" to dbPath,
                "is_sensitive_db" to isSensitiveDb,
                "recent_query_count" to queryCount,
                "is_ioc" to (isIoc != null)
            ))
        }

        return ModuleResult(telemetry = telemetry, telemetryService = "dbinfo_audit")
    }
}
