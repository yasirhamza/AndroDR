package com.androdr.scanner

import android.content.Context
import android.os.StatFs
import androidx.datastore.preferences.core.PreferenceDataStoreFactory
import com.androdr.data.db.VisibleFact
import com.androdr.data.db.VisibleRow
import com.androdr.data.model.ScanResult
import com.androdr.data.model.TelemetrySource
import com.androdr.data.repo.ScanLock
import com.androdr.data.repo.ScanWriteRepository
import com.androdr.data.repo.TimelineRowDeleter
import com.androdr.data.store.StorageHealthFlag
import com.androdr.data.store.StoragePreflight
import com.androdr.data.store.StoreFixture
import com.androdr.data.store.TelemetryStore
import com.androdr.sigma.SigmaRule
import com.androdr.sigma.SigmaRuleEngine
import com.androdr.sigma.SigmaRuleParser
import com.androdr.sigma.StoreRecord
import io.mockk.every
import io.mockk.mockk
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import java.io.Closeable
import java.io.File
import java.nio.file.Files

/**
 * A [ChunkedScanWriter] over a [StoreFixture] database with three test rules (callers use
 * RobolectricTestRunner). [store] / [repo] may be replaced by spies before [writer] is first used.
 */
internal class WriterFixture(recordSql: Boolean = true) : Closeable {
    val f = StoreFixture(recordSql)
    private val scope = CoroutineScope(Dispatchers.IO + SupervisorJob())
    private val dir: File = Files.createTempDirectory("writer-health").toFile()
    val health = StorageHealthFlag(PreferenceDataStoreFactory.create(scope = scope) { File(dir, "h.preferences_pb") })

    /** Free bytes the [preflight] reports; tests change it mid-session. */
    var freeBytes: Long = 64L shl 30
    private val statFs = mockk<StatFs> { every { availableBytes } answers { this@WriterFixture.freeBytes } }
    val preflight = StoragePreflight { statFs }

    val engine = SigmaRuleEngine(mockk<Context>(relaxed = true)).apply {
        setRemoteRules(listOf(
            rule(DNS_RULE, "dns_monitor", "domain", EVIL_DOMAIN, "high"),
            rule(APP_RULE, "app_scanner", "package_name", EVIL_APP, "critical"),
            rule(SEC_RULE, "security_log", "tag_name", "adb_shell_cmd", "medium"),
        ))
    }

    var store: TelemetryStore = f.store
    var repo: ScanWriteRepository =
        ScanWriteRepository(
            f.db, f.store, TimelineRowDeleter(f.db.forensicTimelineEventDao(), f.store, f.db.signalMemberDao()),
            f.findings,
        )
    val lock = ScanLock()
    val writer by lazy { ChunkedScanWriter(engine, store, repo, f.findings, preflight, health) }

    fun scan(id: Long, source: TelemetrySource = TelemetrySource.LIVE_SCAN) = ScanResult(
        id = id, timestamp = id, bugReportFindings = emptyList(),
        riskySideloadCount = 0, knownMalwareCount = 0, source = source,
    )

    fun visibleFacts(): Long = f.count("SELECT COUNT(*) FROM telemetry_record f WHERE ${VisibleFact.SQL}")
    fun visibleRows(): Long = f.count("SELECT COUNT(*) FROM forensic_timeline r WHERE ${VisibleRow.SQL}")
    fun count(sql: String): Long = f.count(sql)

    /** Every finding of COMPLETE scan [scanId], read back from `scan_finding`. */
    suspend fun findingsOf(scanId: Long) = f.findings.findingsOf(scanId)

    override fun close() {
        f.close()
        scope.cancel()
        dir.deleteRecursively()
    }

    companion object {
        const val DNS_RULE = "androdr-t-dns"
        const val APP_RULE = "androdr-t-app"
        const val SEC_RULE = "androdr-t-sec"
        const val EVIL_DOMAIN = "evil.example"
        const val EVIL_APP = "com.evil"
        const val IMPORT_CAPTURED = 5L

        fun rule(id: String, service: String, field: String, value: String, level: String): SigmaRule =
            SigmaRuleParser.parse(
                """
                    title: Test $id
                    id: $id
                    status: experimental
                    description: Test
                    category: incident
                    logsource:
                        product: androdr
                        service: $service
                    detection:
                        selection:
                            $field: $value
                        condition: selection
                    level: $level
                    tags:
                        - attack.t1437
                    display:
                        category: app_risk
                """.trimIndent()
            )!!

        /** An id-less intrusion-log security line (its key is `"$type ? $time"`). */
        fun securityLine(time: Long = 1_729_600_000_000L, tag: String = "adb_shell_cmd") = StoreRecord(
            mapOf("timestamp" to time, "tag" to 210_001L, "tag_name" to tag, "security_data" to listOf("ls"),
                "source" to "INTRUSION_LOG_IMPORT", "captured_at" to IMPORT_CAPTURED),
            "210001 ? $time",
        )
    }
}
