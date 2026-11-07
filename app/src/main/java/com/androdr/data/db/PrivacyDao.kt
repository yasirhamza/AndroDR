package com.androdr.data.db

import androidx.room.Dao
import androidx.room.Insert
import androidx.room.OnConflictStrategy
import androidx.room.Query
import androidx.room.Transaction
import com.androdr.data.model.PrivacyAppResult
import com.androdr.data.model.PrivacyPackageSet
import com.androdr.data.model.PrivacyScan
import com.androdr.data.model.PrivacyTrackerEvidence
import kotlinx.coroutines.flow.Flow

@Suppress("TooManyFunctions") // one method per privacy-store access, as the scan runner and UI need
@Dao
interface PrivacyDao {
    @Insert
    suspend fun insertScan(scan: PrivacyScan): Long

    @Suppress("LongParameterList") // mirrors the columns finalised at scan end
    @Query(
        "UPDATE privacy_scan SET finishedAt = :finishedAt, appsInspected = :inspected, appsPartial = :partial, " +
            "appsFailed = :failed, dnsCoverageDays = :dnsCoverageDays, usageCoverageFrom = :usageFrom, " +
            "networkStatus = :networkStatus WHERE id = :id"
    )
    suspend fun finishScan(
        id: Long, finishedAt: Long, inspected: Int, partial: Int, failed: Int,
        dnsCoverageDays: Int, usageFrom: Long?, networkStatus: String
    )

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun upsertResults(results: List<PrivacyAppResult>)

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun upsertEvidence(evidence: List<PrivacyTrackerEvidence>)

    @Query("SELECT * FROM privacy_scan WHERE id = (SELECT MAX(id) FROM privacy_scan WHERE finishedAt IS NOT NULL)")
    fun latestCompleted(): Flow<PrivacyScan?>

    @Query("SELECT * FROM privacy_scan WHERE id = (SELECT MAX(id) FROM privacy_scan WHERE finishedAt IS NOT NULL)")
    suspend fun latestCompletedOnce(): PrivacyScan?

    @Query("SELECT * FROM privacy_app_result WHERE scanId = :scanId")
    fun results(scanId: Long): Flow<List<PrivacyAppResult>>

    @Query("SELECT * FROM privacy_app_result WHERE scanId = :scanId")
    suspend fun resultsOnce(scanId: Long): List<PrivacyAppResult>

    @Query("SELECT * FROM privacy_tracker_evidence WHERE scanId = :scanId")
    fun evidence(scanId: Long): Flow<List<PrivacyTrackerEvidence>>

    @Query("SELECT * FROM privacy_tracker_evidence WHERE scanId = :scanId")
    suspend fun evidenceOnce(scanId: Long): List<PrivacyTrackerEvidence>

    @Query("SELECT * FROM privacy_package_set WHERE packageName = :pkg")
    suspend fun packageSet(pkg: String): PrivacyPackageSet?

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun upsertPackageSet(row: PrivacyPackageSet)

    @Query("DELETE FROM privacy_package_set WHERE packageName = :pkg")
    suspend fun deletePackageSet(pkg: String)

    /** A subquery, never a bound list: SQLite's 999-variable limit. */
    @Query(
        "DELETE FROM privacy_package_set WHERE packageName NOT IN " +
            "(SELECT packageName FROM privacy_app_result WHERE scanId = :scanId)"
    )
    suspend fun pruneCacheTo(scanId: Long)

    @Query("DELETE FROM privacy_tracker_evidence WHERE scanId < :keepFromId")
    suspend fun deleteEvidenceBefore(keepFromId: Long)

    @Query("DELETE FROM privacy_app_result WHERE scanId < :keepFromId")
    suspend fun deleteResultsBefore(keepFromId: Long)

    @Query("DELETE FROM privacy_scan WHERE id < :keepFromId")
    suspend fun deleteScanRowsBefore(keepFromId: Long)

    @Transaction
    suspend fun deleteScansBefore(keepFromId: Long) {
        deleteEvidenceBefore(keepFromId)
        deleteResultsBefore(keepFromId)
        deleteScanRowsBefore(keepFromId)
    }

    @Query("DELETE FROM privacy_tracker_evidence")
    suspend fun deleteAllEvidence()

    @Query("DELETE FROM privacy_app_result")
    suspend fun deleteAllResults()

    @Query("DELETE FROM privacy_scan")
    suspend fun deleteAllScans()

    @Query("DELETE FROM privacy_package_set")
    suspend fun deleteAllPackageSets()

    @Transaction
    suspend fun deleteAll() {
        deleteAllEvidence()
        deleteAllResults()
        deleteAllScans()
        deleteAllPackageSets()
    }
}
