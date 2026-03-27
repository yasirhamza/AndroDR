package com.androdr.data.db

import androidx.room.Dao
import androidx.room.Query
import androidx.room.Upsert
import com.androdr.data.model.CveEntity

@Dao
interface CveDao {
    @Query("SELECT * FROM cve_entries WHERE isActivelyExploited = 1")
    suspend fun getActivelyExploited(): List<CveEntity>

    @Query("SELECT * FROM cve_entries WHERE isActivelyExploited = 1 AND fixedInPatchLevel > :devicePatchLevel")
    suspend fun getUnpatchedCves(devicePatchLevel: String): List<CveEntity>

    @Query("SELECT COUNT(*) FROM cve_entries WHERE isActivelyExploited = 1")
    suspend fun getActivelyExploitedCount(): Int

    @Query("SELECT COUNT(*) FROM cve_entries")
    suspend fun getTotalCount(): Int

    @Upsert
    suspend fun upsertAll(entries: List<CveEntity>)
}
