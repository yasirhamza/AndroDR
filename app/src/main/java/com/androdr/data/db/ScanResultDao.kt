package com.androdr.data.db

import androidx.room.Dao
import androidx.room.Insert
import androidx.room.Query
import com.androdr.data.model.ScanResult
import kotlinx.coroutines.flow.Flow

@Dao
interface ScanResultDao {

    @Query("SELECT * FROM ScanResult ORDER BY timestamp DESC")
    fun getAllScans(): Flow<List<ScanResult>>

    @Query("SELECT * FROM ScanResult ORDER BY timestamp DESC LIMIT 2")
    suspend fun getLatestTwo(): List<ScanResult>

    @Insert
    suspend fun insert(scan: ScanResult)
}
