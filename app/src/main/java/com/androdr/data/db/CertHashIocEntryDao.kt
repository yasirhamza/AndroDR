package com.androdr.data.db

import androidx.room.Dao
import androidx.room.Insert
import androidx.room.OnConflictStrategy
import androidx.room.Query
import com.androdr.data.model.CertHashIocEntry

@Dao
interface CertHashIocEntryDao {
    @Query("SELECT * FROM cert_hash_ioc_entries WHERE certHash = :certHash LIMIT 1")
    suspend fun getByCertHash(certHash: String): CertHashIocEntry?

    @Query("SELECT * FROM cert_hash_ioc_entries")
    suspend fun getAll(): List<CertHashIocEntry>

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun upsertAll(entries: List<CertHashIocEntry>)

    @Query("SELECT COUNT(*) FROM cert_hash_ioc_entries")
    suspend fun count(): Int

    @Query("SELECT MAX(fetchedAt) FROM cert_hash_ioc_entries WHERE source = :source")
    suspend fun lastFetchTime(source: String): Long?

    @Query("SELECT MAX(fetchedAt) FROM cert_hash_ioc_entries")
    suspend fun mostRecentFetchTime(): Long?

    @Query("DELETE FROM cert_hash_ioc_entries WHERE source = :source AND fetchedAt < :olderThan")
    suspend fun deleteStaleEntries(source: String, olderThan: Long)
}
