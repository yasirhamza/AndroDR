package com.androdr.data.db

import androidx.room.Dao
import androidx.room.Insert
import androidx.room.OnConflictStrategy
import androidx.room.Query
import com.androdr.data.model.EventWatermark

@Dao
interface EventWatermarkDao {

    @Query("SELECT * FROM event_watermark WHERE service = :service")
    suspend fun get(service: String): EventWatermark?

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun put(watermark: EventWatermark)
}
