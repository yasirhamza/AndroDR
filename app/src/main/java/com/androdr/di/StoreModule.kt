package com.androdr.di

import com.androdr.data.db.AppDatabase
import com.androdr.data.db.EventWatermarkDao
import com.androdr.data.db.RecordBodyDao
import com.androdr.data.db.ScanObservationDao
import com.androdr.data.db.SignalMemberDao
import com.androdr.data.db.TelemetryFactDao
import dagger.Module
import dagger.Provides
import dagger.hilt.InstallIn
import dagger.hilt.components.SingletonComponent

/** Hilt providers for the telemetry store (schema 20+). */
@Module
@InstallIn(SingletonComponent::class)
object StoreModule {

    @Provides
    fun provideRecordBodyDao(db: AppDatabase): RecordBodyDao = db.recordBodyDao()

    @Provides
    fun provideTelemetryFactDao(db: AppDatabase): TelemetryFactDao = db.telemetryFactDao()

    @Provides
    fun provideScanObservationDao(db: AppDatabase): ScanObservationDao = db.scanObservationDao()

    @Provides
    fun provideEventWatermarkDao(db: AppDatabase): EventWatermarkDao = db.eventWatermarkDao()

    @Provides
    fun provideSignalMemberDao(db: AppDatabase): SignalMemberDao = db.signalMemberDao()
}
