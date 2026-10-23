package com.androdr.di

import android.content.Context
import android.os.StatFs
import androidx.datastore.core.DataStore
import androidx.datastore.preferences.core.Preferences
import androidx.datastore.preferences.preferencesDataStore
import com.androdr.R
import com.androdr.data.db.AppDatabase
import com.androdr.data.db.EventWatermarkDao
import com.androdr.data.db.RecordBodyDao
import com.androdr.data.db.ScanObservationDao
import com.androdr.data.db.SignalMemberDao
import com.androdr.data.db.TelemetryFactDao
import com.androdr.data.db.TelemetryReadDao
import com.androdr.data.store.EventDisplay
import com.androdr.data.store.StoragePreflight
import com.androdr.data.store.TelemetryDictionaries
import com.androdr.data.store.TelemetryRecordCodec
import dagger.Module
import dagger.Provides
import dagger.hilt.InstallIn
import dagger.hilt.android.qualifiers.ApplicationContext
import dagger.hilt.components.SingletonComponent
import javax.inject.Qualifier
import javax.inject.Singleton

/** The telemetry store's own preferences (kept apart from user settings), e.g. `StoreDirtyFlag`. */
@Qualifier
@Retention(AnnotationRetention.BINARY)
annotation class StoreDataStore

private val Context.storeDataStore: DataStore<Preferences> by preferencesDataStore(name = "androdr_store")

/** Raw resource ids of the Deflate dictionaries, by the names [TelemetryDictionaries] loads. */
internal val DICTIONARY_RESOURCES = mapOf(
    "telemetry_dict_network_v1" to R.raw.telemetry_dict_network_v1,
    "telemetry_dict_dns_v2" to R.raw.telemetry_dict_dns_v2,
    "telemetry_dict_activity_v3" to R.raw.telemetry_dict_activity_v3,
    "telemetry_dict_security_v4" to R.raw.telemetry_dict_security_v4,
)

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

    @Provides
    fun provideTelemetryReadDao(db: AppDatabase): TelemetryReadDao = db.telemetryReadDao()

    @Provides
    @Singleton
    @StoreDataStore
    fun provideStoreDataStore(@ApplicationContext ctx: Context): DataStore<Preferences> = ctx.storeDataStore

    @Provides
    @Singleton
    fun provideTelemetryDictionaries(@ApplicationContext ctx: Context): TelemetryDictionaries =
        TelemetryDictionaries { name ->
            val id = requireNotNull(DICTIONARY_RESOURCES[name]) { "no raw resource for dictionary $name" }
            ctx.resources.openRawResource(id).use { it.readBytes() }
        }

    @Provides
    @Singleton
    fun provideTelemetryRecordCodec(dictionaries: TelemetryDictionaries): TelemetryRecordCodec =
        TelemetryRecordCodec(dictionaries)

    @Provides
    @Singleton
    fun provideEventDisplay(@ApplicationContext ctx: Context): EventDisplay =
        EventDisplay.parse(ctx.resources.openRawResource(R.raw.event_display).bufferedReader().use { it.readText() })

    /** Free space of the partition holding the database (the app's data directory). */
    @Provides
    @Singleton
    fun provideStoragePreflight(@ApplicationContext ctx: Context): StoragePreflight =
        StoragePreflight { StatFs(ctx.filesDir.path) }
}
