package com.androdr.data.db

import android.util.Log
import androidx.room.TypeConverter
import com.androdr.data.model.ScannerFailure
import com.androdr.data.model.TelemetrySource
import com.androdr.sigma.Evidence
import com.androdr.sigma.Finding
import kotlinx.serialization.builtins.ListSerializer
import kotlinx.serialization.builtins.serializer
import kotlinx.serialization.json.Json
import kotlinx.serialization.modules.SerializersModule
import kotlinx.serialization.modules.polymorphic
import kotlinx.serialization.modules.subclass

object Converters {
    private const val TAG = "Converters"

    private val module = SerializersModule {
        polymorphic(Evidence::class) {
            subclass(Evidence.None::class)
            subclass(Evidence.CveList::class)
            subclass(Evidence.IocMatch::class)
            subclass(Evidence.PermissionCluster::class)
        }
    }

    private val json = Json {
        ignoreUnknownKeys = true
        serializersModule = module
    }

    @TypeConverter @JvmStatic
    fun fromFindingList(value: List<Finding>): String =
        json.encodeToString(ListSerializer(Finding.serializer()), value)

    @Suppress("TooGenericExceptionCaught")
    @TypeConverter @JvmStatic
    fun toFindingList(value: String): List<Finding> = try {
        json.decodeFromString(ListSerializer(Finding.serializer()), value)
    } catch (e: Exception) {
        Log.w(TAG, "Failed to deserialize findings (pre-migration data?): ${e.javaClass.simpleName}")
        emptyList()
    }

    /** One finding as `scan_finding.findingJson` / `alert.evidenceJson` store it. */
    fun encodeFinding(value: Finding): String = json.encodeToString(Finding.serializer(), value)

    /**
     * A stored finding, or null when it no longer decodes (an unreadable row is skipped, never fatal).
     * [where] names the row by its ids only (e.g. `scan_finding 7 of scan 3`). The failure log carries
     * [where] and the exception's class, never its message: a decode error quotes the JSON input, which
     * can hold package names or domains, and the app log is copied into exported reports.
     */
    @Suppress("TooGenericExceptionCaught")
    fun decodeFinding(value: String, where: String): Finding? = try {
        json.decodeFromString(Finding.serializer(), value)
    } catch (e: Exception) {
        Log.w(TAG, "Failed to deserialize a stored finding ($where): ${e.javaClass.simpleName}")
        null
    }

    @TypeConverter @JvmStatic
    fun fromStringList(value: List<String>): String =
        json.encodeToString(ListSerializer(String.serializer()), value)

    @TypeConverter @JvmStatic
    fun toStringList(value: String): List<String> =
        json.decodeFromString(ListSerializer(String.serializer()), value)

    @TypeConverter @JvmStatic
    fun fromScannerFailureList(value: List<ScannerFailure>): String =
        json.encodeToString(ListSerializer(ScannerFailure.serializer()), value)

    @Suppress("TooGenericExceptionCaught")
    @TypeConverter @JvmStatic
    fun toScannerFailureList(value: String): List<ScannerFailure> = try {
        json.decodeFromString(ListSerializer(ScannerFailure.serializer()), value)
    } catch (e: Exception) {
        Log.w(TAG, "Failed to deserialize scannerErrors: ${e.javaClass.simpleName}")
        emptyList()
    }

    @TypeConverter @JvmStatic
    fun telemetrySourceToString(source: TelemetrySource): String = source.name

    @TypeConverter @JvmStatic
    fun stringToTelemetrySource(value: String): TelemetrySource = try {
        TelemetrySource.valueOf(value)
    } catch (_: IllegalArgumentException) {
        TelemetrySource.LIVE_SCAN
    }
}
