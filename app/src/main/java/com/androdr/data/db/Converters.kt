package com.androdr.data.db

import androidx.room.TypeConverter
import com.androdr.data.model.AppRisk
import com.androdr.data.model.DeviceFlag
import kotlinx.serialization.builtins.ListSerializer
import kotlinx.serialization.builtins.serializer
import kotlinx.serialization.json.Json

object Converters {

    private val json = Json { ignoreUnknownKeys = true }

    // ── List<AppRisk> ──────────────────────────────────────────────────────────

    @TypeConverter
    @JvmStatic
    fun fromAppRiskList(value: List<AppRisk>): String =
        json.encodeToString(ListSerializer(AppRisk.serializer()), value)

    @TypeConverter
    @JvmStatic
    fun toAppRiskList(value: String): List<AppRisk> =
        json.decodeFromString(ListSerializer(AppRisk.serializer()), value)

    // ── List<DeviceFlag> ───────────────────────────────────────────────────────

    @TypeConverter
    @JvmStatic
    fun fromDeviceFlagList(value: List<DeviceFlag>): String =
        json.encodeToString(ListSerializer(DeviceFlag.serializer()), value)

    @TypeConverter
    @JvmStatic
    fun toDeviceFlagList(value: String): List<DeviceFlag> =
        json.decodeFromString(ListSerializer(DeviceFlag.serializer()), value)

    // ── List<String> ───────────────────────────────────────────────────────────

    @TypeConverter
    @JvmStatic
    fun fromStringList(value: List<String>): String =
        json.encodeToString(ListSerializer(String.serializer()), value)

    @TypeConverter
    @JvmStatic
    fun toStringList(value: String): List<String> =
        json.decodeFromString(ListSerializer(String.serializer()), value)
}
