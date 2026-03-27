package com.androdr.data.db

import androidx.room.TypeConverter
import com.androdr.sigma.Evidence
import com.androdr.sigma.Finding
import kotlinx.serialization.builtins.ListSerializer
import kotlinx.serialization.builtins.serializer
import kotlinx.serialization.json.Json
import kotlinx.serialization.modules.SerializersModule
import kotlinx.serialization.modules.polymorphic
import kotlinx.serialization.modules.subclass

object Converters {
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

    @TypeConverter @JvmStatic
    fun toFindingList(value: String): List<Finding> =
        json.decodeFromString(ListSerializer(Finding.serializer()), value)

    @TypeConverter @JvmStatic
    fun fromStringList(value: List<String>): String =
        json.encodeToString(ListSerializer(String.serializer()), value)

    @TypeConverter @JvmStatic
    fun toStringList(value: String): List<String> =
        json.decodeFromString(ListSerializer(String.serializer()), value)
}
