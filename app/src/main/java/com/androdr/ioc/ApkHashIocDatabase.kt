package com.androdr.ioc

import android.content.Context
import android.util.Log
import com.androdr.R
import dagger.hilt.android.qualifiers.ApplicationContext
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import javax.inject.Inject
import javax.inject.Singleton

@Serializable
data class ApkHashInfo(
    val apkHash: String,
    val familyName: String,
    val category: String,
    val severity: String,
    val description: String
)

@Singleton
class ApkHashIocDatabase @Inject constructor(
    @ApplicationContext private val context: Context
) {
    private val json = Json { ignoreUnknownKeys = true }

    private val hashList: List<ApkHashInfo> by lazy {
        val raw = context.resources
            .openRawResource(R.raw.known_bad_apk_hashes)
            .bufferedReader()
            .use { it.readText() }
        json.decodeFromString(raw)
    }

    private val hashMap: HashMap<String, ApkHashInfo> by lazy {
        HashMap<String, ApkHashInfo>(hashList.size * 2).also { map ->
            hashList.forEach { entry -> map[entry.apkHash.lowercase()] = entry }
        }
    }

    fun isKnownBadApkHash(hash: String): ApkHashInfo? =
        hashMap[hash.lowercase()]

    fun getAllBadHashes(): List<ApkHashInfo> = hashList
}
