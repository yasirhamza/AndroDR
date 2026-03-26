package com.androdr.ioc

import android.content.Context
import com.androdr.R
import dagger.hilt.android.qualifiers.ApplicationContext
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import javax.inject.Inject
import javax.inject.Singleton

@Serializable
data class CertHashInfo(
    val certHash: String,
    val familyName: String,
    val category: String,
    val severity: String,
    val description: String
)

@Singleton
class CertHashIocDatabase @Inject constructor(
    @ApplicationContext private val context: Context
) {
    private val json = Json { ignoreUnknownKeys = true }

    private val certHashList: List<CertHashInfo> by lazy {
        val raw = context.resources
            .openRawResource(R.raw.known_bad_certs)
            .bufferedReader()
            .use { it.readText() }
        json.decodeFromString(raw)
    }

    private val certHashMap: HashMap<String, CertHashInfo> by lazy {
        HashMap<String, CertHashInfo>(certHashList.size * 2).also { map ->
            certHashList.forEach { entry -> map[entry.certHash] = entry }
        }
    }

    fun isKnownBadCert(certHash: String): CertHashInfo? =
        certHashMap[certHash.lowercase()]

    fun getAllBadCerts(): List<CertHashInfo> = certHashList
}
