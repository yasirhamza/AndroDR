package com.androdr.ioc

import android.content.Context
import android.os.Environment
import android.util.Log
import com.androdr.R
import dagger.hilt.android.qualifiers.ApplicationContext
import org.snakeyaml.engine.v2.api.Load
import org.snakeyaml.engine.v2.api.LoadSettings
import javax.inject.Inject
import javax.inject.Singleton

/**
 * Loads the known spyware artifact path list from `res/raw/known_spyware_artifacts.yml`
 * and exposes the resolved paths for [com.androdr.scanner.FileArtifactScanner] to probe.
 *
 * The YAML file is the authoritative source of known spyware file paths — previously
 * hardcoded in `FileArtifactScanner.kt`. Moving to YAML lets the `update-rules` agents
 * add new paths from threat intel feeds without touching Kotlin.
 *
 * Path templates:
 * - `{ext_storage}` is resolved to [Environment.getExternalStorageDirectory].
 *
 * See `docs/superpowers/specs/2026-04-09-unified-telemetry-findings-refactor-design.md`
 * §9 for the full rationale.
 */
@Singleton
class KnownSpywareArtifactsResolver @Inject constructor(
    @ApplicationContext private val context: Context,
) {

    /**
     * Resolved absolute paths for the scanner to probe. Computed lazily on first access;
     * subsequent calls return the cached list.
     */
    val paths: List<String> by lazy { loadAndResolve() }

    @Suppress("TooGenericExceptionCaught")
    private fun loadAndResolve(): List<String> {
        return try {
            val yamlString = context.resources
                .openRawResource(R.raw.known_spyware_artifacts)
                .bufferedReader()
                .use { it.readText() }
            @Suppress("DEPRECATION")
            val extStorage = Environment.getExternalStorageDirectory().absolutePath
            parseAndResolve(yamlString, extStorage)
        } catch (e: Exception) {
            Log.w(TAG, "Failed to load known spyware artifacts: ${e.message}")
            emptyList()
        }
    }

    @Suppress("UNCHECKED_CAST", "TooGenericExceptionCaught")
    internal fun parseAndResolve(yamlContent: String, extStorage: String): List<String> {
        return try {
            val settings = LoadSettings.builder()
                .setAllowDuplicateKeys(false)
                .setMaxAliasesForCollections(10)
                .build()
            val load = Load(settings)
            val doc = load.loadFromString(yamlContent) as? Map<*, *> ?: return emptyList()
            val artifacts = doc["artifacts"] as? List<*> ?: return emptyList()

            artifacts.mapNotNull { entry ->
                val map = entry as? Map<*, *> ?: return@mapNotNull null
                val pathTemplate = map["path"] as? String ?: return@mapNotNull null
                pathTemplate.replace("{ext_storage}", extStorage)
            }
        } catch (e: Exception) {
            Log.w(TAG, "Failed to parse known spyware artifacts YAML: ${e.message}")
            emptyList()
        }
    }

    companion object {
        private const val TAG = "KnownSpywareArtifactsResolver"
    }
}
