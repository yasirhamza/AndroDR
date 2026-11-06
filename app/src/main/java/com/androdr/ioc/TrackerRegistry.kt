package com.androdr.ioc

import android.content.Context
import android.util.Log
import com.androdr.R
import com.androdr.integrity.ManifestVerifier
import com.androdr.privacy.model.DomainGrammar
import com.androdr.privacy.model.Tracker
import com.androdr.privacy.model.TrackerCategory
import com.androdr.privacy.model.TrackerSet
import dagger.hilt.android.qualifiers.ApplicationContext
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.withContext
import org.snakeyaml.engine.v2.api.Load
import org.snakeyaml.engine.v2.api.LoadSettings
import java.util.concurrent.atomic.AtomicReference
import javax.inject.Inject
import javax.inject.Singleton

/**
 * The tracker-SDK registry (`ioc-data/trackers.yml`, mirrored from Exodus Privacy) behind the
 * privacy scan. The bundled copy (`res/raw/trackers.yml`) is parsed lazily on first use; a
 * hash-verified remote copy replaces it atomically via [refresh] (fail closed, see
 * [IocDataManifest]). Parsing is per-entry tolerant: a bad item drops that item, never the file.
 */
@Singleton
class TrackerRegistry @Inject constructor(
    @ApplicationContext private val context: Context,
    private val manifest: IocDataManifest = IocDataManifest(),
) {
    private val set = AtomicReference<TrackerSet?>(null)
    private val bundledAttempted = Any()
    private var bundledLoaded = false
    private val _available = MutableStateFlow(false)

    /**
     * True once a usable set is held (bundled load or verified refresh); updated by both, so a
     * refresh after a corrupt bundled file turns it true without a restart.
     */
    val available: StateFlow<Boolean> = _available.asStateFlow()

    /**
     * Lazily loads the bundled file on first call, never on construction. null = no usable
     * registry (bundled file corrupt and no verified refresh yet); the privacy scan cannot run.
     */
    fun current(): TrackerSet? {
        set.get()?.let { return it }
        synchronized(bundledAttempted) {
            if (!bundledLoaded) {
                bundledLoaded = true
                loadBundled()?.let { loaded ->
                    // A refresh that landed first wins; never overwrite it with the bundled copy.
                    if (set.compareAndSet(null, loaded)) _available.value = true
                }
            }
        }
        return set.get()
    }

    @Suppress("TooGenericExceptionCaught")
    private fun loadBundled(): TrackerSet? = try {
        val yaml = context.resources.openRawResource(R.raw.trackers).bufferedReader().use { it.readText() }
        parse(yaml).also { if (it == null) Log.w(TAG, "Bundled tracker registry is unusable") }
    } catch (e: Exception) {
        Log.w(TAG, "Failed to load bundled tracker registry: ${e.message}")
        null
    }

    /** Trackers accepted this fetch; 0 = refused or unusable, previous set kept. */
    @Suppress("TooGenericExceptionCaught", "ReturnCount")
    suspend fun refresh(): Int = withContext(Dispatchers.IO) {
        try {
            val yaml = manifest.verified(PATH, MAX_RESPONSE_CHARS) ?: return@withContext 0
            val parsed = parse(yaml)
            if (parsed == null) {
                Log.w(TAG, "Remote tracker registry rejected: unusable")
                return@withContext 0
            }
            set.set(parsed)
            _available.value = true
            Log.i(TAG, "Tracker registry refreshed: ${parsed.size} trackers")
            parsed.size
        } catch (e: Exception) {
            Log.w(TAG, "Tracker registry refresh failed: ${e.message}")
            0
        }
    }

    companion object {
        private const val TAG = "TrackerRegistry"
        const val PATH = "ioc-data/trackers.yml"
        const val MAX_RESPONSE_CHARS = 2_000_000
        const val MIN_TRACKERS = 300
        const val MAX_TRACKERS = 2_000
        const val MAX_HOST_CHARS = TrackerSet.MAX_HOST_CHARS
        private const val SUPPORTED_VERSION = 1
        private const val MAX_ALIASES = 10

        /** null = structurally unusable; per-entry problems drop the entry. */
        @Suppress("TooGenericExceptionCaught", "ReturnCount")
        internal fun parse(yaml: String): TrackerSet? {
            return try {
                val settings = LoadSettings.builder()
                    .setAllowDuplicateKeys(false)
                    .setMaxAliasesForCollections(MAX_ALIASES)
                    .build()
                val doc = Load(settings).loadFromString(yaml) as? Map<*, *> ?: return null
                if ((doc["version"] as? Number)?.toInt() != SUPPORTED_VERSION) return null
                val raw = doc["trackers"] as? List<*> ?: return null
                if (raw.size > MAX_TRACKERS) return null
                val trackers = parseTrackers(raw)
                if (trackers.size < MIN_TRACKERS) return null
                TrackerSet(trackers, ManifestVerifier.sha256(yaml))
            } catch (e: Exception) {
                Log.w(TAG, "Failed to parse tracker registry: ${e.message}")
                null
            } catch (e: StackOverflowError) {
                Log.w(TAG, "Failed to parse tracker registry: nesting too deep (${e.javaClass.simpleName})")
                null
            }
        }

        private fun parseTrackers(raw: List<*>): List<Tracker> {
            var patternsLeft = DomainGrammar.MAX_PATTERNS_TOTAL
            val out = ArrayList<Tracker>(raw.size)
            for (item in raw.filterIsInstance<Map<*, *>>()) {
                val tracker = parseTracker(item, patternsLeft)
                if (tracker != null) {
                    patternsLeft -= tracker.domainPatterns.size
                    out.add(tracker)
                }
            }
            return out
        }

        private fun strings(value: Any?, check: String): List<String> {
            val ok = DomainGrammar.FIELD_CHECKS.getValue(check)
            return (value as? List<*>)?.filterIsInstance<String>()?.filter(ok) ?: emptyList()
        }

        private fun parseTracker(m: Map<*, *>, patternsLeft: Int): Tracker? {
            val id = (m["id"] as? Number)?.toInt()
            val name = (m["name"] as? String)?.takeIf { it.isNotBlank() }
            if (id == null || name == null) return null
            val website = (m["website"] as? String)?.takeIf(DomainGrammar.FIELD_CHECKS.getValue("website")) ?: ""
            // A tracker with no usable category is Uncategorised, which is refused by default; an empty set
            // would never be refused.
            val rawCategories = (m["categories"] as? List<*>)?.filterIsInstance<String>()
                ?.takeIf { it.isNotEmpty() } ?: listOf(TrackerCategory.UNCATEGORISED.label)
            val prefixes = strings(m["code_prefixes"], "prefix")
            val segments = strings(m["code_segments"], "segment")
            val suffixes = strings(m["domain_suffixes"], "suffix")
            val labels = strings(m["domain_labels"], "label")
            val patterns = (m["domain_patterns"] as? List<*>)?.filterIsInstance<String>()
                ?.mapNotNull { DomainGrammar.compilePattern(it) }
                ?.take(minOf(DomainGrammar.MAX_PATTERNS_PER_TRACKER, patternsLeft)) ?: emptyList()
            // excluded_domains is read and ignored.
            if (listOf(prefixes, segments, suffixes, labels, patterns).all { it.isEmpty() }) return null
            return Tracker(
                id = id, name = name, website = website,
                categories = rawCategories.map { TrackerCategory.fromLabel(it) }.toSet(),
                rawCategories = rawCategories,
                codePrefixes = prefixes, codeSegments = segments,
                domainSuffixes = suffixes, domainLabels = labels, domainPatterns = patterns,
            )
        }
    }
}
