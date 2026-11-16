package com.androdr.data.repo

import androidx.datastore.core.DataStore
import androidx.datastore.preferences.core.MutablePreferences
import androidx.datastore.preferences.core.Preferences
import androidx.datastore.preferences.core.booleanPreferencesKey
import androidx.datastore.preferences.core.edit
import androidx.datastore.preferences.core.intPreferencesKey
import androidx.datastore.preferences.core.stringPreferencesKey
import androidx.datastore.preferences.core.stringSetPreferencesKey
import com.androdr.privacy.model.TrackerCategory
import com.androdr.ui.theme.ThemeMode
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.map
import javax.inject.Inject
import javax.inject.Singleton

/**
 * Persists two DNS policy settings in Jetpack DataStore (Preferences):
 *
 * - [blocklistBlockMode]: `true` = NXDOMAIN for static blocklist hits; `false` = detect-only
 * - [domainIocBlockMode]: `true` = NXDOMAIN for IOC domain hits; `false` = detect-only (default)
 */
@Singleton
class SettingsRepository @Inject constructor(
    private val dataStore: DataStore<Preferences>
) {

    val blocklistBlockMode: Flow<Boolean> = dataStore.data
        .map { prefs -> prefs[KEY_BLOCKLIST_BLOCK_MODE] ?: true }

    val domainIocBlockMode: Flow<Boolean> = dataStore.data
        .map { prefs -> prefs[KEY_DOMAIN_IOC_BLOCK_MODE] ?: false }

    suspend fun setBlocklistBlockMode(value: Boolean) {
        dataStore.edit { it[KEY_BLOCKLIST_BLOCK_MODE] = value }
    }

    suspend fun setDomainIocBlockMode(value: Boolean) {
        dataStore.edit { it[KEY_DOMAIN_IOC_BLOCK_MODE] = value }
    }

    val themeMode: Flow<ThemeMode> = dataStore.data
        .map { prefs ->
            when (prefs[KEY_THEME_MODE]) {
                "LIGHT" -> ThemeMode.LIGHT
                "DARK"  -> ThemeMode.DARK
                else    -> ThemeMode.AUTO
            }
        }

    suspend fun setThemeMode(mode: ThemeMode) {
        dataStore.edit { it[KEY_THEME_MODE] = mode.name }
    }

    /**
     * Custom SIGMA rule repo URLs (newline-separated). Each URL should point to a
     * raw GitHub directory containing a `rules.txt` manifest. Empty = default repo only.
     */
    val customRuleUrls: Flow<String> = dataStore.data
        .map { prefs -> prefs[KEY_CUSTOM_RULE_URLS] ?: "" }

    suspend fun setCustomRuleUrls(value: String) {
        dataStore.edit { it[KEY_CUSTOM_RULE_URLS] = value }
    }

    suspend fun getCustomRuleUrlsList(): List<String> =
        customRuleUrls.first()
            .lines()
            .map { it.trim() }
            .filter { isValidRuleUrl(it) }

    // URL validation uses early returns to reject each invalid condition clearly
    @Suppress("ReturnCount", "TooGenericExceptionCaught", "SwallowedException")
    private fun isValidRuleUrl(url: String): Boolean {
        if (url.isBlank()) return false
        return try {
            val uri = java.net.URI(url)
            // Require HTTPS
            if (uri.scheme?.lowercase() != "https") return false
            val host = uri.host ?: return false
            if (host.isEmpty()) return false
            // Block private/reserved IP ranges and localhost
            if (isPrivateOrReservedHost(host)) return false
            true
        } catch (e: Exception) {
            false
        }
    }

    // Checking multiple private/reserved IP ranges requires individual early returns
    @Suppress("ReturnCount")
    private fun isPrivateOrReservedHost(host: String): Boolean {
        val lower = host.lowercase()
        if (lower == "localhost" || lower == "127.0.0.1" || lower == "::1") return true
        if (lower == "0.0.0.0") return true
        // Block cloud metadata service
        if (lower == "169.254.169.254") return true
        // Block private IP ranges (RFC 1918 + link-local) without DNS resolution
        // to avoid DNS rebinding attacks and blocking network calls during validation
        if (lower.startsWith("10.")) return true
        if (lower.startsWith("192.168.")) return true
        if (lower.matches(Regex("""172\.(1[6-9]|2\d|3[01])\..*"""))) return true
        if (lower.startsWith("169.254.")) return true
        if (lower.startsWith("fd") || lower.startsWith("fe80:")) return true
        return false
    }

    /**
     * How many of the newest live scans keep their snapshot telemetry (spec §5.1 Retention); older
     * live scans keep only their events (for 30 days) and pinned facts. Default 20.
     */
    val snapshotRetentionScans: Flow<Int> = dataStore.data
        // Clamped on read too: a stored 0 or below (corrupt store, a writer that skipped the setter)
        // would otherwise trim every live scan's snapshots, the newest included.
        .map { prefs -> (prefs[KEY_SNAPSHOT_RETENTION_SCANS] ?: DEFAULT_SNAPSHOT_RETENTION_SCANS).coerceAtLeast(1) }

    suspend fun setSnapshotRetentionScans(value: Int) {
        require(value >= 1) { "snapshot retention must keep at least one scan" }
        dataStore.edit { it[KEY_SNAPSHOT_RETENTION_SCANS] = value }
    }

    /**
     * Tracker categories the user refuses (the privacy threshold). Default: every category except
     * [TrackerCategory.CRASH_REPORTING] and [TrackerCategory.OTHER], so UNCATEGORISED is refused.
     * Stored by enum name; an unknown stored name is ignored.
     *
     * A saved threshold says nothing about a category the app did not have when it was saved
     * (PROXYWARE, #470, is the first). Such a category counts as it does by default until the
     * person next saves the threshold; from then on their saved choice decides. The categories
     * known at the time of a save are stored with it for this.
     */
    val refusedTrackerCategories: Flow<Set<TrackerCategory>> = dataStore.data.map(::refusedIn)

    suspend fun setRefusedTrackerCategories(value: Set<TrackerCategory>) {
        dataStore.edit { it.saveRefused(value) }
    }

    /**
     * Refuses or accepts one category, starting from what is stored and not from what a screen
     * happened to show: a tap that lands before the screen has read the threshold must not save
     * an empty one over it.
     */
    suspend fun setTrackerCategoryRefused(category: TrackerCategory, refused: Boolean) {
        dataStore.edit {
            val current = refusedIn(it)
            it.saveRefused(if (refused) current + category else current - category)
        }
    }

    /** Whether the privacy views list system apps under Crossing and Other (default false). */
    val privacyShowSystemApps: Flow<Boolean> = dataStore.data
        .map { prefs -> prefs[KEY_PRIVACY_SHOW_SYSTEM] ?: false }

    suspend fun setPrivacyShowSystemApps(value: Boolean) {
        dataStore.edit { it[KEY_PRIVACY_SHOW_SYSTEM] = value }
    }

    suspend fun getEtag(cacheKey: String): String? =
        dataStore.data.first()[stringPreferencesKey("etag_$cacheKey")]

    suspend fun setEtag(cacheKey: String, etag: String?) {
        val key = stringPreferencesKey("etag_$cacheKey")
        dataStore.edit { prefs ->
            if (etag != null) prefs[key] = etag else prefs.remove(key)
        }
    }

    companion object {
        private val KEY_BLOCKLIST_BLOCK_MODE  = booleanPreferencesKey("blocklist_block_mode")
        private val KEY_DOMAIN_IOC_BLOCK_MODE = booleanPreferencesKey("domain_ioc_block_mode")
        private val KEY_CUSTOM_RULE_URLS = stringPreferencesKey("custom_sigma_rule_urls")
        private val KEY_THEME_MODE = stringPreferencesKey("theme_mode")
        private val KEY_SNAPSHOT_RETENTION_SCANS = intPreferencesKey("snapshot_retention_scans")
        const val DEFAULT_SNAPSHOT_RETENTION_SCANS = 20
        private val KEY_PRIVACY_REFUSED = stringSetPreferencesKey("privacy_refused_categories")
        private val KEY_PRIVACY_KNOWN_AT_SAVE = stringSetPreferencesKey("privacy_categories_known_at_save")

        /**
         * The categories of the builds that saved a threshold without the known-at-save set.
         * Closed for good: a category added later must never be added here.
         */
        internal val CATEGORIES_BEFORE_KNOWN_WAS_STORED = setOf(
            "ADVERTISEMENT", "PROFILING", "IDENTIFICATION", "LOCATION", "ANALYTICS",
            "CRASH_REPORTING", "UNCATEGORISED", "OTHER",
        )
        private val KEY_PRIVACY_SHOW_SYSTEM = booleanPreferencesKey("privacy_show_system_apps")
        val DEFAULT_REFUSED_CATEGORIES: Set<TrackerCategory> =
            TrackerCategory.entries.toSet() - TrackerCategory.CRASH_REPORTING - TrackerCategory.OTHER

        private fun refusedIn(prefs: Preferences): Set<TrackerCategory> {
            val stored = prefs[KEY_PRIVACY_REFUSED]
                ?.mapNotNull { n -> TrackerCategory.entries.firstOrNull { it.name == n } }?.toSet()
                ?: return DEFAULT_REFUSED_CATEGORIES
            val knownAtSave = prefs[KEY_PRIVACY_KNOWN_AT_SAVE] ?: CATEGORIES_BEFORE_KNOWN_WAS_STORED
            return stored + DEFAULT_REFUSED_CATEGORIES.filter { it.name !in knownAtSave }
        }

        private fun MutablePreferences.saveRefused(value: Set<TrackerCategory>) {
            this[KEY_PRIVACY_REFUSED] = value.map { c -> c.name }.toSet()
            this[KEY_PRIVACY_KNOWN_AT_SAVE] = TrackerCategory.entries.map { c -> c.name }.toSet()
        }
    }
}
