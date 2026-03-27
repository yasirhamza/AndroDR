package com.androdr.data.repo

import androidx.datastore.core.DataStore
import androidx.datastore.preferences.core.Preferences
import androidx.datastore.preferences.core.booleanPreferencesKey
import androidx.datastore.preferences.core.edit
import androidx.datastore.preferences.core.stringPreferencesKey
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

    /**
     * Custom SIGMA rule repo URLs (newline-separated). Each URL should point to a
     * raw GitHub directory containing a `rules.txt` manifest. Empty = default repo only.
     */
    val customRuleUrls: Flow<String> = dataStore.data
        .map { prefs -> prefs[KEY_CUSTOM_RULE_URLS] ?: "" }

    suspend fun setCustomRuleUrls(value: String) {
        dataStore.edit { it[KEY_CUSTOM_RULE_URLS] = value }
    }

    @Suppress("TooGenericExceptionCaught", "SwallowedException")
    suspend fun getCustomRuleUrlsList(): List<String> =
        customRuleUrls.first()
            .lines()
            .map { it.trim() }
            .filter { isValidRuleUrl(it) }

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

    companion object {
        private val KEY_BLOCKLIST_BLOCK_MODE  = booleanPreferencesKey("blocklist_block_mode")
        private val KEY_DOMAIN_IOC_BLOCK_MODE = booleanPreferencesKey("domain_ioc_block_mode")
        private val KEY_CUSTOM_RULE_URLS = stringPreferencesKey("custom_sigma_rule_urls")
    }
}
