package com.androdr.scanner.intrusionlog

import android.annotation.SuppressLint
import android.app.admin.SecurityLog

/** Maps android.app.admin.SecurityLog numeric tags to stable snake_case names. */
object SecurityLogTagRegistry {

    // InlinedApi: SecurityLog.TAG_* are compile-time-inlined int constants, so
    // referencing them is runtime-safe on every API level regardless of when
    // each tag was introduced (some post-date minSdk 26). This registry never
    // calls a device SecurityLog API — it only names tags found in imported
    // Advanced Protection Intrusion Logging export files pulled from Android
    // 16+ source devices (#342), so the "requires API level N" warning does
    // not apply to this usage.
    @SuppressLint("InlinedApi")
    private val names: Map<Int, String> = mapOf(
        SecurityLog.TAG_ADB_SHELL_INTERACTIVE to "adb_shell_interactive",
        SecurityLog.TAG_ADB_SHELL_CMD to "adb_shell_cmd",
        SecurityLog.TAG_SYNC_RECV_FILE to "sync_recv_file",
        SecurityLog.TAG_SYNC_SEND_FILE to "sync_send_file",
        SecurityLog.TAG_APP_PROCESS_START to "app_process_start",
        SecurityLog.TAG_KEYGUARD_DISMISSED to "keyguard_dismissed",
        SecurityLog.TAG_KEYGUARD_DISMISS_AUTH_ATTEMPT to "keyguard_dismiss_auth_attempt",
        SecurityLog.TAG_KEYGUARD_SECURED to "keyguard_secured",
        SecurityLog.TAG_OS_STARTUP to "os_startup",
        SecurityLog.TAG_OS_SHUTDOWN to "os_shutdown",
        SecurityLog.TAG_LOGGING_STARTED to "logging_started",
        SecurityLog.TAG_LOGGING_STOPPED to "logging_stopped",
        SecurityLog.TAG_MEDIA_MOUNT to "media_mount",
        SecurityLog.TAG_MEDIA_UNMOUNT to "media_unmount",
        SecurityLog.TAG_LOG_BUFFER_SIZE_CRITICAL to "log_buffer_size_critical",
        SecurityLog.TAG_PASSWORD_EXPIRATION_SET to "password_expiration_set",
        SecurityLog.TAG_PASSWORD_COMPLEXITY_SET to "password_complexity_set",
        SecurityLog.TAG_PASSWORD_HISTORY_LENGTH_SET to "password_history_length_set",
        SecurityLog.TAG_MAX_SCREEN_LOCK_TIMEOUT_SET to "max_screen_lock_timeout_set",
        SecurityLog.TAG_MAX_PASSWORD_ATTEMPTS_SET to "max_password_attempts_set",
        SecurityLog.TAG_KEYGUARD_DISABLED_FEATURES_SET to "keyguard_disabled_features_set",
        SecurityLog.TAG_REMOTE_LOCK to "remote_lock",
        SecurityLog.TAG_WIPE_FAILURE to "wipe_failure",
        SecurityLog.TAG_KEY_GENERATED to "key_generated",
        SecurityLog.TAG_KEY_IMPORT to "key_import",
        SecurityLog.TAG_KEY_DESTRUCTION to "key_destruction",
        SecurityLog.TAG_USER_RESTRICTION_ADDED to "user_restriction_added",
        SecurityLog.TAG_USER_RESTRICTION_REMOVED to "user_restriction_removed",
        SecurityLog.TAG_CERT_AUTHORITY_INSTALLED to "cert_authority_installed",
        SecurityLog.TAG_CERT_AUTHORITY_REMOVED to "cert_authority_removed",
        SecurityLog.TAG_CRYPTO_SELF_TEST_COMPLETED to "crypto_self_test_completed",
        SecurityLog.TAG_KEY_INTEGRITY_VIOLATION to "key_integrity_violation",
        SecurityLog.TAG_CERT_VALIDATION_FAILURE to "cert_validation_failure",
        SecurityLog.TAG_CAMERA_POLICY_SET to "camera_policy_set",
        SecurityLog.TAG_PASSWORD_CHANGED to "password_changed",
        SecurityLog.TAG_WIFI_CONNECTION to "wifi_connection",
        SecurityLog.TAG_WIFI_DISCONNECTION to "wifi_disconnection",
        SecurityLog.TAG_BLUETOOTH_CONNECTION to "bluetooth_connection",
        SecurityLog.TAG_BLUETOOTH_DISCONNECTION to "bluetooth_disconnection",
        SecurityLog.TAG_PACKAGE_INSTALLED to "package_installed",
        SecurityLog.TAG_PACKAGE_UPDATED to "package_updated",
        SecurityLog.TAG_PACKAGE_UNINSTALLED to "package_uninstalled",
    )

    fun nameFor(tag: Int): String = names[tag] ?: "unknown_$tag"

    fun allNames(): Collection<String> = names.values
}
