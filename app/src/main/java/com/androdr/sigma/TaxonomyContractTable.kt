package com.androdr.sigma

/**
 * The taxonomy facts [TaxonomyContract] mirrors, one entry per service of
 * `logsource-taxonomy.yml`, in taxonomy order. Field descriptions are verbatim.
 *
 * Edit together with the taxonomy: TaxonomyContractTest compares every entry
 * with the pinned submodule in both directions.
 */
internal val TAXONOMY_CONTRACT_TABLE: Map<String, ServiceContract> = linkedMapOf(
    "app_scanner" to ServiceContract(
        keyFields = listOf("package_name"),
        packageField = "package_name",
        fields = listOf(
            "package_name" to "Android package name (e.g., com.example.app)",
            "app_name" to "User-visible app label",
            "cert_hash" to "SHA-256 of signing certificate",
            "cert_hash_sha1" to
                "SHA-1 of signing certificate — required to match community feeds " +
                "(stalkerware-indicators, MVT) that index cert IOCs by SHA-1, per the Android " +
                "ecosystem convention (apksigner --print-certs)",
            "apk_hash" to "SHA-256 of APK file",
            "is_system_app" to "True if app is in /system partition",
            "from_trusted_store" to "True if installed from Play Store or other trusted source",
            "installer" to "Package name of the installer (e.g., com.android.vending)",
            "is_sideloaded" to "True if installed outside trusted stores",
            "is_known_oem_app" to "True if package matches known OEM prefix list",
            "permissions" to
                "Curated security-relevant SHORT-NAME subset (surveillance + high-risk sets from " +
                "AppScanner.EXPOSED_PERMISSION_SHORT_NAMES) — NOT the full requested list. FROZEN " +
                "compat surface for shipped fleet rules; new rules match requested_permissions " +
                "instead",
            "requested_permissions" to
                "EVERY permission the app requests, verbatim fully-qualified names, zero curation " +
                "(emitter-emits-all-facts). Prefer this over the frozen curated short-name subset in " +
                "`permissions` for new rules. MATCHING DISCIPLINE (validate-rule.py enforces): exact " +
                "element-wise equals ONLY — bare key or |all combiner, never |contains/|startswith " +
                "(android.permission.NFC is a substring of android.permission.NFC_TRANSACTION_EVENT; " +
                "substring matching WILL false-positive). FLEET SAFETY — POSITIVE REFERENCES ONLY: " +
                "emitted by app builds after AndroDR #317; older builds have NO unknown-field skip " +
                "floor — a matcher on the missing field evaluates false, which no-ops positive " +
                "selections but INVERTS under `not`, over-firing the old fleet. Never reference this " +
                "field in a negated filter until the fleet floor covers the emitter (validate-rule.py " +
                "rejects it)",
            "surveillance_permission_count" to
                "Count of surveillance-related permissions (camera, mic, location, SMS, etc.)",
            "has_accessibility_service" to "True if app declares an accessibility service",
            "has_device_admin" to "True if app declares a device admin receiver",
            "has_boot_receiver" to
                "True if the app has a receiver registered for BOOT_COMPLETED or " +
                "LOCKED_BOOT_COMPLETED (via queryBroadcastReceivers). FLEET SAFETY — POSITIVE " +
                "REFERENCES ONLY: emitted by app builds after AndroDR #331; on older builds a matcher " +
                "on this field evaluates false, which no-ops positive selections but INVERTS under " +
                "`not`, over-firing the old fleet. Never reference this field in a negated filter " +
                "until the fleet floor covers the emitter (AndroDR #331)",
            "known_app_category" to "Category from known-good apps DB (e.g., SOCIAL, PRODUCTIVITY)",
            "service_permissions" to "Permissions declared on exported services",
            "receiver_permissions" to "Permissions declared on broadcast receivers",
            "has_launcher_activity" to "True if app has a launcher-visible activity",
            "first_install_time" to "Epoch ms of first install (0 = unknown)",
            "last_update_time" to "Epoch ms of last update (0 = unknown)",
            "embedded_component_class" to
                "Class names from manifest services/receivers/activities/providers; deduplicated; " +
                "capped per app. Used by embedded-SDK fingerprinting rules (AndroDR #168).",
            "embedded_native_lib" to
                "Filenames of lib/*/*.so entries inside the APK, ABI prefix stripped; deduplicated; " +
                "capped per app. Used by embedded-SDK fingerprinting rules (AndroDR #168).",
            "webapk_scope" to
                "WebAPK web scope URL from shell-manifest meta-data " +
                "org.chromium.webapk.shell_apk.scope. Null for packages WITHOUT the " +
                "org.chromium.webapk prefix. ATTACKER-CONTROLLED: any app may adopt that prefix and " +
                "self-declare this value, so it is NOT proof of a genuine mint — treat like app_name, " +
                "never as trust (AndroDR #299)",
        ),
    ),
    "device_auditor" to ServiceContract(
        keyFields = listOf("check_id"),
        fields = listOf(
            "check_id" to "Identifier for the specific device check",
            "is_triggered" to "True if the check found an issue",
            "adb_enabled" to "USB debugging enabled",
            "dev_options_enabled" to "Developer options enabled",
            "unknown_sources_enabled" to "Install from unknown sources enabled",
            "screen_lock_enabled" to "Screen lock is configured",
            "patch_level" to "Android security patch level (YYYY-MM-DD)",
            "patch_age_days" to "Days since last security patch",
            "bootloader_unlocked" to "Bootloader is unlocked",
            "wifi_adb_enabled" to "Wireless ADB debugging enabled",
            "unpatched_cve_count" to "Number of unpatched CVEs for this patch level",
            "unpatched_cves" to "List of CveEntity objects",
            "unpatched_cve_id" to "Comma-joined CVE IDs (derived field, not a constructor param)",
        ),
    ),
    "dns_monitor" to ServiceContract(
        eventTimeField = "timestamp",
        packageField = "source_package",
        fields = listOf(
            "domain" to "Queried domain name",
            "app_uid" to "UID of the app that made the DNS query",
            "source_package" to "Package name of querying app (key differs from property appName)",
            "resolved_ips" to
                "IP addresses the DNS response resolved to (strings). Absent when the query was " +
                "blocked or unanswered. Emitted by app builds after the telemetry-store change; older " +
                "binaries never set it. FLEET SAFETY — POSITIVE REFERENCES ONLY: old builds never " +
                "emit this field, so a matcher on it evaluates false there, which no-ops positive " +
                "selections but INVERTS under `not`, over-firing the old fleet. Never reference it in " +
                "a negated filter until the fleet floor covers the emitter (validate-rule.py rejects " +
                "it)",
            "is_blocked" to "True if DNS response was replaced with NXDOMAIN",
            "reason" to "Reason for blocking (blocklist match, etc.)",
            "timestamp" to
                "When the query was observed (epoch ms). Emitted only by app builds newer than " +
                "0.9.0.656 (the last release without it); older binaries never set it. FLEET SAFETY — " +
                "POSITIVE REFERENCES ONLY: on builds up to 0.9.0.656 a matcher on this field " +
                "evaluates false, which no-ops positive selections but INVERTS under `not`, " +
                "over-firing the old fleet. Never reference this field in a negated filter until the " +
                "fleet floor covers the emitter (validate-rule.py rejects it)",
        ),
    ),
    "process_monitor" to ServiceContract(
        keyFields = listOf("process_uid", "process_name"),
        packageField = "package_name",
        fields = listOf(
            "process_name" to "Process name from /proc",
            "process_uid" to "Linux UID of the process",
            "package_name" to "Android package name if resolvable",
            "is_foreground" to "True if process is in foreground",
        ),
    ),
    "file_scanner" to ServiceContract(
        keyFields = listOf("file_path"),
        fields = listOf(
            "file_path" to "Absolute path to the file",
            "file_exists" to "True if the file exists at scan time",
            "file_size" to "File size in bytes",
            "file_modified" to "Last modified timestamp (epoch ms)",
            "accessible" to
                "True when the scanner could stat the path (distinguishes absent from unreadable). " +
                "Emitted by app builds after the telemetry-store change. FLEET SAFETY — POSITIVE " +
                "REFERENCES ONLY: old builds never emit this field, so a matcher on it evaluates " +
                "false there, which no-ops positive selections but INVERTS under `not`, over-firing " +
                "the old fleet. Never reference it in a negated filter until the fleet floor covers " +
                "the emitter (validate-rule.py rejects it)",
        ),
    ),
    "receiver_audit" to ServiceContract(
        keyFields = listOf("package_name", "component_name", "intent_action"),
        packageField = "package_name",
        fields = listOf(
            "package_name" to "Package declaring the receiver",
            "intent_action" to "Intent action the receiver listens for",
            "component_name" to "Fully qualified receiver class name",
            "is_system_app" to "True if declaring app is a system app",
        ),
    ),
    "accessibility_audit" to ServiceContract(
        keyFields = listOf("package_name", "service_name"),
        packageField = "package_name",
        fields = listOf(
            "package_name" to "Package declaring the accessibility service",
            "service_name" to "Fully qualified service class name",
            "is_system_app" to "True if declaring app is a system app",
            "is_enabled" to "True if the service is currently enabled",
        ),
    ),
    "appops_audit" to ServiceContract(
        eventTimeField = "event_time_ms",
        keyFields = listOf("package_name", "operation"),
        packageField = "package_name",
        fields = listOf(
            "package_name" to "Package the operation belongs to",
            "operation" to "AppOps operation name (e.g., android:camera)",
            "last_access_time" to "Epoch ms of last access",
            "last_reject_time" to "Epoch ms of last rejection",
            "access_count" to "Total access count",
            "is_system_app" to "True if app is a system app",
            "event_time_ms" to
                "Epoch ms of the individual access event, set by the bug-report AppOps module only " +
                "when the dumpsys line carries a real timestamp (0 when it does not). Live scans " +
                "never set it. OPTIONAL: only some producers set it, and optional implies " +
                "positive-only. FLEET SAFETY — POSITIVE REFERENCES ONLY: old builds never emit this " +
                "field, so a matcher on it evaluates false there, which no-ops positive selections " +
                "but INVERTS under `not`, over-firing the old fleet. Never reference it in a negated " +
                "filter until the fleet floor covers the emitter (validate-rule.py rejects it)",
        ),
    ),
    "network_monitor" to ServiceContract(
        eventTimeField = "timestamp",
        packageField = "app_name",
        fields = listOf(
            "destination_ip" to "Destination IP address",
            "destination_port" to "Destination port number",
            "protocol" to
                "Protocol (TCP/UDP); null for Intrusion Logging imports, where the source genuinely " +
                "does not record it",
            "app_uid" to "UID of the app making the connection (-1 if unresolvable)",
            "app_name" to
                "Package name of the connecting app (hint, not identity — shared-UID components " +
                "smear)",
            "timestamp" to "Connection timestamp (epoch ms)",
            "source" to "TelemetrySource enum name (INTRUSION_LOG_IMPORT for imported logs)",
            "captured_at" to "When this telemetry was captured/imported (epoch ms)",
        ),
    ),
    "tombstone_parser" to ServiceContract(
        eventTimeField = "crash_timestamp",
        packageField = "package_name",
        fields = listOf(
            "process_name" to "Crashed process name",
            "package_name" to "Package name if resolvable",
            "signal_number" to "Signal that caused the crash",
            "abort_message" to "Abort message from the crash",
            "crash_timestamp" to "When the crash occurred (epoch ms)",
            "source" to "TelemetrySource enum name (LIVE_SCAN or BUGREPORT_IMPORT)",
            "captured_at" to "When this telemetry was captured (epoch ms)",
        ),
    ),
    "wakelock_parser" to ServiceContract(
        eventTimeField = "acquired_at",
        packageField = "package_name",
        fields = listOf(
            "package_name" to "Package holding the wakelock",
            "wakelock_tag" to "Wakelock tag string",
            "acquired_at" to "When the wakelock was acquired (epoch ms)",
            "duration_millis" to "How long the wakelock was held",
            "source" to "TelemetrySource enum name",
            "captured_at" to "When this telemetry was captured (epoch ms)",
        ),
    ),
    "battery_daily" to ServiceContract(
        eventTimeField = "timestamp",
        precisionField = "timestamp_precision",
        packageField = "package_name",
        fields = listOf(
            "day_index" to "Day offset in the battery stats history",
            "version" to
                "Package version string parsed from the battery-stats entry, when present. OPTIONAL: " +
                "set only by the bug-report BatteryDailyModule's generic record, not by the typed " +
                "BatteryDailyEvent; optional implies positive-only (never reference it under `not`)",
            "event_type" to "Battery event type",
            "package_name" to "Package associated with the event",
            "description" to "Human-readable event description",
            "timestamp" to
                "Epoch ms of the event, at day precision (see timestamp_precision). Present only when " +
                "the battery-stats section yields a date. FLEET SAFETY — POSITIVE REFERENCES ONLY: " +
                "old builds never emit this field, so a matcher on it evaluates false there, which " +
                "no-ops positive selections but INVERTS under `not`, over-firing the old fleet. Never " +
                "reference it in a negated filter until the fleet floor covers the emitter " +
                "(validate-rule.py rejects it)",
            "timestamp_precision" to
                "Precision of timestamp; currently always `day`. FLEET SAFETY — POSITIVE REFERENCES " +
                "ONLY: old builds never emit this field, so a matcher on it evaluates false there, " +
                "which no-ops positive selections but INVERTS under `not`, over-firing the old fleet. " +
                "Never reference it in a negated filter until the fleet floor covers the emitter " +
                "(validate-rule.py rejects it)",
            "source" to "TelemetrySource enum name",
            "captured_at" to "When this telemetry was captured (epoch ms)",
        ),
    ),
    "package_install_history" to ServiceContract(
        eventTimeField = "timestamp",
        packageField = "package_name",
        fields = listOf(
            "package_name" to "Installed/updated/uninstalled package name",
            "event_type" to "INSTALL, UNINSTALL, or UPDATE",
            "timestamp" to "When the event occurred (epoch ms)",
            "version_code" to "Version code at time of event",
            "source" to "TelemetrySource enum name",
            "captured_at" to "When this telemetry was captured (epoch ms)",
        ),
    ),
    "platform_compat" to ServiceContract(
        keyFields = listOf("package_name", "change_id"),
        packageField = "package_name",
        fields = listOf(
            "change_id" to "Platform compatibility change ID",
            "package_name" to "Package affected by the change",
            "enabled" to "Whether the compat change is enabled",
            "is_ioc" to
                "True if the package matched a known-bad package IOC at parse time. OPTIONAL: set " +
                "only by the bug-report PlatformCompatModule record, not by the typed " +
                "PlatformCompatChange; optional implies positive-only (never reference it under " +
                "`not`)",
            "source" to "TelemetrySource enum name",
            "captured_at" to "When this telemetry was captured (epoch ms)",
        ),
    ),
    "db_info" to ServiceContract(
        keyFields = listOf("package_name", "file_path"),
        packageField = "package_name",
        fields = listOf(
            "file_path" to "Absolute path to the database file",
            "process_name" to "Process that owns the database",
            "package_name" to "Package that owns the database",
            "observation_timestamp" to "When the database was observed (epoch ms)",
            "db_path" to
                "Database path as referenced in the bug report (typed DatabasePathObservation " +
                "record). FLEET SAFETY — POSITIVE REFERENCES ONLY: old builds never emit this field, " +
                "so a matcher on it evaluates false there, which no-ops positive selections but " +
                "INVERTS under `not`, over-firing the old fleet. Never reference it in a negated " +
                "filter until the fleet floor covers the emitter (validate-rule.py rejects it)",
            "is_ioc" to
                "True if the package matched a known-bad package IOC at parse time. OPTIONAL: set " +
                "only by the bug-report DbInfoModule record, not by the typed " +
                "DatabasePathObservation; optional implies positive-only (never reference it under " +
                "`not`)",
            "recent_query_count" to
                "Recent query count parsed from the dbinfo section for this database. FLEET SAFETY — " +
                "POSITIVE REFERENCES ONLY: old builds never emit this field, so a matcher on it " +
                "evaluates false there, which no-ops positive selections but INVERTS under `not`, " +
                "over-firing the old fleet. Never reference it in a negated filter until the fleet " +
                "floor covers the emitter (validate-rule.py rejects it)",
            "source" to "TelemetrySource enum name",
            "captured_at" to "When this telemetry was captured (epoch ms)",
        ),
    ),
    "security_log" to ServiceContract(
        eventTimeField = "timestamp",
        fields = listOf(
            "timestamp" to "Event time (epoch ms)",
            "tag" to "Numeric android.app.admin.SecurityLog tag",
            "tag_name" to "Registry-resolved tag name (e.g. adb_shell_cmd); unknown_<tag> for unmapped tags",
            "security_data" to
                "Tag-specific value array, emitted verbatim as strings (emitter-emits-all-facts; " +
                "typed per-tag extraction deferred until real fixtures validate layouts — spec §11.1)",
            "source" to "TelemetrySource enum name",
            "captured_at" to "When this telemetry was captured/imported (epoch ms)",
        ),
    ),
    "timeline" to ServiceContract(
        fields = listOf(
            "category" to
                "Timeline event category an atom rule binds to (e.g. app_foreground, package_install, " +
                "ioc_match). BINDING PRECONDITIONS (SigmaRuleEngine.computeAtomBindings / " +
                "extractAtomCategory): matched by EXACT EQUALITY only; the atom must be enabled and " +
                "level: informational; the detection selection must be literally named 'selection'; " +
                "only the FIRST value of the matcher binds. An atom violating name/level/enabled " +
                "NEVER binds; a |modifier on this field is silently IGNORED — the atom still binds by " +
                "exact equality on the first value (dead only if that value is not an exact category " +
                "literal, silently wrong-semantics otherwise).",
        ),
    ),
    "usage_stats" to ServiceContract(
        eventTimeField = "timestamp",
        packageField = "package_name",
        fields = listOf(
            "timestamp" to "When the foreground/background transition occurred (epoch ms)",
            "package_name" to "Package that moved to or from the foreground",
            "app_name" to "User-visible app label (falls back to the package name)",
            "event_type" to "Timeline category of the transition (app_foreground or app_background)",
            "source" to "TelemetrySource enum name",
            "captured_at" to "When this telemetry was captured (epoch ms)",
        ),
    ),
    "system_property" to ServiceContract(
        keyFields = listOf("key"),
        fields = listOf(
            "key" to "System property key (e.g. ro.boot.verifiedbootstate)",
            "value" to "System property value at snapshot time",
            "source" to "TelemetrySource enum name",
            "captured_at" to "When this telemetry was captured (epoch ms)",
        ),
    ),
    "adb_audit" to ServiceContract(
        keyFields = listOf("key_fragment", "host"),
        fields = listOf(
            "key_fragment" to "Truncated fragment of the trusted ADB public key",
            "host" to "Host label (user@machine) recorded in the trusted-key entry",
            "source" to "Record provenance (adb_trusted_key)",
        ),
    ),
    "activity_audit" to ServiceContract(
        keyFields = listOf("package_name", "component_name", "handled_scheme"),
        packageField = "package_name",
        fields = listOf(
            "package_name" to "Package declaring the activity",
            "handled_scheme" to "URI scheme the activity handles (colon stripped)",
            "component_name" to "Fully qualified activity component",
            "is_system_app" to "True if the declaring app is a system app",
            "is_ioc" to "True if the scheme matched an IOC at parse time",
            "source" to "Record provenance (bugreport_import)",
        ),
    ),
)
