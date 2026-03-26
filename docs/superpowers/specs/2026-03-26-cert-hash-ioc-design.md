# APK Certificate Hash IOC Matching — Design Spec

## Goal

Detect malware by matching the SHA-256 hash of an installed app's signing certificate against a known-bad cert hash IOC database. This catches malware family variants that change package names but reuse the same signing key.

## Motivation

Adversary simulation testing (2026-03-26) showed that MalwareBazaar commodity malware uses random package names (`com.cave.series`, `com.appser.verapp`, `com.app.applaunch1234`) that aren't in the IOC database. Package name matching only works for well-known stalkerware. Signing certificate hashes are stable across repackages — one cert hash covers an entire malware family.

---

## Architecture

Follows the `DomainIocEntry` pattern: separate Room entity, DAO, resolver, updater, feed interface.

```
CertHashIocEntry (Room entity)
    ↕
CertHashIocEntryDao (Room DAO)
    ↕
CertHashIocResolver (in-memory cache + bundled fallback)
    ↕
AppScanner (extracts cert hash, checks resolver)

CertHashIocFeed (interface)
    ↑
MalwareBazaarCertFeed (implementation)
    ↕
CertHashIocUpdater (orchestrates feeds, upserts to Room)
    ↕
IocUpdateWorker (triggers updater periodically)
```

---

## Components

### 1. `CertHashIocEntry` (Room entity)

Table: `cert_hash_ioc_entries`

| Column | Type | Description |
|--------|------|-------------|
| `certHash` (PK) | String | SHA-256 of signing cert, lowercase hex, no colons (64 chars) |
| `familyName` | String | Malware family name (e.g. "Cerberus", "SpyNote") |
| `category` | String | Category (e.g. "BANKER", "RAT", "STALKERWARE") |
| `severity` | String | Severity level ("CRITICAL", "HIGH") |
| `description` | String | Human-readable description |
| `source` | String | Feed source ID |
| `fetchedAt` | Long | Epoch millis of last fetch |

File: `app/src/main/java/com/androdr/data/model/CertHashIocEntry.kt`

### 2. `CertHashIocEntryDao` (Room DAO)

Methods (all `suspend`):
- `getByCertHash(certHash: String): CertHashIocEntry?`
- `getAll(): List<CertHashIocEntry>`
- `upsertAll(entries: List<CertHashIocEntry>)`
- `count(): Int`
- `lastFetchTime(source: String): Long?`
- `mostRecentFetchTime(): Long?` — global latest fetch (used by DashboardViewModel)
- `deleteStaleEntries(source: String, olderThan: Long)`

File: `app/src/main/java/com/androdr/data/db/CertHashIocEntryDao.kt`

### 3. `CertHashIocResolver` (lookup engine)

- `@Singleton`, injected via Hilt
- In-memory cache: `AtomicReference<Map<String, CertHashIocEntry>>`
- Two-tier lookup: Room cache → bundled `CertHashIocDatabase` fallback
- `isKnownBadCert(certHash: String): CertHashIocEntry?` — synchronous
- `refreshCache()` — loads all Room entries into memory
- `suspend fun remoteEntryCount(): Int` — delegates to DAO `count()`, must be suspend

File: `app/src/main/java/com/androdr/ioc/CertHashIocResolver.kt`

### 4. `CertHashIocDatabase` (bundled data)

- Loads `R.raw.known_bad_certs` (JSON) lazily
- Provides `isKnownBadCert(certHash): CertHashInfo?` for offline fallback
- Data class: `CertHashInfo(certHash, familyName, category, severity, description)`

File: `app/src/main/java/com/androdr/ioc/CertHashIocDatabase.kt`

### 5. Bundled data: `app/src/main/res/raw/known_bad_certs.json`

Source-tree location: `iocs/known_bad_certs.json` (copied to `res/raw/` during build, same pattern as `known_bad_packages.json`).

JSON array of known-bad signing cert hashes. Seeded from MalwareBazaar samples tested during adversary simulation:

```json
[
  {
    "certHash": "<sha256>",
    "familyName": "Cerberus",
    "category": "BANKER",
    "severity": "CRITICAL",
    "description": "Cerberus Android banking trojan signing certificate"
  }
]
```

Initial entries sourced by extracting signing certs from the pinned MalwareBazaar samples in `test-adversary/manifest.yml` (Cerberus, SpyNote, Anubis, BRATA, Hydra, Vultur, TheTruthSpy, TiSpy). Use `keytool -printcert -jarfile <apk>` or Android `PackageInfo.signingInfo` to extract.

### 6. `CertHashIocFeed` (feed interface)

```kotlin
interface CertHashIocFeed {
    val sourceId: String
    suspend fun fetch(): List<CertHashIocEntry>
}
```

File: `app/src/main/java/com/androdr/ioc/CertHashIocFeed.kt`

### 7. `MalwareBazaarCertFeed` (feed implementation)

- Queries MalwareBazaar API for Android malware signing certificate info
- `MALWAREBAZAAR_API_KEY` is **strictly optional** — the feed returns an empty list if not configured. The project compiles and runs fully offline without any API keys (per CLAUDE.md). The bundled `known_bad_certs.json` provides baseline detection without this feed.
- Source ID: `"malwarebazaar_certs"`

**API approach:** MalwareBazaar doesn't have a direct "list all cert hashes" endpoint. Instead:
- Query by tag (`get_taginfo&tag=<family>&limit=100`) for each tracked family
- For each returned sample, the response includes `signature` field with cert info
- Extract and deduplicate cert SHA-256 hashes per family
- Tracked families: Cerberus, SpyNote, Anubis, BRATA, Hydra, Vultur, stalkerware
- If API key is not set, skip silently — no crash, no error log, just empty list

File: `app/src/main/java/com/androdr/ioc/feeds/MalwareBazaarCertFeed.kt`

### 8. `CertHashIocUpdater`

- `@Singleton`, Mutex-guarded
- Runs all `CertHashIocFeed` implementations in parallel
- Upserts results to Room, prunes stale entries
- Refreshes `CertHashIocResolver` cache after update

File: `app/src/main/java/com/androdr/ioc/CertHashIocUpdater.kt`

### 9. `AppScanner` changes

After the existing package name IOC check (line ~130), add cert hash check:

```kotlin
// ── 1b. Cert hash IOC check ─────────────────────────────────
val certHash = extractCertHash(packageInfo)
if (certHash != null) {
    val certHit = certHashIocResolver.isKnownBadCert(certHash)
    if (certHit != null) {
        isKnownMalware = true
        val newLevel = RiskLevel.CRITICAL
        if (newLevel.score > riskLevel.score) riskLevel = newLevel
        reasons.add("Known malicious signing certificate (${certHit.familyName})")
    }
}
```

**`extractCertHash()` implementation:**
```kotlin
private fun extractCertHash(packageInfo: PackageInfo): String? {
    val signatures = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
        packageInfo.signingInfo?.apkContentsSigners
    } else {
        @Suppress("DEPRECATION")
        packageInfo.signatures
    }
    val cert = signatures?.firstOrNull() ?: return null
    val digest = MessageDigest.getInstance("SHA-256")
    return digest.digest(cert.toByteArray()).joinToString("") { "%02x".format(it) }
}
```

**PackageManager flag change:** The scan call must add `GET_SIGNING_CERTIFICATES` (API 28+) or `GET_SIGNATURES` (deprecated) to retrieve signing info:
```kotlin
val flags = PackageManager.GET_PERMISSIONS or
    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P)
        PackageManager.GET_SIGNING_CERTIFICATES
    else
        @Suppress("DEPRECATION") PackageManager.GET_SIGNATURES
```

**Performance/compatibility note:** Adding `GET_SIGNING_CERTIFICATES` increases the data returned per package. Some OEMs may behave unexpectedly with combined flags. Wrap the `getInstalledPackages(flags)` call in a try/catch — if it fails with the signing flag, fall back to `GET_PERMISSIONS` only and skip cert hash checking for that scan. This matches the existing error handling pattern at the top of `scan()`.

File: `app/src/main/java/com/androdr/scanner/AppScanner.kt`

### 10. Room migration 4→5

```sql
CREATE TABLE IF NOT EXISTS cert_hash_ioc_entries (
    certHash TEXT NOT NULL PRIMARY KEY,
    familyName TEXT NOT NULL,
    category TEXT NOT NULL,
    severity TEXT NOT NULL,
    description TEXT NOT NULL,
    source TEXT NOT NULL,
    fetchedAt INTEGER NOT NULL
)
```

File: `app/src/main/java/com/androdr/data/db/Migrations.kt`

### 11. DI wiring (`AppModule`)

- Provide `CertHashIocEntryDao` from `AppDatabase`
- Provide `CertHashIocDatabase` singleton
- Provide `CertHashIocResolver` singleton
- Provide `MalwareBazaarCertFeed` singleton
- Provide `CertHashIocUpdater` singleton
- Add `CertHashIocUpdater.update()` to `IocUpdateWorker`

### 12. `IocUpdateWorker` changes

- Add `CertHashIocUpdater` as a constructor parameter (injected via `@AssistedInject`)
- Add `certHashIocUpdater.update()` call in `runAllUpdaters()` alongside the existing 3 updaters
- Update `IocUpdateWorkerTest` to provide the new parameter in test setup

### 13. `DashboardViewModel` integration

Add cert hash IOC state to the dashboard, following the existing pattern for package IOCs and domain IOCs:

- New `certHashIocCount: StateFlow<Int>` — total cert hash IOC entries
- New `certHashIocLastUpdate: StateFlow<Long?>` — last fetch timestamp
- New `refreshCertHashIocState()` method — reads from `CertHashIocEntryDao`
- Wire into `ThreatDatabaseCard` composable alongside existing IOC counts
- Constructor injection: add `CertHashIocEntryDao` parameter

### 14. `test-adversary/run.sh` update

The existing `mercenary_cert_hash` scenario seeds the cert hash into the wrong table (`ioc_entries`). Update the seeding logic to INSERT into `cert_hash_ioc_entries` with the correct schema:

```bash
$ADB shell "run-as com.androdr.debug sqlite3 $db_path \
    \"INSERT OR REPLACE INTO cert_hash_ioc_entries \
    (certHash, familyName, category, severity, description, source, fetchedAt) \
    VALUES ('$cert_hash', 'Test Fixture', 'TEST', 'CRITICAL', \
    'Adversary simulation test cert', 'adversary-test', $(date +%s000));\""
```

---

## Testing

### Unit tests
- `CertHashIocResolverTest` — lookup hit, miss, cache refresh, bundled fallback
- `AppScannerTest` — add test case with mock `PackageInfo.signingInfo` returning a known cert hash; verify "Known malicious signing certificate" reason appears
- `extractCertHash()` — test with real cert bytes, verify hex output format

### Adversary simulation
- `mercenary_cert_hash` scenario in `test-adversary/manifest.yml` already expects `"Known malicious signing certificate"` — will transition from EXPECTED FAIL to PASS once implemented
- The `cert-hash-ioc.apk` fixture uses a custom signing key; its cert hash will be seeded into the bundled JSON

---

## Out of scope

- Cert hash feeds beyond MalwareBazaar (e.g. VirusTotal, YARA rules)
- Cert pinning / certificate transparency monitoring
- Multi-signer APK support (v3+ rotation) — only checks first signer
