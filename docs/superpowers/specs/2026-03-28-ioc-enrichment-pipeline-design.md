# IOC Feed Enrichment Pipeline — Design Spec

## Goal

Connect the AI rule update pipeline's IOC data output to the app's runtime IOC databases, so that enriched threat intelligence flows from the pipeline to devices without app updates.

## Motivation

The AI rule update pipeline ingests 7 threat intel sources and can produce IOC data (package names, cert hashes, C2 domains). Currently the `ioc-data/` files in the public repo exist but are empty — no consumer reads them, and the pipeline doesn't populate them. The app's bundled IOC data is static (baked into APK at build time). New threat indicators require an app rebuild.

---

## Architecture

```
AI Pipeline (update-rules skill)
    │
    ├── IOC data entries → ioc-data/*.yml (public repo)
    └── SIGMA rules → app_scanner/*.yml etc. (public repo)
                                │
                                ↓
                    PublicRepoIocFeed (new)
                    Fetches ioc-data/*.yml at runtime
                                │
                                ↓
                    Room DB (IocEntry, DomainIocEntry, CertHashIocEntry)
                                │
                                ↓
                    SIGMA rule evaluation (ioc_lookup modifier)
```

---

## Components

### 1. `PublicRepoIocFeed` (new class)

Single feed class that fetches all three IOC data files from the public repo and upserts into the corresponding Room tables.

```kotlin
@Singleton
class PublicRepoIocFeed @Inject constructor(
    private val iocEntryDao: IocEntryDao,
    private val domainIocEntryDao: DomainIocEntryDao,
    private val certHashIocEntryDao: CertHashIocEntryDao
)
```

**Source URLs:**
- `https://raw.githubusercontent.com/android-sigma-rules/rules/main/ioc-data/package-names.yml`
- `https://raw.githubusercontent.com/android-sigma-rules/rules/main/ioc-data/c2-domains.yml`
- `https://raw.githubusercontent.com/android-sigma-rules/rules/main/ioc-data/cert-hashes.yml`

**Method:** `suspend fun update(): Int` — fetches all three files, parses YAML, upserts entries, returns total count.

**YAML format** (already defined in repo):
```yaml
version: "2026-03-28"
description: "Known malicious Android package names"
sources:
  - stalkerware-indicators
  - citizenlab
entries:
  - indicator: "com.flexispy.android"
    family: "FlexiSpy"
    category: "STALKERWARE"
    severity: "CRITICAL"
    description: "FlexiSpy commercial stalkerware — contact a DV hotline if not self-installed"
    source: "stalkerware-indicators"
  - indicator: "com.thetruthspy.app"
    family: "TheTruthSpy"
    ...
```

**Mapping to Room entities:**

| YAML field | IocEntry | DomainIocEntry | CertHashIocEntry |
|-----------|----------|----------------|------------------|
| `indicator` | `packageName` | `domain` | `certHash` |
| `family` | `name` | `campaignName` | `familyName` |
| `category` | `category` | — | `category` |
| `severity` | `severity` | `severity` | `severity` |
| `description` | `description` | — | `description` |
| `source` | `source` = "androdr_public_repo" | `source` = "androdr_public_repo" | `source` = "androdr_public_repo" |
| — | `fetchedAt` = now | `fetchedAt` = now | `fetchedAt` = now |

### 2. IocUpdateWorker integration

Add `PublicRepoIocFeed.update()` to the worker's update cycle, alongside existing feeds. Runs in parallel with other feeds. Source ID `"androdr_public_repo"` — stale entry cleanup uses this to avoid removing entries from other sources.

### 3. AI pipeline output (update-rules-author skill)

The `update-rules-author` skill (already updated with IOC-first gate) produces IOC data entries. These are committed to `ioc-data/*.yml` files in the public repo by the pipeline. The format matches what `PublicRepoIocFeed` consumes.

### 4. Build-time bundling

GitHub Actions workflow step (or local script) that merges `ioc-data/` entries into the bundled JSON files before building:

- `ioc-data/package-names.yml` entries → merge into `app/src/main/res/raw/known_bad_packages.json`
- `ioc-data/cert-hashes.yml` entries → merge into `app/src/main/res/raw/known_bad_certs.json`
- `ioc-data/c2-domains.yml` entries → append to `app/src/main/res/raw/domain_blocklist.txt`

Script: `scripts/merge-ioc-data.py` — reads YAML from public repo (or local clone), converts to bundled JSON format, writes to `res/raw/`. Run before `./gradlew assembleRelease`.

This ensures the offline baseline includes the latest AI-enriched IOC data.

### 5. Resolver cache refresh

After `PublicRepoIocFeed.update()` completes, refresh the in-memory caches:
- `IocResolver.refreshCache()`
- `CertHashIocResolver.refreshCache()`
- `DomainIocResolver.refreshCache()` (already called by DomainIocUpdater)

The existing updaters already handle this — `PublicRepoIocFeed` upserts directly to the same Room tables, so the next cache refresh picks up the new entries.

---

## Data Flow

```
1. AI pipeline runs /update-rules
2. Ingesters produce SIRs from 7 threat intel sources
3. Rule author applies IOC-first gate:
   - IOC indicators → committed to ioc-data/*.yml
   - Behavioral patterns → committed as SIGMA rules
4. Public repo updated (automatic git push)

5. Device periodic update (IocUpdateWorker):
   a. Existing feeds run (stalkerware, MVT, HaGeZi, etc.)
   b. PublicRepoIocFeed fetches ioc-data/*.yml
   c. Entries upserted to Room alongside other feed data
   d. SigmaRuleFeed fetches latest rules
   e. Resolvers refresh caches

6. Next scan uses enriched IOC data via SIGMA ioc_lookup rules
```

---

## Testing

- Unit test: `PublicRepoIocFeed` parses YAML format correctly
- Unit test: entries map to correct Room entities
- Integration: verify entries appear in resolver lookups after feed update
- Adversary simulation: add a test package name to `ioc-data/package-names.yml`, verify it's detected on next scan

---

## Out of Scope

- Multi-origin fallback / censorship bypass (users expected to have VPN)
- Cloudflare Worker changes (stays as APK proxy only)
- Real-time push updates (periodic pull is sufficient)
- IOC data versioning / delta updates (full file fetch each time)
