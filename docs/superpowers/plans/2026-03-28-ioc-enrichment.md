# IOC Feed Enrichment Pipeline Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Connect the AI pipeline's IOC data output (public repo `ioc-data/*.yml`) to the app's runtime IOC databases so enriched threat intel flows to devices without app updates.

**Architecture:** New `PublicRepoIocFeed` class fetches 3 YAML files from the public repo, parses entries, upserts into existing Room tables. Runs in `IocUpdateWorker` alongside existing feeds. Build script merges IOC data into bundled JSON for offline baseline.

**Tech Stack:** Kotlin, snakeyaml-engine (already added), Room, Hilt DI

**Spec:** `docs/superpowers/specs/2026-03-28-ioc-enrichment-pipeline-design.md`

---

## File Structure

```
# New files
app/src/main/java/com/androdr/ioc/PublicRepoIocFeed.kt
app/src/test/java/com/androdr/ioc/PublicRepoIocFeedTest.kt
scripts/merge-ioc-data.py

# Modified files
app/src/main/java/com/androdr/ioc/IocUpdateWorker.kt  # add PublicRepoIocFeed call
```

---

### Task 1: PublicRepoIocFeed + tests

**Files:**
- Create: `app/src/main/java/com/androdr/ioc/PublicRepoIocFeed.kt`
- Create: `app/src/test/java/com/androdr/ioc/PublicRepoIocFeedTest.kt`

- [ ] **Step 1: Create `PublicRepoIocFeed.kt`**

```kotlin
// app/src/main/java/com/androdr/ioc/PublicRepoIocFeed.kt
package com.androdr.ioc

import android.util.Log
import com.androdr.data.db.CertHashIocEntryDao
import com.androdr.data.db.DomainIocEntryDao
import com.androdr.data.db.IocEntryDao
import com.androdr.data.model.CertHashIocEntry
import com.androdr.data.model.DomainIocEntry
import com.androdr.data.model.IocEntry
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.snakeyaml.engine.v2.api.Load
import org.snakeyaml.engine.v2.api.LoadSettings
import java.net.HttpURLConnection
import java.net.URL
import javax.inject.Inject
import javax.inject.Singleton

/**
 * Fetches IOC data from the public android-sigma-rules repo's ioc-data/ directory.
 * Parses YAML entries and upserts into Room IOC tables alongside other feeds.
 */
@Singleton
class PublicRepoIocFeed @Inject constructor(
    private val iocEntryDao: IocEntryDao,
    private val domainIocEntryDao: DomainIocEntryDao,
    private val certHashIocEntryDao: CertHashIocEntryDao
) {

    @Suppress("TooGenericExceptionCaught")
    suspend fun update(): Int = withContext(Dispatchers.IO) {
        var total = 0
        val now = System.currentTimeMillis()

        try {
            total += fetchAndUpsertPackages(now)
            total += fetchAndUpsertDomains(now)
            total += fetchAndUpsertCertHashes(now)
            Log.i(TAG, "Public repo IOC feed: $total entries upserted")
        } catch (e: Exception) {
            Log.w(TAG, "Public repo IOC feed failed: ${e.message}")
        }

        total
    }

    @Suppress("TooGenericExceptionCaught", "SwallowedException")
    private suspend fun fetchAndUpsertPackages(fetchedAt: Long): Int {
        val yaml = fetchUrl("${BASE_URL}ioc-data/package-names.yml") ?: return 0
        val entries = parseIocYaml(yaml)
        if (entries.isEmpty()) return 0

        val iocEntries = entries.map { entry ->
            IocEntry(
                packageName = entry["indicator"]?.toString() ?: return@map null,
                name = entry["family"]?.toString() ?: "",
                category = entry["category"]?.toString() ?: "MALWARE",
                severity = entry["severity"]?.toString() ?: "CRITICAL",
                description = entry["description"]?.toString() ?: "",
                source = SOURCE_ID,
                fetchedAt = fetchedAt
            )
        }.filterNotNull()

        if (iocEntries.isNotEmpty()) {
            iocEntryDao.upsertAll(iocEntries)
            iocEntryDao.deleteStaleEntries(SOURCE_ID, fetchedAt - 1)
        }
        return iocEntries.size
    }

    @Suppress("TooGenericExceptionCaught", "SwallowedException")
    private suspend fun fetchAndUpsertDomains(fetchedAt: Long): Int {
        val yaml = fetchUrl("${BASE_URL}ioc-data/c2-domains.yml") ?: return 0
        val entries = parseIocYaml(yaml)
        if (entries.isEmpty()) return 0

        val domainEntries = entries.map { entry ->
            DomainIocEntry(
                domain = entry["indicator"]?.toString()?.lowercase() ?: return@map null,
                campaignName = entry["family"]?.toString() ?: "",
                severity = entry["severity"]?.toString() ?: "CRITICAL",
                source = SOURCE_ID,
                fetchedAt = fetchedAt
            )
        }.filterNotNull()

        if (domainEntries.isNotEmpty()) {
            domainIocEntryDao.upsertAll(domainEntries)
            domainIocEntryDao.deleteStaleEntries(SOURCE_ID, fetchedAt - 1)
        }
        return domainEntries.size
    }

    @Suppress("TooGenericExceptionCaught", "SwallowedException")
    private suspend fun fetchAndUpsertCertHashes(fetchedAt: Long): Int {
        val yaml = fetchUrl("${BASE_URL}ioc-data/cert-hashes.yml") ?: return 0
        val entries = parseIocYaml(yaml)
        if (entries.isEmpty()) return 0

        val certEntries = entries.map { entry ->
            CertHashIocEntry(
                certHash = entry["indicator"]?.toString()?.lowercase() ?: return@map null,
                familyName = entry["family"]?.toString() ?: "",
                category = entry["category"]?.toString() ?: "MALWARE",
                severity = entry["severity"]?.toString() ?: "CRITICAL",
                description = entry["description"]?.toString() ?: "",
                source = SOURCE_ID,
                fetchedAt = fetchedAt
            )
        }.filterNotNull()

        if (certEntries.isNotEmpty()) {
            certHashIocEntryDao.upsertAll(certEntries)
            certHashIocEntryDao.deleteStaleEntries(SOURCE_ID, fetchedAt - 1)
        }
        return certEntries.size
    }

    @Suppress("UNCHECKED_CAST", "TooGenericExceptionCaught", "SwallowedException")
    internal fun parseIocYaml(yamlContent: String): List<Map<String, Any>> {
        return try {
            val load = Load(LoadSettings.builder().build())
            val doc = load.loadFromString(yamlContent) as? Map<String, Any> ?: return emptyList()
            (doc["entries"] as? List<Map<String, Any>>) ?: emptyList()
        } catch (e: Exception) {
            Log.w(TAG, "Failed to parse IOC YAML: ${e.message}")
            emptyList()
        }
    }

    @Suppress("TooGenericExceptionCaught", "SwallowedException")
    private fun fetchUrl(url: String): String? {
        return try {
            val conn = URL(url).openConnection() as HttpURLConnection
            conn.connectTimeout = TIMEOUT_MS
            conn.readTimeout = TIMEOUT_MS
            conn.setRequestProperty("User-Agent", "AndroDR/1.0")
            if (conn.responseCode == HttpURLConnection.HTTP_OK) {
                conn.inputStream.bufferedReader().use { it.readText() }
            } else {
                null
            }
        } catch (e: Exception) {
            Log.w(TAG, "HTTP fetch failed for $url: ${e.message}")
            null
        }
    }

    companion object {
        private const val TAG = "PublicRepoIocFeed"
        const val SOURCE_ID = "androdr_public_repo"
        private const val BASE_URL =
            "https://raw.githubusercontent.com/android-sigma-rules/rules/main/"
        private const val TIMEOUT_MS = 15_000
    }
}
```

- [ ] **Step 2: Create `PublicRepoIocFeedTest.kt`**

```kotlin
// app/src/test/java/com/androdr/ioc/PublicRepoIocFeedTest.kt
package com.androdr.ioc

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class PublicRepoIocFeedTest {

    private val feed = PublicRepoIocFeed(
        iocEntryDao = io.mockk.mockk(),
        domainIocEntryDao = io.mockk.mockk(),
        certHashIocEntryDao = io.mockk.mockk()
    )

    @Test
    fun `parseIocYaml extracts entries from valid YAML`() {
        val yaml = """
            version: "2026-03-28"
            description: "Test IOC data"
            sources: []
            entries:
              - indicator: "com.evil.app"
                family: "EvilMalware"
                category: "RAT"
                severity: "CRITICAL"
                description: "Test entry"
                source: "test"
              - indicator: "com.bad.app"
                family: "BadMalware"
                category: "STALKERWARE"
                severity: "HIGH"
                description: "Another test"
                source: "test"
        """.trimIndent()

        val entries = feed.parseIocYaml(yaml)
        assertEquals(2, entries.size)
        assertEquals("com.evil.app", entries[0]["indicator"])
        assertEquals("EvilMalware", entries[0]["family"])
        assertEquals("com.bad.app", entries[1]["indicator"])
    }

    @Test
    fun `parseIocYaml returns empty for empty entries`() {
        val yaml = """
            version: "2026-03-28"
            entries: []
        """.trimIndent()

        val entries = feed.parseIocYaml(yaml)
        assertTrue(entries.isEmpty())
    }

    @Test
    fun `parseIocYaml returns empty for invalid YAML`() {
        val entries = feed.parseIocYaml("not valid yaml [[[")
        assertTrue(entries.isEmpty())
    }

    @Test
    fun `parseIocYaml returns empty for missing entries key`() {
        val yaml = """
            version: "2026-03-28"
            description: "No entries key"
        """.trimIndent()

        val entries = feed.parseIocYaml(yaml)
        assertTrue(entries.isEmpty())
    }
}
```

- [ ] **Step 3: Run tests**

Run: `export JAVA_HOME=/home/yasir/Applications/android-studio/jbr && ./gradlew testDebugUnitTest --tests "com.androdr.ioc.PublicRepoIocFeedTest"`
Expected: 4 tests PASS

- [ ] **Step 4: Commit**

```bash
git add app/src/main/java/com/androdr/ioc/PublicRepoIocFeed.kt \
       app/src/test/java/com/androdr/ioc/PublicRepoIocFeedTest.kt
git commit -m "feat: add PublicRepoIocFeed to fetch IOC data from public rules repo"
```

---

### Task 2: Wire into IocUpdateWorker

**Files:**
- Modify: `app/src/main/java/com/androdr/ioc/IocUpdateWorker.kt`

- [ ] **Step 1: Add `PublicRepoIocFeed` to constructor and doWork()**

Read `IocUpdateWorker.kt` first. Add `PublicRepoIocFeed` to the constructor. Call `publicRepoIocFeed.update()` in `doWork()` after the existing updaters but before SIGMA refresh (IOC data should be available before rules evaluate):

```kotlin
private val publicRepoIocFeed: PublicRepoIocFeed
```

In `doWork()`, after `runAllUpdaters(...)` and before `refreshSigmaRules()`:

```kotlin
// Fetch IOC data from public rules repo
refreshPublicRepoIoc()
```

Add method:
```kotlin
@Suppress("TooGenericExceptionCaught")
private suspend fun refreshPublicRepoIoc() {
    try {
        val count = publicRepoIocFeed.update()
        if (count > 0) {
            Log.i(TAG, "Public repo IOC feed: $count entries loaded")
        }
    } catch (e: Exception) {
        Log.w(TAG, "Public repo IOC feed failed (non-fatal): ${e.message}")
    }
}
```

- [ ] **Step 2: Build and test**

Run: `export JAVA_HOME=/home/yasir/Applications/android-studio/jbr && ./gradlew detekt lintDebug testDebugUnitTest`
Expected: BUILD SUCCESSFUL

- [ ] **Step 3: Commit**

```bash
git add app/src/main/java/com/androdr/ioc/IocUpdateWorker.kt
git commit -m "feat: wire PublicRepoIocFeed into IocUpdateWorker periodic cycle"
```

---

### Task 3: Build-time merge script

**Files:**
- Create: `scripts/merge-ioc-data.py`

- [ ] **Step 1: Create the merge script**

```python
#!/usr/bin/env python3
"""
Merge IOC data from the public android-sigma-rules repo into AndroDR's
bundled JSON/txt files for offline baseline.

Usage:
    python3 scripts/merge-ioc-data.py [--repo-dir /path/to/rules/clone]

If --repo-dir is not specified, clones the public repo to /tmp/androdr-rules-merge.
"""

import argparse
import json
import os
import subprocess
import sys
import yaml


REPO_URL = "https://github.com/android-sigma-rules/rules.git"
DEFAULT_CLONE_DIR = "/tmp/androdr-rules-merge"

BUNDLED_PACKAGES = "app/src/main/res/raw/known_bad_packages.json"
BUNDLED_CERTS = "app/src/main/res/raw/known_bad_certs.json"
BUNDLED_DOMAINS = "app/src/main/res/raw/domain_blocklist.txt"


def load_yaml(path):
    with open(path) as f:
        data = yaml.safe_load(f)
    return data.get("entries", []) if data else []


def merge_packages(entries, bundled_path):
    with open(bundled_path) as f:
        existing = json.load(f)

    existing_names = {e["packageName"] for e in existing}

    added = 0
    for entry in entries:
        indicator = entry.get("indicator", "")
        if indicator and indicator not in existing_names:
            existing.append({
                "packageName": indicator,
                "name": entry.get("family", indicator),
                "category": entry.get("category", "MALWARE"),
                "severity": entry.get("severity", "CRITICAL"),
                "description": entry.get("description", "")
            })
            existing_names.add(indicator)
            added += 1

    with open(bundled_path, "w") as f:
        json.dump(existing, f, indent=2)

    print(f"  Packages: {added} new entries added (total: {len(existing)})")


def merge_certs(entries, bundled_path):
    with open(bundled_path) as f:
        existing = json.load(f)

    existing_hashes = {e["certHash"] for e in existing}

    added = 0
    for entry in entries:
        indicator = entry.get("indicator", "").lower()
        if indicator and indicator not in existing_hashes:
            existing.append({
                "certHash": indicator,
                "familyName": entry.get("family", ""),
                "category": entry.get("category", "MALWARE"),
                "severity": entry.get("severity", "CRITICAL"),
                "description": entry.get("description", "")
            })
            existing_hashes.add(indicator)
            added += 1

    with open(bundled_path, "w") as f:
        json.dump(existing, f, indent=2)

    print(f"  Cert hashes: {added} new entries added (total: {len(existing)})")


def merge_domains(entries, bundled_path):
    with open(bundled_path) as f:
        existing_lines = f.read().strip().split("\n")

    existing_domains = {
        line.strip().lower()
        for line in existing_lines
        if line.strip() and not line.startswith("#")
    }

    added = 0
    new_lines = []
    for entry in entries:
        domain = entry.get("indicator", "").lower().strip()
        if domain and domain not in existing_domains:
            new_lines.append(domain)
            existing_domains.add(domain)
            added += 1

    if new_lines:
        with open(bundled_path, "a") as f:
            f.write(f"\n# Public repo IOC data (auto-merged)\n")
            for domain in sorted(new_lines):
                f.write(f"{domain}\n")

    print(f"  Domains: {added} new entries added (total: {len(existing_domains)})")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-dir", default=None)
    args = parser.parse_args()

    repo_dir = args.repo_dir
    if not repo_dir:
        repo_dir = DEFAULT_CLONE_DIR
        if os.path.exists(repo_dir):
            subprocess.run(["git", "-C", repo_dir, "pull", "--quiet"], check=True)
        else:
            subprocess.run(
                ["git", "clone", "--quiet", REPO_URL, repo_dir], check=True
            )

    print("Merging IOC data from public repo into bundled files...")

    pkg_path = os.path.join(repo_dir, "ioc-data", "package-names.yml")
    if os.path.exists(pkg_path):
        merge_packages(load_yaml(pkg_path), BUNDLED_PACKAGES)

    cert_path = os.path.join(repo_dir, "ioc-data", "cert-hashes.yml")
    if os.path.exists(cert_path):
        merge_certs(load_yaml(cert_path), BUNDLED_CERTS)

    domain_path = os.path.join(repo_dir, "ioc-data", "c2-domains.yml")
    if os.path.exists(domain_path):
        merge_domains(load_yaml(domain_path), BUNDLED_DOMAINS)

    print("Done.")


if __name__ == "__main__":
    main()
```

- [ ] **Step 2: Make executable and test**

```bash
chmod +x scripts/merge-ioc-data.py
python3 scripts/merge-ioc-data.py --repo-dir /tmp/rules_check
```

Expected: "0 new entries added" for each (since `ioc-data/` files are currently empty). No errors.

- [ ] **Step 3: Commit**

```bash
git add scripts/merge-ioc-data.py
git commit -m "feat: add build-time IOC data merge script for offline baseline"
```

---

### Task 4: Populate public repo IOC data with seed entries

**Files:**
- Modify: `ioc-data/package-names.yml` in the public `android-sigma-rules/rules` repo

- [ ] **Step 1: Populate package-names.yml with stalkerware entries**

Clone public repo and populate `ioc-data/package-names.yml` with entries from the deleted per-family rules (050-054). These package names were in the rules — now they belong in IOC data.

Include entries for: TheTruthSpy aliases, FlexiSpy, Cerberus, mSpy/Eyezy, Cocospy cluster.

Format:
```yaml
version: "2026-03-28"
description: "Known malicious Android package names"
sources:
  - stalkerware-indicators
  - citizenlab
entries:
  - indicator: "com.thetruthspy"
    family: "TheTruthSpy"
    category: "STALKERWARE"
    severity: "CRITICAL"
    description: "TheTruthSpy stalkerware — if not self-installed, contact a DV hotline"
    source: "stalkerware-indicators"
```

- [ ] **Step 2: Populate c2-domains.yml with stalkerware C2 domains**

Same domains that were in the deleted `androdr-055` rule.

- [ ] **Step 3: Commit and push to public repo**

```bash
git add ioc-data/ && git commit -m "feat: seed IOC data with stalkerware package names and C2 domains"
git push origin main
```

- [ ] **Step 4: Run merge script to update bundled data**

```bash
cd /home/yasir/AndroDR
python3 scripts/merge-ioc-data.py
```

Verify new entries appear in bundled files.

- [ ] **Step 5: Commit bundled data update**

```bash
git add app/src/main/res/raw/
git commit -m "feat: merge public repo IOC data into bundled files"
```

---

### Task 5: Final verification + push

- [ ] **Step 1: Full build**

Run: `export JAVA_HOME=/home/yasir/Applications/android-studio/jbr && ./gradlew detekt lintDebug testDebugUnitTest`
Expected: BUILD SUCCESSFUL

- [ ] **Step 2: Push**

```bash
git push origin main
```
