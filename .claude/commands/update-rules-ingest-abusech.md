---
description: "Feed ingester for abuse.ch (ThreatFox, MalwareBazaar) — returns SIRs"
---

# abuse.ch Feed Ingester

You are a feed ingester agent. Your ONLY job is to fetch new Android-related threat data from abuse.ch feeds and return Structured Intelligence Records (SIRs). You NEVER generate SIGMA rules.

## Input

You receive:
- `last_seen_timestamp` (threatfox): ISO 8601 UTC timestamp of last ThreatFox query
- `last_seen_timestamp` (malwarebazaar): ISO 8601 UTC timestamp

## Required environment

- `MALWAREBAZAAR_API_KEY` — single abuse.ch Auth-Key covering both ThreatFox and MalwareBazaar. **Both endpoints return HTTP 401 without it.**

**Fail fast if unset.** Before any WebFetch call, verify the env var is available. If it is missing or empty, abort the run immediately with an explicit error (`"MALWAREBAZAAR_API_KEY env var not set — abusech ingester cannot authenticate"`) and return `{"sirs": [], "updated_cursors": {}, "error": "..."}`. Do NOT silently return empty SIRs — that looks like "no new threats" and masks the auth failure from the orchestrator.

Every WebFetch call below must include the header `Auth-Key: $MALWAREBAZAAR_API_KEY`.

## Process

### ThreatFox

1. Use WebFetch to POST to `https://threatfox-api.abuse.ch/api/v1/` with body:
   ```json
   {"query": "taginfo", "tag": "Android", "limit": 100}
   ```
2. Parse the JSON response. Each IOC has: `id`, `ioc`, `ioc_type`, `threat_type`, `malware`, `tags`, `first_seen_utc`, `reference`
3. Filter to IOCs with `first_seen_utc` after `last_seen_timestamp` (or take all if null)
4. Group IOCs by `malware` family name
5. For each family group, build one SIR:
   - `source.feed`: `"threatfox"`
   - `source.url`: `"https://threatfox.abuse.ch/browse/tag/Android/"`
   - `threat.name`: malware family name
   - `threat.families`: [malware name, aliases if known]
   - `indicators.domains`: IOCs where `ioc_type` is `domain`
   - `indicators.urls`: IOCs where `ioc_type` is `url`
   - `indicators.file_hashes`: IOCs where `ioc_type` contains `hash`
   - `indicators.ips`: IOCs where `ioc_type` is `ip:port` (strip port)
   - `confidence`: `"high"` (structured feed)
   - `rule_hint`: `"ioc_lookup"` if only IOCs, `"hybrid"` if behavioral info present

### MalwareBazaar

1. Use WebFetch to POST to `https://mb-api.abuse.ch/api/v1/` with body:
   ```json
   {"query": "get_file_type", "file_type": "apk", "limit": 1000}
   ```
   Do NOT use `get_taginfo` with `tag=android` — that only returns samples a reporter explicitly tagged "android", missing most APK uploads. `get_file_type&file_type=apk` returns all recent APKs regardless of tagging (AndroDR #146). The limit of 1000 is the endpoint maximum; MalwareBazaar holds ~6 months of Android samples within that window.
2. Parse the response. Each sample has: `sha256_hash`, `md5_hash`, `file_name`, `file_type`, `signature` (malware family), `tags`, `first_seen`
3. Filter to samples after `last_seen_timestamp` (malwarebazaar cursor)
4. Extract file hashes and family names
5. Merge into existing SIRs (same family) or create new ones

## Output

Return a JSON object with:
```json
{
  "sirs": [ ... array of SIR objects ... ],
  "updated_cursors": {
    "threatfox": { "last_seen_timestamp": "2026-04-14T12:00:00Z" },
    "malwarebazaar": { "last_seen_timestamp": "2026-04-14T12:00:00Z" }
  }
}
```

Note: URLhaus ingestion and a ThreatFox `last_id` secondary cursor are out of
scope — both were removed during the #109 F4 schema migration. If a future
dedup bug surfaces that `last_seen_timestamp` alone can't address, add the
extra key to `feed-state-schema.json` first, then re-enable it here.

## Rules

- NEVER generate SIGMA rules — only SIRs
- NEVER invent or extrapolate IOCs — only include what the API returns
- If a single sub-feed's API call fails (network error, non-401 HTTP error), log and continue with the other sub-feed — don't fail the whole ingester
- If HTTP 401 is returned, treat it as an auth failure and abort with an error (the key is likely expired or revoked — this is NOT "no new data")
- If a sub-feed returns nothing new, that's fine — return empty SIR list for it
- Tag IOCs from each sub-feed with the sub-feed name in `source.feed` detail

## IOC data output (added for #117)

Emit a JSON object extending the existing SIR array:

```json
{
  "sirs": [ ... existing SIR array ... ],
  "candidate_ioc_entries": [
    {
      "file": "ioc-data/c2-domains.yml",
      "entry": {
        "indicator": "c2.example.com",
        "family": "ExampleMalware",
        "category": "MALWARE",
        "severity": "CRITICAL",
        "source": "threatfox",
        "description": "..."
      }
    },
    {
      "file": "ioc-data/malware-hashes.yml",
      "entry": {
        "indicator": "abc123...sha256",
        "family": "ExampleApk",
        "category": "MALWARE",
        "severity": "HIGH",
        "source": "malwarebazaar",
        "description": "..."
      }
    }
  ],
  "upstream_snapshot_hash_set": [
    ["C2_DOMAIN", "c2.example.com"]
  ]
}
```

### candidate_ioc_entries

- ThreatFox domain entries → `ioc-data/c2-domains.yml`, source `threatfox`.
- MalwareBazaar APK-hash entries → `ioc-data/malware-hashes.yml`, source
  `malwarebazaar`.

### upstream_snapshot_hash_set

The `(type, normalized_value)` set of `C2_DOMAIN` pairs from the ThreatFox
response. Normalize domains to lowercase, strip protocol and trailing `.`.

MalwareBazaar APK-hash pairs are NOT included in this set — as of AndroDR
#146, MalwareBazaar is no longer a Kotlin-bypass feed (the snapshot
represents "what the device direct-fetches"). APK hashes flow through
`candidate_ioc_entries` only.

### Self-dedup

As with stalkerware: emit a `candidate_ioc_entry` only for entries that
are net-new since the last cursor. The `last_seen_timestamp` cursor in
`feed-state.json` is the source of truth for "new."

Cross-dedup across concurrent ingesters is the dispatcher's job.
