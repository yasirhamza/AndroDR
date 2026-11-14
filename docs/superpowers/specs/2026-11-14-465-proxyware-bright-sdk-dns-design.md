# Design: Bright SDK DNS detection and the PROXYWARE category

**Issue:** [#465](https://github.com/yasirhamza/AndroDR/issues/465)
**Date:** 2026-11-14
**Size:** small change (data + rule text; one line of Kotlin forced by a cross-check test)
**Status:** approved by the owner in conversation, 2026-11-14

## Intent

Tell a person that an app on their phone is renting out their internet connection through
the Bright Data residential-proxy SDK ("Bright SDK", formerly Luminati). Detection is by DNS:
the SDK looks up its own infrastructure domains. Coverage should reach every installed
version within the 12-hour feed cycle, without waiting for an app release.

## Goals

- Bright SDK infrastructure domains are on the threat list, attributed to the family and
  to a new category `PROXYWARE` (owner ruling), severity `HIGH` on the entry.
- The text of `androdr-003` no longer claims every threat-list domain is a C2 server; it
  names the three kinds of entry and what to do about each.
- A regression gate fails if the Bright entries or the proxy wording go missing.

## Non-goals

- **Finding level stays critical.** `androdr-003` grades every domain hit critical regardless
  of the entry's severity. The owner accepted this for now (see Approaches).
- No app-scan (embedded SDK) rule here: that is the follow-up, blocked on verified Android
  class names from a real sample.
- No IP indicators (IP filtering is parked; the SDK's raw-IP control pool is out of scope).
- No fix for the data-broker entries' medium-vs-critical mismatch (file separately).

## Anti-goals

- A false alarm for someone who only visits Bright Data's website: `brightdata.com` and
  `luminati.io` are excluded.
- Flagging a shared CDN parent: `b-cdn.net` is BunnyCDN; only the exact tenant host is listed.
- Shipping an indicator whose ownership is unverified, since every hit shows as critical.

## Approaches considered

1. **Own list and own rule** (`proxyware-domains.yml` + new lookup + new rule at high).
   Correct severity and wording; older versions ignore it safely. Needs app code and a
   release before anyone gets a detection.
2. **Add to the existing list (chosen).** No release needed; every install is covered within
   12 hours. Findings show as critical under the shared `androdr-003` text, so the
   distinction is carried by rewording that rule and by the entry's family name.
3. **Make the app honour each entry's severity and category.** Fixes the broker mismatch too,
   but regrades every domain finding; larger change, wider risk.

The owner chose 2, with the distinction made clear in the rule text. The high-severity,
separately worded detection comes from the app-scan rule follow-up, which is rule-only.

## Design

### Rules repo (`android-sigma-rules`)

**Schema.** Add `"PROXYWARE"` to the `category` enum in `validation/ioc-entry-schema.json`.

**Entries** in `ioc-data/c2-domains.yml`, under a delimited section header. All share:
`family: "Bright SDK (residential proxy)"`, `category: "PROXYWARE"`, `severity: "HIGH"`,
`source: "threat_research"`, `block_by_default: true`, and an `https://` reference.

| Indicator | Role | Evidence |
|---|---|---|
| `brdtnet.com` | peer channel, config, per-IP relay nodes | Include Security; field-observed |
| `bright-sdk.com` | config, peer channel, error reporting | Include Security; field-observed |
| `luminatinet.com` | peer channel; TLS cert CN of the peer channel | Include Security |
| `luminati-china.io` | config endpoint | webOS teardown |
| `brdtest.com` | SDK test host | webOS teardown; field-observed |
| `l-err.biz` | error reporting (`perr.`) | webOS teardown; field-observed |
| `cdn-cloud.b-cdn.net` | cloud config file (exact tenant host) | webOS teardown; field-observed |
| `perr.l-agent.me` | error reporting (exact host) | webOS teardown, cloud config `perr_domains` |
| `p.l-conn.net` | peer channel (exact host) | webOS teardown, cloud config `proxyjs_domains_a1` |
| `zagent108/110/111/112/113.l-cdn.com` | SDK updates (five exact hosts) | webOS teardown, cloud config `cdn_update_urls` |

The family name carries the kind because installed app versions drop a category they do not
know (`IocSanitizer`), so `PROXYWARE` shows as blank until an install has the new build.

Fourteen indicators in total. The last seven are exact hosts: their parents (`l-agent.me`,
`l-conn.net`, `l-cdn.com`) are not listed because their wider use is unknown (owner ruling at
the build gate, 2026-11-14, replacing the earlier "hold back" call once the teardown showed
them in the SDK's own cloud config).

`cdn-cloud.b-cdn.net` is blocked by default like the rest (owner ruling), although the
teardown's author warns that blocking it "may break legitimate apps".

Excluded: `brightdata.com`, `luminati.io`.

**Reference allowlist.** `validation/allowed-sources.json` gains two `threat_research`
prefixes (owner-approved): `https://blog.includesecurity.com/` and
`https://blazskufca.com/projects/webos-brightdata/`.

**Blocking baseline.** The fourteen indicators are added to `validation/blocked-baseline.txt`.

**Rule text** of `dns_monitor/androdr_003_domain_ioc.yml`. Title, level, detection and
display category are unchanged. Changed fields:

- `description`: "DNS query matched a domain on the threat list: a malware or spyware
  command-and-control server, a data-broker SDK endpoint, or a residential-proxy SDK
  endpoint. The matched entry names which."
- `display.guidance`: "INVESTIGATE -- device contacted a threat-list domain; the matched
  entry names the threat"
- `remediation`:
  - "This device looked up a domain on the threat list. The finding names the threat family
    it belongs to."
  - "Malware, spyware or stalkerware: an app on this device may be controlled by an attacker.
    Find the app that made the lookup and remove it."
  - "Residential-proxy SDK (for example Bright SDK): an app is using this device's internet
    connection to carry other people's traffic. Uninstall that app; blocking the domain alone
    does not stop the SDK."
  - "Data-broker SDK: an app is sending information about this device to a data broker.
    Uninstall that app or revoke its location permission."

**Manifests.** Regenerate `rules.sha256` (003 is in `rules.txt`) and `ioc-data.sha256`.

### AndroDR

- `IocSanitizer.CATEGORIES` gains `"PROXYWARE"` (forced by `IocSanitizerTest`, which requires
  it to equal the pinned schema's enum).
- Bundled copy `res/raw/sigma_androdr_003_domain_ioc.yml` updated to match the submodule.
- Submodule pointer bumped.
- Regression gate: a unit test over the pinned submodule asserting (a) each of the fourteen
  indicators is present with category `PROXYWARE` and the family above, (b) the excluded domains and
  the unlisted parents are absent, (c) `androdr-003`'s remediation mentions the residential-proxy
  case, and that the bundled rule copy carries the same text.
- Any existing test asserting the old guidance or remediation string is updated.

### Landing order (safe ordering, CLAUDE.md)

1. Rules branch with all of the above; `validate` green.
2. AndroDR PR pointing the submodule at that branch commit; `build-and-test` green
   (`submodule-check` is red mid-ordering by design).
3. Merge the rules branch to main.
4. Re-point the AndroDR submodule at rules main; merge the AndroDR PR.

## Left to the builder

- Exact description text of each entry and which public URL each cites.
- Whether the bundled cold-start list (`known_bad_domains.json`) should carry the entries
  (`cold_start_seed`); follow the existing convention for the broker entries.
- Where the new test lives and its name.
