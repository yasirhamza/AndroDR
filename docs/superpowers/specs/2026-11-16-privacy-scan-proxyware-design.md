# Design: proxyware in the privacy scan

**Follows:** [#465](https://github.com/yasirhamza/AndroDR/issues/465) (Bright SDK by DNS and by app-scan rule `androdr-113`)
**Date:** 2026-11-16
**Size:** small change (one list file, one merge step, one category and its texts)
**Status:** draft, awaiting owner approval

## Intent

The app scan sees only the components an app declares in its manifest, so a build that keeps
Bright SDK out of the manifest gets past `androdr-113`. The privacy scan reads the code packages
inside every installed app. Adding residential-proxy SDKs to its tracker list lets it name those
apps too.

## Goals

- The privacy scan reports an app that contains Bright SDK code, by code package.
- The result is shown under its own category, **Proxyware**, refused by default.
- The list part reaches every install through the 12-hour feed; older app versions show the
  entry safely until they update.
- The entries survive the next regeneration of the Exodus mirror.

## Non-goals

- **Not a security finding** (owner ruling, 2026-11-16). No alert, no Timeline detection, no
  change to the overall risk. Feeding code packages to the rule engine is a separate project.
- No new matcher: entries use the existing fields of `trackers.yml`.
- No other proxy SDK in this change. Honeygain, IPIDEA, NetNut and similar are added one by one
  when there is evidence of their package names.

## Anti-goals

- An entry so broad it matches an ordinary library. Every prefix must pass the mirror's existing
  broad-signature and common-package guards.
- Our entries presented as Exodus data. They are marked as AndroDR's.
- Entries lost silently when the mirror is regenerated.

## Approaches considered

1. **A supplement file merged by the mirror script (chosen).** Our entries live in their own
   reviewed file in the rules repo; the mirror script appends them to `trackers.yml`. The app
   keeps reading one file, so no app release is needed for the list.
2. **A second file the app reads itself.** Cleaner separation, but every install needs an app
   release before it sees anything, and the app gains a second loader, manifest entry and
   failure mode.
3. **Entries appended to `trackers.yml` by hand.** The next mirror run rewrites the file and
   they are gone.

## Design

### Rules repo

**Supplement file** `validation/tracker-supplement.yml`: a `trackers:` list in the same shape
as `trackers.yml`, plus `references` (public URLs) per entry. It is an input of the mirror
script, not a file the app fetches.

**One entry:**

| Field | Value |
|---|---|
| `id` | `900001` (ids from 900001 are reserved for the supplement; Exodus ids are below 1000 today) |
| `name` | `Bright SDK (residential proxy)` |
| `website` | `https://bright-sdk.com` |
| `categories` | `Proxyware` |
| `code_prefixes` | `io.lum.sdk`, `io.topvpn.vpn_api`, `org.hola.peer` (verified in samples); `brdat.sdk`, `com.android.eapx` (unverified, reported for current builds; included by the owner's earlier ruling for `androdr-113`) |
| `domain_suffixes` | the Bright SDK hosts already on the threat list (#466), so the scan's network evidence can show the app's lookups |

The name carries the kind because an older app version shows an unknown category as "Other".

**Mirror script** (`mirror-exodus-trackers.py`):
- reads the supplement and appends its entries after the Exodus ones, through the same field
  checks and guards as an Exodus entry;
- fails (exit 3, nothing written) if the supplement is missing or broken, if an id is below
  900001 or collides, or if a supplement entry is dropped by a guard; a supplement entry is
  never dropped quietly;
- the file header names both sources. The merged file stays ODbL.

**Category vocabulary:** wherever the rules repo checks tracker category labels, `Proxyware`
is added.

**Manifest:** `ioc-data.sha256` regenerated.

### AndroDR (ships in the next app release)

- `TrackerCategory.PROXYWARE("Proxyware")`.
- Texts: label "Proxyware"; description "Lets other people's internet traffic go out through
  your connection, so it appears to come from you".
- Refused by default, through the existing default (everything except crash reporting and
  "Other").
- **People who changed their threshold:** their saved choice does not contain the new
  category. On first start after the update it is added once, as refused (author's call: they
  were never asked about it, and refusing is the safe default). They can turn it off like any
  other.
- Bundled `res/raw/trackers.yml` updated to the merged file; submodule pointer bumped.
- Saved privacy results keep the category as text, so results from before the update are
  relabelled without a rescan.

### What older app versions show

The entry appears in a privacy scan as "Bright SDK (residential proxy)" under "Other", which
is not refused by default. Nothing breaks; it is simply quieter until the update.

### Regression gates

- Mirror tests: supplement entries are in the output; a regeneration from an Exodus dump keeps
  them; a bad id, a collision, a missing file or a guard-dropped entry fails the run.
- AndroDR unit test over the pinned submodule: entry 900001 is present with category
  `Proxyware` and the five prefixes; the bundled copy equals the submodule file;
  `Proxyware` maps to `PROXYWARE` and is in the default refused set.
- Unit test for the one-time addition to a saved threshold (added once; not added again after
  the person turns it off).
- Adversary harness: a fixture app with a class under `io.lum.sdk` and no manifest component
  under it. Expected: the privacy scan lists it under Proxyware; `androdr-113` stays silent.

### Landing order

Safe ordering as for any `ioc-data` change: rules branch, AndroDR PR pinned to it,
`build-and-test` green, merge rules, re-point the submodule, merge AndroDR.

## Left to the builder

- Which of the threat-list hosts are valid `domain_suffixes` under the domain grammar and the
  first-party-host guard; drop any that are refused and say so.
- Whether the weekly mirror workflow needs a change to pass the supplement.
- Where the one-time threshold addition lives (settings repository or a start-up step).
- Exact wording of the report line, if the privacy text export lists categories.
