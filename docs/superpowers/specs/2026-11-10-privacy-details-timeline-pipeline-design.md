# Privacy scan: evidence details, Timeline entries, tracker-list refresh in the rule pipeline — design

Status: draft for owner review, 2026-11-10 (builder check done; its one question for the owner is answered in §3 and §8). Written from a brainstorming conversation with the owner. The owner's decisions are marked **(owner)**, the author's calls **(author's call)**. It builds on, and in two places amends, `docs/superpowers/specs/2026-11-06-privacy-scan-design.md` ("the earlier design"); §8 lists the amendments.

## 1. Intent

The privacy scan is live. The owner used it and reported three gaps:

1. A finding cannot be opened. The screen says "found in code" or "14 lookups on 5 days", but not *which* code or *which* domains. The owner wants to tap a finding and see the ground truth behind it. **(owner)**
2. The privacy scan does not appear in the Timeline. The owner wants it there as a new category of scan, "privacy scan". **(owner)**
3. The tracker list is refreshed by hand, outside the rule pipeline. The owner wants the refresh to be part of `/update-rules`. **(owner)**

These are three separate pieces of work that share one document. Each can be built, reviewed and merged on its own (§7).

## 2. Goals

1. From any place a tracker is listed for an app, one tap opens the evidence behind it: the matching packages in the app's code, the domains the app looked up, and the tracker-list signature each one matched.
2. A completed privacy scan is visible in the Timeline as its own category of scan, and each of its entries leads back to the privacy results.
3. Running `/update-rules` checks Exodus Privacy for tracker-list changes, shows a person what changed, and on approval commits the new list with its manifest, through the same gates as every other list.

## 3. Non-goals and anti-goals

- **Trackers never count toward alerts or the device verdict.** **(owner, 2026-11-10)** A privacy entry in the Timeline is information, not a detection. It has no severity, raises no alert, and changes no count of findings anywhere.
- **No scheduled job.** **(owner, 2026-11-10: "No weekly run")** The tracker list is refreshed only when a person runs `/update-rules`.
- **Phones do not fetch from Exodus.** They keep fetching `ioc-data/trackers.yml` from the rules repository, hash-verified, on the existing 12-hour cycle and the manual update in Settings. Fetching straight from Exodus was discussed and not pursued: the phone would need the mirror script's filtering rebuilt in Kotlin and would still depend on the hand-kept list of first-party hosts in the rules repository. **(author's recommendation; the owner did not pursue the alternative)**
- **SIGMA rules do not see privacy-scan facts.** That question stays open as issue #451 and needs its own design. Nothing here feeds the rule engine or the correlation engine.
- **No history of privacy scans.** The earlier ruling stands: only the last completed privacy scan is kept. **(owner, 2026-11-06)** This design does not keep older results alive through the Timeline (§5.4).
- **No new collection.** Everything shown in the details is derived from what the scan already reads (the app's package list, the DNS log). Nothing leaves the device.
- **What is kept longer is said publicly.** Privacy results, including the tracker domains an app looked up, and the privacy scan's Timeline entries are kept until the next privacy scan or until the user deletes them, which can be longer than the 30 days the privacy policy promises today. The policy changes to say so (§8); the retention is not shortened to fit the old wording. **(owner, 2026-11-10: "Change it")**
- **No AndroDR judgement.** The wording rules of the earlier design (§4.3 there) apply to every new string: facts, each with its evidence source; "looked up domains of X", never "carries", for network-only evidence.
- **Anti-goal: false reassurance or false alarm through a side door.** A privacy entry must not turn an ordinary app into a threat indicator in an export, and a missing detail must never read as "nothing found".

## 4. Part A — evidence details

### 4.1 What the user sees

Today the By-app list opens a sheet for the app, listing its trackers with a one-line summary each. Those tracker entries are not tappable, and neither are the tracker cards on the By-tracker tab.

After this change, **each tracker listed for an app is tappable**, in both places (the app's sheet, and each app line inside a tracker card). It opens a details view for that one tracker in that one app. Back returns to where the user was. **(owner: tap a finding, see ground truth; layout is the author's call)**

The details view, top to bottom:

```
AppsFlyer                                   in  Some Game (com.example.game)
appsflyer.com · Advertisement, Analytics
Tracker list entry 12 (Exodus Privacy)  ›

FOUND IN CODE
Version inspected: 1203 · fully inspected
Signature  com.appsflyer   (package prefix)
  com.appsflyer
  com.appsflyer.internal
  com.appsflyer.share
  … and 9 more

LOOKED UP DOMAINS OF THIS TRACKER
Recorded 11 Oct – 10 Nov · network evidence covers 22 days
Lookups can be caused by links, web pages or emails the app displays.

  t.appsflyer.com            matched  appsflyer.com (domain suffix)
  31 lookups on 9 days · 12 in background · first 14 Oct · last 2 h before the scan   ›
  conversions.appsflyer.com  matched  appsflyer.com (domain suffix)
  4 lookups on 2 days · background unknown · first 2 Nov · last 8 Nov               ›

Privacy scan of 10 Nov 2026 14:02 · tracker list: 428 trackers (a41c…9e)
```

Contents, precisely:

- **Header.** Tracker name, website and categories as shown today; the app's name and package name; the tracker's entry number in the list, with a link to Exodus Privacy's page for that tracker when a stable `https://` address for it exists (the builder confirms the address form; otherwise the number alone). **(author's call)**
- **Found in code** (only when the tracker was found in code). Each tracker-list signature that matched, with its kind (a package prefix, or a package-name segment), and under it the Java packages of the app that matched it. The app version inspected, and whether the app was fully or only partly inspected; when partly: "Only part of this app's code could be read, so this list may be incomplete."
- **Looked up domains** (only when lookups were recorded). The window the lookups come from, and the coverage statement the screen already uses. Each domain the app looked up that belongs to this tracker: the domain as recorded, the signature it matched and its kind (domain suffix, label, or pattern), the number of lookups, the number of days, how many happened in the background (or "unknown" where the scan could not tell), first and last time. Most lookups first. The standing note about displayed content. When the scan's network step was cut short or failed, the view says the list may be incomplete.
- **Lookup times.** Tapping a domain shows the times of its most recent lookups by this app (up to 50), read from the network monitor's log as it is now, labelled as such: the log keeps 30 days and keeps growing, so this list can differ from the scan's counts. **(author's call; this is the one part of the view not frozen at scan time, and it can be dropped without affecting the rest)**
- **Footer.** The scan's date and the tracker-list version it used (size and short hash), both already stored.
- A domain that belongs to several trackers appears under each of them, as the counts do today.

**Results from before this change.** A scan stored by an app version that did not record details shows the totals as today and one line: "Run a new privacy scan to record the matching packages and domains." No back-fill is attempted. **(author's call)**

### 4.2 What is recorded at scan time

The scan already computes everything above and throws most of it away: the code match returns only *which trackers* matched, and the network step sums per-domain counts into one total per tracker. This change keeps the detail.

- **Recorded at scan time, with the scan.** The details are a dated snapshot, like the totals. They are not recomputed when the view opens, for three reasons: the tracker list may have been refreshed since the scan; the saved package list exists only for fully inspected apps; and the DNS log ages. **(author's call, following the earlier design's "stored as a dated snapshot")**
- **Code detail.** For each app and tracker found in code: each signature that matched, its kind, the matching packages (capped, §4.3) and the true number of matching packages.
- **Network detail.** For each app, tracker and looked-up domain: the domain, the signature that matched and its kind, lookups, days, background lookups (or unknown), first and last time. These are the per-domain figures the correlator already holds in memory before summing them.
- **Matching must not fork.** The step that reports *which signature* matched must yield exactly the same trackers as today's matching, for code and for domains. Either today's functions are rebuilt on top of the detailed ones, or a cross-check test proves the two agree on the real tracker list. A second, slightly different matcher is the failure to avoid.
- **Totals stay authoritative.** The existing per-tracker totals are unchanged and remain what the lists, the Dashboard card, the threshold and "new since last scan" read. The detail explains the totals; nothing ranks or counts from it.
- **Storage.** New `privacy_*` table or tables beside the existing ones (Room schema 22 → 23, with a migration test and the exported schema). They follow the scan they belong to in every respect: deleted when a newer scan completes, deleted by "Delete privacy results", never exported, never read by reports, rules, History or the security store. `PrivacyBoundaryTest` continues to hold as written.
- **Reading.** The details for one app and tracker are loaded when the view opens, not with the lists. The lists must not get slower.

### 4.3 Bounds

An app can ship thousands of packages and can look up junk domains on purpose, so every stored list is bounded.

- Matching packages stored per app and tracker: at most 200, with the true total recorded so the view can say "and N more". **(author's call; the builder may adjust the number from real apps)**
- Domains: the correlator's existing limits already bound them (200 matched domains per app, 20,000 in total per scan). No new limit is added; a domain is stored only if it was counted.
- A stored domain is no longer than the longest host the matcher accepts.
- Package names and domains are untrusted text. They reach the screen only through the same sanitising used for app labels today, with a length that fits a full domain; anything cut is visibly cut.
- Background per domain is known only for the pairs the scan already timed; elsewhere it is "unknown", never zero.

## 5. Part B — the privacy scan in the Timeline

### 5.1 What the user sees

- The Timeline's **Source** filter gains a fourth choice, **Privacy scan**, beside Live scan, Bug report import and Intrusion log import. **(owner: a new category of scan)**
- In the Timeline's **By scan** grouping, the privacy scan appears as one more scan header, labelled "Privacy scan", with its date and number of entries, placed by its date among the other scans. Tapping it shows the Timeline narrowed to the privacy scan. It has no "view telemetry" link (it has none). **(author's call on how "category of scan" appears in this grouping)**
- A privacy entry looks like the Timeline's other plain entries, with no severity colour or badge.
- Tapping a privacy entry opens the Timeline's usual details sheet with the entry's text and one action, **Open in privacy results**: for an app entry it opens the privacy screen on that app's sheet (from where Part A's details are one tap away); for the scan entry it opens the privacy screen.

### 5.2 Which entries a privacy scan writes

When a privacy scan completes it writes:

1. **One scan entry**, at the scan's finish time: how many apps were inspected, in how many of them trackers were found in code, how many could not be inspected or were only partly inspected, and whether network evidence was complete. Example: "Privacy scan: 212 apps inspected · trackers found in the code of 87 · 3 could not be inspected".
2. **One entry per user-installed app in whose code at least one tracker was found**, at the same time. Example: "Some Game: 5 trackers found in code", with the tracker names in the entry's details (the first ten, then "and N more"), the number that are new since the previous privacy scan when there are any, and "partly inspected" when that applies.

The reasoning behind that shape, all **author's calls**:

- **Per app, not per app-and-tracker.** A phone with a hundred apps easily has a thousand app-and-tracker pairs; a thousand entries at one instant would bury everything else in the unfiltered Timeline. One entry per app keeps it readable, and the app is also what the Timeline can already be narrowed to: an app's own timeline then shows its installs and permission events together with its privacy entry.
- **Independent of the user's threshold.** The Dashboard card and the privacy screen compute "crosses your threshold" live, under the *current* setting, so that they always agree. An entry written at scan time cannot follow a later change of the setting. So entries state only facts that stay true (what was found in code) and never mention the threshold. Which apps get an entry does not depend on it either.
- **User-installed apps only.** Same reason the privacy screen hides system apps by default: Google and Samsung system apps carrying Firebase would dominate, and the user cannot remove them. The scan entry's counts still cover every app. The system-app toggle on the privacy screen does not affect the Timeline.
- **Code evidence only.** Network-only evidence can be caused by content an app displays, which is why it never counts toward the threshold; an app with network-only evidence gets no entry. An app's entry mentions network lookups only as part of its details.
- **No entry per DNS lookup.** Lookups stay where they are: in the network monitor's log and, summarised, in Part A's details.

### 5.3 What a privacy entry never does

The Timeline table has many readers. This is the complete list of what must hold; each line needs a test (§9).

| Reader | Required behaviour |
|---|---|
| Alerts, Dashboard verdict, finding counts | Unaffected. They read findings and alerts, not the Timeline; a test pins that a privacy scan changes none of them. |
| "Findings only" and the severity filters | Never show a privacy entry. It has no rule, no severity, and is not a signal. |
| Pinned "current findings" section | Unaffected. |
| SIGMA rules and correlation | A privacy entry is never an input (issue #451 stays open). |
| Timeline export (CSV and plain text) | Privacy entries are always left out, whatever the filter. |
| STIX export | Privacy entries are always left out. Without this, every app with a tracker would be exported as a threat indicator. |
| Security report, History | Unchanged; they do not read the Timeline's privacy entries and must not start to. |
| Timeline search | A privacy entry is found by app name, package name or its text, like any entry. |
| One app's timeline (package filter) | The app's privacy entry is shown. |
| 30-day prune | Does not remove privacy entries (§5.4). |
| History's "Clear all" and deleting a security scan | Do not remove privacy entries (§5.4). |

Leaving privacy entries out of the Timeline's exports follows the earlier ruling that privacy results are not part of the exported security report: an export is what people hand to someone else, and the list of installed apps is exactly what "Delete privacy results" exists to protect. **(author's call)** When the filter shows only privacy entries, the export action says there is nothing to export rather than producing an empty file.

### 5.4 Lifetime

**Privacy entries live exactly as long as the privacy results they describe.** **(author's call, following the owner's 2026-11-06 ruling that only the last completed privacy scan is kept)**

- When a new privacy scan completes, the previous scan's entries are removed and the new scan's entries are written, in the same database transaction that completes the scan and removes the previous results. The Timeline never shows two privacy scans, and never a privacy scan whose results are gone.
- **Delete privacy results** removes the entries with the results.
- Nothing else removes them: not the 30-day prune (the results themselves stay visible, dated, until the next scan), not History's "Clear all", not deleting a security scan. The privacy scan is outside scan History, so clearing History does not clear it.
- Consequence, stated plainly: the Timeline shows the latest privacy scan only. It does not show when earlier privacy scans ran, and it cannot answer "when did this tracker first appear" beyond the "new since the previous scan" note. Keeping a one-line dated record of earlier privacy scans would be easy to add later if wanted; it is left out here to keep one rule.
- Every entry can therefore always be opened: its results exist for as long as it does.

### 5.5 How entries are marked and written

- **A new scan source value, `PRIVACY_SCAN`,** on the Timeline's existing source field. This is what the Source filter reads, so the new filter choice follows from it, and it is what keeps privacy entries out of everything that asks for live-scan rows (the 30-day prune, the correlation inputs). **(author's call)**
  - The same source type also labels security scans, imports and stored records. `PRIVACY_SCAN` is used **only** on Timeline entries written by the privacy scan. No security scan, import, stored record or finding ever carries it; a test enforces that.
  - Several places switch over every source value (the filter sheet, the deletion audit text, two places in reporting, one in History). Each gets an explicit branch. In reporting and History the branch can never be reached, because no scan there has this source; it must fail loudly in tests rather than invent a label. Places that treat "not a live scan" as "an import" apply only to security scans and are unaffected, but the builder checks each one.
- **Never tied to a security scan.** A privacy entry's scan reference stays "none". A privacy scan's id must never be stored there: the Timeline's visibility rule would read it as the id of a security scan.
- **Not persistent** in the Timeline's sense (that flag is for audit rows that nothing may delete).
- **Their own categories**, used by nothing else, and in none of the category lists the correlation engine reads.
- **Written by the privacy scan itself**, at completion, in the transaction described in §5.4. Removal goes through the Timeline's single row-deleting component, as every Timeline delete must.
- **No security lock.** The privacy scan still does not take the security scans' writer lock. Its entries reference no stored record and belong to no security scan, so writing and removing them cannot disturb a security scan, an import or a History delete. (Other Timeline entries, such as install events, are already written without that lock.) The builder confirms this holds for the removal path.
- **Entry text is sanitised** the same way as on the privacy screen; app labels are untrusted.
- **The package boundary holds.** Reporting, rules, History and the security store still never reference the privacy package or its tables. The Timeline screen may link to the privacy screen.

## 6. Part C — tracker-list refresh in `/update-rules`

### 6.1 Shape

The tracker list is not threat intelligence and nothing about it is authored: `validation/mirror-exodus-trackers.py` in the rules repository turns Exodus Privacy's published list into `ioc-data/trackers.yml`, deterministically. So it does not go through the pipeline's ingest → author → validate → review path. It becomes **one extra step of the dispatcher**, with one human decision. **(author's call)**

- Runs in `/update-rules full`, and on its own as `/update-rules source trackers`. Not in the `threat` or `discover` modes.
- No scheduled job; a person starts every run. **(owner)**

### 6.2 The step

1. **Build a candidate, away from the live file.** Run the mirror script with its output in the run's scratch directory and the current `ioc-data/trackers.yml` as the previous version. One anonymous request to Exodus; no key.
2. **Failure is reported as a feed failure, not as "no change".** If Exodus cannot be reached, or the script's guards trip (too few trackers; the list shrank by more than a tenth), the live file is untouched, the step reports the failure, and the rest of the run continues.
3. **Validate the candidate** with the rules repository's existing tracker validator. If it fails — the expected case is Exodus introducing a category label the vocabulary does not know — the step stops and tells the person what has to be added by hand (the label, in the rules repository's vocabulary and in the app's category list; the second is an app change and outside the pipeline). Nothing is committed.
4. **No change:** if the candidate is identical to the current file, report "Tracker list: no change" and record the check time.
5. **Change summary.** Otherwise produce a summary a person can review in a minute: trackers added, removed and renamed; category changes; code signatures added and removed; network signatures added and removed, **each added network signature printed in full**; signatures newly set aside as first-party hosts; and the script's report of what it dropped and why. This summary is produced by a small script with its own tests, not composed by the model.
6. **Present** it in the run's results as its own block, apart from rule and indicator candidates, with **one decision for the whole change: approve or skip.** There is no per-tracker editing. `trackers.yml` is never edited by hand.
   - The review that matters is the added network signatures: a signature that matches a domain a company also uses for ordinary services (the `google.com` case) would attribute ordinary traffic to a tracker. The remedy is to add the host to `validation/first_party_hosts.txt` — a person's edit — and run the step again.
   - **Added after the review of this part (author's call):** added code signatures get the same treatment. A code signature that would match a package ordinary apps contain (`androidx.core`, `com.google.android.gms`) would name a tracker in nearly every app. The rules repository keeps a list of such packages (`validation/common_packages.txt`); the mirror sets a matching signature aside, the validator refuses it, and the summary prints every added code signature in full under its own heading. The remedy is the same: a person adds the package to the list and runs the step again.
   - **Added after the review (author's call):** the validator caps a tracker's name (80 characters, no control or formatting characters), website (200) and each signature (253), and the mirror sets aside what breaks a cap, so nothing a person approves is hidden behind a cut in the summary. The mirror also tells a fault in the rules repository's own files (exit code 3) apart from Exodus being unreachable (exit code 2).
   - **Added after the second review round (author's call):** an approval given for rule or indicator candidates ("approve all") does not cover the tracker list; the person approves it by name. A person's edit to one of the two lists is committed in the tracker step and nowhere else: with the list on approval, and with the check time when the edit is what made the candidate equal the list in use; on skip it is left and reported as not committed. Before such a commit the rules repository's whole test suite is run. The mirror sets aside a tracker whose categories are not a list of text, and a `--previous` file that is missing is a fault (exit code 3), not a first run.
   - **Added after the third review round (author's call):** a person's list edit waiting to be committed is shown to the person (`git diff -- validation/`) and committed only on their yes, on approval as well as when the tracker list is unchanged; without it the run commits the check time only. That commit has its own title when the tracker list is unchanged. The mirror keeps each of a tracker's categories once and the validator refuses a repeat; a tracker id must lie between 1 and 999,999,999; and the validator refuses any `ioc-data` file over 1,000,000 bytes, the most the app will fetch.
7. **On approval:** put the candidate in place, regenerate `ioc-data.sha256`, run the validator on the file, record the refresh in `feed-state.json` under a new Exodus entry (the feed-state schema lists feeds by name and rejects unknown ones, so the schema gains the entry), validate the feed state, and commit **as its own commit**, separate from any threat indicators of the same run, so it can be reverted alone.
8. **Skipped on purpose:** the cross-feed de-duplication step and the reference check that indicator candidates go through. Both exist for threat indicators with a cited source; the tracker list is a mirror whose source is the fetched list itself. If the complementarity validator would look at `trackers.yml`, it is told not to.

### 6.3 Delivery

Unchanged, and stated so nothing is assumed:

- The commit travels by the usual safe ordering for rules-repository changes (rules branch → AndroDR pull request that moves the submodule pointer → AndroDR checks green → merge in the rules repository → re-point), with green `validate` on the rules side.
- The AndroDR pull request that moves the submodule pointer also refreshes the bundled copy (`python3 scripts/merge-ioc-data.py`); `TrackerRegistryBundleCrossCheckTest` fails otherwise, and `IocDataManifestIntegrityTest` checks the manifest.
- Phones pick the new list up from the rules repository's main branch within 12 hours, or at once from Settings → update, verified against the manifest; a list that fails the check is not used and the previous one stays.
- A privacy scan already records which list version it used; results are never re-judged against a newer list until the user scans again.

### 6.4 What changes where

- `.claude/commands/update-rules.md`: the new step, the new `source trackers` mode, the results block, the commit rules. If the end-to-end workflow (`.claude/workflows/update-rules-e2e.workflow.js`) performs the same presenting and committing steps, it gains the same step so the two do not drift; the builder checks.
- Rules repository: the change-summary script and its tests; the feed-state schema and file. As first written this said "nothing in the mirror script's matching logic"; the reviews added limits and set-aside rules to the mirror and the validator (§6.2 item 6), kept in `validation/tracker_guards.py`. How the app matches is unchanged.
- No Kotlin change. The pipeline's rule against touching application code stands; refreshing the bundled copy is a data copy done in the AndroDR pull request, as today.

## 7. Order of work

Three pieces, each its own branch, pull request and review:

1. **Part C** (pipeline). Smallest; no app code; useful immediately.
2. **Part A** (details). Database change 22 → 23.
3. **Part B** (Timeline). Touches the Timeline's readers; no database change expected. Its "Open in privacy results" action lands on the app's sheet, which exists today, so B does not strictly need A — but A first makes that landing useful.

The privacy-policy change (§8) is written with Part A, since A is the first piece that stores looked-up domain names past 30 days, and is extended by Part B for the Timeline entries. Neither A nor B may ship in a release before the policy text for it is merged and the Play data-safety declaration is updated; the declaration is edited in the Play console by the owner, so it is a named step on the release checklist, not something the build can do.

A and B ship in an app release and fall under the standing release test battery (emulators, the physical test phone on a clean install, and adversary emulation with fixtures for these changes: at least an app with a known tracker in code, an app flooding junk lookups, and an app whose label is hostile text).

## 8. Amendments to the earlier design

- §3 there said privacy findings "do not enter the Timeline as detections" (an author's call). Still true: they now enter the Timeline as plain information, never as detections. **(owner asked for Timeline presence; trackers still never count toward alerts or the verdict)**
- §5.4 there listed the privacy tables; Part A adds to them. The retention rule is unchanged and now also governs the Timeline entries.
- **`docs/PRIVACY_POLICY.md` and the Play data-safety summary change.** **(owner, 2026-11-10)** Today they say looked-up domain names and Timeline events are deleted automatically after 30 days, that Timeline events are included in exported reports, and they do not mention the privacy scan at all. The new text must say, in the policy's own plain style:
  - what a privacy scan stores on the device: per app, the trackers found, the matching code packages, the tracker domains the app looked up with their counts and times, and the scan's entries in the Timeline;
  - that this is kept until the next privacy scan replaces it or the user chooses "Delete privacy results", and is **not** covered by the 30-day automatic deletion;
  - that the DNS log itself is still deleted after 30 days, and every other Timeline event as today;
  - that privacy results and the privacy scan's Timeline entries are never part of an exported report or Timeline export, and never leave the device;
  - the same correction wherever the 30-day statement appears (the data table, the DNS section, the retention list, and both lines of the Play data-safety summary).
  The live release already stores which trackers each app has without the policy saying so; this change closes that gap too. The policy's "last updated" date moves. The published copies follow by the existing route: `python3 scripts/render_privacy.py docs/PRIVACY_POLICY.md cloudflare-worker.js` in the same pull request (the `check-privacy-sync` workflow fails otherwise; the renderer's expected heading and table counts are updated in the same commit if a section is added), and the same render into the site repository's `index.html`. The policy's closing remark that "AndroDR collects no data" stays true and stays.
- `docs/ARCHITECTURE.md` is updated with the work: the list of what the Timeline table holds gains the privacy entries, and Chapter 12's statement of the Timeline separation is reworded to match §5.3–5.5 here.

## 9. Tests

The regression policy applies: every behaviour ships with a deterministic test wired into the local gates and CI. At minimum:

- **Part A:** detailed matching yields the same trackers as today's matching on the real list (code and domains); the caps (a package list over the cap records the true total; a flood of junk domains cannot displace real ones — the existing property, re-asserted for the stored detail); hostile package and domain text is sanitised; the 22 → 23 migration; details are deleted with their scan and by "Delete privacy results"; a result without details shows the "run a new scan" line, never an empty list that reads as "nothing matched".
- **Part B:** one test per row of the table in §5.3; the lifetime rules of §5.4 (replacement is atomic; the prune, "Clear all" and scan deletion leave the entries; "Delete privacy results" removes them); no entry for system apps or network-only apps; `PRIVACY_SCAN` appears on nothing but privacy Timeline entries; entries never carry a security scan's id; `PrivacyBoundaryTest` unchanged and green.
- **Privacy policy:** a check that fails if the policy stops describing the privacy scan's retention, or states the 30-day automatic deletion without the privacy-scan exception beside it. A document check is a weak gate; it is there so the promise and the behaviour cannot drift apart silently again.
- **Part C:** the change summary from fixture lists (added, removed, renamed, category change, each signature kind, first-party exclusion); the feed-state schema accepts the new entry and still rejects unknown ones; a failed fetch or tripped guard leaves the live file untouched.

## 10. Decided by the owner

- A finding can be tapped to show the ground truth behind it.
- The Timeline gets the privacy scan as a new category of scan.
- Trackers found by the privacy scan do not count toward alerts or the device verdict.
- The tracker-list refresh is part of `/update-rules`; there is no scheduled run.
- Privacy results (including looked-up tracker domains) and the privacy scan's Timeline entries may be kept past 30 days; the privacy policy and the Play data-safety declaration are changed to say so.
- (2026-11-06, unchanged) Only the last completed privacy scan is kept; privacy results stay out of History and the exported security report.

## 11. The author's calls most worth checking

1. **One Timeline entry per app, not per tracker** (§5.2), for user-installed apps with trackers found in code, plus one entry for the scan.
2. **The Timeline shows only the latest privacy scan** (§5.4); its entries are replaced by the next scan and removed by "Delete privacy results", and by nothing else.
3. **Privacy entries are left out of the Timeline's CSV, plain-text and STIX exports** (§5.3).
4. **Entries never mention the threshold** (§5.2), because they cannot follow a later change of the setting.
5. **Details are frozen at scan time**, except the list of recent lookup times, which is read live (§4.1, §4.2).
6. **The tracker refresh is one approve-or-skip decision for the whole change** (§6.2), with problems fixed through the first-party host list, never by editing the list.
7. **Order: pipeline first, then details, then Timeline** (§7).

## 12. Left to the builder

- Table shapes for the stored detail; the exact caps; how the detailed matching is structured, within "must not fork" (§4.2).
- Whether the details view is a second sheet or a full screen; its composition within §4.1; the copy, within the earlier design's wording rules.
- The Exodus per-tracker page address, or dropping the link if none is stable.
- Category names for the two kinds of privacy entry; how the privacy header is merged into the By-scan list; how the exports leave the entries out (at the query, so that reporting code need not know about the privacy scan).
- The exact policy wording, within the points listed in §8; the form of the policy check.
- The shape of the Exodus entry in `feed-state.json`; the name and output format of the change-summary script; the step's position and number in the dispatcher.
