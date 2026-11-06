# Privacy scan: tracker inspection of installed apps — design

Status: approved by the owner 2026-11-06; revised after rounds 1–3 of the four-lens plan gate the same day. Written from a brainstorming conversation with the owner; the owner's decisions are marked **(owner)**, the author's calls **(author's call)**.

## 1. Intent

AndroDR tells a high-risk user whether their phone is compromised. It does not yet tell them which of their ordinary apps are quietly working for someone else: carrying advertising, profiling or analytics kits that report what the user does to companies the user never chose. Google Play's "Data safety" label is self-declared and loosely checked; Play Protect hunts malware, not trackers. Nothing on the phone answers "which of my apps track me, and how" — and the owner's response to a tracking app is not to tame it but to **remove it**.

The privacy scan answers that question with facts, precisely stated, and lets each user apply their own line.

Today AndroDR recognises a handful of surveillance-grade SDKs (data brokers, #168) from what an app **declares in its manifest**. Most tracking kits declare nothing there: they are plain code inside the app. This feature looks inside the code and at the app's network behaviour.

## 2. Goals

1. After one privacy scan, the user can uninstall every app that crosses their own line, knowing exactly why each one did. **(owner's definition of success)**
2. Every finding states its evidence: the tracker, its purpose category, and whether it was **found in the app's code**, **seen on the network**, or both. Both kinds are always listed. **Only code evidence makes an app cross the user's threshold (owner, plan gate 2026-11-06):** network-only evidence can be caused by content the attacker controls (a link preview, a web page, an email image), so a benign app could be framed and the user would uninstall it.
3. The user sets a personal **risk-acceptance threshold** — which tracker categories they refuse — and the report ranks and highlights against that threshold. AndroDR never pronounces an app good or bad on its own. **(owner)**
4. The feature sits in its own screen, functionally separate from security findings. **(owner)**
5. New trackers reach phones through the existing 12-hour feed cycle, without an app release.

## 3. Non-goals and anti-goals

- **No blocking, disabling or "controlling" of trackers.** The owner's model is removal, not control; and Google Play's Device and Network Abuse policy forbids apps that interfere with other apps' ads. AndroDR detects and reports only. **(owner; standing decision from the AdFection ruling, 2026-10-17)**
- **No AndroDR-authored score or rating.** Tolerance differs between people; the app states facts and applies the user's threshold. AndroDR does not rank categories against each other either: apps are ordered by how many refused trackers they carry, not by a "worst category". **(owner; ranking clarified at the plan gate)**
- **Never a security finding.** Presence of a tracker is not compromise. Privacy findings do not raise alerts, do not enter the Timeline as detections, and do not affect the "device appears secure" verdict or the alert counts. **(author's call, consistent with the separation the owner asked for)**
- **Not part of the normal scan.** The normal scan stays lightweight. The privacy scan is a separate, deliberately heavier scan the user starts on purpose. **(owner)**
- **No background re-scanning.** AndroDR does not scan apps continuously today and this feature does not change that: the code inspection runs only when the user starts a privacy scan. Network evidence accrues only while the network monitor the user already enabled is running. **(owner)**
- **No comparison with Play's Data-safety label** in the first version: there is no reliable programmatic way to read it. **(author's call)**
- **No attempt to defeat code obfuscation** beyond what network evidence provides (see §6). **(author's call)**

## 4. The user's experience

### 4.1 Threshold setting ("what I refuse")

A setting listing the tracker purpose categories with a one-line plain explanation of each:

| Category | Plain explanation |
|---|---|
| Advertisement | Shows ads and reports what you do to the ad company |
| Profiling | Builds a profile of you across apps |
| Identification | Fingerprints your device so you can be recognised elsewhere |
| Location | Reports where you are to a third party |
| Analytics | Reports how you use the app to a third party (the same data feeds advertising profiles) |
| Crash reporting | Reports app crashes to the developer |

A seventh entry, **Uncategorised** ("Exodus lists it as a tracker but gives no purpose; many are ad networks"), covers the 116 of 432 Exodus trackers (2026-11-06) that carry no category — among them Google DoubleClick, AppNexus, OutBrain and Ogury. It is **refused by default (owner, plan gate round 2, 2026-11-06)**.

The user ticks the categories they refuse. **Default (author's call): everything ticked except Crash reporting** — the owner's own line (owner: "for-profit, hidden tracking" is out; "bank app troubleshooting, corporate security location, declared crash reporting" are legitimate; analytics is surveillance). The threshold is set from the privacy screen itself (a sheet); it is not duplicated in Settings. **(author's call at the plan gate)** If Exodus adds a new category label, the rules repo's validator stops the update until a person adds the label to the vocabulary (a deliberate review point); an app build older than that vocabulary shows such a label under "Other", **not** refused by default.

Note for the builder: "corporate security location" (a bank checking location to fight fraud) is first-party code, not a third-party tracker, and the registry will not list it; it needs no category.

### 4.2 Where it lives

- A **Dashboard card**: one line of status — "Privacy: 6 apps cross your threshold · 2 new since last scan · 3 could not be inspected · scanned 3 days ago", or "Privacy scan not run yet". The counts are computed live from the stored evidence under the user's *current* threshold and system-app setting, so the card and the screen always agree. The "could not be inspected" clause appears whenever any app failed, so the card can never look clean when inspection failed. Tapping opens the privacy screen.
- The **privacy screen** (full screen, one tap from the Dashboard; the bottom bar keeps its five tabs — UX reasoning: tabs are for things glanced at constantly; a privacy sweep is a periodic review, like Android's own Privacy Dashboard). It has:
  - a **Run privacy scan** action with progress ("Inspecting 83 of 212 apps") and the date of the last completed scan;
  - **By app**: sections in this order — apps that **could not be inspected or were only partly inspected** (with the reason; shown whether or not system apps are included, and counted on the card the same way), then apps crossing the threshold (most refused trackers first; an app that was only partly inspected but already shows refused trackers in its code is listed here, marked "partly inspected", so cutting its own inspection short can never take an app off the list), then the rest; each row shows the tracker count and the refused categories found; tapping shows the app's findings (tracker, website, categories, evidence: "found in code", "looked up domains of this tracker — 14 lookups on 5 days, 3 in background, last 2 h ago", or both);
  - **By tracker**: each tracker with the apps that carry it (useful when one company appears everywhere);
  - a link to the threshold setting;
  - attribution to Exodus Privacy (ODbL requirement, §5.3); a tracker's website is tappable only when it is an `https://` address;
  - a **Delete privacy results** action (the stored package lists reveal what is installed; a user must be able to remove them). **(author's call at the plan gate)**
- The **Apps** tab lists only apps with security findings (there is no per-app page for every installed app), so the crossover is limited to those: an app's finding sheet gains a one-line "Trackers: 3 (1 crosses your threshold)" link, dated with the privacy scan, when the last privacy scan has findings for the version of the app now installed (hidden when the app has been updated since). The privacy screen is the home for everything else; the Apps tab is not widened into an inventory of all apps. **(author's call, after the builder check)**

Results of the last scan stay visible, dated, until the next scan. Network evidence accrues on its own while the monitor runs and is correlated when the privacy scan runs (§5.1).

**System apps.** Every installed app is scanned (owner), but the By-app list defaults to **user-installed apps** — the ones the user can uninstall — with a toggle to include system apps, shown with the note that those can only be disabled, not removed. Otherwise the Dashboard line and the ranked list would be dominated by Google/Samsung system apps carrying Firebase, which the user cannot act on. The Dashboard count follows the same default. **(author's call, after the builder check)**

### 4.3 Wording rules

- Facts, not judgements: "carries AppsFlyer (advertisement, profiling) — found in code", never "this app spies on you".
- Each finding names its evidence source. Network-only evidence is worded as "looked up domains of AppsFlyer", never "carries", with the note "Lookups can be caused by links, web pages or emails the app displays."
- An app whose inspection failed or was cut short never shows "none from the registry found".
- Network coverage is stated, not implied: "Network evidence covers N days" (the number of UTC calendar days in the window with at least one attributed lookup); a separate line when the monitor recorded nothing.
- "New since last scan" compares with the last **completed** scan, and only for apps that scan fully inspected; the first scan marks nothing new.
- Limits shown once on the screen: the obfuscation caveat ("Code inspection can miss trackers whose code has been renamed by the app's build tools"), code loaded at runtime, that apps using encrypted DNS (DNS-over-HTTPS, e.g. Chrome) or reporting through Google Play services are not visible on the network, that domains a tracker shares with its company's ordinary services (e.g. google.com) are not used as evidence, and that tracking by the app's own developer is not covered (§6).

## 5. How it works

### 5.1 Two sources of evidence

**Code inspection (runs during the privacy scan).** For each installed app, AndroDR opens the app's APK file(s) — `base.apk` and any split APKs — reads only the class-name tables of the dex files Android loads (`classes.dex`, `classes2.dex`, … stopping at the first gap; no decompiling, no bytecode), and derives the **set of distinct Java packages present, at full depth** (e.g. `com.google.firebase.analytics` and `com.google.firebase.crashlytics` are distinct entries; the class names themselves are not kept). Deduplicated and capped per app (builder sizes the cap from the largest real apps; thousands of packages for a big app is expected). This fact is **registry-independent** — the emitter does not know what a tracker is, in keeping with the project rule that emitters emit all facts and judgement lives in data — and is cached by package name, version code, install/update time and reader version; only fully inspected results are cached. A registry update therefore needs only a re-join against stored facts, never a re-inspection. **(author's call, after the builder check and plan gate)**

**Hostile APKs.** An attacker can install an app built to break the scan. Byte caps count bytes actually inflated (never the size the zip claims), per dex and per app (one budget shared by the base APK and its splits); any failure — including out-of-memory — costs that app, never the scan; a corrupt dex costs that dex, and the app is shown as partly inspected. A class name the reader does not recognise is skipped, not treated as corruption. Each app has a time limit that the reader itself checks (a blocking read cannot be interrupted from outside). The cached package text has a total size cap; a cache entry that cannot be read is discarded and the app re-inspected.

The mirror script normalises Exodus `code_signature` values (regex-like, matched by Exodus against full class names) into package prefixes per tracker: a class-name signature becomes its package (`com.adobe.mobile.Analytics` → `com.adobe.mobile`) only when that package has at least three segments and is not a parent of another signature of the same tracker — otherwise it is dropped, because it would widen far beyond the tracker (`com.facebook.CampaignTrackingReceiver` → `com.facebook` would flag every React Native app); a lower-case signature that starts with a dot becomes a "package contains this segment" match; anything else that cannot be a Java package (a hyphen, an upper-case dot-led name) is dropped and reported. Measured 2026-11-06: of 36 class-name signatures 20 convert and 16 are dropped; 5 dot-led segments are kept and 3 dropped; 10 trackers are left with no code signature, 3 of them with nothing at all (dropped). **(author's call at the plan gate)**

Verified during design (2026-11-06): APK files are world-readable on Android 13 (physical Samsung, read as AndroDR's own user id) and Android 16 (emulator: app directory `rwxrwxr-x`, `base.apk` `rw-r--r--`). Reading the class tables of YouTube (53 MB of dex) took 0.2 s and Samsung Internet (40 MB) 0.13 s on a desktop; with a prefix index for matching, a large app costs about a second on a phone and a whole phone a minute or two. Real apps ship dex versions 035 to 041 (YouTube 035, Samsung Internet 039), stored uncompressed.

**Network behaviour (accrues continuously while the monitor runs).** The DNS monitor already attributes every lookup to the app that made it, and the DNS log is kept for 30 days. When a privacy scan runs, each **distinct** domain looked up in that window is matched once against the registry's domain signatures — host suffixes on label boundaries, whole labels (Exodus's "contains `.alimama.`" signatures), and a few true patterns in a restricted grammar with no groups, alternation, ranges, lazy quantifiers or backreferences and at most two quantifiers, so matching cannot backtrack badly — producing per app and tracker: lookup count, the number of distinct days, how many happened while the app was not in the foreground, first and last seen. A domain can belong to several trackers; all of them are recorded. Signatures that match a first-party host (e.g. `\.google\.com`, which would attribute every Google lookup to "Google Ads"; `\.facebook\.com`, shared by seven Facebook trackers; Microsoft sign-in; Huawei's `hicloud.com`) are excluded **per signature** by the mirror and never produce network evidence; the tracker's other signatures still do. Background is counted only where usage history actually covers the lookup (a dedicated reader with no system-app filter and no event cap); elsewhere it is "unknown". The DNS log has no size cap, and an app can flood it on purpose, so every read of it is bounded (rows, per-pair timestamps, time); hitting a bound, or any failure in this step, costs the network evidence only — the scan still completes with its code findings, and the screen says the network evidence is incomplete. These aggregates are **stored with the privacy scan result as a dated snapshot** — the screen shows what was known at scan time, consistent with "results stay visible, dated, until the next scan" — rather than recomputed live, so the evidence does not silently shrink as the DNS log ages. **(author's call, after the builder check)**

Both sources are always listed and labelled; only code evidence counts toward the threshold (§2 goal 2).

### 5.2 Tracker registry

The Exodus Privacy tracker database (432 trackers on 2026-11-06; 428 with code signatures, 260 with network signatures; categories as in §4.1, 116 trackers with none, recorded as Uncategorised; after normalisation 428 trackers remain, 113 of them Uncategorised — the 4 dropped include Google Ads, whose only signature, `\.google\.com`, is over-broad) mirrored into the rules repo as an `ioc-data` file — e.g. `ioc-data/trackers.yml` — covered by `ioc-data.sha256` like every other list, so it is manifest-verified and fail-closed on device, and refreshed by the 12-hour feed cycle. Each entry: Exodus id, name, website, categories, code package prefixes and segments, domain suffixes, labels and patterns, and the signatures excluded as over-broad (kept for transparency, never matched). Each privacy scan records which registry version (its hash) it used.

A bundled snapshot ships in the APK for cold start, like the other lists.

The AI pipeline's refresh of this file follows the usual safe ordering; because the data is a mirror of Exodus, the pipeline's job is to pull Exodus's API and diff, not to author entries. **(author's call)**

### 5.3 Licence

Exodus's tracker database is published under the **Open Database License (ODbL 1.0)**; individual entries under the Database Contents License. Consequences: AndroDR attributes Exodus Privacy on the privacy screen and in the rules repo file; the mirrored file is a derivative database and must itself remain under ODbL (a licence notice in the file and the rules repo README). Exodus's *server code* is AGPL, which does not apply: AndroDR uses the data only, with its own code. Compatible with AndroDR's Apache-2.0 licence as long as the data file is kept as a distinct, attributed database.

### 5.4 Fitting AndroDR's architecture

- **Emitters emit facts; judgement lives in data.** The app scanner (privacy-scan mode) emits the package-prefix set as a raw fact; the DNS monitor already emits lookups. The registry is data in the rules repo. The threshold is user data. No tracker name or category is hard-coded in Kotlin.
- **Detection logic stays out of Kotlin**, but note: these are not detection rules — there is no SIGMA rule firing a finding. The privacy screen is a *join* of facts × registry × threshold. The join lives in a dedicated privacy module, not the rule engine: no rule consumes it, and the facts live outside the telemetry store by owner ruling. Feed verification is reused through `IocDataManifest` all the same. **(author's call at the plan gate)**
- **Existing broker rules (#168) are unchanged.** They remain security findings for surveillance-grade SDKs. The privacy scan may show the same SDK as a privacy fact; that is fine and expected.
- **Storage — decided: the privacy scan is its own thing (owner, 2026-11-06).** The telemetry store is keyed by security scans (`ScanResult`, `source = LIVE_SCAN`): everything that reads "the latest live scan" — the Dashboard verdict, the Apps tab, scan diffs, alert re-evaluation, History, the report exporter — would see a privacy scan as a live scan with no findings, i.e. report "secure" and empty the Apps tab. So the privacy scan is **not** a `ScanResult` and does **not** use the telemetry store. It gets dedicated `privacy_*` tables: a scan header, per-app results, per-app tracker evidence (including the network snapshot of §5.1), and a separate package-set cache keyed as in §5.1 that the screen never loads. A source-scan test keeps `com.androdr.privacy` and `privacy_*` out of reporting, rules, History and the security write path. It does not appear in scan History and is not part of the exported security report. No new logsource service, no taxonomy or rules-repo change, no contract-schema migration. Retention: keep the last completed privacy scan (and the facts of the one in progress); older privacy scans are deleted on completion of a new one. **(owner chose option 1 of the two the builder check surfaced)**

### 5.5 Scan mechanics

- Started only by the user from the privacy screen. Runs in an app-wide scope, so leaving the screen does not cancel it, and under its **own** lock (one privacy scan at a time). It does **not** take the security scans' writer lock: it writes nothing the security store holds, and holding that lock for minutes would block security scans, imports and History deletes. **(author's call at the plan gate)**
- Inspects every installed app, system apps included (they carry trackers too); hiding system apps is a display choice on the screen (§4.2), not a scan option.
- Per app: open APK(s), read class tables, derive prefixes, store fact. Failures (unreadable APK, malformed dex) are recorded per app as "could not inspect" and shown as such — never silently dropped (the app's standing rule against false reassurance).
- Memory: read one dex at a time; cap the per-dex and per-app bytes actually read. The class tables are **not** at the start of a dex (string data begins 59–86% of the way into real dex files), so a dex is read whole; caps are sized from the largest real apps (largest dex measured: 9.7 MB).

## 6. Known limits (state them in the UI, do not hide them)

1. **Obfuscation.** Release builds commonly rename third-party packages; a renamed SDK leaves no class-name trace. Exodus has the same limit. Network evidence is the complement; this is why both sources are first-class.
2. **Network evidence needs the monitor.** No monitor, no network evidence; the screen says so.
3. **Registry coverage.** Exodus lists ~430 trackers; unknown kits are not reported. The screen never claims "no trackers", only "none from the registry found".
4. **First-party tracking** (an app reporting to its own developer's servers) is out of scope by definition; it is not a third-party tracker.
5. **Encrypted DNS and shared reporters.** Lookups an app makes over DNS-over-HTTPS (Chrome) never reach the monitor; analytics that upload through Google Play services appear under Play services, not the app.
6. **Code loaded at runtime** (from assets or downloaded) is not inspected.
7. **Network evidence can be caused by content the app displays**, which is why it does not count toward the threshold.

## 7. Decided by the owner (summary)

- All installed apps scanned; manual, separate, heavier scan; not part of the normal scan; no background re-scan.
- Purpose is to decide what to **remove**; no controls.
- Line: advertising, profiling, identification, location and analytics kits are surveillance; declared crash reporting and first-party troubleshooting/fraud checks are legitimate.
- Findings are precise facts; no AndroDR rating; a per-user risk-acceptance threshold turns facts into a ranked list.
- Code and network evidence are both listed; only code evidence makes an app cross the threshold (plan gate, 2026-11-06).
- Own screen, functionally separate; one tap from the Dashboard (owner accepted the author's UX advice).
- Privacy scans are their own thing: own tables, outside scan History and outside the exported security report (option 1).

## 8. Left to the builder

- Exact `privacy_*` table shapes (§5.4).
- The prefix-index data structure for matching; the dex/APK read caps and the per-app package cap; split-APK handling.
- Pipeline script that mirrors Exodus into `ioc-data/trackers.yml` (and its validator entry, manifest regeneration, ODbL notice).
- Screen composition details within the layout in §4.2; copy per §4.3.
- Tests: the regression policy applies (every behaviour ships with a deterministic test); at minimum a dex class-table parser test against a fixture APK, registry cross-check tests between app and rules repo, and threshold/ranking tests.
