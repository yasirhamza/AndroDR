# Documentation Refresh — Design Spec

**Date:** 2026-04-24
**Status:** Approved (pending spec review)
**Scope:** Rewrite contributor and user-facing documentation; consolidate the privacy policy into a single source of truth; create a proper architecture document; clean up drift.

---

## 1. Context and motivation

Three drivers push this work simultaneously:

- **Play Store prep.** Privacy policy must be accurate, internally consistent, and aligned with the Data Safety form when submission happens.
- **External audience.** Journalists, researchers, and potential contributors looking at the public face (site + repo) currently see stale or inconsistent content.
- **Internal cleanliness.** The code has drifted ahead of the docs since March: the SIGMA rule engine, IOC pipeline, bugreport analysis, forensic timeline, and AI rule-authoring pipeline are all either absent from or misrepresented in README / CONTRIBUTING / CLAUDE.md.

Concrete drift identified during discovery:

- `README.md` module tree lists `vpn/` (the code moved to `network/`) and omits `sigma/`, `ioc/`, `scanner/bugreport/`, `ui/timeline`, `ui/settings`, `ui/permissions`, `di/`.
- `CONTRIBUTING.md` has a 4-bullet "Architecture Principles" section that duplicates (and contradicts) content in README.
- `CLAUDE.md` project-layout section predates the SIGMA engine, IOC pipeline, and bugreport module entirely.
- `docs/PRIVACY_POLICY.md` is dated 2026-03-26, still describes the MalwareBazaar cert-hash feed as a "stub" (it has been active since commit `8f5b6c9`), omits bugreport analysis as a retained feature, and carries a hallucinated contact email (`privacy@androdr.dev`) that is not owned by the project.
- The privacy policy exists in **three places** that are already drifting: `docs/PRIVACY_POLICY.md` (2026-03-26 version), `androdr-privacy/index.md` (identical manual mirror), and `androdr-site/index.html` (embedded inline, 2026-04-01 version, with the correct contact email). Same document, three sources, already out of sync.
- `docs/ROADMAP.md` contradicts the project-wide convention that GitHub Issues are the canonical roadmap; the tables are a stale snapshot.
- `docs/play-store/` contains duplicate numbered/unnumbered versions of five files (leftover from a rename that didn't clean up).
- `androdr-site` has two near-identical deploy workflows (`pages.yml` and `static.yml`).

---

## 2. Goals

1. Single source of truth for the privacy policy, rendered automatically into the public site.
2. Accurate, non-duplicated architecture narrative that reflects current code.
3. Contributor guide that covers real dev setup, PR workflow, and both manual and AI-assisted rule-authoring paths.
4. Minimum-viable cleanups that remove drift sources without expanding scope.
5. Correct contact email (`yhamad.dev@gmail.com`) everywhere; removal of the hallucinated `privacy@androdr.dev`.

## 3. Non-goals (scope discipline)

- No Kotlin code changes.
- No changes to `docs/decisions/`, `docs/research/`, or other `docs/superpowers/` content.
- No audit of `docs/detection-rules-catalog.md` (file a follow-up issue).
- No Cloudflare Worker code changes (only verify cache behavior post-cutover).
- No new documentation files beyond `docs/ARCHITECTURE.md`.
- No new linting/checking tools or contributor-facing process rules. (The two new workflows in PR A — `notify-privacy-sync.yml` in AndroDR and `render-privacy.yml` in `androdr-site` — are internal plumbing for the privacy single-source-of-truth, not rules contributors have to follow.)

---

## 4. File responsibilities (no duplication)

After this work, each fact lives in exactly one place. Other files reference it.

| File | Audience | Contents | Approx. size |
|---|---|---|---|
| `README.md` | Users first, curious devs second | What AndroDR is, who it's for, what it detects, short architecture sketch, download, pointers | ~150 lines |
| `docs/ARCHITECTURE.md` (new) | Contributors, researchers, reviewers | The canonical architecture reference | ~600 lines |
| `CONTRIBUTING.md` | Devs about to contribute | Rule authoring (manual + AI-assisted), dev setup, PR workflow, code of conduct | ~300-400 lines |
| `CLAUDE.md` | AI agents working in the repo | Build commands, workflow conventions, submodule handling, smoke test. Architecture section reduced to a pointer. | current length, minus the architecture sections |
| `docs/PRIVACY_POLICY.md` | Users, Play Store reviewers | The privacy policy. The single source of truth rendered into the site. | current structure, updated content |

---

## 5. PR A — Privacy publishing pipeline

Cross-repo work. Lands first.

### 5.1 Changes in `AndroDR` repo

1. **`docs/PRIVACY_POLICY.md` content update.** Keep the existing section structure (philosophy → what we do → data → permissions → network → DNS → bugreport → exports → what we don't collect → sharing → retention → transparency → Play Data Safety → children → GDPR/CCPA → contact). Content edits:
   - Replace all `privacy@androdr.dev` references with `yhamad.dev@gmail.com`.
   - "What AndroDR Does": mention the SIGMA rule engine briefly; mention STIX2 indicator import/export; clarify DNS monitor remains optional.
   - "Data That Stays On Your Device" table: add rows for forensic timeline events (persisted per #79) and bugreport analysis findings.
   - "Network Requests" table: remove the "(planned)" stub; add MalwareBazaar APK hash feed as active; add abuse.ch ThreatFox; update the MVT entry to reflect the IOC dispatcher model; add stalkerware-indicators cert-hash ingestion.
   - "Bug Report Analysis" section: tighten wording; reinforce that only analysis findings persist (no raw bugreport text).
   - "Google Play Data Safety Alignment": expand to mirror the declarations in `docs/play-store/18-data-safety-form.md` so the two stay consistent.
   - Update `_Last updated:_` to the merge date.

2. **Sweep `docs/play-store/store-listing.md`** for `privacy@androdr.dev` and replace with `yhamad.dev@gmail.com` (this PR, not PR B, because it's an email-fix).

3. **New workflow `.github/workflows/notify-privacy-sync.yml`.** Triggers on push to `main` when `docs/PRIVACY_POLICY.md` changes. Fires a `repository_dispatch` to `yasirhamza/androdr-site` with event type `privacy-updated` so the render runs immediately. The daily cron in the site repo is a safety net, not the happy path.

### 5.2 Changes in `androdr-site` repo

4. **Fence the privacy section in `index.html`.** Add HTML comments around the existing `<section class="privacy" id="privacy">` block:

   ```html
   <!-- ANDRODR:PRIVACY:START -->
   <section class="privacy" id="privacy">
     ...existing content...
   </section>
   <!-- ANDRODR:PRIVACY:END -->
   ```

   No content change to the privacy HTML in this commit — just fence markers so the next commit (the first automated render) can cleanly replace between them.

5. **New `scripts/render_privacy.py`** — small Python script. Responsibilities:
   - Read `docs/PRIVACY_POLICY.md` content (passed as argument or fetched via API by the workflow).
   - Convert Markdown to HTML using the PyPI `markdown` package with the `tables` extension (pin version in `scripts/requirements.txt`).
   - Wrap output in `<section class="privacy" id="privacy">...</section>` so existing CSS classes apply.
   - Assert structural invariants before writing. Counts are locked in at first run (observed: 18 `<h2>` headings, 3 `<table>` blocks as of 2026-04-24). Script exits non-zero if invariants fail — a content restructure is deliberate and requires updating the assertion counts in the same commit.
   - Update the `Last updated: YYYY-MM-DD` line inside the rendered section from the markdown's `_Last updated: YYYY-MM-DD_` line.
   - Output: modified `index.html` with the fenced region replaced.

6. **New workflow `.github/workflows/render-privacy.yml`.** Triggers:
   - `push` to main (so edits to the renderer itself take effect)
   - `repository_dispatch` with type `privacy-updated` (fires from AndroDR repo)
   - `schedule` daily at a quiet UTC hour (safety net)
   - `workflow_dispatch` (manual trigger for testing)

   Steps:
   - Checkout `androdr-site`.
   - Fetch `docs/PRIVACY_POLICY.md` from `yasirhamza/AndroDR` using `gh api` (authenticated with `GITHUB_TOKEN`, required because the shadowban blocks anonymous raw.githubusercontent.com reads).
   - Run `scripts/render_privacy.py` → modified `index.html`.
   - If `index.html` changed, commit (`docs(privacy): sync from AndroDR@<shortsha>`) and push to main. The existing Pages deploy workflow handles publishing.

7. **Delete `.github/workflows/static.yml`.** Keep `pages.yml` as the only deploy workflow.

### 5.3 Archive `androdr-privacy`

8. Replace `androdr-privacy/index.md` with a one-line forwarding pointer:

   > Moved. See https://github.com/yasirhamza/AndroDR/blob/main/docs/PRIVACY_POLICY.md

9. `gh repo archive yasirhamza/androdr-privacy --confirm`. Repo remains publicly visible (subject to the shadowban) but is frozen. The URL does not 404.

### 5.4 Verification (PR A)

- Run `scripts/render_privacy.py` locally against current `docs/PRIVACY_POLICY.md`, diff output against today's `<section class="privacy">` — expect structural parity.
- `workflow_dispatch` the render workflow on a branch before merging; inspect the commit it produces.
- After merge, make a trivial whitespace edit to `docs/PRIVACY_POLICY.md` in a throwaway branch, merge it, and confirm the site commit fires within minutes and Cloudflare-fronted site reflects the change.
- Grep: zero matches for `privacy@androdr\.dev` anywhere in either repo after merge.
- API check: `androdr-privacy` is archived.

---

## 6. PR B — Documentation sweep

In-repo prose edits. Lands after PR A is verified.

### 6.1 `docs/ARCHITECTURE.md` (new) — ~600 lines

Chapter outline:

1. **Overview (~50 lines).** One-paragraph description of AndroDR, single block diagram (ASCII) showing the major layers (device → telemetry emitters → rule engine + IOC resolver → findings → persistence → UI/reports), reader's map ("this document covers X; CONTRIBUTING covers how-to; PRIVACY_POLICY covers user-facing guarantees").

2. **Design principles (~40 lines).** Non-negotiables with one-line rationales:
   - Detection logic in YAML SIGMA rules, not Kotlin code.
   - IOC data lives in the external rules repo, not bundled in the APK.
   - Pure-emitter telemetry/findings contract (forward-reference #136, #137).
   - All processing on-device — no backend, no telemetry, no accounts.
   - Privacy-by-design: minimum collection, retention boundaries, no cloud backup.
   - SIGMA compatibility where practical.

3. **Module map (~80 lines).** Accurate tree matching today's code:
   `data/`, `di/`, `ioc/`, `ioc/feeds/`, `network/`, `reporting/`, `scanner/`, `scanner/bugreport/`, `sigma/`, `ui/apps`, `ui/bugreport`, `ui/common`, `ui/dashboard`, `ui/device`, `ui/history`, `ui/network`, `ui/permissions`, `ui/settings`, `ui/theme`, `ui/timeline`. One-liner per package.

4. **Detection pipeline (~120 lines) — the centerpiece.** End-to-end flow from raw device state to a user-visible finding:
   - **Telemetry emitters** (`scanner/*`, `network/*`): pure functions producing structured telemetry events (AppTelemetry, DeviceFlag, DnsEvent, BugreportTelemetry). Why pure: the rule engine is the only place detection logic runs; emitters are trivially testable.
   - **SIGMA rule engine** (`sigma/*`): parser (`SigmaRuleParser`), evaluator, modifier support, schema cross-check test. Field alignment with the `android-sigma-rules` submodule.
   - **IOC resolver** (`ioc/*`): feeds, dispatcher with cross-dedup, cursor/decisions schemas, four IOC types (package name, cert hash, C2 domain, APK file hash), resolution lifecycle.
   - **Findings**: Room persistence, serialization contract, display metadata from rules, remediation text.
   - ASCII flow diagram showing all four lanes.

5. **Data layer (~50 lines).** Room schema, what's persisted vs. transient, auto-prune policy, STIX2 indicator model.

6. **Reporting & export (~40 lines).** `ReportFormatter`, `ReportExporter`, FileProvider, timeline, STIX2 export, user-initiated share flow.

7. **DNS monitor (~40 lines).** `LocalVpnService`, local-only DNS interception, why DNS-only (link to the parked IP-filtering decision), how DNS events flow into the rule engine like any other telemetry.

8. **Bugreport analysis (~60 lines).** Pipeline stages (parse → extract → match → emit findings), what's parsed (dumpsys sections, processes, wakelocks), what's discarded (original bugreport never persisted), how findings reuse the same rule-engine pathway.

9. **AI rule-authoring pipeline (~80 lines).** What lives in `.claude/`: the ingester skills (`/update-rules-ingest-*`), discover agent (`/update-rules-discover`), author agent (`/update-rules-author`), validator (`/update-rules-validate` — the 5-gate pipeline), reviewer (`/update-rules-review`), orchestrator (`/update-rules`). Rule lifecycle: threat intel feed → candidate SIR → draft rule → validation gates → staging → promotion. Link to the rules repo. CONTRIBUTING's AI section points here for depth.

10. **Test strategy (~40 lines).** Unit tests, integration tests, `BundledRulesSchemaCrossCheckTest`, validation gates on rules, UAT persona testing (`/uat-test`), on-device smoke test (`scripts/smoke-test.sh`).

11. **Decisions (~60 lines).** ADR-style short entries: rule engine in YAML, IOC data external, DNS-only VPN scope, pure-emitter contract, SIGMA compatibility, no cloud backend. Absorbs the useful "Architecture Notes" paragraph from the old ROADMAP.md. Forward-references open arch issues (#96, #136, #137) without pretending they're done.

### 6.2 `README.md` rewrite — ~150 lines

Sections:
1. Title + badges (License, Android 8.0+).
2. Tagline (keep current wording).
3. Who it's for (DV survivors / journalists / IT security / privacy-conscious — keep current wording, it's good).
4. What it detects — refreshed bullets:
   - Known malware (package, cert, APK hash)
   - Stalkerware
   - Mercenary spyware (Pegasus, Predator, Graphite, NoviSpy, ResidentBat)
   - Sideloaded apps from untrusted sources
   - Surveillance permission combinations
   - Accessibility / Device Admin abuse
   - Device posture (screen lock, USB debug, bootloader, patch level)
   - Unpatched CVEs (CISA KEV catalog)
   - DNS C2 (optional local VPN monitor)
   - Spyware file artifacts
   - **Bugreport analysis** (new — forensic analysis of `.zip` bugreports)
   - **Forensic timeline** (new — device admin grants, etc., per #79)
5. How it works — tighten current 2-paragraph version, same thrust.
6. Architecture (brief) — short fresh tree + 4 principle bullets, link out to `docs/ARCHITECTURE.md`.
7. Building — the six gradle commands; anything beyond moves to CONTRIBUTING.
8. Download — releases link + Cloudflare mirror note.
9. Privacy — one line pointing to the rendered public site.
10. Contributing — one line pointing to `CONTRIBUTING.md`.
11. License — one line.

### 6.3 `CONTRIBUTING.md` rewrite — ~300-400 lines

Sections:
1. Intro — short; why the project matters; users include DV survivors, journalists, activists. Safety-first ethos.
2. Ways to contribute — taxonomy of contribution types.
3. **Writing detection rules — manual path.**
   - Real rules repo URL.
   - Minimal example rule (refreshed to current schema — includes `display` + `remediation` blocks).
   - Field reference: summary + pointer to `validation/rule-schema.json` in the submodule as authoritative spec.
   - Logsource conventions (services + products taxonomy per #108).
   - Registering in `rules.txt`.
   - Local validation steps.
4. **Writing detection rules — AI-assisted path.**
   - "We use AI to author rules in our own workflow. You're welcome to, too."
   - The schema + existing rules are the context any LLM needs.
   - A short copy-pasteable prompt pattern (not overspecified).
   - All rules — AI-written or hand-written — go through the same validation gates; AI does not skip review.
   - For the internal pipeline details (not needed to contribute), pointer to `docs/ARCHITECTURE.md` §9.
5. IOC data contributions — `ioc-data/{package-names,cert-hashes,c2-domains,malware-hashes,popular-apps}.yml`, dedup / cross-write ownership rules.
6. False-positive reports — template, triage process.
7. Bug reports — template, what to include.
8. Development setup — JDK 21, Android SDK (compile SDK 34), `local.properties`, clone + `git submodule update --init`, Android Studio vs command-line flow.
9. Build & test — gradle commands, lint, detekt, smoke test (`scripts/smoke-test.sh`, AVD `Medium_Phone_API_36.1`), on-device testing, submodule update direction (AI pipeline → AndroDR is pinned).
10. PR workflow — branch naming, target `main`, `Closes #N` keyword, CI `build` check must pass, small focused PRs.
11. Architecture principles — one-line pointer to `docs/ARCHITECTURE.md` (no duplication).
12. Code of conduct — keep current strong wording on user safety; no tracking contributions accepted.

### 6.4 `CLAUDE.md` trim

- **Keep:** build requirements, common commands, development workflow, lint/style, running on physical device, local development (SDK setup, smoke test, submodule handling — Claude Code agents actually use these).
- **Replace** the "Project layout" tree and "Key architectural decisions" section with a single line:
  > See [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) for architecture, module map, and design principles.

### 6.5 `docs/ROADMAP.md` — delete

- Extract the useful "Architecture Notes" paragraph at the tail into `docs/ARCHITECTURE.md` §11 (Decisions) and §4 (rule engine capabilities) as appropriate.
- Delete `docs/ROADMAP.md` entirely.
- Fix any inbound links. Known references:
  - `docs/detection-rules-catalog.md` has six `[ROADMAP #N]` text markers — **leave alone** (they're historical context, issue numbers still resolve).
- No other inbound links found as of 2026-04-24.

### 6.6 `docs/play-store/` dedupe

Pairwise compare numbered vs unnumbered versions, merge forward if unnumbered has unique content, then delete the unnumbered copies:
- `query-all-packages-declaration.md` (keep `16-…`)
- `vpn-service-declaration.md` (keep `17-…`)
- `data-safety-form.md` (keep `18-…`)
- `content-rating-iarc.md` (keep `19-…`)
- `store-listing.md` (keep `20-…`)

Keep: `manage-external-storage-declaration.md`, all media files, all numbered files.

### 6.7 Commit structure for PR B

Split PR B into logical commits so the review diff tells a story:
1. `docs(architecture): add docs/ARCHITECTURE.md`
2. `docs(readme): rewrite README to reflect current code + link to ARCHITECTURE`
3. `docs(contributing): rewrite CONTRIBUTING with manual + AI rule authoring paths`
4. `docs(claude): trim CLAUDE.md architecture section to pointer`
5. `docs: delete stale docs/ROADMAP.md`
6. `docs(play-store): deduplicate numbered and unnumbered filename variants`

### 6.8 Verification (PR B)

- Link check: grep for internal Markdown links after ROADMAP deletion and play-store dedupe; confirm no broken links.
- Every architecture claim in README/CONTRIBUTING/ARCHITECTURE verified against current source tree (not against today's stale docs). Spot-check: module map, SIGMA engine description, IOC pipeline narrative, bugreport analysis stages.
- CLAUDE.md still renders cleanly in a new Claude Code session (no syntax issues).
- `git diff` each play-store pair before deletion; confirm no unique content lost.
- `./gradlew lintDebug` passes.
- Open a follow-up issue: "Audit `docs/detection-rules-catalog.md` for drift from current rule catalog."

---

## 7. Risks and mitigations

| Risk | Mitigation |
|------|-----------|
| Privacy markdown renderer produces HTML that breaks site styling | Script includes structural assertions (expected `<h2>`/`<h3>`/`<table>` counts); dry-run before merge |
| Shadowban blocks render workflow's authenticated GH API calls | Workflow uses `GITHUB_TOKEN`; test on branch first |
| Cloudflare Worker caches stale HTML after site rebuild | Workflow can optionally call Cloudflare purge API; otherwise wait for TTL. Verify manually on first cutover. |
| ARCHITECTURE.md claims something wrong (e.g., wrong module boundary) | Cross-reference every claim against current source while drafting; request code-reviewer pass after draft |
| ROADMAP deletion breaks an inbound link we missed | Full grep before delete |
| `androdr-privacy` archive breaks an external backlink | Leave archived, not deleted; forwarding `index.md` stays in place; URL still resolves |
| Bad privacy email still appears after sweep | Post-change grep returns zero matches for `privacy@androdr\.dev` |
| play-store dedupe silently drops content unique to unnumbered file | Pairwise `diff` of each pair; manual merge-forward before delete |
| PR B is too large to review | Six focused commits (§6.7) so reviewer can walk the history |

## 8. Cutover order

1. Open and land **PR A**. Verify privacy pipeline end-to-end (edit markdown → site commit fires → Cloudflare serves fresh).
2. Only after PR A is verified, open **PR B**. Any privacy content tweaks that surface during PR B work flow through the now-working pipeline.
3. After PR B merges: confirm CI `build` is green; open the follow-up issue for `detection-rules-catalog.md` audit.

## 9. Open questions / follow-ups

- **Cloudflare cache purge:** whether to add a `cloudflare/purge` step to the render workflow is deferred. If the Worker's TTL is short enough the daily cron + manual verification is sufficient; if stale content sticks for more than a few hours after a merge, add the purge step in a follow-up.
- **detection-rules-catalog.md audit:** out of scope here; follow-up issue filed at end of PR B.
- **Spec/plan split for PR B:** the writing-plans skill will turn this spec into a concrete step plan. Expectation is PR A gets its own plan; PR B gets its own plan; the AI can sequence them.
