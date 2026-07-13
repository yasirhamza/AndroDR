export const meta = {
  name: 'update-rules-e2e',
  description: 'Research Android threat intel across feeds + open sources, author & validate AndroDR SIGMA rule/IOC candidates for a final human-in-the-loop review (no writes/commits in the workflow)',
  phases: [
    { title: 'Ingest', detail: 'parallel feed ingesters (abuse.ch, ASB, NVD, stalkerware, ATT&CK, Amnesty, PRODAFT)' },
    { title: 'Discover', detail: 'vendor-blog discovery (incl. ThreatFabric, Cleafy, Group-IB) → top-5 emerging threat names' },
    { title: 'Research', detail: 'per-threat + open-web researchers → SIRs' },
    { title: 'Author', detail: 'SIRs → candidate rules + IOC-data entries' },
    { title: 'Dedup', detail: 'drop IOC candidates already pulled on-device via kotlin-mirror-feeds (incl. manual MVT STIX traversal — parser_limited feeds the validator skips)' },
    { title: 'Validate', detail: 'gates 1/1.2/2/3 + independent Gate-5 reviewer per candidate + one author-repair round; IOC structural validation (gate 4 + strict complementarity deferred)' },
  ],
}

// ---- Run-specific state: supplied via `args` by the main session, which must
// read the LIVE feed-state.json and glob the rules index immediately before
// invoking. Workflow scripts cannot call Date.now(), and baked-in constants go
// stale (a previous revision hardcoded a month-old cursor set and a since-
// retired next_id) — so live state is REQUIRED, not optional.
const REPO = '/home/yasir/AndroDR'
const SIGMA = REPO + '/third-party/android-sigma-rules'

const REQUIRED_ARGS = ['today', 'next_id', 'rule_index', 'tracked_threat_names', 'cursors', 'discover_cursors', 'since']
const ARGS = (typeof args === 'undefined' || !args) ? {} : args
const missingArgs = REQUIRED_ARGS.filter(k => !ARGS[k])
if (missingArgs.length) {
  return {
    status: 'error',
    error: 'Missing required args: ' + missingArgs.join(', '),
    usage: {
      today: 'YYYY/MM/DD (current date — scripts cannot read the clock)',
      next_id: 'androdr-NNN — highest existing ID + 1 from globbing <service>/ and staging/ in the submodule; NEVER reuse an ID that existed before and was removed (check git log)',
      rule_index: 'one "androdr-NNN Title" line per existing rule (production service dirs + staging/)',
      tracked_threat_names: 'comma-separated threat names already covered by rules/IOC data',
      cursors: 'object keyed abusech/asb/nvd/stalkerware/attack/amnesty/prodaft — one human-readable cursor summary string per feed, from the live feed-state.json',
      discover_cursors: 'per-source "id: last_seen=... url=..." lines from feed-state.json discover.sources',
      since: 'YYYY-MM-DD lower bound for the open-web sweep (use feed-state.json last_full_sweep)',
    },
  }
}
const TODAY = ARGS.today
const NEXT_ID = ARGS.next_id
const RULE_INDEX = ARGS.rule_index
const TRACKED_THREAT_NAMES = ARGS.tracked_threat_names
const CURSORS = ARGS.cursors
const DISCOVER_CURSORS = ARGS.discover_cursors
const OPEN_WEB_SINCE = ARGS.since

// ---- Schemas (kept loose on item shape to avoid spurious retries) ----
const SIR_OUT = {
  type: 'object',
  required: ['sirs', 'updated_cursors'],
  additionalProperties: true,
  properties: {
    sirs: { type: 'array', items: { type: 'object', additionalProperties: true } },
    updated_cursors: { type: 'object', additionalProperties: true },
    error: { type: 'string' },
    log: { type: 'array', items: { type: 'string' } },
  },
}
const DISCOVER_OUT = {
  type: 'object',
  required: ['threat_names'],
  additionalProperties: true,
  properties: {
    threat_names: { type: 'array', items: { type: 'string' } },
    source_urls: { type: 'object', additionalProperties: true },
    updated_cursors: { type: 'object', additionalProperties: true },
    log: { type: 'array', items: { type: 'string' } },
  },
}
const AUTHOR_OUT = {
  type: 'object',
  required: ['candidates', 'ioc_data'],
  additionalProperties: true,
  properties: {
    candidates: { type: 'array', items: { type: 'object', additionalProperties: true } },
    ioc_data: { type: 'array', items: { type: 'object', additionalProperties: true } },
  },
}
const VALIDATE_OUT = {
  type: 'object',
  required: ['rule_id', 'overall', 'gates'],
  additionalProperties: true,
  properties: {
    rule_id: { type: 'string' },
    overall: { type: 'string' },
    gates: { type: 'object', additionalProperties: true },
    retry_count: { type: 'number' },
  },
}
const REVIEW_OUT = {
  type: 'object',
  required: ['verdict'],
  additionalProperties: true,
  properties: {
    verdict: { type: 'string' },              // pass | pass_with_notes | fail
    false_positive_risk: { type: 'string' },  // low | medium | high
    issues: { type: 'array', items: { type: 'string' } },
    suggestions: { type: 'array', items: { type: 'string' } },
    notes: { type: 'array', items: { type: 'string' } },
  },
}
const REPAIR_OUT = {
  type: 'object',
  required: ['rule_id', 'yaml'],
  additionalProperties: true,
  properties: {
    rule_id: { type: 'string' },
    yaml: { type: 'string' },
    decisions: { type: 'array', items: { type: 'object', additionalProperties: true } },
    skip_note: { type: 'string' },
  },
}
const DEDUP_OUT = {
  type: 'object',
  required: ['additive', 'dropped'],
  additionalProperties: true,
  properties: {
    additive: { type: 'array', items: { type: 'object', additionalProperties: true } },
    dropped: { type: 'array', items: { type: 'object', additionalProperties: true } },
    log: { type: 'array', items: { type: 'string' } },
  },
}
const IOC_VALIDATE_OUT = {
  type: 'object',
  required: ['valid_entries', 'rejected'],
  additionalProperties: true,
  properties: {
    valid_entries: { type: 'array', items: { type: 'object', additionalProperties: true } },
    rejected: { type: 'array', items: { type: 'object', additionalProperties: true } },
    log: { type: 'array', items: { type: 'string' } },
  },
}

const TOOLING = `Tooling: you have Bash, WebFetch, WebSearch, Read, Glob, Write. If WebFetch/WebSearch show up as deferred tools, load them first with ToolSearch ("select:WebFetch,WebSearch"). Use a polite User-Agent for raw fetches: AndroDR-AI-Rule-Pipeline/1.0 (+https://github.com/yasirhamza/AndroDR).`
const INTEGRITY = `INTEGRITY RULES (non-negotiable): NEVER invent, guess, or extrapolate IOCs — include ONLY exact values returned by a source you fetched in THIS session. NEVER use IOCs from training data. NEVER generate SIGMA rules in this role — only SIRs. Tag each IOC with the source URL it came from.`

function ingestPrompt(id) {
  const abuse = id === 'abusech'
  return `You are the "${id}" threat-intel feed ingester for the AndroDR SIGMA pipeline, running inside ${REPO} (rules submodule at ${SIGMA}).

Read ${REPO}/.claude/commands/update-rules-ingest-${id}.md and follow it EXACTLY — it defines the fetch procedure and the precise SIR JSON output shape.

Cursor / last-seen state for this feed:
  ${CURSORS[id]}

Existing AndroDR rule index (id + title), for DEDUP AWARENESS only — do not regenerate these:
${RULE_INDEX}

${TOOLING}
${abuse
    ? `The abuse.ch endpoints (ThreatFox + MalwareBazaar) REQUIRE the header "Auth-Key: $MALWAREBAZAAR_API_KEY". Use Bash + curl (NOT WebFetch) so you can set that header. The key is exported in this shell — first verify: test -n "$MALWAREBAZAAR_API_KEY" && echo present. If empty, abort and return {"sirs":[],"updated_cursors":{},"error":"MALWAREBAZAAR_API_KEY not set"}.`
    : `Check the source's robots.txt where the command instructs. Anonymous access is fine (NVD/GitHub work without tokens at lower rate limits).`}
${INTEGRITY}

Return ONLY the JSON object the command specifies (top-level keys: sirs, updated_cursors, and optionally error/log). Your entire final message must be that JSON object — it is parsed by a program, not read by a human.`
}

function discoverPrompt() {
  return `You are the discover agent for the AndroDR SIGMA pipeline, running inside ${REPO}.

Read ${REPO}/.claude/commands/update-rules-discover.md and follow it EXACTLY, with top_n=5.

rule_index (already-tracked threat names, comma-separated): ${TRACKED_THREAT_NAMES}

cursor_per_source:
${DISCOVER_CURSORS}

${TOOLING}
Use the helper exactly as the command says: python3 ${REPO}/.claude/commands/scripts/discover_extract.py (parse mode for RSS, --validate-tokens for the structural XPIA filter, --check-robots for robots). Run per-post LLM extraction yourself, ONE post at a time (per-post isolation is the XPIA boundary — never batch). EVERY extracted name MUST pass through --validate-tokens before you emit it. Advance a source cursor ONLY if that source parsed successfully.

Return ONLY the JSON the command specifies (threat_names, source_urls, updated_cursors, log). Entire final message = that JSON.`
}

function researchPrompt(name, url) {
  return `You are a threat researcher for the AndroDR SIGMA pipeline, running inside ${REPO}.

Read ${REPO}/.claude/commands/update-rules-research-threat.md and follow it EXACTLY.

threat_name: "${name}"
primary source hint: ${url || '(none — locate authoritative coverage yourself)'}
existing_rule_ids / tracked threats (avoid duplicating coverage): ${TRACKED_THREAT_NAMES}

Search broadly across reliable sources: Kaspersky Securelist, Lookout, Zimperium, ESET/WeLiveSecurity, Dr.Web, Cleafy, ThreatFabric, Bitdefender, Google TAG/GTIG, Amnesty Tech, Citizen Lab, MITRE ATT&CK Mobile, NVD (for CVEs), abuse.ch. ${TOOLING}
${INTEGRITY}
MANDATORY: if a SIR is built entirely from a single unstructured source (one blog/report, no corroborating feed), set "requires_verification": true at the SIR top level.

Return ONLY {sirs, updated_cursors} JSON. Entire final message = that JSON.`
}

function openWebPrompt() {
  return `You are an open-source threat-intel researcher casting a WIDE net for AndroDR, running inside ${REPO}.

Goal: find EMERGING Android malware / spyware / stalkerware / commercial-surveillance campaigns disclosed roughly since ${OPEN_WEB_SINCE} that are NOT already covered by AndroDR and that the configured feeds + the discover source list (Securelist / WeLiveSecurity / Google / Zimperium / Lookout / ThreatFabric / Cleafy / Group-IB) may have MISSED.

Cast wider — search these additional reliable vendors/authorities: Dr.Web, Cleafy, ThreatFabric, Bitdefender, McAfee, Trend Micro, Check Point Research, Group-IB, Palo Alto Unit 42, CISA mobile advisories, NCSC. ${TOOLING}

Already tracked (skip): ${TRACKED_THREAT_NAMES}.

Follow the SIR construction + integrity rules in ${REPO}/.claude/commands/update-rules-research-threat.md. For each distinct threat that has at least one concrete IOC OR a crisp, detectable behavioral pattern, build a SIR.
${INTEGRITY}
Set "requires_verification": true on any SIR built from a single unstructured source.

Return ONLY {sirs, updated_cursors: {}} JSON. Entire final message = that JSON.`
}

function authorPrompt(sirs, nextId) {
  return `You are the Rule Author for the AndroDR SIGMA pipeline, running inside ${REPO} (rules submodule at ${SIGMA}).

Read ${REPO}/.claude/commands/update-rules-author.md and follow it EXACTLY, including the IOC-data-vs-rule Decision Gate that you MUST apply to every SIR.

next_id: ${nextId}  (assign rule IDs sequentially from here; this range is reserved for your shard, so never reuse an id outside it)
today's date: ${TODAY}

Existing rule index (for dedup; do NOT recreate a rule that already exists):
${RULE_INDEX}

Do NOT dedup IOC indicators against the existing ioc-data corpus — a dedicated downstream stage reads the actual ioc-data files and drops anything already present. Emit every indicator your SIRs attribute (correctly typed and formatted); redundancy is removed later, so do not spend time reading c2-domains.yml / malware-hashes.yml / package-names.yml / cert-hashes.yml.

Logsource taxonomy: READ ${SIGMA}/validation/logsource-taxonomy.yml. Only use field names listed there for the target service, and only target services with status: active in that file (do not rely on a memorized list — the taxonomy is the source of truth). Any status: unwired service (currently network_monitor) must NEVER be targeted; record a telemetry_gap decision instead.

Authoring lessons: READ ${SIGMA}/validation/authoring-lessons.yml if it exists — it is curated guidance distilled from past human rejections. Apply every lesson. If the file is missing or unparseable, proceed without it and say so in a log field.

Decision Gate reminder: pure indicator lists (package names / cert hashes / domains / file hashes) → emit ioc_data entries (the generic androdr-001/002/003/004 lookups already match them), do NOT create a per-family rule. Only unique behavioral / TTP / device-posture patterns become SIGMA rules. status must be experimental; author "AndroDR AI Pipeline". Use ONLY the supported modifiers listed in the command.

SIRs to process (JSON array):
${JSON.stringify(sirs)}

Return ONLY {candidates:[...], ioc_data:[...]} JSON as the command specifies. Entire final message = that JSON.`
}

function validatePrompt(c, sirs, slot) {
  const yaml = c.yaml || ''
  // slot disambiguates the temp file when the author emits duplicate or
  // missing rule_ids — parallel validators must never share a path.
  const rid = `${c.rule_id || 'unknown'}-${slot}`
  // Match SIRs the author attributed to this candidate; source_sirs entries may
  // be SIR ids or threat names. Fall back to ALL SIRs only if nothing matches.
  const matched = (Array.isArray(c.source_sirs) && c.source_sirs.length)
    ? sirs.filter(s => s && c.source_sirs.some(ref =>
        ref === s.id || ref === s.sir_id || (s.threat && ref === s.threat.name)))
    : []
  const srcSirs = matched.length ? matched : sirs
  return `You are the rule Validator for the AndroDR SIGMA pipeline, running inside ${REPO} (rules submodule at ${SIGMA}). You NEVER modify the rule — only assess it.

Read ${REPO}/.claude/commands/update-rules-validate.md. Run Gates 1, 1.2, 2, and 3 ONLY.
DO NOT run Gate 4 (the gradle dry-run): it is DEFERRED to the post-approval step in the main session to avoid concurrent gradle builds racing in a shared working tree. Record gates.dry_run = {"pass": null, "skipped": true, "reason": "deferred to post-approval"}.
DO NOT run Gate 5 (self-review): an INDEPENDENT reviewer agent runs it separately in this workflow so it has genuinely fresh eyes. Record gates.self_review = {"pass": null, "skipped": true, "reason": "run independently by the workflow"}.
Authoring lessons: READ ${SIGMA}/validation/authoring-lessons.yml if it exists and apply its guidance when judging the rule. If missing or unparseable, proceed without it and note that in your output.

Write the candidate YAML to a UNIQUE temp file: /tmp/cand-${rid}.yml (do NOT use a shared filename — other validators run in parallel). Then:
  python3 ${SIGMA}/validation/validate-rule.py /tmp/cand-${rid}.yml
If the candidate carries a non-empty decisions array, also validate it via ${SIGMA}/validation/validate-decisions.py (wrap under a decisions: key in a temp file). Include validator stderr verbatim in any failure.

Gate 2: verify every concrete IOC in the rule exists in the source SIR(s) below; permission names against ${SIGMA}/validation/android-permissions.txt; ATT&CK tags match attack.tNNNN[.NNN].
Gate 3: check ID collision / exact-duplicate / subsumption against the existing rule index below.

sigma_repo_path: ${SIGMA}
existing rule index:
${RULE_INDEX}
source SIR(s) (JSON):
${JSON.stringify(srcSirs)}

Candidate YAML:
---
${yaml}
---

Return ONLY the ValidationResult JSON (rule_id, overall, gates{schema,ioc_verify,dedup,dry_run,self_review}, retry_count). Base "overall" on Gates 1/1.2/2/3 only (the skipped gates are merged by the workflow). Entire final message = that JSON.`
}

function reviewPrompt(c, sirs) {
  const related = sirs
    .filter(s => s && s.threat && s.threat.name)
    .map(s => `- ${s.threat.name}: ${(s.threat.description || '').slice(0, 200)}`)
    .slice(0, 10)
    .join('\n')
  return `You are an INDEPENDENT reviewer for the AndroDR SIGMA pipeline (Gate 5), running inside ${REPO} (rules submodule at ${SIGMA}). You have NOT seen the Rule Author's reasoning or any validator gate results — review with completely fresh eyes.

Read ${REPO}/.claude/commands/update-rules-review.md and apply ALL of its review criteria exactly (the skill file is authoritative — do not assume a fixed count).
Also READ ${SIGMA}/validation/authoring-lessons.yml if it exists and apply its guidance; if missing, proceed without it.

For "similar_rules" context, pick 2-3 same-category entries from this index and read their YAML files in the submodule (production rules live in service-named dirs at the repo root, staged ones under staging/<service>/):
${RULE_INDEX}

SIR summaries (source threat intel context):
${related || '(none provided)'}

Candidate YAML:
---
${c.yaml || ''}
---

Return ONLY {verdict, false_positive_risk, issues, suggestions, notes} JSON per the review command's output section. Entire final message = that JSON.`
}

function repairPrompt(candidate, validation, sirs) {
  return `You are the Rule Author for the AndroDR SIGMA pipeline, running inside ${REPO} (rules submodule at ${SIGMA}).

Read ${REPO}/.claude/commands/update-rules-author.md and follow it EXACTLY.
Also READ ${SIGMA}/validation/authoring-lessons.yml if it exists and apply its guidance.

Your earlier candidate FAILED validation. Fix ONLY the reported failures — do not redesign the rule, change its ID, or touch passing aspects. If a failure cannot be fixed without inventing data (e.g. an IOC the SIRs never contained), return the original yaml unchanged plus a skip_note explaining why.

today's date: ${TODAY}

FAILED candidate (rule_id ${candidate.rule_id || 'unknown'}):
---
${candidate.yaml || ''}
---

ValidationResult (fix every gate with pass=false; validator stderr is included verbatim):
${JSON.stringify(validation)}

Source SIRs (the ONLY permitted data source for indicators):
${JSON.stringify(sirs)}

Return ONLY {rule_id, yaml, decisions, skip_note?} JSON. Entire final message = that JSON.`
}

function dedupPrompt(iocs) {
  return `You enforce the IOC complementarity invariant for the AndroDR SIGMA pipeline, running inside ${REPO} (rules submodule at ${SIGMA}). AndroDR's on-device Kotlin "bypass" feed clients fetch some upstreams DIRECTLY, so any ioc-data entry that duplicates them is REDUNDANT and must be dropped.

Proposed IOC-data candidates (JSON array):
${JSON.stringify(iocs)}

The candidates above are pre-filtered to DOMAIN and PACKAGE-NAME types only — file/cert hashes are dropped from your input upstream because NO mirror feed carries them (always additive), so you never need to handle hashes here.

Step 1 — read ${SIGMA}/validation/kotlin-mirror-feeds.yml. It lists the feeds the app pulls on-device and the IOC TYPES each delivers.

Step 2 — build the authoritative on-device coverage set U for the candidate types present (domains, package names). CRITICAL: feeds tagged 'parser_limited: true' (currently mvt-indicators and threatfox) are SKIPPED by validate-ioc-complementarity.py, but the Kotlin client still delivers them on-device — so you MUST fetch them MANUALLY rather than trusting the Python parser:
  - mvt-indicators: fetch https://raw.githubusercontent.com/mvt-project/mvt-indicators/main/indicators.yaml (a dict with key 'indicators'). Each item has a 'github' ref {owner,repo,branch,path}; build the raw URL https://raw.githubusercontent.com/<owner>/<repo>/<branch>/<path> and fetch that STIX2 JSON. From each object of type 'indicator', regex the pattern for domain-name:value and (for package candidates) app/process names. Union every bundle. (As of last run there were 15 bundles incl. a dedicated "Wintego Helios" bundle — MVT mirrors AmnestyTech/investigations, so Amnesty-sourced domains very often ALREADY live in MVT.)
  - threatfox: its on-device parser is currently broken vs the live schema (#127), so it delivers 0 — treat threatfox C2 domains as ADDITIVE for now, but say so in the log.
  - stalkerware-indicators: fetch https://raw.githubusercontent.com/AssoEchap/stalkerware-indicators/master/ioc.yaml directly (PACKAGE_NAME only) if any package candidates exist.
Use Bash + python3 + urllib for the fetch/traversal (a polite User-Agent). ${TOOLING}

Step 3 — for each candidate, drop it if its normalized (type,value) is in U. Keep the rest.

Return ONLY {additive:[...full candidate objects that survive...], dropped:[{indicator, type, reason}], log:[...per-feed counts + which manual fetches you ran...]}. Entire final message = that JSON.`
}

function iocValidatePrompt(iocs) {
  return `You validate proposed IOC-data entries for the AndroDR SIGMA pipeline, running inside ${REPO} (rules submodule at ${SIGMA}). Read-only: NEVER modify the real ioc-data files.

Proposed entries (JSON array):
${JSON.stringify(iocs)}

For each entry, route to its target file under ${SIGMA}/ioc-data/ by type:
  package_name → package-names.yml ; cert_hash → cert-hashes.yml ; domain → c2-domains.yml ; file_hash → malware-hashes.yml
Per-entry checks (reject with a reason if any fail):
  1. Required fields present per ${SIGMA}/validation/ioc-entry-schema.json: indicator, category, severity, source ("family" is optional but recommended; "familyName" is NOT a valid key — the schema rejects unknown properties). "source" MUST appear in ${SIGMA}/validation/allowed-sources.json.
  2. category MUST be in the schema enum (STALKERWARE, SPYWARE, MALWARE, NATION_STATE_SPYWARE, FORENSIC_TOOL, MONITORING, DATA_BROKER_SDK — no TROJAN; label trojans/RATs as MALWARE); family must NOT contain test/fixture/simulation/sample/example.
  3. cert hashes: 64 lowercase hex (SHA-256) or 40 (SHA-1).
  4. NOT already present in the target file — READ the target file and dedup by normalized indicator (this is the local authoritative-coverage filter; the strict upstream complementarity check is deferred to the commit step in the main session).

Structural validation of the SURVIVORS: write surviving entries (preserving the target file's header shape) to a temp file per target type and run:
  python3 ${SIGMA}/validation/validate-ioc-data.py <tmpfile>
Include validator stderr in your log. Do NOT run validate-ioc-complementarity.py here (it may need reachable upstream; deferred to commit). Do NOT touch the real files.

Return ONLY {valid_entries:[...], rejected:[{entry, reason}], log:[...]}. Entire final message = that JSON.`
}

// ============================ ORCHESTRATION ============================

phase('Ingest')
const INGEST_IDS = ['abusech', 'asb', 'nvd', 'stalkerware', 'attack', 'amnesty', 'prodaft']
const ingestRaw = await parallel(
  INGEST_IDS.map(id => () => agent(ingestPrompt(id), { label: `ingest:${id}`, phase: 'Ingest', schema: SIR_OUT }))
)
const ingestResults = ingestRaw.map((r, i) => ({ id: INGEST_IDS[i], r }))
const feedLogs = []
for (const { id, r } of ingestResults) {
  if (!r) { feedLogs.push(`[ingest:${id}] FAILED (agent error/skip)`); continue }
  if (r.error) { feedLogs.push(`[ingest:${id}] feed error: ${r.error}`); continue }
  feedLogs.push(`[ingest:${id}] ${(r.sirs || []).length} SIR(s)`)
}

phase('Discover')
const discover = await agent(discoverPrompt(), { label: 'discover:top5', phase: 'Discover', schema: DISCOVER_OUT })
const threatNames = (discover && discover.threat_names ? discover.threat_names : []).slice(0, 5)
log(`Discover surfaced ${threatNames.length} threat name(s): ${threatNames.join(', ') || '(none)'}`)

phase('Research')
const researchThunks = [
  ...threatNames.map(name => () =>
    agent(researchPrompt(name, discover.source_urls && discover.source_urls[name]),
      { label: `research:${name}`.slice(0, 60), phase: 'Research', schema: SIR_OUT })),
  () => agent(openWebPrompt(), { label: 'research:open-web', phase: 'Research', schema: SIR_OUT }),
]
const researchRaw = await parallel(researchThunks)

// ---- Collect + triage SIRs ----
const allSirs = [
  ...ingestRaw.filter(Boolean).flatMap(r => r.sirs || []),
  ...researchRaw.filter(Boolean).flatMap(r => r.sirs || []),
].filter(s => s && s.confidence !== 'none')

log(`Collected ${allSirs.length} usable SIR(s) after triage`)

const proposedCursors = {}
for (const r of [...ingestRaw, discover, ...researchRaw].filter(Boolean)) {
  if (r.updated_cursors) Object.assign(proposedCursors, r.updated_cursors)
}

if (allSirs.length === 0) {
  return {
    status: 'no_new_intel',
    summary: { feeds_checked: INGEST_IDS.length, discover_names: threatNames.length, new_sirs: 0 },
    feed_logs: feedLogs,
    discover_log: (discover && discover.log) || [],
    proposed_cursors: proposedCursors,
    note: 'No usable threat intelligence found this run. Cursors above can still be advanced. Nothing to approve.',
  }
}

phase('Author')
// Shard the SIRs across parallel author agents. The author is read-heavy and its
// output (often hundreds of IOC entries) is generated sequentially, so a single
// agent over all SIRs is the pipeline's slowest stage. Fan-out turns wall-clock
// from sum-of-all-SIRs into slowest-single-shard. Each shard gets a disjoint
// rule-id range so sequential id assignment can never collide across shards.
const AUTHOR_SHARD_SIZE = 8
const ID_BASE = (() => {
  const m = /(\d+)\s*$/.exec(NEXT_ID || '')
  return m ? parseInt(m[1], 10) : NaN
})()
const ID_PREFIX = (NEXT_ID || 'androdr-089').replace(/(\d+)\s*$/, '')
const ID_STRIDE = 50 // per-shard id headroom; far above any single-shard rule count
function shardNextId(shardIndex) {
  return Number.isNaN(ID_BASE) ? NEXT_ID : `${ID_PREFIX}${String(ID_BASE + shardIndex * ID_STRIDE).padStart(3, '0')}`
}
const sirShards = []
for (let i = 0; i < allSirs.length; i += AUTHOR_SHARD_SIZE) sirShards.push(allSirs.slice(i, i + AUTHOR_SHARD_SIZE))
log(`Author: ${allSirs.length} SIR(s) → ${sirShards.length} parallel shard(s) of ≤${AUTHOR_SHARD_SIZE}`)

const authoredShards = await parallel(
  sirShards.map((shard, i) => () =>
    agent(authorPrompt(shard, shardNextId(i)), { label: `author:shard${i}`, phase: 'Author', schema: AUTHOR_OUT })
  )
)
const candidates = authoredShards.filter(Boolean).flatMap(a => a.candidates || [])
const iocDataRaw = authoredShards.filter(Boolean).flatMap(a => a.ioc_data || [])
log(`Author produced ${candidates.length} rule candidate(s) + ${iocDataRaw.length} IOC-data entr(ies) across ${sirShards.length} shard(s)`)

phase('Dedup')
// The mirror-feed dedup's cost is the manual on-device coverage fetch (MVT's ~15
// STIX bundles + stalkerware), which only covers DOMAINS and PACKAGE NAMES. Per
// the stage's own Step 1, NO mirror feed carries file/cert hashes, so those are
// always additive — route them straight through and only send the dedup agent
// the types it can actually drop. On a hash-only run the expensive agent is
// skipped entirely.
const needsMirrorDedup = (t) => !/hash/i.test(t || '')
const alwaysAdditive = iocDataRaw.filter(e => !needsMirrorDedup(e.type))
const dedupCandidates = iocDataRaw.filter(e => needsMirrorDedup(e.type))
let iocData = iocDataRaw
let dedupResult = { additive: dedupCandidates, dropped: [], log: ['no domain/package candidates to dedup'] }
if (dedupCandidates.length) {
  dedupResult = await agent(dedupPrompt(dedupCandidates), { label: 'dedup:mirror-feeds', phase: 'Dedup', schema: DEDUP_OUT })
  const survivors = (dedupResult && dedupResult.additive) || []
  iocData = [...alwaysAdditive, ...survivors]
  log(`Mirror-feed dedup: ${survivors.length}/${dedupCandidates.length} domain+package additive, ` +
    `${(dedupResult.dropped || []).length} dropped; ${alwaysAdditive.length} hash entr(ies) bypassed (always additive)`)
} else {
  log(`Mirror-feed dedup skipped: all ${alwaysAdditive.length} candidate(s) are file/cert hashes (always additive)`)
}

phase('Validate')

function mergeAssessment(c, v, r, retryCount) {
  const validation = v || { rule_id: c.rule_id || 'unknown', overall: 'error', gates: {}, retry_count: 0 }
  validation.gates = validation.gates || {}
  validation.gates.self_review = r
    ? { pass: r.verdict !== 'fail', verdict: r.verdict, fp_risk: r.false_positive_risk || 'unknown', suggestions: r.suggestions || [], issues: r.issues || [] }
    : { pass: false, verdict: 'error', fp_risk: 'unknown', suggestions: [], issues: ['review agent failed or was skipped'] }
  const gatesPass = !!v && validation.overall === 'pass'
  const reviewPass = !!r && r.verdict !== 'fail'
  validation.overall = (gatesPass && reviewPass) ? 'pass' : 'fail'
  validation.retry_count = retryCount
  return { candidate: c, validation }
}

// Validator and independent reviewer run concurrently per candidate:
// slots [2i] = validation, [2i+1] = review. IOC validation rides last.
const assessThunks = candidates.flatMap((c, i) => [
  () => agent(validatePrompt(c, allSirs, `a${i}`), { label: `validate:${c.rule_id || 'rule'}`, phase: 'Validate', schema: VALIDATE_OUT }),
  () => agent(reviewPrompt(c, allSirs), { label: `review:${c.rule_id || 'rule'}`, phase: 'Validate', schema: REVIEW_OUT }),
])
const iocValidationThunk = iocData.length
  ? [() => agent(iocValidatePrompt(iocData), { label: 'validate:ioc-data', phase: 'Validate', schema: IOC_VALIDATE_OUT })]
  : []

const assessRaw = (assessThunks.length || iocValidationThunk.length)
  ? await parallel([...assessThunks, ...iocValidationThunk])
  : []
const iocValidation = iocData.length
  ? (assessRaw[assessRaw.length - 1] || { valid_entries: [], rejected: [], log: ['ioc validation agent failed or was skipped'] })
  : { valid_entries: [], rejected: [], log: [] }

const firstRound = candidates.map((c, i) => mergeAssessment(c, assessRaw[2 * i], assessRaw[2 * i + 1], 0))
const passed = firstRound.filter(rv => rv.validation.overall === 'pass')
let failed = firstRound.filter(rv => rv.validation.overall !== 'pass')

// One author-repair round for failures (dispatcher Step 6 contract: a second
// failure is final). Repaired candidates are re-validated AND re-reviewed.
if (failed.length) {
  log(`${failed.length} candidate(s) failed first assessment — one repair round`)
  const repairs = await parallel(failed.map(rv => () =>
    agent(repairPrompt(rv.candidate, rv.validation, allSirs),
      { label: `repair:${rv.candidate.rule_id || 'rule'}`, phase: 'Validate', schema: REPAIR_OUT })))
  const retryPairs = []
  const unrepairable = []
  repairs.forEach((rep, i) => {
    if (rep && rep.yaml && !rep.skip_note) {
      retryPairs.push({ candidate: { ...failed[i].candidate, yaml: rep.yaml, decisions: (Array.isArray(rep.decisions) && rep.decisions.length) ? rep.decisions : failed[i].candidate.decisions } })
    } else {
      if (rep && rep.skip_note) failed[i].validation.repair_skip_note = rep.skip_note
      unrepairable.push(failed[i])
    }
  })
  const reRaw = retryPairs.length ? await parallel(retryPairs.flatMap((p, i) => [
    () => agent(validatePrompt(p.candidate, allSirs, `b${i}`), { label: `revalidate:${p.candidate.rule_id || 'rule'}`, phase: 'Validate', schema: VALIDATE_OUT }),
    () => agent(reviewPrompt(p.candidate, allSirs), { label: `rereview:${p.candidate.rule_id || 'rule'}`, phase: 'Validate', schema: REVIEW_OUT }),
  ])) : []
  const secondRound = retryPairs.map((p, i) => mergeAssessment(p.candidate, reRaw[2 * i], reRaw[2 * i + 1], 1))
  passed.push(...secondRound.filter(rv => rv.validation.overall === 'pass'))
  failed = [...unrepairable, ...secondRound.filter(rv => rv.validation.overall !== 'pass')]
  log(`After repair round: ${passed.length} passed, ${failed.length} failed`)
}

return {
  status: 'candidates_ready',
  summary: {
    feeds_checked: INGEST_IDS.length,
    discover_names: threatNames.length,
    new_sirs: allSirs.length,
    rule_candidates: candidates.length,
    rules_passed: passed.length,
    rules_failed: failed.length,
    ioc_authored: iocDataRaw.length,
    ioc_dropped_redundant: (dedupResult && dedupResult.dropped ? dedupResult.dropped.length : 0),
    ioc_additive: iocData.length,
    ioc_valid: (iocValidation && iocValidation.valid_entries ? iocValidation.valid_entries.length : 0),
    ioc_rejected: (iocValidation && iocValidation.rejected ? iocValidation.rejected.length : 0),
  },
  feed_logs: feedLogs,
  discover_log: (discover && discover.log) || [],
  dedup_log: (dedupResult && dedupResult.log) || [],
  dropped_redundant: (dedupResult && dedupResult.dropped) || [],
  passed_candidates: passed,
  failed_candidates: failed,
  ioc_candidates: iocValidation,
  proposed_cursors: proposedCursors,
  deferred_to_main_session: [
    'Gate 4 (gradle dry-run via GateFourFixtureTest) for each approved rule',
    'validate-ioc-complementarity.py --mode strict for each approved IOC entry (needs reachable upstream)',
    'HiTL approve/modify/reject per candidate, then write to staging/ + ioc-data/, re-validate, and commit to the submodule',
    'Run ledger write to pipeline-runs/YYYY-MM-DD-e2e.yml after HiTL decisions (dispatcher Step 8.3)',
    'Lessons curation + approval-rate trend (dispatcher Step 8.4)',
  ],
}
