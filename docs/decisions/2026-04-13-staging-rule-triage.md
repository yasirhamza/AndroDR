# Staging Rule Triage — 2026-04-13

**Context:** 5 AI-generated rules sat in `android-sigma-rules/staging/` since
2026-04-02. Sub-plans 1a and 1b updated the validator and added Gate 4 harness
support. This triage re-validates each rule and records promote/reject decisions.

**Tracking:** Epic #104, sub-plan 1c (#107).

## Triage Results

| Rule | ID | Validator | Gate 4 | Decision | Notes |
|------|----|-----------|--------|----------|-------|
| Cellebrite CVEs | 051 | PASS (after adding `category`) | PASS | **Promoted** | Added `category: device_posture`. Strong detection, specific CVEs, Amnesty reference. |
| DDNS C2 | 070 | PASS (after adding `category`) | PASS | **Promoted** | Added `category: incident`. `endswith` modifier correct for DDNS suffixes — not migrated to `ioc_lookup` because these are TLD-like patterns, not individual domain IOCs. |
| Overlay Permission | 069 | PASS (after adding `category`) | PASS | **Promoted at medium** | Added `category: incident`, demoted `high` → `medium`. Sideload + known-good filter limits FP, but single permission is still broad. |
| Boot Persistence | 066 | PASS (after adding `category` + condition fix) | PASS | **Promoted at low** | Added `category: incident`, demoted `medium` → `low`. Merged two selections into one (evaluator lacks parenthesis support). Boot receivers extremely common; useful as triage signal, not standalone alert. |
| Popular App Impersonation | 071→077 | PASS (after renumber + `category`) | PASS | **Renumbered + Promoted** | Renumbered from 071 (collides with production `crash_loop_anti_forensics`) to 077 (next available). Added `category: incident`. |

## Common Fix Applied

All 5 rules were missing the top-level `category` field, which became required
when sub-plan 1a synced the schema. This is the expected failure mode — staging
rules predate the schema update. The build-time gate now prevents this class of
drift.

## Evaluator Limitation Discovered

Rule androdr-066 used parenthesised condition: `(selection_boot or selection_locked_boot) and not filter_known_good`. The `SigmaRuleEvaluator` does not support parentheses in condition expressions — it splits by OR before AND without respecting grouping. Fix: merged both selections into a single selection using a YAML list for `intent_action`. This is functionally equivalent and evaluator-compatible.

This is a latent limitation that could affect future AI-generated rules. Consider adding parenthesis support to the evaluator or a parse-time rejection of parenthesised conditions.

## End-to-End Pipeline Run

**Feed:** stalkerware-indicators (AssoEchap)
**Cursor:** `348fd7b` → `b8635c5` (1 new commit, 2026-04-10)

The ingester found 11 new stalkerware entries. Of these:
- 4 had C2 domain indicators: mSpyitaly, SpyTek, Android007/SpyBunker, RioSPY
- 6 had website-only data (no technical indicators) — skipped
- 1 (SpyTec) excluded as potentially legitimate GPS tracker

**Result:** 9 new C2 domains added to `ioc-data/c2-domains.yml`. No new SIGMA
rule generated — the domains extend existing rule `androdr-003` (domain IOC
lookup via `domain|ioc_lookup: domain_ioc_db`) automatically.

This demonstrates the pipeline's triage logic correctly: when new indicators
match an existing rule's detection pattern, the pipeline updates IOC data rather
than generating redundant rules.

## Summary

- 5 staging rules promoted to production (53 total bundled rules)
- 9 new C2 domains added to IOC data (4 new stalkerware families)
- Feed cursor updated
- Gate 4 fixtures written for all 5 promoted rules (8 total fixtures)
- First AI-generated SIGMA rules successfully promoted via the end-to-end pipeline
