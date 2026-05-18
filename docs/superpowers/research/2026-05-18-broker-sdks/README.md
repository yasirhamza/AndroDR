# Data-broker SDK SIRs — research pass 2026-05-18

Structured Intelligence Records (SIRs) for the 8 entities named in issue #168,
produced as input to the future `installed_app` rule pack (6 SDKs) and the
future `dns` rule pack (2 aggregators). Both reviewer cycles
(spec-compliance + harsh-quality) passed.

## Files

### SDKs (anchor the future `installed_app` rule pack)

- [`outlogic.json`](outlogic.json) — Outlogic (X-Mode Social): high confidence; 3 component-class prefixes (`io.xmode.BcnConfig`, `io.xmode.locationsdk`, `io.mysdk.`), 5 telemetry domains, 9 known consumer packages; verify:false.
- [`venntel.json`](venntel.json) — Venntel (Gravy GOLD legacy SDK): high confidence; 2 component-class prefixes (`com.timerazor.gravysdk`, `com.gravy.gravysdk`), 5 domains, 1 package; verify:false. Note: Venntel itself is largely an aggregator; the anchors here pin the legacy on-device collector only.
- [`mobilewalla.json`](mobilewalla.json) — Mobilewalla: high confidence; 0 on-device anchors, 1 corporate domain, 1 server-side reference; verify:true. ~95% of Mobilewalla's data sourced from RTB bidstream per FTC complaint; no first-party Android SDK fingerprint published.
- [`adsquare.json`](adsquare.json) — Adsquare: high confidence; 0 on-device anchors, 2 corporate domains; verify:true. Aggregator-only posture confirmed by vendor statement + own GitHub artifacts being server-side Java + absence from Exodus Privacy tracker DB.
- [`predicio.json`](predicio.json) — Predicio (Telescope SDK): high confidence; 3 component-class prefixes (`com.telescope.android`, `io.predic.tracker`, `io.predic`), 2 domains, 1 package; verify:false. SDK and parent company largely defunct post-2021 Google/Apple ban; historical detection still valuable.
- [`cuebiq.json`](cuebiq.json) — Cuebiq: high confidence; 2 component-class anchors (`com.cuebiq.cuebiqsdk.model.Collector`, `com.cuebiq.cuebiqsdk.receiver.CoverageReceiver`); verify:false. No telemetry domain documented in reachable structured sources.

**Cohort anchor result:** 4 of 6 SDKs (Outlogic, Venntel, Predicio, Cuebiq) carry concrete on-device anchors — meets the spec's ≥4-of-6 acceptance criterion. Mobilewalla and Adsquare have documented gaps with `requires_verification: true` per spec policy.

### Aggregators / consumers (anchor the future `dns` rule pack)

- [`gravy-analytics.json`](gravy-analytics.json) — Gravy Analytics (Unacast, Venntel parent): high confidence; 4 domains, 12 historical consumer packages from January 2025 breach extraction; verify:true (mandatory — no on-device collector of its own).
- [`babel-street.json`](babel-street.json) — Babel Street (LocateX product): high confidence; 6 corporate/portal domains; verify:true (mandatory — buys broker data, no on-device collector). Domains are analyst-side, not target-side, so high-FP for end-user devices.

## References

- **Spec:** [../../specs/2026-05-18-broker-sdk-sir-research-design.md](../../specs/2026-05-18-broker-sdk-sir-research-design.md)
- **Scanner prereq (PR #183):** [../../specs/2026-05-17-data-broker-sdk-scanner-design.md](../../specs/2026-05-17-data-broker-sdk-scanner-design.md)
- **Plan:** [../../plans/2026-05-18-broker-sdk-sir-research.md](../../plans/2026-05-18-broker-sdk-sir-research.md)
- **Issue:** [#168](https://github.com/yasirhamza/AndroDR/issues/168)

## Handoff

Next session opens `update-rules-author` against the 6 SDK SIRs to produce the
`installed_app` rule pack. The `requires_verification:true` flag on Mobilewalla
and Adsquare instructs the author to record a `telemetry_gap` decision for
human review instead of writing thin rules. The 2 aggregator SIRs sit unused
until the future `dns` rule pack session opens.

Concatenate the 8 SIR files into an array for batch consumption:

```bash
jq -s '.' docs/superpowers/research/2026-05-18-broker-sdks/*.json > /tmp/broker-sdk-sirs.json
```
