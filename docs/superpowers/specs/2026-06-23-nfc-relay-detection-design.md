# NFC-Relay Detection (androdr-087) — Design Spec

**Date:** 2026-06-23
**Status:** Approved design, pending implementation plan
**Branch:** `feat/nfc-relay-detection`

## 1. Motivation

NFC-relay fraud is the fastest-growing Android threat class of 2025–2026 — SuperCard X (Cleafy), Ghost Tapped (Group-IB, 54+ variants), NGate (ESET), DevilNFC/NFCMultiPay. A reader/tapper app pair relays a victim's contactless payment-card APDU traffic to a criminal's POS/ATM in real time. AndroDR has **zero** coverage of this class today.

Critically, these families **evade permission-count heuristics**: their footprint is minimal (NFC + INTERNET + FOREGROUND_SERVICE + an HCE service), and SuperCard X had *zero* VirusTotal detections at disclosure. The distinguishing capability is a **Host Card Emulation (HCE) service** — `HostApduService`, which on Android is always protected by `android.permission.BIND_NFC_SERVICE`.

## 2. Key finding (shapes the design)

HCE is detectable with **no new scanner subsystem**. The scanner already emits every declared `<service>`'s `android:permission` in the `service_permissions` telemetry field (consumed today by rule 067 for `BIND_NOTIFICATION_LISTENER_SERVICE`). A `HostApduService` is declared with `android:permission="android.permission.BIND_NFC_SERVICE"`, so `service_permissions|contains: "BIND_NFC_SERVICE"` matches it. Detection therefore lives in YAML, honoring the "detection logic is rule-driven, not hardcoded Kotlin" principle (ARCHITECTURE §2.1).

## 3. The rule — `androdr-087` (`app_scanner`)

A multi-condition composite. Per the severity convention (§7), `high` requires multiple conditions across distinct dimensions; a lone capability + sideloaded would be `medium`.

```yaml
title: Sideloaded app emulating a contactless payment card (NFC relay)
id: androdr-087
status: experimental
category: incident
logsource:
  product: androdr
  service: app_scanner
detection:
  selection:
    is_sideloaded: true                                  # provenance: untrusted source
    service_permissions|contains: "BIND_NFC_SERVICE"     # capability: HCE / HostApduService
    permissions|contains: "NFC"                          # capability: NFC access
  filter_known_good:
    package_name|ioc_lookup: known_good_app_db           # trust: not a vetted app
  condition: selection and not filter_known_good
level: high
falsepositives:
  - "Sideloaded but legitimate contactless apps: third-party wallets, transit/payment
     cards, crypto hardware-wallet companions, and tap-to-pay tools installed outside
     an app store. Popular ones are suppressed by filter_known_good."
display:
  category: app_risk
  icon: contactless        # finalize against the icon set during implementation
  triggered_title: "NFC Card Emulation (Sideloaded)"
  evidence_type: none
remediation:
  - "This sideloaded app can emulate a contactless payment card (NFC HCE). NFC-relay
     malware abuses this to relay your bank card to a criminal's payment terminal in
     real time. If you didn't install a wallet you trust, uninstall it:
     Settings > Apps > [this app] > Uninstall."
implies_flags:
  - sideloaded
references:
  - https://www.cleafy.com/cleafy-labs/supercardx-exposing-chinese-speaker-maas-for-nfc-relay-fraud-operation
  - https://www.group-ib.com/blog/ghost-tapped-chinese-malware/
tags:
  - <MITRE Mobile ATT&CK technique — finalize against rule-schema's allowed tags during implementation>
```

The composite is the NFC-relay fingerprint: a **sideloaded, unvetted app that holds NFC access AND registers a card-emulation service**. Four conditions across two dimensions (capability + trust). `BIND_NFC_SERVICE` is the primary, specific signal; HCE always co-declares `NFC`, so requiring both adds no false negatives.

## 4. Scanner change (one line)

Add `Manifest.permission.NFC` to the existing `highRiskPermissions` set in `AppScanner.kt` (the hook introduced by the androdr-069 fix). This surfaces `"NFC"` (short-named) in the `permissions` field. It is **load-bearing** — a required condition in the rule — not speculative. `surveillancePermissionCount` is unaffected (NFC is not a surveillance permission).

## 5. IOCs (rules-repo `ioc-data/c2-domains.yml`)

Add the verified NFC-relay C2 domains, `source: "threat_research"` (an existing entry in `allowed-sources.json`). Feeds the existing domain-IOC rule (androdr-003) for DNS detection; ships via the 12h feed.

- `nfc.rc8820.com`, `xxnfc.com`, `txnfc.com` (Ghost Tapped / Group-IB)
- `api.kingcardnfc.com`, `kingnfc.*`, `payforce-x.*` (SuperCard X / Cleafy)
- `register-buzzy.store` (Crocodilus dropper, research-verified)

Domains only — IP filtering is parked (DNS-only scope). `nfcrackatm.com` (DevilNFC) is already present.

## 6. Tests & verification (full cycle)

- **Unit (gate4 fixture):** `nfc-relay.yml` — TP: sideloaded app with `service_permissions: [BIND_NFC_SERVICE]` + `permissions: [NFC]`; TNs: system app, trusted-store app, known-good app, and a sideloaded app missing the HCE service.
- **Scanner unit test:** an app declaring `android.permission.NFC` exposes `"NFC"` in `permissions` (and does not change `surveillancePermissionCount`).
- **Adversary fixture:** new `nfc-relay` module — manifest declares a `<service android:permission="android.permission.BIND_NFC_SERVICE">` with an `android.nfc.cardemulation.action.HOST_APDU_SERVICE` intent-filter + `<uses-permission android:name="android.permission.NFC"/>`. (Manifest-only; the scanner reads declared components statically.)
- **Emulator smoke harness** + **real-device scan**: install the fixture, run a scan, confirm androdr-087 fires for it and does NOT fire for a Play-installed HCE app (e.g. Google Pay).
- **4-agent review ceremony** (correctness / quality / architect / code-security) before commit.

## 7. Severity convention (established here)

Single capability signal + sideloaded → `medium`. Multiple conditions across distinct dimensions → `high`. This codifies the detection reviewer's guidance from the androdr-069 review (see issue #226, the overlay+accessibility combo) and the user's directive. androdr-087 is `high` because it requires four conditions.

## 8. Delivery

- **AndroDR PR:** the rule (`res/raw`), the `AppScanner.kt` one-liner, register the rule in `SigmaRuleEngine`'s bundled list, gate4 fixture, scanner unit test, adversary `nfc-relay` fixture (+ `settings.gradle.kts`).
- **Companion rules-repo PR:** staging mirror of androdr-087 (per the rule-repo mirror convention) + the `ioc-data/c2-domains.yml` additions.

## 9. Out of scope (deferred)

- **`is_default_payment_app` / RoleManager scanner field** — catches the NGate/HandyPay zero-permission, role-only variant. Genuinely new scanner code; a fast-follow if warranted.
- **IP-based IOCs** — IP filtering is parked indefinitely; DNS-only.
- A broad-net `medium` "lone sideloaded HCE" rule — unnecessary (HCE always co-declares NFC), YAGNI.
