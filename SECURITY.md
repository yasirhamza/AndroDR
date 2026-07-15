# Security Policy

## Reporting a vulnerability

**Please do not open a public issue for security vulnerabilities.**

Preferred: use GitHub's private vulnerability reporting —
**Security → Report a vulnerability** on this repository.

Alternatively, email **yhamad.dev@gmail.com** with:

- A description of the issue and its impact
- Steps to reproduce (a PoC APK, rule file, or DNS trace if relevant)
- Affected version (Settings → About in the app, or the release tag)

You can expect an acknowledgement within **72 hours**. Please allow up to
**90 days** for a coordinated fix before public disclosure; most fixes ship
much faster since releases are cut automatically from `main`.

## Supported versions

Only the **latest release** (Play Store and GitHub Releases) is supported.
The app also pulls detection rules and threat intel on a 12-hour cycle, so
many detection-content fixes reach all installs without an app update.

## Verifying release artifacts

> **Status: pending PR 2 of #252** — remove this note when it merges.

Every GitHub release ships a signed APK, a CycloneDX SBOM, and a SLSA
build-provenance attestation. See
[docs/supply-chain.md](docs/supply-chain.md) for verification commands.
The Play upload key is never stored in CI; GitHub releases are signed with
a dedicated CI release key.

## Scope notes

- The DNS-monitoring VPN is local-only; no traffic leaves the device for
  analysis. Reports of data exfiltration by the app itself are always in
  scope and taken seriously.
- Vulnerabilities in bundled detection *rules* (false negatives/positives)
  are welcome as regular issues unless exploitable.
