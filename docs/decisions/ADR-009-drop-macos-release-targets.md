# ADR-009: Drop macOS release targets

## Status
Accepted

## Date
2026-08-15

## Context
The release matrix (ADR-007) shipped 5 targets, two of them macOS
(aarch64-apple-darwin, x86_64-apple-darwin). The product review
(2026-08-13, Domain 1) found macOS blocked-by-default: the binaries are
unsigned and not notarized, so Gatekeeper refuses both `cf-scanner` and the
bundled `xray` (quarantine propagates to the downloaded child binary).
Signing requires Apple Developer certificates and a paid account — not
available. Each macOS release therefore published artifacts most users
cannot run, with a silent failure mode (no docs, README only covers
SmartScreen on Windows).

## Decision
- Remove `aarch64-apple-darwin` and `x86_64-apple-darwin` from the
  `targets` list in `dist-workspace.toml`. The matrix becomes
  `aarch64-unknown-linux-gnu`, `x86_64-unknown-linux-gnu`,
  `x86_64-pc-windows-msvc`.
- Record the restore condition: if Apple signing/notarization becomes
  available, add the two targets back and re-verify Gatekeeper behavior.
- Update `docs/release-process.md` (matrix, post-publish verification) to
  match the 3-target reality.

## Alternatives Considered

### Keep macOS targets and document the limitation
- Pros: coverage exists for users willing to bypass Gatekeeper
- Cons: ships broken-by-default artifacts from a "self-contained" pipeline;
  the review rated this a major gap with no fix path without certificates
- Rejected

### Sign with a self-signed certificate
- Pros: silences the quarantine warning locally
- Cons: not trusted by Gatekeeper for downloaded binaries; no real fix
- Rejected

## Consequences
- Releases now cover Linux (aarch64 + x86_64) and Windows (x86_64) only.
  macOS users must build from source; that path is documented in
  `docs/development.md` (cross-target builds).
- One fewer platform to maintain in `build.rs::xray_asset` and the WiX/MSI
  path (Windows unchanged).
- If Apple tooling is later acquired, the restore is a two-line matrix
  change plus re-verification, not a redesign.