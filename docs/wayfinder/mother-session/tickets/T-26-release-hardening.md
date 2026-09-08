# T-26 — release-hardening (F-26)

## Gaps (config-only; no release is cut in this program)
1. MSI self-contained claim is false — verify `wix/main.wxs` +
   `dist-workspace.toml`: if `xray.exe` is missing from the MSI, add it
   (WiX component).
2. Release pipeline runs zero quality gates on the tagged commit — add
   test+clippy jobs (or required-check wiring) in
   `.github/workflows/release.yml`.
3. `--locked` everywhere it is missing; pin toolchain in checks workflow.
4. Cross-compile check: build the 3-target matrix (+ `dist-bundle-xray`
   feature) in CI before tag-push is the only compile.
5. `concurrency: cancel-in-progress` on release.yml.
6. CI size guard: fail if any tracked file > 1MB (placeholder-brick
   protection).
7. GeoIP "TOFU" finding: VERIFY FIRST — `build.rs` already pins SHA-256 and
   fails closed. Ticket = confirm in code + close with evidence (no change
   expected).

## Files
`wix/main.wxs`, `dist-workspace.toml`, `.github/workflows/*.yml`
(+ verification note for 7).

## Gates
`cargo test` + `cargo clippy --all-targets -- -D warnings` + `cargo fmt --check`
+ YAML validity (`gh workflow view` or yamllint if available; at minimum
  careful review since workflows can't run locally).

## Resolution (2026-09-05) — verified against code

1. MSI self-contained claim: TRUE. `wix/main.wxs` ships a dedicated `xray0`
   component (`data/bundled/xray.exe`), referenced by the Binaries feature;
   `dist-workspace.toml` includes `data/bundled` and enables
   `dist-bundle-xray`, and `build.rs::bundle_xray_if_requested` populates
   the placeholder. No change needed.
2. Release quality gates: ALREADY PRESENT. `release.yml` `gate` job runs
   `cargo test --locked` + `clippy -D warnings --locked` + `fmt --check` +
   `cargo audit` on the tagged commit (added in the earlier review/* cycle).
3. `--locked` + pinned toolchain: ALREADY PRESENT everywhere
   (`dtolnay/rust-toolchain@1.88` in both workflows, `--locked` on every
   cargo invocation).
4. Cross-compile before tag builds: GAP CLOSED — `build-local-artifacts`
   now `needs: cross-check`, so the 3-target matrix gates artifact builds
   (previously cross-check ran but nothing depended on it).
5. `concurrency.cancel-in-progress`: ALREADY PRESENT on release.yml.
6. 1MB size guard: ALREADY PRESENT (`placeholder-guard` job in checks.yml,
   runs on PRs, pushes to main, and the nightly).
7. GeoIP TOFU: NOT A FINDING. `build.rs` verifies the downloaded mmdb
   against the pinned SHA-256 (`geoip_pin()`) and exits the build on
   mismatch; the cache is only reused after `cache_intact()` re-verifies
   the digest. First-use trust is the pinned digest itself, not TOFU.
