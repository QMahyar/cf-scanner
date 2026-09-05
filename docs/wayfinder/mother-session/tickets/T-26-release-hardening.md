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
