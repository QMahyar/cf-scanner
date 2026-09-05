# T-27 — arch-paydown-1: split configs.rs (F-27.1)

## Gap
`src/configs.rs` is 1,975 lines with 5+ responsibilities: vless/trojan/vmess/ss
URI parsing, subscription fetch, Xray-JSON normalization, share-link rewrite.

## Fix
Split along natural seams (e.g. `configs/uri.rs`, `configs/subscription.rs`,
`configs/xray_json.rs`, `configs/mod.rs` re-exporting the public API).
Behavior-preservation proof: zero public-API change (same `pub` surface via
re-exports), full test suite green, `git diff --stat` shows moves + mods only.

## Rules
No logic changes in the move commit(s); any drive-by fix gets its own commit
or is left out. ≤5 files touched per commit; multiple commits OK.

## Files
`src/configs.rs` → `src/configs/*`.

## Gates
`cargo test` + `cargo clippy --all-targets -- -D warnings` + `cargo fmt --check`.
