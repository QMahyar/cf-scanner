# Phase 06 — Fetch error hygiene (central URL strip)

Back to [[plans/01-findings-hardening/overview]]

## Goal
Reqwest errors must never leak embedded URLs (userinfo/query tokens) to stderr.

## Findings addressed
- **F12 (low)**: reqwest 0.12 Display appends ` for url ({url})` with the raw URL serialization (userinfo + query intact) on send/redirect errors (verified in reqwest sources). `ranges/http.rs:200` and `check_sub.rs:38-41` add sanitized context layers, but `main.rs` prints the whole chain (`{err:#}`), so a failing fetch of `https://user:pass@host/sub?token=x` prints credentials. `validate_fetch_url` gates scheme/host but does not strip userinfo/query.

## Changes
- `src/ranges/http.rs` (`fetch_tls_inner`): on send/body-read failure, strip the trailing ` for url (...)` segment and rebuild a fresh error carrying only `sanitize_url_for_error(url)` (userinfo/credentials removed) — dropping the original reqwest source so the raw URL can never re-enter the chain. This covers check-sub and phase-2 subscription fetches in one place (central fix, per fix-root-causes).
- If a `sanitize_url_for_error` helper doesn't exist yet, add it next to the existing `sanitize_error_text`.

## Data structures
None. Error-shape change only; no logging of credentials (hard boundary rule).

## Verification
### Static
- fmt / clippy `-D warnings` / full test suite GREEN.
### Runtime
- New test (must FAIL before, PASS after): a failing send against a URL with userinfo/query yields an error chain containing NO ` for url (` fragment and no user/password text; the scheme+host still appear for debuggability.
