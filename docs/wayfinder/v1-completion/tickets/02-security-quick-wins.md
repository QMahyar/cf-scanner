## Question

How do we close the probe-URL SSRF gap (`--phase2-probe-urls` bypassing
`validate_fetch_url`) and harden trial-directory permissions without breaking
existing valid configurations?

## Scope

Two security findings from the 2026-09-06 audit:

1. **Probe URL SSRF** (`src/api/validate.rs:138`): probe URLs are only checked
   for `https://` prefix + length, NOT validated through
   `ranges::validate_fetch_url` (blocks loopback, link-local, multicast).
   A URL like `https://[::1]/admin` would be forwarded to 127.0.0.1 via the
   xray tunnel.

2. **Trial dir permissions** (`src/xray.rs:233`): trial directories containing
   xray config.json (with proxy credentials) use `create_dir_all` without
   setting permissions — inherits umask (typically 0o755, world-readable
   listing). The config.json inside IS 0o600, but the directory itself is not.

## Acceptance

- [ ] Probe URLs run through `validate_fetch_url` (or equivalent hostname
      allowlist check) before acceptance
- [ ] Existing valid probe URLs (public HTTPS endpoints) still pass
- [ ] Trial directories created with 0o700 permissions on Unix
- [ ] Non-Unix behavior unchanged
- [ ] New tests: loopback probe URL rejected, trial dir perms asserted
- [ ] `cargo test` + `cargo clippy --all-targets -- -D warnings` +
      `cargo fmt --check` all pass

## Boundaries

- Never log probe URLs, configs, or keys
- Don't change behavior for already-valid URLs
