# ADR-010: API hardening — localhost-only, register rate limit, overwrite guard

## Status
Accepted

## Date
2026-08-16

## Context
The HTTP API is an unauthenticated service on 127.0.0.1 shared by the
frontend and the CLI. Host-header allowlisting + Origin/Sec-Fetch-Site
checks close the remote (DNS-rebinding) surface, but the API stays
reachable by any local process: a malicious page or local app could start
scans against internal networks (loopback, RFC1918, ...), silently replace
a registered WARP identity, or spam Cloudflare's registration endpoint —
the only API call that talks to a third party and the only one that mutates
persistent state (the identity file).

## Decision
- **No auth token.** The API remains a localhost-only service (127.0.0.1
  only, port configurable via `--port`). An auth token would need key
  storage/management for a single-user local tool, and it cannot stop the
  local-process attacker it would target — anything that can read the token
  can call the API. The host allowlist + Origin checks stay the
  transport-level boundary.
- **`POST /api/warp/register` is rate-limited** to one request per 60
  seconds per server process. Registration is heavyweight and
  third-party-bound (multi-attempt, ~45 s worst case); nothing else in the
  API needs a limit.
- **Existing identity refuses overwrite** unless the request explicitly
  passes `overwrite: true`. Accidental re-registration must not silently
  discard a working (possibly WARP+ bound) identity.
- **The API rejects non-routable custom ranges and endpoints** — loopback,
  link-local, unspecified, RFC1918 private, and IPv6 ULA blocks. The CLI is
  unrestricted: an explicit, human-driven local user may scan their own LAN.

## Alternatives Considered

### Auth token on every request
- Pros: any process without the token is locked out
- Cons: token storage and rotation burden for a single-user local tool;
  ineffective against the local-process threat (the token is readable by
  whatever can call the API)
- Rejected

### No register rate limit (status quo)
- Pros: zero added state
- Cons: a local page can burn Cloudflare registration attempts (third-party
  traffic + persistent writes) as often as it likes
- Rejected

### Reject non-routable ranges everywhere, CLI included
- Pros: one rule, simpler to explain
- Cons: the CLI is an explicit human interface; an ISP-restricted user may
  legitimately scan their own LAN with it. Trusting explicit CLI input is
  the existing project rule (ADR-005 boundary)
- Rejected

## Consequences
- The API surface is safe by default: unauthenticated local requests cannot
  scan internal networks or spam Cloudflare registration, and the persisted
  identity cannot be clobbered by accident.
- The register endpoint carries a documented one-call-per-60 s contract; the
  frontend must handle the rate-limit response gracefully.
- CLI behavior is unchanged (explicit user input stays unrestricted).
- Implementation lands with the API-hardening work (plan 001). If 001's
  exact numbers or flag names change, update this ADR.
- The hardening is transport + policy, not a contract change: the API
  contract itself stays as ADR-005/ADR-011 decide.

## Links
- ADR-005 — single binary, contract first