# ADR-004: DPI-bypass fragmentation via freedom outbound + sockopt.dialerProxy

## Status
Accepted

## Date
2026-08-13

## Context
On ISP-restricted networks, TLS connections to Cloudflare IPs are often
reset or throttled by DPI that fingerprints the ClientHello. Xray's
fragment feature splits the TLS hello into packets that evade naive
fingerprinting. Per XTLS docs, `fragment` lives on a Freedom outbound
(`"fragment": {"packets": "tlshello", "length": "100-200",
"interval": "10-20"}` — Int32Range strings), and the proxied outbound
chains to it via `dialerProxy` in `streamSettings.sockopt`.

## Decision
Phase-2 configs are generated with the fragment outbound + sockopt chaining
exactly as documented. Presets (community-verified, cfray):

- light: length 100-200, interval 10-20
- medium: length 50-200, interval 10-40
- heavy: length 10-300, interval 5-50

Custom = user-supplied packets/length/interval, validated before use.
Verdicts record which preset + SNI variant was used.

## Alternatives Considered

### Fragment on the TLS inbound/proxied outbound directly
- Pros: simpler config
- Cons: undocumented placement; XTLS docs require it on a Freedom outbound
  chained via `dialerProxy`
- Rejected: wrong placement silently produces unfragmented traffic

### Hand-rolled TCP-level fragmentation of the probe
- Pros: no xray dependency for phase 2
- Cons: only fragments our own probe, not the user's real traffic through
  xray; DPI still sees the app's full hello
- Rejected: phase 2 exists to verify real configs end to end

## Consequences
- Generated xray JSON is two outbounds: the fragment Freedom + the proxied
  outbound with `sockopt.dialerProxy`.
- Preset strings must round-trip through the existing Int32Range validation;
  invalid user input is rejected at scan-config time.
- Future xray versions might rename fields; the JSON builder is isolated in
  one module to contain such changes.
