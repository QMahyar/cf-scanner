# CF-Scanner — Glossary

## Verdict

The classification of a scanned endpoint as working or not. The verdict is
binary and lives in the engine; the results row IS the verdict — a row
existing means the endpoint works, a missing row means it doesn't.

## Working

An endpoint that satisfies its mode's verdict rule:

- **WARP**: every handshake probe responded (open AND zero probe loss). A
  single dropped probe excludes the endpoint — lossy endpoints are not
  reported, not listed.
- **CDN phase 1**: the TCP/TLS probe connected.
- **Phase 2**: the config URI verified over the candidate.

## Probe loss

The share of handshake probes to one endpoint that got no response,
`failed / probes * 100`. For WARP rows it is always 0.0 because any loss
excludes the row. The probes-per-endpoint setting therefore controls how
strictly "working" is judged, not just measurement accuracy.

## Open endpoint

A WARP endpoint that answered at least one probe with a Response or Cookie
packet. Open is necessary but not sufficient for Working — the endpoint must
also have zero probe loss.