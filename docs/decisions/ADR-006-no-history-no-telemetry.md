# ADR-006: No history, no telemetry — last-scan-only results in memory

## Status
Accepted

## Date
2026-08-13

## Context
Scanned IPs and user proxy configs are sensitive: they reveal what a user
is working around and how. The confirmed intent explicitly requires no
scan history, no telemetry, and no configs leaving the machine. Persisting
results to disk or reporting usage would both violate the product promise
and create data-retention liability for a tool meant to be ephemeral.

## Decision
Results are last-scan-only and in memory: a new scan replaces the previous
result set; `reset` clears everything. Nothing is written to disk except
what the user explicitly saves (copy/save actions are client-side, explicit).
No telemetry, no crash reporting, no analytics endpoints. Imported configs
and keys are never logged or transmitted; scan requests always bind to
127.0.0.1 unless an explicit bind flag is given.

## Alternatives Considered

### Persistent scan history on disk
- Pros: resumable sessions, comparison across scans
- Cons: sensitive data at rest; grows unboundedly; contradicts stated intent
- Rejected

### Anonymous usage metrics
- Pros: product insight
- Cons: exfiltrates metadata about a tool that exists to evade ISP
  restrictions; trust-destroying
- Rejected

## Consequences
- No migration/storage code to maintain; fewer attack surfaces.
- "What did my last scan find?" after a restart is impossible by design.
- The API surface stays small (`/scan`, events, results, reset, ranges).
- Anything that would persist, log, or transmit scan data is a spec
  violation and must be reviewed out.
