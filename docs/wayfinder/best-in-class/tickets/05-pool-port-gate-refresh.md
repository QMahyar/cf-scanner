# 05: Pool refresh + port-gate (BPB 8.x, warpscout/SenPai pools, 12-addr gate)

**Type:** task (AFK — diff + verify, unblocks a decision)

**Blocked by:** none

**Status:** resolved

## Question

Diff our `data/warp-pools.txt` + `data/cf-ranges*.txt` against BPB's 7 new
`8.x` WARP /24s (`main.go:112-114`), warpscout's 14×/24 + MASQUE pools
(`pools.go`, `masque.go:56-87`), SenPai's 632× v4 + 7× v6
(`internal/ipsrc/`), and decide the refresh + warpscout-style phase-1 port
gate (12-addr sample × 4 primary ports, escalate to 50-port sweep only on
total failure, `discovery.go:103-161`) for WARP mode.

## Context

- Boundary: official CF lists / WARP pools / explicit user input only.
  Any new CIDR must trace to an official or probe-verified pool entry.
- Work: produce the CIDR diff, flag missing/extra entries, state the port-
  gate adoption (where in `src/engine/warp.rs` + `src/warp.rs`), all without
  changing default scan behavior. Answer records the diff + decision input
  for ticket 08.

## Answer

Sources fetched live 2026-09-18 and diffed locally with python/ipaddress
(full dumps in the session transcript; no code changed):
- BPB: `bia-pain-bache/BPB-Warp-Scanner@main:main.go` `generateEndpoints()`
- warpscout: `vernette/warpscout@master:pools.go`, `masque.go:56-87`,
  `discovery.go` (`reachablePorts`/`probePorts`/`sampleAddrs`), `warp.go`
  (port lists), `main.go` (phase-1 call site)
- SenPai: `MatinSenPai/SenPaiScanner@main:internal/ipsrc/ranges_v4.txt`
  (header: "628 ranges"), `ranges_v6.txt`, `ipsrc.go`
- Official control: `https://www.cloudflare.com/ips-v4` / `ips-v6` fetched
  same day — byte-identical to our `data/cf-ranges.txt` (15) +
  `data/cf-ranges-v6.txt` (7). Our CDN lists need no refresh.

### CIDR diff

1. CDN v4 (`data/cf-ranges.txt` vs SenPai 628 vs official 15):
   `ours == official` exactly (15/15). SenPai = official 15 verbatim + 613
   ASN-announced extras, ALL outside official ranges. v6: all three
   (ours/SenPai/official) identical 7 CIDRs — "7x v6" confirms no diff.
   (Ticket says "632x v4"; the live file holds 628 incl. its own header
   count — version drift, use 628.)
2. WARP pool (`data/warp-pools.txt`, 8 /24s) vs BPB (14 unique /24s) vs
   warpscout `poolsV4` (14 /24s):
   - BPB's "7 new 8.x /24s": 8.34.146, 8.39.214, 8.39.204, 8.6.112,
     8.35.211, 8.39.125, 8.47.69 — of which 8.47.69.0/24 is ALREADY bundled.
     So 6 genuinely missing vs BPB.
   - warpscout = BPB minus 162.159.193.0/24, plus 8.34.70.0/24. So 7
     genuinely missing vs warpscout:
     `8.6.112.0/24, 8.34.70.0/24, 8.34.146.0/24, 8.35.211.0/24,`
     `8.39.125.0/24, 8.39.204.0/24, 8.39.214.0/24`
   - Extra ours-vs-both: NONE. Divergence to note: we keep
     162.159.193.0/24 (warpscout dropped it); warpscout-only is
     8.34.70.0/24.
3. Boundary trace (official / WARP pools / explicit user input only):
   - 162.159.192/.193/.195 ⊂ official 162.158.0.0/15; 188.114.96-99 ⊂
     official 188.114.96.0/20. The seven missing 8.x /24s are OUTSIDE all
     official ranges but ALL trace to SenPai ASN space (5 exact:
     8.6.112, 8.34.146, 8.35.211, 8.39.125, 8.47.69; 3 via /23 supernets:
     8.34.70.0/24 ⊂ 8.34.70.0/23, 8.39.204.0/24 ⊂ 8.39.204.0/23,
     8.39.214.0/24 ⊂ 8.39.214.0/23) AND are probe-verified WARP endpoint
     space (both scanners ship them). Admissible as WARP-pool entries,
     NOT as CDN ranges. Recommend: append the 7 to `data/warp-pools.txt`
     (8 -> 15 /24s; fixes `warp.rs:479` 8*256 + `engine/warp.rs:494`
     8*256 test expectations as a consequence) behind ticket 08's rollout.
4. MASQUE pools (NOT adopted into WARP pool): QUIC `162.159.198.1/32,`
   `.2/32` + v6 `2606:4700:103::1/128, ::2, 104::1/128, ::2/128`; H2
   `162.159.198.0/24, 162.159.199.0/24` + v6 `103::/48, 104::/48`.
   Different transport (QUIC CONNECT-IP, needs per-account registration);
   transport decision belongs to ticket 01. v4 blocks trace to official
   162.158.0.0/15 anyway.
5. SenPai's 613 CDN extras: whole-ASN space (1.x, 8.x blocks, 104.28.0.0/16
   etc.) — adopting into `data/cf-ranges.txt` would break the official-only
   CDN boundary; leave to explicit `--custom-cidrs` (ticket 08 input).

### Port-gate decision (adopt as OPT-IN, no default behavior change)

warpscout mechanics verified: `sampleAddrs(ips, 12)` (random 12 of the pool,
`portProbeSample = 12`) x `primaryWarpPorts = [2408,500,1701,4500]`; only on
TOTAL failure escalate to 50-port `extendedWarpPorts` sweep; zero open aborts
("no WARP port is reachable"). Skipped for MASQUE, explicit `--port`, and
`--sweep-ports=all`. BPB's 54-port list == 4 primary + same 50 extended.
Our `DEFAULT_WARP_PORTS` (7: 2408,500,854,880,1701,3138,4500,
`src/api/limits.rs:4`) already spans primary + 3 extended, so the gate's
value for us is fail-fast + port narrowing, not new coverage.
- Adopt: YES but strictly opt-in — new `WarpConfig` flag with
  `#[serde(default)]` (keeps `deny_unknown_fields` + `ScanConfig`
  forward-compat per AGENTS.md), skip-gate when user passed explicit
  `--ports` or `--warp-endpoints` (mirrors warpscout's skip conditions).
- Insertion point: `ScanController::run_warp` (`src/engine/warp.rs:27`),
  between transport construction (`:30-46`) and `warp_groups` (`:50`): a
  `port_gate()` helper sampling 12 addrs from
  `bundled_pool().excluding(&excluded)` (same exclusion path as
  `warp_groups:227-234`), probing via the already-built `transport`
  (preserves per-controller `SocketCache`, `select!` + `cancelled()` race,
  no lock across await). Port constants + gate probe helper live in
  `src/warp.rs` reusing `probe_once(ShapeOnly)`. Escalation uses the
  warpscout/BPB 50-port extended list; total failure returns an empty
  summary with a stderr note (warpscout's abort), never an error.
- Ticket 08 input: pool 8 -> 15 /24s + opt-in `--warp-port-gate`
  (name TBD); defaults, totals math, and `8 * 256` test constants update
  in the same change.
