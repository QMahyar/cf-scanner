# UI v2 research synthesis — 2026-08-23

Ten parallel web-verified research passes (ports, ranges, AWG noise, probe tuning,
table UX, dual-mode/RTL, skip heuristics, competitor defaults, share-link grammars,
vmess/subscriptions). Every claim below was fetched live on 2026-08-23 by a scout
agent; source URLs inline. This file is the evidence base for the UI-v2 plan;
decisions at the bottom map findings onto CF-Scanner knobs.

---

## 1. Cloudflare port catalogs

Source: https://developers.cloudflare.com/fundamentals/reference/network-ports/
(lastModified 2026-04-20; unchanged content since pre-2022).

- HTTPS-proxied (TLS) ports, exactly 6: **443, 2053, 2083, 2087, 2096, 8443**.
- HTTP-only proxied ports (7): 80, 8080, 8880, 2052, 2082, 2086, 2095 — TLS
  ClientHello against these fails (HTTP listener / 525). Caching disabled on all
  non-443 proxied ports (Enterprise can re-enable).
- Community tools split families identically (yonggekkk/Cloudflare-vless-trojan;
  GFW4Fun sing-box script gist f59393436c829ae8574919cd6d22430e).

WARP ingress (https://developers.cloudflare.com/cloudflare-one/team-and-resources/devices/cloudflare-one-client/deployment/firewall/, dateModified 2026-07-24):
- WireGuard ingress `162.159.193.0/24` (+v6 `2606:4700:100::/48`): UDP **2408**
  default, fallbacks **500, 1701, 4500**. Matches our `WARP_PRIMARY` exactly.
- MASQUE (QUIC/HTTP3) ingress `162.159.197.0/24`: UDP 443 default + 4443, 8443,
  8095, TCP 443 — different protocol; NOT WireGuard-probeable. Out of scope.
- `162.159.192.0/24` = consumer 1.1.1.1+WARP pre-login (we exclude these in CDN
  scans already via the WARP-ingress exclude preset — correct).

Extended community WARP ports: origin is **bepass-org/warp-plus**
`warp/endpoint.go WarpPorts()` (raw master fetched Aug 2026; 54 entries =
4 primary + 50 extended). All 50 entries in `ui/src/lib/cfPorts.ts`
`WARP_EXTENDED_PORTS` match the origin verbatim. `1012` seen in samnet.dev's
copy is copy-drift, absent upstream — do not add. All 50 are empirical/anycast
heuristics, not Cloudflare-official.

Iran-context ordering evidence (OONI Iran report; arxiv 2507.14183; bepass-org):
443 survives DPI whitelist mode most often; among WARP ports 500/4500/1701 often
survive when 2408 is flagged. First-run should use primary tier only and escalate
to extended on failure — matches the existing two-tier chip UI.

## 2. Cloudflare IP pools

Official lists (fetched live from cloudflare.com/ips-v4, /ips-v6, and
api.cloudflare.com/client/v4/ips — all three agree; page last updated 2023-09-28):

IPv4 (15 CIDRs, ~1,524,736 hosts, ~5,956 /24s):
```
173.245.48.0/20   103.21.244.0/22  103.22.200.0/22  103.31.4.0/22
141.101.64.0/18   108.162.192.0/18 190.93.240.0/20  188.114.96.0/20
197.234.240.0/22  198.41.128.0/17  162.158.0.0/15   104.16.0.0/13
104.24.0.0/14     172.64.0.0/13    131.0.72.0/22
```
IPv6 (7): 2400:cb00::/32, 2606:4700::/32, 2803:f800::/32, 2405:b500::/32,
2405:8100::/32, 2a06:98c0::/29, 2c0f:f248::/32.

Competitor bundles:
- XIU2/CloudflareSpeedTest `ip.txt` (raw master fetched): diverges from official —
  carries stale `104.16.0.0/12` (covers unadvertised 104.28.0.0/14, wasted probes)
  and fragments 172.64.0.0/13 into 13 sub-ranges (same coverage). Manual updates.
- mortezabashsiz/CFScanner `config/cf.local.iplist`: exact official 15.
- Aggregators (lord-alfred/ipranges, mansourjabin/cdn-ip-database): mirror the
  official 15 daily.
- "Clean IP" one-per-line community lists churn hourly (anycast + DPI) — correct
  architecture is bundling authoritative CIDRs + local probing, never bundling
  clean-IP dumps.

Sampling: XIU2 default = 1 random IP per /24 (`-allip` opts out). CFScanner full
sweep by default, `-r` reservoir sampling opt-in (docs recommend `-r 20`). No
tool ships 3-per-/24 by default.

Beginner sample-size reasoning (ranges agent): under heavy DPI expect ~1–5%
phase-1 yield; 400–800 candidates typically surface 2–4 hits fast while staying
below ISP/CF scan-rate attention (XIU2 README warns about temporary bans from
aggressive scanning). 500–800 probes finishes in ~15–45s.

## 3. Competitor parameter defaults

XIU2/CloudflareSpeedTest (README + task/tcping.go fetched):
- `-n 200` threads (max 1000), TCP connect timeout **1s** (HTTPing 2s),
  `-t 4` pings averaged, any-success counts + loss-rate filter (`-tlr`,
  default allows lossy, sorts zero-loss first), `-tp 443`, `-dn 10` download
  tests capped, `-sl` min speed stops download phase once satisfied, README
  explicitly warns to pair `-sl` with `-tl` (max avg latency, default 200ms
  examples) or the run may never terminate.
- Warning quoted in README: scanning-like volume from servers/residential IPs
  triggers temporary ISP/CDN limits → reduce `-n`.

mortezabashsiz/CFScanner (golang/py/bash READMEs fetched):
- xray-backed probing ⇒ low thread defaults (1; examples use 4–8), `--tries n`
  = ALL tries must succeed (unanimous), fronting timeout 1s, download timeout 2s,
  sorts result CSV by time asc.

peanut996/CloudflareWarpSpeedTest: WG handshake probes, `-t 10` tries, 1s UDP
timeout, 200 workers, `-c 5000` pool cap, `-tl 300` latency filter examples.
bepass-org/warp-plus `--scan`: rtt threshold 1s, desirable 400ms, queue-based.
cf-knife timing templates: Normal 200 thr/3s, Aggressive 2s, Insane 1s/8000thr.
warp-conf-gen: 20 workers, 1.5s timeout.

Stop-after-N precedents: **N=10 dominates** (XIU2 `-dn 10`/`-p 10`, WST `-p 10`;
SenPai Top-N caps phase-2 verification at 10/25/50/100). No tool implements an
interactive mid-scan phase jump — ours would be novel UI over an existing engine
capability (`phase2_only`).

Latency classes: no standard bins found; common filters cluster at 200ms (XIU2
examples), 300ms (WST), 400ms (warp-plus desirable RTT). Our color coding
(<300 fast / <800 mid / ≥800 slow) sits within community norms.

## 4. Probe/concurrency engineering

- Windows ephemeral range 49152–65535 = 16,384 ports (Microsoft troubleshooting
  doc): 64–200 concurrent dials are safe; sustained high SYN *rates* × 240s
  TIME_WAIT are the real exhaustion risk. Termux `ulimit -n` often 1024 → cap
  real concurrency there.
- XIU2 author warning: >~200 sustained concurrent SYNs from one residential IP
  can trip temporary ISP/CF limits (community-reported, no official threshold).
- WG handshake cost (Donenfeld benchmarks; wireguard.com/protocol): scanner side
  ≈ 1 ephemeral keygen + DH; thousands/sec possible CPU-wise. Cookie replies
  (64B type 3) still prove liveness; CF answers dummy-key probes (verified live
  2026-08-13, see docs/intent).
- Retry semantics split: cheap TCP scanners = tolerant (4 tries, loss filter);
  expensive tunnel verification = unanimous (CFScanner all-or-nothing). Our WARP
  `probes_per_endpoint` (default 3, zero-loss) follows the unanimous precedent —
  stricter than warp scanners' single-shot, defensible for result quality.
- Recommended bands: beginner conc 64 (ours) ✓; simple-mode 128 ✓; pro max 500+
  only with warning (docs exist in-app already). Timeout 2s simple / 3s pro ✓
  consistent with cf-knife Normal 3s + XIU2 2s HTTPing.

## 5. AmneziaWG noise parameters (for the planned wgconf noise editor)

Authoritative: amneziawg-linux-kernel-module README + amneziawg-go uapi.go +
receive.go (fetched live).

Hard limits / constraints:
- `Jc` 1..128 (0 = off; kernel rec 4..12; docs.amnezia operational 0..10)
- `Jmin < Jmax`, both < 1280 (MTU assumption; GL.iNet allows 0..1279/1280)
- `S1` ≤ 1132, `S2` ≤ 1188, `S3` ≤ 1216, `S4` ≤ 32 (kernel, assuming MTU 1280);
  operational guidance 15..150; generator-era 0..64; constraint **S1+56 ≠ S2**
- `H1..H4` each 5..2147483647 (INT32_MAX for Windows-client compat), pairwise
  distinct; amneziawg-go v2 accepts `N` or `N-M` ranges, ranges must NOT overlap;
  reject 1..4 (real WG message types 1=Init 2=Response 3=Cookie 4=Transport)
- Failure modes: bad numerics/ranges = hard parse error ("headers must not
  overlap"); mismatched S/H = silent handshake drop (`MessageUnknownType`);
  wrong J* = handshake still works (junk discarded unvalidated), only DPI
  fingerprint changes; `Jmax ≥ MTU` risks IP fragmentation.

Real-world presets seen: bivlked installer defaults (Jc6/Jmin55/Jmax205/S172/
S256/H-ranges), amnezigo generator (jc 4-5, jmin 50-250, jmax 750-1000,
h1 100..5M … h4 1B..2.1B), VPNSmith example (Jc8/Jmin8/Jmax80/S186/S2118),
Russia-TSPU minimal (Jc1/Jmin1/Jmax3/S0/S0/H1..H4=1..4 — vanilla-compatible),
xeovo provider (Jc5/Jmin42/Jmax54/S0/S0/H1..H4=1..4).

Scheme notes: Throne/MahsaNG/Incy convention is `awg://<base64url(INI)>` /
`wg://`/`wireguard://` for plain WG — base64url of the whole INI, NOT
query-string params. Our `src/wgconf.rs` already parses INI + awg URIs incl.
percent-decoding; editor targets INI keys Jc/Jmin/Jmax/S1/S2/H1-H4 (the exact
set `AmneziaParams` supports — no S3/S4/I-packets in our engine).

Suggested preset buttons (validated against constraints):
- Off/vanilla: all J/S = 0, H1..H4 = 1,2,3,4 (falls back to standard WG)
- Light: Jc4, Jmin50, Jmax300, S1 30, S2 40 (30+56≠40 ✓), H 100000-400000 /
  5000000-9000000 / 50000000-90000000 / 600000000-900000000
- Heavy: Jc8, Jmin64, Jmax1024, S1 64, S2 48 (120≠48 ✓), H 123456-654321 /
  7654321-8765432 / 31415926-41415926 / 271828182-371828182

## 6. Share-link grammars (phase-2 configs + URI export)

vless:// (XTLS discussions #716 + xtls.github.io, fetched live): params
encryption/flow/security/type/sni/alpn/fp/pbk/sid/spx/pqv/ech/pcs/vcn/path/host/
serviceName/mode/headerType/seed…; `allowInsecure` deprecated upstream but
de-facto emitted. Minimal parse = uuid@host:port; REALITY needs pbk(+fp).
trojan:// password@host:port (+ trojan-go sni/type/host/path/encryption/plugin).
ss:// SIP002 (shadowsocks.org docs): base64url(method:password)@host:port or
plain userinfo for AEAD-2022; plugin escaping rules; legacy whole-b64 form.
vmess:// base64(JSON): fields v/ps/add/port/id/aid/scy/net/type/host/path/tls/
sni/alpn/fp/insecure/vcn/pcs — all strings; aid="0"; producer quirks documented
(v2rayN emits raw alias handling; V2RayNG forces aid="0", detects std form by
'?'+& presence; NekoBox reuses v2rayN import).

Substitution safety (applies to our `/api/config/export`): rewrite ONLY the
authority host:port (= dial target). NEVER touch sni / ws `host=` param /
REALITY pbk-sid / uuid/password / method:password / vmess host-field (WS Host
header ≠ address). Naive string replace breaks TLS (IP-as-SNI) and CDN routing
(IP-as-Host-header). Our engine's exporter separates address from stream
settings — consistent with these rules (re-verify in tests).

Subscriptions: body = plain newline-delimited URIs OR base64 blob thereof OR
sing-box/clash JSON; detection = try base64 decode → line-split → magic-prefix
dispatch; batch paste separator = newline; QR = single URI only (size limit).

## 7. Results-table UX (NN/g, APG, M3, TanStack — fetched live)

- Sorting: `<button>` inside `<th>`, `aria-sort` ONLY on the active column,
  tri-state asc→desc→clear, numeric comparator for latency, focus stays on the
  header button. Icons `aria-hidden`.
- Selection: header checkbox selects the FILTERED set only, explicit banner
  when filtered ⊂ total ("select all 342 matching" affordance like Gmail);
  indeterminate via property + `aria-checked="mixed"`; touch target ≥44px
  (WCAG 2.5.5) / 48dp (M3) — wrap small checkboxes in padded hit areas;
  Shift+click range select is the expected bulk accelerator.
- Copy feedback: transient inline button state (✓ 1.5–2s) for row actions +
  polite live-region/toast for bulk ("Copied 42 endpoints"); clipboard needs
  secure context + gesture (localhost IS secure context) — provide
  execCommand/manual-select fallback; Web Share API = mobile secondary
  (Firefox desktop lacks it entirely — caniuse 91.7%), Blob `.txt` download =
  universal final fallback.
- Scale: virtualize at ≥1000 rows only; sticky header always; sticky bulk-action
  bar bottom on mobile (thumb zone + safe-area-inset); horizontal scroll tables
  freeze the first column and signal overflow with shadow; 4 narrow columns
  (endpoint/latency/country/status) justify keeping a TABLE on mobile — cards
  stay the beginner view (progressive disclosure), not a forced replacement.
- States: skeleton rows while scanning (aria-busy), never "no records" mid-run;
  three distinct empties: pre-scan / filtered-empty (with clear-filter action) /
  true-zero-after-finish (with remediation tips); errors get cause + Retry.
- Progress (NN/g response-time limits): spinner 2–10s; determinate % + counters
  + ETA beyond 10s; cancel always visible; reassurance copy for multi-minute ops.

## 8. Dual-mode, i18n, RTL

- Progressive disclosure (NN/g): core upfront + ONE labelled affordance for the
  rest; ≤2 levels; persistent top-level toggle (never buried); pros shouldn't
  pay a tax — Advanced shows beginner defaults prefilled. Our Simple|Pro header
  toggle matches; rename copy accordingly.
- Running-operation patterns (VPN onboarding case studies): phase label in plain
  language, live last-hit ticker, reassurance line with honest duration band.
- Language detection/persistence convention: localStorage manual pick →
  `navigator.languages[0]` startsWith('fa') → 'en'; persist on toggle; apply
  `document.documentElement.lang/dir` BEFORE first paint to avoid FOUC.
- Tiny dictionary beats i18next for exactly 2 locales (~150 strings): <2kB,
  synchronous, no async init; revisit only at 3+ locales/ICU plurals.
- RTL checklist: `html[dir]`; Tailwind logical utilities ms/me/ps/pe/start/end/
  rounded-s·e/border-s·e (v3.3+) replacing ml/mr/pl/pr/left/right; wrap LTR
  data tokens (ip:port, ms numbers, CIDRs) in `<span dir="ltr">`; mirror only
  directional icons (`rtl:scale-x-[-1]`); gap/flex flip automatically.
- Font: Vazirmatn variable woff2 self-hosted (jsdelivr font-face css as source;
  OFL-1.1), `font-display: swap`, line-height 1.7–1.8 for fa vs 1.5 en.

## 9. Phase-skip heuristics

Prior art: NONE of the audited tools offer interactive mid-scan phase jumps
(XIU2 sequential phases with declarative caps; warpscout Ctrl+C keeps best-so-far
only). Declarative "stop at N good" exists (`-dn`+`-sl`) — ours is `stop.found`.

Recommended shape (skip agent; REASONING marked where unsourced):
- **Suggest-only, never auto-jump.** Non-modal badge near Stop once BOTH:
  survivors ≥ ~12 AND sliding-window success rate over last ~500 probes < ~2–3%
  (diminishing returns). SOURCED basis: group-sequential futility testing exists
  (MLR/acm refs); thresholds themselves are calibrated guesses.
- Guardrails: confirm-before-skip if survivors < 5 (binomial 95% CI math: ≥5
  survivors gives >50% chance ≥1 phase-2 pass at ~30% verify rate); phase-2 cost
  = survivors × configs × SNIs combos ÷ concurrency — cap suggested verify batch
  around ~150 combos.
- Verify fastest-first: sort survivors by phase-1 latency ascending before
  verification. SOURCED precedent (XIU2 sorts before speed phase; warpscout
  sorts loss then ping). OUR ENGINE ALREADY DOES THIS: the store is
  latency-sorted and phase2 clones it in order.
- Undoability language: after skip, offer "Resume scanning" framing (engine
  restarts fresh — phrase honestly as "start a new scan with remaining pool"
  only if we implement resume; otherwise omit the claim).

---

## Decisions adopted for CF-Scanner (UI v2)

| Area | Decision | Basis |
|---|---|---|
| CDN port catalog | keep [443,2053,2083,2087,2096,8443] | §1 official, complete |
| WARP catalogs | keep primary + 50-port extended verbatim | §1 bepass-org origin audit |
| Bundled ranges | verify bundled pool == official 15 v4 (+7 v6 behind include_v6); fix drift if any | §2 |
| Beginner find-target default | 20 (range 5–100 kept) | §3 N=10 dominant; user floated 50; midpoint |
| Beginner test-count default | 800 candidates (slider 100–10,000) | §2 400–800 band |
| Concurrency/timeout defaults | unchanged (64/128; 3s pro, 2s simple) | §4 |
| WARP probes_per_endpoint semantics | KEEP zero-loss (ask-first boundary; unanimous precedent) | §4 |
| Latency filter | table filter stays post-hoc; NO new API field for now | §3 bins vary 200–400ms; table covers it |
| AWG editor | INI-key editor (Jc,Jmin,Jmax,S1,S2,H1–H4) with validation per §5 + Off/Light/Heavy presets | §5 |
| Skip to Phase 2 | suggest-only badge + manual button; confirm <5 survivors; fastest-first already native | §9 |
| Results table | tri-state aria-sort buttons, 48dp hit areas, toast for bulk copy, skeleton rows, 3 empty states, virtualize ≥1000 rows | §7 |
| Export chain | clipboard → navigator.share (feature-detected) → Blob .txt | §7 |
| Modes | sticky Simple|Pro segmented control, persistent, prefilled | §8 |
| i18n | tiny {en,fa} dict, key `cf-lang`, detect fa→fa, dir/lang applied pre-paint | §8 |
| RTL | logical Tailwind props sweep, dir=ltr spans for data tokens, mirrored chevrons only, Vazirmatn | §8 |

Rejected / deferred (with reasons):
- MASQUE UDP-443 probe tier — different protocol, out of scope (§1).
- Engine-side max_latency_ms field — table filter covers the need; avoids
  contract change (user prefers none unless missing; it isn't).
- Majority-vote WARP probe semantics — engine default-behavior boundary; keep
  unanimous (stricter, quality-first) (§4).
- Auto-jump without consent — novel + risky; suggest-only wins (§9).
- i18next/paraglide — 2 locales don't justify 15kB+async init (§8).
