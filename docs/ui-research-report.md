# CF-Scanner Frontend Research Report — 10 Agent Findings

Date: 2026-08-13
Status: Research pass — recommendations with trust scores

---

## Agent 1: Typography & Fonts

| Recommendation | Trust | Status |
|---|---|---|
| Keep system font stack, reorder `system-ui` first | 9/10 | Reorder needed |
| Keep Cascadia Code + JetBrains Mono monospace | 8/10 | Done |
| `font-size: 15px` → `0.9375rem` (unlock browser scaling) | 9/10 | Needs change |
| Apply `tabular-nums` + `slashed-zero` to ALL numeric elements | 10/10 | Needs change |
| Font-weight 650 → 600 or 700 (static font compat) | 8/10 | Needs change |
| Context-specific line-heights: headings 1.2, tables 1.4, body 1.55 | 8/10 | Partially done |
| Remove letter-spacing from h1/h2/h3 (keep on uppercase labels only) | 9/10 | Needs change |
| Adopt modular type scale (Major Second 1.125) | 7/10 | Needs change |
| Add `-webkit-font-smoothing: antialiased` to root | 7/10 | Needs addition |
| Consider 16px base (browser default, WCAG recommended minimum) | 7/10 | Optional |

### Recommendation: System Font Stack is Correct Choice
**Trust: 9/10**
**What:** Keep the system font stack. Reorder to put `system-ui` first: `system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif`.
**Why:** For an embedded single-file tool with zero external deps, system fonts are objectively the best choice. Zero HTTP requests, no FOUT/FOIT, zero layout shift, fastest possible rendering. System-ui renders San Francisco (macOS), Segoe UI (Windows), Roboto (Android).
**Current code status:** Already done — just needs reorder.

### Recommendation: Monospace Font — Keep Cascadia Code + JetBrains Mono
**Trust: 8/10**
**What:** No change needed. Cascadia Code is the best first choice for a Windows-primary developer tool. JetBrains Mono has the tallest x-height of any monospace font.
**Why:** 2026 comparisons consistently rank JetBrains Mono #1 overall and Cascadia Code as the best Windows-native option.
**Current code status:** Already done.

### Recommendation: Switch Base Font-Size from px to rem
**Trust: 9/10**
**What:** Change `font-size: 15px` to `font-size: 0.9375rem`.
**Why:** Over 75% of low-vision users change their browser's default font size (WebAIM survey). Using px locks the base size, preventing rem-based children from scaling.
**Current code status:** Needs change.

### Recommendation: Tabular Numerals — Apply Broadly to All Numeric Data
**Trust: 10/10**
**What:** Apply `font-variant-numeric: tabular-nums` to ALL elements displaying numbers. Also add `slashed-zero` for IP addresses.
**Why:** This is the most universally agreed-upon recommendation. Loke.dev (2026): "In a data table, tabular-nums is non-negotiable."
**Current code status:** Needs change — currently only on `.stat-val`.

### Recommendation: Font Weights — Adopt a 3-Weight System
**Trust: 8/10**
**What:** Use exactly 3 weights: 400 (body), 500 or 600 (labels/subheadings), 700 (headings/emphasis). Stop using 650.
**Why:** The Certbolt 2026 guide confirms: "Readable interfaces usually rely on a restrained set: 400 for body, 500 for UI labels, 600 for subheadings/buttons, 700 for headings."
**Current code status:** Needs change — 650 → 600 or 700.

---

## Agent 2: Color System

| Recommendation | Trust | Status |
|---|---|---|
| 3-state theme toggle: Auto / Light / Dark | 10/10 | Needs change |
| `--muted` on all surfaces passes AA, but bump to `#94a3b8` for safety | 9/10 | Verify |
| Add `--warning-contrast` dark text for yellow badge backgrounds | 7/10 | Needs change |
| Multi-level shadow system (sm/md/lg/xl) | 8/10 | Needs change |
| Add `--border-subtle` (3rd border level) | 7/10 | Needs change |
| Soften dark accent saturation (reduce halation) | 8/10 | Partially done |
| Reduce shadow reliance in dark mode (use borders + surface lightness) | 9/10 | Needs change |
| Add `--surface-4` for modal/dropdown overlays | 7/10 | Needs change |
| 3-tier latency colors (add orange 150-500ms tier) | 7/10 | Optional |
| Set `color-scheme: light dark` for system mode toggle | 9/10 | Needs update |

### Recommendation: Use 3-state theme toggle (system/light/dark)
**Trust: 10/10**
**What:** Change from current 2-state to a 3-state model: `system` (default), `light` (override), `dark` (override). Store preference as `"system"|"light"|"dark"` in localStorage.
**Why:** The current implementation silently locks the user to their OS preference at load time. The 3-state model (recommended by cr0x.net, web.dev, Radix, and Material Design) lets users say "follow system" explicitly.
**Current code status:** Needs change.

### Recommendation: Off-black bg is correct, keep #0a0e14
**Trust: 9/10**
**What:** Keep `--bg: #0a0e14`. Avoid pure #000000.
**Why:** Material Design, Apple HIG, and every 2025-2026 guide recommends dark gray (7-12% lightness) over pure black.
**Current code status:** Already done.

### Recommendation: --muted fails WCAG AA on some surfaces
**Trust: 9/10**
**What:** Verify every text-on-surface combination. Consider bumping `--muted` to `#94a3b8` (zinc-400) which guarantees 6:1+ on all surfaces.
**Why:** The #1 rule of dark mode contrast: test muted/secondary text against EVERY surface it appears on.
**Current code status:** Partially done.

### Recommendation: Border vs shadow for elevation in dark mode
**Trust: 9/10**
**What:** In dark mode, prefer surface lightness + subtle border over shadows for elevation. Reserve shadows for highest-level overlays (modals, tooltips).
**Why:** Shadows are physically meaningless on dark backgrounds. Material Design 3 formalized this: dark mode elevation = lighter surfaces + tonal overlay, not shadows.
**Current code status:** Needs change.

### Recommendation: Set color-scheme on root for native UI theming
**Trust: 9/10**
**What:** Already done. Ensure the 3-state toggle also updates `color-scheme` when switching. System mode sets `color-scheme: light dark`.
**Why:** Without `color-scheme`, dark pages get bright native scrollbars and form inputs.
**Current code status:** Already done.

---

## Agent 3: Layout & Spacing

| Recommendation | Trust | Status |
|---|---|---|
| Adopt 8px base spacing scale with CSS custom properties | 9/10 | Needs change |
| Fix 3-column → 2-column form layout | 9/10 | Needs change |
| Improve mobile touch targets (min 44x44px) | 9/10 | Needs change |
| CSS custom property tokens for all spacing | 9/10 | Needs change |
| Single-column forms on mobile (verify) | 9/10 | Verify |
| Standard responsive breakpoints (768px instead of 900px) | 8/10 | Needs change |
| Normalize grid gap from 0.9rem to 1rem | 7/10 | Needs change |
| Keep always-visible sticky header (no auto-hide for live-data tool) | 8/10 | Done |
| Evaluate max-width 1080px vs 1200px for data table | 7/10 | Evaluate |
| Keep stacked single-column layout (no sidebar) | 7/10 | Done |

### Recommendation: Adopt 8px base spacing scale
**Trust: 9/10**
**What:** Define CSS custom properties for a spacing scale: `--sp-1: 0.25rem` (4px), `--sp-2: 0.5rem` (8px), `--sp-3: 0.75rem` (12px), `--sp-4: 1rem` (16px), `--sp-5: 1.5rem` (24px), `--sp-6: 2rem` (32px).
**Why:** The 8px grid is the industry standard (Material Design, Carbon, Tailwind). Current code uses 1.25rem (20px) as the dominant value — 20px is not on the standard 4/8px grid.
**Current code status:** Needs change.

### Recommendation: Fix multi-column form layout
**Trust: 9/10**
**What:** Change the connection settings from 3-column to 2-column grid.
**Why:** Baymard Institute research (130K+ hours of usability testing) found multi-column forms cause significantly more errors. The current 3-column form is problematic.
**Current code status:** Needs change.

### Recommendation: Improve mobile touch targets
**Trust: 9/10**
**What:** Ensure all interactive elements are minimum 44x44px (iOS) / 48x48dp (Android). Increase button and input padding on mobile.
**Why:** WCAG 2.2 SC 2.5.8 requires minimum 24x24px touch targets. Apple recommends 44x44pt.
**Current code status:** Needs change.

### Recommendation: Use CSS custom properties for all spacing tokens
**Trust: 9/10**
**What:** Define spacing as CSS custom properties in `:root` and use them everywhere.
**Why:** CSS custom properties create a single source of truth. Makes theme switching and density mode changes trivial.
**Current code status:** Partially done.

---

## Agent 4: Header & Navigation

| Recommendation | Trust | Status |
|---|---|---|
| Keep always-visible sticky header (no auto-hide) | 8/10 | Done |
| Add 3-state theme toggle (Auto/Light/Dark) | 9/10 | Needs change |
| Add `@supports` fallback + `-webkit-` for backdrop-filter | 8/10 | Needs change |
| Add GitHub link icon button to header | 8/10 | Needs change |
| Reduce header height from 56px to 48px | 7/10 | Needs change |
| Keep version pill, add tooltip with build info | 7/10 | Partially done |
| Crosshair logo is appropriate | 7/10 | Done |
| Add subtitle to one line or remove entirely | 6/10 | Needs change |
| No mode indicator in header (correct) | 8/10 | Done |
| Keep 2 header actions max (GitHub + theme toggle) | 8/10 | Needs change |

### Recommendation: Header Content Completeness
**Trust: 9/10**
**What:** Add a single GitHub icon link (right-aligned, before theme toggle). No navigation links needed.
**Why:** A localhost tool has no page navigation, so no nav links are appropriate. GitHub link is the only "missing" global action.
**Current code status:** Mostly done.

### Recommendation: Sticky Header Behavior — Keep Always-Visible
**Trust: 8/10**
**What:** Keep the header always visible. Do NOT implement scroll-up/scroll-down auto-hide.
**Why:** For a scanning tool where users watch live results, hiding the header on scroll-down would disorient the user during active scans.
**Current code status:** Already done.

### Recommendation: Theme Toggle — Add "Auto" Option as Three-State
**Trust: 9/10**
**What:** Change the theme toggle from two-state (Light/Dark) to three-state: Auto / Light / Dark.
**Why:** The current code already detects `prefers-color-scheme` on load but has no way to return to auto mode. Three-state is the industry standard in 2026.
**Current code status:** Needs change.

### Recommendation: Header Actions — Add GitHub Link, Keep Minimal
**Trust: 8/10**
**What:** Add exactly one GitHub icon link button to the header. Keep total header actions to 2.
**Why:** Research consistently shows 1-3 icon buttons is the right amount for utility tool headers.
**Current code status:** Needs change.

---

## Agent 5: Form Design

| Recommendation | Trust | Status |
|---|---|---|
| Keep single scrollable form (no tabs/wizard) | 9/10 | Done |
| Segmented control for CDN/WARP is correct | 8/10 | Done |
| Size numeric inputs narrower (ports ~8ch, timeout ~7ch) | 8/10 | Needs change |
| Hybrid validation: on-blur inline + submit-time safety net | 9/10 | Needs change |
| Add explanatory text to disabled fields | 9/10 | Needs change |
| Make WARP endpoints collapsible (like Phase 2) | 7/10 | Needs change |
| Add drag-and-drop + paste zone for wgconf | 7/10 | Needs change |
| Add inline help text below complex fields | 8/10 | Needs change |
| Move Reset button to results section toolbar | 7/10 | Needs change |
| Add `Ctrl+Enter` keyboard shortcut to start scan | 8/10 | Needs change |
| Placeholders as format examples only (correct) | 9/10 | Done |
| Show validation errors below fields with `aria-describedby` | 8/10 | Needs change |

### Recommendation: Hybrid validation — on-blur inline + submit-time summary
**Trust: 9/10**
**What:** Add on-blur validation for ports (format), concurrency (range), timeout (range), and CIDR textareas (line format). Keep submit-time validation as the safety net.
**Why:** "Reward Early, Punish Late" pattern from Smashing Magazine. Smart Interface Design Patterns: "Validate on blur for most fields."
**Current code status:** Needs change.

### Recommendation: Add explanatory text to disabled fields
**Trust: 9/10**
**What:** When fields disable, add a small muted note below explaining why.
**Why:** "Always explain why a field is disabled — never show it without context."
**Current code status:** Needs change.

### Recommendation: Add inline help text below complex fields
**Trust: 8/10**
**What:** Add concise help text below ports, CIDRs, concurrency, timeout fields.
**Why:** "Placeholders disappear when users type — use labels for identity, help text for guidance."
**Current code status:** Needs change.

---

## Agent 6: Data Table

| Recommendation | Trust | Status |
|---|---|---|
| Keep IP as first column (correct order) | 9/10 | Done |
| Right-align numeric columns (Latency, Loss, Port) | 9/10 | Needs change |
| Flex-based column widths + resizable columns | 8/10 | Needs change |
| Default sort by latency ascending | 8/10 | Needs change |
| Three density levels (compact/normal/comfortable) | 8/10 | Needs change |
| Empty state with illustration + CTA | 8/10 | Needs change |
| Sticky first column (IP) for horizontal scroll | 9/10 | Needs change |
| Multi-column sort (Shift+click) | 7/10 | Needs change |
| Inline latency bar in each cell | 7/10 | Needs change |
| Phase 2 failed detail on hover/click | 7/10 | Needs change |
| Per-row copy + copy format options | 7/10 | Needs change |
| Timestamped filenames + Markdown export | 7/10 | Needs change |
| Interactive histogram (click-to-filter) | 6/10 | Optional |
| Column group headers | 5/10 | Skip |

### Recommendation: Right-align numeric columns
**Trust: 9/10**
**What:** Right-align the Latency, Loss, and Port columns. Add `font-variant-numeric: tabular-nums` to all numeric cells.
**Why:** This is the single highest-impact readability rule for data tables. Right-aligned numbers let users scan digit columns vertically.
**Current code status:** Needs change.

### Recommendation: Sticky first column (IP) for horizontal scroll
**Trust: 9/10**
**What:** Add sticky first column (IP) for when horizontal scrolling is needed.
**Why:** On mobile, the current 7-column layout will overflow — horizontal scroll with sticky IP is the minimum viable solution.
**Current code status:** Partially done.

### Recommendation: Default sort by latency ascending
**Trust: 8/10**
**What:** When results first appear, apply a default sort of Latency ascending (fastest first).
**Why:** The purpose of CF-Scanner is to find usable IPs — fastest latency is the primary quality signal.
**Current code status:** Needs change.

### Recommendation: Empty state with illustration + CTA
**Trust: 8/10**
**What:** Replace the current text-only empty state with a simple SVG illustration, text, and a "Start a scan" button that scrolls to the form.
**Why:** Empty state best practices: explain the situation + provide a clear next step.
**Current code status:** Needs change.

---

## Agent 7: Status & Progress

| Recommendation | Trust | Status |
|---|---|---|
| Indeterminate → determinate transition + "X of Y" text | 9/10 | Needs change |
| Inline error with Retry button (no toast for errors) | 9/10 | Needs change |
| Update `document.title` during scan progress | 8/10 | Needs change |
| Progress bar 6px → 8px + ease-out transition | 8/10 | Needs change |
| Add Estimated Time Remaining (smoothed) | 8/10 | Needs change |
| Browser notification opt-in (post-first-scan) | 8/10 | Optional |
| Completion: checkmark animation + auto-scroll to results | 7/10 | Needs change |
| Cancel: no dialog, immediate stop + undo feedback | 7/10 | Needs change |
| Result counter badge on results header | 7/10 | Needs change |
| Rolling average rate (10s window) | 6/10 | Optional |
| Stats layout: move elapsed to progress bar area | 6/10 | Optional |

### Recommendation: Indeterminate → Determinate Transition
**Trust: 9/10**
**What:** Start with indeterminate progress bar during first 300-700ms warm-up, then switch to determinate. Always show "X of Y" text alongside the bar when determinate.
**Why:** For tasks >3s, determinate bars measurably reduce perceived wait. People overestimate passive waits by 36%.
**Current code status:** Partially done.

### Recommendation: Inline Error with Retry
**Trust: 9/10**
**What:** Keep errors inline in the status card but add a prominent "Retry" button. Do NOT use toast notifications for scan errors.
**Why:** "Use inline for operation-level status tied to the scan; reserve toasts for transient feedback."
**Current code status:** Partially done.

### Recommendation: Update Page Title During Scan
**Trust: 8/10**
**What:** Set `document.title` to reflect scan progress while scanning (e.g., "Scanning... 47% — CF-Scanner").
**Why:** Common pattern in Vercel deployments, CI/CD tools, and file uploaders.
**Current code status:** Needs change.

---

## Agent 8: Results & Export

| Recommendation | Trust | Status |
|---|---|---|
| Clipboard feedback: icon swap + aria-live + failure state | 10/10 | Needs change |
| Clipboard fallback for non-secure contexts | 8/10 | Needs change |
| Unified Download dropdown (merge Save/Export) | 8/10 | Needs change |
| ISO 8601 timestamped filenames with scan mode | 9/10 | Needs change |
| Keep CSV + JSON, add JSONL as third option | 8/10 | Needs change |
| Row click → expandable detail panel | 8/10 | Optional |
| Add search/filter in results header | 7/10 | Optional |
| Copy format options (IPs only, ip:port, JSON) | 7/10 | Needs change |
| Post-download toast confirmation | 7/10 | Needs change |
| Markdown table copy option | 6/10 | Optional |
| Reset confirmation dialog with consequence text | 9/10 | Needs change |
| Active profile indicator chip | 7/10 | Optional |

### Recommendation: Clipboard feedback with state machine
**Trust: 9/10**
**What:** Implement 4-state machine: idle → copying → copied/failed → idle. Icon swaps clipboard→check for ~1.5s with `aria-live="polite"` announcement.
**Why:** This is the single most documented UX pattern across all sources. Silent failure is the #1 reported clipboard UX bug.
**Current code status:** Needs change.

### Recommendation: ISO 8601 timestamp in filename
**Trust: 9/10**
**What:** Pattern: `cf-scanner-{mode}-{YYYY-MM-DDTHHmmss}.{ext}`
**Why:** ISO 8601 sorts alphabetically correctly, eliminates date ambiguity, and is parsed by every tool.
**Current code status:** Needs change.

### Recommendation: Reset confirmation dialog
**Trust: 9/10**
**What:** On Reset click: show modal dialog with "Clear all results?" and specific consequence text.
**Why:** Destructive actions need confirmation, but match friction to blast radius.
**Current code status:** Needs change.

---

## Agent 9: Accessibility & Platform

| Recommendation | Trust | Status |
|---|---|---|
| Target WCAG 2.2 Level AA (not AAA) | 10/10 | Adopt |
| Add skip-to-content link | 9/10 | Needs change |
| Make sort column headers keyboard-operable | 7/10 | Needs change |
| Add `<caption>` + `scope="col"` to table | 8/10 | Needs change |
| Live region for result count announcements | 9/10 | Needs change |
| Fix theme button `aria-label` mismatch | 6/10 | Needs change |
| Add forced-colors media query (Windows High Contrast) | 7/10 | Needs change |
| Add `scroll-padding-top` for sticky header | 7/10 | Needs change |
| Refine `prefers-reduced-motion` (keep essential transitions) | 7/10 | Needs change |
| Add `backdrop-filter` `@supports` fallback | 6/10 | Needs change |
| Remove redundant `aria-live` on `role="status"` | 6/10 | Trivial |
| Verify 200% zoom layout works | 8/10 | Manual test |
| Verify touch target sizes at mobile breakpoint | 9/10 | Audit |
| Do NOT support IE11 | 10/10 | Done |

### Recommendation: Target WCAG 2.2 Level AA conformance
**Trust: 10/10**
**What:** Aim for full WCAG 2.2 Level AA conformance. Do not target AAA.
**Why:** W3C states AA is the standard "many organizations strive to meet."
**Current code status:** Partially done.

### Recommendation: Add a skip-to-content link
**Trust: 9/10**
**What:** Add a visually-hidden-until-focused "Skip to main content" link as the first focusable element.
**Why:** WCAG 2.4.1 Bypass Blocks (Level A) requires a mechanism to bypass repeated content.
**Current code status:** Needs change.

### Recommendation: Add live region for result count updates
**Trust: 9/10**
**What:** Add a dedicated `role="status"` region that announces result count changes.
**Why:** WCAG 4.1.3 Status Messages (Level AA) requires status updates to be programmatically determinable.
**Current code status:** Needs change.

---

## Agent 10: Backend Exposure & Microinteractions

### Backend Exposure

| Recommendation | Trust | Status |
|---|---|---|
| Add `GET /api/status` (version, scan state, uptime) | 9/10 | Needs change |
| Frontend should call `GET /api/results` on load | 7/10 | Needs change |
| Remove `bundled` CIDRs from `/api/ranges` response | 8/10 | Needs change |
| Remove `generate_config`/`warp_plus_license` from frontend API | 8/10 | Needs change |
| Add structured error codes to `ScanEvent::Failed` | 7/10 | Needs change |
| Sanitize profiles on store (strip license fields) | 6/10 | Needs change |
| API versioning not needed (correct) | 5/10 | Done |
| Config URIs in plaintext over localhost acceptable | 4/10 | Done |

### Recommendation: Version hardcoded in HTML should come from API
**Trust: 9/10**
**What:** Add `GET /api/status` returning `{ version, git_hash, geoip_db_version, scan_running }`.
**Why:** The version is hardcoded in two places in `embed/index.html` and will drift from `Cargo.toml`.
**Current code status:** Needs change.

### Recommendation: `GET /api/ranges` leaks full CIDR list
**Trust: 8/10**
**What:** Remove `bundled` from the response, or expose it only behind a query param.
**Why:** The CIDR list is operational intelligence that adds no UI value.
**Current code status:** Needs change.

### Recommendation: Frontend doesn't use `GET /api/results`
**Trust: 7/10**
**What:** The frontend should call `GET /api/results` on load to recover from page refresh mid-scan.
**Why:** On page refresh, results are lost in the UI even though the engine still has them.
**Current code status:** Needs change.

### Microinteractions

| Recommendation | Trust | Status |
|---|---|---|
| Toast notifications for transient actions | 9/10 | Needs change |
| Keyboard shortcuts (Ctrl+Enter, Escape, ?) | 9/10 | Needs change |
| Preserve config on failure + Retry button | 9/10 | Partially done |
| Form state persistence in localStorage | 8/10 | Needs change |
| Undo toast for destructive actions (delete/reset) | 8/10 | Needs change |
| Progressive disclosure for advanced settings | 8/10 | Needs change |
| Copy feedback with inline icon swap | 9/10 | Needs change |
| Button loading state during scan | 8/10 | Needs change |
| Error shake animation on invalid form fields | 8/10 | Needs change |
| Empty state CTA improvement | 8/10 | Needs change |

### Recommendation: Toast notifications for transient actions
**Trust: 9/10**
**What:** Add a lightweight toast system (bottom-right, auto-dismiss 3s for success). Use for: "Copied to clipboard", "Profile saved", "Profile deleted", "Results exported".
**Why:** The current `showStatus()` mixes persistent scan state with ephemeral action confirmations — these should be separate channels.
**Current code status:** Needs change.

### Recommendation: Keyboard shortcuts with `?` overlay
**Trust: 9/10**
**What:** Add `Ctrl+Enter` to start scan, `Escape` to cancel, `?` to open a shortcut overlay. Show shortcuts as subtle badges next to buttons.
**Why:** Developer utility users expect keyboard-first workflows. Shortcuts must be discoverable.
**Current code status:** Needs change.

### Recommendation: Preserve config on scan failure + Retry button
**Trust: 9/10**
**What:** When a scan fails, keep the form populated. Show a "Retry" button that re-submits the same config.
**Why:** "Tell users what they can do next whenever recovery matters."
**Current code status:** Partially done.

---

## Top 20 Highest-Impact Changes (sorted by Trust)

| # | Change | Trust | Effort |
|---|---|---|---|
| 1 | Apply `tabular-nums` + `slashed-zero` to all numeric elements | 10/10 | 5 min |
| 2 | 3-state theme toggle (Auto/Light/Dark) | 10/10 | Medium |
| 3 | Clipboard feedback (icon swap + aria-live + failure state) | 10/10 | Low |
| 4 | Target WCAG 2.2 AA conformance | 10/10 | Adopt |
| 5 | Indeterminate→determinate progress + "X of Y" text | 9/10 | Low |
| 6 | Add skip-to-content link | 9/10 | Small |
| 7 | Add `GET /api/status` endpoint + frontend calls `GET /api/results` on load | 9/10 | Medium |
| 8 | Adopt 8px spacing scale with CSS custom properties | 9/10 | Medium |
| 9 | Add keyboard shortcuts (Ctrl+Enter, Escape, ? overlay) | 9/10 | Medium |
| 10 | Toast notifications for transient actions | 9/10 | Medium |
| 11 | Reset confirmation dialog with consequence text | 9/10 | Low |
| 12 | Right-align numeric columns in table | 9/10 | 5 min |
| 13 | `font-size: 15px` → rem for accessibility scaling | 9/10 | 1 min |
| 14 | Add inline help text below complex form fields | 9/10 | Small |
| 15 | Add explanatory text to disabled fields | 9/10 | Small |
| 16 | On-blur validation for ports/numbers/CIDRs | 9/10 | Medium |
| 17 | Live region for result count + sort announcements | 9/10 | Small |
| 18 | Fix 3-column → 2-column form layout | 9/10 | Small |
| 19 | Mobile touch targets 44x44px minimum | 9/10 | Small |
| 20 | Sticky first column (IP) for horizontal scroll | 9/10 | Medium |
