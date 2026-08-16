# UI Review Implementation Plan

Generated from 10-aspect design review (visual, typography, color, a11y, guidelines, performance, responsive, UX, code quality, security). Organized into 6 independently committable batches.

---

## Batch 1: Accessibility + Color Contrast (P1 critical)

### A1 — `aria-busy` silences live regions during scan
**File:** `embed/index.html:545, 1014, 1038`
**Problem:** `aria-busy="true"` on `.status-card` section suppresses `#scan-status`, `#progress-text`, and `#scan-error` announcements for the entire scan duration.
**Fix:** Remove `aria-busy` from the card. The scan status is not a "loading region" — it's live progress. If you want busy for the stats grid only, move it to `#stats` specifically.
- Delete `aria-busy="false"` from line 545
- Delete the `setAttribute("aria-busy", ...)` calls at lines 1014 and 1038

### C1 — Light-theme focus ring fails 3:1
**File:** `embed/index.html` (light theme block, around line 59–85)
**Problem:** Focus ring `--accent: #06b6d4` on white surface = 2.4:1 (needs 3:1 per WCAG 2.4.13).
**Fix:** Add a dedicated `--focus` token in the light block:
```css
[data-theme="light"] {
  --focus: #0891b2;  /* 3.7:1 on white */
}
```
Then use it in the focus rules (line 264–267):
```css
input:focus-visible, select:focus-visible, textarea:focus-visible {
  outline: 2px solid var(--focus, var(--accent));
}
```

### C2 — Placeholder text fails contrast in both themes
**File:** `embed/index.html:269`
**Problem:** `color-mix(in srgb, var(--muted) 70%, transparent)` yields ~4.1:1 dark, ~3.0:1 light (need 4.5:1).
**Fix:** Remove the `color-mix` — full `var(--muted)` passes in both (7.1 dark / 5.4 light):
```css
input::placeholder, textarea::placeholder { color: var(--muted); }
```

### C3 — Light primary button hover text illegible
**File:** `embed/index.html` (button.primary:hover, around line 357–361)
**Problem:** `--accent-strong` (#0e7490) as hover fill with `--accent-contrast` text = 2.6:1.
**Fix:** Make hover a lightened accent instead:
```css
[data-theme="light"] button.primary:hover {
  background: color-mix(in srgb, var(--accent) 85%, #fff);
}
```

### A5 — Sort announcement leaks caret glyph
**File:** `embed/index.html` (sort handler, around line 1637)
**Problem:** `th.textContent` includes the `.caret` span, SRs hear "Sorted by IP ▴ ascending".
**Fix:** Read label from `th.dataset.label` or strip `.caret` text:
```js
const label = th.querySelector('.caret')
  ? th.textContent.replace(th.querySelector('.caret').textContent, '').trim()
  : th.textContent.trim();
live.textContent = `Sorted by ${label} ${sortAsc ? 'ascending' : 'descending'}, ${results.length} results`;
```

### A8 — Global Escape cancels scan while typing
**File:** `embed/index.html` (keydown handler, around line 2184–2192)
**Problem:** Escape fires `cancelBtn.click()` regardless of focus — typing in a textarea cancels the scan.
**Fix:** Guard against text controls:
```js
if (e.key === "Escape" && !e.target.matches("input, textarea, select")) {
  if (cancelBtn.disabled) return;
  cancelBtn.click();
}
```

### G1 — Profile delete has no confirmation
**File:** `embed/index.html` (delete handler, around line 2105–2115)
**Problem:** Immediate DELETE + toast, no confirm. Inconsistent with Reset (which confirms).
**Fix:** Add confirm before deletion:
```js
del.addEventListener("click", () => {
  if (!confirm(`Delete profile "${name}"?`)) return;
  // ...existing delete logic
});
```

### C7 — Remove dead tokens
**File:** `embed/index.html:27, 29, 42` and `64, 66, 79`
**Problem:** `--surface-4`, `--border-subtle`, `--warning-contrast` defined but never used.
**Fix:** Delete these 6 lines (3 in :root, 3 in light block). Or use `--warning-contrast` for a warning badge — but simpler to remove.

### T6 — Dash consistency in help text
**File:** `embed/index.html` (help spans and validation strings)
**Problem:** Labels use en dashes (`1&ndash;1000`) but help text uses hyphens (`1-65535`).
**Fix:** Replace hyphen-ranges with en dashes in help text: `1-65535` → `1&ndash;65535`, and in JS validation strings: `1-65535` → `1–65535`.

---

## Batch 2: Performance (P1)

### V1 — Full table re-sort on every flush including progress-only ticks
**File:** `embed/index.html` (flushRender ~line 1217, renderTable ~line 1248, sortedResults ~line 1196)
**Problem:** `flushRender()` unconditionally calls `renderTable()` → `sortedResults()` even when only progress text changed.
**Fix:** Add dirty flags:
```js
let tableDirty = false, histDirty = false;

// In addResult() success path:
tableDirty = true; histDirty = true;

// In sort click handler:
tableDirty = true;

// In flushRender:
function flushRender() {
  flushQueued = false; flushTimer = null;
  if (tableDirty) { renderTable(); tableDirty = false; }
  if (histDirty) { renderHistogram(); histDirty = false; }
  applyProgress(); // always update stats/title (cheap textContent)
}
```

### V3 — Memoized sort
**File:** `embed/index.html` (sortedResults ~line 1196)
**Problem:** O(n log n) re-slice + re-sort on every flush even when rows only append.
**Fix:** Cache sorted array and binary-insert new rows:
```js
let sortedCache = null, cacheLen = 0, cacheKey = null, cacheAsc = true;
function sortedResults() {
  if (sortedCache && cacheLen === results.length && cacheKey === sortKey && cacheAsc === sortAsc) {
    return sortedCache;
  }
  if (sortedCache && cacheKey === sortKey && cacheAsc === sortAsc) {
    // Only new rows — binary insert
    for (let i = cacheLen; i < results.length; i++) {
      const r = results[i];
      let lo = 0, hi = sortedCache.length;
      while (lo < hi) { const mid = (lo + hi) >> 1; compareRows(sortedCache[mid], r) <= 0 ? lo = mid + 1 : hi = mid; }
      sortedCache.splice(lo, 0, r);
    }
  } else {
    sortedCache = results.slice().sort(compareRows);
  }
  cacheLen = results.length; cacheKey = sortKey; cacheAsc = sortAsc;
  return sortedCache;
}
```

### V2 — content-visibility for unbounded table
**File:** `embed/index.html` (CSS, around tbody rules)
**Fix:** Add CSS-only virtualization:
```css
tbody tr {
  content-visibility: auto;
  contain-intrinsic-size: auto 34px;
}
```

### P2-01 — Fix localeCompare for IP sort
**File:** `embed/index.html` (compareRows ~line 1199–1206)
**Problem:** `localeCompare` is ~100× slower than `<` and produces wrong IPv4 sort.
**Fix:**
```js
function cmpIp(a, b) {
  const an = a.split(".").map(Number), bn = b.split(".").map(Number);
  for (let i = 0; i < 4; i++) { const d = an[i] - bn[i]; if (d) return d; }
  return 0;
}
// In compareRows: if (sortKey === "ip") return cmpIp(a.ip, b.ip);
// For country/colo: use simple < > instead of localeCompare
```

---

## Batch 3: Responsive (P1)

### R1 — App bar overflows 320–375px
**File:** `embed/index.html` (CSS, add media query)
**Fix:**
```css
@media (max-width: 480px) {
  .appbar-inner { gap: 0.6rem; padding: 0.55rem 0.9rem; }
  .appbar-sub { display: none; }
  .version-pill { display: none; }
}
```

### R2 — Segmented control overflows 320–414px
**File:** `embed/index.html` (CSS, add media query)
**Fix:**
```css
@media (max-width: 420px) {
  .seg-item { white-space: normal; text-align: center; line-height: 1.25; }
}
```

### R3 — iOS auto-zoom on form fields
**File:** `embed/index.html` (CSS, add media query)
**Fix:**
```css
@media (max-width: 768px) {
  input, select, textarea { font-size: 16px; }
}
```

### R4/R5 — Touch target bumps
**File:** `embed/index.html` (CSS, add media query)
**Fix:**
```css
@media (max-width: 640px) {
  .appbar a[aria-label="GitHub"] { width: 44px; height: 44px; }
  th.sortable { padding-top: 0.75rem; padding-bottom: 0.75rem; }
}
```

---

## Batch 4: Visual Polish (P2)

### V4 — Drop card shadow
**File:** `embed/index.html` (.card rule ~line 166)
**Fix:** Remove or reduce box-shadow on cards:
```css
.card { box-shadow: none; }  /* elevation via surface lightness already */
```

### V5 — Panel border → divider
**File:** `embed/index.html` (.panel rule ~line 234)
**Fix:** Replace panel boxes with dividers:
```css
.panel { background: transparent; border: 0; border-radius: 0; border-top: 1px solid var(--border); }
.panel:first-of-type { border-top: 0; }
```

### V8 — grid-3 orphan fix
**File:** `embed/index.html` (CSS ~line 242, HTML Connection panel ~line 611, Phase-2 ~line 747)
**Fix:** Rename `.grid-3` to `.grid-2` (it already renders 2 columns). Add `.grid-3-wide` for the Connection panel that places 3 fields as full-width + 2-column pair:
```css
/* In Connection panel: Ports full-width, then Concurrency + Timeout side-by-side */
/* In Phase-2: Packets, Length, Interval all full-width or 3-col at >1080px */
```

### V10 — Start button collapse mid-scan
**File:** `embed/index.html` (#start-btn CSS, line 765 area)
**Fix:** Add min-width and hide inner elements via class toggle:
```css
#start-btn { min-width: 11rem; }
#start-btn.is-running svg, #start-btn.is-running kbd { display: none; }
```

### T1 — Loss column needs tabular-nums
**File:** `embed/index.html` (Loss cell rendering, ~line 1369–1373)
**Fix:** Add `mono` class to loss cells:
```js
return cell(pct, v.loss_pct > 0 ? "lat-bad mono" : "mono");
```
And in CSS, ensure `td.mono` gets `font-variant-numeric: tabular-nums slashed-zero` (already does via line 409).

### T2 — Mono on form inputs
**File:** `embed/index.html` (CSS, around line 247–255)
**Fix:** Add mono font to technical inputs:
```css
textarea[name="phase2_configs"],
input[name="ports"],
textarea[name="custom_cidrs"],
textarea[name="exclude_cidrs"],
textarea[name="warp_wgconf"],
input[name="phase2_snis"],
input[name="phase2_packets"],
input[name="phase2_length"],
input[name="phase2_interval"] {
  font-family: "Cascadia Code", "JetBrains Mono", ui-monospace, Consolas, monospace;
}
```

### T8 — Empty-state italic leaks into CTA
**File:** `embed/index.html` (#empty-row CSS ~line 433)
**Fix:**
```css
#empty-row td { font-style: normal; }
#empty-row .empty-title { font-style: italic; font-weight: 600; }
#empty-row button { font-style: normal; }
```

---

## Batch 5: Code Quality + Security (P2)

### F2 — Safe localStorage wrapper
**File:** `embed/index.html` (JS, near top of script section, ~line 850+)
**Fix:** Replace direct `localStorage` calls with a safe wrapper:
```js
const store = {
  get(k, d) { try { const v = localStorage.getItem(k); return v == null ? d : v; } catch { return d; } },
  set(k, v) { try { localStorage.setItem(k, v); } catch { /* blocked */ } }
};
// Replace: localStorage.getItem("ui-theme") → store.get("ui-theme", "system")
// Replace: localStorage.setItem(...) → store.set(...)
```

### F7 — Clear error/progress on terminal state
**File:** `embed/index.html` (finishScan ~line 1074, failScan ~line 1118)
**Fix:** Add cleanup to terminal functions:
```js
// In finishScan(), after setting state:
hideErrorCard();
progressText.textContent = "";

// In failScan():
progressText.textContent = "";
```

### S1 — CSP meta tag
**File:** `embed/index.html` (head section, after line 7)
**Fix:** Add CSP meta tag (inline scripts require hashes — but for a first pass, use report-only or nonce approach via the Rust server):
Actually — since this is `include_str!` from Rust, the cleanest approach is a CSP header in `src/server.rs`. Add to the HTML response handler:
```rust
headers.insert("Content-Security-Policy", "default-src 'self'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'".parse().unwrap());
headers.insert("X-Content-Type-Options", "nosniff".parse().unwrap());
```

### G3 — Empty-state copy after 0-result scan
**File:** `embed/index.html` (empty row builder ~line 1230–1245)
**Fix:** Differentiate pre-scan vs. zero-result states:
```js
const isPostScan = scanState === "done" || scanState === "idle";
const copy = results.length === 0 && isPostScan
  ? "No working endpoints found — try wider ports or different ranges."
  : "Results will appear here once you start a scan.";
```

### G4 — Phase-2 help spans missing
**File:** `embed/index.html` (Phase-2 HTML ~line 739–756)
**Fix:** Add `.help` spans to `phase2_snis`, `phase2_packets`, `phase2_length`, `phase2_interval` fields, mirroring the pattern of `help-ports`.

---

## Batch 6: Phase-2 Panel Layout (P2)

### Phase-2 grid layout cleanup
**File:** `embed/index.html` (Phase-2 HTML ~line 719–757, CSS)
**Problem:** Configs textarea dominates left column; Fragment/Parallel float mid-right; Packets/Length/Interval orphaned.
**Fix:** Restructure to a single-column flow:
```
Configs textarea (full width)
Fragment preset + Parallel instances (side by side)
SNI variants + Probe URL (side by side)
Packets + Length + Interval (3-column at >1080, else stacked)
```

Replace the outer `grid grid-2` with a simpler layout:
```html
<label class="field">Configs... (full width textarea)</label>
<div class="grid grid-2">
  <label class="field">Fragment preset...</label>
  <label class="field">Parallel instances...</label>
</div>
<div class="grid grid-2">
  <label class="field">SNI variants...</label>
  <label class="field">Probe URL...</label>
</div>
<div class="grid grid-3">
  <label class="field">Packets...</label>
  <label class="field">Length...</label>
  <label class="field">Interval...</label>
</div>
```

---

## Implementation Order

1. **Batch 1** (Accessibility + Color) — highest impact, mostly token changes
2. **Batch 3** (Responsive) — pure CSS additions, no JS risk
3. **Batch 5** (Code Quality) — localStorage safety, terminal cleanup, CSP
4. **Batch 2** (Performance) — JS logic changes, test carefully
5. **Batch 4** (Visual Polish) — CSS changes
6. **Batch 6** (Phase-2 Layout) — HTML restructuring

Each batch should be a separate commit. Run `cargo clippy --all-targets -- -D warnings` and `cargo fmt --check` after each.

---

## Verification

After all batches:
1. `cargo build --release` — confirm build succeeds
2. Start server (`cargo run -- serve --port 8765`)
3. Open in browser and verify:
   - Theme toggle works (system/light/dark)
   - Focus ring visible in light theme
   - Form validation shows errors
   - Scan completes and results table renders
   - Sort works, no caret glyph in announcement
   - Escape doesn't cancel while typing
   - App bar doesn't overflow at 320px
   - Phase-2 panel fields align properly
   - Toasts don't stack up
4. `cargo clippy --all-targets -- -D warnings`
5. `cargo fmt --check`
