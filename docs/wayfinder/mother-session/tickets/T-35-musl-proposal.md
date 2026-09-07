# Proposal — musl/Alpine support (from T-25/F-25, proposal only)

## Status

PROPOSAL — not approved for implementation. Written per the T-25 refine
decision ("musl/Alpine: APPROVED as proposal ticket only"). No matrix,
dist config, or wrapper behavior changes until the USER accepts this.

## Problem

The npm wrapper ships glibc-linked binaries
(`x86_64-unknown-linux-gnu`, `aarch64-unknown-linux-gnu`). On musl
systems (Alpine, some Docker CI images, postmarketOS) the binary fails
at spawn time with a bare loader error:

```
Error loading shared library ld-linux-x86-64.so.2: No such file or directory
```

install.js now warns at install time (T-25), and README documents the
glibc requirement — but the binary still does not run there.

## Constraints

- AGENTS.md Termux gotcha stands: static musl builds of cf-scanner itself
  work, but the bundled xray linux-arm64 release is glibc; that is
  "document, don't fix".
- ADR-009 already dropped macOS targets; adding musl must not reopen a
  matrix-expansion pattern without weighing CI cost.
- npm package must stay dep-free (no postinstall JS unzipping stacks).

## Proposal

1. **dist targets.** Add `x86_64-unknown-linux-musl` (x64 first; arm64 musl
   only if there is demand — Alpine arm64 CI is slow and flaky). dist builds
   it in a musl cross container (`dockcross/linux-x64-musl` or a
   `rust:alpine` image); the profile already sets `lto="thin"` +
   `codegen-units=1`.
2. **xray on musl x64.** The xray release ships `Xray-linux-64.zip`
   (glibc). Two options:
   a. Bundle the glibc xray anyway and document `apk add gcompat` (the
      compatibility layer) — zero xray build work, one doc line. Risk:
      gcompat covers most syscalls but xray's QUIC paths are untested on it.
   b. Skip bundling xray for the musl target (0-byte placeholder +
      `CF_SCANNER_OFFLINE_BUILD`-style fallback): the runtime download
      fallback in `xray.rs::resolve_binary` then fetches the glibc xray,
      which still needs gcompat. Same end state; cleaner intent.
   Recommended: (b) + document gcompat, until an official musl xray exists.
3. **Wrapper detection.** In `install.js`, extend `TARGETS` with
   `"linux-x64": "x86_64-unknown-linux-musl"` chosen when
   `/lib/ld-musl-x86_64.so.1` exists (the same probe main() already runs
   for the warning). Archive name follows dist's triple naming, so
   `cf-scanner-x86_64-unknown-linux-musl.tar.xz` downloads automatically.
   Fallback stays the glibc triple if the musl archive 404s, with the
   existing warning as the explanation.
4. **CI.** One extra dist host job (musl x64) + one smoke test inside an
   Alpine container (`apk add libstdc++ gcompat`, run `cf-scanner --help`,
   assert exit 0). Estimated +3-5 min per release run.
5. **Docs.** README platform table gains a musl row; the Termux gotcha in
   AGENTS.md is referenced (arm64 musl stays unsupported for the same
   glibc-xray reason).

## Effort & Risk

- Effort: dist container config (~1h), wrapper detection (~30min, largely
  written), CI job (~1h), docs (~30min).
- Risk: low — additive target, no existing-artifact change; gcompat
  uncertainty is contained by documenting xray as "phase 2 requires
  gcompat" on musl.
- Reversibility: a 404 on the new archive falls back to glibc + warning,
  so a botched release degrades to today's behavior.
