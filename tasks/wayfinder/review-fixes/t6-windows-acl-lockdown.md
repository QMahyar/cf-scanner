---
name: Windows ACL lockdown for secret files
labels: [wayfinder:task]
state: closed
assignee: ox-alpha
branch: review/platform
blocked-by: []
---

## Question

Private-key/config files on Windows use default ACLs: `identity.json`
(warpgen), `profiles.json` (`server.rs:89-92` TODO), trial configs
(`xray.rs:284-287` plain `fs::write` on non-unix). Other local users can read
them. Unix paths are already 0o600-at-open.

**Pre-approved**: adding the `windows` crate (windows-rs) for DACL work — the
user approved a crate up front in grilling round 2.

Fix direction: a small helper (e.g. `paths::lock_down_to_owner(path)`) that on
Windows sets a DACL granting only the current user (and SYSTEM/Administrators
if conventional) access, called right after every write of a secret-bearing
file; no-op on non-Windows. Apply to identity.json, profiles.json, and the
non-unix arm of `write_trial_config`. Prefer setting the protected flag so
inherited ACEs are dropped. Unit-test what is testable off-Windows (cfg-gated)
plus a Windows-only integration test behind `#[cfg(windows)]`.

Coordinate with `t5-build-platform-cli.md` — same branch; claim whichever is
open, never write concurrently.

Acceptance: verification trio green on Windows; helper covers all three write
sites; TODO comment at server.rs:89-92 removed.

## Resolution

Fixed on eview/platform, commit dc5570c. paths::lock_down_to_owner builds
a one-ACE ACL (current user GENERIC_ALL via TRUSTEE_IS_SID from the process
token) and applies it with SetNamedSecurityInfoW +
PROTECTED_DACL_SECURITY_INFORMATION, dropping inherited ACEs; no-op on
non-Windows. Wired into warpgen::write_private, xray::write_trial_config and
the profiles.json save (server.rs TODO removed). Dependency: windows 0.62.2,
default-features off, features Win32_Foundation / Win32_Security /
Win32_Security_Authorization / Win32_System_Threading. Live proof (icacls):
normal file = 5 inherited ACEs (sandbox group M, SYSTEM F, Admins F, owner F);
locked-down file = single 'qmahyar:(F)', no inheritance. Gate green incl. new
cfg(windows) owner-write test (330 lib tests).
