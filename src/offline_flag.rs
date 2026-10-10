use std::ffi::OsStr;

/// Explicit truthy parse for `CFSCANNER_OFFLINE_BUILD` (story 24): only
/// `1`/`true`/`yes`/`on` (case-insensitive, trimmed) take the offline path.
/// Everything else — unset, empty, `0`, `false`, `no`, `off`, or any other
/// value — builds online. The old non-empty check treated `0`/`false` as
/// offline, which surprised builders.
pub fn is_truthy(var: Option<&OsStr>) -> bool {
    match var.and_then(|v| v.to_str()) {
        Some(s) => matches!(
            s.trim().to_ascii_lowercase().as_str(),
            "1" | "true" | "yes" | "on" | "y"
        ),
        None => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn offline_flag_truthy_only_on_explicit_values() {
        // Acceptance: "0"/"false" must NOT take the offline path.
        for off in [
            None,
            Some(""),
            Some("   "),
            Some("0"),
            Some("false"),
            Some("FALSE"),
            Some("no"),
            Some("off"),
            Some("2"),
            Some("maybe"),
        ] {
            let var = off.map(std::ffi::OsStr::new);
            assert!(!is_truthy(var), "must be online for {off:?}");
        }
        for on in [
            "1", "true", "TRUE", "yes", "YES", "on", "ON", "y", "  True  ",
        ] {
            let var = Some(std::ffi::OsStr::new(on));
            assert!(is_truthy(var), "must be offline for {on:?}");
        }
    }
}
