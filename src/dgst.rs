//! XTLS `.dgst` digest grammar, shared by the build script (`#[path]` include
//! in build.rs) and the runtime downloader (src/xray.rs). One canonical copy
//! so the two parsers cannot silently diverge. Std-only: build-deps are fixed.

/// Digest from `.dgst` text: strict `SHA2-256= <64 hex>[ <filename>]` line
/// grammar. A loose "first 64-char hex run" scan could grab a substring of a
/// longer digest on a comment line, so the value must be a clean 64-hex token.
/// Lowercased to match `Sha256` hex output.
pub fn dgst_sha256_hex(text: &str) -> Option<String> {
    let line = text
        .lines()
        .map(str::trim_start)
        .find(|l| l.starts_with("SHA2-256="))?;
    let hex = line["SHA2-256=".len()..].split_whitespace().next()?;
    (hex.len() == 64 && hex.bytes().all(|b| b.is_ascii_hexdigit()))
        .then(|| hex.to_ascii_lowercase())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_labeled_sha2_256_and_lowercases() {
        let dgst = format!(
            "MD5= {}\nSHA2-256= {}\nSHA2-512= {}",
            "b".repeat(32),
            "A".repeat(64),
            "d".repeat(128)
        );
        assert_eq!(dgst_sha256_hex(&dgst), Some("a".repeat(64)));
    }

    #[test]
    fn garbage_has_no_digest() {
        assert_eq!(dgst_sha256_hex("garbage"), None);
        assert_eq!(dgst_sha256_hex(""), None);
        let short = format!("SHA2-256= {}", "a".repeat(63));
        assert_eq!(dgst_sha256_hex(&short), None);
    }

    #[test]
    fn long_hex_run_on_other_line_is_not_grabbed() {
        let dgst = format!(
            "# see also SHA2-384= {}\nSHA2-256= {}",
            "e".repeat(96),
            "f".repeat(64)
        );
        assert_eq!(dgst_sha256_hex(&dgst), Some("f".repeat(64)));
    }

    #[test]
    fn duplicate_labels_take_first_and_trailing_junk_rejected() {
        let dgst = format!(
            "SHA2-256= {}x\nSHA2-256= {}",
            "a".repeat(64),
            "b".repeat(64)
        );
        assert_eq!(dgst_sha256_hex(&dgst), None);
        let clean = format!("SHA2-256= {}\n", "1".repeat(64));
        assert_eq!(dgst_sha256_hex(&clean), Some("1".repeat(64)));
    }

    #[test]
    fn trailing_filename_after_space_is_tolerated() {
        let dgst = format!("SHA2-256= {} Xray-linux-64.zip", "2".repeat(64));
        assert_eq!(dgst_sha256_hex(&dgst), Some("2".repeat(64)));
    }
}
