//! XTLS `.dgst` digest grammar, shared by the build script (`#[path]` include
//! in build.rs) and the runtime downloader (src/xray.rs). One canonical copy
//! so the two parsers cannot silently diverge. Std-only: build-deps are fixed.

/// Digest from `.dgst` text: labeled lines (`SHA2-256= <hex>`, no filename);
/// scoped to the first 64-char hex run on the SHA-256 line so format
/// variations are tolerated. Lowercased to match `Sha256` hex output.
pub fn dgst_sha256_hex(text: &str) -> Option<String> {
    let line = text
        .lines()
        .find(|l| l.trim_start().starts_with("SHA2-256"))?;
    line.split(|c: char| !c.is_ascii_hexdigit())
        .find(|s| s.len() == 64)
        .map(str::to_ascii_lowercase)
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
}
