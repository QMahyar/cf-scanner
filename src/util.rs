pub(crate) fn percent_decode(s: &str) -> String {
    percent_encoding::percent_decode_str(s)
        .decode_utf8_lossy()
        .into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn percent_decode_plain_and_empty_strings() {
        assert_eq!(percent_decode(""), "");
        assert_eq!(percent_decode("plain-text_1.2"), "plain-text_1.2");
        assert_eq!(percent_decode("a+b"), "a+b", "+ is not a space here");
    }

    #[test]
    fn percent_decode_standard_and_multi_byte_sequences() {
        assert_eq!(percent_decode("%41%42"), "AB");
        assert_eq!(percent_decode("a%20b"), "a b");
        assert_eq!(percent_decode("%C3%A9"), "é", "UTF-8 multi-byte");
        assert_eq!(percent_decode("%E4%B8%AD"), "中");
        assert_eq!(percent_decode("%3D%26"), "=&", "wg URI query separators");
    }

    #[test]
    fn percent_decode_invalid_sequences_pass_through_lossily() {
        // Truncated and malformed sequences are kept as literal text.
        assert_eq!(percent_decode("%"), "%");
        assert_eq!(percent_decode("%4"), "%4");
        assert_eq!(percent_decode("100%"), "100%");
        // Non-UTF-8 bytes become the replacement char, never panic.
        assert_eq!(
            percent_decode("%FF"),
            char::REPLACEMENT_CHARACTER.to_string()
        );
        assert_eq!(
            percent_decode("%C3"),
            char::REPLACEMENT_CHARACTER.to_string()
        );
    }
}
