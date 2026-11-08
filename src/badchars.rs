//! Bad-character test buffers.
//!
//! You drop this buffer into the vulnerable input, then compare it byte-for-byte
//! in memory against what the program stored. Bytes that are missing or mangled
//! are "bad" (classically `\x00`, `\x0a`, `\x0d`) and must be excluded from
//! addresses and shellcode.

/// Build the ordered byte set `0x01..=0xff` minus `exclude`.
pub fn buffer(exclude: &[u8]) -> Vec<u8> {
    (1u16..=0xff)
        .map(|b| b as u8)
        .filter(|b| !exclude.contains(b))
        .collect()
}

/// Render bytes as `\xNN` escapes.
pub fn as_escapes(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("\\x{b:02x}")).collect()
}

/// Render bytes as a C array body.
pub fn as_c_array(bytes: &[u8]) -> String {
    let body = bytes
        .iter()
        .map(|b| format!("0x{b:02x}"))
        .collect::<Vec<_>>()
        .join(", ");
    format!("unsigned char badchar_test[] = {{ {body} }};")
}

/// Parse a comma/space separated list of hex bytes (e.g. "00,0a 0d").
pub fn parse_bytes(s: &str) -> Result<Vec<u8>, String> {
    s.split([',', ' ', '\\', 'x'])
        .map(str::trim)
        .filter(|t| !t.is_empty())
        .map(|t| u8::from_str_radix(t, 16).map_err(|_| format!("bad hex byte: {t}")))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn excludes_requested() {
        let b = buffer(&[0x00, 0x0a, 0x0d]);
        assert!(!b.contains(&0x0a));
        assert!(b.contains(&0x0b));
        assert_eq!(b[0], 0x01); // 0x00 never present anyway
        assert_eq!(b.len(), 255 - 2); // 0x01..0xff is 255; minus 0a,0d
    }

    #[test]
    fn parses_hex_forms() {
        assert_eq!(parse_bytes("00,0a 0d").unwrap(), vec![0x00, 0x0a, 0x0d]);
        assert_eq!(parse_bytes("\\x41\\x42").unwrap(), vec![0x41, 0x42]);
        assert!(parse_bytes("zz").is_err());
    }
}
