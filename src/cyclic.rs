//! De Bruijn ("cyclic") patterns for locating the saved return address.
//!
//! You overflow a buffer with `pattern(n)`, read back the value that landed in
//! EIP/RIP (or any register) from the debugger, and `find()` tells you the exact
//! offset. This is pwntools-compatible: the default alphabet is lowercase ascii
//! and the default subsequence length is 4 (use 8 for 64-bit saved addresses).

const ALPHABET: &[u8] = b"abcdefghijklmnopqrstuvwxyz";

/// Generate the first `length` bytes of the De Bruijn sequence B(26, n).
pub fn pattern(length: usize, n: usize) -> Vec<u8> {
    let k = ALPHABET.len();
    let mut a = vec![0usize; k * n];
    let mut seq: Vec<u8> = Vec::with_capacity(length);

    // Iterative De Bruijn generation (Frank Ruskey's algorithm), stopping as
    // soon as we have emitted `length` symbols.
    fn db(
        t: usize,
        p: usize,
        n: usize,
        k: usize,
        a: &mut [usize],
        seq: &mut Vec<u8>,
        length: usize,
    ) -> bool {
        if seq.len() >= length {
            return true;
        }
        if t > n {
            if n % p == 0 {
                for &i in &a[1..=p] {
                    seq.push(ALPHABET[i]);
                    if seq.len() >= length {
                        return true;
                    }
                }
            }
        } else {
            a[t] = a[t - p];
            if db(t + 1, p, n, k, a, seq, length) {
                return true;
            }
            for j in (a[t - p] + 1)..k {
                a[t] = j;
                if db(t + 1, t, n, k, a, seq, length) {
                    return true;
                }
            }
        }
        false
    }

    db(1, 1, n, k, &mut a, &mut seq, length);
    seq.truncate(length);
    seq
}

/// Find the offset of `needle` within the De Bruijn sequence of subsequence
/// length `n`. `needle` is usually the `n` bytes recovered from the crash.
pub fn find(needle: &[u8], n: usize) -> Option<usize> {
    if needle.is_empty() {
        return None;
    }
    // The full sequence has length 26^n; generate enough to contain any n-gram.
    let full = pattern(ALPHABET.len().pow(n as u32), n);
    full.windows(needle.len()).position(|w| w == needle)
}

/// Interpret a crash value as little-endian bytes (the common case: the value
/// you read from RIP/EIP is stored little-endian in memory).
pub fn value_to_needle(value: u64, width: usize) -> Vec<u8> {
    value.to_le_bytes()[..width.min(8)].to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pattern_prefix_is_stable() {
        let p = pattern(16, 4);
        assert_eq!(&p, b"aaaabaaacaaadaaa");
    }

    #[test]
    fn find_roundtrips() {
        let p = pattern(1024, 4);
        // Take a 4-byte window at a known offset and recover it.
        let off = 500;
        let needle = &p[off..off + 4];
        assert_eq!(find(needle, 4), Some(off));
    }

    #[test]
    fn find_from_le_value() {
        // "faaa" little-endian recovered from a 32-bit crash.
        let needle = value_to_needle(u32::from_le_bytes(*b"faaa") as u64, 4);
        assert_eq!(find(&needle, 4), find(b"faaa", 4));
    }
}
