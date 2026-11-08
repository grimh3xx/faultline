//! ROP gadget discovery with the pure-Rust iced-x86 disassembler.
//!
//! For each gadget terminator (a `ret`, `ret imm16`, or — with `--jop` — an
//! indirect `jmp`/`call`), faultline walks backwards a bounded number of
//! instructions and keeps every clean, linear instruction stream that ends
//! exactly on the terminator. Results are de-duplicated by text.

use std::collections::HashMap;

use iced_x86::{Decoder, DecoderOptions, FlowControl, Formatter, Instruction, IntelFormatter};
use serde::Serialize;

use crate::binary::ExecImage;

#[derive(Debug, Clone, Serialize)]
pub struct Gadget {
    pub addr: u64,
    pub text: String,
    /// Number of instructions (including the terminator).
    pub len: usize,
}

#[derive(Debug, Clone)]
pub struct Options {
    /// Maximum instructions per gadget (including the terminator).
    pub max_depth: usize,
    /// Also end gadgets on indirect jmp/call (JOP/COP).
    pub jop: bool,
    /// Keep only gadgets whose text contains this substring.
    pub filter: Option<String>,
    /// Cap on returned gadgets.
    pub limit: usize,
}

impl Default for Options {
    fn default() -> Self {
        Options {
            max_depth: 6,
            jop: false,
            filter: None,
            limit: 2000,
        }
    }
}

/// Internal cap on distinct gadgets collected while scanning, so a `--filter`
/// still finds matches anywhere in the binary (the output `limit` applies only
/// after filtering). Bounds memory on very large images.
const SCAN_CAP: usize = 500_000;

/// Find gadgets across every executable section of an image.
pub fn find(image: &ExecImage, opts: &Options) -> Vec<Gadget> {
    let mut seen: HashMap<String, u64> = HashMap::new();
    for sec in &image.sections {
        scan_section(&sec.bytes, sec.va, image.bits, opts, &mut seen);
        if seen.len() >= SCAN_CAP {
            break;
        }
    }

    let mut out: Vec<Gadget> = seen
        .into_iter()
        .map(|(text, addr)| {
            let len = text.matches(';').count() + 1;
            Gadget { addr, text, len }
        })
        .collect();
    if let Some(f) = &opts.filter {
        let f = f.to_ascii_lowercase();
        out.retain(|g| g.text.to_ascii_lowercase().contains(&f));
    }
    out.sort_by_key(|g| g.addr);
    out.truncate(opts.limit);
    out
}

/// Byte offsets within `bytes` where a gadget may terminate.
fn terminator_offsets(bytes: &[u8], jop: bool) -> Vec<(usize, usize)> {
    // (offset, terminator byte length) — c3=ret(1), c2=ret imm16(3).
    let mut t = Vec::new();
    for (i, &b) in bytes.iter().enumerate() {
        match b {
            0xc3 => t.push((i, 1)),
            0xc2 if i + 3 <= bytes.len() => t.push((i, 3)),
            // Indirect jmp/call reg: opcode ff, modrm reg field 2 (call) or 4 (jmp).
            0xff if jop && i + 2 <= bytes.len() => {
                let reg = (bytes[i + 1] >> 3) & 0x7;
                if reg == 2 || reg == 4 {
                    t.push((i, 2));
                }
            }
            _ => {}
        }
    }
    t
}

fn scan_section(bytes: &[u8], va: u64, bits: u32, opts: &Options, seen: &mut HashMap<String, u64>) {
    // Average x86 instruction is a few bytes; bound the backward window.
    let max_back = opts.max_depth * 8;

    for (term, term_len) in terminator_offsets(bytes, opts.jop) {
        let term_end = term + term_len;
        let lo = term.saturating_sub(max_back);
        for start in lo..=term {
            if let Some(g) = try_gadget(bytes, va, bits, start, term, term_end, opts.max_depth) {
                seen.entry(g.0).or_insert(g.1);
                if seen.len() >= SCAN_CAP {
                    return;
                }
            }
        }
    }
}

/// Try to decode a clean gadget from `start` that ends exactly at the
/// terminator. Returns (text, address) on success.
fn try_gadget(
    bytes: &[u8],
    va: u64,
    bits: u32,
    start: usize,
    term: usize,
    term_end: usize,
    max_depth: usize,
) -> Option<(String, u64)> {
    let mut decoder = Decoder::with_ip(
        bits,
        &bytes[start..term_end],
        va + start as u64,
        DecoderOptions::NONE,
    );
    let mut fmt = IntelFormatter::new();
    let mut parts: Vec<String> = Vec::new();
    let mut instr = Instruction::default();

    while decoder.can_decode() {
        decoder.decode_out(&mut instr);
        if instr.is_invalid() {
            return None;
        }
        let ip = instr.ip() - va; // byte offset within section
        let next = ip + instr.len() as u64;

        if (ip as usize) < term {
            // A mid-gadget instruction must be linear: no control-flow changes.
            if instr.flow_control() != FlowControl::Next {
                return None;
            }
            if next as usize > term {
                return None; // overlaps the terminator
            }
            let mut s = String::new();
            fmt.format(&instr, &mut s);
            parts.push(s);
            if parts.len() >= max_depth {
                return None;
            }
        } else if ip as usize == term {
            // The terminator itself.
            let mut s = String::new();
            fmt.format(&instr, &mut s);
            parts.push(s);
            let text = parts.join("; ");
            return Some((text, va + start as u64));
        } else {
            return None;
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::binary::{ExecImage, ExecSection};

    fn img(bytes: Vec<u8>, bits: u32) -> ExecImage {
        ExecImage {
            bits,
            sections: vec![ExecSection {
                name: ".text".into(),
                va: 0x1000,
                bytes,
            }],
        }
    }

    #[test]
    fn finds_pop_rdi_ret() {
        // 5f = pop rdi ; c3 = ret
        let image = img(vec![0x5f, 0xc3], 64);
        let g = find(&image, &Options::default());
        assert!(g.iter().any(|x| x.text == "pop rdi; ret"));
        // The gadget containing the pop starts at 0x1000.
        let gad = g.iter().find(|x| x.text == "pop rdi; ret").unwrap();
        assert_eq!(gad.addr, 0x1000);
    }

    #[test]
    fn bare_ret_is_a_gadget() {
        let image = img(vec![0xc3], 64);
        let g = find(&image, &Options::default());
        assert!(g.iter().any(|x| x.text == "ret"));
    }

    #[test]
    fn filter_narrows_results() {
        // 58 = pop rax ; 5f = pop rdi ; c3 = ret
        let image = img(vec![0x58, 0x5f, 0xc3], 64);
        let opts = Options {
            filter: Some("pop rax".into()),
            ..Default::default()
        };
        let g = find(&image, &opts);
        assert!(g.iter().all(|x| x.text.contains("pop rax")));
        assert!(!g.is_empty());
    }
}
