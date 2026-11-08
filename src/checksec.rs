//! Binary mitigation summary ("checksec") for ELF images.
//!
//! Before writing an exploit you need to know what you are up against: NX,
//! PIE/ASLR, RELRO, stack canaries, FORTIFY and any RWX segment. faultline reads
//! these straight from the ELF headers, dynamic section and symbol tables.

use anyhow::{bail, Result};
use goblin::elf::{Elf, ProgramHeader};
use serde::Serialize;

const PT_LOAD: u32 = 1;
const PT_INTERP: u32 = 3;
const PT_GNU_STACK: u32 = 0x6474_e551;
const PT_GNU_RELRO: u32 = 0x6474_e552;
const PF_X: u32 = 1;
const PF_W: u32 = 2;

const DT_BIND_NOW: u64 = 24;
const DT_FLAGS: u64 = 30;
const DT_FLAGS_1: u64 = 0x6fff_fffb;
const DF_BIND_NOW: u64 = 0x08;
const DF_1_NOW: u64 = 0x01;
const DF_1_PIE: u64 = 0x0800_0000;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Relro {
    None,
    Partial,
    Full,
}

#[derive(Debug, Clone, Serialize)]
pub struct Checksec {
    pub bits: u8,
    pub arch: String,
    pub pie: bool,
    pub nx: bool,
    pub relro: Relro,
    pub canary: bool,
    pub fortify: bool,
    pub rwx_segment: bool,
    pub stripped: bool,
}

/// Analyze ELF bytes. Returns an error for non-ELF input.
pub fn analyze(bytes: &[u8]) -> Result<Checksec> {
    let elf = match Elf::parse(bytes) {
        Ok(e) => e,
        Err(_) => bail!("not an ELF image (checksec currently supports ELF)"),
    };

    let bits = if elf.is_64 { 64 } else { 32 };
    let arch = arch_name(elf.header.e_machine);

    let has_interp = elf.program_headers.iter().any(|p| p.p_type == PT_INTERP);
    // PIE: ET_DYN that is an executable (has an interpreter) or is flagged PIE.
    let et_dyn = elf.header.e_type == goblin::elf::header::ET_DYN;
    let pie = et_dyn && (has_interp || has_flag(&elf, DT_FLAGS_1, DF_1_PIE));

    // NX: a GNU_STACK header that is not executable. Absence => executable stack.
    let nx = match elf
        .program_headers
        .iter()
        .find(|p| p.p_type == PT_GNU_STACK)
    {
        Some(p) => p.p_flags & PF_X == 0,
        None => false,
    };

    let relro = relro(&elf);
    let canary = has_symbol(&elf, |n| {
        n == "__stack_chk_fail" || n == "__stack_chk_guard"
    });
    let fortify = has_symbol(&elf, |n| n.ends_with("_chk") && n != "__stack_chk_fail");
    let rwx_segment = elf.program_headers.iter().any(|p: &ProgramHeader| {
        p.p_type == PT_LOAD && p.p_flags & PF_X != 0 && p.p_flags & PF_W != 0
    });
    let stripped = elf.syms.is_empty();

    Ok(Checksec {
        bits,
        arch,
        pie,
        nx,
        relro,
        canary,
        fortify,
        rwx_segment,
        stripped,
    })
}

fn relro(elf: &Elf) -> Relro {
    let has_relro = elf.program_headers.iter().any(|p| p.p_type == PT_GNU_RELRO);
    if !has_relro {
        return Relro::None;
    }
    let bind_now = elf
        .dynamic
        .as_ref()
        .map(|d| {
            d.dyns.iter().any(|dy| dy.d_tag == DT_BIND_NOW)
                || d.dyns
                    .iter()
                    .any(|dy| dy.d_tag == DT_FLAGS && dy.d_val & DF_BIND_NOW != 0)
                || d.dyns
                    .iter()
                    .any(|dy| dy.d_tag == DT_FLAGS_1 && dy.d_val & DF_1_NOW != 0)
        })
        .unwrap_or(false);
    if bind_now {
        Relro::Full
    } else {
        Relro::Partial
    }
}

fn has_flag(elf: &Elf, tag: u64, flag: u64) -> bool {
    elf.dynamic
        .as_ref()
        .map(|d| {
            d.dyns
                .iter()
                .any(|dy| dy.d_tag == tag && dy.d_val & flag != 0)
        })
        .unwrap_or(false)
}

fn has_symbol(elf: &Elf, pred: impl Fn(&str) -> bool) -> bool {
    let in_dyn = elf
        .dynsyms
        .iter()
        .filter_map(|s| elf.dynstrtab.get_at(s.st_name))
        .any(&pred);
    let in_sym = elf
        .syms
        .iter()
        .filter_map(|s| elf.strtab.get_at(s.st_name))
        .any(&pred);
    in_dyn || in_sym
}

fn arch_name(machine: u16) -> String {
    match machine {
        0x03 => "x86".into(),
        0x3e => "x86-64".into(),
        0x28 => "ARM".into(),
        0xb7 => "AArch64".into(),
        0xf3 => "RISC-V".into(),
        other => format!("machine 0x{other:x}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_non_elf() {
        assert!(analyze(b"MZ\x90\x00not elf").is_err());
    }

    #[test]
    fn reads_local_binary() {
        // /bin/ls exists on CI/Linux and is a normal PIE + NX binary.
        if let Ok(bytes) = std::fs::read("/bin/ls") {
            let cs = analyze(&bytes).unwrap();
            assert_eq!(cs.bits, 64);
            assert!(cs.nx, "/bin/ls should be NX");
        }
    }
}
