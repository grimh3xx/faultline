//! Executable-section extraction for ELF and PE, shared by the gadget finder.

use anyhow::{bail, Result};
use goblin::Object;

/// One executable region mapped into memory.
pub struct ExecSection {
    /// Section name (kept for display / future per-section reporting).
    #[allow(dead_code)]
    pub name: String,
    /// Virtual address the bytes are loaded at.
    pub va: u64,
    pub bytes: Vec<u8>,
}

pub struct ExecImage {
    /// 32 or 64.
    pub bits: u32,
    pub sections: Vec<ExecSection>,
}

/// Pull the executable sections out of an ELF or PE image.
pub fn exec_image(bytes: &[u8]) -> Result<ExecImage> {
    match Object::parse(bytes)? {
        Object::Elf(elf) => {
            let bits = if elf.is_64 { 64 } else { 32 };
            let mut sections = Vec::new();
            for sh in &elf.section_headers {
                // SHF_EXECINSTR = 0x4, SHT_NOBITS = 8 (no file bytes).
                if sh.sh_flags & 0x4 != 0 && sh.sh_type != 8 {
                    let start = sh.sh_offset as usize;
                    let end = start.saturating_add(sh.sh_size as usize);
                    if let Some(slice) = bytes.get(start..end) {
                        sections.push(ExecSection {
                            name: elf
                                .shdr_strtab
                                .get_at(sh.sh_name)
                                .unwrap_or("?")
                                .to_string(),
                            va: sh.sh_addr,
                            bytes: slice.to_vec(),
                        });
                    }
                }
            }
            if sections.is_empty() {
                bail!("no executable sections found");
            }
            Ok(ExecImage { bits, sections })
        }
        Object::PE(pe) => {
            let bits = if pe.is_64 { 64 } else { 32 };
            let image_base = pe.image_base as u64;
            let mut sections = Vec::new();
            for sec in &pe.sections {
                // IMAGE_SCN_MEM_EXECUTE = 0x2000_0000.
                if sec.characteristics & 0x2000_0000 != 0 {
                    let start = sec.pointer_to_raw_data as usize;
                    let end = start.saturating_add(sec.size_of_raw_data as usize);
                    if let Some(slice) = bytes.get(start..end) {
                        sections.push(ExecSection {
                            name: sec.name().unwrap_or("?").to_string(),
                            va: image_base + sec.virtual_address as u64,
                            bytes: slice.to_vec(),
                        });
                    }
                }
            }
            if sections.is_empty() {
                bail!("no executable sections found");
            }
            Ok(ExecImage { bits, sections })
        }
        _ => bail!("unsupported object (need ELF or PE)"),
    }
}
