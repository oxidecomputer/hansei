// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Debugger related functionality for loading elf binary and core files and
//! providing access to DWARF and elf segments.

use anyhow::{Context, Result, bail};
use camino::Utf8PathBuf;
use debugdb::{DebugDb, ElfSegments};

use memmap2::Mmap;
use proc::Proc;
use rangemap::RangeInclusiveMap;

pub struct Dbg {
    pub core_path: Utf8PathBuf,
    pub elf_path: Utf8PathBuf,
    pub elf_mmap: Mmap,
    pub db: DebugDb,
    pub core: Proc,
    pub segments: ElfSegments,
}

impl Dbg {
    pub fn new(core_path: Utf8PathBuf, elf_path: Utf8PathBuf) -> Result<Self> {
        if !core_path.exists() {
            bail!("core file not found: {core_path}");
        }
        if !elf_path.exists() {
            bail!("ELF binary not found: {elf_path}");
        }
        let elf_file = std::fs::File::open(&elf_path)?;
        // SAFETY: We assume the file is not modified while mapped.
        let elf_mmap = unsafe { Mmap::map(&elf_file)? };
        let object = object::File::parse(&*elf_mmap)?;
        let db = debugdb::parse_file(&object)?;
        let core = Proc::open_core(core_path.as_std_path())
            .with_context(|| format!("failed to open core file: {core_path}"))?;

        // Load segments from the executable and core file
        // Note that the core file must come second, or the segments will be
        // incorrectly overwritten.
        let mut segments = ElfSegments::new();
        segments.extend_from_object(&object)?;
        segments.extend_from_elf(core_path.as_std_path())?;

        Ok(Self {
            core_path,
            elf_path,
            elf_mmap,
            db,
            core,
            segments,
        })
    }

    pub fn segments(&self) -> &RangeInclusiveMap<u64, Vec<u8>> {
        &self.segments.segments
    }
}
