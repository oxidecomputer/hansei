// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use gimli::Reader;
use object::{Object, ObjectSection};

use std::borrow::Cow;
use std::collections::BTreeMap;
use std::ffi::OsString;
use std::path::Path;
use std::process::Command;
use std::rc::Rc;

#[derive(Clone, Debug)]
struct Relocations(Rc<object::RelocationMap>);

impl gimli::Relocate for Relocations {
    fn relocate_address(&self, offset: usize, value: u64) -> gimli::Result<u64> {
        Ok(self.0.relocate(offset as u64, value))
    }

    fn relocate_offset(&self, offset: usize, value: usize) -> gimli::Result<usize> {
        usize::try_from(self.0.relocate(offset as u64, value as u64))
            .map_err(|_| gimli::Error::UnsupportedOffsetSize(8))
    }
}

struct Normalized {
    assembly: String,
    checksums: BTreeMap<u64, [u8; 16]>,
}

// Rust supplies MD5 for real source files but not its synthetic CU root.
// LLVM suppresses the entire line-header MD5 column in that situation.
// Removing an unused root directive lets the assembler use file 1 as
// its default root, preserving every original real file's index/hash.
fn without_synthetic_root(assembly: &str) -> Result<Normalized, String> {
    let mut result = String::new();
    let mut roots = 0;
    let mut checksums = BTreeMap::new();
    for line in assembly.lines() {
        let mut words = line.split_whitespace();
        match (words.next(), words.next()) {
            (Some(".file"), Some("0")) => {
                if !line.contains("/@/") || !line.contains("-cgu.") || line.contains(" md5 ") {
                    return Err("root is not a checksum-less synthetic Rust CU".into());
                }
                roots += 1;
                continue;
            }
            (Some(".file"), Some(index)) if index.parse::<u64>().is_ok() => {
                let hash = line
                    .split(" md5 0x")
                    .nth(1)
                    .and_then(|suffix| suffix.split_whitespace().next())
                    .and_then(|hex| u128::from_str_radix(hex, 16).ok())
                    .ok_or("real source file has no compiler MD5 checksum")?;
                if checksums
                    .insert(index.parse().unwrap(), hash.to_be_bytes())
                    .is_some()
                {
                    return Err("duplicate source file index".into());
                }
            }
            (Some(".loc"), Some("0")) => return Err("line row uses synthetic file zero".into()),
            _ => {}
        }
        result.push_str(line);
        result.push('\n');
    }
    if roots != 1 || checksums.is_empty() {
        return Err("expected one synthetic root and real checksummed files".into());
    }
    Ok(Normalized {
        assembly: result,
        checksums,
    })
}

fn check_object(
    path: &Path,
    checksums: Option<&BTreeMap<u64, [u8; 16]>>,
) -> Vec<(u64, String, String)> {
    let bytes = std::fs::read(path).unwrap();
    let object = object::File::parse(&bytes[..]).unwrap();
    let endian = if object.is_little_endian() {
        gimli::RunTimeEndian::Little
    } else {
        gimli::RunTimeEndian::Big
    };
    let sections = gimli::DwarfSections::load(|id: gimli::SectionId| -> Result<_, object::Error> {
        match object.section_by_name(id.name()) {
            Some(section) => Ok((
                section.uncompressed_data()?,
                Relocations(Rc::new(section.relocation_map()?)),
            )),
            None => Ok((
                Cow::Borrowed(&[]),
                Relocations(Rc::new(object::RelocationMap::default())),
            )),
        }
    })
    .unwrap();
    let dwarf = sections.borrow(|(bytes, relocations)| {
        gimli::RelocateReader::new(gimli::EndianSlice::new(bytes, endian), relocations.clone())
    });
    let mut units = dwarf.units();
    let mut files = Vec::new();
    while let Some(header) = units.next().unwrap() {
        let unit = dwarf.unit(header).unwrap();
        assert_eq!(unit.header.version(), 5, "expected DWARF 5");
        let mut entries = unit.entries();
        while let Some(die) = entries.next_dfs().unwrap() {
            for attr in die.attrs() {
                assert!(
                    !matches!(attr.value(), gimli::AttributeValue::FileIndex(0)),
                    "DIE uses synthetic file zero in {}",
                    path.display()
                );
            }
        }
        if let Some(lines) = &unit.line_program {
            let header = lines.header();
            assert_eq!(header.version(), 5);
            assert_eq!(header.file_has_md5(), checksums.is_some());
            for (index, file) in header.file_names().iter().enumerate().skip(1) {
                let name = dwarf.attr_string(&unit, file.path_name()).unwrap();
                let directory = dwarf
                    .attr_string(&unit, file.directory(header).unwrap())
                    .unwrap();
                if let Some(checksums) = checksums {
                    assert_eq!(
                        file.md5(),
                        &checksums[&(index as u64)],
                        "compiler MD5 changed"
                    );
                }
                files.push((
                    index as u64,
                    name.to_string_lossy().unwrap().into_owned(),
                    directory.to_string_lossy().unwrap().into_owned(),
                ));
            }
        }
    }
    assert!(!files.is_empty(), "object has no real source files");
    files
}

fn main() {
    let mut args: Vec<OsString> = std::env::args_os().skip(1).collect();
    if args == ["--recipe-id"] {
        let mut hash = blake3::Hasher::new();
        for input in [
            include_bytes!("checksum-linker.rs").as_slice(),
            include_bytes!("../../Cargo.toml").as_slice(),
            include_bytes!("../../../Cargo.toml").as_slice(),
            include_bytes!("../../../Cargo.lock").as_slice(),
        ] {
            hash.update(input);
        }
        println!("{}", hash.finalize().to_hex());
        return;
    }
    let mut replaced = 0;
    for arg in &mut args {
        let object = Path::new(arg);
        if object.extension().is_none_or(|extension| extension != "o") {
            continue;
        }
        let assembly = object.with_extension("s");
        if !assembly.exists() {
            continue;
        }
        let source = std::fs::read_to_string(&assembly).unwrap();
        let source = without_synthetic_root(&source).unwrap_or_else(|error| {
            panic!("{}: {error}", assembly.display());
        });
        let before = check_object(object, None);
        let revised_assembly = object.with_extension("md5.s");
        let revised_object = object.with_extension("md5.o");
        std::fs::write(&revised_assembly, source.assembly).unwrap();
        let status = Command::new("clang")
            .arg("-gdwarf-5")
            .arg("-c")
            .arg(&revised_assembly)
            .arg("-o")
            .arg(&revised_object)
            .status()
            .expect("run clang assembler");
        assert!(status.success(), "assemble compiler source checksums");
        assert_eq!(
            before,
            check_object(&revised_object, Some(&source.checksums)),
            "source file indices changed"
        );
        *arg = revised_object.into_os_string();
        replaced += 1;
    }
    assert!(replaced > 0, "link has no saved compiler assembly");
    let linker = if cfg!(target_os = "illumos") {
        "gcc"
    } else {
        "cc"
    };
    let status = Command::new(linker)
        .args(args)
        .status()
        .expect("run linker");
    std::process::exit(status.code().unwrap_or(1));
}

#[cfg(test)]
mod tests {
    use super::*;

    const INPUT: &str = ".file 0 \"/build\" \"src/main.rs/@/fixture-cgu.0\"\n.file 1 \"/source\" \"adapter.rs\" md5 0x0123456789abcdef0123456789abcdef\n.loc 1 7 0\n";

    #[test]
    fn test_only_unused_synthetic_root_is_removed() {
        let normalized = without_synthetic_root(INPUT).unwrap();
        assert_eq!(
            normalized.assembly,
            INPUT
                .lines()
                .skip(1)
                .map(|line| format!("{line}\n"))
                .collect::<String>()
        );
        assert_eq!(
            normalized.checksums[&1],
            0x0123456789abcdef0123456789abcdefu128.to_be_bytes()
        );
        for source in [
            INPUT.replace(".loc 1", ".loc 0"),
            INPUT.replace("src/main.rs/@/fixture-cgu.0", "src/main.rs"),
            INPUT.replace(" md5 0x0123456789abcdef0123456789abcdef", ""),
            format!("{INPUT}.file 0 \"/build\" \"src/main.rs/@/fixture-cgu.0\"\n"),
        ] {
            assert!(without_synthetic_root(&source).is_err());
        }
    }

    #[test]
    fn test_real_object_preserves_compiler_file_indices_and_hashes() {
        let temporary = tempfile::tempdir().unwrap();
        let dir = temporary.path();
        std::fs::write(
            dir.join("probe.rs"),
            "pub fn probe(x: u64) -> u64 { x + 1 }\n",
        )
        .unwrap();
        let status = Command::new("rustc")
            .current_dir(dir)
            .args([
                "--crate-type=lib",
                "--emit=asm,obj",
                "-C",
                "debuginfo=2",
                "-C",
                "dwarf-version=5",
                "probe.rs",
            ])
            .status()
            .unwrap();
        assert!(status.success());
        let before = check_object(&dir.join("probe.o"), None);
        let assembly = std::fs::read_to_string(dir.join("probe.s")).unwrap();
        let normalized = without_synthetic_root(&assembly).unwrap();
        std::fs::write(dir.join("checked.s"), normalized.assembly).unwrap();
        let status = Command::new("clang")
            .current_dir(dir)
            .args(["-gdwarf-5", "-c", "checked.s", "-o", "checked.o"])
            .status()
            .unwrap();
        assert!(status.success());
        assert_eq!(
            before,
            check_object(&dir.join("checked.o"), Some(&normalized.checksums))
        );
    }
}
