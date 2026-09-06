// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use crate::Inputs;

use serde::Deserialize;

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Matrix {
    pub primary: Primary,
    pub tokio: Axis,
    pub toolchain: Axis,
    pub cells: Cells,
    #[serde(default)]
    pub provenance: Vec<Provenance>,
    #[serde(default)]
    pub capture: BTreeMap<String, Capture>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Primary {
    pub tokio: String,
    pub toolchain: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Axis {
    pub floor: String,
    pub versions: Vec<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Cells {
    pub no_unstable_tokio: Vec<String>,
    pub secondary_toolchain_tokio: Vec<String>,
    pub ct_only_tokio: Vec<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Provenance {
    pub toolchain: String,
    pub tokio: String,
    pub unstable: bool,
    pub dwarf_version: u8,
    pub programs: Vec<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Capture {
    pub dwarf_version: u8,
}

impl Matrix {
    pub fn load() -> Self {
        Self::read(&PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../test-programs"))
    }

    pub fn read(dir: &Path) -> Self {
        let path = dir.join("matrix.toml");
        let text = std::fs::read_to_string(&path).expect("read fixture matrix");
        let matrix: Self = toml::from_str(&text).expect("parse fixture matrix");
        for cell in &matrix.provenance {
            assert!(matches!(cell.dwarf_version, 4 | 5), "invalid DWARF version");
            assert!(matrix.toolchain.versions.contains(&cell.toolchain));
            assert!(matrix.tokio.versions.contains(&cell.tokio));
            assert!(!cell.programs.is_empty());
        }
        for recipe in matrix.capture.values() {
            assert!(
                matches!(recipe.dwarf_version, 4 | 5),
                "invalid DWARF version"
            );
        }
        matrix
    }

    pub fn primary_recipe(&self) -> Recipe {
        Recipe {
            toolchain: self.primary.toolchain.clone(),
            tokio: self.primary.tokio.clone(),
            unstable: true,
            ct_only: false,
            debug_info: true,
            dwarf_version: 4,
            dwp: false,
        }
    }

    pub fn capture_recipe(&self, set: &str, program: &str) -> Recipe {
        assert!(
            matches!(set, "illumos" | "linux" | "linux-floor"),
            "unknown capture set {set}"
        );
        let mut recipe = self.primary_recipe();
        if set.ends_with("-floor") {
            recipe.tokio = self.tokio.floor.clone();
        }
        if let Some(capture) = self.capture.get(program) {
            recipe.dwarf_version = capture.dwarf_version;
        }
        recipe
    }
}

pub fn floor() -> String {
    Matrix::load().tokio.floor
}

/// The effective settings recorded by regen.sh, independent of output paths.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Recipe {
    pub toolchain: String,
    pub tokio: String,
    pub unstable: bool,
    pub ct_only: bool,
    pub debug_info: bool,
    pub dwarf_version: u8,
    pub dwp: bool,
}

impl Recipe {
    pub fn source_checksums(&self) -> &'static str {
        if self.debug_info && self.dwarf_version == 5 && !self.dwp {
            "compiler-assembly-v1"
        } else {
            "none"
        }
    }

    pub fn text(&self) -> String {
        format!(
            "toolchain={}\ntokio={}\nunstable={}\nct_only={}\ndebug_info={}\ndwarf_version={}\ndwp={}\nsource_checksums={}\n",
            self.toolchain,
            self.tokio,
            u8::from(self.unstable),
            u8::from(self.ct_only),
            u8::from(self.debug_info),
            self.dwarf_version,
            u8::from(self.dwp),
            self.source_checksums()
        )
    }

    pub fn cell_name(&self) -> String {
        let cfg = if self.ct_only {
            "ctonly"
        } else if self.unstable {
            "unstable"
        } else {
            "stable"
        };
        let suffix = if self.dwarf_version == 4 {
            String::new()
        } else {
            format!("-dw{}", self.dwarf_version)
        };
        format!("rust-{}-tokio-{}-{cfg}{suffix}", self.toolchain, self.tokio)
    }

    pub fn target_recipe(&self) -> Self {
        Self {
            debug_info: false,
            dwarf_version: 4,
            dwp: false,
            ..self.clone()
        }
    }

    pub fn lockfile(&self, matrix: &Matrix) -> String {
        if self.tokio == matrix.primary.tokio {
            "Cargo.lock".to_owned()
        } else {
            format!("locks/tokio-{}.lock", self.tokio)
        }
    }

    pub fn inputs(&self, dir: &Path, matrix: &Matrix, program: &str) -> String {
        let mut inputs = Inputs::new();
        inputs.text(program).text(&self.text());
        for path in [
            "Cargo.toml",
            "matrix.toml",
            "regen.sh",
            "capture-snapshots.sh",
            "src/lib.rs",
        ] {
            inputs.file(&dir.join(path));
        }
        inputs
            .file(&dir.join(self.lockfile(matrix)))
            .file(&dir.join("src/bin").join(format!("{program}.rs")));
        if self.source_checksums() != "none" {
            for path in [
                "../testrun/src/bin/checksum-linker.rs",
                "../testrun/Cargo.toml",
                "../Cargo.toml",
                "../Cargo.lock",
            ] {
                inputs.file(&dir.join(path));
            }
        }
        inputs.finish()
    }

    pub fn capture_record(&self, dir: &Path, matrix: &Matrix, set: &str, program: &str) -> String {
        let target = self.target_recipe();
        format!(
            "set={set}\nprogram={program}\n[target]\n{}inputs={}\n[bundle]\n{}inputs={}\n",
            target.text(),
            target.inputs(dir, matrix, program),
            self.text(),
            self.inputs(dir, matrix, program)
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_target_recipe_drops_every_bundle_only_setting() {
        let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../test-programs");
        let mut recipe = Matrix::read(&dir).primary_recipe();
        recipe.debug_info = true;
        recipe.dwarf_version = 5;
        recipe.dwp = true;
        let target = recipe.target_recipe();
        assert!(!target.debug_info);
        assert_eq!(target.dwarf_version, 4);
        assert!(!target.dwp);
        assert_eq!(target.toolchain, recipe.toolchain);
        assert_eq!(target.tokio, recipe.tokio);
        assert_eq!(target.unstable, recipe.unstable);
        assert_eq!(target.ct_only, recipe.ct_only);
    }

    #[test]
    fn test_dwarf_only_change_invalidates_reuse_and_capture() {
        let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../test-programs");
        let matrix = Matrix::read(&dir);
        let mut recipe = matrix.primary_recipe();
        let before = recipe.inputs(&dir, &matrix, "simple-await");
        let capture = recipe.capture_record(&dir, &matrix, "linux", "simple-await");
        let name = recipe.cell_name();
        recipe.dwarf_version = 5;
        assert_ne!(before, recipe.inputs(&dir, &matrix, "simple-await"));
        assert_ne!(
            capture,
            recipe.capture_record(&dir, &matrix, "linux", "simple-await")
        );
        assert_ne!(name, recipe.cell_name());
        assert_eq!(recipe.target_recipe().dwarf_version, 4);

        let temporary = tempfile::tempdir().unwrap();
        let stamp = temporary.path().join("build");
        let builds = std::cell::Cell::new(0);
        let build = || builds.set(builds.get() + 1);
        crate::once_stamped(&stamp, Some(before.clone()), build);
        crate::once_stamped(&stamp, Some(before), build);
        assert_eq!(builds.get(), 1);
        crate::once_stamped(
            &stamp,
            Some(recipe.inputs(&dir, &matrix, "simple-await")),
            build,
        );
        assert_eq!(builds.get(), 2);
    }
}
