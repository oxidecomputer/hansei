// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use crate::Inputs;

use serde::Deserialize;

use std::path::{Path, PathBuf};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Matrix {
    pub primary: Primary,
    pub tokio: Axis,
    pub toolchain: Axis,
    pub cells: Cells,
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

impl Matrix {
    pub fn load() -> Self {
        Self::read(&PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../test-programs"))
    }

    pub fn read(dir: &Path) -> Self {
        let path = dir.join("matrix.toml");
        let text = std::fs::read_to_string(&path).expect("read fixture matrix");
        toml::from_str(&text).expect("parse fixture matrix")
    }

    pub fn primary_recipe(&self) -> Recipe {
        Recipe {
            toolchain: self.primary.toolchain.clone(),
            tokio: self.primary.tokio.clone(),
            unstable: true,
            ct_only: false,
            debug_info: true,
            dwp: false,
        }
    }

    /// The recipe every pair in `set` is captured with: the primary
    /// build, or the floor's lockfile for the version-endpoint set. The
    /// program is not a parameter — every program in a set shares its
    /// recipe.
    pub fn capture_recipe(&self, set: &str) -> Recipe {
        assert!(
            matches!(set, "illumos" | "linux" | "linux-floor"),
            "unknown capture set {set}"
        );
        let mut recipe = self.primary_recipe();
        if set.ends_with("-floor") {
            recipe.tokio = self.tokio.floor.clone();
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
    pub dwp: bool,
}

impl Recipe {
    pub fn text(&self) -> String {
        format!(
            "toolchain={}\ntokio={}\nunstable={}\nct_only={}\ndebug_info={}\ndwp={}\n",
            self.toolchain,
            self.tokio,
            u8::from(self.unstable),
            u8::from(self.ct_only),
            u8::from(self.debug_info),
            u8::from(self.dwp),
        )
    }

    pub fn target_recipe(&self) -> Self {
        Self {
            debug_info: false,
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

    /// The workspace's toolchain file names the matrix's primary, so
    /// hansei and the fixtures it is tested against build on one
    /// release.
    #[test]
    fn test_workspace_toolchain_is_the_matrix_primary() {
        #[derive(Deserialize)]
        struct ToolchainFile {
            toolchain: Channel,
        }
        #[derive(Deserialize)]
        struct Channel {
            channel: String,
        }

        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("..");
        let text = std::fs::read_to_string(root.join("rust-toolchain.toml"))
            .expect("read rust-toolchain.toml");
        let file: ToolchainFile = toml::from_str(&text).expect("parse rust-toolchain.toml");
        let matrix = Matrix::read(&root.join("test-programs"));
        assert_eq!(
            file.toolchain.channel, matrix.primary.toolchain,
            "rust-toolchain.toml and test-programs/matrix.toml name different \
             primary toolchains; advance both in one commit"
        );
    }

    #[test]
    fn test_target_recipe_drops_every_bundle_only_setting() {
        let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../test-programs");
        let mut recipe = Matrix::read(&dir).primary_recipe();
        recipe.debug_info = true;
        recipe.dwp = true;
        let target = recipe.target_recipe();
        assert!(!target.debug_info);
        assert!(!target.dwp);
        assert_eq!(target.toolchain, recipe.toolchain);
        assert_eq!(target.tokio, recipe.tokio);
        assert_eq!(target.unstable, recipe.unstable);
        assert_eq!(target.ct_only, recipe.ct_only);
    }

    /// A bundle-only flag is part of the recipe: flipping it changes the
    /// reuse digest and the capture record, while the target recipe,
    /// which never carries it, stays what it was.
    #[test]
    fn test_flag_only_change_invalidates_reuse_and_capture() {
        let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../test-programs");
        let matrix = Matrix::read(&dir);
        let mut recipe = matrix.primary_recipe();
        let before = recipe.inputs(&dir, &matrix, "simple-await");
        let capture = recipe.capture_record(&dir, &matrix, "linux", "simple-await");
        recipe.dwp = true;
        assert_ne!(before, recipe.inputs(&dir, &matrix, "simple-await"));
        assert_ne!(
            capture,
            recipe.capture_record(&dir, &matrix, "linux", "simple-await")
        );
        assert!(!recipe.target_recipe().dwp);

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
