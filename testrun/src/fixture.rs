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
        for path in ["Cargo.toml", "matrix.toml", "regen.sh", "src/lib.rs"] {
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

    /// The cell `regen.sh` names this recipe's build after,
    /// `rust-<toolchain>-tokio-<version>-{unstable,stable,ctonly}`.
    pub fn cell(&self) -> String {
        format!(
            "rust-{}-tokio-{}-{}",
            self.toolchain,
            self.tokio,
            self.cfg()
        )
    }

    /// Whether `regen.sh` builds this recipe in its everyday dirs, in
    /// place, rather than as a matrix cell from a scratch copy.
    pub fn is_primary(&self, matrix: &Matrix) -> bool {
        self.toolchain == matrix.primary.toolchain
            && self.tokio == matrix.primary.tokio
            && self.unstable
            && !self.ct_only
    }

    fn cfg(&self) -> &'static str {
        if self.ct_only {
            "ctonly"
        } else if self.unstable {
            "unstable"
        } else {
            "stable"
        }
    }

    /// The `regen.sh` flags that build exactly this recipe.
    fn regen_args(&self) -> Vec<String> {
        assert!(!self.dwp, "the two-binary builds never split their DWARF");
        let mut args = vec![
            "--tokio".to_owned(),
            self.tokio.clone(),
            "--toolchain".to_owned(),
            self.toolchain.clone(),
        ];
        if self.ct_only {
            args.push("--ct-only".to_owned());
        } else if !self.unstable {
            args.push("--no-unstable".to_owned());
        }
        if !self.debug_info {
            args.push("--no-debug-info".to_owned());
        }
        args
    }
}

/// `test-programs`: the fixture sources, `regen.sh`, and under
/// `fixtures/` (gitignored) everything built from them.
pub fn test_programs_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../test-programs")
}

/// Build B of `programs` under `recipe`, once per run, and return the
/// directory holding them: the compilation carrying DWARF, which
/// bundles are extracted from and which nothing runs. It is the
/// standard fixture build, in `regen.sh`'s own dirs, so the extraction
/// goldens, the matrix and everything here share one.
///
/// Each program is stamped on its own, so a caller asking for one
/// builds one, and a caller asking for every program builds whichever
/// of them no one has built this run, in one compilation.
pub fn build_b(recipe: &Recipe, programs: &[&str]) -> PathBuf {
    assert!(recipe.debug_info, "build B carries debug info");
    build(recipe, programs)
}

/// Build A of `programs` under `recipe` (the bundle's recipe; A's own
/// drops its debug info), once per run, and return the directory
/// holding them: the compilation that runs and is cored.
///
/// It carries no debug info, the shape of a production binary a core
/// comes from, and is a compilation of its own rather than a stripped
/// copy of B. That is the two-binary constraint: a bundle from B joined
/// against memory from A proves the join holds across separate
/// compilations, which one build serving both would not.
pub fn build_a(recipe: &Recipe, programs: &[&str]) -> PathBuf {
    build(&recipe.target_recipe(), programs)
}

/// The packed-split build of `program` in the primary cell (`regen.sh
/// --dwp`), once per run, and the directory holding it: the
/// skeleton-DWARF binary, with its `.dwp` beside it. It is stamped and
/// digested apart from the unsplit build of the same sources. Linux
/// only, where rustc packs a dwp.
pub fn build_dwp(program: &str) -> PathBuf {
    let dir = test_programs_dir();
    let matrix = Matrix::read(&dir);
    let mut recipe = matrix.primary_recipe();
    recipe.dwp = true;
    crate::once_per_run_each(
        &dir.join("fixtures/.built/dwp"),
        &[program],
        |program| recipe.inputs(&dir, &matrix, program),
        |stale| {
            // Through bash: a copied tree need not keep the mode bit.
            let status = std::process::Command::new("bash")
                .arg(dir.join("regen.sh"))
                .arg("--dwp")
                .args(stale)
                .status()
                .expect("failed to run regen.sh");
            assert!(status.success(), "regen.sh --dwp failed for {stale:?}");
        },
    );
    let bin = dir.join("fixtures/bin/dwp");
    assert!(
        bin.join(program).exists(),
        "regen.sh --dwp succeeded but the {program} binary is still missing"
    );
    bin
}

/// Build `programs` exactly as `recipe` says, once per run each, and
/// hold every one of them to it: `regen.sh` records the settings it
/// actually built with beside each binary, and a binary whose record
/// differs from `recipe` panics here, whoever built it.
fn build(recipe: &Recipe, programs: &[&str]) -> PathBuf {
    let dir = test_programs_dir();
    let fixtures = dir.join("fixtures");
    let matrix = Matrix::read(&dir);
    let cell = recipe.cell();
    let primary = recipe.is_primary(&matrix);
    let a = !recipe.debug_info;
    // B lands where `regen.sh` puts it unasked. A gets dirs of its own
    // beside B's: the everyday ones for the primary cell, and for every
    // other, a bin dir under the primary's and a target dir beside the
    // cell's (toolchain, cfg) pair's.
    let (bin, target) = match (a, primary) {
        (false, true) => (fixtures.join("bin"), None),
        (false, false) => (fixtures.join("bin").join(&cell), None),
        (true, true) => (fixtures.join("bin-a"), Some(fixtures.join("target-a"))),
        (true, false) => (
            fixtures.join("bin-a").join(&cell),
            Some(
                fixtures
                    .join("cells")
                    .join(format!("rust-{}-{}", recipe.toolchain, recipe.cfg()))
                    .join("target-a"),
            ),
        ),
    };
    let stamps = fixtures
        .join(".built")
        .join(format!("{cell}-{}", if a { "a" } else { "b" }));
    crate::once_per_run_each(
        &stamps,
        programs,
        |program| recipe.inputs(&dir, &matrix, program),
        |stale| {
            // Every cell of one (toolchain, cfg) pair compiles from the
            // same scratch copy of the crate, which `regen.sh` rewrites
            // with that cell's lockfile; two cells building at once
            // would each compile the other's.
            let _pair = (!primary).then(|| {
                let lock = fixtures.join(".built").join(format!(
                    "rust-{}-{}.lock",
                    recipe.toolchain,
                    recipe.cfg()
                ));
                let lock = std::fs::File::create(lock).expect("failed to open the cell lock");
                lock.lock().expect("failed to take the cell lock");
                lock
            });
            // Through bash rather than by its mode bit, which a copy of
            // the tree need not keep: cargo-mutants' reflink copies drop it.
            let mut command = std::process::Command::new("bash");
            command.arg(dir.join("regen.sh"));
            command.args(recipe.regen_args()).args(stale);
            command.env("REGEN_BIN_DIR", &bin);
            if let Some(target) = &target {
                command.env("REGEN_TARGET_DIR", target);
            }
            let status = command.status().expect("failed to run regen.sh");
            assert!(
                status.success(),
                "regen.sh failed building {cell}: {stale:?}"
            );
        },
    );
    let expected = recipe.text();
    for program in programs {
        let record = bin.join(format!("{program}.recipe"));
        let actual = std::fs::read_to_string(&record)
            .unwrap_or_else(|e| panic!("{} was not written: {e}", record.display()));
        assert_eq!(
            actual,
            expected,
            "{} was built with other settings than its recipe",
            bin.join(program).display()
        );
    }
    bin
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

    /// A recipe names the cell `regen.sh` builds it as and passes the
    /// flags that build exactly it, and only the primary recipe is the
    /// one `regen.sh` builds in place.
    #[test]
    fn test_a_recipe_names_its_cell_and_flags() {
        let matrix = Matrix::read(&test_programs_dir());
        let primary = matrix.primary_recipe();
        let (toolchain, tokio) = (&matrix.primary.toolchain, &matrix.primary.tokio);
        assert!(primary.is_primary(&matrix));
        assert_eq!(
            primary.cell(),
            format!("rust-{toolchain}-tokio-{tokio}-unstable")
        );
        assert_eq!(
            primary.regen_args(),
            ["--tokio", tokio, "--toolchain", toolchain]
        );
        assert_eq!(
            primary.target_recipe().regen_args(),
            [
                "--tokio",
                tokio,
                "--toolchain",
                toolchain,
                "--no-debug-info"
            ]
        );
        assert!(primary.target_recipe().is_primary(&matrix));

        let floor = Recipe {
            tokio: matrix.tokio.floor.clone(),
            ..primary.clone()
        };
        assert!(!floor.is_primary(&matrix));
        let stable = Recipe {
            unstable: false,
            ..primary.clone()
        };
        assert!(!stable.is_primary(&matrix));
        assert_eq!(
            stable.cell(),
            format!("rust-{toolchain}-tokio-{tokio}-stable")
        );
        assert_eq!(stable.regen_args().last().unwrap(), "--no-unstable");
        let ct = Recipe {
            unstable: false,
            ct_only: true,
            ..primary
        };
        assert!(!ct.is_primary(&matrix));
        assert_eq!(ct.cell(), format!("rust-{toolchain}-tokio-{tokio}-ctonly"));
        assert_eq!(ct.regen_args().last().unwrap(), "--ct-only");
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
