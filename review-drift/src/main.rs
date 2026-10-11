// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! review-drift — hold a project to what hansei was reviewed against,
//! and to what its fixtures build.
//!
//! Given a project's `Cargo.lock` and toolchain file, it prints one
//! finding per line, or with `--json` one document. The kinds are
//! described in [`drift::Finding`]. It exits 0 with no findings, 1 with
//! some, and 2 when the check itself fails.
//! `.github/scripts/review-drift.sh` runs it weekly over omicron and
//! opens an issue for each finding.
//!
//! It is repository tooling, not part of hansei: it reads this
//! checkout's `test-programs`, so it means nothing outside one.

mod drift;

use anyhow::{Context as _, Result};
use clap::Parser;
use exegesis::detect::reviewed::project::{locked, toolchain_channel};
use exegesis::detect::reviewed::reviews;
use serde::Serialize;
use testrun::fixture::{Matrix, test_programs_dir};

use std::path::{Path, PathBuf};
use std::process::ExitCode;

/// Hold a project's dependencies and toolchain to hansei's reviews and
/// to what its fixtures build.
#[derive(Parser)]
struct Args {
    /// The project's `Cargo.lock`.
    #[arg(long, value_name = "PATH")]
    lockfile: PathBuf,
    /// The project's `rust-toolchain.toml` (or a bare `rust-toolchain`).
    #[arg(long, value_name = "PATH")]
    toolchain: PathBuf,
    /// Print one JSON document rather than a line per finding.
    #[arg(long)]
    json: bool,
}

/// What `--json` prints.
#[derive(Serialize)]
struct Document<'a> {
    command: &'static str,
    findings: &'a [drift::Finding],
}

fn main() -> ExitCode {
    let args = Args::parse();
    match run(&args) {
        Ok(0) => ExitCode::SUCCESS,
        Ok(_) => ExitCode::from(1),
        Err(e) => {
            eprintln!("review-drift: {e:?}");
            ExitCode::from(2)
        }
    }
}

/// Print the project's findings, and return how many there were.
fn run(args: &Args) -> Result<usize> {
    let read = |path: &Path| {
        std::fs::read_to_string(path).with_context(|| format!("failed to read {}", path.display()))
    };
    let parse = |path: &Path| {
        locked(&read(path)?).with_context(|| format!("failed to parse {}", path.display()))
    };
    let dir = test_programs_dir();
    let findings = drift::findings(&drift::Inputs {
        project: &parse(&args.lockfile)?,
        channel: &toolchain_channel(&read(&args.toolchain)?),
        fixtures: &parse(&dir.join("Cargo.lock"))?,
        matrix: &Matrix::read(&dir),
        reviews: &reviews(),
    });
    if args.json {
        let document = Document {
            command: "review-drift",
            findings: &findings,
        };
        println!("{}", serde_json::to_string_pretty(&document)?);
    } else {
        for finding in &findings {
            println!("{finding}");
        }
    }
    Ok(findings.len())
}
