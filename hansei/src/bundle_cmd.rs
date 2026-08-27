//! `hansei bundle …` — the producing side.
//!
//! A session reads a bundle; these verbs make one, and say what is in
//! it. They are thin wrappers over `exegesis`'s public library calls,
//! and this is the one place in hansei that reaches for the DWARF
//! stack: nothing a session, the runtime, or the renderer does may
//! import exegesis.

use anyhow::{Context as _, Result};
use clap::Subcommand;
use exegesis::extract::{ExtractOptions, RUSTC_FLOOR, extract_file};

use std::path::{Path, PathBuf};

#[derive(Subcommand)]
pub enum BundleCmd {
    /// Extract an async debug bundle from a debug binary's DWARF.
    Extract {
        /// Debug binary (or any DWARF-bearing object).
        binary: PathBuf,
        /// Output bundle path.
        #[arg(short, long)]
        output: PathBuf,
        /// Print extraction statistics.
        #[arg(long)]
        stats: bool,
        /// Extra root types to include, by fully-qualified name.
        #[arg(long = "include-type")]
        include_types: Vec<String>,
        /// Extract even when tokio infrastructure types or statics are
        /// missing (placeholders are emitted instead).
        #[arg(long)]
        allow_missing_infra: bool,
        /// Report why a formatter did or did not attach, for every emitted
        /// type whose fully-qualified name contains this substring.
        #[arg(long, value_name = "FQN")]
        explain_format: Option<String>,
        /// Report how the walk binder resolved each contract role whose
        /// name contains this substring (e.g. "Sleep.deadline").
        #[arg(long, value_name = "ROLE")]
        explain_walk: Option<String>,
    },
}

pub fn exec(cmd: BundleCmd) -> Result<()> {
    match cmd {
        BundleCmd::Extract {
            binary,
            output,
            stats,
            include_types,
            allow_missing_infra,
            explain_format,
            explain_walk,
        } => extract(
            &binary,
            &output,
            stats,
            include_types,
            allow_missing_infra,
            explain_format,
            explain_walk,
        ),
    }
}

fn extract(
    binary: &Path,
    output: &Path,
    print_stats: bool,
    include_types: Vec<String>,
    allow_missing_infra: bool,
    explain_format: Option<String>,
    explain_walk: Option<String>,
) -> Result<()> {
    let explaining = explain_format.clone();
    let explaining_walk = explain_walk.clone();
    let opts = ExtractOptions {
        include_types,
        allow_missing_infra,
        extract_args: std::env::args().skip(1).collect::<Vec<_>>().join(" "),
        explain_format,
        explain_walk,
    };
    let (bundle, stats) = extract_file(binary, &opts)
        .with_context(|| format!("failed to extract from {}", binary.display()))?;
    if let Some(v) = &stats.rustc_below_floor {
        eprintln!(
            "warning: this binary was produced by rustc {v}, older than the \
             supported floor {RUSTC_FLOOR}; extraction proceeds but is \
             untested against older toolchains"
        );
    }
    if let Some(family) = &stats.tokio_family_guessed {
        eprintln!(
            "warning: no tokio version could be recovered from this binary \
             (vendored or forked tokio?); version-dependent formatters \
             assumed the newest supported family ({family})"
        );
    }
    bundle
        .save(output)
        .with_context(|| format!("failed to write {}", output.display()))?;
    println!(
        "wrote {} ({} types, {} task entries, {} dyn futures)",
        output.display(),
        bundle.types.types.len(),
        bundle.tasks.entries.len(),
        bundle.dyn_futures.by_symbol.len(),
    );
    if let Some(wanted) = explaining {
        if stats.format_explanations.is_empty() {
            println!(
                "no emitted type's name contains {wanted:?}; \
                 --include-type pulls in one nothing else reaches"
            );
        }
        for explanation in &stats.format_explanations {
            print!("{}", explanation.render(&bundle));
        }
    }
    if let Some(wanted) = explaining_walk {
        if stats.walk_explanations.is_empty() {
            println!("no walk role's name contains {wanted:?}");
        }
        for explanation in &stats.walk_explanations {
            println!("{}", explanation.role.name());
            for line in &explanation.trace {
                println!("  {line}");
            }
            match bundle.walks.entries.get(&explanation.role) {
                Some(binding) => {
                    println!(
                        "  => {}",
                        exegesis::summary::walk_entry_line(explanation.role, binding)
                    );
                }
                None => println!("  => no binding recorded"),
            }
        }
    }
    if print_stats {
        print!("{stats}");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{BundleCmd, exec};

    use hansei_bundle::Bundle;

    fn extract_cmd(binary: std::path::PathBuf, output: std::path::PathBuf) -> BundleCmd {
        BundleCmd::Extract {
            binary,
            output,
            stats: false,
            include_types: Vec::new(),
            allow_missing_infra: true,
            explain_format: None,
            explain_walk: None,
        }
    }

    /// The verb runs a real extraction and leaves behind a bundle that
    /// loads. Its subject is this test binary, a Rust program with no
    /// tokio in it — which is what `--allow-missing-infra` is for — so
    /// the case needs neither a fixture nor a target, and what the
    /// bundle *says* is exegesis's own suites' business.
    #[test]
    fn test_extract_writes_a_loadable_bundle() {
        let dir = tempfile::tempdir().expect("tempdir");
        let output = dir.path().join("self.bundle");
        let binary = std::env::current_exe().expect("this test binary's path");
        exec(extract_cmd(binary, output.clone())).expect("extraction should succeed");
        Bundle::load(&output).expect("the bundle it wrote should load");
    }

    /// A subject nothing can be read out of fails, naming the file,
    /// rather than reporting a bundle it never wrote.
    #[test]
    fn test_extract_reports_what_it_could_not_read() {
        let dir = tempfile::tempdir().expect("tempdir");
        let binary = dir.path().join("not-an-object");
        std::fs::write(&binary, b"neither an ELF nor a Mach-O").expect("write");
        let output = dir.path().join("out.bundle");
        let err = exec(extract_cmd(binary.clone(), output.clone()))
            .expect_err("a file with no object format in it cannot be extracted from");
        let msg = format!("{err:?}");
        assert!(msg.contains(&binary.display().to_string()), "{msg}");
        assert!(!output.exists(), "nothing should have been written");
    }
}
