// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! `hansei tokio-info …` — the producing side.
//!
//! A session reads a tokio-info file; these verbs make one, and say
//! what is in it. They are thin wrappers over `exegesis`'s public
//! library calls, and this is the one place in hansei that reaches for
//! the DWARF stack: nothing a session, the runtime, or the renderer
//! does may import exegesis.

use anyhow::{Context as _, Result};
use clap::Subcommand;
use exegesis::extract::{
    DebugSources, ExtractOptions, ExtractStats, ParsedDwarf, RUSTC_FLOOR, classify_file,
    dwarf_summary, extract_sources_with,
};
use hansei_bundle::{Bundle, BundleTypeId, MemberRef, StaticRole, Step, TypeDef, VtableDataSource};

use std::path::{Path, PathBuf};

#[derive(Subcommand)]
pub enum BundleCmd {
    /// Extract tokio runtime debug info from a debug binary's DWARF.
    Extract {
        /// The binary — with its DWARF embedded, or the sibling the
        /// split debug info named by --debug-info was split from.
        binary: PathBuf,
        /// Split debug info for the binary (a companion file, a dSYM,
        /// a dwp): the DWARF is read from here, the program contents
        /// and identity from the binary.
        #[arg(short, long, value_name = "PATH")]
        debug_info: Option<PathBuf>,
        /// Output path (`.tinfo` by convention).
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
    /// Print summary statistics for a tokio-info file.
    Stats {
        /// Tokio-info file produced by `hansei tokio-info extract`.
        tokio_info: PathBuf,
    },
    /// Dump a tokio-info file's tables as text.
    Dump {
        /// Tokio-info file produced by `hansei tokio-info extract`.
        tokio_info: PathBuf,
    },
    /// Parse a binary's DWARF and summarize its types and statics.
    #[command(hide = true)]
    DumpDwarf {
        /// Debug binary (or any DWARF-bearing object).
        binary: PathBuf,
    },
}

pub fn exec(cmd: BundleCmd) -> Result<()> {
    match cmd {
        BundleCmd::Extract {
            binary,
            debug_info,
            output,
            stats,
            include_types,
            allow_missing_infra,
            explain_format,
            explain_walk,
        } => extract(
            &binary,
            debug_info.as_deref(),
            &output,
            stats,
            include_types,
            allow_missing_infra,
            explain_format,
            explain_walk,
        ),
        BundleCmd::Stats { tokio_info } => stats(&tokio_info),
        BundleCmd::Dump { tokio_info } => dump(&tokio_info),
        BundleCmd::DumpDwarf { binary } => dump_dwarf(&binary),
    }
}

/// Load a bundle a verb was pointed at, saying which file failed —
/// these verbs take a path from argv, so a typo is the likeliest way
/// in and the message has to name what it tried.
fn load(path: &Path) -> Result<Bundle> {
    Bundle::load(path).with_context(|| format!("failed to load {}", path.display()))
}

/// Extract a bundle for a session to attach to, rather than for a file
/// to be written: every option is its default, since the flags that
/// shape an extraction are `tokio-info extract`'s alone, and the argv a
/// bundle records is provenance for a file this one never becomes.
///
/// `--debug-info` takes any flavor; when it is split debug info, the
/// session's `--binary` is the sibling it was split from and extraction
/// consumes it — the returned flag says so, because the caller's
/// surplus-`--binary` warning must stay quiet then. A self-sufficient
/// `--debug-info` is extracted alone, exactly as the same file would be
/// as a positional: a separate debug build is one file playing every
/// role, never a sibling.
///
/// The warnings come back as text for the caller to print when it
/// suits; nothing here writes to stderr, because this runs on the
/// thread overlapping the attach.
pub fn extract_for_session_with<R>(
    debug_info: &Path,
    binary: Option<&Path>,
    then: impl FnOnce(Bundle, Vec<String>, bool) -> R,
) -> Result<R> {
    let flavor = classify_file(debug_info)
        .with_context(|| format!("failed to read {}", debug_info.display()))?;
    let sources = match (flavor.is_split(), binary) {
        (false, _) => DebugSources {
            binary: debug_info,
            debug_info: None,
        },
        (true, Some(binary)) => DebugSources {
            binary,
            debug_info: Some(debug_info),
        },
        (true, None) => anyhow::bail!(
            "{} is {flavor}, which holds no program contents; also pass \
             --binary naming the binary it was split from",
            debug_info.display()
        ),
    };
    extract_sources_with(
        &sources,
        &ExtractOptions::default(),
        ParsedDwarf::Free,
        |bundle, stats| then(bundle, warnings(&stats), flavor.is_split()),
    )
    .with_context(|| format!("failed to extract from {}", debug_info.display()))
}

fn warnings(stats: &ExtractStats) -> Vec<String> {
    let mut out = Vec::new();
    if let Some(v) = &stats.rustc_below_floor {
        out.push(format!(
            "warning: this binary was produced by rustc {v}, older than the \
             supported floor {RUSTC_FLOOR}; extraction proceeds but is \
             untested against older toolchains"
        ));
    }
    if let Some(family) = &stats.tokio_family_guessed {
        out.push(format!(
            "warning: no tokio version could be recovered from this binary \
             (vendored or forked tokio?); version-dependent formatters \
             assumed the newest supported family ({family})"
        ));
    }
    out
}

#[allow(clippy::too_many_arguments)]
fn extract(
    binary: &Path,
    debug_info: Option<&Path>,
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
    let sources = DebugSources { binary, debug_info };
    // The parse is leaked rather than freed: this process exits as soon
    // as the file is written, and exit reclaims it in one stroke.
    extract_sources_with(&sources, &opts, ParsedDwarf::Leak, |bundle, stats| {
        write_extracted(
            bundle,
            stats,
            output,
            print_stats,
            explaining,
            explaining_walk,
        )
    })
    .with_context(|| match debug_info {
        Some(d) => format!(
            "failed to extract from {} with debug info {}",
            binary.display(),
            d.display()
        ),
        None => format!("failed to extract from {}", binary.display()),
    })?
}

/// The extract verb's second half: report, write, and say what was written.
fn write_extracted(
    bundle: Bundle,
    stats: ExtractStats,
    output: &Path,
    print_stats: bool,
    explaining: Option<String>,
    explaining_walk: Option<String>,
) -> Result<()> {
    for warning in warnings(&stats) {
        eprintln!("{warning}");
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

fn stats(path: &Path) -> Result<()> {
    let bundle = load(path)?;
    let m = &bundle.meta;
    println!("tokio info: {}", path.display());
    println!("  format version:  {}", m.format_version);
    println!("  rustc:           {}", m.rustc_version);
    match &m.tokio_version {
        Some(v) => println!("  tokio:           {v}"),
        None => println!("  tokio:           (unknown)"),
    }
    match m.tokio_unstable {
        Some(true) => println!("  tokio_unstable:  yes"),
        Some(false) => println!("  tokio_unstable:  no"),
        None => println!("  tokio_unstable:  (unknown)"),
    }
    println!("  binary:          {}", m.binary.basename);
    if let Some(d) = &m.debug_info {
        println!("  debug info:      {}", d.basename);
    }
    match &m.vtable_data {
        VtableDataSource::File(file) => println!("  vtable data:     {file}"),
        VtableDataSource::None => println!("  vtable data:     none (dyn coverage incomplete)"),
    }
    println!("  extract args:    {}", m.extract_args);
    println!("  fingerprint:     {} symbols", m.symbol_fingerprint.len());

    let mut kinds = [
        ("base", 0usize),
        ("pointer", 0),
        ("array", 0),
        ("struct", 0),
        ("union", 0),
        ("enum", 0),
        ("c-enum", 0),
        ("opaque", 0),
    ];
    for def in &bundle.types.types {
        let slot = match def {
            TypeDef::Base { .. } => 0,
            TypeDef::Pointer { .. } => 1,
            TypeDef::Array { .. } => 2,
            TypeDef::Struct { .. } => 3,
            TypeDef::Union { .. } => 4,
            TypeDef::Enum { .. } => 5,
            TypeDef::CEnum { .. } => 6,
            TypeDef::Opaque { .. } => 7,
        };
        kinds[slot].1 += 1;
    }
    println!("  types:           {}", bundle.types.types.len());
    for (name, count) in kinds {
        if count > 0 {
            println!("    {name:<10} {count}");
        }
    }
    println!("  strings:         {}", bundle.strings.len());
    println!(
        "  task entries:    {} ({} symbol keys)",
        bundle.tasks.entries.len(),
        bundle.tasks.by_symbol.len()
    );
    println!(
        "    normalized     {} keys ({} ambiguous)",
        bundle.tasks.by_normalized_symbol.len(),
        bundle
            .tasks
            .by_normalized_symbol
            .values()
            .filter(|ids| ids.len() > 1)
            .count()
    );
    println!("  dyn futures:     {}", bundle.dyn_futures.by_symbol.len());
    println!(
        "    normalized     {} keys ({} ambiguous)",
        bundle.dyn_futures.by_normalized_symbol.len(),
        bundle
            .dyn_futures
            .by_normalized_symbol
            .values()
            .filter(|ids| ids.len() > 1)
            .count()
    );
    println!("  statics:         {}", bundle.statics.entries.len());
    let with_decl = bundle
        .provenance
        .entries
        .iter()
        .filter(|p| p.decl.is_some())
        .count();
    println!(
        "  provenance:      {}/{} with source location",
        with_decl,
        bundle.provenance.entries.len()
    );
    println!("  impls:           {}", bundle.impls.entries.len());
    Ok(())
}

fn dump(path: &Path) -> Result<()> {
    let bundle = load(path)?;
    // Loading trusts the payload hash; the debugging tool re-checks the
    // contents in depth, so a bad display program or cross-reference
    // surfaces here rather than silently.
    bundle
        .validate()
        .with_context(|| format!("{} is not internally consistent", path.display()))?;
    let s = |r| bundle.strings.get(r).unwrap_or("<bad strref>");

    println!("== types ({}) ==", bundle.types.types.len());
    for (i, def) in bundle.types.types.iter().enumerate() {
        match def {
            TypeDef::Base {
                name,
                size,
                encoding,
            } => {
                println!("[{i}] base {} size={size} {encoding:?}", s(*name));
            }
            TypeDef::Pointer { name, target } => {
                let name = name.map(s).unwrap_or("<anon>");
                println!("[{i}] pointer {name} -> [{}]", target.0);
            }
            TypeDef::Array { elem, count } => println!("[{i}] array [{}; {count}]", elem.0),
            TypeDef::Struct {
                name,
                size,
                members,
            } => {
                println!("[{i}] struct {} size={size}", s(*name));
                for m in members {
                    println!("      +{:<5} {} : [{}]", m.offset, s(m.name), m.ty.0);
                }
            }
            TypeDef::Union {
                name,
                size,
                members,
            } => {
                println!("[{i}] union {} size={size}", s(*name));
                for m in members {
                    println!("      +{:<5} {} : [{}]", m.offset, s(m.name), m.ty.0);
                }
            }
            TypeDef::Enum { name, size, shape } => {
                println!("[{i}] enum {} size={size}", s(*name));
                if let Some(d) = &shape.discr {
                    println!("      discr +{} : [{}]", d.offset, d.ty.0);
                }
                for v in &shape.variants {
                    let vals = match &v.discr_values {
                        None => "default".to_string(),
                        Some(dv) => format!("{:?}", dv.0),
                    };
                    let decl = v
                        .decl
                        .map(|l| format!(" @ {}:{}", s(l.file), l.line))
                        .unwrap_or_default();
                    // Only when it says something `decl` does not: an await
                    // whose two descriptions agree needs no second line.
                    let await_site = v
                        .await_site
                        .filter(|l| v.decl != Some(*l))
                        .map(|l| format!(" (awaited at {}:{})", s(l.file), l.line))
                        .unwrap_or_default();
                    println!(
                        "      {} ({vals}) +{} : [{}]{decl}{await_site}",
                        s(v.name),
                        v.payload.offset,
                        v.payload.ty.0
                    );
                }
            }
            TypeDef::CEnum {
                name,
                size,
                repr,
                enumerators,
            } => {
                println!("[{i}] c-enum {} size={size} repr=[{}]", s(*name), repr.0);
                for (ename, val) in enumerators {
                    println!("      {} = {val}", s(*ename));
                }
            }
            TypeDef::Opaque { name, size } => {
                println!("[{i}] opaque {} size={size:?}", s(*name));
            }
        }
        let id = BundleTypeId(i as u32);
        if let Some(format) = bundle.types.debug_formats.get(&id) {
            // Resolved, not `Debug`: a raw dump spells a selector as interned
            // string ids, which says nothing about which member a formatter
            // reaches or where it sits.
            //
            // Indented shallower than the member and variant lines above: the
            // display program belongs to the type, and at their column it reads
            // as one more entry in a list it is not part of.
            println!(
                "  debug: {}",
                exegesis::describe::describe_node(&bundle, id, format)
            );
        }
    }

    println!("== tasks ({}) ==", bundle.tasks.entries.len());
    for (i, e) in bundle.tasks.entries.iter().enumerate() {
        println!(
            "[{i}] {} future=[{}] cell=[{}] stage=[{}] scheduler=[{}]",
            s(e.display_name),
            e.future.0,
            e.cell.0,
            e.stage.0,
            e.scheduler.0
        );
        if let Some(p) = bundle.provenance.entries.get(i) {
            let loc = p
                .decl
                .map(|l| format!("{}:{}", s(l.file), l.line))
                .unwrap_or_else(|| "<no decl>".into());
            println!("      {:?} {loc}", p.kind);
        }
    }
    println!("== task symbol keys ({}) ==", bundle.tasks.by_symbol.len());
    for (sym, id) in &bundle.tasks.by_symbol {
        println!("{sym} -> [{}]", id.0);
    }

    println!("== dyn futures ({}) ==", bundle.dyn_futures.by_symbol.len());
    for (sym, id) in &bundle.dyn_futures.by_symbol {
        println!("{sym} -> [{}]", id.0);
    }

    println!("== statics ({}) ==", bundle.statics.entries.len());
    for (role, def) in &bundle.statics.entries {
        let role = match role {
            StaticRole::TlsContextKey => "tls-context-key",
            StaticRole::TaskWakerVtable => "task-waker-vtable",
            StaticRole::TlsLocalSetKey => "tls-local-set-key",
        };
        println!("{role}: {} ({})", def.symbol, def.display);
    }

    println!("== impls ({}) ==", bundle.impls.entries.len());
    for &(path, self_type) in &bundle.impls.entries {
        println!("{} -> {}", s(path), s(self_type));
    }

    println!("== walks ({}) ==", bundle.walks.entries.len());
    for (role, binding) in &bundle.walks.entries {
        println!("{}", exegesis::summary::walk_entry_line(*role, binding));
        if binding.steps.is_empty() {
            continue;
        }
        let steps: Vec<String> = binding
            .steps
            .iter()
            .map(|step| match step {
                Step::Member(MemberRef::Named(name)) => s(*name).to_owned(),
                Step::Member(MemberRef::Index(index)) => format!("%{index}"),
                Step::Deref => "*".to_owned(),
                Step::Variant(name) => format!("<{}>", s(*name)),
                Step::ActiveVariant => "<active variant>".to_owned(),
            })
            .collect();
        let roots: Vec<String> = binding
            .roots
            .iter()
            .map(|id| format!("[{}]", id.0))
            .collect();
        println!("        {} from {}", steps.join("."), roots.join(" "));
    }
    Ok(())
}

fn dump_dwarf(path: &Path) -> Result<()> {
    let summary = dwarf_summary(path)
        .with_context(|| format!("failed to read DWARF from {}", path.display()))?;
    println!("{} total types", summary.types);
    println!("{} total statics", summary.statics);
    println!("{} dup strings", summary.duplicate_strings);
    println!("{} total strings", summary.strings);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{BundleCmd, ExtractStats, RUSTC_FLOOR, exec, warnings};

    #[cfg(not(target_os = "macos"))]
    use hansei_bundle::Bundle;

    fn extract_cmd(binary: std::path::PathBuf, output: std::path::PathBuf) -> BundleCmd {
        BundleCmd::Extract {
            binary,
            debug_info: None,
            output,
            stats: false,
            include_types: Vec::new(),
            allow_missing_infra: true,
            explain_format: None,
            explain_walk: None,
        }
    }

    /// The two facts extraction can be unsure of each get said, and a
    /// binary it was sure of draws nothing. Both callers — the verb and
    /// a session extracting at launch — print whatever comes back, so
    /// what is worth pinning is that the text names the version and the
    /// family the operator has to judge the bundle by.
    #[test]
    fn test_warnings_name_what_extraction_had_to_assume() {
        assert!(warnings(&ExtractStats::default()).is_empty());

        let stats = ExtractStats {
            rustc_below_floor: Some("1.70.0".to_owned()),
            ..Default::default()
        };
        let [line] = warnings(&stats).try_into().expect("one warning");
        assert!(line.contains("1.70.0"), "{line}");
        assert!(line.contains(RUSTC_FLOOR), "{line}");

        let stats = ExtractStats {
            tokio_family_guessed: Some("v1_53".to_owned()),
            ..Default::default()
        };
        let [line] = warnings(&stats).try_into().expect("one warning");
        assert!(line.contains("v1_53"), "{line}");

        let stats = ExtractStats {
            rustc_below_floor: Some("1.70.0".to_owned()),
            tokio_family_guessed: Some("v1_53".to_owned()),
            ..Default::default()
        };
        assert_eq!(warnings(&stats).len(), 2);
    }

    /// The verb runs a real extraction and leaves behind a bundle that
    /// loads. Its subject is this test binary, a Rust program with no
    /// tokio in it — which is what `--allow-missing-infra` is for — so
    /// the case needs neither a fixture nor a target, and what the
    /// bundle *says* is exegesis's own suites' business.
    #[cfg(not(target_os = "macos"))]
    #[test]
    fn test_extract_writes_a_loadable_bundle() {
        let dir = tempfile::tempdir().expect("tempdir");
        let output = dir.path().join("self.tinfo");
        let binary = std::env::current_exe().expect("this test binary's path");
        exec(extract_cmd(binary, output.clone())).expect("extraction should succeed");
        Bundle::load(&output).expect("the bundle it wrote should load");
    }

    /// A macOS test binary carries no DWARF of its own — the compiler
    /// leaves it in the object files — so this is the natural subject
    /// for the no-debug-info refusal: the verb names the file and says
    /// what it lacks instead of writing an empty bundle.
    #[cfg(target_os = "macos")]
    #[test]
    fn test_extract_refuses_a_binary_without_debug_info() {
        let dir = tempfile::tempdir().expect("tempdir");
        let output = dir.path().join("self.tinfo");
        let binary = std::env::current_exe().expect("this test binary's path");
        let err = exec(extract_cmd(binary.clone(), output.clone()))
            .expect_err("a DWARF-less binary alone is refused");
        let msg = format!("{err:?}");
        assert!(msg.contains("no debug info"), "{msg}");
        assert!(msg.contains(&binary.display().to_string()), "{msg}");
        assert!(!output.exists(), "nothing should have been written");
    }

    /// A subject nothing can be read out of fails, naming the file,
    /// rather than reporting a bundle it never wrote — and the readers
    /// say the same of a file that is no bundle, since a path from argv
    /// is as easily mistyped as it is right.
    #[test]
    fn test_the_verbs_report_what_they_could_not_read() {
        let dir = tempfile::tempdir().expect("tempdir");
        let junk = dir.path().join("not-an-object");
        std::fs::write(&junk, b"neither an ELF nor a Mach-O").expect("write");
        let output = dir.path().join("out.tinfo");

        let err = exec(extract_cmd(junk.clone(), output.clone()))
            .expect_err("a file with no object format in it cannot be extracted from");
        let msg = format!("{err:?}");
        assert!(msg.contains(&junk.display().to_string()), "{msg}");
        assert!(!output.exists(), "nothing should have been written");

        for cmd in [
            BundleCmd::Stats {
                tokio_info: junk.clone(),
            },
            BundleCmd::Dump {
                tokio_info: junk.clone(),
            },
            BundleCmd::DumpDwarf {
                binary: junk.clone(),
            },
        ] {
            let err = exec(cmd).expect_err("a file that is not what the verb takes");
            let msg = format!("{err:?}");
            assert!(msg.contains(&junk.display().to_string()), "{msg}");
        }
    }
}
