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
    DebugSources, ExtractOptions, ExtractStats, ParsedDwarf, classify_file, dwarf_summary,
    extract_sources_with,
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
        /// Write the tokio info even where parts of the binary have no
        /// extraction rules: a crate, tokio or rustc version outside the
        /// supported range, or a tokio whose version could not be
        /// recovered. Those parts may show incomplete, raw or wrong
        /// data; by default extraction refuses, naming each.
        #[arg(long)]
        allow_unsupported: bool,
        /// Report why a formatter did or did not attach, for every emitted
        /// type whose fully-qualified name contains this substring.
        #[arg(long, value_name = "FQN")]
        explain_format: Option<String>,
        /// Report how the walk binder resolved each contract role whose
        /// name contains this substring (e.g. "Sleep.deadline").
        #[arg(long, value_name = "ROLE")]
        explain_walk: Option<String>,
        /// Report the semantic facts bound for every emitted type whose
        /// fully-qualified name contains this substring: future
        /// evidence, continuation, coroutine states, resource, container
        /// and the reasons a binding was declined.
        #[arg(long, value_name = "FQN")]
        explain_future: Option<String>,
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
            allow_unsupported,
            explain_format,
            explain_walk,
            explain_future,
        } => extract(
            &binary,
            debug_info.as_deref(),
            &output,
            stats,
            include_types,
            allow_missing_infra,
            allow_unsupported,
            explain_format,
            explain_walk,
            explain_future,
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
/// thread overlapping the attach. A binary with parts no extraction
/// rule supports is refused, as the extract verb refuses it, unless
/// `allow_unsupported` says to attach anyway.
pub fn extract_for_session_with<R>(
    debug_info: &Path,
    binary: Option<&Path>,
    allow_unsupported: bool,
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
        |bundle, stats| {
            let warnings = admit(
                stats.unsupported(),
                allow_unsupported,
                "refusing to attach",
                "attach",
            )?;
            Ok(then(bundle, warnings, flavor.is_split()))
        },
    )
    .with_context(|| format!("failed to extract from {}", debug_info.display()))?
}

/// The warnings to print over what [`ExtractStats::unsupported`] found when
/// `--allow-unsupported` admits it, or the refusal naming all of it
/// when nothing does. `refusing` says what is refused and `proceed`
/// what the flag lets the operator do instead.
fn admit(
    unsupported: Vec<String>,
    allow_unsupported: bool,
    refusing: &str,
    proceed: &str,
) -> Result<Vec<String>> {
    if unsupported.is_empty() || allow_unsupported {
        return Ok(unsupported
            .into_iter()
            .map(|s| format!("warning: {s}"))
            .collect());
    }
    let mut message = format!(
        "{refusing}: parts of this binary do not have extraction rules, and \
         may show incomplete, raw, or wrong data:"
    );
    for s in &unsupported {
        message.push_str("\n  ");
        message.push_str(s);
    }
    message.push_str(&format!("\n(--allow-unsupported to {proceed} anyway)"));
    Err(anyhow::anyhow!(message))
}

#[allow(clippy::too_many_arguments)]
fn extract(
    binary: &Path,
    debug_info: Option<&Path>,
    output: &Path,
    print_stats: bool,
    include_types: Vec<String>,
    allow_missing_infra: bool,
    allow_unsupported: bool,
    explain_format: Option<String>,
    explain_walk: Option<String>,
    explain_future: Option<String>,
) -> Result<()> {
    let explaining = explain_format.clone();
    let explaining_walk = explain_walk.clone();
    let opts = ExtractOptions {
        extract_args: provenance(binary, debug_info, &include_types, allow_missing_infra),
        include_types,
        allow_missing_infra,
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
            allow_unsupported,
            explaining,
            explaining_walk,
            explain_future,
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

/// The command line a bundle records as its provenance: the verb and
/// only the inputs that shape what the bundle holds, so extracting one
/// file with the same flags writes the same bytes whatever directory it
/// ran in and wherever the output went. Files are named by basename, as
/// `Meta` identifies them anyway; `--output`, `--stats` and the
/// `--explain-*` reports change what is printed, not what is written,
/// and are left out.
fn provenance(
    binary: &Path,
    debug_info: Option<&Path>,
    include_types: &[String],
    allow_missing_infra: bool,
) -> String {
    let basename = |path: &Path| {
        path.file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default()
    };
    let mut words = vec![
        "tokio-info".to_owned(),
        "extract".to_owned(),
        basename(binary),
    ];
    if let Some(debug_info) = debug_info {
        words.push("--debug-info".to_owned());
        words.push(basename(debug_info));
    }
    for ty in include_types {
        words.push("--include-type".to_owned());
        words.push(ty.clone());
    }
    if allow_missing_infra {
        words.push("--allow-missing-infra".to_owned());
    }
    words.join(" ")
}

/// The extract verb's second half: report, write, and say what was
/// written — or, for a binary with parts no extraction rule supports,
/// refuse to write. A refused bundle still answers the
/// `--explain-*` and `--stats` reports, which are how to see what the
/// refusal is about.
#[allow(clippy::too_many_arguments)]
fn write_extracted(
    bundle: Bundle,
    stats: ExtractStats,
    output: &Path,
    print_stats: bool,
    allow_unsupported: bool,
    explaining: Option<String>,
    explaining_walk: Option<String>,
    explain_future: Option<String>,
) -> Result<()> {
    let refusing = format!("refusing to write {}", output.display());
    let admitted = admit(
        stats.unsupported(),
        allow_unsupported,
        &refusing,
        "write it",
    );
    if let Ok(warnings) = &admitted {
        for warning in warnings {
            eprintln!("{warning}");
        }
        // Extraction validated the bundle before handing it over;
        // `save` would only validate it again.
        bundle
            .write_file(output)
            .with_context(|| format!("failed to write {}", output.display()))?;
        println!(
            "wrote {} ({} types, {} task entries, {} dyn futures)",
            output.display(),
            bundle.types.types.len(),
            bundle.tasks.entries.len(),
            bundle.dyn_futures.by_symbol.len(),
        );
    }
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
    if let Some(wanted) = explain_future {
        print!("{}", exegesis::describe::explain_future(&bundle, &wanted));
    }
    if print_stats {
        print!("{stats}");
    }
    admitted.map(drop)
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
    let same_named = same_named_types(&bundle);
    println!(
        "    same-named {} names, {} types",
        same_named.len(),
        same_named.iter().map(|(_, ids)| ids.len()).sum::<usize>()
    );
    println!(
        "    crate labels {} types, {} naming two releases",
        bundle.types.crate_labels.len(),
        bundle
            .types
            .crate_labels
            .values()
            .filter(|label| label.versions.len() > 1)
            .count()
    );
    println!("  strings:         {}", bundle.strings.len());
    println!("  poll decls:      {}", bundle.types.poll_decls.len());
    println!(
        "  local decls:     {} coroutines, {} locals",
        bundle.types.local_decls.len(),
        bundle
            .types
            .local_decls
            .values()
            .map(Vec::len)
            .sum::<usize>()
    );
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

/// The names the bundle records more than one type under, each with
/// its ids: two releases of one crate whose layouts differ, or two
/// types one name happens to cover. Grouped off the name index, which
/// is sorted by name, so a name's types arrive together.
fn same_named_types(bundle: &Bundle) -> Vec<(&str, Vec<BundleTypeId>)> {
    let mut groups: Vec<(&str, Vec<BundleTypeId>)> = Vec::new();
    for (name, ty) in hansei_bundle::BundleView::new(bundle).named_types() {
        match groups.last_mut() {
            Some((seen, ids)) if *seen == name => ids.push(ty.id()),
            _ => groups.push((name, vec![ty.id()])),
        }
    }
    groups.retain(|(_, ids)| ids.len() > 1);
    groups
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
        if let Some(label) = bundle.types.crate_labels.get(&id) {
            let versions: Vec<&str> = label.versions.iter().map(|&v| s(v)).collect();
            println!("  crate: {} {}", s(label.package), versions.join("/"));
        }
    }

    // The names two or more types share, so a reader can tell the
    // types apart by id and size where a name alone cannot.
    let view = hansei_bundle::BundleView::new(&bundle);
    let same_named = same_named_types(&bundle);
    println!("== same-named types ({}) ==", same_named.len());
    for (name, ids) in &same_named {
        let ids: Vec<String> = ids
            .iter()
            .map(|id| {
                let ty = view.ty(*id);
                let size = ty.map_or(0, |ty| ty.size());
                // The crate release, where the bundle labeled the type:
                // the size alone tells two layouts apart, the label
                // says which release each is.
                match ty.and_then(|ty| ty.crate_release()) {
                    Some(release) => format!("[{}] size={size} {release}", id.0),
                    None => format!("[{}] size={size}", id.0),
                }
            })
            .collect();
        println!("{name}: {}", ids.join(", "));
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
    for (sym, ids) in &bundle.tasks.by_symbol {
        let ids: Vec<_> = ids.iter().map(|id| id.0).collect();
        println!("{sym} -> {ids:?}");
    }

    println!("== dyn futures ({}) ==", bundle.dyn_futures.by_symbol.len());
    for (sym, ids) in &bundle.dyn_futures.by_symbol {
        let ids: Vec<_> = ids.iter().map(|id| id.0).collect();
        println!("{sym} -> {ids:?}");
    }

    println!("== statics ({}) ==", bundle.statics.entries.len());
    for (role, def) in &bundle.statics.entries {
        let role = match role {
            StaticRole::TlsContextKey => "tls-context-key",
            StaticRole::TaskWakerVtable => "task-waker-vtable",
            StaticRole::TlsLocalSetKey => "tls-local-set-key",
            StaticRole::TlsThreadId => "tls-thread-id",
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

    println!(
        "== semantics ({} origins, {} rules, {} types) ==",
        bundle.semantics.origins.len(),
        bundle.semantics.rules.len(),
        bundle.semantics.types.len()
    );
    print!("{}", exegesis::describe::describe_semantics(&bundle));
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
    use super::{BundleCmd, ExtractStats, admit, exec, provenance, write_extracted};

    use hansei_bundle::Bundle;
    use hansei_runtime::testkit::{self, FIXTURE_SETS, PROGRAMS};

    use std::path::Path;

    fn extract_cmd(binary: std::path::PathBuf, output: std::path::PathBuf) -> BundleCmd {
        BundleCmd::Extract {
            binary,
            debug_info: None,
            output,
            stats: false,
            include_types: Vec::new(),
            allow_missing_infra: true,
            allow_unsupported: false,
            explain_format: None,
            explain_walk: None,
            explain_future: None,
        }
    }

    /// Nothing unsupported passes untouched; something unsupported is
    /// refused with every sentence and the flag named, or, with the
    /// flag, comes back as one warning each for the caller to print.
    #[test]
    fn test_unsupported_refuses_unless_allowed() {
        assert!(
            admit(Vec::new(), false, "refusing", "go")
                .unwrap()
                .is_empty()
        );

        let unsupported = vec!["parking_lot 0.11.2 is older".to_owned(), "tokio".to_owned()];
        let refusal = admit(
            unsupported.clone(),
            false,
            "refusing to write x.tinfo",
            "write it",
        )
        .expect_err("unsupported refuses by default")
        .to_string();
        assert_eq!(
            refusal,
            "refusing to write x.tinfo: parts of this binary do not have \
             extraction rules, and may show incomplete, raw, or wrong data:\n  \
             parking_lot 0.11.2 is older\n  \
             tokio\n\
             (--allow-unsupported to write it anyway)"
        );

        assert_eq!(
            admit(unsupported, true, "refusing", "go").unwrap(),
            ["warning: parking_lot 0.11.2 is older", "warning: tokio"]
        );
    }

    /// The verb writes nothing it refuses: an unsupported extraction
    /// fails naming the flag and leaves no file behind, and the flag
    /// writes the same bundle out. Any checked-in bundle stands in for
    /// the extraction's, since what is refused is the stats' doing.
    #[test]
    fn test_extract_writes_nothing_it_refuses() {
        let tinfo = testkit::fixture(FIXTURE_SETS[0], &format!("{}.tinfo", PROGRAMS[0]));
        let bundle = Bundle::load(&tinfo).expect("the fixture bundle should load");
        let stats = || ExtractStats {
            tokio_family_guessed: Some("v1_53".to_owned()),
            ..Default::default()
        };
        let dir = tempfile::tempdir().expect("tempdir");
        let output = dir.path().join("x.tinfo");

        let write = |allow_unsupported| {
            write_extracted(
                bundle.clone(),
                stats(),
                &output,
                false,
                allow_unsupported,
                None,
                None,
                None,
            )
        };
        let refusal = write(false).expect_err("unsupported refuses by default");
        assert!(
            refusal.to_string().contains("--allow-unsupported"),
            "{refusal}"
        );
        assert!(!output.exists(), "a refused bundle was written");

        write(true).expect("the flag admits it");
        assert_eq!(
            Bundle::load(&output).expect("the bundle it wrote should load"),
            bundle
        );
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

    /// The provenance a bundle records names the files it came from by
    /// basename and keeps every flag that shapes the bundle, so two
    /// spellings of one invocation agree and two different extractions
    /// do not.
    #[test]
    fn test_provenance_keeps_what_shapes_the_bundle() {
        assert_eq!(
            provenance(Path::new("../cores/nexus"), None, &[], false),
            "tokio-info extract nexus",
        );
        assert_eq!(
            provenance(Path::new("/data/nexus"), None, &[], false),
            provenance(Path::new("./nexus"), None, &[], false),
        );
        assert_eq!(
            provenance(
                Path::new("/data/rama.bin"),
                Some(Path::new("/data/rama.dwp")),
                &[
                    "tokio::sync::Notify".to_owned(),
                    "std::net::IpAddr".to_owned()
                ],
                true,
            ),
            "tokio-info extract rama.bin --debug-info rama.dwp \
             --include-type tokio::sync::Notify --include-type std::net::IpAddr \
             --allow-missing-infra",
        );
    }

    /// Extracting the same binary twice writes the same bytes, even when
    /// the binary path is written differently and the output goes
    /// somewhere else: neither is anything the bundle describes.
    #[cfg(not(target_os = "macos"))]
    #[test]
    fn test_extract_writes_the_same_bytes_from_any_path() {
        let dir = tempfile::tempdir().expect("tempdir");
        let binary = std::env::current_exe().expect("this test binary's path");
        let respelled = binary
            .parent()
            .expect("the test binary sits in a directory")
            .join(".")
            .join(binary.file_name().expect("the test binary has a name"));
        let first = dir.path().join("first.tinfo");
        let second = dir.path().join("a-longer-second-name.tinfo");
        exec(extract_cmd(binary, first.clone())).expect("extraction should succeed");
        exec(extract_cmd(respelled, second.clone())).expect("extraction should succeed");
        let first = std::fs::read(&first).expect("read the first bundle");
        let second = std::fs::read(&second).expect("read the second bundle");
        assert!(first == second, "re-extracting changed the bundle's bytes");
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
