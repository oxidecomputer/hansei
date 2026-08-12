//! Named-statics recovery: locate the tokio statics hansei resolves by
//! symbol name — the TLS context key and the task waker vtable — from
//! DWARF variables where they exist, and from the symbol table's mangled
//! names where they do not.

use super::{ExtractStats, strip};
use crate::bundle::{StaticDef, StaticRole};
use crate::view::DwView;

use std::collections::{BTreeMap, BTreeSet};

const WAKER_NS: &str = "tokio::runtime::task::waker";

/// Locate the named statics by DWARF shape, not by hardcoded
/// mangled names: the TLS key static's path spelling is a std internal
/// that differs across platforms and std versions.
pub(super) fn find_statics(
    view: &DwView<'_>,
    symbols: &[&str],
    symtab: &BTreeSet<&str>,
    stats: &mut ExtractStats,
) -> BTreeMap<StaticRole, StaticDef> {
    let waker_ns = view.find_ns(WAKER_NS).map(|n| n.id());

    let mut out = BTreeMap::new();
    for (_, var) in view.variables() {
        let Some(linkage) = var.linkage_name() else {
            continue;
        };
        match var.name() {
            // std's thread_local storage for tokio's CONTEXT: named
            // `__RUST_STD_INTERNAL_VAL` (1.97-era std), nested under
            // namespaces rooted at tokio::runtime::context::CONTEXT.
            Some("__RUST_STD_INTERNAL_VAL") => {
                let mut segments = Vec::new();
                let mut ns = var.namespace();
                while let Some(n) = ns {
                    segments.push(n.name().to_owned());
                    ns = n.parent();
                }
                segments.reverse();
                if segments.len() >= 4
                    && segments[..4] == ["tokio", "runtime", "context", "CONTEXT"]
                {
                    out.entry(StaticRole::TlsContextKey).or_insert(StaticDef {
                        symbol: strip(linkage).to_owned(),
                        display: format!("{:#}", rustc_demangle::demangle(linkage)),
                    });
                }
            }
            Some("WAKER_VTABLE") if var.raw().namespace == waker_ns && waker_ns.is_some() => {
                out.entry(StaticRole::TaskWakerVtable).or_insert(StaticDef {
                    symbol: strip(linkage).to_owned(),
                    display: format!("{:#}", rustc_demangle::demangle(linkage)),
                });
            }
            _ => {}
        }
    }

    // A DWARF sweep can name a symbol the binary does not have. The
    // CONTEXT thread-local is emitted once per codegen unit, and the DIE
    // that survives need not be the one whose symbol did: on Linux the
    // DWARF names `CONTEXT::{K#0}::{closure#1}` while the symbol table
    // keeps `{closure#0}`, and the two mangle differently. A name the
    // symtab does not have is no use to a consumer that resolves it by
    // name, so drop it here and let the symbol table answer instead.
    out.retain(|_, def| symtab.contains(def.symbol.as_str()));

    // Fall back to the symbol table for any static the DWARF sweep missed
    // or named unusably. On some targets (notably illumos release builds)
    // rustc emits no `DW_TAG_variable` DIE for these tokio/std dependency
    // statics, yet the symbol survives in `.symtab`/`.dynsym`; the mangled
    // v0 name is all the bundle needs, since the consumer resolves the
    // address by name anyway.
    for &sym in symbols {
        let stripped = strip(sym);
        if let Some(role) = match_static_symbol(stripped) {
            out.entry(role).or_insert_with(|| {
                stats.statics_from_symtab += 1;
                StaticDef {
                    symbol: stripped.to_owned(),
                    display: format!("{:#}", rustc_demangle::demangle(sym)),
                }
            });
        }
    }

    if !out.contains_key(&StaticRole::TlsContextKey) {
        stats
            .statics_missing
            .push("TlsContextKey (tokio::runtime::context::CONTEXT thread-local)".to_owned());
    }
    if !out.contains_key(&StaticRole::TaskWakerVtable) {
        stats
            .statics_missing
            .push("TaskWakerVtable (tokio::runtime::task::waker::WAKER_VTABLE)".to_owned());
    }
    out
}

/// Match an ELF symbol-table name to a named static by its v0-mangled
/// shape. Used as a fallback when the DWARF carries no `DW_TAG_variable` DIE
/// for the static (e.g. illumos release builds), where the symbol is still
/// present in `.symtab`/`.dynsym`.
///
/// The match keys on the length-prefixed path segments of the mangled name so
/// it is independent of the crate disambiguator (which varies per build) and
/// of the thread-local implementation (`native` vs `os`), which changes the
/// symbol's namespace nesting but not the `tokio::runtime::context::CONTEXT`
/// prefix or the trailing `__RUST_STD_INTERNAL_VAL` identifier.
fn match_static_symbol(sym: &str) -> Option<StaticRole> {
    if sym.ends_with("5tokio7runtime4task5waker12WAKER_VTABLE") {
        return Some(StaticRole::TaskWakerVtable);
    }
    // Several crates define a `__RUST_STD_INTERNAL_VAL` thread-local; take the
    // one under `tokio::runtime::context::CONTEXT`, not, say,
    // `std::sync::mpmc::context` or `tokio::task::local::CURRENT`.
    if sym.contains("5tokio7runtime7context7CONTEXT") && sym.ends_with("__RUST_STD_INTERNAL_VAL") {
        return Some(StaticRole::TlsContextKey);
    }
    None
}

#[cfg(test)]
mod tests {
    use super::{StaticRole, match_static_symbol};

    // v0-mangled symbols observed in an illumos futurelock release build,
    // whose DWARF omits the `DW_TAG_variable` DIE for these statics.
    #[test]
    fn test_match_waker_vtable_symbol() {
        let sym = "_RNvNtNtNtCsjd01hASgEtw_5tokio7runtime4task5waker12WAKER_VTABLE";
        assert_eq!(match_static_symbol(sym), Some(StaticRole::TaskWakerVtable));
    }

    #[test]
    fn test_match_tls_context_symbol() {
        let sym =
            "_RNvNCNvNtNtCsjd01hASgEtw_5tokio7runtime7context7CONTEXT023___RUST_STD_INTERNAL_VAL";
        assert_eq!(match_static_symbol(sym), Some(StaticRole::TlsContextKey));
    }

    // Other crates define a `__RUST_STD_INTERNAL_VAL`; only the one nested
    // under `tokio::runtime::context::CONTEXT` is the tokio context key.
    #[test]
    fn test_reject_foreign_internal_val_symbols() {
        let mpmc_context = "_RNvNCNvNvMNtNtNtCsijgp68BdGXk_3std4sync4mpmc7contextNtB8_7Context4with7CONTEXT023___RUST_STD_INTERNAL_VAL";
        let tokio_local =
            "_RNvNCNvNtNtCsjd01hASgEtw_5tokio4task5local7CURRENT023___RUST_STD_INTERNAL_VAL";
        let parking_lot = "_RNvNCNvNvNtCs6eIw0jaMQft_16parking_lot_core11parking_lot16with_thread_data11THREAD_DATA023___RUST_STD_INTERNAL_VAL";
        assert_eq!(match_static_symbol(mpmc_context), None);
        assert_eq!(match_static_symbol(tokio_local), None);
        assert_eq!(match_static_symbol(parking_lot), None);
    }

    #[test]
    fn test_ignore_unrelated_symbols() {
        assert_eq!(match_static_symbol("main"), None);
        assert_eq!(match_static_symbol(""), None);
    }
}
