//! Named-statics recovery: locate the tokio statics hansei resolves by
//! symbol name — the TLS context key and the task waker vtable — by their
//! v0-mangled shape in the symbol table.
//!
//! A DWARF variable sweep used to run first, with this as the fallback,
//! but its answer was only ever trusted when the symbol existed in the
//! symbol table — the surviving DIE need not be the one whose symbol
//! survived (on Linux the DWARF names `CONTEXT::{K#0}::{closure#1}`
//! while the symtab keeps `{closure#0}`), and illumos release builds
//! emit no `DW_TAG_variable` for these statics at all. That filter made
//! the sweep answer from exactly the set this matcher searches, and a
//! check across every reachable target (macOS/Linux/illumos, every
//! version-matrix cell, two production-scale binaries) found the two
//! routes agreeing everywhere, with exactly one matching symbol per
//! role, so the sweep was removed.

use super::{ExtractStats, strip};
use crate::bundle::{StaticDef, StaticRole};

use std::collections::BTreeMap;

/// Locate the named statics in the symbol table: the mangled v0 name is
/// all the bundle needs, since the consumer resolves the address by name
/// anyway.
pub(super) fn find_statics(
    symbols: &[&str],
    stats: &mut ExtractStats,
) -> BTreeMap<StaticRole, StaticDef> {
    let mut out = BTreeMap::new();
    for &sym in symbols {
        let stripped = strip(sym);
        if let Some(role) = match_static_symbol(stripped) {
            out.entry(role).or_insert_with(|| StaticDef {
                symbol: stripped.to_owned(),
                display: format!("{:#}", rustc_demangle::demangle(sym)),
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

/// Match a symbol-table name to a named static by its v0-mangled shape.
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
