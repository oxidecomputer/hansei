// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Naming bundle types by id for the listings: the full name, the
//! folded forms a row prints, and the source sites a detail line
//! cites, each memoized per type across a listing's rows.

use crate::Session;

use hansei_bundle::{BundleTypeId, BundleView, names};

use std::collections::HashMap;
use std::sync::RwLock;

/// How the listings name a type they hold by id — a census find's
/// future, a set's type, the type an unknown continuation stopped at:
/// the bundle's name, folded for display. Built over the session's
/// bundle; over none for a listing test laid out by hand, where every
/// type is nameless.
pub(crate) struct TypeNames<'a> {
    view: Option<BundleView<'a>>,
    impls: &'a names::ImplFold,
    /// Labels by type id. A listing's stops are a few dozen types over
    /// tens of thousands of rows, and each label is a fold pass over
    /// the name — 0.4 s of wall time (0.9 s of CPU) across the nexus
    /// core's futures rows uncached, against a 1.5 s launch.
    labels: RwLock<HashMap<BundleTypeId, Option<String>>>,
    /// The same types' full names, memoized the same way and for the
    /// same reason: a name is folded once however many rows carry it.
    names: RwLock<HashMap<BundleTypeId, Option<String>>>,
    /// The same types as futures are named, kind word first.
    futures: RwLock<HashMap<BundleTypeId, String>>,
}

impl<'a> TypeNames<'a> {
    pub(crate) fn of<T: proc::Target>(session: &'a Session<'_, T>) -> Self {
        TypeNames {
            view: Some(session.ctx.view),
            impls: &session.impl_fold,
            labels: RwLock::default(),
            names: RwLock::default(),
            futures: RwLock::default(),
        }
    }

    /// No bundle to name a stop from.
    #[cfg(test)]
    pub(crate) fn none(impls: &'a names::ImplFold) -> Self {
        TypeNames {
            view: None,
            impls,
            labels: RwLock::default(),
            names: RwLock::default(),
            futures: RwLock::default(),
        }
    }

    /// Over a bundle view and its impl fold, with no session around them.
    pub(crate) fn over(view: BundleView<'a>, impls: &'a names::ImplFold) -> Self {
        TypeNames {
            view: Some(view),
            impls,
            labels: RwLock::default(),
            names: RwLock::default(),
            futures: RwLock::default(),
        }
    }

    /// The bundle's impl-path substitutions, for a name held as text
    /// rather than by id.
    pub(crate) fn impls(&self) -> &'a names::ImplFold {
        self.impls
    }

    /// The stop's label, or `None` where the type is not in the bundle.
    pub(crate) fn label(&self, ty: BundleTypeId) -> Option<String> {
        if let Some(label) = self.labels.read().unwrap().get(&ty) {
            return label.clone();
        }
        let label = self
            .view
            .and_then(|view| view.ty(ty))
            .map(|ty| stop_label(ty.name(), self.impls));
        self.labels
            .write()
            .unwrap()
            .entry(ty)
            .or_insert(label)
            .clone()
    }

    /// The type's name in full, for a line that names one future
    /// rather than a bucket of them: `None` where the type is not in
    /// the bundle.
    pub(crate) fn name(&self, ty: BundleTypeId) -> Option<String> {
        if let Some(name) = self.names.read().unwrap().get(&ty) {
            return name.clone();
        }
        let name = self
            .view
            .and_then(|view| view.ty(ty))
            .map(|ty| self.spell(ty.name()));
        self.names
            .write()
            .unwrap()
            .entry(ty)
            .or_insert(name)
            .clone()
    }

    /// The type's name as the bundle records it, unfolded: `None` where
    /// the type is not in the bundle.
    pub(crate) fn raw(&self, ty: BundleTypeId) -> Option<&'a str> {
        Some(self.view?.ty(ty)?.name())
    }

    /// The type's name folded for display, its generic arguments kept.
    pub(crate) fn folded(&self, ty: BundleTypeId) -> String {
        match self.raw(ty) {
            Some(name) => names::fold_type_name(name, self.impls).into_owned(),
            None => absent(ty),
        }
    }

    /// The type as a future is named where no kind column carries its
    /// kind: the kind word joined to the folded name — `async fn
    /// foo::bar`, `future tokio::time::Sleep`.
    pub(crate) fn future(&self, ty: BundleTypeId) -> String {
        if let Some(name) = self.futures.read().unwrap().get(&ty) {
            return name.clone();
        }
        let name = match self.view.and_then(|view| view.ty(ty)) {
            Some(ty) => ty.future_display_name(self.impls),
            None => absent(ty),
        };
        self.futures
            .write()
            .unwrap()
            .entry(ty)
            .or_insert(name)
            .clone()
    }

    /// Where the type is written, for the `type defined at:` line of
    /// a member or an item: a hand-written future's or stream's `poll`,
    /// or a coroutine's own `async fn` or block. `None` where the type
    /// is not in the bundle or has no declaration recorded. Not
    /// memoized, unlike the two above: those fold a name per call, and
    /// this is two map probes at most.
    pub(crate) fn site(&self, ty: BundleTypeId) -> Option<(String, u32)> {
        let ty = self.view?.ty(ty)?;
        let (file, line) = ty.implementation_site().or_else(|| ty.declaration_site())?;
        Some((file.to_string(), line))
    }

    /// Where the coroutine `ty` declares its frame-resident local
    /// `name` — the `let` or argument behind a `held in:` line's
    /// backticked name, printed under it as `declared at:`. `None`
    /// where the frame is no coroutine, or the bundle recorded no
    /// declaration for the name.
    pub(crate) fn local_site(&self, ty: BundleTypeId, name: &str) -> Option<(String, u32)> {
        let (file, line) = self.view?.ty(ty)?.local_site(name)?;
        Some((file.to_string(), line))
    }

    /// One type name as a line that names a future carries it: folded
    /// for display, its generic arguments kept — they are what tells
    /// one `select!` arm from the arm beside it — with a coroutine's
    /// kind word in front, as [`stop_label`] puts one there.
    pub(crate) fn spell(&self, name: &str) -> String {
        let folded = names::fold_type_name(name, self.impls);
        match names::coroutine_kind(name) {
            Some(kind) => format!("{kind} {folded}"),
            None => folded.into_owned(),
        }
    }
}

/// What stands for the name of a type the bundle does not carry.
fn absent(ty: BundleTypeId) -> String {
    format!("<type {} not in the tokio info>", ty.0)
}

/// The label a stop type buckets under: its path folded for display
/// and cut of its generic arguments — `futures_util::future::Map` —
/// with a coroutine's kind word in front, as the listings spell one
/// (`async fn app::serve`).
pub(crate) fn stop_label(name: &str, impls: &names::ImplFold) -> String {
    let path = names::outer_path(&names::fold_type_name(name, impls));
    match names::coroutine_kind(name) {
        Some(kind) => format!("{kind} {path}"),
        None => path,
    }
}

/// What a listing test laid out by hand names its finds' types from:
/// one bundle holding a type for each name the tests give a find,
/// that name's position its id.
#[cfg(test)]
pub(crate) mod testing {
    use super::TypeNames;

    use hansei_bundle::{Bundle, BundleTypeId, BundleView, names};

    use std::sync::LazyLock;

    /// Every type name a hand-laid find carries.
    const NAMES: &[&str] = &[
        "app::work::{async_fn_env#0}",
        "app::child",
        "FuturesUnordered<app::child>",
        "JoinSet<()>",
        "Mutex::lock::{async_fn_env#0}",
        "app::poll::{async_fn_env#0}",
        "futures_util::stream::futures_unordered::FuturesUnordered<()>",
        "tokio::task::join_set::JoinSet<()>",
        "step::{async_fn_env#0}",
        "FuturesUnordered<step::{async_fn_env#0}>",
        "x::branch",
        "app::work",
        "FuturesUnordered",
        "child::fut",
        "cold::fut",
        "h::fut",
        "held::fut",
        "hot::fut",
        "rare::fut",
        "FuturesUnordered<f>",
        LONG,
        LONG_SET,
        LONG_JOIN_SET,
        "app::a::very::long::module::path::to::the::work::{async_fn_env#0}",
        "a::very::long::module::path::to::some::future_type",
    ];

    /// A future's name long enough that any fit width cuts it, and the
    /// two sets holding it.
    pub(crate) const LONG: &str = "app::a::very::long::module::path::down::to::the::future::in::\
                                   question::with::generic::arguments::spelled::out::in::full::Type";
    pub(crate) const LONG_SET: &str = "FuturesUnordered<app::a::very::long::module::path::down::\
                                       to::the::future::in::question::with::generic::arguments::\
                                       spelled::out::in::full::Type>";
    pub(crate) const LONG_JOIN_SET: &str = "JoinSet<app::a::very::long::module::path::down::to::\
                                            the::future::in::question::with::generic::arguments::\
                                            spelled::out::in::full::Type>";

    /// The id the test bundle gives `name`.
    pub(crate) fn named(name: &str) -> BundleTypeId {
        let at = NAMES
            .iter()
            .position(|n| *n == name)
            .unwrap_or_else(|| panic!("no test type is named {name}"));
        BundleTypeId(at as u32)
    }

    static IMPLS: LazyLock<names::ImplFold> = LazyLock::new(names::ImplFold::default);
    static TYPES: LazyLock<Bundle> = LazyLock::new(|| hansei_runtime::testkit::named_types(NAMES));
    static TYPE_NAMES: LazyLock<TypeNames<'static>> =
        LazyLock::new(|| TypeNames::over(BundleView::new(&TYPES), &IMPLS));

    /// The names of the test bundle's types.
    pub(crate) fn type_names() -> &'static TypeNames<'static> {
        &TYPE_NAMES
    }
}

#[cfg(test)]
mod tests {
    use super::TypeNames;

    use hansei_bundle::{BundleTypeId, BundleView, names};

    /// A type the bundle does not carry is named for its id and the
    /// fact, however it is asked for.
    #[test]
    fn test_a_type_not_in_the_bundle_is_named_as_absent() {
        let bundle = hansei_runtime::testkit::named_types(&["app::serve::{async_fn_env#0}"]);
        let impls = names::ImplFold::default();
        let names = TypeNames::over(BundleView::new(&bundle), &impls);
        let missing = BundleTypeId(7);
        assert_eq!(names.raw(missing), None);
        assert_eq!(names.folded(missing), "<type 7 not in the tokio info>");
        assert_eq!(names.future(missing), "<type 7 not in the tokio info>");
    }
}
