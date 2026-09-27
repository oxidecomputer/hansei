// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Naming bundle types by id for the listings: the full name, the
//! folded forms a row prints, and the source sites a detail line
//! cites, each memoized per type across a listing's rows.

use crate::Session;

use hansei_bundle::{BundleType, BundleTypeId, BundleView, names};

use std::collections::{BTreeMap, HashMap};
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
            .map(|ty| stop_label(ty, self.impls));
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
            .map(|ty| self.spell(ty));
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
    fn spell(&self, ty: BundleType<'_>) -> String {
        let folded = names::fold_type_name(ty.name(), self.impls);
        match ty.coroutine_word() {
            Some(kind) => format!("{kind} {folded}"),
            None => folded.into_owned(),
        }
    }

    /// The bucket a row of type `ty` is tallied under, where `printed`
    /// is what the row prints for it.
    pub(crate) fn bucket(&self, ty: Option<BundleTypeId>, printed: &str) -> Bucket {
        match ty.and_then(|ty| Some((ty, self.raw(ty)?))) {
            Some((ty, raw)) => Bucket {
                key: BucketKey::Type(raw.to_string()),
                label: printed.to_string(),
                ty: Some(ty),
            },
            None => Bucket {
                key: BucketKey::Printed(printed.to_string()),
                label: printed.to_string(),
                ty: None,
            },
        }
    }
}

/// What a tally of rows by their type keys each row under.
///
/// A type is keyed by its name as the bundle records it, unfolded:
/// identical instantiations recorded under several ids are one type,
/// while two types whose printed names agree — impls of one generic
/// whose arguments the fold drops — are two. A row with no type is
/// keyed by what it prints.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub(crate) enum BucketKey {
    Type(String),
    Printed(String),
}

/// One row's bucket: its key, the label the row prints, and the type
/// the key names — the lowest id carrying it, once merged.
#[derive(Clone, Debug)]
pub(crate) struct Bucket {
    pub(crate) key: BucketKey,
    pub(crate) label: String,
    pub(crate) ty: Option<BundleTypeId>,
}

/// Tally `rows` into their buckets, each summed with `add`, and return
/// the buckets labelled and in label order. A label two buckets share
/// is joined by each one's type id, `(type N)` — the handle an
/// ambiguous join's candidates carry — so that neither reads as the
/// other.
pub(crate) fn tally<R, V: Default>(
    rows: impl IntoIterator<Item = (Bucket, R)>,
    mut add: impl FnMut(&mut V, R),
) -> Vec<(String, V)> {
    let mut buckets: BTreeMap<BucketKey, (String, Option<BundleTypeId>, V)> = BTreeMap::new();
    for (bucket, row) in rows {
        let (_, ty, value) = buckets
            .entry(bucket.key)
            .or_insert_with(|| (bucket.label, bucket.ty, V::default()));
        *ty = match (*ty, bucket.ty) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (a, b) => a.or(b),
        };
        add(value, row);
    }
    let mut shared: HashMap<String, usize> = HashMap::new();
    for (label, ..) in buckets.values() {
        *shared.entry(label.clone()).or_default() += 1;
    }
    let mut labelled: Vec<(String, V)> = buckets
        .into_values()
        .map(|(label, ty, value)| match ty {
            Some(ty) if shared[&label] > 1 => (format!("{label} (type {})", ty.0), value),
            _ => (label, value),
        })
        .collect();
    labelled.sort_by(|(a, _), (b, _)| a.cmp(b));
    labelled
}

/// What stands for the name of a type the bundle does not carry.
fn absent(ty: BundleTypeId) -> String {
    format!("<type {} not in the tokio info>", ty.0)
}

/// The label a stop type buckets under: its path folded for display
/// and cut of its generic arguments — `futures_util::future::Map` —
/// with a coroutine's kind word in front, as the listings spell one
/// (`async fn app::serve`).
pub(crate) fn stop_label(ty: BundleType<'_>, impls: &names::ImplFold) -> String {
    let path = names::outer_path(&names::fold_type_name(ty.name(), impls));
    match ty.coroutine_word() {
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

    use hansei_bundle::{Bundle, BundleTypeId, BundleView, SemanticRuleKind, names};

    use std::sync::LazyLock;

    /// Every type name a hand-laid find carries.
    const NAMES: &[&str] = &[
        // First, as the tasks tables' own hand-built bundle has it.
        "x::branch",
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
        "x::skipped",
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
        "worker::{async_fn_env#0}",
        "tokio::sync::batch_semaphore::Acquire",
        "x",
        "x::fut",
        "a::fut",
        "b::fut",
        "c::fut",
        "f",
        "f0",
        "f1",
        "f2",
        "f3",
        "f4",
        "f5",
        "one::fut",
        "core::pin::Pin<alloc::boxed::Box<dyn core::future::future::Future>>",
        "dyn core::future::future::Future",
        "work::step::{async_fn_env#0}",
        // Two types that print alike: the fold drops a default
        // allocator written out.
        "app::Wrap<u32>",
        "app::Wrap<u32, alloc::alloc::Global>",
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

    /// An id the test bundle carries no type at: a stop no bundle
    /// names.
    pub(crate) const NAMELESS: BundleTypeId = BundleTypeId(u32::MAX);

    /// The id the test bundle gives `name`.
    pub(crate) fn named(name: &str) -> BundleTypeId {
        let at = NAMES
            .iter()
            .position(|n| *n == name)
            .unwrap_or_else(|| panic!("no test type is named {name}"));
        BundleTypeId(at as u32)
    }

    static IMPLS: LazyLock<names::ImplFold> = LazyLock::new(names::ImplFold::default);
    /// The bundle, each coroutine environment's kind recorded as
    /// extraction records it for a reviewed compiler.
    static TYPES: LazyLock<Bundle> = LazyLock::new(|| {
        let mut bundle = hansei_runtime::testkit::named_types(NAMES);
        let kinds: Vec<(BundleTypeId, SemanticRuleKind)> = NAMES
            .iter()
            .enumerate()
            .filter_map(|(at, name)| {
                let kind = match names::coroutine_kind(name)? {
                    "async fn" => SemanticRuleKind::RustcAsyncFn,
                    "async block" => SemanticRuleKind::RustcAsyncBlock,
                    _ => SemanticRuleKind::RustcAsyncClosure,
                };
                Some((BundleTypeId(at as u32), kind))
            })
            .collect();
        hansei_runtime::testkit::coroutine_kinds(&mut bundle, &kinds);
        bundle
    });
    static TYPE_NAMES: LazyLock<TypeNames<'static>> =
        LazyLock::new(|| TypeNames::over(BundleView::new(&TYPES), &IMPLS));

    /// The names of the test bundle's types.
    pub(crate) fn type_names() -> &'static TypeNames<'static> {
        &TYPE_NAMES
    }
}

#[cfg(test)]
mod tests {
    use super::{TypeNames, tally};

    use hansei_bundle::{BundleTypeId, BundleView, names};

    /// Two impls of one generic that print alike are two buckets, each
    /// labelled with its id; one type recorded under two ids is one,
    /// labelled plain and carrying the lower id; a row with no type is
    /// bucketed by what it prints.
    #[test]
    fn test_a_tally_buckets_by_the_type_itself() {
        let bundle = hansei_runtime::testkit::named_types(&[
            "app::{impl#0}::run::{async_fn_env#0}",
            "app::{impl#1}::run::{async_fn_env#0}",
            "app::serve::{async_fn_env#0}",
            "app::serve::{async_fn_env#0}",
        ]);
        let impls = names::ImplFold::default();
        let names = TypeNames::over(BundleView::new(&bundle), &impls);
        let row = |ty: Option<u32>, printed: &str| (names.bucket(ty.map(BundleTypeId), printed), 1);
        let counted = tally(
            [
                row(Some(0), "async fn app::Foo::run"),
                row(Some(1), "async fn app::Foo::run"),
                row(Some(1), "async fn app::Foo::run"),
                row(Some(3), "async fn app::serve"),
                row(Some(2), "async fn app::serve"),
                row(None, "<unknown>"),
                row(None, "<unknown>"),
            ],
            |count: &mut usize, one| *count += one,
        );
        assert_eq!(
            counted,
            [
                ("<unknown>".to_string(), 2),
                ("async fn app::Foo::run (type 0)".to_string(), 1),
                ("async fn app::Foo::run (type 1)".to_string(), 2),
                ("async fn app::serve".to_string(), 2),
            ]
        );
    }

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
