// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Sparse identity seeds, the library-layout bindings, and the reviewed
//! poll programs. Compiler candidates retain an unavailable storage
//! boundary until a reviewed defining-origin convention can bind them;
//! Tokio and futures-util resource, container and scheduler facts bind
//! from the walk contract's own roots, so each is a layout fact about the
//! exact type it names.
//!
//! A poll program is emitted only under a reviewed rule — a compiler
//! coroutine's suspended states, the four std pointer adapters, tracing's
//! `Instrumented` — whose origin and layout both check out on this
//! binary, and only for a type that is positively a future: a task's
//! root, a `Future::poll` self type, a bound coroutine, or the static
//! delegate of a parent whose own program is bound. That closure is a
//! least fixed point over the emitted programs; nothing about a
//! wrapper's shape, member count or drop glue seeds it.

use super::emitter::Emitter;
use super::passes::{members_of, state_name};
use super::sweep::PollSource;
use crate::TypeId;
use crate::bundle::names::coroutine_kind;
use crate::bundle::origin::registry_origin;
use crate::bundle::{
    AccessBinding, AccessKind, BundleTypeId, ContainerBinding, ContainerKind, Continuation,
    CoroutineLayout, CoroutinePhase, CoroutineState, DynFutureLayout, FutureEvidence, FutureFacts,
    FutureTarget, IoOperationKind, LayoutSelection, MemberRef, PollAction, PollCase, PollProgram,
    ResourceBinding, ResourceKind, SchedulerBinding, SchedulerClass, SelectBinding, Selector,
    SemanticIssue, SemanticIssueKind, SemanticOrigin, SemanticOriginId, SemanticRule,
    SemanticRuleId, SemanticRuleKind, SemanticTable, SourceFileEvidence, Step, StoragePolicy,
    StrRef, StringInterner, TaskEntryId, TaskFutureEntry, TypeDef, TypeSemantics, TypeTable,
    TypedPath, WalkOutcome, WalkRole, WalksTable, container_roles, container_routes,
    required_resource_roles, required_resource_routes, scheduler_role, semantic_path_target,
};
use crate::detect::Family;
use crate::detect::adapters::{
    self, InstrumentedLayout, Pointee, SelectLayout, StdAdapter, WidePointer,
};
use crate::detect::semantics::{
    FUTURES_UTIL_ADAPTERS_V0_3_30, HYPER_UTIL_TOKIO_SLEEP_V0_1_10, LibraryConvention,
    RustcConvention, TOKIO_SELECT_V1_47, TOKIO_STREAM_MAP_V0_1_14, TOKIO_STREAM_WATCH_V0_1_14,
    TOKIO_UTIL_REUSABLE_BOX_V0_7_11, TRACING_INSTRUMENTED_V0_1_40, library_convention,
    rustc_coroutine_convention, rustc_dyn_future_abi_convention, rustc_std_adapter_convention,
    tokio_state_protocol,
};

use std::collections::{BTreeMap, BTreeSet, VecDeque};

/// What the defining units of a compiler-storage candidate said about
/// the convention its layout follows, decided where the reader's origins
/// are at hand and carried to the binder by bundle id.
#[derive(Clone, Debug)]
pub(super) enum CompilerVerdict {
    /// Every defining unit's producer falls inside one reviewed range.
    Supported {
        /// The canonical definition's producer, as the origin records it.
        producer: String,
        convention: &'static RustcConvention,
    },
    /// Why no convention applies: the reader's decline, spelled out.
    Declined(String),
}

/// Which reviewed compiler convention a verdict is asked under: each is
/// a separate review of a separate fact, over the same defining units.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub(super) enum Reviewed {
    Coroutine,
    StdAdapters,
    DynFutureAbi,
}

impl Reviewed {
    /// The convention selector the verdict runs a producer through.
    pub(super) fn select(self, producer: &str) -> Option<&'static RustcConvention> {
        match self {
            Reviewed::Coroutine => rustc_coroutine_convention(producer),
            Reviewed::StdAdapters => rustc_std_adapter_convention(producer),
            Reviewed::DynFutureAbi => rustc_dyn_future_abi_convention(producer),
        }
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum AdapterKind {
    Box,
    MutRef,
    PinBox,
    PinMutRef,
}

impl AdapterKind {
    fn poll_rule(self) -> SemanticRuleKind {
        match self {
            AdapterKind::Box => SemanticRuleKind::StdBoxPoll,
            AdapterKind::MutRef => SemanticRuleKind::StdMutRefPoll,
            AdapterKind::PinBox => SemanticRuleKind::StdPinBoxPoll,
            AdapterKind::PinMutRef => SemanticRuleKind::StdPinMutRefPoll,
        }
    }

    fn access_rule(self) -> SemanticRuleKind {
        match self {
            AdapterKind::Box => SemanticRuleKind::StdBoxAccess,
            AdapterKind::MutRef => SemanticRuleKind::StdMutRefAccess,
            AdapterKind::PinBox => SemanticRuleKind::StdPinBoxAccess,
            AdapterKind::PinMutRef => SemanticRuleKind::StdPinMutRefAccess,
        }
    }

    fn access(self) -> AccessKind {
        match self {
            AdapterKind::Box | AdapterKind::PinBox => AccessKind::Owned,
            AdapterKind::MutRef | AdapterKind::PinMutRef => AccessKind::Borrowed,
        }
    }
}

/// A wide pointer to a trait object, by bundle id: the struct, its two
/// members and their types, the trait object, whether that object is a
/// bare `dyn Future`, and the verdict on the vtable ABI the struct's
/// defining units were compiled under.
#[derive(Clone, Debug)]
struct DynSeed {
    wide: BundleTypeId,
    pointer: String,
    vtable: String,
    data_ptr: BundleTypeId,
    vtable_ptr: BundleTypeId,
    trait_ty: BundleTypeId,
    future_trait: bool,
    abi: CompilerVerdict,
}

#[derive(Clone, Debug)]
enum PointeeSeed {
    Sized(BundleTypeId),
    Dyn(DynSeed),
}

/// A std adapter as the raw screen saw it, carried by bundle id: the
/// kind, the `Pin` member and its `Ptr` where there is one, what it
/// points at, and the verdict on the adapter convention.
#[derive(Clone, Debug)]
struct AdapterSeed {
    kind: AdapterKind,
    pin: Option<(String, BundleTypeId)>,
    pointee: PointeeSeed,
    compiler: CompilerVerdict,
}

#[derive(Clone, Debug)]
struct InstrumentedSeed {
    inner: String,
    future: BundleTypeId,
}

/// A reviewed third-party wrapper as its screen saw it, by bundle id.
/// The layout is the screen's. Which crate owns it is the kind's, and
/// so is what proves the rule: a sole-member forwarder binds on the
/// layout alone, and every other seed on the origin its poll or method
/// declarations name.
#[derive(Clone, Debug)]
enum LibrarySeed {
    /// futures-util's `map::Map` enum: the incomplete variant and the
    /// member inside it, the complete variant, and the mapped future.
    Map {
        incomplete: String,
        future_member: String,
        complete: String,
        future: BundleTypeId,
    },
    /// The public `Map` newtype the `delegate_all!` macro builds.
    MapWrapper(String, BundleTypeId),
    /// `MapErr`, another such newtype.
    MapErr(String, BundleTypeId),
    /// `IntoFuture`.
    IntoFuture(String, BundleTypeId),
    /// hyper-util's `TokioSleep` over `tokio::time::Sleep`.
    TokioSleep(String, BundleTypeId),
    /// tokio's `Coop<F>` over the `F` it budgets.
    Coop(String, BundleTypeId),
    /// futures-util's `Next<'_, St>`: the `&mut St` member and the
    /// stream it targets — a stream, which the route names without
    /// proving it a future.
    Next(String, BundleTypeId),
    /// tokio-stream's `WatchStream<T>` over the `ReusableBoxFuture` it
    /// owns: a storage route, not a future.
    WatchStream(String, BundleTypeId),
    /// tokio-util's `ReusableBoxFuture<'_, T>` over its pinned box: a
    /// storage route to the trait object inside.
    ReusableBox {
        boxed: String,
        pin: (String, BundleTypeId),
        dyn_: DynSeed,
    },
}

impl LibrarySeed {
    fn rule_kind(&self) -> SemanticRuleKind {
        match self {
            LibrarySeed::Map { .. } | LibrarySeed::MapWrapper(..) => {
                SemanticRuleKind::FuturesUtilMap
            }
            LibrarySeed::MapErr(..) => SemanticRuleKind::FuturesUtilMapErr,
            LibrarySeed::IntoFuture(..) => SemanticRuleKind::FuturesUtilIntoFuture,
            LibrarySeed::TokioSleep(..) => SemanticRuleKind::HyperUtilTokioSleep,
            LibrarySeed::Coop(..) => SemanticRuleKind::TokioCoop,
            LibrarySeed::Next(..) => SemanticRuleKind::FuturesUtilNext,
            LibrarySeed::WatchStream(..) => SemanticRuleKind::TokioStreamWatchStream,
            LibrarySeed::ReusableBox { .. } => SemanticRuleKind::TokioUtilReusableBox,
        }
    }

    /// The crate whose reviewed implementation the rule runs, and the
    /// convention its version has to fall inside. Not asked of a seed
    /// that binds on its layout.
    fn convention(&self) -> &'static LibraryConvention {
        match self {
            LibrarySeed::TokioSleep(..) => &HYPER_UTIL_TOKIO_SLEEP_V0_1_10,
            LibrarySeed::WatchStream(..) => &TOKIO_STREAM_WATCH_V0_1_14,
            LibrarySeed::ReusableBox { .. } => &TOKIO_UTIL_REUSABLE_BOX_V0_7_11,
            _ => &FUTURES_UTIL_ADAPTERS_V0_3_30,
        }
    }

    /// Whether the rule's origin is the type's own method declarations
    /// rather than a `poll`'s: the two storage routes are no futures
    /// and have no poll to be declared anywhere.
    fn origin_is_the_type(&self) -> bool {
        matches!(
            self,
            LibrarySeed::WatchStream(..) | LibrarySeed::ReusableBox { .. }
        )
    }

    /// Whether the layout the screen proved is the whole of the rule's
    /// evidence. A wrapper whose one member is the future its own
    /// template parameter names can poll that member or nothing: there
    /// is nothing else in it to wait on, so the delegation is read off
    /// the layout and needs no declaration to say which implementation
    /// forwards it. That matters because a `poll` the optimizer folded
    /// into an identical instantiation's leaves no declaration at all,
    /// and a rule whose evidence came and went with the fold would bind
    /// or decline by build. The map's state machine, the `select!`
    /// mask and the box's refill keep the origin proof: their behavior
    /// is read from the source, not the layout. hyper-util's sleep is
    /// the same shape as these but keeps the proof too, for want of a
    /// hyper-util layout origin to file it under.
    fn origin_is_the_layout(&self) -> bool {
        matches!(
            self,
            LibrarySeed::Coop(..)
                | LibrarySeed::MapWrapper(..)
                | LibrarySeed::MapErr(..)
                | LibrarySeed::IntoFuture(..)
        )
    }
}

/// A `select!`'s `PollFn` as its screen saw it, by bundle id: the
/// closure and its two captures, what each points at, the tuple's
/// members in branch order, and where the closure environment was
/// declared — the origin the rule is read off.
#[derive(Clone, Debug)]
struct SelectSeed {
    closure: String,
    mask: String,
    mask_word: BundleTypeId,
    futures: String,
    tuple: BundleTypeId,
    branches: Vec<(String, BundleTypeId)>,
    source: Option<PollSource>,
}

#[derive(Default)]
pub(super) struct Seed {
    polls: BTreeSet<String>,
    poll_sources: BTreeSet<PollSource>,
    coroutine_candidate: bool,
    compiler: Option<CompilerVerdict>,
    resource: Option<ResourceKind>,
    container: Option<ContainerKind>,
    adapter: Option<AdapterSeed>,
    instrumented: Option<InstrumentedSeed>,
    library: Option<LibrarySeed>,
    select: Option<SelectSeed>,
    /// Where the type's own methods were declared, for a library rule
    /// whose origin is the type rather than a `poll` (a `WatchStream`
    /// has none, nor does the `StreamMap` container); empty otherwise.
    type_sources: BTreeSet<PollSource>,
}

impl Seed {
    /// Whether the seed alone puts a record in the table: identity,
    /// storage or a library binding, as opposed to an adapter or
    /// wrapper screen that only matters once something proves the type
    /// a future or its pointee interesting.
    fn is_own_record(&self) -> bool {
        !self.polls.is_empty()
            || self.coroutine_candidate
            || self.resource.is_some()
            || self.container.is_some()
            || self.select.is_some()
    }
}

pub(super) type SemanticSeeds = BTreeMap<BundleTypeId, Seed>;

/// What the library bindings dispatch on: the bound walk contract, and
/// the tokio version and family every versioned row answered from.
pub(super) struct Library<'a> {
    pub(super) walks: &'a WalksTable,
    pub(super) tokio_version: Option<&'a semver::Version>,
    pub(super) family: Family,
}

/// A wide pointer as the binder carries it, by bundle id, with the
/// verdict on the vtable ABI its defining units were compiled under.
fn dyn_seed(
    w: WidePointer,
    verdict: &mut impl FnMut(TypeId, Reviewed) -> CompilerVerdict,
    bundle_id: &impl Fn(TypeId) -> Option<BundleTypeId>,
) -> Option<DynSeed> {
    Some(DynSeed {
        abi: verdict(w.wide, Reviewed::DynFutureAbi),
        future_trait: w.future_trait,
        wide: bundle_id(w.wide)?,
        pointer: w.pointer,
        vtable: w.vtable,
        data_ptr: bundle_id(w.data_ptr)?,
        vtable_ptr: bundle_id(w.vtable_ptr)?,
        trait_ty: bundle_id(w.trait_ty)?,
    })
}

/// The reviewed third-party wrapper `raw` is, if it is one. The name
/// picks the screen — a definition path is where a crate's own type
/// lives — and the screen decides, over the type's own declaration.
/// `dyn_seed` carries a wide pointer a screen found to the binder,
/// with its ABI verdict.
fn library_seed(
    reader: &crate::DwReader<'_>,
    raw: TypeId,
    name: &str,
    bundle_id: impl Fn(TypeId) -> Option<BundleTypeId>,
    mut dyn_seed: impl FnMut(WidePointer) -> Option<DynSeed>,
) -> Option<LibrarySeed> {
    let forward = |layout: Option<adapters::ForwardLayout>| {
        let layout = layout?;
        Some((layout.member, bundle_id(layout.inner)?))
    };
    if name.starts_with("futures_util::future::future::map::Map<") {
        let layout = adapters::futures_util_map(reader, raw)?;
        Some(LibrarySeed::Map {
            incomplete: layout.incomplete,
            future_member: layout.future_member,
            complete: layout.complete,
            future: bundle_id(layout.future)?,
        })
    } else if name.starts_with("futures_util::future::future::Map<") {
        let (member, inner) = forward(adapters::futures_util_map_wrapper(reader, raw))?;
        Some(LibrarySeed::MapWrapper(member, inner))
    } else if name.starts_with("futures_util::future::try_future::MapErr<") {
        let (member, inner) = forward(adapters::futures_util_map_err(reader, raw))?;
        Some(LibrarySeed::MapErr(member, inner))
    } else if name.starts_with("futures_util::future::try_future::into_future::IntoFuture<") {
        let (member, inner) = forward(adapters::futures_util_into_future(reader, raw))?;
        Some(LibrarySeed::IntoFuture(member, inner))
    } else if name == "hyper_util::rt::tokio::TokioSleep" {
        let (member, inner) = forward(adapters::hyper_util_tokio_sleep(reader, raw))?;
        Some(LibrarySeed::TokioSleep(member, inner))
    } else if name.starts_with("tokio::task::coop::Coop<") {
        let (member, inner) = forward(adapters::tokio_coop(reader, raw))?;
        Some(LibrarySeed::Coop(member, inner))
    } else if name.starts_with("futures_util::stream::stream::next::Next<") {
        let layout = adapters::futures_util_next(reader, raw)?;
        Some(LibrarySeed::Next(layout.stream, bundle_id(layout.target)?))
    } else if name.starts_with("tokio_stream::wrappers::watch::WatchStream<") {
        let (member, inner) = forward(adapters::tokio_stream_watch_stream(reader, raw))?;
        Some(LibrarySeed::WatchStream(member, inner))
    } else if name.starts_with("tokio_util::sync::reusable_box::ReusableBoxFuture<") {
        let layout = adapters::tokio_util_reusable_box(reader, raw)?;
        Some(LibrarySeed::ReusableBox {
            boxed: layout.boxed,
            pin: (layout.pin.0, bundle_id(layout.pin.1)?),
            dyn_: dyn_seed(layout.wide)?,
        })
    } else {
        None
    }
}

pub(super) fn collect_semantic_seeds(
    em: &Emitter<'_>,
    polls: &BTreeMap<TypeId, BTreeSet<String>>,
    poll_sources: &BTreeMap<TypeId, BTreeSet<PollSource>>,
    coroutines: &BTreeSet<TypeId>,
    mut verdict: impl FnMut(TypeId, Reviewed) -> CompilerVerdict,
    env_source: impl Fn(TypeId) -> Option<PollSource>,
    type_sources: impl Fn(TypeId) -> BTreeSet<PollSource>,
) -> SemanticSeeds {
    let mut seeds = SemanticSeeds::new();
    let reader = em.reader;
    let bundle_id = |raw: TypeId| em.bundle_id_of(raw);
    for (raw, name) in em.emitted_named() {
        let Some(ty) = bundle_id(raw) else {
            continue;
        };
        let canonical = reader
            .canonical_type(raw)
            .and_then(|t| t.name())
            .map(|n| reader.strings.get(n))
            .unwrap_or_default();
        let candidate =
            coroutines.contains(&raw) || crate::bundle::names::is_coroutine_candidate(canonical);
        if candidate {
            let seed = seeds.entry(ty).or_default();
            seed.coroutine_candidate = true;
            seed.compiler = Some(verdict(raw, Reviewed::Coroutine));
        }
        // The adapter and wrapper screens run on the shapes their names
        // announce; the screen decides, the name only saves the walk.
        if name.starts_with("core::pin::Pin<")
            || name.starts_with("alloc::boxed::Box<")
            || name.starts_with("&mut ")
        {
            if let Some(adapter) = adapters::std_adapter(reader, raw) {
                let compiler = verdict(raw, Reviewed::StdAdapters);
                let mut pointee = |pointee: Pointee| -> Option<PointeeSeed> {
                    Some(match pointee {
                        Pointee::Sized(f) => PointeeSeed::Sized(bundle_id(f)?),
                        Pointee::Dyn(w) => PointeeSeed::Dyn(dyn_seed(w, &mut verdict, &bundle_id)?),
                    })
                };
                let seed = match adapter {
                    StdAdapter::Box(p) => pointee(p).map(|pointee| AdapterSeed {
                        kind: AdapterKind::Box,
                        pin: None,
                        pointee,
                        compiler,
                    }),
                    StdAdapter::MutRef(p) => pointee(p).map(|pointee| AdapterSeed {
                        kind: AdapterKind::MutRef,
                        pin: None,
                        pointee,
                        compiler,
                    }),
                    StdAdapter::PinBox {
                        member,
                        boxed,
                        pointee: p,
                    } => pointee(p)
                        .zip(bundle_id(boxed))
                        .map(|(pointee, boxed)| AdapterSeed {
                            kind: AdapterKind::PinBox,
                            pin: Some((member, boxed)),
                            pointee,
                            compiler,
                        }),
                    StdAdapter::PinMutRef {
                        member,
                        reference,
                        pointee: p,
                    } => pointee(p)
                        .zip(bundle_id(reference))
                        .map(|(pointee, reference)| AdapterSeed {
                            kind: AdapterKind::PinMutRef,
                            pin: Some((member, reference)),
                            pointee,
                            compiler,
                        }),
                };
                if let Some(seed) = seed {
                    seeds.entry(ty).or_default().adapter = Some(seed);
                }
            }
        } else if name.starts_with("tracing::instrument::Instrumented<")
            && let Some(InstrumentedLayout { inner, future }) = adapters::instrumented(reader, raw)
            && let Some(future) = bundle_id(future)
        {
            seeds.entry(ty).or_default().instrumented = Some(InstrumentedSeed { inner, future });
        } else if name.starts_with("core::future::poll_fn::PollFn<")
            && let Some(layout) = adapters::tokio_select(reader, raw)
            && let Some(seed) = select_seed(layout, bundle_id, &env_source)
        {
            seeds.entry(ty).or_default().select = Some(seed);
        } else if let Some(library) = library_seed(reader, raw, name, bundle_id, |w| {
            dyn_seed(w, &mut verdict, &bundle_id)
        }) {
            let seed = seeds.entry(ty).or_default();
            if library.origin_is_the_type() {
                seed.type_sources = type_sources(raw);
            }
            seed.library = Some(library);
        } else if name.starts_with(STREAM_MAP) {
            // The map's layout is the walk contract's to bind, by the
            // roles rooted at its name; its origin is the type's own
            // method declarations, gathered here where the DWARF is
            // still open and read when the container binds.
            seeds.entry(ty).or_default().type_sources = type_sources(raw);
        }
    }
    for (raw, symbols) in polls {
        // Poll roots have already been emitted through the dynamic table.
        if let Some(ty) = bundle_id(*raw) {
            let seed = seeds.entry(ty).or_default();
            seed.polls.extend(symbols.iter().cloned());
            if let Some(sources) = poll_sources.get(raw) {
                seed.poll_sources.extend(sources.iter().cloned());
            }
        }
    }
    seeds
}

/// The screen's `select!` layout by bundle id, with the closure
/// environment's declaration site. `None` when any type it names was
/// not emitted: a branch future the table does not carry cannot be a
/// recorded route.
fn select_seed(
    layout: SelectLayout,
    bundle_id: impl Fn(TypeId) -> Option<BundleTypeId>,
    env_source: &impl Fn(TypeId) -> Option<PollSource>,
) -> Option<SelectSeed> {
    let branches = layout
        .branches
        .iter()
        .map(|(member, future)| Some((member.clone(), bundle_id(*future)?)))
        .collect::<Option<Vec<_>>>()?;
    Some(SelectSeed {
        closure: layout.closure,
        mask: layout.mask,
        mask_word: bundle_id(layout.mask_word)?,
        futures: layout.futures,
        tuple: bundle_id(layout.tuple)?,
        branches,
        source: env_source(layout.env),
    })
}

/// The every-kind order the bindings are attempted in, which is also the
/// order their rules are numbered: a bundle's rule ids depend on which
/// kinds bound, never on the order types were met.
const RESOURCE_KINDS: [(ResourceKind, SemanticRuleKind); 9] = [
    (ResourceKind::Sleep, SemanticRuleKind::TokioSleep),
    (ResourceKind::JoinHandle, SemanticRuleKind::TokioJoinHandle),
    (
        ResourceKind::SemaphoreAcquire,
        SemanticRuleKind::TokioAcquire,
    ),
    (
        ResourceKind::IoOperation(IoOperationKind::Read),
        SemanticRuleKind::TokioIoOperation,
    ),
    (
        ResourceKind::IoOperation(IoOperationKind::WriteAll),
        SemanticRuleKind::TokioIoOperation,
    ),
    (
        ResourceKind::IoOperation(IoOperationKind::Readiness),
        SemanticRuleKind::TokioIoOperation,
    ),
    (ResourceKind::MpscRecv, SemanticRuleKind::TokioMpscRecv),
    (ResourceKind::Notified, SemanticRuleKind::TokioNotified),
    (
        ResourceKind::OneshotRecv,
        SemanticRuleKind::TokioOneshotRecv,
    ),
];

const CONTAINER_KINDS: [(ContainerKind, SemanticRuleKind); 3] = [
    (ContainerKind::JoinSet, SemanticRuleKind::TokioJoinSet),
    (
        ContainerKind::FuturesUnordered,
        SemanticRuleKind::FuturesUnordered,
    ),
    (
        ContainerKind::StreamMap,
        SemanticRuleKind::TokioStreamStreamMap,
    ),
];

/// The by-value type every tokio-stream `StreamMap` is recognized as:
/// the walk contract's leaf key, whose roles bound at a type are what
/// seed the container.
const STREAM_MAP: &str = "tokio_stream::stream_map::StreamMap<";

/// The rule a container binds under. The two tokio and futures-util
/// sets bind under the bundle's one layout origin for their library;
/// the map is a third-party type whose layout the contract binds by
/// name alone, so its rule is read off the type's own method
/// declarations like a stream route's, and declines the same ways.
fn container_rule(kind: ContainerKind, seed: &Seed) -> Result<RuleKey, Decline> {
    let rule_kind = CONTAINER_KINDS
        .iter()
        .find(|(k, _)| *k == kind)
        .map(|(_, rule)| *rule)
        .expect("every container kind has a rule");
    match kind {
        ContainerKind::JoinSet | ContainerKind::FuturesUnordered => Ok(RuleKey::Library(rule_kind)),
        ContainerKind::StreamMap => {
            let origin =
                delegation_origin(&seed.type_sources, &TOKIO_STREAM_MAP_V0_1_14, "method")?;
            Ok(RuleKey::Delegation {
                kind: rule_kind,
                origin,
            })
        }
    }
}

const SCHEDULER_CLASSES: [(SchedulerClass, SemanticRuleKind); 4] = [
    (
        SchedulerClass::MultiThread,
        SemanticRuleKind::TokioMultiThreadScheduler,
    ),
    (
        SchedulerClass::CurrentThread,
        SemanticRuleKind::TokioCurrentThreadScheduler,
    ),
    (
        SchedulerClass::LocalSet,
        SemanticRuleKind::TokioLocalScheduler,
    ),
    (
        SchedulerClass::Blocking,
        SemanticRuleKind::TokioBlockingScheduler,
    ),
];

/// The types every one of `roles` bound at, provided every chained
/// `route` below them bound too: a binding's roots are the set its
/// spelling resolved against, so a role broken for any root is broken
/// for all, and the intersection is the roots the whole route holds for.
fn bound_roots(
    walks: &WalksTable,
    roles: &[WalkRole],
    routes: &[WalkRole],
) -> BTreeSet<BundleTypeId> {
    let bound = |role: &WalkRole| {
        walks
            .entries
            .get(role)
            .is_some_and(|binding| matches!(binding.outcome, WalkOutcome::Bound { .. }))
    };
    if !routes.iter().all(bound) {
        return BTreeSet::new();
    }
    let mut roots: Option<BTreeSet<BundleTypeId>> = None;
    for role in roles {
        let bound: BTreeSet<BundleTypeId> = match walks.entries.get(role) {
            Some(binding) if matches!(binding.outcome, WalkOutcome::Bound { .. }) => {
                binding.roots.iter().copied().collect()
            }
            _ => BTreeSet::new(),
        };
        roots = Some(match roots {
            Some(roots) => &roots & &bound,
            None => bound,
        });
    }
    roots.unwrap_or_default()
}

/// A third-party delegation origin as the binder established it: the
/// crate and version the declaration path spells, the family that
/// version selected, the anchored path, and whatever checksums the file
/// tables carried for the implementing file.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Debug)]
struct DelegationOrigin {
    package: &'static str,
    version: String,
    family: &'static str,
    source: String,
    files: Vec<(String, [u8; 16])>,
}

/// A rule as a plan names it, before ids exist: enough to intern the
/// origin and the rule once each, in the order the records are emitted.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Debug)]
enum RuleKey {
    /// A tokio or futures-util layout rule under the bundle's one
    /// origin for that library.
    Library(SemanticRuleKind),
    /// A compiler rule under the origin of one producer and one
    /// reviewed family: two producers inside one range are two origins,
    /// and two families over one producer are two as well.
    Rustc {
        kind: SemanticRuleKind,
        producer: String,
        family: &'static str,
    },
    Delegation {
        kind: SemanticRuleKind,
        origin: DelegationOrigin,
    },
}

/// The origins and rules a bundle applied, interned on first use in
/// record order.
struct Rules {
    origins: Vec<SemanticOrigin>,
    rules: Vec<SemanticRule>,
    by_key: BTreeMap<RuleKey, SemanticRuleId>,
    tokio: Option<SemanticOriginId>,
    futures_util: Option<SemanticOriginId>,
    rustc: BTreeMap<(String, &'static str), SemanticOriginId>,
    delegation: BTreeMap<DelegationOrigin, SemanticOriginId>,
}

impl Rules {
    fn new() -> Self {
        Rules {
            origins: Vec::new(),
            rules: Vec::new(),
            by_key: BTreeMap::new(),
            tokio: None,
            futures_util: None,
            rustc: BTreeMap::new(),
            delegation: BTreeMap::new(),
        }
    }

    fn push_origin(&mut self, origin: SemanticOrigin) -> SemanticOriginId {
        let id = SemanticOriginId(u32::try_from(self.origins.len()).expect("origin overflow"));
        self.origins.push(origin);
        id
    }

    fn library_origin(
        &mut self,
        kind: SemanticRuleKind,
        strings: &mut StringInterner,
        library: &Library<'_>,
    ) -> SemanticOriginId {
        let futures_util = matches!(
            kind,
            SemanticRuleKind::FuturesUnordered
                | SemanticRuleKind::FuturesUtilMap
                | SemanticRuleKind::FuturesUtilMapErr
                | SemanticRuleKind::FuturesUtilIntoFuture
        );
        let (slot, origin) = if futures_util {
            // The set walker's layout has held across every futures-util
            // release the fixtures cover, and no version is recovered for
            // it: its rows are unversioned, and the origin says so. The
            // sole-member forwarders bound on their layout are filed
            // under the same origin, being read off nothing else.
            let origin = SemanticOrigin::LibraryLayout {
                package: strings.intern("futures-util"),
                version: None,
                family: strings.intern("unversioned"),
                selection: LayoutSelection::VersionUnknown,
            };
            (&mut self.futures_util, origin)
        } else {
            let origin = SemanticOrigin::LibraryLayout {
                package: strings.intern("tokio"),
                version: library
                    .tokio_version
                    .map(|version| strings.intern(&version.to_string())),
                family: strings.intern(library.family.name()),
                selection: Family::layout_selection(library.tokio_version),
            };
            (&mut self.tokio, origin)
        };
        if let Some(id) = *slot {
            return id;
        }
        let id = SemanticOriginId(u32::try_from(self.origins.len()).expect("origin overflow"));
        self.origins.push(origin);
        *slot = Some(id);
        id
    }

    /// The rule a key names, interned on first use with its origin.
    fn rule(
        &mut self,
        key: &RuleKey,
        strings: &mut StringInterner,
        library: &Library<'_>,
    ) -> SemanticRuleId {
        if let Some(id) = self.by_key.get(key) {
            return *id;
        }
        let (kind, origin) = match key {
            RuleKey::Library(kind) => (*kind, self.library_origin(*kind, strings, library)),
            RuleKey::Rustc {
                kind,
                producer,
                family,
            } => {
                let origin = match self.rustc.get(&(producer.clone(), *family)) {
                    Some(id) => *id,
                    None => {
                        let id = self.push_origin(SemanticOrigin::Rustc {
                            producer: strings.intern(producer),
                            family: strings.intern(family),
                        });
                        self.rustc.insert((producer.clone(), family), id);
                        id
                    }
                };
                (*kind, origin)
            }
            RuleKey::Delegation { kind, origin } => {
                let id = match self.delegation.get(origin) {
                    Some(id) => *id,
                    None => {
                        let id = self.push_origin(SemanticOrigin::LibraryDelegation {
                            package: strings.intern(origin.package),
                            version: strings.intern(&origin.version),
                            family: strings.intern(origin.family),
                            source: strings.intern(&origin.source),
                            files: origin
                                .files
                                .iter()
                                .map(|(file, md5)| SourceFileEvidence {
                                    file: strings.intern(file),
                                    md5: *md5,
                                })
                                .collect(),
                        });
                        self.delegation.insert(origin.clone(), id);
                        id
                    }
                };
                (*kind, id)
            }
        };
        let id = SemanticRuleId(u32::try_from(self.rules.len()).expect("rule overflow"));
        self.rules.push(SemanticRule {
            kind,
            revision: 1,
            origin,
        });
        self.by_key.insert(key.clone(), id);
        id
    }
}

/// Where a planned delegation lands, before the dyn ABI rule has an id.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Target {
    Value(TypedPath),
    Dynamic {
        pointer: TypedPath,
        data: TypedPath,
        vtable: TypedPath,
        trait_ty: BundleTypeId,
        /// Whether the reviewed ABI settles where the poll sits, which
        /// it does for a bare `dyn Future` and no other trait.
        future_trait: bool,
        abi: RuleKey,
    },
}

impl Target {
    /// The static type a delegation proves a future, if it names one.
    fn static_child(&self) -> Option<BundleTypeId> {
        match self {
            Target::Value(path) => Some(path.target),
            Target::Dynamic { .. } => None,
        }
    }

    fn into_future_target(
        self,
        rules: &mut Rules,
        strings: &mut StringInterner,
        library: &Library<'_>,
    ) -> FutureTarget {
        match self {
            Target::Value(path) => FutureTarget::Value(path),
            Target::Dynamic {
                pointer,
                data,
                vtable,
                trait_ty,
                future_trait,
                abi,
            } => FutureTarget::Dynamic {
                pointer,
                layout: DynFutureLayout {
                    abi: rules.rule(&abi, strings, library),
                    data,
                    vtable,
                    trait_ty,
                    drop_slot: 0,
                    size_slot: 1,
                    align_slot: 2,
                    poll_slot: future_trait.then_some(3),
                },
            },
        }
    }
}

/// One coroutine state's planned action.
#[derive(Clone, Debug)]
enum CaseAction {
    Unresumed,
    Returned,
    Panicked,
    Delegate(Box<Target>),
    Unknown(SemanticIssue),
}

/// A program as planned: its rule, and either one action or a case per
/// coroutine state. Every path in it has been held to the validator's
/// rule over the final table already.
#[derive(Clone, Debug)]
struct Plan {
    rule: RuleKey,
    /// The poll program, for a type that is a future. A storage route
    /// that is polled through and never polled itself — a stream over
    /// the box it owns — plans none, and has only its access.
    program: Option<Delegation>,
    /// The storage access the same route establishes, for an adapter.
    access: Option<(RuleKey, AccessKind, Target)>,
    /// Whether the program's delegate is thereby a future: a poll
    /// forwarded to a poll proves it, a poll that runs the delegate's
    /// `poll_next` names a stream and proves nothing.
    delegate_is_future: bool,
}

/// A `select!` binding as planned: its rule, and the three routes held
/// to the final table.
#[derive(Clone, Debug)]
struct SelectPlan {
    rule: RuleKey,
    mask: TypedPath,
    futures: TypedPath,
    branches: Vec<TypedPath>,
}

#[derive(Clone, Debug)]
enum Delegation {
    Direct {
        target: Target,
        exclusive: bool,
    },
    /// One action per state of an enum the reviewed implementation
    /// matches on: a compiler coroutine's states, or futures-util's
    /// two-state `Map`.
    Match {
        cases: Vec<(StrRef, CaseAction)>,
    },
}

impl Plan {
    fn static_children(&self) -> Vec<BundleTypeId> {
        if !self.delegate_is_future {
            return Vec::new();
        }
        match &self.program {
            None => Vec::new(),
            Some(Delegation::Direct { target, .. }) => target.static_child().into_iter().collect(),
            Some(Delegation::Match { cases }) => cases
                .iter()
                .filter_map(|(_, action)| match action {
                    CaseAction::Delegate(target) => target.static_child(),
                    _ => None,
                })
                .collect(),
        }
    }
}

type Decline = (SemanticIssueKind, String);

/// A record in the making: everything decided about one type before the
/// rules are numbered.
#[derive(Default)]
struct Draft {
    storage: Option<StoragePolicy>,
    coroutine: Option<CoroutineLayout>,
    coroutine_rule: Option<RuleKey>,
    issues: Vec<Decline>,
    evidence: BTreeSet<FutureEvidence>,
    resource: Option<ResourceKind>,
    /// The container the type is bound as, with the rule it binds
    /// under — decided with the seed in hand, since the map's rule is
    /// an origin read off the seed's sources.
    container: Option<(ContainerKind, RuleKey)>,
    plan: Option<Plan>,
    /// Why no program was planned, when a reviewed shape was screened
    /// and declined: the continuation's reason, over the bare `NoRule`.
    decline: Option<Decline>,
    /// The type an adapter's storage leads to, for deciding whether an
    /// adapter with no future evidence still earns a record.
    pointee: Option<BundleTypeId>,
    /// The `select!` branches this `PollFn` polls, where it is one.
    select: Option<SelectPlan>,
    own_record: bool,
}

impl Draft {
    /// Whether the type is positively a future: something proved it
    /// one, or its storage is a bound coroutine's — which is proof in
    /// itself, ahead of the rule number that spells it as evidence.
    fn is_future(&self) -> bool {
        !self.evidence.is_empty() || self.coroutine.is_some()
    }
}

/// Run after type demotion and coroutine member pruning, while strings can
/// still be interned. Identity survives an opaque executable layout; the
/// library bindings attach to the exact types the walk contract bound
/// its routes at, and a task entry's scheduler class to the entry whose
/// `S` the class's route bound at.
pub(super) fn bind_semantics(
    mut seeds: SemanticSeeds,
    types: &TypeTable,
    names: &[Option<String>],
    strings: &mut StringInterner,
    tasks: &mut [TaskFutureEntry],
    library: &Library<'_>,
) -> SemanticTable {
    let mut rules = Rules::new();
    let mut drafts: BTreeMap<BundleTypeId, Draft> = BTreeMap::new();
    for (i, task) in tasks.iter().enumerate() {
        seeds.entry(task.future).or_default();
        drafts
            .entry(task.future)
            .or_default()
            .evidence
            .insert(FutureEvidence::TaskEntry(TaskEntryId(
                u32::try_from(i).expect("task table overflow"),
            )));
    }
    for (kind, _) in RESOURCE_KINDS {
        for ty in bound_roots(
            library.walks,
            required_resource_roles(kind),
            required_resource_routes(kind),
        ) {
            seeds.entry(ty).or_default().resource = Some(kind);
        }
    }
    for (kind, _) in CONTAINER_KINDS {
        for ty in bound_roots(library.walks, container_roles(kind), container_routes(kind)) {
            seeds.entry(ty).or_default().container = Some(kind);
        }
    }

    // Phase A: decide storage, layout and the candidate program of every
    // seed, without numbering anything.
    for (&ty, seed) in &seeds {
        let draft = drafts.entry(ty).or_default();
        draft.own_record = seed.is_own_record() || !draft.evidence.is_empty();
        for symbol in &seed.polls {
            draft
                .evidence
                .insert(FutureEvidence::PollSymbol(strings.intern(symbol)));
        }
        let storage = if seed.coroutine_candidate {
            // A compiler candidate reads its states only under a reviewed
            // convention that its every defining unit supports and whose
            // shape this enum then actually has; anything less leaves the
            // storage unavailable, with the reason beside it.
            match bind_coroutine(ty, seed, types, names, strings) {
                Ok((rule, layout)) => {
                    draft.plan = Some(coroutine_plan(ty, &rule, &layout, types, strings));
                    draft.coroutine = Some(layout);
                    draft.coroutine_rule = Some(rule);
                    StoragePolicy::CoroutineStates
                }
                Err(decline) => {
                    draft.issues.push(decline.clone());
                    StoragePolicy::Unavailable(SemanticIssue {
                        kind: decline.0,
                        detail: Some(strings.intern(&decline.1)),
                    })
                }
            }
        } else if matches!(types.get(ty), Some(TypeDef::Opaque { .. })) {
            StoragePolicy::Unavailable(SemanticIssue {
                kind: SemanticIssueKind::MissingLayout,
                detail: None,
            })
        } else {
            StoragePolicy::DeclaredMembers
        };
        // A capability needs readable storage; a route cannot have bound
        // at a type without it, so this only guards the record's shape.
        let readable = matches!(storage, StoragePolicy::DeclaredMembers);
        draft.resource = seed.resource.filter(|_| readable);
        // A container whose rule declines — the map declared off the
        // registry, or at an unreviewed version — keeps its record and
        // says why, and is walked by no contract.
        draft.container =
            seed.container
                .filter(|_| readable)
                .and_then(|kind| match container_rule(kind, seed) {
                    Ok(rule) => Some((kind, rule)),
                    Err(decline) => {
                        draft.issues.push(decline);
                        None
                    }
                });
        if readable && draft.plan.is_none() {
            if let Some(adapter) = &seed.adapter {
                match plan_adapter(ty, adapter, types, strings) {
                    Ok(plan) => {
                        draft.pointee = adapter_pointee(adapter);
                        draft.plan = Some(plan);
                    }
                    Err(decline) => draft.decline = Some(decline),
                }
            } else if let Some(instrumented) = &seed.instrumented {
                match plan_instrumented(ty, instrumented, seed, types, names, strings) {
                    Ok(plan) => draft.plan = Some(plan),
                    Err(decline) => draft.decline = Some(decline),
                }
            } else if let Some(library) = &seed.library {
                // A route that is polled through and never polled — a
                // stream over the box it owns — is a record on the
                // strength of its screen alone: nothing will ever prove
                // it a future, and a declined origin has nowhere else
                // to be recorded.
                draft.own_record |= library.origin_is_the_type();
                match plan_library(ty, library, seed, types, strings) {
                    Ok(plan) => draft.plan = Some(plan),
                    Err(decline) => draft.decline = Some(decline),
                }
            }
        }
        // The select binding is a fact beside the continuation, not a
        // program: the `PollFn` still polls nothing any rule follows.
        if readable && let Some(select) = &seed.select {
            match plan_select(ty, select, types, strings) {
                Ok(plan) => draft.select = Some(plan),
                Err(decline) => draft.issues.push(decline),
            }
        }
        draft.storage = Some(storage);
    }

    // Phase B: the least fixed point over the bound delegations. A type
    // that is positively a future and has a planned program proves each
    // static delegate a future; a delegate so proved runs its own plan,
    // if it has one. An adapter with no evidence proves nothing. A
    // bound coroutine is a future by its storage alone — its own
    // evidence is numbered only at emit time, so the seed asks the
    // draft, not the evidence set.
    let mut queue: VecDeque<BundleTypeId> = drafts
        .iter()
        .filter(|(_, d)| d.is_future() && d.plan.is_some())
        .map(|(&ty, _)| ty)
        .collect();
    while let Some(parent) = queue.pop_front() {
        let children = drafts[&parent]
            .plan
            .as_ref()
            .map(Plan::static_children)
            .unwrap_or_default();
        for child in children {
            let draft = drafts.entry(child).or_default();
            let was_future = draft.is_future();
            draft
                .evidence
                .insert(FutureEvidence::DelegatedBy { parent });
            if !was_future && draft.plan.is_some() {
                queue.push_back(child);
            }
        }
    }

    // Phase C: which drafts become records. A seed with identity,
    // storage or a library binding always does; a future does; an
    // adapter whose storage leads to a record does, so that discovery
    // can follow the owned route to it.
    let mut included: BTreeSet<BundleTypeId> = drafts
        .iter()
        .filter(|(_, d)| d.own_record || !d.evidence.is_empty())
        .map(|(&ty, _)| ty)
        .collect();
    loop {
        let more: Vec<BundleTypeId> = drafts
            .iter()
            .filter(|(ty, d)| {
                !included.contains(ty)
                    && d.plan.as_ref().is_some_and(|p| p.access.is_some())
                    && d.pointee.is_some_and(|p| included.contains(&p))
            })
            .map(|(&ty, _)| ty)
            .collect();
        if more.is_empty() {
            break;
        }
        included.extend(more);
    }

    // Phase D: number the rules in record order and emit.
    let issue = |kind| SemanticIssue { kind, detail: None };
    let mut records = Vec::with_capacity(included.len());
    for ty in included {
        let draft = drafts.remove(&ty).expect("included drafts exist");
        let storage = draft.storage.unwrap_or_else(|| {
            // A type that entered through a delegation alone: its storage
            // is whatever its layout says, like any other seed.
            if matches!(types.get(ty), Some(TypeDef::Opaque { .. })) {
                StoragePolicy::Unavailable(issue(SemanticIssueKind::MissingLayout))
            } else if names
                .get(ty.0 as usize)
                .and_then(|n| n.as_deref())
                .is_some_and(crate::bundle::names::is_coroutine_candidate)
            {
                StoragePolicy::Unavailable(SemanticIssue {
                    kind: SemanticIssueKind::UnsupportedOrigin,
                    detail: Some(strings.intern("no defining unit recorded")),
                })
            } else {
                StoragePolicy::DeclaredMembers
            }
        });
        let readable = matches!(storage, StoragePolicy::DeclaredMembers);
        let resource = draft.resource.map(|kind| {
            let rule_kind = RESOURCE_KINDS
                .iter()
                .find(|(k, _)| *k == kind)
                .map(|(_, rule)| *rule)
                .expect("every resource kind has a rule");
            // The layout rule binds under whatever family was selected;
            // the state protocol only inside its reviewed range, which
            // the one tokio origin's selection records — so a guessed
            // family observes and never assesses. Each reviewed
            // primitive polls nothing else while pending, which is the
            // exclusive-pending guarantee the barrier proof needs.
            let rule = rules.rule(&RuleKey::Library(rule_kind), strings, library);
            let state_rule = tokio_state_protocol(kind, library.tokio_version)
                .filter(|_| {
                    Family::layout_selection(library.tokio_version)
                        == LayoutSelection::ReviewedRange
                })
                .map(|protocol| rules.rule(&RuleKey::Library(protocol.kind), strings, library));
            ResourceBinding {
                rule,
                kind,
                state_rule,
                exclusive_pending: state_rule.is_some(),
            }
        });
        let container = draft.container.map(|(kind, rule)| ContainerBinding {
            rule: rules.rule(&rule, strings, library),
            kind,
            wakers: kind.wakers(),
        });
        let coroutine = draft.coroutine.map(|layout| CoroutineLayout {
            rule: rules.rule(
                draft
                    .coroutine_rule
                    .as_ref()
                    .expect("a coroutine layout has its rule"),
                strings,
                library,
            ),
            states: layout.states,
        });
        let mut evidence: Vec<FutureEvidence> = draft.evidence.into_iter().collect();
        if let Some(layout) = &coroutine {
            evidence.push(FutureEvidence::Coroutine(layout.rule));
            evidence.sort();
        }
        let mut issues: Vec<SemanticIssue> = draft
            .issues
            .iter()
            .map(|(kind, detail)| SemanticIssue {
                kind: *kind,
                detail: Some(strings.intern(detail)),
            })
            .collect();
        let mut access = None;
        // A program is a fact about polling, so it needs a future to be
        // about: an adapter nothing proves a future keeps its storage
        // access and no continuation, and numbers no poll rule.
        let program = match draft.plan.filter(|_| readable || coroutine.is_some()) {
            Some(plan) => {
                if let Some((access_rule, kind, target)) = plan.access {
                    access = Some(AccessBinding {
                        rule: rules.rule(&access_rule, strings, library),
                        kind,
                        target: target.into_future_target(&mut rules, strings, library),
                    });
                }
                if evidence.is_empty() {
                    None
                } else if let Some(program) = plan.program {
                    let rule = rules.rule(&plan.rule, strings, library);
                    let program = match program {
                        Delegation::Direct { target, exclusive } => {
                            PollProgram::Direct(PollAction::Delegate {
                                target: target.into_future_target(&mut rules, strings, library),
                                exclusive,
                            })
                        }
                        Delegation::Match { cases } => PollProgram::MatchVariant {
                            state: TypedPath {
                                steps: Vec::new(),
                                target: ty,
                            },
                            cases: cases
                                .into_iter()
                                .map(|(variant, action)| PollCase {
                                    variant,
                                    action: match action {
                                        CaseAction::Unresumed => PollAction::Unresumed,
                                        CaseAction::Returned => PollAction::Returned,
                                        CaseAction::Panicked => PollAction::Panicked,
                                        CaseAction::Delegate(target) => PollAction::Delegate {
                                            target: target
                                                .into_future_target(&mut rules, strings, library),
                                            exclusive: true,
                                        },
                                        CaseAction::Unknown(issue) => PollAction::Unknown(issue),
                                    },
                                })
                                .collect(),
                        },
                    };
                    Some((rule, program))
                } else {
                    // Proved a future by something, yet a route with no
                    // program: its continuation stays unknown, its
                    // access beside it.
                    None
                }
            }
            None => None,
        };
        // A resource that is positively a future polls its own state and
        // nothing else: its continuation is the primitive boundary. What
        // that state means — ready, pending, closed — is the state
        // rule's to say, and none is bound here.
        let continuation = match (&resource, program) {
            (Some(resource), _) => Continuation::Bound {
                rule: resource.rule,
                program: PollProgram::Direct(PollAction::Primitive),
            },
            (None, Some((rule, program))) => Continuation::Bound { rule, program },
            (None, None) => match &draft.decline {
                Some((kind, detail)) => {
                    let detail = strings.intern(detail);
                    issues.push(SemanticIssue {
                        kind: *kind,
                        detail: Some(detail),
                    });
                    Continuation::Unknown(SemanticIssue {
                        kind: *kind,
                        detail: Some(detail),
                    })
                }
                None => Continuation::Unknown(issue(SemanticIssueKind::NoRule)),
            },
        };
        let select = draft.select.filter(|_| readable).map(|plan| SelectBinding {
            rule: rules.rule(&plan.rule, strings, library),
            mask: plan.mask,
            futures: plan.futures,
            branches: plan.branches,
        });
        records.push(TypeSemantics {
            ty,
            storage,
            future: (!evidence.is_empty()).then_some(FutureFacts {
                evidence,
                continuation,
            }),
            coroutine,
            access,
            resource,
            container,
            select,
            issues,
        });
    }
    for task in tasks.iter_mut() {
        let mut classes = SCHEDULER_CLASSES.iter().filter(|(class, _)| {
            bound_roots(library.walks, &[scheduler_role(*class)], &[]).contains(&task.scheduler)
        });
        // Exactly one class may claim an entry's S; the roots are exact
        // types, so two claiming the same one is a table bug, and the
        // entry is left unknown rather than guessed.
        task.scheduler_binding = match (classes.next(), classes.next()) {
            (Some((class, rule_kind)), None) => Some(SchedulerBinding {
                class: *class,
                rule: rules.rule(&RuleKey::Library(*rule_kind), strings, library),
            }),
            _ => None,
        };
    }
    SemanticTable {
        origins: rules.origins,
        rules: rules.rules,
        types: records,
    }
}

fn adapter_pointee(adapter: &AdapterSeed) -> Option<BundleTypeId> {
    match &adapter.pointee {
        PointeeSeed::Sized(f) => Some(*f),
        PointeeSeed::Dyn(_) => None,
    }
}

/// Hold a planned path to the validator's own rule over the final table:
/// named members only, in bounds, landing on exactly the type claimed.
fn checked_path(
    types: &TypeTable,
    root: BundleTypeId,
    steps: Vec<Step>,
    target: BundleTypeId,
) -> Result<TypedPath, Decline> {
    match semantic_path_target(types, root, &Selector(steps.clone())) {
        Ok(landed) if landed == target => Ok(TypedPath { steps, target }),
        Ok(_) => Err((
            SemanticIssueKind::MissingLayout,
            "the route lands on another type than declared".to_owned(),
        )),
        Err(e) => Err((SemanticIssueKind::MissingLayout, e.to_string())),
    }
}

/// The unique member of `ty` named `name`, with its type.
fn member_named(
    types: &TypeTable,
    strings: &StringInterner,
    ty: BundleTypeId,
    name: &str,
) -> Option<(StrRef, BundleTypeId, u64)> {
    let mut found = members_of(types, ty)
        .iter()
        .filter(|m| strings.get(m.name) == Some(name));
    let member = found.next()?;
    found
        .next()
        .is_none()
        .then_some((member.name, member.ty, member.offset))
}

fn supported(verdict: &CompilerVerdict) -> Result<(&str, &'static RustcConvention), Decline> {
    match verdict {
        CompilerVerdict::Supported {
            producer,
            convention,
        } => Ok((producer, convention)),
        CompilerVerdict::Declined(detail) => {
            Err((SemanticIssueKind::UnsupportedOrigin, detail.clone()))
        }
    }
}

/// Plan a std adapter's delegation: the compiler verdict on its
/// defining units, then the route the screen described held to the
/// final table — the `Pin` member that is its `Ptr`, the thin pointer
/// whose pointee is the declared `F`, or the wide pointer whose data
/// and vtable words are where the screen found them.
fn plan_adapter(
    ty: BundleTypeId,
    adapter: &AdapterSeed,
    types: &TypeTable,
    strings: &mut StringInterner,
) -> Result<Plan, Decline> {
    let (producer, convention) = supported(&adapter.compiler)?;
    let rule = |kind| RuleKey::Rustc {
        kind,
        producer: producer.to_owned(),
        family: convention.family,
    };
    let mut steps = Vec::new();
    let mut current = ty;
    if let Some((member, ptr)) = &adapter.pin {
        let Some(TypeDef::Struct { members, .. }) = types.get(ty) else {
            return Err((
                SemanticIssueKind::MissingLayout,
                "Pin is not a struct in the final table".to_owned(),
            ));
        };
        let (name, member_ty, offset) = member_named(types, strings, ty, member).ok_or((
            SemanticIssueKind::AmbiguousLayout,
            format!("Pin has no unique member {member:?}"),
        ))?;
        if members.len() != 1 || member_ty != *ptr || offset != 0 {
            return Err((
                SemanticIssueKind::MissingLayout,
                "Pin's member is not its declared pointer".to_owned(),
            ));
        }
        steps.push(Step::Member(MemberRef::Named(name)));
        current = *ptr;
    }
    let target = match &adapter.pointee {
        PointeeSeed::Sized(f) => {
            if !matches!(types.get(current), Some(TypeDef::Pointer { target, .. }) if target == f) {
                return Err((
                    SemanticIssueKind::MissingLayout,
                    "the adapter's pointer does not target its declared future".to_owned(),
                ));
            }
            steps.push(Step::Deref);
            Target::Value(checked_path(types, ty, steps, *f)?)
        }
        PointeeSeed::Dyn(d) => dynamic_target(ty, steps, current, d, types, strings)?,
    };
    Ok(Plan {
        rule: rule(adapter.kind.poll_rule()),
        access: Some((
            rule(adapter.kind.access_rule()),
            adapter.kind.access(),
            target.clone(),
        )),
        program: Some(Delegation::Direct {
            target,
            exclusive: true,
        }),
        delegate_is_future: true,
    })
}

/// The dynamic target a wide pointer plans: `steps` from `ty` to the
/// wide pointer `current`, which has to be the one the screen saw,
/// held to the final table; inside it the two words the screen named,
/// each pointer-sized, the data word targeting the zero-sized trait
/// object; and the ABI rule its defining units were compiled under.
fn dynamic_target(
    ty: BundleTypeId,
    steps: Vec<Step>,
    current: BundleTypeId,
    d: &DynSeed,
    types: &TypeTable,
    strings: &mut StringInterner,
) -> Result<Target, Decline> {
    let (abi_producer, abi) = supported(&d.abi)?;
    if current != d.wide {
        return Err((
            SemanticIssueKind::MissingLayout,
            "the adapter's wide pointer is not the one screened".to_owned(),
        ));
    }
    let (pointer, data_ptr, _) = member_named(types, strings, d.wide, &d.pointer).ok_or((
        SemanticIssueKind::AmbiguousLayout,
        "no unique data pointer member".to_owned(),
    ))?;
    let (vtable, vtable_ptr, _) = member_named(types, strings, d.wide, &d.vtable).ok_or((
        SemanticIssueKind::AmbiguousLayout,
        "no unique vtable member".to_owned(),
    ))?;
    let wide_shape = data_ptr == d.data_ptr
        && vtable_ptr == d.vtable_ptr
        && matches!(types.get(d.data_ptr), Some(TypeDef::Pointer { target, .. }) if *target == d.trait_ty)
        && matches!(
            types.get(d.trait_ty),
            Some(TypeDef::Struct { size: 0, members, .. }) if members.is_empty()
        )
        && types.size_of(d.data_ptr) == Some(crate::bundle::POINTER_SIZE)
        && types.size_of(d.vtable_ptr) == Some(crate::bundle::POINTER_SIZE);
    if !wide_shape {
        return Err((
            SemanticIssueKind::MissingLayout,
            "the wide pointer's words or trait object moved in the final table".to_owned(),
        ));
    }
    Ok(Target::Dynamic {
        pointer: checked_path(types, ty, steps, d.wide)?,
        data: checked_path(
            types,
            d.wide,
            vec![Step::Member(MemberRef::Named(pointer))],
            d.data_ptr,
        )?,
        vtable: checked_path(
            types,
            d.wide,
            vec![Step::Member(MemberRef::Named(vtable))],
            d.vtable_ptr,
        )?,
        trait_ty: d.trait_ty,
        future_trait: d.future_trait,
        abi: RuleKey::Rustc {
            kind: SemanticRuleKind::DynFutureAbi,
            producer: abi_producer.to_owned(),
            family: abi.family,
        },
    })
}

/// Plan a reviewed third-party wrapper's delegation: the origin first —
/// every declaration of its `poll` on a cargo registry path naming the
/// convention's crate at a version inside its reviewed range, or of
/// the type's own methods where the type is a storage route with no
/// poll — then the route the screen described, held to the final
/// table. Each of these implementations polls its delegate and nothing
/// else, so all of them forward exclusively; the two storage routes
/// plan no program at all, only the access their one member is.
fn plan_library(
    ty: BundleTypeId,
    seed_layout: &LibrarySeed,
    seed: &Seed,
    types: &TypeTable,
    strings: &mut StringInterner,
) -> Result<Plan, Decline> {
    let rule = if seed_layout.origin_is_the_layout() {
        // The forward below is the proof: a sole member of the declared
        // type, under the crate's layout origin.
        RuleKey::Library(seed_layout.rule_kind())
    } else {
        let (sources, declared_by) = if seed_layout.origin_is_the_type() {
            (&seed.type_sources, "method")
        } else {
            (&seed.poll_sources, "poll")
        };
        let origin = delegation_origin(sources, seed_layout.convention(), declared_by)?;
        RuleKey::Delegation {
            kind: seed_layout.rule_kind(),
            origin,
        }
    };
    // A wrapper's route is its one member; the map's is the member
    // inside its incomplete state, and the state is what selects it.
    let forward = |member: &str, inner: BundleTypeId, strings: &mut StringInterner| {
        let (name, member_ty, _) = member_named(types, strings, ty, member).ok_or((
            SemanticIssueKind::AmbiguousLayout,
            format!("no unique member {member:?}"),
        ))?;
        if member_ty != inner {
            return Err((
                SemanticIssueKind::MissingLayout,
                format!("{member} holds another type than the screen declared"),
            ));
        }
        checked_path(types, ty, vec![Step::Member(MemberRef::Named(name))], inner)
    };
    let program = match seed_layout {
        LibrarySeed::Map {
            incomplete,
            future_member,
            complete,
            future,
        } => {
            let Some(TypeDef::Enum { shape, .. }) = types.get(ty) else {
                return Err((
                    SemanticIssueKind::MissingLayout,
                    "Map is not an enum in the final table".to_owned(),
                ));
            };
            let variant = |name: &str| {
                shape
                    .variants
                    .iter()
                    .find(|v| strings.get(v.name) == Some(name))
                    .map(|v| (v.name, v.payload.ty))
            };
            let (incomplete_name, payload) = variant(incomplete).ok_or((
                SemanticIssueKind::MissingLayout,
                format!("Map has no {incomplete} state in the final table"),
            ))?;
            let (complete_name, _) = variant(complete).ok_or((
                SemanticIssueKind::MissingLayout,
                format!("Map has no {complete} state in the final table"),
            ))?;
            if shape.variants.len() != 2 {
                return Err((
                    SemanticIssueKind::MissingLayout,
                    "Map has states beyond the two reviewed ones".to_owned(),
                ));
            }
            let (member, member_ty, _) = member_named(types, strings, payload, future_member)
                .ok_or((
                    SemanticIssueKind::AmbiguousLayout,
                    format!("Map's {incomplete} state has no unique member {future_member:?}"),
                ))?;
            if member_ty != *future {
                return Err((
                    SemanticIssueKind::MissingLayout,
                    format!("{future_member} holds another type than the screen declared"),
                ));
            }
            let path = checked_path(
                types,
                ty,
                vec![
                    Step::Variant(incomplete_name),
                    Step::Member(MemberRef::Named(member)),
                ],
                *future,
            )?;
            Delegation::Match {
                cases: vec![
                    (
                        incomplete_name,
                        CaseAction::Delegate(Box::new(Target::Value(path))),
                    ),
                    // Polling a completed map panics, so this state is
                    // where its output was already produced.
                    (complete_name, CaseAction::Returned),
                ],
            }
        }
        LibrarySeed::MapWrapper(member, inner)
        | LibrarySeed::MapErr(member, inner)
        | LibrarySeed::IntoFuture(member, inner)
        | LibrarySeed::TokioSleep(member, inner)
        | LibrarySeed::Coop(member, inner) => Delegation::Direct {
            target: Target::Value(forward(member, *inner, strings)?),
            exclusive: true,
        },
        // `Next` polls through its `&mut St`: the route dereferences the
        // reference to the stream itself, whose own record says what
        // polling it polls. A stream is no future, so the delegate is
        // named and not proved.
        LibrarySeed::Next(member, stream) => {
            let (name, member_ty, _) = member_named(types, strings, ty, member).ok_or((
                SemanticIssueKind::AmbiguousLayout,
                format!("no unique member {member:?}"),
            ))?;
            if !matches!(types.get(member_ty), Some(TypeDef::Pointer { target, .. }) if target == stream)
            {
                return Err((
                    SemanticIssueKind::MissingLayout,
                    format!("{member} is not a reference to the declared stream"),
                ));
            }
            let path = checked_path(
                types,
                ty,
                vec![Step::Member(MemberRef::Named(name)), Step::Deref],
                *stream,
            )?;
            return Ok(Plan {
                rule,
                program: Some(Delegation::Direct {
                    target: Target::Value(path),
                    exclusive: true,
                }),
                access: None,
                delegate_is_future: false,
            });
        }
        // The stream owns the box it polls through, and is polled
        // through itself: an access and no program.
        LibrarySeed::WatchStream(member, inner) => {
            let path = forward(member, *inner, strings)?;
            return Ok(Plan {
                rule: rule.clone(),
                program: None,
                access: Some((rule, AccessKind::Owned, Target::Value(path))),
                delegate_is_future: true,
            });
        }
        // The box's every poll is the trait object's: the route runs
        // through `boxed` and the `Pin`'s one member to the wide
        // pointer, which the dyn join resolves.
        LibrarySeed::ReusableBox { boxed, pin, dyn_ } => {
            let (boxed_name, pin_ty, _) = member_named(types, strings, ty, boxed).ok_or((
                SemanticIssueKind::AmbiguousLayout,
                format!("no unique member {boxed:?}"),
            ))?;
            let Some(TypeDef::Struct { members, .. }) = types.get(pin_ty) else {
                return Err((
                    SemanticIssueKind::MissingLayout,
                    "Pin is not a struct in the final table".to_owned(),
                ));
            };
            let (pin_name, box_ty, offset) =
                member_named(types, strings, pin_ty, &pin.0).ok_or((
                    SemanticIssueKind::AmbiguousLayout,
                    format!("Pin has no unique member {:?}", pin.0),
                ))?;
            if members.len() != 1 || box_ty != pin.1 || offset != 0 {
                return Err((
                    SemanticIssueKind::MissingLayout,
                    "Pin's member is not its declared pointer".to_owned(),
                ));
            }
            let steps = vec![
                Step::Member(MemberRef::Named(boxed_name)),
                Step::Member(MemberRef::Named(pin_name)),
            ];
            let target = dynamic_target(ty, steps, box_ty, dyn_, types, strings)?;
            return Ok(Plan {
                rule: rule.clone(),
                program: None,
                access: Some((rule, AccessKind::Owned, target)),
                delegate_is_future: true,
            });
        }
    };
    Ok(Plan {
        rule,
        program: Some(program),
        access: None,
        delegate_is_future: true,
    })
}

/// Plan a `select!`'s binding: the origin first — the closure
/// environment declared in tokio's `src/macros/select.rs` on a cargo
/// registry path at a version inside the reviewed range — then the two
/// routes through the closure's references and one per tuple member,
/// each held to the final table. The mask word has to be the unsigned
/// integer the screen saw, of a width tokio-macros emits, with room
/// for every branch.
fn plan_select(
    ty: BundleTypeId,
    seed: &SelectSeed,
    types: &TypeTable,
    strings: &mut StringInterner,
) -> Result<SelectPlan, Decline> {
    let Some(source) = &seed.source else {
        return Err((
            SemanticIssueKind::UnsupportedOrigin,
            "the closure environment records no declaration site".to_owned(),
        ));
    };
    let origin = delegation_origin(
        &BTreeSet::from([source.clone()]),
        &TOKIO_SELECT_V1_47,
        "closure",
    )?;
    let rule = RuleKey::Delegation {
        kind: SemanticRuleKind::TokioSelect,
        origin,
    };
    let member = |strings: &mut StringInterner, parent: BundleTypeId, name: &str| {
        member_named(types, strings, parent, name).ok_or((
            SemanticIssueKind::AmbiguousLayout,
            format!("no unique member {name:?}"),
        ))
    };
    // Both captures: the `PollFn`'s closure, the closure's reference,
    // then what it points at.
    let (closure, env, _) = member(strings, ty, &seed.closure)?;
    let capture = |strings: &mut StringInterner, name: &str, target| {
        let (name, _, _) = member(strings, env, name)?;
        checked_path(
            types,
            ty,
            vec![
                Step::Member(MemberRef::Named(closure)),
                Step::Member(MemberRef::Named(name)),
                Step::Deref,
            ],
            target,
        )
    };
    let mask = capture(strings, &seed.mask, seed.mask_word)?;
    if !matches!(
        types.get(seed.mask_word),
        Some(TypeDef::Base {
            encoding: crate::Encoding::Unsigned,
            size: 1 | 2 | 4 | 8,
            ..
        })
    ) {
        return Err((
            SemanticIssueKind::MissingLayout,
            "the mask is not an unsigned word in the final table".to_owned(),
        ));
    }
    let futures = capture(strings, &seed.futures, seed.tuple)?;
    let mut branches = Vec::with_capacity(seed.branches.len());
    for (name, future) in &seed.branches {
        let (name, member_ty, _) = member(strings, seed.tuple, name)?;
        if member_ty != *future {
            return Err((
                SemanticIssueKind::MissingLayout,
                format!(
                    "{} holds another type than the screen declared",
                    strings.get(name).unwrap_or_default()
                ),
            ));
        }
        branches.push(checked_path(
            types,
            seed.tuple,
            vec![Step::Member(MemberRef::Named(name))],
            *future,
        )?);
    }
    if branches.is_empty() {
        return Err((
            SemanticIssueKind::MissingLayout,
            "the tuple has no members".to_owned(),
        ));
    }
    Ok(SelectPlan {
        rule,
        mask,
        futures,
        branches,
    })
}

/// Plan `Instrumented<F>`'s delegation: the origin first — every
/// declaration of its `poll` on a cargo registry path naming `tracing`
/// at one version inside the reviewed range, any checksum the file
/// tables carried among the reviewed revisions — then the storage
/// route, `inner` and whatever std wrappers hold `F` inside it, held to
/// the final table. The forwarded poll runs the span's subscriber
/// callbacks around it, so the delegation is not exclusive.
fn plan_instrumented(
    ty: BundleTypeId,
    layout: &InstrumentedSeed,
    seed: &Seed,
    types: &TypeTable,
    names: &[Option<String>],
    strings: &mut StringInterner,
) -> Result<Plan, Decline> {
    let origin = delegation_origin(&seed.poll_sources, &TRACING_INSTRUMENTED_V0_1_40, "poll")?;
    let (name, inner_ty, _) = member_named(types, strings, ty, &layout.inner).ok_or((
        SemanticIssueKind::AmbiguousLayout,
        format!("Instrumented has no unique member {:?}", layout.inner),
    ))?;
    let mut steps = vec![Step::Member(MemberRef::Named(name))];
    let mut current = inner_ty;
    // `inner` is `ManuallyDrop<F>`, which std currently lays out as
    // `{ value: MaybeDangling<F> }` over `{ __0: F }`: each a transparent
    // wrapper with one member at offset zero, entered by name, and
    // nothing else is.
    const WRAPPERS: [&str; 2] = [
        "core::mem::manually_drop::ManuallyDrop<",
        "core::mem::maybe_dangling::MaybeDangling<",
    ];
    for _ in 0..WRAPPERS.len() {
        if current == layout.future {
            break;
        }
        let name = names
            .get(current.0 as usize)
            .and_then(|n| n.as_deref())
            .unwrap_or_default();
        if !WRAPPERS.iter().any(|w| name.starts_with(w)) {
            return Err((
                SemanticIssueKind::MissingLayout,
                format!("inner holds {name:?}, not a reviewed std wrapper of the future"),
            ));
        }
        let [member] = members_of(types, current) else {
            return Err((
                SemanticIssueKind::MissingLayout,
                format!("{name} is not a one-member wrapper"),
            ));
        };
        if member.offset != 0 {
            return Err((
                SemanticIssueKind::MissingLayout,
                format!("{name}'s member is not at offset zero"),
            ));
        }
        steps.push(Step::Member(MemberRef::Named(member.name)));
        current = member.ty;
    }
    if current != layout.future {
        return Err((
            SemanticIssueKind::MissingLayout,
            "inner does not reach the declared future through reviewed wrappers".to_owned(),
        ));
    }
    let path = checked_path(types, ty, steps, layout.future)?;
    Ok(Plan {
        rule: RuleKey::Delegation {
            kind: SemanticRuleKind::TracingInstrumented,
            origin,
        },
        program: Some(Delegation::Direct {
            target: Target::Value(path),
            exclusive: false,
        }),
        access: None,
        delegate_is_future: true,
    })
}

/// The origin an instantiation's poll declarations establish for a
/// reviewed third-party implementation. Every declaration has to lie on
/// a cargo registry path naming the convention's crate; they have to
/// agree on one such path; its version has to fall inside the reviewed
/// range; and a checksum, where a file table carried one, has to be a
/// reviewed revision. No declaration at all is no origin: the
/// implementation may be inlined away, but then nothing says which one
/// it was.
fn delegation_origin(
    sources: &BTreeSet<PollSource>,
    convention: &'static LibraryConvention,
    declared_by: &str,
) -> Result<DelegationOrigin, Decline> {
    let decline = |detail: String| (SemanticIssueKind::UnsupportedOrigin, detail);
    let package = convention.package;
    if sources.is_empty() {
        return Err(decline(format!(
            "no {declared_by} declaration records where this instantiation's implementation lives"
        )));
    }
    let mut agreed: Option<(String, semver::Version)> = None;
    let mut files: Vec<(String, [u8; 16])> = Vec::new();
    for source in sources {
        let Some(origin) = registry_origin(&source.path) else {
            return Err(decline(format!(
                "declared in {}, which is not a cargo registry path",
                source.path
            )));
        };
        if origin.package != package {
            return Err(decline(format!(
                "declared in {}, which is not the {package} crate",
                source.path
            )));
        }
        match &agreed {
            Some((path, _)) if path != origin.path => {
                return Err(decline(format!(
                    "declared in both {path} and {}",
                    origin.path
                )));
            }
            Some(_) => {}
            None => agreed = Some((origin.path.to_owned(), origin.version)),
        }
        if let Some(md5) = source.md5 {
            files.push((origin.path.to_owned(), md5));
        }
    }
    let (source, version) = agreed.expect("at least one source");
    let convention = match library_convention(convention, &version) {
        Ok(convention) => convention,
        Err(side) => {
            let side = match side {
                LayoutSelection::BelowFloor => "below",
                _ => "above",
            };
            return Err(decline(format!(
                "{package} {version} is {side} the reviewed range {}",
                convention.range()
            )));
        }
    };
    files.sort();
    files.dedup();
    for (file, md5) in &files {
        if !convention.reviewed_checksum(md5) {
            return Err(decline(format!(
                "{file} has checksum {}, not a reviewed revision of {}",
                hex(md5),
                convention.family
            )));
        }
    }
    Ok(DelegationOrigin {
        package: convention.package,
        version: version.to_string(),
        family: convention.family,
        source,
        files,
    })
}

fn hex(md5: &[u8; 16]) -> String {
    md5.iter().map(|b| format!("{b:02x}")).collect()
}

/// The program a bound coroutine layout spells: one case per state, a
/// suspended state delegating to its `__awaitee` — the one member the
/// convention names as the future being awaited — and to nothing else.
/// A suspended state without one keeps an unknown case: the layout is
/// still read, the continuation not guessed.
fn coroutine_plan(
    ty: BundleTypeId,
    rule: &RuleKey,
    layout: &CoroutineLayout,
    types: &TypeTable,
    strings: &mut StringInterner,
) -> Plan {
    let awaitee = strings.intern("__awaitee");
    let Some(TypeDef::Enum { shape, .. }) = types.get(ty) else {
        unreachable!("a bound coroutine is an enum");
    };
    let cases = layout
        .states
        .iter()
        .map(|state| {
            let action = match state.stage {
                CoroutinePhase::Unresumed => CaseAction::Unresumed,
                CoroutinePhase::Returned => CaseAction::Returned,
                CoroutinePhase::Panicked => CaseAction::Panicked,
                CoroutinePhase::Unknown => CaseAction::Unknown(SemanticIssue {
                    kind: SemanticIssueKind::UnsupportedState,
                    detail: None,
                }),
                CoroutinePhase::Suspended => {
                    let payload = shape
                        .variants
                        .iter()
                        .find(|v| v.name == state.variant)
                        .map(|v| v.payload.ty);
                    let member = payload.and_then(|payload| {
                        let mut found = members_of(types, payload)
                            .iter()
                            .filter(|m| m.name == awaitee);
                        let member = found.next()?;
                        (found.next().is_none() && state.locals.contains(&awaitee))
                            .then_some(member.ty)
                    });
                    match member {
                        Some(target) => match checked_path(
                            types,
                            ty,
                            vec![
                                Step::Variant(state.variant),
                                Step::Member(MemberRef::Named(awaitee)),
                            ],
                            target,
                        ) {
                            Ok(path) => CaseAction::Delegate(Box::new(Target::Value(path))),
                            Err((kind, detail)) => CaseAction::Unknown(SemanticIssue {
                                kind,
                                detail: Some(strings.intern(&detail)),
                            }),
                        },
                        None => CaseAction::Unknown(SemanticIssue {
                            kind: SemanticIssueKind::MissingLayout,
                            detail: Some(strings.intern("the suspended state lists no __awaitee")),
                        }),
                    }
                }
            };
            (state.variant, action)
        })
        .collect();
    Plan {
        rule: rule.clone(),
        program: Some(Delegation::Match { cases }),
        access: None,
        delegate_is_future: true,
    }
}

/// The stage rustc's variant numbering assigns, and the payload name it
/// carries: the convention the reviewed range was checked for.
fn expected_state(index: usize) -> (CoroutinePhase, String) {
    match index {
        0 => (CoroutinePhase::Unresumed, "Unresumed".to_owned()),
        1 => (CoroutinePhase::Returned, "Returned".to_owned()),
        2 => (CoroutinePhase::Panicked, "Panicked".to_owned()),
        n => (CoroutinePhase::Suspended, format!("Suspend{}", n - 3)),
    }
}

/// Bind a compiler candidate's states under its reviewed convention, or
/// say why not. The verdict on its defining units comes first; the enum
/// is then held to the convention's exact shape — numbered variants in
/// stage order, payload names to match, terminal states emptied — and
/// each state's members are classed: an `Unresumed`'s are its arguments,
/// a suspended state's are the locals live across its await, except
/// that an async block's captures, which the state kept whether or not
/// the body has moved them out, are uncertain.
fn bind_coroutine(
    ty: BundleTypeId,
    seed: &Seed,
    types: &TypeTable,
    names: &[Option<String>],
    strings: &mut StringInterner,
) -> Result<(RuleKey, CoroutineLayout), Decline> {
    let (producer, convention) = match &seed.compiler {
        Some(CompilerVerdict::Supported {
            producer,
            convention,
        }) => (producer, *convention),
        Some(CompilerVerdict::Declined(detail)) => {
            return Err((SemanticIssueKind::UnsupportedOrigin, detail.clone()));
        }
        None => {
            return Err((
                SemanticIssueKind::UnsupportedOrigin,
                "no defining unit recorded".to_owned(),
            ));
        }
    };
    let name = names
        .get(ty.0 as usize)
        .and_then(|n| n.as_deref())
        .unwrap_or_default();
    let kind = match coroutine_kind(name) {
        Some("async fn") => SemanticRuleKind::RustcAsyncFn,
        Some("async block") => SemanticRuleKind::RustcAsyncBlock,
        _ => {
            return Err((
                SemanticIssueKind::NoRule,
                "only async fn and async block environments have a reviewed rule".to_owned(),
            ));
        }
    };
    let states = coroutine_states(
        ty,
        kind == SemanticRuleKind::RustcAsyncBlock,
        types,
        names,
        strings,
    )?;
    let rule = RuleKey::Rustc {
        kind,
        producer: producer.clone(),
        family: convention.family,
    };
    Ok((
        rule,
        CoroutineLayout {
            // Numbered when the record is emitted.
            rule: SemanticRuleId(u32::MAX),
            states,
        },
    ))
}

/// Hold the final enum to the convention's shape and class each state's
/// members. `strings` is read only, for the variant keys.
fn coroutine_states(
    ty: BundleTypeId,
    is_block: bool,
    types: &TypeTable,
    names: &[Option<String>],
    strings: &StringInterner,
) -> Result<Vec<CoroutineState>, Decline> {
    let Some(TypeDef::Enum { shape, .. }) = types.get(ty) else {
        return Err((
            SemanticIssueKind::MissingLayout,
            "the environment is not an enum".to_owned(),
        ));
    };
    if shape.variants.len() < 3 {
        return Err((
            SemanticIssueKind::UnsupportedState,
            format!(
                "{} variants, fewer than the three fixed stages",
                shape.variants.len()
            ),
        ));
    }
    let unresumed: BTreeSet<(StrRef, BundleTypeId, u64)> =
        members_of(types, shape.variants[0].payload.ty)
            .iter()
            .map(|m| (m.name, m.ty, m.offset))
            .collect();
    let mut states = Vec::with_capacity(shape.variants.len());
    for (index, variant) in shape.variants.iter().enumerate() {
        let key = strings.get(variant.name).unwrap_or_default();
        if key != index.to_string() {
            return Err((
                SemanticIssueKind::UnsupportedState,
                format!("variant {index} is keyed {key:?}, not by its position"),
            ));
        }
        let (stage, expected) = expected_state(index);
        let actual = state_name(names, variant.payload.ty).unwrap_or_default();
        if actual != expected {
            return Err((
                SemanticIssueKind::UnsupportedState,
                format!("variant {index} is {actual:?}, not {expected:?}"),
            ));
        }
        if !matches!(types.get(variant.payload.ty), Some(TypeDef::Struct { .. })) {
            return Err((
                SemanticIssueKind::MissingLayout,
                format!("{expected} is not a struct"),
            ));
        }
        let members = members_of(types, variant.payload.ty);
        let mut seen = BTreeSet::new();
        for member in members {
            if !seen.insert(member.name) {
                return Err((
                    SemanticIssueKind::AmbiguousLayout,
                    format!(
                        "{expected} lists {:?} twice",
                        strings.get(member.name).unwrap_or_default()
                    ),
                ));
            }
        }
        let (locals, uncertain_locals): (Vec<StrRef>, Vec<StrRef>) = match stage {
            CoroutinePhase::Returned | CoroutinePhase::Panicked => {
                if !members.is_empty() {
                    return Err((
                        SemanticIssueKind::UnsupportedState,
                        format!("{expected} still lists {} members", members.len()),
                    ));
                }
                (Vec::new(), Vec::new())
            }
            CoroutinePhase::Unresumed => (members.iter().map(|m| m.name).collect(), Vec::new()),
            CoroutinePhase::Suspended => {
                let (captures, live): (Vec<_>, Vec<_>) = members
                    .iter()
                    .partition(|m| is_block && unresumed.contains(&(m.name, m.ty, m.offset)));
                (
                    live.into_iter().map(|m| m.name).collect(),
                    captures.into_iter().map(|m| m.name).collect(),
                )
            }
            CoroutinePhase::Unknown => unreachable!("expected_state never says unknown"),
        };
        states.push(CoroutineState {
            variant: variant.name,
            stage,
            locals,
            uncertain_locals,
        });
    }
    Ok(states)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bundle::{MemberDef, VariantDef, VariantShape, WalkBinding};
    use crate::detect::semantics::{RUSTC_DYN_FUTURE_ABI_V1_97, RUSTC_STD_ADAPTERS_V1_97};

    fn binding(roots: &[u32], bound: bool) -> WalkBinding {
        WalkBinding {
            roots: if bound {
                roots.iter().map(|&r| BundleTypeId(r)).collect()
            } else {
                Vec::new()
            },
            steps: Vec::new(),
            outcome: if bound {
                WalkOutcome::Bound {
                    spelling: 0,
                    spellings: 1,
                    note: None,
                }
            } else {
                WalkOutcome::Absent {
                    reason: "none".to_owned(),
                }
            },
        }
    }

    fn ids(roots: &[u32]) -> BTreeSet<BundleTypeId> {
        roots.iter().map(|&r| BundleTypeId(r)).collect()
    }

    /// A kind binds at the types every one of its roles bound at — the
    /// intersection, never the union — and at none when a role is
    /// unbound or a chained route below them is.
    #[test]
    fn test_bound_roots_intersects_roles_and_requires_every_route() {
        use WalkRole::*;
        let mut walks = WalksTable::default();
        walks
            .entries
            .insert(SleepDeadline, binding(&[1, 2, 3], true));
        walks
            .entries
            .insert(JoinHandleRaw, binding(&[2, 3, 4], true));
        walks.entries.insert(IoReadShared, binding(&[9], true));
        walks.entries.insert(IoWriteAllShared, binding(&[], false));
        assert_eq!(
            bound_roots(&walks, &[SleepDeadline, JoinHandleRaw], &[]),
            ids(&[2, 3])
        );
        assert_eq!(bound_roots(&walks, &[SleepDeadline], &[]), ids(&[1, 2, 3]));
        // A route only has to be bound; it roots elsewhere.
        assert_eq!(
            bound_roots(&walks, &[SleepDeadline], &[IoReadShared]),
            ids(&[1, 2, 3])
        );
        // An entry that recorded roots but no `Bound` outcome — which
        // the bundle validator forbids, so only a hand-built table has
        // one — binds nothing either: the outcome decides, not the list.
        let mut stale = binding(&[1, 2], true);
        stale.outcome = WalkOutcome::Broken {
            errors: vec!["moved".to_owned()],
        };
        walks.entries.insert(AcquireQueued, stale);
        assert!(bound_roots(&walks, &[AcquireQueued], &[]).is_empty());
        assert!(bound_roots(&walks, &[SleepDeadline], &[AcquireQueued]).is_empty());
        // An unbound route, an unbound role, or a role never recorded
        // binds nothing.
        assert!(bound_roots(&walks, &[SleepDeadline], &[IoWriteAllShared]).is_empty());
        assert!(bound_roots(&walks, &[SleepDeadline, IoWriteAllShared], &[]).is_empty());
        assert!(bound_roots(&walks, &[SleepDeadline, AcquireNode], &[]).is_empty());
        assert!(bound_roots(&walks, &[SleepDeadline], &[AcquireNode]).is_empty());
    }

    /// A coroutine env spelled the way rustc does: numbered variants whose
    /// payload structs carry the state names, with the member sets the
    /// state pass leaves behind.
    struct Env {
        types: TypeTable,
        names: Vec<Option<String>>,
        strings: StringInterner,
        env: BundleTypeId,
    }

    fn env(kind: &str, states: &[(&str, &[&str])], keys: &[&str]) -> Env {
        let mut strings = StringInterner::new();
        let mut names: Vec<Option<String>> = vec![Some("u32".to_owned())];
        let mut types = vec![TypeDef::Base {
            name: strings.intern("u32"),
            size: 4,
            encoding: crate::Encoding::Unsigned,
        }];
        let env_name = format!("app::work::{{{kind}_env#0}}");
        let mut variants = Vec::new();
        for (index, (state, members)) in states.iter().enumerate() {
            let payload = BundleTypeId(types.len() as u32);
            let name = format!("{env_name}::{state}");
            types.push(TypeDef::Struct {
                name: strings.intern(&name),
                size: 32,
                members: members
                    .iter()
                    .enumerate()
                    .map(|(i, m)| MemberDef {
                        name: strings.intern(m),
                        ty: BundleTypeId(0),
                        // A repeated name at a distinct slot is the
                        // shadowed-local case; the same name at the same
                        // slot is what the capture check keys on.
                        offset: 4 * i as u64,
                    })
                    .collect(),
            });
            names.push(Some(name));
            let key = strings.intern(keys.get(index).copied().unwrap_or(&index.to_string()));
            variants.push(VariantDef {
                name: key,
                discr_values: None,
                payload: MemberDef {
                    name: key,
                    ty: payload,
                    offset: 0,
                },
                decl: None,
                await_site: None,
            });
        }
        let env = BundleTypeId(types.len() as u32);
        types.push(TypeDef::Enum {
            name: strings.intern(&env_name),
            size: 32,
            shape: VariantShape {
                discr: None,
                variants,
            },
        });
        names.push(Some(env_name));
        Env {
            types: TypeTable {
                types,
                ..Default::default()
            },
            names,
            strings,
            env,
        }
    }

    fn render(e: &Env, states: &[CoroutineState]) -> Vec<String> {
        let s = |r| e.strings.get(r).unwrap();
        states
            .iter()
            .map(|st| {
                format!(
                    "{}:{:?}[{}]({})",
                    s(st.variant),
                    st.stage,
                    st.locals
                        .iter()
                        .map(|&n| s(n))
                        .collect::<Vec<_>>()
                        .join(","),
                    st.uncertain_locals
                        .iter()
                        .map(|&n| s(n))
                        .collect::<Vec<_>>()
                        .join(",")
                )
            })
            .collect()
    }

    const FN: &[(&str, &[&str])] = &[
        ("Unresumed", &["arg"]),
        ("Returned", &[]),
        ("Panicked", &[]),
        ("Suspend0", &["local", "__awaitee"]),
        ("Suspend1", &["__awaitee"]),
    ];

    #[test]
    fn test_async_fn_states_class_arguments_and_live_locals() {
        let e = env("async_fn", FN, &[]);
        let states = coroutine_states(e.env, false, &e.types, &e.names, &e.strings).unwrap();
        assert_eq!(
            render(&e, &states),
            [
                "0:Unresumed[arg]()",
                "1:Returned[]()",
                "2:Panicked[]()",
                "3:Suspended[local,__awaitee]()",
                "4:Suspended[__awaitee]()",
            ]
        );
    }

    /// An async block's suspended states keep its captures at the slot
    /// `Unresumed` lists them at; those are uncertain, everything else is
    /// live. The same name at another slot is a distinct local.
    #[test]
    fn test_async_block_captures_are_uncertain_only_at_their_unresumed_slot() {
        let e = env(
            "async_block",
            &[
                ("Unresumed", &["cap", "other"]),
                ("Returned", &[]),
                ("Panicked", &[]),
                ("Suspend0", &["cap", "__awaitee", "other"]),
            ],
            &[],
        );
        let states = coroutine_states(e.env, true, &e.types, &e.names, &e.strings).unwrap();
        // `cap` sits at slot 0 in both; `other` moved from slot 4 to 8.
        assert_eq!(render(&e, &states)[3], "3:Suspended[__awaitee,other](cap)");
        // The same shape as an async fn admits every member as live: its
        // arguments were already stripped from the suspended states.
        let states = coroutine_states(e.env, false, &e.types, &e.names, &e.strings).unwrap();
        assert_eq!(render(&e, &states)[3], "3:Suspended[cap,__awaitee,other]()");
    }

    #[test]
    fn test_coroutine_shape_declines_name_each_departure_from_the_convention() {
        let decline = |e: &Env| {
            coroutine_states(e.env, false, &e.types, &e.names, &e.strings)
                .unwrap_err()
                .0
        };
        // Variants keyed by anything but their position.
        let e = env("async_fn", FN, &["0", "1", "2", "Suspend0", "4"]);
        assert_eq!(decline(&e), SemanticIssueKind::UnsupportedState);
        // States out of the fixed order.
        let e = env(
            "async_fn",
            &[
                ("Unresumed", &[]),
                ("Panicked", &[]),
                ("Returned", &[]),
                ("Suspend0", &["__awaitee"]),
            ],
            &[],
        );
        assert_eq!(decline(&e), SemanticIssueKind::UnsupportedState);
        // Suspend numbering that skips.
        let e = env(
            "async_fn",
            &[
                ("Unresumed", &[]),
                ("Returned", &[]),
                ("Panicked", &[]),
                ("Suspend1", &["__awaitee"]),
            ],
            &[],
        );
        assert_eq!(decline(&e), SemanticIssueKind::UnsupportedState);
        // A terminal state still listing storage.
        let e = env(
            "async_fn",
            &[
                ("Unresumed", &[]),
                ("Returned", &["arg"]),
                ("Panicked", &[]),
                ("Suspend0", &["__awaitee"]),
            ],
            &[],
        );
        assert_eq!(decline(&e), SemanticIssueKind::UnsupportedState);
        // A shadowed local listed twice in one state: which is which is
        // not knowable by name, so the whole type declines.
        let e = env(
            "async_fn",
            &[
                ("Unresumed", &[]),
                ("Returned", &[]),
                ("Panicked", &[]),
                ("Suspend0", &["x", "__awaitee", "x"]),
            ],
            &[],
        );
        assert_eq!(decline(&e), SemanticIssueKind::AmbiguousLayout);
        // Too few variants for the three fixed stages.
        let e = env("async_fn", &[("Unresumed", &[]), ("Returned", &[])], &[]);
        assert_eq!(decline(&e), SemanticIssueKind::UnsupportedState);
        // Not an enum at all.
        let mut e = env("async_fn", FN, &[]);
        e.types.types[e.env.0 as usize] = TypeDef::Opaque {
            name: e.strings.intern("app::work::{async_fn_env#0}"),
            size: Some(32),
        };
        assert_eq!(decline(&e), SemanticIssueKind::MissingLayout);
    }

    const PRODUCER: &str = "clang LLVM (rustc version 1.98.0 (88d9e12ae 2026-08-18))";

    fn supported(convention: &'static RustcConvention) -> CompilerVerdict {
        CompilerVerdict::Supported {
            producer: PRODUCER.to_owned(),
            convention,
        }
    }

    /// A final type table with a future `app::Fut` (id 1), a `dyn Future`
    /// (2) with its data (3) and vtable (5) pointers, a sized box (6), a
    /// reference (7), a wide box (8), and `Pin`s over the box (9) and the
    /// wide box (10).
    struct Adapters {
        types: TypeTable,
        names: Vec<Option<String>>,
        strings: StringInterner,
    }

    fn adapters() -> Adapters {
        let mut strings = StringInterner::new();
        let mut names = Vec::new();
        let mut types = Vec::new();
        let mut add = |name: &str, def: TypeDef| {
            names.push(Some(name.to_owned()));
            types.push(def);
            BundleTypeId(types.len() as u32 - 1)
        };
        let usize_t = add(
            "usize",
            TypeDef::Base {
                name: strings.intern("usize"),
                size: 8,
                encoding: crate::Encoding::Unsigned,
            },
        );
        let fut = add(
            "app::Fut",
            TypeDef::Struct {
                name: strings.intern("app::Fut"),
                size: 16,
                members: vec![MemberDef {
                    name: strings.intern("state"),
                    ty: usize_t,
                    offset: 0,
                }],
            },
        );
        let dyn_name = "(dyn core::future::future::Future<Output=()> + core::marker::Send)";
        let dyn_t = add(
            dyn_name,
            TypeDef::Struct {
                name: strings.intern(dyn_name),
                size: 0,
                members: Vec::new(),
            },
        );
        let data = add(
            "*const dyn",
            TypeDef::Pointer {
                name: None,
                target: dyn_t,
            },
        );
        let slots = add(
            "[usize; 4]",
            TypeDef::Array {
                elem: usize_t,
                count: 4,
            },
        );
        let vtable = add(
            "&[usize; 4]",
            TypeDef::Pointer {
                name: Some(strings.intern("&[usize; 4]")),
                target: slots,
            },
        );
        let boxed = add(
            "alloc::boxed::Box<app::Fut, alloc::alloc::Global>",
            TypeDef::Pointer {
                name: Some(strings.intern("alloc::boxed::Box<app::Fut, alloc::alloc::Global>")),
                target: fut,
            },
        );
        let reference = add(
            "&mut app::Fut",
            TypeDef::Pointer {
                name: Some(strings.intern("&mut app::Fut")),
                target: fut,
            },
        );
        let wide_name = "alloc::boxed::Box<(dyn core::future::future::Future<Output=()> + core::marker::Send), alloc::alloc::Global>";
        let wide = add(
            wide_name,
            TypeDef::Struct {
                name: strings.intern(wide_name),
                size: 16,
                members: vec![
                    MemberDef {
                        name: strings.intern("pointer"),
                        ty: data,
                        offset: 0,
                    },
                    MemberDef {
                        name: strings.intern("vtable"),
                        ty: vtable,
                        offset: 8,
                    },
                ],
            },
        );
        for (name, inner) in [
            (
                "core::pin::Pin<alloc::boxed::Box<app::Fut, alloc::alloc::Global>>",
                boxed,
            ),
            (
                "core::pin::Pin<alloc::boxed::Box<(dyn core::future::future::Future<Output=()> + core::marker::Send), alloc::alloc::Global>>",
                wide,
            ),
        ] {
            let size = if inner == wide { 16 } else { 8 };
            add(
                name,
                TypeDef::Struct {
                    name: strings.intern(name),
                    size,
                    members: vec![MemberDef {
                        name: strings.intern("pointer"),
                        ty: inner,
                        offset: 0,
                    }],
                },
            );
        }
        let box_ref = add(
            "alloc::boxed::Box<&mut app::Fut, alloc::alloc::Global>",
            TypeDef::Pointer {
                name: Some(
                    strings.intern("alloc::boxed::Box<&mut app::Fut, alloc::alloc::Global>"),
                ),
                target: reference,
            },
        );
        add(
            "core::pin::Pin<alloc::boxed::Box<&mut app::Fut, alloc::alloc::Global>>",
            TypeDef::Struct {
                name: strings.intern(
                    "core::pin::Pin<alloc::boxed::Box<&mut app::Fut, alloc::alloc::Global>>",
                ),
                size: 8,
                members: vec![MemberDef {
                    name: strings.intern("pointer"),
                    ty: box_ref,
                    offset: 0,
                }],
            },
        );
        // tokio-util's box over the pinned wide pointer, for the
        // storage route whose target is the trait object.
        add(
            "tokio_util::sync::reusable_box::ReusableBoxFuture<()>",
            TypeDef::Struct {
                name: strings.intern("tokio_util::sync::reusable_box::ReusableBoxFuture<()>"),
                size: 16,
                members: vec![MemberDef {
                    name: strings.intern("boxed"),
                    ty: PIN_WIDE,
                    offset: 0,
                }],
            },
        );
        Adapters {
            types: TypeTable {
                types,
                ..Default::default()
            },
            names,
            strings,
        }
    }

    const FUT: BundleTypeId = BundleTypeId(1);
    const DYN: BundleTypeId = BundleTypeId(2);
    const DATA: BundleTypeId = BundleTypeId(3);
    const VTABLE: BundleTypeId = BundleTypeId(5);
    const BOX: BundleTypeId = BundleTypeId(6);
    const REF: BundleTypeId = BundleTypeId(7);
    const WIDE: BundleTypeId = BundleTypeId(8);
    const PIN_BOX: BundleTypeId = BundleTypeId(9);
    const PIN_WIDE: BundleTypeId = BundleTypeId(10);
    const BOX_REF: BundleTypeId = BundleTypeId(11);
    const PIN_BOX_REF: BundleTypeId = BundleTypeId(12);
    const REUSABLE: BundleTypeId = BundleTypeId(13);

    fn dyn_seed() -> DynSeed {
        DynSeed {
            wide: WIDE,
            pointer: "pointer".into(),
            vtable: "vtable".into(),
            data_ptr: DATA,
            vtable_ptr: VTABLE,
            trait_ty: DYN,
            future_trait: true,
            abi: supported(&RUSTC_DYN_FUTURE_ABI_V1_97),
        }
    }

    fn seed(
        kind: AdapterKind,
        pin: Option<(&str, BundleTypeId)>,
        pointee: PointeeSeed,
    ) -> AdapterSeed {
        AdapterSeed {
            kind,
            pin: pin.map(|(m, p)| (m.to_owned(), p)),
            pointee,
            compiler: supported(&RUSTC_STD_ADAPTERS_V1_97),
        }
    }

    fn steps_of(a: &Adapters, target: &Target) -> String {
        let s = |r: StrRef| a.strings.get(r).unwrap().to_owned();
        let render = |p: &TypedPath| {
            p.steps
                .iter()
                .map(|step| match step {
                    Step::Member(MemberRef::Named(n)) => s(*n),
                    Step::Deref => "*".to_owned(),
                    Step::Variant(n) => format!("::{}", s(*n)),
                    other => format!("{other:?}"),
                })
                .collect::<Vec<_>>()
                .join(".")
                + &format!(" -> {}", a.names[p.target.0 as usize].as_deref().unwrap())
        };
        match target {
            Target::Value(p) => render(p),
            Target::Dynamic {
                pointer,
                data,
                vtable,
                ..
            } => format!(
                "dyn {} [{} | {}]",
                render(pointer),
                render(data),
                render(vtable)
            ),
        }
    }

    /// Each adapter's route is the one std declares — the `Pin` member,
    /// then the thin pointer's dereference or the wide pointer's two
    /// words — held to the final table, and the same route is the
    /// adapter's storage access.
    #[test]
    fn test_adapter_plans_follow_the_declared_route() {
        let mut a = adapters();
        let cases = [
            (
                BOX,
                seed(AdapterKind::Box, None, PointeeSeed::Sized(FUT)),
                "* -> app::Fut",
                SemanticRuleKind::StdBoxPoll,
                AccessKind::Owned,
            ),
            (
                REF,
                seed(AdapterKind::MutRef, None, PointeeSeed::Sized(FUT)),
                "* -> app::Fut",
                SemanticRuleKind::StdMutRefPoll,
                AccessKind::Borrowed,
            ),
            (
                PIN_BOX,
                seed(
                    AdapterKind::PinBox,
                    Some(("pointer", BOX)),
                    PointeeSeed::Sized(FUT),
                ),
                "pointer.* -> app::Fut",
                SemanticRuleKind::StdPinBoxPoll,
                AccessKind::Owned,
            ),
            (
                PIN_WIDE,
                seed(
                    AdapterKind::PinBox,
                    Some(("pointer", WIDE)),
                    PointeeSeed::Dyn(dyn_seed()),
                ),
                "dyn pointer -> alloc::boxed::Box<(dyn core::future::future::Future<Output=()> + core::marker::Send), alloc::alloc::Global> [pointer -> *const dyn | vtable -> &[usize; 4]]",
                SemanticRuleKind::StdPinBoxPoll,
                AccessKind::Owned,
            ),
        ];
        for (ty, seed, expected, rule, access) in cases {
            let plan = plan_adapter(ty, &seed, &a.types, &mut a.strings)
                .unwrap_or_else(|e| panic!("{expected}: {e:?}"));
            let Delegation::Direct { target, exclusive } = plan.program.as_ref().unwrap() else {
                panic!("adapters delegate directly");
            };
            assert!(exclusive, "{expected}");
            assert_eq!(steps_of(&a, target), expected);
            assert!(matches!(&plan.rule, RuleKey::Rustc { kind, family, .. }
                if *kind == rule && *family == "rustc-std-adapters-1.97"));
            let (_, kind, access_target) = plan.access.as_ref().unwrap();
            assert_eq!(*kind, access);
            assert_eq!(access_target, target);
            if let Target::Dynamic { abi, .. } = target {
                assert!(
                    matches!(abi, RuleKey::Rustc { kind: SemanticRuleKind::DynFutureAbi, family, .. }
                    if *family == "rustc-dyn-future-abi-1.97")
                );
            }
        }
    }

    /// A container's rule: the two sets under their library's one
    /// layout origin, whatever the seed says; the map under
    /// tokio-stream's delegation origin read off the type's own method
    /// declarations, declining — with no container — where those are
    /// missing, off the registry, another crate's, or at a version on
    /// either side of the reviewed range.
    #[test]
    fn test_the_map_container_rule_reads_the_type_origin() {
        let typed = |path: &str| Seed {
            type_sources: BTreeSet::from([source(path, None)]),
            ..Seed::default()
        };
        let registry = |package: &str, version: &str| {
            typed(&format!(
                "/home/u/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/\
                 {package}-{version}/src/stream_map.rs"
            ))
        };
        for kind in [ContainerKind::JoinSet, ContainerKind::FuturesUnordered] {
            let rule = container_rule(kind, &Seed::default()).unwrap();
            assert!(matches!(rule, RuleKey::Library(_)), "{kind:?}: {rule:?}");
        }
        let rule = container_rule(
            ContainerKind::StreamMap,
            &registry("tokio-stream", "0.1.19"),
        )
        .unwrap();
        assert!(
            matches!(&rule, RuleKey::Delegation { kind: SemanticRuleKind::TokioStreamStreamMap, origin }
            if origin.package == "tokio-stream" && origin.version == "0.1.19"
                && origin.family == TOKIO_STREAM_MAP_V0_1_14.family),
            "{rule:?}"
        );
        let reviewed = TOKIO_STREAM_MAP_V0_1_14.checksums[4].1;
        let checked = Seed {
            type_sources: BTreeSet::from([source(
                "/home/u/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/\
                 tokio-stream-0.1.19/src/stream_map.rs",
                Some(reviewed),
            )]),
            ..Seed::default()
        };
        assert!(container_rule(ContainerKind::StreamMap, &checked).is_ok());
        for (seed, expected) in [
            (Seed::default(), "no method declaration"),
            (
                typed("/build/vendor/tokio-stream-0.1.19/src/stream_map.rs"),
                "not a cargo registry path",
            ),
            (
                registry("tokio-util", "0.7.19"),
                "not the tokio-stream crate",
            ),
            (
                registry("tokio-stream", "0.1.13"),
                "below the reviewed range",
            ),
            (
                registry("tokio-stream", "0.1.20"),
                "above the reviewed range",
            ),
            (
                Seed {
                    type_sources: BTreeSet::from([source(
                        "/home/u/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/\
                         tokio-stream-0.1.19/src/stream_map.rs",
                        Some([9; 16]),
                    )]),
                    ..Seed::default()
                },
                "not a reviewed revision",
            ),
        ] {
            let (kind, detail) = container_rule(ContainerKind::StreamMap, &seed).unwrap_err();
            assert_eq!(kind, SemanticIssueKind::UnsupportedOrigin, "{detail}");
            assert!(detail.contains(expected), "{detail}");
        }
    }

    /// tokio-util's box plans an owned access and no program: the route
    /// runs through `boxed` and the `Pin`'s member to the wide pointer,
    /// whose two words the dyn join reads, under the tokio-util origin
    /// read off the type's own method declarations. A `Pin` whose
    /// member is not the box the screen saw declines on the layout; no
    /// method declaration, or one off the registry, declines before it.
    #[test]
    fn test_the_reusable_box_plans_an_owned_dynamic_access() {
        let mut a = adapters();
        let typed = |path: &str| Seed {
            type_sources: BTreeSet::from([source(path, None)]),
            ..Seed::default()
        };
        let registry = typed(
            "/home/u/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/\
             tokio-util-0.7.19/src/sync/reusable_box.rs",
        );
        let layout = |pin| LibrarySeed::ReusableBox {
            boxed: "boxed".into(),
            pin: ("pointer".into(), pin),
            dyn_: dyn_seed(),
        };
        let plan =
            plan_library(REUSABLE, &layout(WIDE), &registry, &a.types, &mut a.strings).unwrap();
        assert!(
            plan.program.is_none(),
            "a storage route polls nothing itself"
        );
        assert!(plan.delegate_is_future);
        let (rule, kind, target) = plan.access.as_ref().unwrap();
        assert_eq!(*kind, AccessKind::Owned);
        assert!(
            matches!(rule, RuleKey::Delegation { kind: SemanticRuleKind::TokioUtilReusableBox, origin }
            if origin.package == "tokio-util" && origin.version == "0.7.19"
                && origin.family == TOKIO_UTIL_REUSABLE_BOX_V0_7_11.family)
        );
        assert_eq!(&plan.rule, rule);
        assert_eq!(
            steps_of(&a, target),
            "dyn boxed.pointer -> alloc::boxed::Box<(dyn core::future::future::Future<Output=()> \
             + core::marker::Send), alloc::alloc::Global> [pointer -> *const dyn | vtable -> \
             &[usize; 4]]"
        );
        let (kind, detail) =
            plan_library(REUSABLE, &layout(BOX), &registry, &a.types, &mut a.strings).unwrap_err();
        assert_eq!(kind, SemanticIssueKind::MissingLayout);
        assert!(detail.contains("Pin's member"), "{detail}");
        for (seed, expected) in [
            (Seed::default(), "no method declaration"),
            (
                typed("/build/vendor/tokio-util-0.7.19/src/sync/reusable_box.rs"),
                "not a cargo registry path",
            ),
            (
                typed(
                    "/home/u/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/\
                     tokio-util-0.7.20/src/sync/reusable_box.rs",
                ),
                "above the reviewed range",
            ),
        ] {
            let (kind, detail) =
                plan_library(REUSABLE, &layout(WIDE), &seed, &a.types, &mut a.strings).unwrap_err();
            assert_eq!(kind, SemanticIssueKind::UnsupportedOrigin, "{detail}");
            assert!(detail.contains(expected), "{detail}");
        }
    }

    /// A route that the final table does not bear out declines with the
    /// reason, as does an adapter compiled outside the reviewed range or
    /// a wide pointer whose ABI was.
    #[test]
    fn test_adapter_plans_decline_layout_and_origin_departures() {
        let mut a = adapters();
        let kind_of = |result: Result<Plan, Decline>| result.unwrap_err().0;
        // The declared pointee is not what the pointer targets.
        let s = seed(AdapterKind::Box, None, PointeeSeed::Sized(DYN));
        assert_eq!(
            kind_of(plan_adapter(BOX, &s, &a.types, &mut a.strings)),
            SemanticIssueKind::MissingLayout
        );
        // Pin's member is not its declared pointer.
        let s = seed(
            AdapterKind::PinBox,
            Some(("pointer", REF)),
            PointeeSeed::Sized(FUT),
        );
        assert_eq!(
            kind_of(plan_adapter(PIN_BOX, &s, &a.types, &mut a.strings)),
            SemanticIssueKind::MissingLayout
        );
        // The wide pointer's trait object grew a member.
        let mut grown = adapters();
        if let TypeDef::Struct { members, .. } = &mut grown.types.types[DYN.0 as usize] {
            members.push(MemberDef {
                name: grown.strings.intern("x"),
                ty: BundleTypeId(0),
                offset: 0,
            });
        }
        let s = seed(AdapterKind::Box, None, PointeeSeed::Dyn(dyn_seed()));
        assert_eq!(
            kind_of(plan_adapter(WIDE, &s, &grown.types, &mut grown.strings)),
            SemanticIssueKind::MissingLayout
        );
        // Outside the reviewed toolchains, on either review.
        let mut s = seed(AdapterKind::Box, None, PointeeSeed::Sized(FUT));
        s.compiler = CompilerVerdict::Declined("rustc 1.99".into());
        assert_eq!(
            kind_of(plan_adapter(BOX, &s, &a.types, &mut a.strings)),
            SemanticIssueKind::UnsupportedOrigin
        );
        let mut d = dyn_seed();
        d.abi = CompilerVerdict::Declined("rustc 1.99".into());
        let s = seed(AdapterKind::Box, None, PointeeSeed::Dyn(d));
        assert_eq!(
            kind_of(plan_adapter(WIDE, &s, &a.types, &mut a.strings)),
            SemanticIssueKind::UnsupportedOrigin
        );
        // The supported case still plans, so the declines above were
        // the departures and not the fixture.
        let s = seed(AdapterKind::Box, None, PointeeSeed::Dyn(dyn_seed()));
        plan_adapter(WIDE, &s, &a.types, &mut a.strings).unwrap();
    }

    fn source(path: &str, md5: Option<[u8; 16]>) -> PollSource {
        PollSource {
            path: path.to_owned(),
            md5,
        }
    }

    const REGISTRY: &str = "/home/u/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/tracing-0.1.40/src/instrument.rs";

    /// The origin is what every poll declaration agrees on: a registry
    /// path naming tracing at a reviewed version, with any checksum a
    /// reviewed one. Each departure declines and says which.
    #[test]
    fn test_instrumented_origin_reads_the_registry_path() {
        let reviewed = crate::detect::semantics::TRACING_INSTRUMENTED_V0_1_40.checksums[0].1;
        let origin = delegation_origin(
            &BTreeSet::from([source(REGISTRY, None)]),
            &TRACING_INSTRUMENTED_V0_1_40,
            "poll",
        )
        .unwrap();
        assert_eq!(
            origin,
            DelegationOrigin {
                package: "tracing",
                version: "0.1.40".into(),
                family: "tracing-instrumented-0.1.40",
                source:
                    "registry/src/index.crates.io-1949cf8c6b5b557f/tracing-0.1.40/src/instrument.rs"
                        .into(),
                files: Vec::new(),
            }
        );
        // A checksum the table carried is recorded when reviewed.
        let origin = delegation_origin(
            &BTreeSet::from([source(REGISTRY, Some(reviewed))]),
            &TRACING_INSTRUMENTED_V0_1_40,
            "poll",
        )
        .unwrap();
        assert_eq!(origin.files.len(), 1);
        assert_eq!(origin.files[0].1, reviewed);
        // Two declarations on the same path agree.
        delegation_origin(
            &BTreeSet::from([source(REGISTRY, None), source(REGISTRY, Some(reviewed))]),
            &TRACING_INSTRUMENTED_V0_1_40,
            "poll",
        )
        .unwrap();
        let declined = |sources: &[PollSource]| {
            let (kind, detail) = delegation_origin(
                &sources.iter().cloned().collect(),
                &TRACING_INSTRUMENTED_V0_1_40,
                "poll",
            )
            .unwrap_err();
            assert_eq!(kind, SemanticIssueKind::UnsupportedOrigin, "{detail}");
            detail
        };
        assert!(declined(&[]).contains("no poll declaration"));
        assert!(
            declined(&[source(
                "/build/vendor/tracing-0.1.40/src/instrument.rs",
                None
            )])
            .contains("not a cargo registry path")
        );
        assert!(
            declined(&[source(
                "/home/u/.cargo/git/checkouts/tracing-1a2b3c4d5e6f7a8b/0123abc/tracing/src/instrument.rs",
                None
            )])
            .contains("not a cargo registry path")
        );
        assert!(
            declined(&[source("/home/u/tracing/src/instrument.rs", None)])
                .contains("not a cargo registry path")
        );
        assert!(
            declined(&[source(
                "/home/u/.cargo/registry/src/idx/tracing-core-0.1.40/src/instrument.rs",
                None
            )])
            .contains("not the tracing crate")
        );
        assert!(
            declined(&[source(
                "/home/u/.cargo/registry/src/idx/tracing-0.1.39/src/instrument.rs",
                None
            )])
            .contains("0.1.39 is below the reviewed range 0.1.40–0.1.44")
        );
        assert!(
            declined(&[source(
                "/home/u/.cargo/registry/src/idx/tracing-0.1.45/src/instrument.rs",
                None
            )])
            .contains("0.1.45 is above the reviewed range 0.1.40–0.1.44")
        );
        assert!(
            declined(&[
                source(REGISTRY, None),
                source(
                    "/home/u/.cargo/registry/src/idx/tracing-0.1.41/src/instrument.rs",
                    None
                ),
            ])
            .contains("declared in both")
        );
        let mismatch = declined(&[source(REGISTRY, Some([0xab; 16]))]);
        assert!(
            mismatch.contains(&format!(
                "has checksum {}, not a reviewed revision of tracing-instrumented-0.1.40",
                "ab".repeat(16)
            )),
            "{mismatch}"
        );
    }

    /// Which screen a type is offered to is decided by where it is
    /// defined, and the name that routes it is the exact one each
    /// crate's own type has. A type under a name no rule claims is
    /// offered to none, and a screen that refuses leaves no seed.
    #[test]
    fn test_library_seeds_route_by_the_definition_path() {
        use crate::raw_types::{NsId, RawMember, RawStruct, RawType};
        use gimli::UnitSectionOffset;

        let mut reader = crate::DwReader::default();
        let ns = |reader: &mut crate::DwReader<'static>, path: &'static str| -> NsId {
            let mut at = None;
            for segment in path.split("::") {
                let name = reader.strings.intern(segment);
                at = Some(reader.namespaces.insert(at, name));
            }
            at.expect("a namespace path has segments")
        };
        let sleep_mod = ns(&mut reader, "tokio::time::sleep");
        let rt = ns(&mut reader, "hyper_util::rt::tokio");
        let into_mod = ns(&mut reader, "futures_util::future::try_future::into_future");
        let coop_mod = ns(&mut reader, "tokio::task::coop");
        let id = |offset: usize| TypeId(UnitSectionOffset(offset));
        let (sleep, tokio_sleep, into, fut, coop) = (id(1), id(2), id(3), id(4), id(5));
        let strukt = |reader: &mut crate::DwReader<'static>,
                      at: TypeId,
                      namespace: NsId,
                      name: &'static str,
                      member: Option<(&'static str, TypeId)>,
                      param: Option<(&'static str, TypeId)>| {
            let name = Some(reader.strings.intern(name));
            let members = member
                .map(|(name, type_id)| RawMember {
                    name: Some(reader.strings.intern(name)),
                    offset: 0,
                    type_id,
                    source_loc: None,
                })
                .into_iter()
                .collect();
            let template_params = param
                .map(|(name, type_id)| crate::raw_types::RawGenericParameter {
                    name: Some(reader.strings.intern(name)),
                    type_id,
                })
                .into_iter()
                .collect();
            reader.types.insert(
                at,
                RawType::Struct(RawStruct {
                    name,
                    namespace: Some(namespace),
                    size: 8,
                    members,
                    template_params,
                    source_loc: None,
                }),
            );
        };
        strukt(&mut reader, sleep, sleep_mod, "Sleep", None, None);
        strukt(&mut reader, fut, sleep_mod, "Fut", None, None);
        strukt(
            &mut reader,
            tokio_sleep,
            rt,
            "TokioSleep",
            Some(("inner", sleep)),
            None,
        );
        strukt(
            &mut reader,
            into,
            into_mod,
            "IntoFuture<tokio::time::sleep::Fut>",
            Some(("future", fut)),
            Some(("Fut", fut)),
        );
        strukt(
            &mut reader,
            coop,
            coop_mod,
            "Coop<tokio::time::sleep::Fut>",
            Some(("fut", fut)),
            Some(("F", fut)),
        );
        // The stream routes: `Next<St>` over a `&mut St`, and a
        // `WatchStream` whose `inner` is tokio-util's box by that
        // type's own declaration.
        let next_mod = ns(&mut reader, "futures_util::stream::stream::next");
        let watch_mod = ns(&mut reader, "tokio_stream::wrappers::watch");
        let reusable_mod = ns(&mut reader, "tokio_util::sync::reusable_box");
        let (st, ref_st, next, reusable, watch) = (id(6), id(7), id(8), id(9), id(10));
        strukt(&mut reader, st, sleep_mod, "St", None, None);
        reader.types.insert(
            ref_st,
            RawType::Pointer(crate::raw_types::RawPointer {
                name: Some(reader.strings.intern("&mut tokio::time::sleep::St")),
                target_type_id: st,
            }),
        );
        strukt(
            &mut reader,
            next,
            next_mod,
            "Next<tokio::time::sleep::St>",
            Some(("stream", ref_st)),
            Some(("St", st)),
        );
        strukt(
            &mut reader,
            reusable,
            reusable_mod,
            "ReusableBoxFuture<()>",
            Some(("boxed", fut)),
            None,
        );
        strukt(
            &mut reader,
            watch,
            watch_mod,
            "WatchStream<u32>",
            Some(("inner", reusable)),
            Some(("T", fut)),
        );
        let bundle_id = |raw: TypeId| Some(BundleTypeId(raw.0.0 as u32));
        let seed = |raw, name: &str| library_seed(&reader, raw, name, bundle_id, |_| None);
        assert!(matches!(
            seed(next, "futures_util::stream::stream::next::Next<tokio::time::sleep::St>"),
            Some(LibrarySeed::Next(member, target)) if member == "stream" && target == bundle_id(st).unwrap()
        ));
        assert!(matches!(
            seed(watch, "tokio_stream::wrappers::watch::WatchStream<u32>"),
            Some(LibrarySeed::WatchStream(member, inner)) if member == "inner" && inner == bundle_id(reusable).unwrap()
        ));
        // The box's screen needs a pinned wide pointer, which this
        // table does not carry: the name reaches the screen, the
        // screen refuses.
        assert!(
            seed(
                reusable,
                "tokio_util::sync::reusable_box::ReusableBoxFuture<()>"
            )
            .is_none()
        );
        assert!(matches!(
            seed(tokio_sleep, "hyper_util::rt::tokio::TokioSleep"),
            Some(LibrarySeed::TokioSleep(member, _)) if member == "inner"
        ));
        assert!(matches!(
            seed(coop, "tokio::task::coop::Coop<tokio::time::sleep::Fut>"),
            Some(LibrarySeed::Coop(member, _)) if member == "fut"
        ));
        assert!(matches!(
            seed(
                into,
                "futures_util::future::try_future::into_future::IntoFuture<tokio::time::sleep::Fut>"
            ),
            Some(LibrarySeed::IntoFuture(member, _)) if member == "future"
        ));
        // The name is the route: the same layout under any other name
        // reaches no screen, and a name whose screen refuses seeds
        // nothing either.
        for (raw, name) in [
            (tokio_sleep, "hyper_util::rt::tokio::TokioSleeper"),
            (tokio_sleep, "TokioSleep"),
            (tokio_sleep, "app::TokioSleep"),
            (sleep, "hyper_util::rt::tokio::TokioSleep"),
            (
                sleep,
                "futures_util::future::try_future::into_future::IntoFuture<x>",
            ),
            (coop, "tokio::task::Coop<tokio::time::sleep::Fut>"),
            (fut, "tokio::task::coop::Coop<tokio::time::sleep::Fut>"),
            (
                next,
                "tokio_stream::StreamExt::next::Next<tokio::time::sleep::St>",
            ),
            (watch, "tokio_stream::wrappers::WatchStream<u32>"),
            (
                st,
                "futures_util::stream::stream::next::Next<tokio::time::sleep::St>",
            ),
        ] {
            assert!(seed(raw, name).is_none(), "{name}");
        }
    }

    /// Each reviewed third-party convention reads its origin off the
    /// registry path its own `poll` was declared on, and every
    /// departure declines with the reason: a tree that is not the
    /// registry's, another crate's, a version outside the range, two
    /// declarations disagreeing, or a checksum that is not a reviewed
    /// revision.
    #[test]
    fn test_every_delegation_origin_is_read_off_its_registry_path() {
        const ROOT: &str = "/home/u/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f";
        for (convention, version, file, other) in [
            (
                &FUTURES_UTIL_ADAPTERS_V0_3_30,
                "0.3.33",
                "src/future/future/map.rs",
                "futures-core",
            ),
            (
                &HYPER_UTIL_TOKIO_SLEEP_V0_1_10,
                "0.1.20",
                "src/rt/tokio.rs",
                "hyper",
            ),
            (
                &TOKIO_STREAM_WATCH_V0_1_14,
                "0.1.19",
                "src/wrappers/watch.rs",
                "tokio",
            ),
            (
                &TOKIO_UTIL_REUSABLE_BOX_V0_7_11,
                "0.7.19",
                "src/sync/reusable_box.rs",
                "tokio",
            ),
        ] {
            let package = convention.package;
            let at = |version: &str| format!("{ROOT}/{package}-{version}/{file}");
            let origin = delegation_origin(
                &BTreeSet::from([source(&at(version), None)]),
                convention,
                "poll",
            )
            .unwrap();
            assert_eq!(
                origin,
                DelegationOrigin {
                    package,
                    version: version.to_owned(),
                    family: convention.family,
                    source: at(version)
                        .strip_prefix("/home/u/.cargo/")
                        .unwrap()
                        .to_owned(),
                    files: Vec::new(),
                }
            );
            let reviewed = convention.checksums[0].1;
            let origin = delegation_origin(
                &BTreeSet::from([source(&at(version), Some(reviewed))]),
                convention,
                "poll",
            )
            .unwrap();
            assert_eq!(origin.files.len(), 1);
            let declined = |sources: &[PollSource]| {
                let (kind, detail) =
                    delegation_origin(&sources.iter().cloned().collect(), convention, "poll")
                        .unwrap_err();
                assert_eq!(kind, SemanticIssueKind::UnsupportedOrigin, "{detail}");
                detail
            };
            assert!(declined(&[]).contains("no poll declaration"));
            for path in [
                format!("/build/vendor/{package}-{version}/{file}"),
                format!("/home/u/.cargo/git/checkouts/{package}-1a2b3c4d5e6f7a8b/0123abc/{file}"),
                format!("/home/u/{package}/{file}"),
            ] {
                assert!(
                    declined(&[source(&path, None)]).contains("not a cargo registry path"),
                    "{path}"
                );
            }
            assert!(
                declined(&[source(&format!("{ROOT}/{other}-{version}/{file}"), None)])
                    .contains(&format!("not the {package} crate"))
            );
            // The release just below the floor: the previous patch, or
            // the previous minor where the floor is a `.0`.
            let (a, b, c) = convention.floor;
            let below = match c {
                0 => format!("{a}.{}.0", b - 1),
                c => format!("{a}.{b}.{}", c - 1),
            };
            let (x, y, z) = convention.ceiling;
            let above = format!("{x}.{y}.{}", z + 1);
            assert!(
                declined(&[source(&at(&below), None)])
                    .contains(&format!("{package} {below} is below the reviewed range"))
            );
            assert!(
                declined(&[source(&at(&above), None)])
                    .contains(&format!("{package} {above} is above the reviewed range"))
            );
            assert!(
                declined(&[
                    source(&at(version), None),
                    source(&format!("{ROOT}/{package}-{version}/src/other.rs"), None),
                ])
                .contains("declared in both")
            );
            assert!(
                declined(&[source(&at(version), Some([0xab; 16]))])
                    .contains("not a reviewed revision of")
            );
        }
    }

    /// The reviewed wrappers plan one exclusive forward each — through
    /// the member their implementation polls — and `Map` plans a case
    /// per state: its incomplete one delegates into the future it holds,
    /// its complete one has already returned. A member holding another
    /// type than the screen declared plans nothing.
    #[test]
    fn test_the_reviewed_wrappers_plan_one_forward_each() {
        let mut strings = StringInterner::new();
        let mut names: Vec<Option<String>> = Vec::new();
        let mut types: Vec<TypeDef> = Vec::new();
        let mut add = |name: &str, def: TypeDef| {
            names.push(Some(name.to_owned()));
            types.push(def);
            BundleTypeId(types.len() as u32 - 1)
        };
        let fut = add(
            "app::Fut",
            TypeDef::Struct {
                name: strings.intern("app::Fut"),
                size: 8,
                members: Vec::new(),
            },
        );
        let sleep = add(
            "tokio::time::sleep::Sleep",
            TypeDef::Struct {
                name: strings.intern("tokio::time::sleep::Sleep"),
                size: 8,
                members: Vec::new(),
            },
        );
        let one = |strings: &mut StringInterner, name: &str, member: &str, ty| TypeDef::Struct {
            name: strings.intern(name),
            size: 8,
            members: vec![MemberDef {
                name: strings.intern(member),
                ty,
                offset: 0,
            }],
        };
        let tokio_sleep = {
            let def = one(
                &mut strings,
                "hyper_util::rt::tokio::TokioSleep",
                "inner",
                sleep,
            );
            add("hyper_util::rt::tokio::TokioSleep", def)
        };
        let coop = {
            let def = one(
                &mut strings,
                "tokio::task::coop::Coop<app::Fut>",
                "fut",
                fut,
            );
            add("tokio::task::coop::Coop<app::Fut>", def)
        };
        let into = {
            let def = one(
                &mut strings,
                "futures_util::future::try_future::into_future::IntoFuture<app::Fut>",
                "future",
                fut,
            );
            add(
                "futures_util::future::try_future::into_future::IntoFuture<app::Fut>",
                def,
            )
        };
        let incomplete = add(
            "map::Map::Incomplete",
            TypeDef::Struct {
                name: strings.intern("map::Map::Incomplete"),
                size: 8,
                members: vec![MemberDef {
                    name: strings.intern("future"),
                    ty: fut,
                    offset: 0,
                }],
            },
        );
        let complete = add(
            "map::Map::Complete",
            TypeDef::Struct {
                name: strings.intern("map::Map::Complete"),
                size: 0,
                members: Vec::new(),
            },
        );
        let variant = |strings: &mut StringInterner, name: &str, ty| VariantDef {
            name: strings.intern(name),
            discr_values: None,
            payload: MemberDef {
                name: strings.intern(name),
                ty,
                offset: 0,
            },
            decl: None,
            await_site: None,
        };
        let map = {
            let variants = vec![
                variant(&mut strings, "Incomplete", incomplete),
                variant(&mut strings, "Complete", complete),
            ];
            let def = TypeDef::Enum {
                name: strings.intern("futures_util::future::future::map::Map<app::Fut, app::Fn>"),
                size: 16,
                shape: VariantShape {
                    discr: None,
                    variants,
                },
            };
            add(
                "futures_util::future::future::map::Map<app::Fut, app::Fn>",
                def,
            )
        };
        let types = TypeTable {
            types,
            ..Default::default()
        };
        let registry = |package: &str, version: &str, file: &str| Seed {
            poll_sources: BTreeSet::from([source(
                &format!(
                    "/home/u/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/\
                     {package}-{version}/{file}"
                ),
                None,
            )]),
            ..Seed::default()
        };
        let futures_util = registry("futures-util", "0.3.33", "src/lib.rs");
        let hyper_util = registry("hyper-util", "0.1.20", "src/rt/tokio.rs");
        // No declaration at all: what a `poll` the optimizer folded
        // into another instantiation's leaves behind.
        let unproven = Seed::default();
        let render = |strings: &StringInterner, path: &TypedPath| {
            path.steps
                .iter()
                .map(|step| match step {
                    Step::Member(MemberRef::Named(n)) => strings.get(*n).unwrap().to_owned(),
                    Step::Variant(n) => format!("::{}", strings.get(*n).unwrap()),
                    other => format!("{other:?}"),
                })
                .collect::<Vec<_>>()
                .join(".")
        };
        // hyper-util's sleep is proved by its poll's origin; a
        // sole-member forwarder by its layout alone, under the crate's
        // layout origin, with nothing declared anywhere.
        for (ty, seed_layout, seed, expected, target, rule) in [
            (
                tokio_sleep,
                LibrarySeed::TokioSleep("inner".into(), sleep),
                &hyper_util,
                "inner",
                sleep,
                None,
            ),
            (
                into,
                LibrarySeed::IntoFuture("future".into(), fut),
                &unproven,
                "future",
                fut,
                Some(RuleKey::Library(SemanticRuleKind::FuturesUtilIntoFuture)),
            ),
            (
                coop,
                LibrarySeed::Coop("fut".into(), fut),
                &unproven,
                "fut",
                fut,
                Some(RuleKey::Library(SemanticRuleKind::TokioCoop)),
            ),
        ] {
            let plan = plan_library(ty, &seed_layout, seed, &types, &mut strings).unwrap();
            match rule {
                Some(rule) => assert_eq!(plan.rule, rule),
                None => assert!(
                    matches!(
                        plan.rule,
                        RuleKey::Delegation {
                            kind: SemanticRuleKind::HyperUtilTokioSleep,
                            ..
                        }
                    ),
                    "{:?}",
                    plan.rule
                ),
            }
            let Delegation::Direct {
                target: t,
                exclusive,
            } = plan.program.as_ref().unwrap()
            else {
                panic!("a wrapper forwards directly");
            };
            assert!(exclusive, "a reviewed forward polls its delegate alone");
            let Target::Value(path) = t else {
                panic!("a wrapper forwards to a value");
            };
            assert_eq!(render(&strings, path), expected);
            assert_eq!(path.target, target);
            assert!(plan.access.is_none(), "a wrapper is not a pointer");
        }
        // The map's two states, and the one member the incomplete one
        // polls.
        let layout = LibrarySeed::Map {
            incomplete: "Incomplete".into(),
            future_member: "future".into(),
            complete: "Complete".into(),
            future: fut,
        };
        let plan = plan_library(map, &layout, &futures_util, &types, &mut strings).unwrap();
        let Delegation::Match { cases } = plan.program.as_ref().unwrap() else {
            panic!("a map matches its state");
        };
        let [
            (incomplete_name, CaseAction::Delegate(target)),
            (_, CaseAction::Returned),
        ] = cases.as_slice()
        else {
            panic!("the incomplete state delegates and the complete one has returned");
        };
        assert_eq!(strings.get(*incomplete_name), Some("Incomplete"));
        let Target::Value(path) = target.as_ref() else {
            panic!("a map delegates to a value");
        };
        assert_eq!(render(&strings, path), "::Incomplete.future");
        assert_eq!(path.target, fut);
        // A member the screen's declared type no longer matches.
        let wrong = LibrarySeed::TokioSleep("inner".into(), fut);
        let (kind, detail) =
            plan_library(tokio_sleep, &wrong, &hyper_util, &types, &mut strings).unwrap_err();
        assert_eq!(kind, SemanticIssueKind::MissingLayout);
        assert!(
            detail.contains("another type than the screen declared"),
            "{detail}"
        );
        // And an origin no review covers stops before the layout.
        let vendored = Seed {
            poll_sources: BTreeSet::from([source(
                "/build/vendor/hyper-util-0.1.20/src/rt/tokio.rs",
                None,
            )]),
            ..Seed::default()
        };
        let (kind, _) = plan_library(
            tokio_sleep,
            &LibrarySeed::TokioSleep("inner".into(), sleep),
            &vendored,
            &types,
            &mut strings,
        )
        .unwrap_err();
        assert_eq!(kind, SemanticIssueKind::UnsupportedOrigin);

        // The stream routes. `Next` forwards through its `&mut` to the
        // stream itself — a dereference on the route — exclusively,
        // and proves the stream nothing; a `WatchStream` is an owned
        // access into its box and no program, under an origin read off
        // the type's own methods rather than a poll it does not have.
        let mut types = types.types;
        let mut add = |_name: &str, def: TypeDef| {
            types.push(def);
            BundleTypeId(types.len() as u32 - 1)
        };
        let st = add(
            "app::St",
            TypeDef::Struct {
                name: strings.intern("app::St"),
                size: 8,
                members: Vec::new(),
            },
        );
        let ref_st = add(
            "&mut app::St",
            TypeDef::Pointer {
                name: Some(strings.intern("&mut app::St")),
                target: st,
            },
        );
        let next = {
            let def = one(
                &mut strings,
                "futures_util::stream::stream::next::Next<app::St>",
                "stream",
                ref_st,
            );
            add("futures_util::stream::stream::next::Next<app::St>", def)
        };
        let by_value = {
            let def = one(
                &mut strings,
                "futures_util::stream::stream::next::Next<app::St>",
                "stream",
                st,
            );
            add("futures_util::stream::stream::next::Next<app::St>", def)
        };
        let watch = {
            let def = one(
                &mut strings,
                "tokio_stream::wrappers::watch::WatchStream<u32>",
                "inner",
                sleep,
            );
            add("tokio_stream::wrappers::watch::WatchStream<u32>", def)
        };
        let types = TypeTable {
            types,
            ..Default::default()
        };
        let plan = plan_library(
            next,
            &LibrarySeed::Next("stream".into(), st),
            &registry("futures-util", "0.3.33", "src/stream/stream/next.rs"),
            &types,
            &mut strings,
        )
        .unwrap();
        let Some(Delegation::Direct { target, exclusive }) = &plan.program else {
            panic!("`Next` forwards directly");
        };
        assert!(exclusive, "`Next` polls its stream alone");
        let Target::Value(path) = target else {
            panic!("`Next` forwards to a value");
        };
        assert_eq!(render(&strings, path), "stream.Deref");
        assert_eq!(path.target, st);
        assert!(plan.access.is_none());
        assert!(!plan.delegate_is_future, "a stream is proved nothing");
        let (kind, detail) = plan_library(
            by_value,
            &LibrarySeed::Next("stream".into(), st),
            &registry("futures-util", "0.3.33", "src/stream/stream/next.rs"),
            &types,
            &mut strings,
        )
        .unwrap_err();
        assert_eq!(kind, SemanticIssueKind::MissingLayout);
        assert!(detail.contains("not a reference"), "{detail}");
        let typed = |path: &str| Seed {
            type_sources: BTreeSet::from([source(path, None)]),
            ..Seed::default()
        };
        let plan = plan_library(
            watch,
            &LibrarySeed::WatchStream("inner".into(), sleep),
            &typed(
                "/home/u/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/\
                 tokio-stream-0.1.19/src/wrappers/watch.rs",
            ),
            &types,
            &mut strings,
        )
        .unwrap();
        assert!(
            plan.program.is_none(),
            "a storage route polls nothing itself"
        );
        let (rule, kind, target) = plan.access.as_ref().unwrap();
        assert_eq!(*kind, AccessKind::Owned);
        assert_eq!(rule, &plan.rule);
        assert!(
            matches!(rule, RuleKey::Delegation { kind: SemanticRuleKind::TokioStreamWatchStream, origin }
            if origin.package == "tokio-stream" && origin.version == "0.1.19")
        );
        let Target::Value(path) = target else {
            panic!("the stream's access is a value route");
        };
        assert_eq!(render(&strings, path), "inner");
        assert_eq!(path.target, sleep);
        // The stream's poll sources are nobody's evidence: only its
        // own methods' declarations count, and none is a decline of
        // its own kind.
        for (seed, expected) in [
            (
                registry("tokio-stream", "0.1.19", "src/wrappers/watch.rs"),
                "no method declaration",
            ),
            (
                typed("/build/vendor/tokio-stream-0.1.19/src/wrappers/watch.rs"),
                "not a cargo registry path",
            ),
            (
                typed(
                    "/home/u/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/\
                     tokio-stream-0.1.13/src/wrappers/watch.rs",
                ),
                "below the reviewed range",
            ),
        ] {
            let (kind, detail) = plan_library(
                watch,
                &LibrarySeed::WatchStream("inner".into(), sleep),
                &seed,
                &types,
                &mut strings,
            )
            .unwrap_err();
            assert_eq!(kind, SemanticIssueKind::UnsupportedOrigin, "{detail}");
            assert!(detail.contains(expected), "{detail}");
        }
    }

    /// A `select!` plan: the origin off the closure's declaration file,
    /// then the two capture routes and one per tuple member, each held
    /// to the final table. A closure declared outside the registry, in
    /// another crate or at an unreviewed version declines before the
    /// layout; a mask that is not an unsigned word, a tuple member
    /// holding another type than the screen saw, or a member missing
    /// from the table decline on the layout.
    #[test]
    fn test_the_select_plan_reads_the_captures_and_the_tuple() {
        let mut strings = StringInterner::new();
        let mut types: Vec<TypeDef> = Vec::new();
        let mut add = |name: &str, def: TypeDef| {
            let _ = name;
            types.push(def);
            BundleTypeId(types.len() as u32 - 1)
        };
        let u8_t = add(
            "u8",
            TypeDef::Base {
                name: strings.intern("u8"),
                size: 1,
                encoding: crate::Encoding::Unsigned,
            },
        );
        let i8_t = add(
            "i8",
            TypeDef::Base {
                name: strings.intern("i8"),
                size: 1,
                encoding: crate::Encoding::Signed,
            },
        );
        let fut = add(
            "app::Fut",
            TypeDef::Struct {
                name: strings.intern("app::Fut"),
                size: 8,
                members: Vec::new(),
            },
        );
        let other = add(
            "app::Other",
            TypeDef::Struct {
                name: strings.intern("app::Other"),
                size: 8,
                members: Vec::new(),
            },
        );
        let member = |strings: &mut StringInterner, name: &str, ty, offset| MemberDef {
            name: strings.intern(name),
            ty,
            offset,
        };
        let first = member(&mut strings, "__0", fut, 0);
        let second = member(&mut strings, "__1", other, 8);
        let tuple = add(
            "(app::Fut, app::Other)",
            TypeDef::Struct {
                name: strings.intern("(app::Fut, app::Other)"),
                size: 16,
                members: vec![first, second],
            },
        );
        let mask_ref = add(
            "&mut u8",
            TypeDef::Pointer {
                name: Some(strings.intern("&mut u8")),
                target: u8_t,
            },
        );
        let signed_ref = add(
            "&mut i8",
            TypeDef::Pointer {
                name: Some(strings.intern("&mut i8")),
                target: i8_t,
            },
        );
        let tuple_ref = add(
            "&mut (app::Fut, app::Other)",
            TypeDef::Pointer {
                name: Some(strings.intern("&mut (app::Fut, app::Other)")),
                target: tuple,
            },
        );
        let disabled = member(&mut strings, "_ref__disabled", mask_ref, 0);
        let futures = member(&mut strings, "_ref__futures", tuple_ref, 8);
        let env = add(
            "app::run::{async_fn#0}::{closure_env#1}",
            TypeDef::Struct {
                name: strings.intern("app::run::{async_fn#0}::{closure_env#1}"),
                size: 16,
                members: vec![disabled, futures.clone()],
            },
        );
        let signed_env = add(
            "app::run::{async_fn#0}::{closure_env#2}",
            TypeDef::Struct {
                name: strings.intern("app::run::{async_fn#0}::{closure_env#2}"),
                size: 16,
                members: vec![
                    member(&mut strings, "_ref__disabled", signed_ref, 0),
                    futures,
                ],
            },
        );
        let f = member(&mut strings, "f", env, 0);
        let poll_fn = add(
            "core::future::poll_fn::PollFn<…#1>",
            TypeDef::Struct {
                name: strings.intern("core::future::poll_fn::PollFn<…#1>"),
                size: 16,
                members: vec![f],
            },
        );
        let signed_poll_fn = add(
            "core::future::poll_fn::PollFn<…#2>",
            TypeDef::Struct {
                name: strings.intern("core::future::poll_fn::PollFn<…#2>"),
                size: 16,
                members: vec![member(&mut strings, "f", signed_env, 0)],
            },
        );
        let types = TypeTable {
            types,
            ..Default::default()
        };
        const ROOT: &str = "/home/u/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f";
        let seed = |mask_word, branches: Vec<(&str, BundleTypeId)>, path: &str| SelectSeed {
            closure: "f".into(),
            mask: "_ref__disabled".into(),
            mask_word,
            futures: "_ref__futures".into(),
            tuple,
            branches: branches
                .into_iter()
                .map(|(m, t)| (m.to_owned(), t))
                .collect(),
            source: (!path.is_empty()).then(|| source(path, None)),
        };
        let reviewed = format!("{ROOT}/tokio-1.52.4/src/macros/select.rs");
        let render = |strings: &StringInterner, path: &TypedPath| {
            path.steps
                .iter()
                .map(|step| match step {
                    Step::Member(MemberRef::Named(n)) => strings.get(*n).unwrap().to_owned(),
                    Step::Deref => "*".to_owned(),
                    other => format!("{other:?}"),
                })
                .collect::<Vec<_>>()
                .join(".")
        };
        let plan = plan_select(
            poll_fn,
            &seed(u8_t, vec![("__0", fut), ("__1", other)], &reviewed),
            &types,
            &mut strings,
        )
        .unwrap();
        let RuleKey::Delegation { kind, origin } = &plan.rule else {
            panic!("{:?}", plan.rule);
        };
        assert_eq!(*kind, SemanticRuleKind::TokioSelect);
        assert_eq!(origin.package, "tokio");
        assert_eq!(origin.version, "1.52.4");
        assert_eq!(origin.family, TOKIO_SELECT_V1_47.family);
        assert_eq!(render(&strings, &plan.mask), "f._ref__disabled.*");
        assert_eq!(plan.mask.target, u8_t);
        assert_eq!(render(&strings, &plan.futures), "f._ref__futures.*");
        assert_eq!(plan.futures.target, tuple);
        assert_eq!(
            plan.branches
                .iter()
                .map(|b| (render(&strings, b), b.target))
                .collect::<Vec<_>>(),
            [("__0".to_owned(), fut), ("__1".to_owned(), other)]
        );
        // The origin: no declaration site, a vendored tree, another
        // crate's registry path, and a version past the review.
        for (path, expected) in [
            ("", "no declaration site"),
            (
                "/build/vendor/tokio-1.52.4/src/macros/select.rs",
                "not a cargo registry path",
            ),
            (
                &format!("{ROOT}/tokio-util-0.7.12/src/macros/select.rs"),
                "not the tokio crate",
            ),
            (
                &format!("{ROOT}/tokio-1.54.0/src/macros/select.rs"),
                "above the reviewed range",
            ),
            (
                &format!("{ROOT}/tokio-1.46.1/src/macros/select.rs"),
                "below the reviewed range",
            ),
        ] {
            let (kind, detail) = plan_select(
                poll_fn,
                &seed(u8_t, vec![("__0", fut)], path),
                &types,
                &mut strings,
            )
            .unwrap_err();
            assert_eq!(kind, SemanticIssueKind::UnsupportedOrigin, "{path}");
            assert!(detail.contains(expected), "{path}: {detail}");
        }
        // The layout: a signed mask, a member holding another type, a
        // member the table does not have.
        let (kind, detail) = plan_select(
            signed_poll_fn,
            &seed(i8_t, vec![("__0", fut)], &reviewed),
            &types,
            &mut strings,
        )
        .unwrap_err();
        assert_eq!(kind, SemanticIssueKind::MissingLayout);
        assert!(detail.contains("not an unsigned word"), "{detail}");
        let (kind, detail) = plan_select(
            poll_fn,
            &seed(u8_t, vec![("__0", other)], &reviewed),
            &types,
            &mut strings,
        )
        .unwrap_err();
        assert_eq!(kind, SemanticIssueKind::MissingLayout);
        assert!(detail.contains("another type than the screen"), "{detail}");
        let (kind, detail) = plan_select(
            poll_fn,
            &seed(u8_t, vec![("__2", fut)], &reviewed),
            &types,
            &mut strings,
        )
        .unwrap_err();
        assert_eq!(kind, SemanticIssueKind::AmbiguousLayout);
        assert!(detail.contains("no unique member"), "{detail}");
    }

    /// A route is held to the type it claims to land on: the same steps
    /// declared for another endpoint decline, and so do steps the table
    /// cannot walk at all.
    #[test]
    fn test_checked_paths_land_on_the_declared_target() {
        let mut a = adapters();
        let pointer = a.strings.intern("pointer");
        let steps = vec![Step::Member(MemberRef::Named(pointer)), Step::Deref];
        let path = checked_path(&a.types, PIN_BOX, steps.clone(), FUT).unwrap();
        assert_eq!(path.target, FUT);
        let (kind, detail) = checked_path(&a.types, PIN_BOX, steps.clone(), DYN).unwrap_err();
        assert_eq!(kind, SemanticIssueKind::MissingLayout);
        assert!(detail.contains("another type than declared"), "{detail}");
        let (kind, _) = checked_path(&a.types, FUT, steps, FUT).unwrap_err();
        assert_eq!(kind, SemanticIssueKind::MissingLayout);
    }

    /// An adapter whose storage the bundle cannot read plans nothing: no
    /// route is attempted through an opaque type, so its record carries
    /// no layout decline, only the storage boundary.
    #[test]
    fn test_an_adapter_over_unavailable_storage_plans_nothing() {
        let mut a = adapters();
        a.types.types[PIN_BOX.0 as usize] = TypeDef::Opaque {
            name: a
                .strings
                .intern("core::pin::Pin<alloc::boxed::Box<app::Fut, alloc::alloc::Global>>"),
            size: Some(8),
        };
        let library = Library {
            walks: &WalksTable::default(),
            tokio_version: None,
            family: Family::select(None),
        };
        let mut seeds = SemanticSeeds::new();
        seeds.insert(
            PIN_BOX,
            Seed {
                adapter: Some(seed(
                    AdapterKind::PinBox,
                    Some(("pointer", BOX)),
                    PointeeSeed::Sized(FUT),
                )),
                ..Default::default()
            },
        );
        let mut tasks = vec![TaskFutureEntry {
            future: PIN_BOX,
            cell: BundleTypeId(0),
            stage: BundleTypeId(0),
            scheduler: BundleTypeId(0),
            scheduler_binding: None,
            display_name: a.strings.intern("task"),
        }];
        let table = bind_semantics(
            seeds,
            &a.types,
            &a.names,
            &mut a.strings,
            &mut tasks,
            &library,
        );
        let record = table.types.iter().find(|r| r.ty == PIN_BOX).unwrap();
        assert!(matches!(
            record.storage,
            StoragePolicy::Unavailable(SemanticIssue {
                kind: SemanticIssueKind::MissingLayout,
                ..
            })
        ));
        assert!(record.issues.is_empty(), "{:?}", record.issues);
        assert!(matches!(
            record.future.as_ref().unwrap().continuation,
            Continuation::Unknown(SemanticIssue {
                kind: SemanticIssueKind::NoRule,
                ..
            })
        ));
        assert!(record.access.is_none());
        assert!(table.rules.is_empty());
    }

    /// Evidence crosses every bound hop: the pin over a box over a
    /// reference proves the reference a future, whose own rule then
    /// proves the future it points at.
    #[test]
    fn test_evidence_closes_transitively_over_two_hops() {
        let mut a = adapters();
        let library = Library {
            walks: &WalksTable::default(),
            tokio_version: None,
            family: Family::select(None),
        };
        let mut seeds = SemanticSeeds::new();
        seeds.insert(
            PIN_BOX_REF,
            Seed {
                adapter: Some(seed(
                    AdapterKind::PinBox,
                    Some(("pointer", BOX_REF)),
                    PointeeSeed::Sized(REF),
                )),
                ..Default::default()
            },
        );
        seeds.insert(
            REF,
            Seed {
                adapter: Some(seed(AdapterKind::MutRef, None, PointeeSeed::Sized(FUT))),
                ..Default::default()
            },
        );
        let mut tasks = vec![TaskFutureEntry {
            future: PIN_BOX_REF,
            cell: BundleTypeId(0),
            stage: BundleTypeId(0),
            scheduler: BundleTypeId(0),
            scheduler_binding: None,
            display_name: a.strings.intern("task"),
        }];
        let table = bind_semantics(
            seeds,
            &a.types,
            &a.names,
            &mut a.strings,
            &mut tasks,
            &library,
        );
        let evidence = |ty: BundleTypeId| {
            table
                .types
                .iter()
                .find(|r| r.ty == ty)
                .and_then(|r| r.future.as_ref())
                .map(|f| f.evidence.clone())
        };
        assert_eq!(
            evidence(REF),
            Some(vec![FutureEvidence::DelegatedBy {
                parent: PIN_BOX_REF
            }])
        );
        assert_eq!(
            evidence(FUT),
            Some(vec![FutureEvidence::DelegatedBy { parent: REF }])
        );
        let bound = |ty: BundleTypeId| {
            matches!(
                table
                    .types
                    .iter()
                    .find(|r| r.ty == ty)
                    .unwrap()
                    .future
                    .as_ref()
                    .unwrap()
                    .continuation,
                Continuation::Bound { .. }
            )
        };
        assert!(bound(PIN_BOX_REF) && bound(REF) && !bound(FUT));
    }

    /// Two coroutines awaiting each other — async recursion through a
    /// box, as the type graph sees it — close in one pass: each proves
    /// the other, and the fixed point stops where the evidence stops
    /// changing.
    #[test]
    fn test_evidence_closes_over_a_delegation_cycle() {
        let mut strings = StringInterner::new();
        let mut names: Vec<Option<String>> = Vec::new();
        let mut types: Vec<TypeDef> = Vec::new();
        let u32_t = strings.intern("u32");
        names.push(Some("u32".into()));
        types.push(TypeDef::Base {
            name: u32_t,
            size: 4,
            encoding: crate::Encoding::Unsigned,
        });
        // Each env: 4 payloads then the enum, so A's enum is id 5 and
        // B's is id 10; Suspend0 of each awaits the other's enum.
        const A_ENUM: BundleTypeId = BundleTypeId(5);
        const B_ENUM: BundleTypeId = BundleTypeId(10);
        for (env_name, awaitee) in [
            ("app::a::{async_fn_env#0}", B_ENUM),
            ("app::b::{async_fn_env#0}", A_ENUM),
        ] {
            let mut variants = Vec::new();
            for (index, state) in ["Unresumed", "Returned", "Panicked", "Suspend0"]
                .into_iter()
                .enumerate()
            {
                let payload = BundleTypeId(types.len() as u32);
                let name = format!("{env_name}::{state}");
                let members = if state == "Suspend0" {
                    vec![MemberDef {
                        name: strings.intern("__awaitee"),
                        ty: awaitee,
                        offset: 0,
                    }]
                } else {
                    Vec::new()
                };
                types.push(TypeDef::Struct {
                    name: strings.intern(&name),
                    size: 8,
                    members,
                });
                names.push(Some(name));
                let key = strings.intern(&index.to_string());
                variants.push(VariantDef {
                    name: key,
                    discr_values: None,
                    payload: MemberDef {
                        name: key,
                        ty: payload,
                        offset: 0,
                    },
                    decl: None,
                    await_site: None,
                });
            }
            names.push(Some(env_name.into()));
            types.push(TypeDef::Enum {
                name: strings.intern(env_name),
                size: 8,
                shape: VariantShape {
                    discr: None,
                    variants,
                },
            });
        }
        let types = TypeTable {
            types,
            ..Default::default()
        };
        let library = Library {
            walks: &WalksTable::default(),
            tokio_version: None,
            family: Family::select(None),
        };
        let mut seeds = SemanticSeeds::new();
        for env in [A_ENUM, B_ENUM] {
            seeds.insert(
                env,
                Seed {
                    coroutine_candidate: true,
                    compiler: Some(supported(&crate::detect::semantics::RUSTC_COROUTINE_V1_97)),
                    ..Default::default()
                },
            );
        }
        let mut tasks = vec![TaskFutureEntry {
            future: A_ENUM,
            cell: BundleTypeId(0),
            stage: BundleTypeId(0),
            scheduler: BundleTypeId(0),
            scheduler_binding: None,
            display_name: strings.intern("task"),
        }];
        let table = bind_semantics(seeds, &types, &names, &mut strings, &mut tasks, &library);
        let record = |ty: BundleTypeId| table.types.iter().find(|r| r.ty == ty).unwrap();
        let rule = record(A_ENUM).coroutine.as_ref().unwrap().rule;
        assert_eq!(
            record(A_ENUM).future.as_ref().unwrap().evidence,
            [
                FutureEvidence::TaskEntry(TaskEntryId(0)),
                FutureEvidence::Coroutine(rule),
                FutureEvidence::DelegatedBy { parent: B_ENUM },
            ]
        );
        assert_eq!(
            record(B_ENUM).future.as_ref().unwrap().evidence,
            [
                FutureEvidence::Coroutine(rule),
                FutureEvidence::DelegatedBy { parent: A_ENUM },
            ]
        );
        for env in [A_ENUM, B_ENUM] {
            assert!(matches!(
                record(env).future.as_ref().unwrap().continuation,
                Continuation::Bound {
                    program: PollProgram::MatchVariant { .. },
                    ..
                }
            ));
        }
    }

    /// `inner` reaches the future through std's `ManuallyDrop` and
    /// `MaybeDangling` wrappers by name, each a one-member struct at
    /// offset zero; anything else in the way declines.
    #[test]
    fn test_instrumented_plan_enters_only_the_reviewed_wrappers() {
        let mut strings = StringInterner::new();
        let mut names = Vec::new();
        let mut types = Vec::new();
        let mut add = |name: &str, def: TypeDef| {
            names.push(Some(name.to_owned()));
            types.push(def);
            BundleTypeId(types.len() as u32 - 1)
        };
        let fut = add(
            "app::Fut",
            TypeDef::Struct {
                name: strings.intern("app::Fut"),
                size: 8,
                members: Vec::new(),
            },
        );
        let dangling = add(
            "core::mem::maybe_dangling::MaybeDangling<app::Fut>",
            TypeDef::Struct {
                name: strings.intern("core::mem::maybe_dangling::MaybeDangling<app::Fut>"),
                size: 8,
                members: vec![MemberDef {
                    name: strings.intern("__0"),
                    ty: fut,
                    offset: 0,
                }],
            },
        );
        let manually = add(
            "core::mem::manually_drop::ManuallyDrop<app::Fut>",
            TypeDef::Struct {
                name: strings.intern("core::mem::manually_drop::ManuallyDrop<app::Fut>"),
                size: 8,
                members: vec![MemberDef {
                    name: strings.intern("value"),
                    ty: dangling,
                    offset: 0,
                }],
            },
        );
        let span = add(
            "tracing::span::Span",
            TypeDef::Struct {
                name: strings.intern("tracing::span::Span"),
                size: 40,
                members: Vec::new(),
            },
        );
        let inst = add(
            "tracing::instrument::Instrumented<app::Fut>",
            TypeDef::Struct {
                name: strings.intern("tracing::instrument::Instrumented<app::Fut>"),
                size: 48,
                members: vec![
                    MemberDef {
                        name: strings.intern("span"),
                        ty: span,
                        offset: 0,
                    },
                    MemberDef {
                        name: strings.intern("inner"),
                        ty: manually,
                        offset: 40,
                    },
                ],
            },
        );
        let types = TypeTable {
            types,
            ..Default::default()
        };
        let layout = InstrumentedSeed {
            inner: "inner".into(),
            future: fut,
        };
        let seed = Seed {
            poll_sources: BTreeSet::from([source(REGISTRY, None)]),
            ..Default::default()
        };
        let plan = plan_instrumented(inst, &layout, &seed, &types, &names, &mut strings).unwrap();
        let Delegation::Direct { target, exclusive } = plan.program.as_ref().unwrap() else {
            panic!("direct")
        };
        assert!(
            !exclusive,
            "a span's callbacks are not reviewed control flow"
        );
        assert!(plan.access.is_none());
        let s = |r: StrRef| strings.get(r).unwrap().to_owned();
        let Target::Value(path) = target else {
            panic!("static")
        };
        let spelled: Vec<String> = path
            .steps
            .iter()
            .map(|step| match step {
                Step::Member(MemberRef::Named(n)) => s(*n),
                other => format!("{other:?}"),
            })
            .collect();
        assert_eq!(spelled, ["inner", "value", "__0"]);
        assert_eq!(path.target, fut);
        assert!(
            matches!(&plan.rule, RuleKey::Delegation { kind: SemanticRuleKind::TracingInstrumented, origin }
            if origin.family == "tracing-instrumented-0.1.40" && origin.version == "0.1.40")
        );
        // A wrapper that is not one of the two, or one that grew a
        // member, stops the route.
        let mut other = types.clone();
        if let TypeDef::Struct { name, .. } = &mut other.types[dangling.0 as usize] {
            *name = strings.intern("app::Cell<app::Fut>");
        }
        let mut other_names = names.clone();
        other_names[dangling.0 as usize] = Some("app::Cell<app::Fut>".into());
        let (kind, detail) =
            plan_instrumented(inst, &layout, &seed, &other, &other_names, &mut strings)
                .unwrap_err();
        assert_eq!(kind, SemanticIssueKind::MissingLayout);
        assert!(detail.contains("not a reviewed std wrapper"), "{detail}");
        let mut grown = types.clone();
        if let TypeDef::Struct { members, .. } = &mut grown.types[manually.0 as usize] {
            members.push(MemberDef {
                name: strings.intern("extra"),
                ty: fut,
                offset: 0,
            });
        }
        let (kind, _) =
            plan_instrumented(inst, &layout, &seed, &grown, &names, &mut strings).unwrap_err();
        assert_eq!(kind, SemanticIssueKind::MissingLayout);
        // And an unsupported origin never reaches the layout.
        let seed = Seed::default();
        let (kind, _) =
            plan_instrumented(inst, &layout, &seed, &types, &names, &mut strings).unwrap_err();
        assert_eq!(kind, SemanticIssueKind::UnsupportedOrigin);
    }

    /// Evidence closes over bound delegations from seeded types only: a
    /// task root's `Pin<Box<F>>` proves `F` a future, whose own program
    /// then proves its delegate; a `Pin<Box<G>>` nothing points at
    /// proves nothing, and appears only as the owned route to a `G`
    /// that has a record of its own.
    #[test]
    fn test_evidence_closes_over_seeded_delegations_only() {
        let mut a = adapters();
        let library = Library {
            walks: &WalksTable::default(),
            tokio_version: None,
            family: Family::select(None),
        };
        let mut seeds = SemanticSeeds::new();
        let boxed = |pin: Option<(&str, BundleTypeId)>, kind, pointee| Seed {
            adapter: Some(seed(kind, pin, pointee)),
            ..Default::default()
        };
        // A task root: Pin<Box<Fut>> over the sized box over Fut.
        seeds.insert(
            PIN_BOX,
            boxed(
                Some(("pointer", BOX)),
                AdapterKind::PinBox,
                PointeeSeed::Sized(FUT),
            ),
        );
        seeds.insert(BOX, boxed(None, AdapterKind::Box, PointeeSeed::Sized(FUT)));
        // A reference nothing points at, over the same future.
        seeds.insert(
            REF,
            boxed(None, AdapterKind::MutRef, PointeeSeed::Sized(FUT)),
        );
        // A wide box nothing points at: no static child, no record.
        seeds.insert(
            WIDE,
            boxed(None, AdapterKind::Box, PointeeSeed::Dyn(dyn_seed())),
        );
        let mut tasks = vec![TaskFutureEntry {
            future: PIN_BOX,
            cell: BundleTypeId(0),
            stage: BundleTypeId(0),
            scheduler: BundleTypeId(0),
            scheduler_binding: None,
            display_name: a.strings.intern("task"),
        }];
        let table = bind_semantics(
            seeds,
            &a.types,
            &a.names,
            &mut a.strings,
            &mut tasks,
            &library,
        );
        let record = |ty: BundleTypeId| table.types.iter().find(|r| r.ty == ty);
        let evidence = |ty: BundleTypeId| {
            record(ty)
                .and_then(|r| r.future.as_ref())
                .map(|f| f.evidence.clone())
        };
        assert_eq!(
            evidence(PIN_BOX),
            Some(vec![FutureEvidence::TaskEntry(TaskEntryId(0))])
        );
        // Pin<Box<Fut>> delegates to Fut directly; the box's own record
        // is the owned route to a future that has one.
        assert_eq!(
            evidence(FUT),
            Some(vec![FutureEvidence::DelegatedBy { parent: PIN_BOX }])
        );
        assert!(matches!(
            record(FUT).unwrap().future.as_ref().unwrap().continuation,
            Continuation::Unknown(SemanticIssue {
                kind: SemanticIssueKind::NoRule,
                ..
            })
        ));
        assert_eq!(evidence(BOX), None);
        assert!(record(BOX).unwrap().access.is_some());
        assert_eq!(evidence(REF), None);
        assert!(record(REF).unwrap().access.is_some());
        assert!(record(WIDE).is_none());
        // The rules: the pin's poll and access, the box's and the
        // reference's access, each once, under one rustc origin.
        let kinds: BTreeSet<SemanticRuleKind> = table.rules.iter().map(|r| r.kind).collect();
        assert_eq!(
            kinds,
            BTreeSet::from([
                SemanticRuleKind::StdPinBoxPoll,
                SemanticRuleKind::StdPinBoxAccess,
                SemanticRuleKind::StdBoxAccess,
                SemanticRuleKind::StdMutRefAccess,
            ])
        );
        assert_eq!(table.origins.len(), 1);
        assert!(matches!(table.origins[0], SemanticOrigin::Rustc { .. }));
        let Continuation::Bound { program, .. } = &record(PIN_BOX)
            .unwrap()
            .future
            .as_ref()
            .unwrap()
            .continuation
        else {
            panic!("the root's program is bound")
        };
        assert!(matches!(
            program,
            PollProgram::Direct(PollAction::Delegate {
                target: FutureTarget::Value(TypedPath { target: FUT, .. }),
                exclusive: true,
            })
        ));
    }

    /// A bound coroutine seeds the fixed point by its storage alone: a
    /// block nothing delegates to statically — one reached only through
    /// a dyn hop at runtime — still proves the pinned wide box its
    /// suspended state awaits a future, so the box carries a record the
    /// chain can cross and the scan can enter. Before this was so, the
    /// box had no record at all: its evidence was empty when the queue
    /// was seeded, and the coroutine's own evidence is numbered only
    /// at emit time.
    #[test]
    fn test_a_bound_coroutine_seeds_its_awaitee_without_evidence_of_its_own() {
        let mut a = adapters();
        let library = Library {
            walks: &WalksTable::default(),
            tokio_version: None,
            family: Family::select(None),
        };
        // The env, appended to the adapter table: four payloads then
        // the enum, its Suspend0 awaiting the wide pin.
        let env_name = "app::dynamic::{async_block_env#0}";
        let base = a.types.types.len() as u32;
        let mut variants = Vec::new();
        for (index, state) in ["Unresumed", "Returned", "Panicked", "Suspend0"]
            .into_iter()
            .enumerate()
        {
            let payload = BundleTypeId(a.types.types.len() as u32);
            let name = format!("{env_name}::{state}");
            let members = if state == "Suspend0" {
                vec![MemberDef {
                    name: a.strings.intern("__awaitee"),
                    ty: PIN_WIDE,
                    offset: 0,
                }]
            } else {
                Vec::new()
            };
            a.types.types.push(TypeDef::Struct {
                name: a.strings.intern(&name),
                size: 16,
                members,
            });
            a.names.push(Some(name));
            let key = a.strings.intern(&index.to_string());
            variants.push(VariantDef {
                name: key,
                discr_values: None,
                payload: MemberDef {
                    name: key,
                    ty: payload,
                    offset: 0,
                },
                decl: None,
                await_site: None,
            });
        }
        let env = BundleTypeId(base + 4);
        a.types.types.push(TypeDef::Enum {
            name: a.strings.intern(env_name),
            size: 16,
            shape: VariantShape {
                discr: None,
                variants,
            },
        });
        a.names.push(Some(env_name.to_owned()));

        let mut seeds = SemanticSeeds::new();
        seeds.insert(
            env,
            Seed {
                coroutine_candidate: true,
                compiler: Some(supported(&crate::detect::semantics::RUSTC_COROUTINE_V1_97)),
                ..Default::default()
            },
        );
        seeds.insert(
            PIN_WIDE,
            Seed {
                adapter: Some(seed(
                    AdapterKind::PinBox,
                    Some(("pointer", WIDE)),
                    PointeeSeed::Dyn(dyn_seed()),
                )),
                ..Default::default()
            },
        );
        // No task entry and no poll symbol anywhere: the block is a
        // future only by being a bound coroutine.
        let mut tasks = Vec::new();
        let table = bind_semantics(
            seeds,
            &a.types,
            &a.names,
            &mut a.strings,
            &mut tasks,
            &library,
        );
        let record = |ty: BundleTypeId| table.types.iter().find(|r| r.ty == ty);
        let rule = record(env).unwrap().coroutine.as_ref().unwrap().rule;
        assert_eq!(
            record(env).unwrap().future.as_ref().unwrap().evidence,
            [FutureEvidence::Coroutine(rule)]
        );
        let pin = record(PIN_WIDE).expect("the awaited pin has a record");
        assert_eq!(
            pin.future.as_ref().unwrap().evidence,
            [FutureEvidence::DelegatedBy { parent: env }]
        );
        assert!(matches!(
            pin.future.as_ref().unwrap().continuation,
            Continuation::Bound {
                program: PollProgram::Direct(PollAction::Delegate {
                    target: FutureTarget::Dynamic { .. },
                    exclusive: true,
                }),
                ..
            }
        ));
        assert!(pin.access.is_some(), "the owned route into the box");
    }

    /// A bound coroutine's program matches its states: the fixed three
    /// and, per suspended state, a delegation to the listed `__awaitee`
    /// or an unknown case where none is listed.
    #[test]
    fn test_coroutine_plan_delegates_only_to_a_listed_awaitee() {
        let mut e = env(
            "async_fn",
            &[
                ("Unresumed", &["arg"]),
                ("Returned", &[]),
                ("Panicked", &[]),
                ("Suspend0", &["local", "__awaitee"]),
                ("Suspend1", &["local"]),
            ],
            &[],
        );
        let states = coroutine_states(e.env, false, &e.types, &e.names, &e.strings).unwrap();
        let layout = CoroutineLayout {
            rule: SemanticRuleId(u32::MAX),
            states,
        };
        let rule = RuleKey::Rustc {
            kind: SemanticRuleKind::RustcAsyncFn,
            producer: PRODUCER.into(),
            family: "rustc-coroutine-1.97",
        };
        let plan = coroutine_plan(e.env, &rule, &layout, &e.types, &mut e.strings);
        let Delegation::Match { cases } = plan.program.as_ref().unwrap() else {
            panic!("coroutine")
        };
        let spelled: Vec<String> = cases
            .iter()
            .map(|(variant, action)| {
                let s = e.strings.get(*variant).unwrap();
                match action {
                    CaseAction::Unresumed => format!("{s}:unresumed"),
                    CaseAction::Returned => format!("{s}:returned"),
                    CaseAction::Panicked => format!("{s}:panicked"),
                    CaseAction::Delegate(target) => match target.as_ref() {
                        Target::Value(p) => {
                            format!("{s}:delegate {} steps -> {}", p.steps.len(), p.target.0)
                        }
                        Target::Dynamic { .. } => format!("{s}:dyn"),
                    },
                    CaseAction::Unknown(i) => format!("{s}:unknown {:?}", i.kind),
                }
            })
            .collect();
        assert_eq!(
            spelled,
            [
                "0:unresumed",
                "1:returned",
                "2:panicked",
                "3:delegate 2 steps -> 0",
                "4:unknown MissingLayout",
            ]
        );
        assert_eq!(plan.static_children(), [BundleTypeId(0)]);
        // An `__awaitee` the convention lists as uncertain — an async
        // block's capture at the slot its `Unresumed` state keeps it at —
        // is not a delegate: stale bytes are not a future being polled.
        let mut e = env(
            "async_block",
            &[
                ("Unresumed", &["__awaitee"]),
                ("Returned", &[]),
                ("Panicked", &[]),
                ("Suspend0", &["__awaitee"]),
            ],
            &[],
        );
        let states = coroutine_states(e.env, true, &e.types, &e.names, &e.strings).unwrap();
        assert_eq!(render(&e, &states)[3], "3:Suspended[](__awaitee)");
        let layout = CoroutineLayout {
            rule: SemanticRuleId(u32::MAX),
            states,
        };
        let plan = coroutine_plan(e.env, &rule, &layout, &e.types, &mut e.strings);
        let Delegation::Match { cases } = plan.program.as_ref().unwrap() else {
            panic!("coroutine")
        };
        assert!(matches!(
            cases[3].1,
            CaseAction::Unknown(SemanticIssue {
                kind: SemanticIssueKind::MissingLayout,
                ..
            })
        ));
        assert!(plan.static_children().is_empty());
    }
}
