// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use super::*;
use crate::{
    Bundle, Error, MemberRef, Result, Selector, Step, TypeDef, VariantDef, WalkOutcome, WalkRole,
};

use std::collections::{BTreeMap, BTreeSet, VecDeque};

fn require(ok: bool, message: &str) -> Result<()> {
    if ok {
        Ok(())
    } else {
        Err(Error::Corrupt(format!("semantics: {message}")))
    }
}

struct Check<'a>(&'a Bundle);

impl<'a> Check<'a> {
    fn string(&self, id: StrRef) -> Result<&'a str> {
        self.0
            .strings
            .get(id)
            .filter(|s| !s.is_empty())
            .ok_or_else(|| Error::Corrupt("semantics: invalid or empty string".into()))
    }

    fn ty(&self, id: BundleTypeId) -> Result<&'a TypeDef> {
        self.0
            .types
            .get(id)
            .ok_or_else(|| Error::Corrupt("semantics: invalid type id".into()))
    }

    fn issue(&self, issue: &SemanticIssue) -> Result<()> {
        if let Some(detail) = issue.detail {
            self.string(detail)?;
        }
        Ok(())
    }

    fn rule(&self, id: SemanticRuleId, kinds: &[SemanticRuleKind]) -> Result<&'a SemanticRule> {
        let rule = self
            .0
            .semantics
            .rules
            .get(id.0 as usize)
            .ok_or_else(|| Error::Corrupt("semantics: invalid rule id".into()))?;
        require(
            kinds.contains(&rule.kind),
            "rule has an incompatible capability",
        )?;
        Ok(rule)
    }

    fn origin(&self, origin: &SemanticOrigin) -> Result<()> {
        let version = |id| -> Result<()> {
            require(
                semver::Version::parse(self.string(id)?).is_ok(),
                "invalid library version",
            )
        };
        match origin {
            SemanticOrigin::Rustc { producer, family } => {
                // rustc's LLVM backend spells its producer
                // `clang LLVM (rustc version X (hash date))`; the bare form
                // is accepted too. Both anchored at the front.
                let producer = self.string(*producer)?;
                let token = producer
                    .strip_prefix("clang LLVM (rustc version ")
                    .or_else(|| producer.strip_prefix("rustc version "))
                    .and_then(|s| s.split_ascii_whitespace().next())
                    .map(|s| s.strip_suffix(')').unwrap_or(s));
                require(
                    token.is_some_and(|s| semver::Version::parse(s).is_ok()),
                    "invalid Rust producer",
                )?;
                self.string(*family)?;
            }
            SemanticOrigin::LibraryLayout {
                package,
                version: v,
                family,
                selection,
            } => {
                self.string(*package)?;
                self.string(*family)?;
                require(
                    v.is_none() == (*selection == LayoutSelection::VersionUnknown),
                    "layout selection disagrees with version availability",
                )?;
                if let Some(v) = v {
                    version(*v)?;
                }
            }
            SemanticOrigin::LibraryDelegation {
                package,
                version: v,
                family,
                source,
                files,
            } => {
                let package = self.string(*package)?;
                let v = self.string(*v)?;
                self.string(*family)?;
                // The recorded path is the anchored tail, so a reader
                // re-parses exactly what the producer parsed, and it has
                // to say what the origin says.
                let origin =
                    crate::origin::registry_origin(self.string(*source)?).ok_or_else(|| {
                        Error::Corrupt("semantics: delegation source is not a registry path".into())
                    })?;
                require(
                    origin.path == self.string(*source)?,
                    "delegation source is not anchored at its registry segment",
                )?;
                require(
                    origin.package == package && origin.version.to_string() == v,
                    "delegation source names another crate or version",
                )?;
                let mut names = BTreeSet::new();
                for file in files {
                    require(
                        names.insert(self.string(file.file)?),
                        "duplicate source checksum file",
                    )?;
                }
            }
            SemanticOrigin::GitDelegation {
                package,
                repository,
                revision,
                family,
                source,
                files,
            } => {
                self.string(*package)?;
                self.string(*family)?;
                let source = self.string(*source)?;
                // The recorded path is the anchored tail, and it has to
                // name the repository and revision the origin does.
                let origin = crate::origin::git_origin(source).ok_or_else(|| {
                    Error::Corrupt("semantics: delegation source is not a git checkout path".into())
                })?;
                require(
                    origin.path == source,
                    "delegation source is not anchored at its checkout segment",
                )?;
                require(
                    origin.repository == self.string(*repository)?
                        && origin.revision == self.string(*revision)?,
                    "delegation source names another repository or revision",
                )?;
                let mut names = BTreeSet::new();
                for file in files {
                    require(
                        names.insert(self.string(file.file)?),
                        "duplicate source checksum file",
                    )?;
                }
            }
        }
        Ok(())
    }

    fn rule_origin(&self, rule: &SemanticRule) -> Result<()> {
        use SemanticRuleKind::*;
        require(rule.revision == 1, "unknown rule revision")?;
        let origin = self
            .0
            .semantics
            .origins
            .get(rule.origin.0 as usize)
            .ok_or_else(|| Error::Corrupt("semantics: invalid origin id".into()))?;
        let package = match rule.kind {
            RustcAsyncFn | RustcAsyncBlock | DynFutureAbi | StdBoxAccess | StdMutRefAccess
            | StdPinBoxAccess | StdPinMutRefAccess | StdBoxPoll | StdMutRefPoll | StdPinBoxPoll
            | StdPinMutRefPoll | CorePending | RustcAsyncClosure | StdRefcountHeader
            | StdFutexMutex => {
                return require(
                    matches!(origin, SemanticOrigin::Rustc { .. }),
                    "compiler rule needs a compiler origin",
                );
            }
            // The `map` newtype forwards on its layout and the enum it
            // forwards into is read off its declaration: one kind, under
            // either of futures-util's origins.
            FuturesUtilMap => {
                return require(
                    matches!(
                        origin,
                        SemanticOrigin::LibraryDelegation { package, .. }
                        | SemanticOrigin::LibraryLayout { package, .. }
                        if self.0.strings.get(*package) == Some("futures-util")
                    ),
                    "futures-util map rule needs a futures-util origin",
                );
            }
            TracingInstrumented
            | HyperUtilTokioSleep
            | HyperUtilAutoConn
            | HyperUtilPool
            | HyperUtilConnected
            | HyperUtilResponseFuture
            | HyperH1Conn
            | DropshotRequestHandler
            | DropshotRequestContext
            | ReqwestPendingRequest
            | ReqwestCookie
            | HttpRequest
            | ParkingLotRawMutex
            | TokioSelect
            | TokioIntervalTick
            | FuturesUtilNext
            | FuturesUtilEither
            | TowerRetry
            | TokioStreamWatchStream
            | TokioUtilReusableBox
            | TokioStreamStreamMap
            | TokioRustlsStream
            | HyperUtilStream
            | DropshotTlsConn
            | ReqwestConn
            | HyperRustlsStream
            | TokioRustlsHandshake => {
                let crate_name = match rule.kind {
                    TracingInstrumented => "tracing",
                    HyperUtilTokioSleep
                    | HyperUtilAutoConn
                    | HyperUtilPool
                    | HyperUtilConnected
                    | HyperUtilResponseFuture
                    | HyperUtilStream => "hyper-util",
                    HyperH1Conn => "hyper",
                    DropshotRequestHandler | DropshotRequestContext | DropshotTlsConn => "dropshot",
                    ReqwestPendingRequest | ReqwestCookie | ReqwestConn => "reqwest",
                    HyperRustlsStream => "hyper-rustls",
                    TowerRetry => "tower",
                    HttpRequest => "http",
                    ParkingLotRawMutex => "parking_lot",
                    // tokio's own macro and its own async fn, but read
                    // like a third-party rule: the declaration file is
                    // the evidence, and tokio's version comes off its
                    // registry path rather than the layout family.
                    TokioSelect | TokioIntervalTick => "tokio",
                    // The map is a container, but one whose layout the
                    // walk contract binds by name alone: its origin is
                    // the type's own method declarations, read like the
                    // stream route's.
                    TokioStreamWatchStream | TokioStreamStreamMap => "tokio-stream",
                    TokioUtilReusableBox => "tokio-util",
                    TokioRustlsStream | TokioRustlsHandshake => "tokio-rustls",
                    _ => "futures-util",
                };
                return require(
                    matches!(origin, SemanticOrigin::LibraryDelegation { package, .. }
                    if self.0.strings.get(*package) == Some(crate_name)),
                    "third-party delegation needs source evidence",
                );
            }
            // A crate with no release, reviewed per git revision.
            SprocketsTlsStream | SprocketsHandshake => {
                return require(
                    matches!(origin, SemanticOrigin::GitDelegation { package, .. }
                    if self.0.strings.get(*package) == Some("sprockets-tls")),
                    "git delegation needs checkout evidence",
                );
            }
            // A sole-member forwarder binds on its layout — the one
            // member of the declared type is the whole of the evidence,
            // and no declaration has to say which implementation
            // forwards it — under its crate's layout origin.
            // `Pending` binds on its layout too: a zero-sized future
            // over a `PhantomData<T>` has nothing to poll and cannot
            // produce a `T`, and no build leaves a declaration of it.
            FuturesUnordered | FuturesUtilMapErr | FuturesUtilIntoFuture | FuturesUtilPending => {
                "futures-util"
            }
            TokioCoop
            | TokioSleep
            | TokioJoinHandle
            | TokioAcquire
            | TokioJoinSet
            | TokioSleepState
            | TokioJoinHandleState
            | TokioAcquireState
            | TokioIoOperation
            | TokioIoState
            | TokioMultiThreadScheduler
            | TokioCurrentThreadScheduler
            | TokioLocalScheduler
            | TokioBlockingScheduler
            | TokioMpscRecv
            | TokioMpscRecvState
            | TokioNotified
            | TokioNotifiedState
            | TokioOneshotRecv
            | TokioOneshotRecvState
            | TokioAcquireOwner
            | TokioIoRoute => "tokio",
            // A layout rule whose version is read off the declarations
            // of hashbrown's map, where std's vendored copy has no cargo
            // registry path to be a delegation origin by.
            HashbrownTable => "hashbrown",
            // A layout rule whose release is read off the declarations
            // of rustls's connection, like hashbrown's.
            RustlsSession => "rustls",
        };
        require(
            matches!(origin, SemanticOrigin::LibraryLayout { package: p, .. }
            if self.0.strings.get(*p) == Some(package)),
            "layout rule has an incompatible library origin",
        )?;
        if matches!(
            rule.kind,
            TokioSleepState
                | TokioJoinHandleState
                | TokioAcquireState
                | TokioIoState
                | TokioMpscRecvState
                | TokioNotifiedState
                | TokioOneshotRecvState
        ) {
            // Layout validation alone cannot authorize a state protocol:
            // revision 1 of each is the reading the runtime's assessor
            // was reviewed against, and it binds only where the origin
            // records a version inside the reviewed range — a guessed
            // family observes and never assesses.
            require(
                matches!(
                    origin,
                    SemanticOrigin::LibraryLayout {
                        selection: LayoutSelection::ReviewedRange,
                        ..
                    }
                ),
                "state rule requires a reviewed range",
            )?;
        }
        if matches!(rule.kind, HashbrownTable | RustlsSession) {
            // The table rule authorizes reading a map's buckets as the
            // value's storage, and the session rule reading a
            // connection's words as its verdict, so like a state
            // protocol each binds only on a release the review read.
            require(
                matches!(
                    origin,
                    SemanticOrigin::LibraryLayout {
                        selection: LayoutSelection::ReviewedRange,
                        ..
                    }
                ),
                "layout rule requires a reviewed range",
            )?;
        }
        Ok(())
    }

    fn path(&self, root: BundleTypeId, path: &TypedPath) -> Result<()> {
        self.ty(root)?;
        self.ty(path.target)?;
        for step in &path.steps {
            match step {
                Step::Member(MemberRef::Named(name)) | Step::Variant(name) => {
                    self.string(*name)?;
                }
                Step::Deref => {}
                Step::Member(MemberRef::Index(_)) | Step::ActiveVariant => {
                    return require(
                        false,
                        "semantic paths require named members and explicit variants",
                    );
                }
            }
        }
        let target =
            crate::io::semantic_path_target(&self.0.types, root, &Selector(path.steps.clone()))?;
        require(
            target == path.target,
            "path endpoint type differs from recorded target",
        )
    }

    /// A path from `root` that lands on a pointer.
    fn pointer(&self, root: BundleTypeId, path: &TypedPath, what: &str) -> Result<()> {
        self.path(root, path)?;
        require(
            matches!(self.ty(path.target)?, TypeDef::Pointer { .. }),
            &format!("{what} is not reached by a pointer"),
        )
    }

    /// A text's two words from `root`: a pointer to bytes and an
    /// unsigned word beside it, entered through one member.
    fn text(&self, root: BundleTypeId, ptr: &TypedPath, len: &TypedPath, what: &str) -> Result<()> {
        self.pointer(root, ptr, what)?;
        let byte = match self.ty(ptr.target)? {
            TypeDef::Pointer { target, .. } => self.ty(*target)?,
            _ => unreachable!("checked above"),
        };
        require(
            matches!(
                byte,
                TypeDef::Base {
                    encoding: crate::Encoding::Unsigned,
                    size: 1,
                    ..
                }
            ),
            &format!("{what} pointer does not point at bytes"),
        )?;
        self.path(root, len)?;
        require(
            matches!(
                self.ty(len.target)?,
                TypeDef::Base {
                    encoding: crate::Encoding::Unsigned,
                    size: 8,
                    ..
                }
            ),
            &format!("{what} length is not an unsigned word"),
        )?;
        // The pointer and the length are read out of one value — the
        // `Bytes` of a path, the `String` of a URL — so both routes
        // enter the root through the member holding it; where they part
        // below that is the holder's own layout (a `String`'s length
        // sits beside its raw buffer, not beside the pointer).
        require(
            ptr.steps.len() > 1 && len.steps.len() > 1 && ptr.steps[0] == len.steps[0],
            &format!("{what} pointer and length are not under one member"),
        )
    }

    /// A pool binding: under the hyper-util pool rule, every connection
    /// it names has a key text and a `want` pointer. A reaper's pool is
    /// reached through a pointer to its strong count and its idle map,
    /// which is a hash table whose bucket the key and the list are read
    /// from, and whose list's element holds the pointer.
    fn pool(&self, record: &TypeSemantics, binding: &HttpPoolBinding) -> Result<()> {
        match binding {
            HttpPoolBinding::Reaper {
                rule,
                strong,
                idle,
                key_ptr,
                key_len,
                entries_ptr,
                entries_len,
                entry,
                want,
                conn_info,
            } => {
                self.rule(*rule, &[SemanticRuleKind::HyperUtilPool])?;
                if let Some(conn_info) = conn_info {
                    self.conn_info(*entry, conn_info)?;
                }
                self.path(record.ty, strong)?;
                require(
                    self.0.types.size_of(strong.target) == Some(crate::POINTER_SIZE),
                    "HTTP pool strong count is not a word",
                )?;
                require(
                    strong.steps.contains(&Step::Deref)
                        && idle.steps.starts_with(
                            &strong.steps[..=strong
                                .steps
                                .iter()
                                .position(|s| *s == Step::Deref)
                                .expect("checked above")],
                        ),
                    "HTTP pool map is not reached through the pool its count is",
                )?;
                self.path(record.ty, idle)?;
                let table = self
                    .0
                    .semantics
                    .types
                    .binary_search_by_key(&idle.target, |r| r.ty)
                    .ok()
                    .and_then(|i| self.0.semantics.types[i].table.as_ref());
                let Some(table) = table else {
                    return require(false, "HTTP pool map carries no table binding");
                };
                self.text(table.bucket, key_ptr, key_len, "HTTP pool key")?;
                self.pointer(table.bucket, entries_ptr, "HTTP pool idle list")?;
                self.path(table.bucket, entries_len)?;
                require(
                    matches!(
                        self.ty(entries_len.target)?,
                        TypeDef::Base {
                            encoding: crate::Encoding::Unsigned,
                            size: 8,
                            ..
                        }
                    ),
                    "HTTP pool idle list length is not an unsigned word",
                )?;
                self.ty(*entry)?;
                require(
                    self.0.types.size_of(*entry).is_some_and(|size| size > 0),
                    "HTTP pool idle entry is unsized",
                )?;
                self.pointer(*entry, want, "HTTP pool entry's want handle")
            }
            HttpPoolBinding::Checkout {
                rule,
                key_ptr,
                key_len,
                want,
                conn_info,
            } => {
                self.rule(*rule, &[SemanticRuleKind::HyperUtilPool])?;
                self.text(record.ty, key_ptr, key_len, "HTTP pool key")?;
                if let Some(conn_info) = conn_info {
                    self.conn_info(record.ty, conn_info)?;
                }
                self.pointer(record.ty, want, "HTTP pool checkout's want handle")
            }
        }
    }

    /// A pooled connection's info: a path from the pool's value landing
    /// on a type whose record carries the `Connected` binding.
    fn conn_info(&self, root: BundleTypeId, path: &TypedPath) -> Result<()> {
        self.path(root, path)?;
        let binds = self
            .0
            .semantics
            .types
            .binary_search_by_key(&path.target, |r| r.ty)
            .ok()
            .is_some_and(|i| self.0.semantics.types[i].connected.is_some());
        require(binds, "HTTP pool connection info carries no binding")
    }

    /// hyper-util's `Connected`, under its own rule: the negotiated
    /// protocol an enum, the proxy flag a byte, and the extras a box of
    /// a trait object read under the compiler's header rule, whose
    /// cases each name a distinct symbol and type. A case's addresses
    /// come as a pair, each landing on one address enum; a chain's
    /// `next` lands on the binding's own box, so the walk down a chain
    /// reads every link the same way.
    fn connected(&self, record: &TypeSemantics, binding: &ConnectedBinding) -> Result<()> {
        self.rule(binding.rule, &[SemanticRuleKind::HyperUtilConnected])?;
        self.path(record.ty, &binding.alpn)?;
        require(
            matches!(
                self.ty(binding.alpn.target)?,
                TypeDef::Enum { .. } | TypeDef::CEnum { .. }
            ),
            "connection info's ALPN is not an enum",
        )?;
        self.path(record.ty, &binding.is_proxied)?;
        require(
            self.0.types.size_of(binding.is_proxied.target) == Some(1),
            "connection info's proxy flag is not a byte",
        )?;
        self.path(record.ty, &binding.extra)?;
        let wide = binding.extra.target;
        let layout = &binding.layout;
        self.rule(layout.abi, &[SemanticRuleKind::DynFutureAbi])?;
        for (word, what) in [(&layout.data, "data"), (&layout.vtable, "vtable")] {
            self.path(wide, word)?;
            require(
                self.0.types.size_of(word.target) == Some(crate::POINTER_SIZE),
                &format!("connection info's extras {what} word is not a pointer"),
            )?;
        }
        require(
            layout.size_slot != layout.align_slot
                && layout.read_slot > layout.size_slot
                && layout.read_slot > layout.align_slot,
            "connection info's extras vtable slots overlap",
        )?;
        let mut seen = BTreeSet::new();
        let mut address = None;
        for case in &binding.cases {
            self.string(case.symbol)?;
            self.ty(case.target)?;
            require(
                seen.insert((case.symbol, case.target)),
                "connection info lists one extra twice",
            )?;
            match (&case.remote_addr, &case.local_addr) {
                (Some(remote), Some(local)) => {
                    for path in [remote, local] {
                        self.path(case.target, path)?;
                        require(
                            matches!(self.ty(path.target)?, TypeDef::Enum { .. }),
                            "connection info's address is not an enum",
                        )?;
                        require(
                            *address.get_or_insert(path.target) == path.target,
                            "connection info's addresses are not one type",
                        )?;
                    }
                }
                (None, None) => {}
                _ => return require(false, "connection info's addresses are not a pair"),
            }
            if let Some(next) = &case.next {
                self.path(case.target, next)?;
                require(
                    next.target == wide,
                    "connection info's chain does not wrap its extras' box",
                )?;
            }
        }
        Ok(())
    }

    fn target(&self, root: BundleTypeId, target: &FutureTarget) -> Result<()> {
        match target {
            FutureTarget::Value(path) => {
                self.path(root, path)?;
                require(
                    !path.steps.is_empty() || path.target != root,
                    "empty self delegation",
                )
            }
            FutureTarget::Dynamic { pointer, layout } => {
                self.path(root, pointer)?;
                self.rule(layout.abi, &[SemanticRuleKind::DynFutureAbi])?;
                self.ty(layout.trait_ty)?;
                self.path(pointer.target, &layout.data)?;
                self.path(pointer.target, &layout.vtable)?;
                let field_offset = |path: &TypedPath| {
                    crate::io::selector_offset(
                        self.0,
                        pointer.target,
                        &Selector(path.steps.clone()),
                    )
                };
                require(
                    field_offset(&layout.data)
                        .zip(field_offset(&layout.vtable))
                        .is_some_and(|(data, vtable)| data.abs_diff(vtable) >= crate::POINTER_SIZE),
                    "dyn fields must be distinct inline words",
                )?;
                require(
                    self.0.types.size_of(layout.data.target) == Some(crate::POINTER_SIZE)
                        && self.0.types.size_of(layout.vtable.target) == Some(crate::POINTER_SIZE),
                    "dyn fields must be pointer sized",
                )?;
                require(
                    matches!(self.ty(layout.data.target)?, TypeDef::Pointer { target, .. } if *target == layout.trait_ty),
                    "dyn data pointer has the wrong pointee",
                )?;
                // rustc spells a trait object as an empty zero-sized
                // struct; a hand-built table may leave it opaque. Either
                // way it has no members of its own to read.
                let name = match self.ty(layout.trait_ty)? {
                    TypeDef::Opaque { name, .. } => name,
                    TypeDef::Struct {
                        name,
                        size: 0,
                        members,
                    } if members.is_empty() => name,
                    _ => return require(false, "dyn pointee is not a trait object"),
                };
                // A poll slot is a claim about where the trait puts
                // `Future::poll`, which the reviewed ABI settles only
                // for `dyn Future` itself. Another trait's object is
                // legal here — polling the adapter over it proves its
                // concrete pointee a future, and the vtable's drop glue
                // names which one — but it claims no slot.
                require(
                    layout.poll_slot.is_none()
                        || crate::names::is_future_trait_object(self.string(*name)?),
                    "a poll slot needs a Future trait object",
                )?;
                require(
                    (layout.drop_slot, layout.size_slot, layout.align_slot) == (0, 1, 2)
                        && matches!(layout.poll_slot, None | Some(3)),
                    "dyn ABI slots disagree with rule",
                )?;
                require(
                    layout.data.steps != layout.vtable.steps,
                    "dyn data and vtable alias",
                )
            }
        }
    }

    fn variants(&self, ty: BundleTypeId) -> Result<&'a [VariantDef]> {
        let TypeDef::Enum { shape, size, .. } = self.ty(ty)? else {
            return Err(Error::Corrupt("semantics: state is not an enum".into()));
        };
        require(!shape.variants.is_empty(), "state enum has no variants")?;
        if let Some(discr) = &shape.discr {
            require(
                matches!(
                    self.ty(discr.ty)?,
                    TypeDef::Base {
                        encoding: crate::Encoding::Signed | crate::Encoding::Unsigned,
                        size: 1 | 2 | 4 | 8 | 16,
                        ..
                    }
                ),
                "state discriminant is not a supported integer",
            )?;
            require(
                self.0
                    .types
                    .size_of(discr.ty)
                    .and_then(|n| discr.offset.checked_add(n))
                    .is_some_and(|end| end <= *size),
                "state discriminant is out of bounds",
            )?;
        } else {
            require(
                shape.variants.len() == 1,
                "multiple states require a discriminant",
            )?;
        }
        let mut names = BTreeSet::new();
        for variant in &shape.variants {
            require(
                names.insert(self.string(variant.name)?),
                "ambiguous variant name",
            )?;
        }
        Ok(&shape.variants)
    }

    fn roles(&self, root: BundleTypeId, roles: &[WalkRole]) -> Result<()> {
        for role in roles {
            let binding = self.0.walks.entries.get(role);
            require(
                binding.is_some_and(|b| {
                    matches!(b.outcome, WalkOutcome::Bound { .. }) && b.roots.contains(&root)
                }),
                "essential walk role is not bound for this root",
            )?;
        }
        Ok(())
    }

    fn routes(&self, routes: &[WalkRole]) -> Result<()> {
        for role in routes {
            let binding = self.0.walks.entries.get(role);
            require(
                binding.is_some_and(|b| matches!(b.outcome, WalkOutcome::Bound { .. })),
                "essential walk route is not bound",
            )?;
        }
        Ok(())
    }

    fn resource(&self, record: &TypeSemantics, binding: &ResourceBinding) -> Result<()> {
        use SemanticRuleKind::*;
        let ty = record.ty;
        // A connection resource is hyper's dispatcher, whose state words
        // the connection binding routes to, or hyper-util's
        // version-choosing wrapper while it still reads the first
        // bytes — a connection with no HTTP/1 words yet, under the
        // wrapper's own rule.
        let kinds: &[SemanticRuleKind] = match binding.kind {
            ResourceKind::Sleep => &[TokioSleep],
            ResourceKind::JoinHandle => &[TokioJoinHandle],
            ResourceKind::SemaphoreAcquire => &[TokioAcquire],
            ResourceKind::IoOperation(IoOperationKind::Handshake) => &[TokioRustlsHandshake],
            ResourceKind::IoOperation(_) => &[TokioIoOperation],
            ResourceKind::MpscRecv => &[TokioMpscRecv],
            ResourceKind::Notified => &[TokioNotified],
            ResourceKind::OneshotRecv => &[TokioOneshotRecv],
            ResourceKind::HttpConn => &[HyperH1Conn, HyperUtilAutoConn],
        };
        let rule = self.rule(binding.rule, kinds)?;
        self.roles(ty, required_resource_roles(binding.kind))?;
        self.routes(required_resource_routes(binding.kind))?;
        // The connection's words are reached by the record's own
        // paths, not by walk roles: the binding that holds them is the
        // resource's, under the same rule — and only the dispatcher
        // has words to hold; the wrapper still choosing a version
        // carries none.
        require(
            (binding.kind == ResourceKind::HttpConn && rule.kind == HyperH1Conn)
                == record
                    .http
                    .as_ref()
                    .is_some_and(|http| http.rule == binding.rule),
            "HTTP connection resource and binding disagree",
        )?;
        // An operation over a stream reaches it by the record's own
        // path, under the operation's rule; a readiness await names its
        // registration through walk roles and holds no stream.
        require(
            matches!(binding.kind, ResourceKind::IoOperation(op) if op != IoOperationKind::Readiness)
                == record.io.as_ref().is_some_and(|io| io.rule == binding.rule),
            "io operation resource and binding disagree",
        )?;
        if let Some(state_rule) = binding.state_rule {
            let kind = match binding.kind {
                ResourceKind::Sleep => TokioSleepState,
                ResourceKind::JoinHandle => TokioJoinHandleState,
                ResourceKind::SemaphoreAcquire => TokioAcquireState,
                // A handshake's protocol, like a connection's, is its
                // own rule.
                ResourceKind::IoOperation(IoOperationKind::Handshake) => {
                    require(
                        state_rule == binding.rule,
                        "a handshake's protocol is not the handshake's own rule",
                    )?;
                    rule.kind
                }
                ResourceKind::IoOperation(_) => TokioIoState,
                ResourceKind::MpscRecv => TokioMpscRecvState,
                ResourceKind::Notified => TokioNotifiedState,
                ResourceKind::OneshotRecv => TokioOneshotRecvState,
                // The reviewed range is the state protocol: the same
                // rule, whose delegation origin binds only inside it.
                ResourceKind::HttpConn => {
                    require(
                        state_rule == binding.rule,
                        "HTTP connection protocol is not the connection's own rule",
                    )?;
                    rule.kind
                }
            };
            self.rule(state_rule, &[kind])?;
        }
        // Whether a pending primitive polls nothing else is a fact about
        // its reviewed implementation, and the state protocol is the
        // review: a layout binding alone carries no such guarantee.
        require(
            !binding.exclusive_pending || binding.state_rule.is_some(),
            "unreviewed exclusive-pending guarantee",
        )
    }

    /// One step of a stream's route: a forward to another type, under
    /// tokio's route rule or a reviewed third-party stream's; a match
    /// over an enum's variants, under tokio-rustls's; or a socket whose
    /// roles are bound at exactly this type, under tokio's. That every
    /// forward reaches a routed type, and every route a socket, is the
    /// whole table's to say ([`io_routes_end_at_sockets`]).
    fn io_route(&self, record: &TypeSemantics, binding: &IoRouteBinding) -> Result<()> {
        use SemanticRuleKind::*;
        let forward = |inner: &TypedPath| {
            self.path(record.ty, inner)?;
            require(
                inner.target != record.ty,
                "a stream route forwards to itself",
            )
        };
        match &binding.step {
            IoRouteStep::Forward { inner } => {
                self.rule(
                    binding.rule,
                    &[
                        TokioIoRoute,
                        TokioRustlsStream,
                        SprocketsTlsStream,
                        HyperUtilStream,
                        DropshotTlsConn,
                        ReqwestConn,
                    ],
                )?;
                forward(inner)
            }
            IoRouteStep::Match { cases } => {
                self.rule(binding.rule, &[TokioRustlsStream, HyperRustlsStream])?;
                require(!cases.is_empty(), "a stream match has no case")?;
                let mut variants = BTreeSet::new();
                for case in cases {
                    let Some(Step::Variant(variant)) = case.steps.first() else {
                        return Err(Error::Corrupt(
                            "semantics: a stream match case selects no variant first".into(),
                        ));
                    };
                    require(
                        variants.insert(*variant),
                        "a stream match selects one variant twice",
                    )?;
                    forward(case)?;
                }
                Ok(())
            }
            IoRouteStep::Dyn {
                pointer,
                layout,
                cases,
            } => {
                self.rule(binding.rule, &[ReqwestConn])?;
                self.rule(layout.abi, &[DynFutureAbi])?;
                forward(pointer)?;
                for (word, what) in [(&layout.data, "data"), (&layout.vtable, "vtable")] {
                    self.path(pointer.target, word)?;
                    require(
                        self.0.types.size_of(word.target) == Some(crate::POINTER_SIZE),
                        &format!("a stream trait object's {what} word is not a pointer"),
                    )?;
                }
                // The header's words first, then the trait's methods.
                require(
                    layout.size_slot != layout.align_slot
                        && layout.read_slot > layout.size_slot
                        && layout.read_slot > layout.align_slot,
                    "a stream trait object's vtable slots overlap",
                )?;
                require(!cases.is_empty(), "a stream trait object has no case")?;
                let mut seen = BTreeSet::new();
                for case in cases {
                    self.string(case.symbol)?;
                    self.ty(case.target)?;
                    require(
                        case.target != record.ty,
                        "a stream route forwards to itself",
                    )?;
                    require(
                        seen.insert((case.symbol, case.target)),
                        "a stream trait object lists one case twice",
                    )?;
                }
                Ok(())
            }
            IoRouteStep::Socket(socket) => {
                self.rule(binding.rule, &[TokioIoRoute])?;
                self.roles(record.ty, &socket_roles(*socket))
            }
        }
    }

    /// A rustls connection's words, under rustls's session rule: its
    /// state a `Result`, its side a C-like enum, its version an
    /// option whose payload's variant is read, one-byte flags and
    /// unsigned sequence words, every path starting at the connection.
    fn tls_session(&self, record: &TypeSemantics, binding: &TlsSessionBinding) -> Result<()> {
        self.rule(binding.rule, &[SemanticRuleKind::RustlsSession])?;
        let variant_names = |path: &TypedPath, what: &str| -> Result<BTreeSet<&str>> {
            self.path(record.ty, path)?;
            require(
                matches!(self.ty(path.target)?, TypeDef::Enum { .. }),
                &format!("TLS session {what} is not an enum"),
            )?;
            self.variants(path.target)?
                .iter()
                .map(|variant| self.string(variant.name))
                .collect()
        };
        require(
            variant_names(&binding.state, "state")? == BTreeSet::from(["Ok", "Err"]),
            "TLS session state is not a result",
        )?;
        self.path(record.ty, &binding.side)?;
        require(
            matches!(self.ty(binding.side.target)?, TypeDef::CEnum { .. }),
            "TLS session side is not a C-like enum",
        )?;
        require(
            variant_names(&binding.negotiated_version, "version")?
                == BTreeSet::from(["None", "Some"]),
            "TLS session version is not an option",
        )?;
        variant_names(&binding.version, "version name")?;
        require(
            binding
                .version
                .steps
                .starts_with(&binding.negotiated_version.steps)
                && matches!(
                    binding.version.steps.get(binding.negotiated_version.steps.len()),
                    Some(Step::Variant(v)) if self.string(*v)? == "Some"
                ),
            "TLS session version name is not selected from its option",
        )?;
        for flag in [
            &binding.may_send_application_data,
            &binding.may_receive_application_data,
            &binding.has_sent_close_notify,
            &binding.has_received_close_notify,
            &binding.has_seen_eof,
            &binding.sent_fatal_alert,
        ] {
            self.path(record.ty, flag)?;
            require(
                self.0.types.size_of(flag.target) == Some(1),
                "TLS session flag is not one byte",
            )?;
        }
        for seq in [&binding.read_seq, &binding.write_seq] {
            self.path(record.ty, seq)?;
            self.unsigned_word(seq, "TLS session count is not an unsigned word")?;
        }
        self.chunks(record, &binding.sendable)?;
        if let Some(received) = &binding.received {
            self.chunks(record, received)?;
        }
        // How the handshake went: a C-like enum selected out of its
        // option. The suite: an enum behind the `&'static` each variant
        // of the chosen suite holds. ALPN's text, and the count of the
        // peer's certificates, words like any other.
        if let Some(kind) = &binding.handshake_kind {
            self.path(record.ty, kind)?;
            require(
                matches!(self.ty(kind.target)?, TypeDef::CEnum { .. })
                    && kind
                        .steps
                        .iter()
                        .any(|step| matches!(step, Step::Variant(_))),
                "TLS session handshake kind is not a C-like enum in an option",
            )?;
        }
        for suite in &binding.suites {
            self.path(record.ty, suite)?;
            require(
                matches!(
                    self.ty(suite.target)?,
                    TypeDef::Enum { .. } | TypeDef::CEnum { .. }
                ) && suite.steps.contains(&Step::Deref),
                "TLS session suite is not an enum behind its pointer",
            )?;
        }
        match (&binding.alpn_ptr, &binding.alpn_len) {
            (Some(ptr), Some(len)) => self.text(record.ty, ptr, len, "TLS session ALPN")?,
            (None, None) => {}
            _ => return require(false, "TLS session ALPN is not a pointer and a length"),
        }
        if let Some(count) = &binding.peer_certificates {
            self.path(record.ty, count)?;
            self.unsigned_word(
                count,
                "TLS session certificate count is not an unsigned word",
            )?;
        }
        Ok(())
    }

    /// One of rustls's record buffers: a ring of `Vec<u8>` records, its
    /// words unsigned, its storage a pointer the records stride from,
    /// each one a sized record whose length is a word.
    fn chunks(&self, record: &TypeSemantics, sendable: &SendableBinding) -> Result<()> {
        for seq in [
            &sendable.prefix_used,
            &sendable.head,
            &sendable.len,
            &sendable.cap,
        ] {
            self.path(record.ty, seq)?;
            self.unsigned_word(seq, "TLS session count is not an unsigned word")?;
        }
        self.path(record.ty, &sendable.buf)?;
        require(
            matches!(self.ty(sendable.buf.target)?, TypeDef::Pointer { .. }),
            "TLS session record ring is not behind a pointer",
        )?;
        require(
            matches!(self.ty(sendable.record)?, TypeDef::Struct { .. })
                && self
                    .0
                    .types
                    .size_of(sendable.record)
                    .is_some_and(|size| size > 0),
            "TLS session record is not a sized struct",
        )?;
        self.path(sendable.record, &sendable.record_len)?;
        self.unsigned_word(
            &sendable.record_len,
            "TLS session record length is not an unsigned word",
        )
    }

    /// Whether a path lands on a `u64`.
    fn unsigned_word(&self, path: &TypedPath, what: &str) -> Result<()> {
        require(
            matches!(
                self.ty(path.target)?,
                TypeDef::Base {
                    encoding: crate::Encoding::Unsigned,
                    size: 8,
                    ..
                }
            ),
            what,
        )
    }

    /// A TLS stream's words, under its route's rule: the connection it
    /// holds, landing on a session, and its own state enum.
    fn tls_stream(
        &self,
        record: &TypeSemantics,
        binding: &TlsStreamBinding,
        session: &impl Fn(BundleTypeId) -> bool,
    ) -> Result<()> {
        self.rule(binding.rule, &[SemanticRuleKind::TokioRustlsStream])?;
        require(
            record
                .io_route
                .as_ref()
                .is_some_and(|route| route.rule == binding.rule),
            "TLS stream binding is not its route's",
        )?;
        self.path(record.ty, &binding.session)?;
        require(
            session(binding.session.target),
            "TLS stream's connection has no session binding",
        )?;
        self.path(record.ty, &binding.state)?;
        require(
            matches!(
                self.ty(binding.state.target)?,
                TypeDef::Enum { .. } | TypeDef::CEnum { .. }
            ),
            "TLS stream state is not an enum",
        )
    }

    /// A stream's peer, under its route's rule: a path to an array of
    /// unsigned bytes.
    fn stream_peer(&self, record: &TypeSemantics, binding: &StreamPeerBinding) -> Result<()> {
        self.rule(binding.rule, &[SemanticRuleKind::SprocketsTlsStream])?;
        require(
            record
                .io_route
                .as_ref()
                .is_some_and(|route| route.rule == binding.rule),
            "stream peer binding is not its route's",
        )?;
        self.path(record.ty, &binding.name)?;
        self.byte_array(&binding.name, "stream peer name")
    }

    /// Whether a path lands on a nonempty array of unsigned bytes.
    fn byte_array(&self, path: &TypedPath, what: &str) -> Result<()> {
        let TypeDef::Array { elem, count } = self.ty(path.target)? else {
            return Err(Error::Corrupt(format!("semantics: {what} is not an array")));
        };
        require(
            *count > 0
                && matches!(
                    self.ty(*elem)?,
                    TypeDef::Base {
                        encoding: crate::Encoding::Unsigned,
                        size: 1,
                        ..
                    }
                ),
            &format!("{what} is not an array of bytes"),
        )
    }

    /// What a handshake's frame keeps of the far end, under its crate's
    /// rule: per state, every path entering one variant of the
    /// coroutine first, the same for all three; the stream landing on a
    /// routed TLS stream, the address on an enum, the name on an array
    /// of bytes; and no state named twice.
    fn far_end(
        &self,
        record: &TypeSemantics,
        binding: &FarEndBinding,
        tls_stream: &impl Fn(BundleTypeId) -> bool,
    ) -> Result<()> {
        self.rule(binding.rule, &[SemanticRuleKind::SprocketsHandshake])?;
        require(!binding.states.is_empty(), "far end binding has no state")?;
        let mut variants = BTreeSet::new();
        for state in &binding.states {
            let Some(variant @ Step::Variant(name)) = state.stream.steps.first() else {
                return Err(Error::Corrupt(
                    "semantics: a far end's stream selects no state first".into(),
                ));
            };
            require(
                variants.insert(*name),
                "far end binding names a state twice",
            )?;
            let in_state = |path: &TypedPath, what: &str| -> Result<()> {
                self.path(record.ty, path)?;
                require(path.steps.first() == Some(variant), what)
            };
            in_state(&state.stream, "far end stream is outside its state")?;
            require(
                tls_stream(state.stream.target),
                "far end stream is not a routed TLS stream",
            )?;
            if let Some(addr) = &state.addr {
                in_state(addr, "far end address is outside its state")?;
                require(
                    matches!(self.ty(addr.target)?, TypeDef::Enum { .. }),
                    "far end address is not an enum",
                )?;
            }
            if let Some(name) = &state.name {
                in_state(name, "far end name is outside its state")?;
                self.byte_array(name, "far end name")?;
            }
        }
        Ok(())
    }

    /// An operation's stream, under the resource's rule: a path through
    /// the future's `&mut`, landing on a routed type; and the length it
    /// completes by, where it has one, an unsigned word.
    fn io_operation(
        &self,
        record: &TypeSemantics,
        binding: &IoOperationBinding,
        routed: &impl Fn(BundleTypeId) -> bool,
    ) -> Result<()> {
        let rule = self.rule(
            binding.rule,
            &[
                SemanticRuleKind::TokioIoOperation,
                SemanticRuleKind::TokioRustlsHandshake,
            ],
        )?;
        self.path(record.ty, &binding.stream)?;
        // tokio's operations poll a stream they borrow; a handshake
        // holds its stream in the variant it is handshaking in.
        if rule.kind == SemanticRuleKind::TokioRustlsHandshake {
            require(
                matches!(binding.stream.steps.first(), Some(Step::Variant(_))),
                "a handshake's stream is not selected from its state",
            )?;
        } else {
            require(
                binding.stream.steps.last() == Some(&Step::Deref),
                "an io operation's stream is not behind its pointer",
            )?;
        }
        require(
            routed(binding.stream.target),
            "an io operation's stream has no route",
        )?;
        if let Some(remaining) = &binding.remaining {
            self.path(record.ty, remaining)?;
            require(
                matches!(
                    self.ty(remaining.target)?,
                    TypeDef::Base {
                        encoding: crate::Encoding::Unsigned,
                        size: 8,
                        ..
                    }
                ),
                "an io operation's remaining length is not an unsigned word",
            )?;
        }
        Ok(())
    }

    /// A refcount header's value is one member of its own struct, named
    /// and unique, past the counts at its start.
    fn refcount(&self, record: &TypeSemantics, binding: &RefcountBinding) -> Result<()> {
        require(
            matches!(record.storage, StoragePolicy::DeclaredMembers),
            "refcount binding needs declared-member storage",
        )?;
        require(
            matches!(binding.value, MemberRef::Named(_)),
            "a refcount header's value is addressed by name",
        )?;
        let TypeDef::Struct { members, .. } = self.ty(record.ty)? else {
            return Err(Error::Corrupt(
                "semantics: a refcount header is not a struct".into(),
            ));
        };
        let at = binding
            .value
            .resolve(members.len(), |i, name| members[i].name == name)
            .ok_or_else(|| Error::Corrupt("semantics: no unique refcount value member".into()))?;
        require(
            members[at].offset > 0,
            "a refcount header's value sits past its counts",
        )
    }

    /// A lock word is a whole unsigned integer inside the lock, and its
    /// mask names bits of it.
    fn lock(&self, record: &TypeSemantics, word: &LockWord) -> Result<()> {
        require(
            matches!(record.storage, StoragePolicy::DeclaredMembers),
            "lock binding needs declared-member storage",
        )?;
        require(
            matches!(word.size, 1 | 2 | 4 | 8),
            "a lock word is 1, 2, 4 or 8 bytes",
        )?;
        let bits = u32::from(word.size) * 8;
        require(
            word.locked_mask != 0 && (bits == 64 || word.locked_mask >> bits == 0),
            "a lock's mask names no bit of its word",
        )?;
        let size = match self.ty(record.ty)? {
            TypeDef::Struct { size, .. } | TypeDef::Union { size, .. } => *size,
            _ => return Err(Error::Corrupt("semantics: a lock is not a struct".into())),
        };
        require(
            word.offset
                .checked_add(u64::from(word.size))
                .is_some_and(|end| end <= size),
            "a lock word lies past the lock",
        )
    }

    /// An HTTP/1 connection binding: every path walks from the record's
    /// type — the dispatcher — to a word of the shape the verdict reads,
    /// under the hyper rule, and the role's own dispatch paths are
    /// there for the role and for no other.
    /// A request binding: under one of the rules whose crate keeps a
    /// request's words, the method routes to an enum and the target's
    /// text to a byte pointer and a word, the three from the record's
    /// own type.
    fn request(&self, record: &TypeSemantics, binding: &HttpRequestBinding) -> Result<()> {
        self.rule(
            binding.rule,
            &[
                SemanticRuleKind::ReqwestPendingRequest,
                SemanticRuleKind::HttpRequest,
                SemanticRuleKind::DropshotRequestContext,
            ],
        )?;
        self.path(record.ty, &binding.method)?;
        require(
            matches!(self.ty(binding.method.target)?, TypeDef::Enum { .. }),
            "HTTP request method is not an enum",
        )?;
        self.text(
            record.ty,
            &binding.target_ptr,
            &binding.target_len,
            "HTTP request target",
        )
    }

    /// A hash table's words: two unsigned words and a pointer to the
    /// control bytes, each its own member, and a sized bucket type the
    /// entries are read as.
    fn table(&self, record: &TypeSemantics, binding: &HashTableBinding) -> Result<()> {
        self.rule(binding.rule, &[SemanticRuleKind::HashbrownTable])?;
        let word = |ty: &TypeDef| {
            matches!(
                ty,
                TypeDef::Base {
                    encoding: crate::Encoding::Unsigned,
                    size: 8,
                    ..
                }
            )
        };
        self.path(record.ty, &binding.bucket_mask)?;
        require(
            word(self.ty(binding.bucket_mask.target)?),
            "hash table bucket mask is not an unsigned word",
        )?;
        self.path(record.ty, &binding.items)?;
        require(
            word(self.ty(binding.items.target)?),
            "hash table item count is not an unsigned word",
        )?;
        self.path(record.ty, &binding.ctrl)?;
        let byte = match self.ty(binding.ctrl.target)? {
            TypeDef::Pointer { target, .. } => self.ty(*target)?,
            _ => {
                return require(
                    false,
                    "hash table control bytes are not reached by a pointer",
                );
            }
        };
        require(
            matches!(
                byte,
                TypeDef::Base {
                    encoding: crate::Encoding::Unsigned,
                    size: 1,
                    ..
                }
            ),
            "hash table control pointer does not point at bytes",
        )?;
        require(
            binding.bucket_mask.steps != binding.items.steps
                && binding.bucket_mask.steps != binding.ctrl.steps
                && binding.items.steps != binding.ctrl.steps,
            "hash table reads one member as two of its words",
        )?;
        self.ty(binding.bucket)?;
        require(
            self.0.types.size_of(binding.bucket).is_some(),
            "hash table bucket type is unsized",
        )
    }

    fn http(
        &self,
        record: &TypeSemantics,
        binding: &HttpConnBinding,
        routed: &impl Fn(BundleTypeId) -> bool,
    ) -> Result<()> {
        self.rule(binding.rule, &[SemanticRuleKind::HyperH1Conn])?;
        // The binding is the resource's: the words it routes to are
        // what the connection resource reads. That the resource is the
        // connection kind under this same rule is the resource check's
        // to hold, which it does before this runs; here only its
        // presence is in question.
        require(
            record.resource.is_some(),
            "HTTP connection binding has no resource",
        )?;
        let enumeration = |path: &TypedPath, what: &str| -> Result<()> {
            self.path(record.ty, path)?;
            require(
                matches!(self.ty(path.target)?, TypeDef::Enum { .. }),
                &format!("HTTP connection {what} is not an enum"),
            )
        };
        // `KA` carries no payload: a C-like enum, read by enumerator.
        self.path(record.ty, &binding.keep_alive)?;
        require(
            matches!(self.ty(binding.keep_alive.target)?, TypeDef::CEnum { .. }),
            "HTTP connection keep-alive is not a C-like enum",
        )?;
        enumeration(&binding.reading, "reading")?;
        enumeration(&binding.writing, "writing")?;
        enumeration(&binding.method, "method")?;
        // The words inside a word: each is reached through the enum it
        // sits in, selecting the variant that carries it.
        for (inner, through, what) in [
            (&binding.method_inner, &binding.method, "method name"),
            (
                &binding.read_continue_kind,
                &binding.reading,
                "continue framing",
            ),
            (&binding.read_body_kind, &binding.reading, "read framing"),
            (&binding.write_body_kind, &binding.writing, "write framing"),
        ] {
            enumeration(inner, what)?;
            require(
                inner.steps.starts_with(&through.steps)
                    && matches!(inner.steps.get(through.steps.len()), Some(Step::Variant(_))),
                &format!("HTTP connection {what} is not selected from its word"),
            )?;
        }
        self.path(record.ty, &binding.is_closing)?;
        require(
            self.0.types.size_of(binding.is_closing.target) == Some(1),
            "HTTP connection closing flag is not one byte",
        )?;
        // The stream the connection reads, where one is bound: through
        // the connection member, onto a routed type.
        if let Some(stream) = &binding.stream {
            self.path(record.ty, stream)?;
            require(
                stream.steps.first() == binding.keep_alive.steps.first(),
                "HTTP connection stream is not reached through the connection",
            )?;
            require(routed(stream.target), "HTTP connection stream has no route")?;
        }
        require(
            (binding.role == HttpRole::Client) == binding.client.is_some()
                && (binding.role == HttpRole::Server) == binding.server.is_some(),
            "HTTP connection dispatch paths disagree with the role",
        )?;
        if let Some(client) = &binding.client {
            enumeration(&client.callback, "callback")?;
            for sender in [&client.retry, &client.no_retry] {
                self.path(record.ty, sender)?;
                require(
                    sender.steps.starts_with(&client.callback.steps)
                        && sender.steps.len() > client.callback.steps.len(),
                    "HTTP callback sender is not reached through the callback",
                )?;
            }
            self.path(record.ty, &client.rx)?;
            self.pointer(record.ty, &client.want, "HTTP receiver's want handle")?;
        }
        if let Some(server) = &binding.server {
            // The handler's `Option`, behind the pinned box the route
            // crosses: read for whether a request is being handled.
            enumeration(&server.in_flight, "in-flight handler")?;
            self.path(record.ty, &server.header_read_timeout_running)?;
            require(
                self.0
                    .types
                    .size_of(server.header_read_timeout_running.target)
                    == Some(1),
                "HTTP header-read timer flag is not one byte",
            )?;
            // The timeout's two words: unsigned words of `Duration`'s
            // widths, reached through the state the connection's words
            // sit in and selected out of the `Option`, so a server with
            // no timeout reads as none rather than as whatever `None`
            // leaves there.
            let state = binding
                .keep_alive
                .steps
                .split_last()
                .map_or(&[][..], |(_, state)| state);
            for (word, size, what) in [
                (&server.header_read_timeout_secs, 8, "seconds"),
                (&server.header_read_timeout_nanos, 4, "nanoseconds"),
            ] {
                self.path(record.ty, word)?;
                require(
                    matches!(
                        self.ty(word.target)?,
                        TypeDef::Base {
                            encoding: crate::Encoding::Unsigned,
                            size: s,
                            ..
                        } if *s == size
                    ),
                    &format!("HTTP header-read timeout {what} is not an unsigned word"),
                )?;
                require(
                    !state.is_empty()
                        && word.steps.starts_with(state)
                        && word.steps[state.len()..]
                            .iter()
                            .any(|step| matches!(step, Step::Variant(_))),
                    &format!("HTTP header-read timeout {what} is not selected from the state"),
                )?;
            }
            // The timer's address: a pointer, selected out of the
            // state's `Option` the same way.
            let timer = &server.header_read_timer;
            self.path(record.ty, timer)?;
            require(
                matches!(self.ty(timer.target)?, TypeDef::Pointer { .. }),
                "HTTP header-read timer is not a pointer",
            )?;
            require(
                !state.is_empty()
                    && timer.steps.starts_with(state)
                    && timer.steps[state.len()..]
                        .iter()
                        .any(|step| matches!(step, Step::Variant(_))),
                "HTTP header-read timer is not selected from the state",
            )?;
            // The service: under its crate's own rule, the peer an
            // address enum reached through the dispatch, past the
            // handler, and the context a type the table carries. The
            // server's state is past the handler too, behind the
            // pointer it shares: the listening address the peer's
            // type, the acceptor an enum.
            if let Some(service) = &server.service {
                self.rule(service.rule, &[SemanticRuleKind::DropshotRequestHandler])?;
                enumeration(&service.peer, "peer address")?;
                require(
                    service.peer.steps.len() > 2
                        && service.peer.steps[0] == server.in_flight.steps[0],
                    "HTTP peer address is not reached through the dispatch",
                )?;
                self.ty(service.context)?;
                let handler = &service.peer.steps[..2];
                let shared = |path: &TypedPath, what: &str| -> Result<()> {
                    enumeration(path, what)?;
                    require(
                        path.steps.starts_with(handler) && path.steps.contains(&Step::Deref),
                        &format!("HTTP server {what} is not reached through the handler's state"),
                    )
                };
                if let Some(local_addr) = &service.local_addr {
                    shared(local_addr, "listening address")?;
                    require(
                        local_addr.target == service.peer.target,
                        "HTTP server listening address is not the peer's address type",
                    )?;
                }
                if let Some(tls_acceptor) = &service.tls_acceptor {
                    shared(tls_acceptor, "TLS acceptor")?;
                }
            }
        }
        Ok(())
    }

    /// A `select!` binding: both routes walk from the record's type
    /// through the closure's references, the mask lands on an unsigned
    /// word of a width tokio-macros emits, the tuple is an aggregate,
    /// and every branch is one of its members — no more of them than
    /// the mask has bits.
    fn select(&self, record: &TypeSemantics, binding: &SelectBinding) -> Result<()> {
        self.rule(binding.rule, &[SemanticRuleKind::TokioSelect])?;
        self.path(record.ty, &binding.mask)?;
        require(
            matches!(binding.mask.steps.last(), Some(Step::Deref)),
            "select mask is not reached through the closure's reference",
        )?;
        let width = match self.ty(binding.mask.target)? {
            TypeDef::Base {
                encoding: crate::Encoding::Unsigned,
                size: size @ (1 | 2 | 4 | 8),
                ..
            } => *size,
            _ => return require(false, "select mask is not an unsigned word"),
        };
        self.path(record.ty, &binding.futures)?;
        require(
            matches!(binding.futures.steps.last(), Some(Step::Deref)),
            "select tuple is not reached through the closure's reference",
        )?;
        let TypeDef::Struct { members, .. } = self.ty(binding.futures.target)? else {
            return require(false, "select tuple is not an aggregate");
        };
        require(!binding.branches.is_empty(), "select has no branches")?;
        require(
            binding.branches.len() <= members.len() && binding.branches.len() as u64 <= width * 8,
            "select has more branches than tuple members or mask bits",
        )?;
        let mut seen = BTreeSet::new();
        for branch in &binding.branches {
            let [Step::Member(MemberRef::Named(name))] = branch.steps.as_slice() else {
                return require(false, "select branch is not one named tuple member");
            };
            require(seen.insert(*name), "duplicate select branch")?;
            self.path(binding.futures.target, branch)?;
        }
        require(
            binding.arms.len() == binding.branches.len(),
            "select arms do not pair with its branches",
        )?;
        for arm in binding.arms.iter().flatten() {
            self.string(arm.file)?;
        }
        Ok(())
    }

    fn coroutine(&self, record: &TypeSemantics, layout: &CoroutineLayout) -> Result<()> {
        self.rule(
            layout.rule,
            &[
                SemanticRuleKind::RustcAsyncFn,
                SemanticRuleKind::RustcAsyncBlock,
            ],
        )?;
        require(
            record.storage == StoragePolicy::CoroutineStates,
            "coroutine layout requires state storage",
        )?;
        let variants = self.variants(record.ty)?;
        let mut seen = BTreeSet::new();
        for state in &layout.states {
            require(seen.insert(state.variant), "duplicate coroutine state")?;
            let variant = variants
                .iter()
                .find(|v| v.name == state.variant)
                .ok_or_else(|| Error::Corrupt("semantics: unknown coroutine variant".into()))?;
            self.path(
                record.ty,
                &TypedPath {
                    steps: vec![Step::Variant(state.variant)],
                    target: variant.payload.ty,
                },
            )?;
            let TypeDef::Struct { members, .. } = self.ty(variant.payload.ty)? else {
                return require(false, "coroutine payload is not a struct");
            };
            let mut names = BTreeSet::new();
            for &name in state.locals.iter().chain(&state.uncertain_locals) {
                self.string(name)?;
                require(
                    names.insert(name),
                    "duplicate or overlapping coroutine locals",
                )?;
                let mut found = members.iter().filter(|m| m.name == name);
                let member = found
                    .next()
                    .ok_or_else(|| Error::Corrupt("semantics: missing coroutine local".into()))?;
                require(found.next().is_none(), "ambiguous coroutine local")?;
                self.path(
                    record.ty,
                    &TypedPath {
                        steps: vec![
                            Step::Variant(state.variant),
                            Step::Member(MemberRef::Named(name)),
                        ],
                        target: member.ty,
                    },
                )?;
            }
            if matches!(
                state.stage,
                CoroutinePhase::Returned | CoroutinePhase::Panicked
            ) {
                require(names.is_empty(), "terminal coroutine state has locals")?;
            }
            if state.stage == CoroutinePhase::Unknown {
                require(
                    state.locals.is_empty(),
                    "unknown coroutine state has initialized locals",
                )?;
            }
        }
        require(seen.len() == variants.len(), "missing coroutine states")
    }

    fn action(
        &self,
        record: &TypeSemantics,
        rule: SemanticRuleId,
        action: &PollAction,
        guard: Option<(&TypedPath, StrRef)>,
    ) -> Result<()> {
        use SemanticRuleKind::*;
        match action {
            PollAction::Delegate { target, exclusive } => {
                let binding = self.rule(
                    rule,
                    &[
                        RustcAsyncFn,
                        RustcAsyncBlock,
                        StdBoxPoll,
                        StdMutRefPoll,
                        StdPinBoxPoll,
                        StdPinMutRefPoll,
                        TracingInstrumented,
                        FuturesUtilMap,
                        FuturesUtilMapErr,
                        FuturesUtilIntoFuture,
                        HyperUtilTokioSleep,
                        TokioCoop,
                        FuturesUtilNext,
                        TokioIntervalTick,
                        HyperH1Conn,
                        HyperUtilAutoConn,
                        FuturesUtilEither,
                        TowerRetry,
                        ReqwestCookie,
                        HyperUtilResponseFuture,
                        TokioRustlsHandshake,
                    ],
                )?;
                self.target(record.ty, target)?;
                // The wire bit cannot promote a structurally valid path into
                // reviewed control flow: only a rule revision whose reviewed
                // implementation polls nothing but its delegate may carry
                // it. A coroutine resumes into its awaitee alone; the std
                // adapters forward one poll and nothing else, as do the
                // reviewed futures-util combinators, hyper-util's sleep
                // newtype, tokio's cooperative wrapper, whose budget
                // check polls nothing, and futures-util's `Next`, whose
                // poll is its stream's `poll_next` alone. `Instrumented`
                // enters a span around its poll, running subscriber
                // callbacks the review does not bound, so it stays
                // false. The tick's `PollFn` polls the interval's box
                // and, while that is pending, nothing else. hyper's
                // connection wrappers poll the dispatcher inside them
                // and act only on its output, and hyper-util's
                // version-choosing wrapper polls the HTTP/1 connection
                // its `H1` state holds the same way. futures-util's
                // `Either` polls the side it holds, tower's retry the
                // future its state holds, reqwest's cookie layer the
                // service's future, and hyper-util's response future the
                // box its wrapper lends, each and nothing else, as
                // tokio-rustls's `Connect` and `Accept` poll the handshake
                // they hold.
                let reviewed = matches!(
                    binding.kind,
                    RustcAsyncFn
                        | RustcAsyncBlock
                        | StdBoxPoll
                        | StdMutRefPoll
                        | StdPinBoxPoll
                        | StdPinMutRefPoll
                        | FuturesUtilMap
                        | FuturesUtilMapErr
                        | FuturesUtilIntoFuture
                        | HyperUtilTokioSleep
                        | TokioCoop
                        | FuturesUtilNext
                        | TokioIntervalTick
                        | HyperH1Conn
                        | HyperUtilAutoConn
                        | FuturesUtilEither
                        | TowerRetry
                        | ReqwestCookie
                        | HyperUtilResponseFuture
                        | TokioRustlsHandshake
                );
                require(!exclusive || reviewed, "unreviewed delegation exclusivity")?;
                let path = match target {
                    FutureTarget::Value(p) => p,
                    FutureTarget::Dynamic { pointer, .. } => pointer,
                };
                if let Some((state, variant)) = guard {
                    require(
                        path.steps.starts_with(&state.steps)
                            && path.steps.get(state.steps.len()) == Some(&Step::Variant(variant)),
                        "delegate does not carry its selected variant guard",
                    )?;
                } else {
                    require(
                        !path.steps.iter().any(|s| matches!(s, Step::Variant(_))),
                        "variant delegation requires a match guard",
                    )?;
                }
            }
            PollAction::Primitive => {
                self.rule(
                    rule,
                    &[
                        TokioSleep,
                        TokioJoinHandle,
                        TokioAcquire,
                        TokioIoOperation,
                        TokioMpscRecv,
                        TokioNotified,
                        TokioOneshotRecv,
                        HyperH1Conn,
                        HyperUtilAutoConn,
                        TokioRustlsHandshake,
                    ],
                )?;
                require(
                    record
                        .resource
                        .as_ref()
                        .is_some_and(|resource| resource.rule == rule),
                    "primitive has no compatible resource binding",
                )?;
            }
            // A terminal state is a state, so it needs the match that
            // selected it. Only a compiler coroutine is ever unresumed
            // or panicked; a reviewed combinator whose enum records
            // that it already produced its output is returned.
            PollAction::Unresumed | PollAction::Panicked => {
                self.rule(rule, &[RustcAsyncFn, RustcAsyncBlock])?;
                require(guard.is_some(), "a terminal state requires a variant guard")?;
            }
            PollAction::Returned => {
                self.rule(rule, &[RustcAsyncFn, RustcAsyncBlock, FuturesUtilMap])?;
                require(guard.is_some(), "a terminal state requires a variant guard")?;
            }
            // Never ready is a property of the type, not of a state,
            // and a type that has state to read — a resource, a
            // coroutine, a container, a select — is not one whose poll
            // reads nothing.
            PollAction::NeverReady => {
                self.rule(rule, &[CorePending, FuturesUtilPending])?;
                require(guard.is_none(), "never ready is not a state")?;
                require(
                    record.resource.is_none()
                        && record.coroutine.is_none()
                        && record.container.is_none()
                        && record.select.is_none(),
                    "never ready on a type with state to read",
                )?;
            }
            PollAction::Unknown(issue) => self.issue(issue)?,
        }
        Ok(())
    }

    fn program(
        &self,
        record: &TypeSemantics,
        rule: SemanticRuleId,
        program: &PollProgram,
    ) -> Result<()> {
        use SemanticRuleKind::*;
        let binding = self.rule(
            rule,
            &[
                RustcAsyncFn,
                RustcAsyncBlock,
                StdBoxPoll,
                StdMutRefPoll,
                StdPinBoxPoll,
                StdPinMutRefPoll,
                TracingInstrumented,
                FuturesUtilMap,
                FuturesUtilMapErr,
                FuturesUtilIntoFuture,
                HyperUtilTokioSleep,
                TokioCoop,
                FuturesUtilNext,
                TokioIntervalTick,
                TokioSleep,
                TokioJoinHandle,
                TokioAcquire,
                TokioIoOperation,
                TokioMpscRecv,
                TokioNotified,
                TokioOneshotRecv,
                CorePending,
                FuturesUtilPending,
                HyperH1Conn,
                HyperUtilAutoConn,
                FuturesUtilEither,
                TowerRetry,
                ReqwestCookie,
                HyperUtilResponseFuture,
                TokioRustlsHandshake,
            ],
        )?;
        require(
            !matches!(record.storage, StoragePolicy::Unavailable(_)),
            "bound program has unavailable storage",
        )?;
        if matches!(binding.kind, RustcAsyncFn | RustcAsyncBlock) {
            require(
                record.coroutine.is_some(),
                "compiler polling rule lacks a coroutine layout",
            )?;
        }
        match program {
            PollProgram::Direct(action) => {
                require(
                    record.coroutine.is_none(),
                    "coroutine requires a state match",
                )?;
                self.action(record, rule, action, None)
            }
            PollProgram::MatchVariant { state, cases } => {
                // Which rule kinds read a state is exegesis' business,
                // asserted over its real extractions: a bundle built by
                // hand to exercise the stateful executor names whatever
                // forwarding kind it has, and the structure below —
                // every variant covered, every delegate carrying its
                // own guard — is what makes such a program legible.
                self.path(record.ty, state)?;
                let variants = self.variants(state.target)?;
                let mut seen = BTreeSet::new();
                for case in cases {
                    require(seen.insert(case.variant), "duplicate poll case")?;
                    require(
                        variants.iter().any(|v| v.name == case.variant),
                        "poll case names an unknown variant",
                    )?;
                    self.action(record, rule, &case.action, Some((state, case.variant)))?;
                    if let Some(layout) = &record.coroutine {
                        require(
                            layout.rule == rule && state.steps.is_empty(),
                            "coroutine program uses a different state or rule",
                        )?;
                        let stage = layout
                            .states
                            .iter()
                            .find(|s| s.variant == case.variant)
                            .ok_or_else(|| {
                                Error::Corrupt("semantics: poll case lacks coroutine state".into())
                            })?;
                        require(
                            matches!(
                                (&stage.stage, &case.action),
                                (CoroutinePhase::Unresumed, PollAction::Unresumed)
                                    | (CoroutinePhase::Returned, PollAction::Returned)
                                    | (CoroutinePhase::Panicked, PollAction::Panicked)
                                    | (CoroutinePhase::Unknown, PollAction::Unknown(_))
                                    | (
                                        CoroutinePhase::Suspended,
                                        PollAction::Delegate { .. } | PollAction::Unknown(_)
                                    )
                            ),
                            "poll action disagrees with coroutine stage",
                        )?;
                        if let PollAction::Delegate { target, .. } = &case.action {
                            let path = match target {
                                FutureTarget::Value(path) => path,
                                FutureTarget::Dynamic { pointer, .. } => pointer,
                            };
                            require(
                                matches!(path.steps.get(1), Some(Step::Member(MemberRef::Named(name))) if stage.locals.contains(name)),
                                "coroutine delegate is not an initialized local",
                            )?;
                        }
                    }
                }
                require(seen.len() == variants.len(), "missing poll cases")
            }
        }
    }
}

/// The walk roles rooted at a socket a route ends at: the route to its
/// registration, and to its descriptor.
pub fn socket_roles(socket: IoSocket) -> [WalkRole; 2] {
    use WalkRole::*;
    match socket {
        IoSocket::TcpStream => [TcpStreamShared, TcpStreamFd],
        IoSocket::UnixStream => [UnixStreamShared, UnixStreamFd],
    }
}

/// Essential roles rooted at the resource type itself: a binding needs
/// every one of them bound at exactly that type. An io operation over a
/// stream needs none: the record's own binding reaches the stream, and
/// the stream's route reaches the socket, whose roles are the ones that
/// must bind.
pub fn required_resource_roles(kind: ResourceKind) -> &'static [WalkRole] {
    use WalkRole::*;
    match kind {
        ResourceKind::Sleep => &[SleepDeadline],
        ResourceKind::JoinHandle => &[JoinHandleRaw],
        ResourceKind::SemaphoreAcquire => &[
            AcquireSemaphore,
            AcquireNode,
            AcquireNumPermits,
            AcquireNeeded,
            AcquireQueued,
        ],
        ResourceKind::IoOperation(IoOperationKind::Readiness) => {
            &[ReadinessScheduledIo, ReadinessState, ReadinessWaiter]
        }
        ResourceKind::IoOperation(_) => &[],
        ResourceKind::MpscRecv => &[MpscRecvRx],
        ResourceKind::Notified => &[NotifiedNotify, NotifiedState, NotifiedCalls, NotifiedWaiter],
        ResourceKind::OneshotRecv => &[OneshotInner],
        // The connection's words are the record's own paths, under a
        // third-party rule the walk contract does not bind.
        ResourceKind::HttpConn => &[],
    }
}

/// Essential routes chained below those roles — rooted where a role
/// landed, so at other types — that must also have bound for the
/// binding to identify its resource: the waker, interest and ready flag
/// inside a readiness await's node.
pub fn required_resource_routes(kind: ResourceKind) -> &'static [WalkRole] {
    use WalkRole::*;
    match kind {
        ResourceKind::Sleep | ResourceKind::JoinHandle | ResourceKind::SemaphoreAcquire => &[],
        ResourceKind::IoOperation(IoOperationKind::Readiness) => &[
            ReadinessWaiterWaker,
            ReadinessWaiterInterest,
            ReadinessWaiterReady,
        ],
        ResourceKind::IoOperation(_) => &[],
        // The channel behind the receiver's `Rx`, and every word the
        // recv protocol reads from it: the sender count, the two list
        // positions, the block chain the head names, the receiver's
        // close flag and its registered waker. The bounded semaphore's
        // permit word and bound serve one branch (a receiver closed
        // from its own side) and are enrichment, not identity.
        ResourceKind::MpscRecv => &[
            MpscRecvChan,
            ChanTxCount,
            ChanTailPosition,
            ChanRxIndex,
            ChanRxHead,
            ChanRxClosed,
            ChanRxWakerState,
            ChanRxWaker,
            BlockStartIndex,
            BlockNext,
            BlockReadySlots,
        ],
        // The `Notify` the future borrowed and its wait list, whose
        // nodes carry the waker, the successor and the notification
        // word the protocol reads on the embedded node too.
        ResourceKind::Notified => &[
            NotifyState,
            NotifyQueueHead,
            NotifyWaiterNext,
            NotifyWaiterWaker,
            NotifyWaiterNotification,
        ],
        // The shared `Inner` behind the receiver's `Arc`: the state
        // word the recv protocol reads, the value whose presence says
        // whether a completion carried one, and the receiver's own
        // waker slot.
        ResourceKind::OneshotRecv => &[OneshotState, OneshotValue, OneshotRxTask],
        ResourceKind::HttpConn => &[],
    }
}

/// The route that identifies a task cell's scheduler `S` as one class:
/// the data behind the flavor handle's `Arc`, the `LocalSet`'s shared
/// state, or the blocking schedule's hooks. Each roots at the exact `S`
/// type, so a binding is a layout fact about that type, not a name.
pub fn scheduler_role(class: SchedulerClass) -> WalkRole {
    match class {
        SchedulerClass::MultiThread => WalkRole::MtSchedulerHandle,
        SchedulerClass::CurrentThread => WalkRole::CtSchedulerHandle,
        SchedulerClass::LocalSet => WalkRole::LocalSchedulerShared,
        SchedulerClass::Blocking => WalkRole::BlockingScheduleHooks,
    }
}

/// The roles a container binding needs bound at the container type.
pub fn container_roles(kind: ContainerKind) -> &'static [WalkRole] {
    use WalkRole::*;
    match kind {
        ContainerKind::JoinSet => &[JoinSetLength, JoinSetLists],
        ContainerKind::FuturesUnordered => &[SetHeadAll],
        ContainerKind::StreamMap => &[StreamMapEntries],
    }
}

/// The routes chained below them that the set walkers execute.
pub fn container_routes(kind: ContainerKind) -> &'static [WalkRole] {
    use WalkRole::*;
    match kind {
        ContainerKind::JoinSet => &[JoinSetNotifiedHead, JoinSetIdleHead],
        ContainerKind::FuturesUnordered => &[],
        ContainerKind::StreamMap => &[StreamMapEntryStream],
    }
}

fn actions(program: &PollProgram) -> impl Iterator<Item = &PollAction> {
    let (direct, cases): (_, &[PollCase]) = match program {
        PollProgram::Direct(action) => (Some(action), &[]),
        PollProgram::MatchVariant { cases, .. } => (None, cases),
    };
    direct.into_iter().chain(cases.iter().map(|c| &c.action))
}

pub(crate) fn check_semantics(bundle: &Bundle) -> Result<()> {
    let check = Check(bundle);
    let table = &bundle.semantics;
    require(
        u32::try_from(bundle.types.types.len()).is_ok() && u32::try_from(table.types.len()).is_ok(),
        "type table exceeds semantic index capacity",
    )?;
    for (i, origin) in table.origins.iter().enumerate() {
        check.origin(origin)?;
        require(
            !table.origins[..i].contains(origin),
            "duplicate semantic origin",
        )?;
    }
    for (i, rule) in table.rules.iter().enumerate() {
        check.rule_origin(rule)?;
        require(!table.rules[..i].contains(rule), "duplicate semantic rule")?;
    }
    require(
        table.types.windows(2).all(|w| w[0].ty < w[1].ty),
        "unsorted or duplicate type semantics",
    )?;
    for record in &table.types {
        check.ty(record.ty)?;
    }
    let positions: BTreeMap<_, _> = table
        .types
        .iter()
        .enumerate()
        .map(|(i, t)| (t.ty, i))
        .collect();
    let mut seeded = vec![false; table.types.len()];
    let mut children = vec![Vec::new(); table.types.len()];
    for (i, record) in table.types.iter().enumerate() {
        check.ty(record.ty)?;
        for issue in &record.issues {
            check.issue(issue)?;
        }
        match &record.storage {
            StoragePolicy::CoroutineStates => require(
                record.coroutine.is_some(),
                "state storage lacks coroutine layout",
            )?,
            StoragePolicy::Unavailable(issue) => {
                check.issue(issue)?;
                require(
                    record.access.is_none()
                        && record.resource.is_none()
                        && record.container.is_none()
                        && record.select.is_none()
                        && record.http.is_none()
                        && record.request.is_none()
                        && record.table.is_none()
                        && record.pool.is_none()
                        && record.connected.is_none()
                        && record.io_route.is_none()
                        && record.io.is_none()
                        && record.tls_session.is_none()
                        && record.tls_stream.is_none()
                        && record.stream_peer.is_none()
                        && record.far_end.is_none()
                        && record.refcount.is_none()
                        && record.lock.is_none(),
                    "unavailable storage carries a readable capability",
                )?;
            }
            StoragePolicy::DeclaredMembers => {
                require(
                    record.coroutine.is_none(),
                    "coroutine cannot use declared-member storage",
                )?;
                if let TypeDef::Enum { name, .. }
                | TypeDef::Opaque { name, .. }
                | TypeDef::Struct { name, .. } = check.ty(record.ty)?
                {
                    require(
                        !crate::names::is_coroutine_candidate(check.string(*name)?),
                        "unsupported compiler storage cannot use declared members",
                    )?;
                }
            }
        }
        if let Some(layout) = &record.coroutine {
            check.coroutine(record, layout)?;
        }
        if let Some(access) = &record.access {
            use SemanticRuleKind::*;
            check.rule(
                access.rule,
                // The two library routes are owned: each type holds
                // the storage it polls through, and neither is a
                // future in its own right.
                match access.kind {
                    AccessKind::Owned => &[
                        StdBoxAccess,
                        StdPinBoxAccess,
                        TokioStreamWatchStream,
                        TokioUtilReusableBox,
                    ],
                    AccessKind::Borrowed => &[StdMutRefAccess, StdPinMutRefAccess],
                },
            )?;
            check.target(record.ty, &access.target)?;
        }
        if let Some(resource) = &record.resource {
            check.resource(record, resource)?;
        }
        if let Some(http) = &record.http {
            require(
                matches!(record.storage, StoragePolicy::DeclaredMembers),
                "HTTP connection binding needs declared-member storage",
            )?;
            let routed = |ty| {
                positions
                    .get(&ty)
                    .is_some_and(|&i| table.types[i].io_route.is_some())
            };
            check.http(record, http, &routed)?;
        }
        if let Some(request) = &record.request {
            require(
                matches!(record.storage, StoragePolicy::DeclaredMembers),
                "HTTP request binding needs declared-member storage",
            )?;
            check.request(record, request)?;
        }
        if let Some(table) = &record.table {
            require(
                matches!(record.storage, StoragePolicy::DeclaredMembers),
                "hash table binding needs declared-member storage",
            )?;
            check.table(record, table)?;
        }
        if let Some(pool) = &record.pool {
            require(
                matches!(record.storage, StoragePolicy::DeclaredMembers),
                "HTTP pool binding needs declared-member storage",
            )?;
            check.pool(record, pool)?;
        }
        if let Some(connected) = &record.connected {
            require(
                matches!(record.storage, StoragePolicy::DeclaredMembers),
                "connection info binding needs declared-member storage",
            )?;
            check.connected(record, connected)?;
        }
        if let Some(route) = &record.io_route {
            require(
                matches!(record.storage, StoragePolicy::DeclaredMembers),
                "stream route needs declared-member storage",
            )?;
            check.io_route(record, route)?;
        }
        if let Some(io) = &record.io {
            require(
                matches!(record.storage, StoragePolicy::DeclaredMembers),
                "io operation binding needs declared-member storage",
            )?;
            let routed = |ty| {
                positions
                    .get(&ty)
                    .is_some_and(|&i| table.types[i].io_route.is_some())
            };
            check.io_operation(record, io, &routed)?;
        }
        if let Some(session) = &record.tls_session {
            require(
                matches!(record.storage, StoragePolicy::DeclaredMembers),
                "TLS session binding needs declared-member storage",
            )?;
            check.tls_session(record, session)?;
        }
        if let Some(stream) = &record.tls_stream {
            require(
                matches!(record.storage, StoragePolicy::DeclaredMembers),
                "TLS stream binding needs declared-member storage",
            )?;
            let session = |ty| {
                positions
                    .get(&ty)
                    .is_some_and(|&i| table.types[i].tls_session.is_some())
            };
            check.tls_stream(record, stream, &session)?;
        }
        if let Some(peer) = &record.stream_peer {
            require(
                matches!(record.storage, StoragePolicy::DeclaredMembers),
                "stream peer binding needs declared-member storage",
            )?;
            check.stream_peer(record, peer)?;
        }
        if let Some(far_end) = &record.far_end {
            require(
                matches!(record.storage, StoragePolicy::CoroutineStates),
                "far end binding needs coroutine state storage",
            )?;
            let tls_stream = |ty| {
                positions.get(&ty).is_some_and(|&i| {
                    let stream = &table.types[i];
                    stream.io_route.is_some() && stream.tls_stream.is_some()
                })
            };
            check.far_end(record, far_end, &tls_stream)?;
        }
        if let Some(refcount) = &record.refcount {
            check.rule(refcount.rule, &[SemanticRuleKind::StdRefcountHeader])?;
            check.refcount(record, refcount)?;
        }
        if let Some(lock) = &record.lock {
            check.rule(
                lock.rule,
                &[
                    SemanticRuleKind::StdFutexMutex,
                    SemanticRuleKind::ParkingLotRawMutex,
                ],
            )?;
            check.lock(record, &lock.word)?;
        }
        if let Some(acquires) = &record.acquires_for {
            check.rule(acquires.rule, &[SemanticRuleKind::TokioAcquireOwner])?;
            check.string(acquires.primitive)?;
            require(
                record.future.is_some(),
                "an acquire's owner binding needs a future",
            )?;
        }
        if let Some(rule) = record.coroutine_kind {
            check.rule(
                rule,
                &[
                    SemanticRuleKind::RustcAsyncFn,
                    SemanticRuleKind::RustcAsyncBlock,
                    SemanticRuleKind::RustcAsyncClosure,
                ],
            )?;
            // A layout is bound under the kind's own rule: one says what
            // the coroutine is, and the other cannot say otherwise.
            if let Some(layout) = &record.coroutine {
                require(
                    layout.rule == rule,
                    "a coroutine's kind and layout name different rules",
                )?;
            }
        }
        if let Some(container) = &record.container {
            let kind = match container.kind {
                ContainerKind::JoinSet => SemanticRuleKind::TokioJoinSet,
                ContainerKind::FuturesUnordered => SemanticRuleKind::FuturesUnordered,
                ContainerKind::StreamMap => SemanticRuleKind::TokioStreamStreamMap,
            };
            check.rule(container.rule, &[kind])?;
            // Whose waker the children get is the reviewed
            // implementation's, so the recorded flag must be the
            // kind's own: a set claiming forwarded wakers would have
            // the wait set list its children as the task's branches.
            require(
                container.wakers == container.kind.wakers(),
                "container wakers disagree with its kind",
            )?;
            check.roles(record.ty, container_roles(container.kind))?;
            check.routes(container_routes(container.kind))?;
        }
        if let Some(select) = &record.select {
            require(
                matches!(record.storage, StoragePolicy::DeclaredMembers),
                "select binding needs declared-member storage",
            )?;
            check.select(record, select)?;
        }
        let Some(future) = &record.future else {
            continue;
        };
        require(!future.evidence.is_empty(), "empty future evidence")?;
        require(
            future.evidence.windows(2).all(|w| w[0] < w[1]),
            "unsorted or duplicate future evidence",
        )?;
        match &future.continuation {
            Continuation::Unknown(issue) => check.issue(issue)?,
            Continuation::Bound { rule, program } => check.program(record, *rule, program)?,
        }
        for evidence in &future.evidence {
            match evidence {
                FutureEvidence::TaskEntry(id) => {
                    require(
                        bundle
                            .tasks
                            .entries
                            .get(id.0 as usize)
                            .is_some_and(|entry| entry.future == record.ty),
                        "task evidence has the wrong future",
                    )?;
                    seeded[i] = true;
                }
                FutureEvidence::PollSymbol(symbol) => {
                    let symbol = check.string(*symbol)?;
                    require(
                        crate::strip_llvm_suffix(symbol) == symbol
                            && bundle
                                .dyn_futures
                                .by_symbol
                                .get(symbol)
                                .is_some_and(|ids| ids.contains(&record.ty)),
                        "poll evidence is not an exact symbol candidate",
                    )?;
                    let demangled = format!("{:#}", rustc_demangle::demangle(symbol));
                    require(
                        demangled.ends_with(" as core::future::future::Future>::poll"),
                        "poll evidence is not a Future trait implementation",
                    )?;
                    seeded[i] = true;
                }
                FutureEvidence::Coroutine(rule) => {
                    require(
                        record.coroutine.as_ref().is_some_and(|c| c.rule == *rule),
                        "coroutine evidence lacks its layout",
                    )?;
                    seeded[i] = true;
                }
                FutureEvidence::DelegatedBy { parent } => {
                    let parent = positions.get(parent).copied().ok_or_else(|| {
                        Error::Corrupt("semantics: missing delegation parent".into())
                    })?;
                    let continuation = table.types[parent].future.as_ref().map(|f| &f.continuation);
                    let Some(Continuation::Bound { program, .. }) = continuation else {
                        return require(false, "delegation parent has no bound program");
                    };
                    require(actions(program).any(|a| matches!(a, PollAction::Delegate { target: FutureTarget::Value(p), .. } if p.target == record.ty)), "parent does not delegate to this static type")?;
                    children[parent].push(i);
                }
            }
        }
    }
    let mut queue: VecDeque<_> = seeded
        .iter()
        .enumerate()
        .filter_map(|(i, &s)| s.then_some(i))
        .collect();
    while let Some(parent) = queue.pop_front() {
        for &child in &children[parent] {
            if !seeded[child] {
                seeded[child] = true;
                queue.push_back(child);
            }
        }
    }
    require(
        table
            .types
            .iter()
            .zip(seeded)
            .all(|(record, seed)| record.future.is_none() || seed),
        "future evidence cycle has no independent seed",
    )?;
    for entry in &bundle.tasks.entries {
        if let Some(binding) = &entry.scheduler_binding {
            use SemanticRuleKind::*;
            let kind = match binding.class {
                SchedulerClass::MultiThread => TokioMultiThreadScheduler,
                SchedulerClass::CurrentThread => TokioCurrentThreadScheduler,
                SchedulerClass::LocalSet => TokioLocalScheduler,
                SchedulerClass::Blocking => TokioBlockingScheduler,
            };
            check.rule(binding.rule, &[kind])?;
            require(
                bundle.types.size_of(entry.scheduler).is_some(),
                "scheduler binding has opaque storage",
            )?;
            // The class's route must have bound at this entry's own S; the
            // shared-state walks root elsewhere and prove nothing about it.
            check.roles(entry.scheduler, &[scheduler_role(binding.class)])?;
        }
    }
    io_routes_end_at_sockets(table, &positions)
}

/// Every stream route in the table ends at a socket: following forwards
/// — every case of a match — from any routed type reaches a type whose
/// step is a socket, through routed types only, in fewer hops than the
/// table has records — so no route dangles off an unrouted type or runs
/// in a cycle, and a reader following one never needs a bound of its
/// own.
fn io_routes_end_at_sockets(
    table: &SemanticTable,
    positions: &BTreeMap<BundleTypeId, usize>,
) -> Result<()> {
    let step = |ty: BundleTypeId| {
        positions
            .get(&ty)
            .and_then(|&i| table.types[i].io_route.as_ref())
            .map(|route| &route.step)
    };
    // The types already known to end at a socket, so a route many
    // others forward to is followed once.
    let mut ending = BTreeSet::new();
    fn ends<'t>(
        ty: BundleTypeId,
        hops: usize,
        limit: usize,
        step: &impl Fn(BundleTypeId) -> Option<&'t IoRouteStep>,
        ending: &mut BTreeSet<BundleTypeId>,
    ) -> Result<()> {
        if ending.contains(&ty) {
            return Ok(());
        }
        require(hops < limit, "a stream route runs in a cycle")?;
        let current = step(ty).ok_or_else(|| {
            Error::Corrupt("semantics: a stream route forwards to an unrouted type".into())
        })?;
        match current {
            IoRouteStep::Socket(_) => {}
            IoRouteStep::Forward { inner } => ends(inner.target, hops + 1, limit, step, ending)?,
            IoRouteStep::Match { cases } => {
                for case in cases {
                    ends(case.target, hops + 1, limit, step, ending)?;
                }
            }
            IoRouteStep::Dyn { cases, .. } => {
                for case in cases {
                    ends(case.target, hops + 1, limit, step, ending)?;
                }
            }
        }
        ending.insert(ty);
        Ok(())
    }
    for record in &table.types {
        if record.io_route.is_some() {
            ends(record.ty, 0, table.types.len(), &step, &mut ending)?;
        }
    }
    Ok(())
}
