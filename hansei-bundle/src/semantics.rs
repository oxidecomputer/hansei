// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Independent identity, storage, and polling facts. Absence of a capability
//! is unknown; it does not establish that a value contains nothing of interest.

use crate::{BundleTypeId, MemberRef, SourceLoc, Step, StrRef, TaskEntryId};

use serde::{Deserialize, Serialize};

pub(crate) mod check;

pub use check::{
    container_roles, container_routes, required_resource_roles, required_resource_routes,
    scheduler_role, socket_roles,
};

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Debug, Serialize, Deserialize)]
pub struct SemanticRuleId(pub u32);

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Debug, Serialize, Deserialize)]
pub struct SemanticOriginId(pub u32);

#[derive(Clone, PartialEq, Eq, Debug, Default, Serialize, Deserialize)]
pub struct SemanticTable {
    pub origins: Vec<SemanticOrigin>,
    pub rules: Vec<SemanticRule>,
    /// Sparse records, strictly ordered by type id.
    pub types: Vec<TypeSemantics>,
}

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct TypeSemantics {
    pub ty: BundleTypeId,
    pub storage: StoragePolicy,
    pub future: Option<FutureFacts>,
    pub coroutine: Option<CoroutineLayout>,
    pub access: Option<AccessBinding>,
    pub resource: Option<ResourceBinding>,
    pub container: Option<ContainerBinding>,
    /// The branches this future polls in turn, where it is the
    /// `PollFn` a reviewed `select!` expansion parks in.
    pub select: Option<SelectBinding>,
    /// The state words of the HTTP/1 connection this future drives,
    /// where it is hyper's `Dispatcher` under a reviewed range: the
    /// paths the [`ResourceKind::HttpConn`] resource is read through.
    pub http: Option<HttpConnBinding>,
    /// The request line this value carries, where its type is one a
    /// reviewed range says keeps a request's method and target: a
    /// client's in-flight request, a server's request context. A fact
    /// beside the record, read wherever a chain or a frame holds the
    /// value; the type polls nothing through it.
    pub request: Option<HttpRequestBinding>,
    /// The hash table this value keeps its entries in, where its type
    /// is hashbrown's map or set, or std's wrapper of either, under a
    /// reviewed range: the words that say which buckets are full, and
    /// what a bucket holds. What reads the entries — as owned storage
    /// of the value — reads them through this.
    pub table: Option<HashTableBinding>,
    /// The pooled HTTP connections this value names, where its type is
    /// a hyper-util client pool's reaper or checkout under a reviewed
    /// range: what names a client connection's far end.
    pub pool: Option<HttpPoolBinding>,
    /// Where the type is hyper-util's `Connected` under a reviewed
    /// range: what a pooled connection's info says of it.
    pub connected: Option<ConnectedBinding>,
    /// Where the type is a stream a reviewed range says forwards its
    /// reads and writes, or a socket registered with tokio's io driver:
    /// how reading or writing a value of it reaches the registration.
    pub io_route: Option<IoRouteBinding>,
    /// Where the type is one of tokio's io operation futures over a
    /// routed stream: the stream it polls. Present exactly when the
    /// record's resource is such an operation.
    pub io: Option<IoOperationBinding>,
    /// Where the type is rustls's connection state under a reviewed
    /// range: the words that say how far its handshake got and whether
    /// either side has closed.
    pub tls_session: Option<TlsSessionBinding>,
    /// Where the type is a routed TLS stream that holds a rustls
    /// connection: the connection, and the stream's own shutdown state.
    pub tls_stream: Option<TlsStreamBinding>,
    /// Where the type is a routed stream that names its peer: the
    /// peer's name, as NUL-padded text.
    pub stream_peer: Option<StreamPeerBinding>,
    /// Where the type is the coroutine of an async fn a reviewed range
    /// says sets up a TLS stream as a local beside what it knows of the
    /// far end: per state that holds the stream, the stream and each
    /// fact. A fact beside the record, read wherever a chain reaches
    /// the frame; the coroutine polls nothing through it.
    pub far_end: Option<FarEndBinding>,
    /// Where the type is a refcounted allocation's header — an `Arc`'s
    /// `ArcInner<T>`, an `Rc`'s `RcInner<T>` — the member holding the
    /// value its counts guard: what a path through the pointer names.
    pub refcount: Option<RefcountBinding>,
    /// Where the type is a raw lock guarding a wait list: the word
    /// that says whether it is held.
    pub lock: Option<LockBinding>,
    /// Where the future acquires a batch semaphore on behalf of a
    /// primitive — `Mutex::lock`, `Semaphore::acquire`, a bounded
    /// sender's `reserve` — the primitive it acquires for.
    pub acquires_for: Option<AcquiresForBinding>,
    /// Where the type is a coroutine rustc generated, the rule whose
    /// kind says which: an async fn's, an async block's or an async
    /// closure's.
    pub coroutine_kind: Option<SemanticRuleId>,
    pub issues: Vec<SemanticIssue>,
}

/// The value a refcounted allocation's header holds.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct RefcountBinding {
    pub rule: SemanticRuleId,
    /// The header's member holding the value, by name.
    pub value: MemberRef,
}

/// A raw lock's state, as a reviewed implementation keeps it.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct LockBinding {
    pub rule: SemanticRuleId,
    pub word: LockWord,
}

/// Where a lock keeps its state and what says it is held: the
/// little-endian word of `size` bytes at `offset` into the lock, held
/// whenever any bit of `locked_mask` is set in it.
#[derive(Copy, Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct LockWord {
    pub offset: u64,
    pub size: u8,
    pub locked_mask: u64,
}

impl LockWord {
    /// Whether `bytes`, the lock's own, say it is held: `None` where
    /// they are too short to hold the word.
    pub fn held(&self, bytes: &[u8]) -> Option<bool> {
        let start = usize::try_from(self.offset).ok()?;
        let word = bytes.get(start..start.checked_add(usize::from(self.size))?)?;
        let mut buf = [0u8; 8];
        buf.get_mut(..word.len())?.copy_from_slice(word);
        Some(u64::from_le_bytes(buf) & self.locked_mask != 0)
    }
}

/// The primitive a future acquires a batch semaphore for.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct AcquiresForBinding {
    pub rule: SemanticRuleId,
    /// The primitive, as a listing names it: `tokio::sync::Mutex`.
    pub primitive: StrRef,
}

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub enum StoragePolicy {
    DeclaredMembers,
    CoroutineStates,
    Unavailable(SemanticIssue),
}

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct FutureFacts {
    pub evidence: Vec<FutureEvidence>,
    pub continuation: Continuation,
}

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Debug, Serialize, Deserialize)]
pub enum FutureEvidence {
    TaskEntry(TaskEntryId),
    /// Canonical linkage key, never a display-demangled name or drop glue.
    PollSymbol(StrRef),
    Coroutine(SemanticRuleId),
    DelegatedBy {
        parent: BundleTypeId,
    },
}

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub enum Continuation {
    Unknown(SemanticIssue),
    Bound {
        rule: SemanticRuleId,
        program: PollProgram,
    },
}

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub enum PollProgram {
    Direct(PollAction),
    MatchVariant {
        state: TypedPath,
        cases: Vec<PollCase>,
    },
}

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct PollCase {
    pub variant: StrRef,
    pub action: PollAction,
}

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub enum PollAction {
    /// Exclusivity needs a reviewed control-flow guarantee in addition to
    /// the ordinary forwarding rule. A single path does not establish it.
    Delegate {
        target: FutureTarget,
        exclusive: bool,
    },
    Primitive,
    Unresumed,
    Returned,
    Panicked,
    /// The reviewed implementation returns `Poll::Pending` without
    /// touching its `Context`: it registers no waker, polls nothing,
    /// and no poll of it ever returns `Ready`. A terminal about
    /// readiness, not waking — a spurious or stale wake still
    /// schedules the task, which polls this and parks again. Legal
    /// only as a whole program, never as a state's case: no reviewed
    /// matcher has a state that means this.
    NeverReady,
    Unknown(SemanticIssue),
}

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct TypedPath {
    /// Literal, name-addressed steps from the nominal future root. Case
    /// actions also start at that root, not at the selected payload.
    pub steps: Vec<Step>,
    pub target: BundleTypeId,
}

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub enum FutureTarget {
    Value(TypedPath),
    Dynamic {
        pointer: TypedPath,
        layout: DynFutureLayout,
    },
}

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct DynFutureLayout {
    pub abi: SemanticRuleId,
    /// Paths relative to the wide-pointer value, not the future root.
    pub data: TypedPath,
    pub vtable: TypedPath,
    pub trait_ty: BundleTypeId,
    pub drop_slot: u32,
    pub size_slot: u32,
    pub align_slot: u32,
    /// Where `Future::poll` sits, when the reviewed ABI places it: the
    /// trait object is a bare `dyn Future`, whose one method is the
    /// poll. A trait object of another trait that has `Future` as a
    /// supertrait carries a poll too, but which slot holds it depends
    /// on that trait's own declaration order, which no reviewed
    /// convention covers — the slot is then `None` and identity comes
    /// from the drop glue alone.
    pub poll_slot: Option<u32>,
}

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct CoroutineLayout {
    pub rule: SemanticRuleId,
    pub states: Vec<CoroutineState>,
}

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct CoroutineState {
    pub variant: StrRef,
    pub stage: CoroutinePhase,
    pub locals: Vec<StrRef>,
    pub uncertain_locals: Vec<StrRef>,
}

#[derive(Copy, Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub enum CoroutinePhase {
    Unresumed,
    Suspended,
    Returned,
    Panicked,
    Unknown,
}

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct AccessBinding {
    pub rule: SemanticRuleId,
    pub kind: AccessKind,
    pub target: FutureTarget,
}

#[derive(Copy, Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub enum AccessKind {
    Owned,
    Borrowed,
}

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct ResourceBinding {
    pub rule: SemanticRuleId,
    pub kind: ResourceKind,
    pub state_rule: Option<SemanticRuleId>,
    pub exclusive_pending: bool,
}

#[derive(Copy, Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub enum ResourceKind {
    Sleep,
    JoinHandle,
    SemaphoreAcquire,
    IoOperation(IoOperationKind),
    /// The bounded mpsc `Receiver::recv` future: the `PollFn` its
    /// `async fn` awaits, whose closure holds the receiver's `Rx`.
    MpscRecv,
    /// `tokio::sync::notify::Notified`, the borrowed form.
    Notified,
    /// `tokio::sync::oneshot::Receiver<T>`, which is its own future:
    /// its `poll` reads the shared `Inner`'s state word.
    OneshotRecv,
    /// hyper's `proto::h1::dispatch::Dispatcher`, the future an HTTP/1
    /// connection task polls: its poll drives the connection's state
    /// machine, and the words that machine keeps — keep-alive, what is
    /// being read and written, the method in flight — say where the
    /// connection stands. The record's [`HttpConnBinding`] holds the
    /// paths to them.
    HttpConn,
}

/// Which end of an HTTP exchange a connection drives.
#[derive(Copy, Clone, PartialEq, Eq, Hash, Debug, Serialize, Deserialize)]
pub enum HttpRole {
    Client,
    Server,
}

/// hyper's HTTP/1 `Dispatcher<D, Bs, I, T>` as a reviewed range lays it
/// out: the routes from the dispatcher to every word the connection
/// verdict reads. The connection's own words sit in `conn.state`; the
/// role's dispatch holds what it is parked on — the client's response
/// callback and request receiver, the server's in-flight handler and
/// header-read timer flag. Every path starts at the dispatcher and
/// names its members; a variant step selects the payload it reads
/// through, and the read reports the variant inactive where it is not.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct HttpConnBinding {
    pub rule: SemanticRuleId,
    pub role: HttpRole,
    /// `conn.state.keep_alive`: the `KA` enum — `Idle`, `Busy`,
    /// `Disabled`.
    pub keep_alive: TypedPath,
    /// `conn.state.reading`: the `Reading` enum, whose `Continue` and
    /// `Body` carry the body's `Decoder`.
    pub reading: TypedPath,
    /// `conn.state.writing`: the `Writing` enum, whose `Body` carries
    /// the `Encoder`.
    pub writing: TypedPath,
    /// `conn.state.method`: the `Option<Method>` of the message in
    /// flight, `None` between exchanges.
    pub method: TypedPath,
    /// The method's own enum, through the option and the newtype:
    /// `conn.state.method.Some.__0.__0`, whose variant is the method's
    /// name. Read only where `method` is `Some`.
    pub method_inner: TypedPath,
    /// The body decoder's framing while reading a body, through
    /// `Reading::Continue`: `conn.state.reading.Continue.__0.kind`, a
    /// `Length(remaining)`, `Chunked { .. }` or `Eof(..)`.
    pub read_continue_kind: TypedPath,
    /// The same through `Reading::Body`.
    pub read_body_kind: TypedPath,
    /// The body encoder's framing while writing one, through
    /// `Writing::Body`: `conn.state.writing.Body.__0.kind`, a
    /// `Length(remaining)`, `Chunked(..)` or `CloseDelimited`.
    pub write_body_kind: TypedPath,
    /// `is_closing`: set once the dispatcher has closed both directions.
    pub is_closing: TypedPath,
    /// `conn.io.io`: the stream the connection reads and writes, where
    /// its type is routed to a socket — the route a reader follows to
    /// the connection's registration and descriptor, and to the TLS
    /// connection on the way where there is one.
    pub stream: Option<TypedPath>,
    /// The client's dispatch, where `T` is `role::Client`.
    pub client: Option<HttpClientBinding>,
    /// The server's dispatch, where `T` is `role::Server`.
    pub server: Option<HttpServerBinding>,
}

/// The client dispatch's words: what a client connection is parked on.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct HttpClientBinding {
    /// `dispatch.callback`: the `Option<Callback<..>>` holding the
    /// response oneshot while a request is in flight, `None` when idle.
    pub callback: TypedPath,
    /// The oneshot `Sender` inside the callback's `Retry` variant, from
    /// the dispatcher: `dispatch.callback.Some.__0.Retry.__0.Some.__0`.
    pub retry: TypedPath,
    /// The same through the `NoRetry` variant.
    pub no_retry: TypedPath,
    /// `dispatch.rx.inner`: the unbounded mpsc receiver the connection
    /// takes requests from, parked on while idle.
    pub rx: TypedPath,
    /// `dispatch.rx.taker.inner.ptr.pointer`: the `*const` to the
    /// `ArcInner<want::Inner>` the receiver's `Taker` shares with the
    /// one `Giver` of the sender that feeds it — what tells which pooled
    /// sender is this connection's.
    pub want: TypedPath,
}

/// The server dispatch's words: what a server connection is parked on.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct HttpServerBinding {
    /// The `Option` behind `dispatch.in_flight`'s pinned box —
    /// `dispatch.in_flight.pointer.*` — holding the handler's future
    /// while a request is being handled, `None` between requests.
    pub in_flight: TypedPath,
    /// `conn.state.h1_header_read_timeout_running`: whether the
    /// header-read timer the server arms while idle is running.
    pub header_read_timeout_running: TypedPath,
    /// The header-read timeout the timer is armed for, as its
    /// `Duration`'s two words through the `Option`:
    /// `conn.state.h1_header_read_timeout.Some.__0.secs`, a `u64`, and
    /// `.nanos.__0`, a `u32`. A read of either reports the variant
    /// inactive where the server was built with no timeout.
    pub header_read_timeout_secs: TypedPath,
    pub header_read_timeout_nanos: TypedPath,
    /// The header-read timer's address: the data pointer of the boxed
    /// `dyn Sleep` in `conn.state.h1_header_read_timeout_fut`, through
    /// the `Option` and the `Pin` — `...Some.__0.pointer.pointer`. A
    /// read reports the variant inactive where no timer was made.
    pub header_read_timer: TypedPath,
    /// What the service the dispatch drives keeps, where it is one a
    /// reviewed convention covers: dropshot's request handler. `None`
    /// for a service the review does not cover.
    pub service: Option<HttpServiceBinding>,
}

/// What a server connection's service keeps, under the rule of the
/// crate whose service type keeps it.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct HttpServiceBinding {
    pub rule: SemanticRuleId,
    /// `dispatch.service.remote_addr`, landing on the `SocketAddr` enum:
    /// the accepted socket's peer.
    pub peer: TypedPath,
    /// The application's context type the server was built with — the
    /// `C` of `DropshotState<C>`, whose `private` holds it — which is
    /// what tells one server of a program from another.
    pub context: BundleTypeId,
    /// The address the server listens on, in the state the handler
    /// shares with every connection the server accepted:
    /// `dispatch.service.server.ptr.pointer.*.data.local_addr`, landing
    /// on the `SocketAddr` enum. `None` where the state's layout did
    /// not bind; the peer and the context stand without it.
    pub local_addr: Option<TypedPath>,
    /// The same state's `tls_acceptor`, an `Option` whose variant says
    /// whether the server serves TLS. `None` as `local_addr` is.
    pub tls_acceptor: Option<TypedPath>,
}

/// Where a request's method and target are stored in a value, under
/// the rule of the crate whose type keeps them: the routes from the
/// record's type to the method's enum and to the text of the target.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct HttpRequestBinding {
    pub rule: SemanticRuleId,
    /// The method's own enum, through the `Method` newtype —
    /// `http::method::Inner`, whose variant names the method.
    pub method: TypedPath,
    /// What the target's text is: the whole URL a client wrote, or the
    /// path and query a server parsed.
    pub target: HttpRequestTarget,
    /// The pointer to the target's bytes: a `*const u8`, the data
    /// pointer of the `String` or `Bytes` holding the text.
    pub target_ptr: TypedPath,
    /// The target's length in bytes: the `usize` beside that pointer.
    pub target_len: TypedPath,
}

/// What a request binding's target text spells.
#[derive(Copy, Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub enum HttpRequestTarget {
    /// The whole URL, scheme and authority included, as the client
    /// wrote it.
    Url,
    /// The request target as the server parsed it: the path, and the
    /// query after its `?` where there is one.
    PathAndQuery,
}

/// A hashbrown `RawTable` as a reviewed range lays it out, reached from
/// the record's type: hashbrown's `HashMap` or `HashSet`, or std's,
/// which wrap them. The table has `bucket_mask + 1` buckets, a power of
/// two, and one control byte per bucket at `ctrl`; a byte with its top
/// bit clear marks a full bucket, and `items` counts them. The buckets
/// sit below the control bytes in reverse, so bucket `i` is the
/// `bucket` value ending `i` buckets below `ctrl`, at `ctrl - (i + 1) *
/// size`. Every path starts at the record's type and names its members.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct HashTableBinding {
    pub rule: SemanticRuleId,
    /// `…table.table.bucket_mask`, a `usize`.
    pub bucket_mask: TypedPath,
    /// `…table.table.ctrl.pointer`: the `*const u8` to the control
    /// bytes, under the `NonNull` holding it.
    pub ctrl: TypedPath,
    /// `…table.table.items`, a `usize`.
    pub items: TypedPath,
    /// What a bucket holds: the `(K, V)` a map stores, the `(T, ())` a
    /// set does.
    pub bucket: BundleTypeId,
}

/// hyper-util's legacy client pool as a reviewed range lays it out: the
/// routes from one of its types to the connections it holds, each named
/// by its pool key's authority and by the `want::Inner` its sender
/// shares with the connection's receiver
/// ([`HttpClientBinding::want`]). Every path names its members.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub enum HttpPoolBinding {
    /// `IdleTask<T, K>`, the reaper a pool with an idle timeout spawns:
    /// it holds the pool weakly, and the pool's idle map holds, per
    /// key, the connections waiting to be checked out.
    Reaper {
        rule: SemanticRuleId,
        /// From the reaper to the pool's `ArcInner` strong count,
        /// `pool.__0.Some.__0.ptr.pointer.*.strong`: zero once the pool
        /// is dropped, when the map behind it is no longer the pool's.
        strong: TypedPath,
        /// From the reaper to the idle map,
        /// `…*.data.data.value.idle`: a `HashMap` whose record carries
        /// the table binding its buckets are read through.
        idle: TypedPath,
        /// From a bucket of that map, `((Scheme, Authority),
        /// Vec<Idle<T>>)`, to the key's authority text: its `Bytes`
        /// pointer and length, `__0.__1.data.bytes.ptr` and `.len`.
        key_ptr: TypedPath,
        key_len: TypedPath,
        /// From the bucket to the list's buffer pointer,
        /// `__1.buf.inner.ptr.pointer.pointer`, and its length,
        /// `__1.len`.
        entries_ptr: TypedPath,
        entries_len: TypedPath,
        /// The list's element, `Idle<T>`, whose size is the stride.
        entry: BundleTypeId,
        /// From an entry to its sender's `want` pointer,
        /// `value.tx.Http1.__0.dispatch.giver.inner.ptr.pointer`.
        want: TypedPath,
        /// From an entry to the connection's info, `value.conn_info`,
        /// landing on a type whose record carries the `Connected`
        /// binding. `None` where the info's layout did not bind; the
        /// key and the sender stand without it.
        conn_info: Option<TypedPath>,
    },
    /// `Pooled<T, K>`, a connection checked out of the pool: its key
    /// and its sender, held by whoever checked it out.
    Checkout {
        rule: SemanticRuleId,
        /// `key.__1.data.bytes.ptr` and `.len`: the authority's text.
        key_ptr: TypedPath,
        key_len: TypedPath,
        /// `value.Some.__0.tx.Http1.__0.dispatch.giver.inner.ptr.pointer`.
        want: TypedPath,
        /// `value.Some.__0.conn_info`, as the reaper's.
        conn_info: Option<TypedPath>,
    },
}

/// hyper-util's `Connected` as a reviewed range lays it out: what the
/// pool keeps of how its connection was made. Every path starts at
/// the `Connected` and names its members.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct ConnectedBinding {
    pub rule: SemanticRuleId,
    /// `alpn`, the `Alpn` enum: `H2` where ALPN chose HTTP/2, `None`
    /// otherwise.
    pub alpn: TypedPath,
    /// `is_proxied`: whether the connection goes through a proxy.
    pub is_proxied: TypedPath,
    /// `extra.Some.__0.__0`, the `Box<dyn ExtraInner>` the connector's
    /// extras sit behind; the read reports the variant inactive where
    /// it recorded none.
    pub extra: TypedPath,
    /// The box's vtable under the compiler's rule for its header, with
    /// `read_slot` the slot of `ExtraInner::set`, whose symbol names
    /// the concrete extra.
    pub layout: DynStreamLayout,
    /// Every concrete extra the vtable may name.
    pub cases: Vec<ExtraCase>,
}

/// One concrete extra a `Connected` may hold: hyper-util's envelope of
/// one value, or its chain of a value over the extras before it.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct ExtraCase {
    /// The linkage symbol of its `ExtraInner::set`.
    pub symbol: StrRef,
    pub target: BundleTypeId,
    /// Where the value it carries is hyper-util's `HttpInfo`: its
    /// `remote_addr` and `local_addr`, each landing on std's
    /// `SocketAddr` enum.
    pub remote_addr: Option<TypedPath>,
    pub local_addr: Option<TypedPath>,
    /// For a chain, `__0`: the box of the extras it wraps, the same
    /// type as the binding's `extra`.
    pub next: Option<TypedPath>,
}

/// tokio's io operation futures, by the `io::util` module each lives
/// in, and the readiness await the driver's own resources park in.
#[derive(Copy, Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub enum IoOperationKind {
    Read,
    ReadExact,
    ReadBuf,
    Write,
    WriteAll,
    WriteBuf,
    Flush,
    Shutdown,
    Readiness,
    /// A TLS handshake in progress, tokio-rustls's `MidHandshake`: it
    /// reads and writes its stream as the protocol needs, so which
    /// readiness it waits for is the direction slot its waker sits in.
    Handshake,
}

impl IoOperationKind {
    /// Whether a pending operation waits for the stream to take bytes
    /// rather than to yield them: a write, a flush or a shutdown parks
    /// in the socket's writer slot, a read in its reader slot. `None`
    /// for a readiness await, which names its interest itself, and for
    /// a handshake, whose direction is the slot holding its waker.
    pub fn writes(self) -> Option<bool> {
        match self {
            Self::Read | Self::ReadExact | Self::ReadBuf => Some(false),
            Self::Write | Self::WriteAll | Self::WriteBuf | Self::Flush | Self::Shutdown => {
                Some(true)
            }
            Self::Readiness | Self::Handshake => None,
        }
    }
}

/// How reading or writing a value reaches the socket underneath.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct IoRouteBinding {
    pub rule: SemanticRuleId,
    pub step: IoRouteStep,
}

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub enum IoRouteStep {
    /// Reading or writing the value reads or writes the stream `inner`
    /// lands on, and nothing else: a path from the value through the
    /// members that hold it, and through a pointer where the value
    /// holds it behind one (an `Arc`, a `Box`, a reference). The
    /// target is itself a routed type.
    Forward { inner: TypedPath },
    /// The value is an enum whose reads and writes are its live
    /// variant's: one forward per variant with a routed payload, each
    /// path's first step the variant it selects. A value whose live
    /// variant has no case has no route.
    Match { cases: Vec<TypedPath> },
    /// The value holds its stream behind a trait object: `pointer`
    /// reaches the wide pointer, the reviewed vtable layout reads it,
    /// and the concrete stream is the case whose read method's symbol
    /// the vtable's read slot holds. A stream in no case has no route.
    Dyn {
        pointer: TypedPath,
        layout: DynStreamLayout,
        cases: Vec<DynStreamCase>,
    },
    /// The value is a socket registered with tokio's io driver: the
    /// walk contract's roles rooted at its type reach the registration
    /// and the descriptor.
    Socket(IoSocket),
}

/// A stream trait object's vtable, as a dynamic route reads it: the
/// header's size and alignment under the compiler's rule, and the slot
/// the trait's first read method sits in under the rule of the crate
/// that declares the trait.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct DynStreamLayout {
    /// The compiler rule the vtable header is read under.
    pub abi: SemanticRuleId,
    /// Paths relative to the wide pointer.
    pub data: TypedPath,
    pub vtable: TypedPath,
    pub size_slot: u32,
    pub align_slot: u32,
    pub read_slot: u32,
}

/// One concrete stream a dynamic route may reach: the linkage symbol of
/// its read method, which names it in the vtable, and its type.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct DynStreamCase {
    pub symbol: StrRef,
    pub target: BundleTypeId,
}

/// rustls's `ConnectionCommon<Data>`: every path starts at it and
/// names its members.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct TlsSessionBinding {
    pub rule: SemanticRuleId,
    /// `core.state`: a `Result` whose `Err` holds the error that ended
    /// the connection.
    pub state: TypedPath,
    /// `core.common_state.side`: the C-like `Side`, `Client` or
    /// `Server`.
    pub side: TypedPath,
    /// `core.common_state.negotiated_version`: an
    /// `Option<ProtocolVersion>`, `None` until the handshake picks one.
    pub negotiated_version: TypedPath,
    /// The version's own enum, selected out of the option
    /// (`….negotiated_version.Some.__0`), whose variant names it.
    pub version: TypedPath,
    /// The common state's one-byte flags.
    pub may_send_application_data: TypedPath,
    pub may_receive_application_data: TypedPath,
    pub has_sent_close_notify: TypedPath,
    pub has_received_close_notify: TypedPath,
    pub has_seen_eof: TypedPath,
    pub sent_fatal_alert: TypedPath,
    /// `core.common_state.record_layer.{read,write}_seq`: the records
    /// each direction has carried, as unsigned words.
    pub read_seq: TypedPath,
    pub write_seq: TypedPath,
    /// `core.common_state.sendable_tls`: the records written into the
    /// connection and not yet written to its socket — a `VecDeque` ring
    /// of encoded records, one `Vec<u8>` each, whose first one has
    /// `prefix_used` bytes already sent. What the next flush or write
    /// would send, and nothing else will.
    pub sendable: SendableBinding,
    /// `core.common_state.received_plaintext`, a buffer of the same
    /// shape: the records decrypted and not yet read by the
    /// application. `None` where its layout did not bind, as for every
    /// word below; the connection's verdict stands without them.
    pub received: Option<SendableBinding>,
    /// `core.common_state.handshake_kind.Some.__0`: the C-like
    /// `HandshakeKind`, whose enumerator says how the handshake went
    /// (`Full`, `FullWithHelloRetryRequest`, `Resumed`); inactive until
    /// it settles.
    pub handshake_kind: Option<TypedPath>,
    /// The cipher suite the handshake chose, one path per variant of
    /// `SupportedCipherSuite` the build has
    /// (`core.common_state.suite.Some.__0.Tls13.__0.*.common.suite`):
    /// through the variant's `&'static` suite to the IANA `CipherSuite`
    /// enum, whose variant names it. The one whose variant is live reads.
    pub suites: Vec<TypedPath>,
    /// `core.common_state.alpn_protocol.Some.__0.__0`'s byte pointer and
    /// length: the protocol ALPN chose, as text.
    pub alpn_ptr: Option<TypedPath>,
    pub alpn_len: Option<TypedPath>,
    /// `core.common_state.peer_certificates.Some.__0.__0.len`: how many
    /// certificates the peer presented; inactive where it presented none.
    pub peer_certificates: Option<TypedPath>,
}

/// rustls's `ChunkVecBuffer` of outgoing records, reached from the
/// connection: the ring's words, by std's member names, and the record
/// type it strides by. Every path but `record_len` starts at the
/// connection.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct SendableBinding {
    /// `….sendable_tls.prefix_used`: the bytes of the first record
    /// already written.
    pub prefix_used: TypedPath,
    /// `….sendable_tls.chunks.head` and `.len`: the ring's first slot
    /// and how many records it holds, unsigned words (through the index
    /// newtype where the standard library wraps one).
    pub head: TypedPath,
    pub len: TypedPath,
    /// `….sendable_tls.chunks.buf.inner.ptr.pointer.pointer`: the ring's
    /// storage; `….buf.inner.cap` its capacity in records (through the
    /// niche newtype where the standard library wraps one).
    pub buf: TypedPath,
    pub cap: TypedPath,
    /// The record type the ring holds, `Vec<u8>`, whose size strides the
    /// storage, and the path from it to its length.
    pub record: BundleTypeId,
    pub record_len: TypedPath,
}

/// A TLS stream's words: the rustls connection it holds, and its own
/// shutdown state.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct TlsStreamBinding {
    /// The stream's route rule: the same review names both.
    pub rule: SemanticRuleId,
    /// The path to the connection, landing on a type with a session
    /// binding.
    pub session: TypedPath,
    /// The stream's state enum, whose variant says which directions it
    /// has shut down.
    pub state: TypedPath,
}

/// The peer a stream names: a path to a byte array holding its name as
/// text, NUL-padded to the array's width.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct StreamPeerBinding {
    /// The stream's route rule: the same review names both.
    pub rule: SemanticRuleId,
    pub name: TypedPath,
}

/// What an async fn setting up a TLS stream keeps of the far end, under
/// the rule of the crate that declares it.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct FarEndBinding {
    pub rule: SemanticRuleId,
    pub states: Vec<FarEndState>,
}

/// One coroutine state that holds the stream, every path from the
/// coroutine through the state's variant first: the stream, landing on
/// a routed TLS stream — a local of the state, or, while the state
/// awaits the TLS handshake, the stream that handshake holds, through
/// the state's `__awaitee` — then each fact the state keeps beside it.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct FarEndState {
    pub stream: TypedPath,
    /// The far end's socket address, landing on the `SocketAddr` enum:
    /// the accepted socket's, for a server. `None` where the state
    /// keeps none.
    pub addr: Option<TypedPath>,
    /// The far end's name, as NUL-padded text in an array of bytes:
    /// the platform id its certificates attest. `None` where the state
    /// keeps none.
    pub name: Option<TypedPath>,
}

/// The sockets a route ends at, by the walk roles rooted at each.
#[derive(Copy, Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub enum IoSocket {
    TcpStream,
    UnixStream,
}

/// One of tokio's io operation futures, over a routed stream: the path
/// from the future through its `&mut` to the stream it polls, and, for
/// an operation whose buffer says when it completes without parking,
/// the path to that buffer's length.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct IoOperationBinding {
    pub rule: SemanticRuleId,
    pub stream: TypedPath,
    pub remaining: Option<TypedPath>,
}

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct ContainerBinding {
    pub rule: SemanticRuleId,
    pub kind: ContainerKind,
    /// Whose waker the container hands its children; fixed by the
    /// kind ([`ContainerKind::wakers`]) and recorded beside it so a
    /// consumer reads the fact it dispatches on rather than
    /// re-deriving it.
    pub wakers: ContainerWakers,
}

#[derive(Copy, Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub enum ContainerKind {
    JoinSet,
    FuturesUnordered,
    /// tokio-stream's `StreamMap<K, V>`: a `Vec<(K, V)>` of streams
    /// polled in turn with the polling task's own context, every
    /// pending one keeping its registration.
    StreamMap,
}

/// Whose waker a container's children are polled with.
#[derive(Copy, Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub enum ContainerWakers {
    /// The container's own per-child waker (`FuturesUnordered`,
    /// `JoinSet`): a child's registration names the container, and
    /// the task polling the container is woken through it.
    Own,
    /// The polling task's context, forwarded unchanged (`StreamMap`):
    /// every child's registration names the task itself.
    Forwarded,
}

impl ContainerKind {
    /// How the kind polls its children; the reviewed implementation's
    /// business, not the target's.
    pub fn wakers(self) -> ContainerWakers {
        match self {
            ContainerKind::JoinSet | ContainerKind::FuturesUnordered => ContainerWakers::Own,
            ContainerKind::StreamMap => ContainerWakers::Forwarded,
        }
    }
}

/// A `select!` as tokio's macro lays it out around the `PollFn` it
/// awaits: the closure borrows the branch mask and the tuple of branch
/// futures from the enclosing frame, and polls each tuple member whose
/// bit in the mask is clear. Member `i` of the tuple is branch `i` in
/// source order; bit `i` set means that branch is disabled — by a
/// false precondition before the first poll, or by a completed output
/// that missed its pattern — and is polled no more. Which of the two
/// set it is not recorded anywhere in memory.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct SelectBinding {
    pub rule: SemanticRuleId,
    /// From the future root to the mask word itself, through the
    /// closure's reference: an unsigned integer of 1, 2, 4 or 8 bytes,
    /// the width tokio-macros picks by branch count.
    pub mask: TypedPath,
    /// From the future root to the tuple of branch futures, through the
    /// closure's reference.
    pub futures: TypedPath,
    /// Branch `i`, as a path from the tuple: its member `__i` and the
    /// future type that member holds.
    pub branches: Vec<TypedPath>,
    /// Where branch `i`'s arm is written in the caller's source — the
    /// line its pattern is on — parallel to `branches`. `None` where
    /// the arm's pattern binds nothing (`_ = …`), or where extraction
    /// could not tell which arm is the branch's; the record's issues
    /// say which.
    pub arms: Vec<Option<SourceLoc>>,
}

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct SemanticRule {
    pub kind: SemanticRuleKind,
    pub revision: u32,
    pub origin: SemanticOriginId,
}

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Debug, Serialize, Deserialize)]
pub enum SemanticRuleKind {
    RustcAsyncFn,
    RustcAsyncBlock,
    DynFutureAbi,
    StdBoxAccess,
    StdMutRefAccess,
    StdPinBoxAccess,
    StdPinMutRefAccess,
    StdBoxPoll,
    StdMutRefPoll,
    StdPinBoxPoll,
    StdPinMutRefPoll,
    TokioSleep,
    TokioJoinHandle,
    TokioAcquire,
    TokioJoinSet,
    TokioSleepState,
    TokioJoinHandleState,
    TokioAcquireState,
    TokioIoOperation,
    TokioIoState,
    TokioMultiThreadScheduler,
    TokioCurrentThreadScheduler,
    TokioLocalScheduler,
    TokioBlockingScheduler,
    FuturesUnordered,
    TracingInstrumented,
    TokioMpscRecv,
    TokioMpscRecvState,
    TokioNotified,
    TokioNotifiedState,
    /// futures-util's `map` combinator: the public `delegate_all!`
    /// newtype and the `map::Map` enum it forwards into.
    FuturesUtilMap,
    /// futures-util's `map_err`: a `delegate_all!` newtype over a `Map`.
    FuturesUtilMapErr,
    /// futures-util's `into_future`.
    FuturesUtilIntoFuture,
    /// hyper-util's `TokioSleep`, the newtype that gives
    /// `tokio::time::Sleep` an `Unpin` trait object.
    HyperUtilTokioSleep,
    TokioOneshotRecv,
    TokioOneshotRecvState,
    /// tokio's `select!` expansion: the `PollFn` closure that borrows
    /// the branch mask and the tuple of branch futures.
    TokioSelect,
    /// tokio's `task::coop::Coop<F>`, the cooperative-budget wrapper
    /// `cooperative()` puts around a leaf future: its poll spends a
    /// budget unit, then polls `fut` and nothing else.
    TokioCoop,
    /// futures-util's `stream::Next<'_, St>`, the `StreamExt::next`
    /// future: `{ stream: &mut St }`, whose poll is the stream's
    /// `poll_next` and nothing else. Its delegate is a stream, so the
    /// route proves nothing about it being a future.
    FuturesUtilNext,
    /// tokio-stream's `WatchStream<T>`: an access binding, not a
    /// future — polling the stream polls the one `ReusableBoxFuture`
    /// it owns.
    TokioStreamWatchStream,
    /// tokio-util's `ReusableBoxFuture<'_, T>`: an access binding
    /// through `boxed`, the `Pin<Box<dyn Future>>` its every poll
    /// forwards to.
    TokioUtilReusableBox,
    /// tokio-stream's `StreamMap<K, V>`: a container binding over its
    /// `entries`, each polled with the polling task's own context.
    TokioStreamStreamMap,
    /// tokio's `Interval::tick`: the `PollFn` over the closure the
    /// async fn awaits, whose pending path polls the `Pin<Box<Sleep>>`
    /// in the interval's `delay` and nothing else. The route runs
    /// through the closure's capture to the interval and lands on
    /// the box; its std record crosses to the `Sleep`.
    TokioIntervalTick,
    /// core's `future::pending::Pending<T>`, the future
    /// `std::future::pending()` returns: `poll` returns `Poll::Pending`
    /// and does nothing else. A compiler-origin rule, since the source
    /// it reviews ships with the toolchain.
    CorePending,
    /// futures-util's `future::pending::Pending<T>`, the future
    /// `futures::future::pending()` returns: the same never-ready
    /// terminal, under the crate's layout origin — a zero-sized future
    /// over a `PhantomData<T>` holds nothing to poll and cannot produce
    /// a `T`, and no build leaves a declaration of its poll to read a
    /// version off.
    FuturesUtilPending,
    /// hyper's HTTP/1 connection under a reviewed range: the
    /// `Dispatcher` as the resource whose state words are the
    /// connection's verdict, and the `client::conn::http1` and
    /// `server::conn::http1` wrappers whose polls forward to it.
    HyperH1Conn,
    /// hyper-util's version-choosing server connection
    /// (`server::conn::auto::UpgradeableConnection`) under a reviewed
    /// range, whose state says whether the connection is still reading
    /// its first bytes — the wrapper is then the connection resource
    /// itself, with no HTTP/1 words to bind — is HTTP/1, polling the
    /// `server::conn::http1` connection inside and acting only on its
    /// output, or HTTP/2.
    HyperUtilAutoConn,
    /// dropshot's `server::ServerRequestHandler`, the service its server
    /// hands hyper for each accepted connection, under a reviewed
    /// range: it keeps the accepted socket's peer address in
    /// `remote_addr`, which is what names a server connection's peer.
    DropshotRequestHandler,
    /// reqwest's `async_impl::client::PendingRequest`, the future a
    /// client's `send()` resolves through, under a reviewed range: it
    /// keeps the request's `method` and its whole `url` for retries and
    /// redirects, which is what names the request a client connection
    /// is carrying.
    ReqwestPendingRequest,
    /// http's `request::Request<B>` under a reviewed range: its head
    /// keeps the `method` and the `uri`, which is what names the
    /// request a server's handler is running for, where the handler
    /// holds the request itself.
    HttpRequest,
    /// dropshot's `handler::RequestContext<C>` under a reviewed range:
    /// its `request` keeps the `method` and `uri` of the request its
    /// handler is running for.
    DropshotRequestContext,
    /// hashbrown's `RawTable` under a reviewed range, as its `HashMap`
    /// and `HashSet` keep it and std's wrap them: which buckets are full
    /// and where each sits, which is what reads a map's entries. A
    /// layout rule, whose version is read off the declarations of
    /// hashbrown's map — a cargo registry release, or the one the
    /// toolchain vendors for std.
    HashbrownTable,
    /// hyper-util's legacy client pool under a reviewed range: its idle
    /// reaper and its checked-out connections, which name each pooled
    /// connection by its key and its sender.
    HyperUtilPool,
    /// hyper-util's `Connected` under a reviewed range: the connection
    /// info its client pool keeps beside each sender — how the
    /// connection was negotiated, and the extras its connector recorded
    /// behind a trait object.
    HyperUtilConnected,
    /// futures-util's `future::Either<A, B>`: a match on which side it
    /// holds, forwarding to that side's future.
    FuturesUtilEither,
    /// tower's retry `ResponseFuture` under a reviewed range: a match on
    /// its state, forwarding to the service's or the policy's future it
    /// holds, and to nothing while it polls the service's readiness.
    TowerRetry,
    /// reqwest's cookie layer's `ResponseFuture` under a reviewed range,
    /// forwarding to the future of the service it wraps.
    ReqwestCookie,
    /// hyper-util's legacy client `ResponseFuture` under a reviewed
    /// range, forwarding to the boxed future its `SyncWrapper` holds.
    HyperUtilResponseFuture,
    /// rustc's async closure environment: a coroutine whose kind is
    /// known by its name, and nothing reviewed about its states.
    RustcAsyncClosure,
    /// std's refcounted allocation headers — `alloc::sync::ArcInner<T>`
    /// and `alloc::rc::RcInner<T>` (formerly `RcBox<T>`) — whose value
    /// sits in one named member past the two counts.
    StdRefcountHeader,
    /// std's futex mutex, `std::sys::sync::mutex::futex::Mutex`: one
    /// `u32` word, zero while unlocked.
    StdFutexMutex,
    /// parking_lot's `raw_mutex::RawMutex` under a reviewed range: one
    /// state byte whose low bit is the lock.
    ParkingLotRawMutex,
    /// The tokio futures that acquire a batch semaphore for a primitive
    /// of their own module — `Mutex`, `RwLock`, `Semaphore`, a bounded
    /// mpsc channel's capacity — under the family's layout.
    TokioAcquireOwner,
    /// tokio's own streams under the family's layout: the wrappers whose
    /// `AsyncRead`/`AsyncWrite` forward to the stream they hold — the
    /// halves `io::split` and a socket's `split`/`into_split` make, the
    /// buffered wrappers, and its impls for `Box` and `&mut` — and the
    /// sockets their routes end at.
    TokioIoRoute,
    /// tokio-rustls's streams under a reviewed range: the `TlsStream`
    /// enum, whose reads and writes are its live variant's, and the
    /// client and server streams, whose socket reads and writes are
    /// their `io`'s.
    TokioRustlsStream,
    /// sprockets-tls's `Stream` at a reviewed revision, whose reads and
    /// writes are the TLS stream it holds.
    SprocketsTlsStream,
    /// sprockets-tls's handshakes at a reviewed revision — the client's
    /// `connect_with_config`, the server's `SprocketsAcceptor::handshake`
    /// — whose frames keep the TLS stream they set up beside the far
    /// end's address and platform id.
    SprocketsHandshake,
    /// rustls's connection state under a reviewed range, read as the
    /// words of a TLS session.
    RustlsSession,
    /// hyper-util's io adapters under a reviewed range — `TokioIo`,
    /// `Rewind` — whose reads and writes are the stream they hold.
    HyperUtilStream,
    /// dropshot's `TlsConn` under a reviewed range, whose reads and
    /// writes are the TLS stream it holds.
    DropshotTlsConn,
    /// reqwest's connection types under a reviewed range: `Conn`,
    /// whose stream is a trait object whose read slot the review
    /// places, and the `RustlsTlsConn` and `Verbose` wrappers.
    ReqwestConn,
    /// hyper-rustls's `MaybeHttpsStream` under a reviewed range, whose
    /// reads and writes are its live variant's.
    HyperRustlsStream,
    /// tokio-rustls's handshake under a reviewed range: `MidHandshake`,
    /// an io operation over the stream its `Handshaking` variant holds,
    /// and the `Connect`/`Accept` newtypes that poll it and nothing else.
    TokioRustlsHandshake,
}

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub enum SemanticOrigin {
    Rustc {
        producer: StrRef,
        family: StrRef,
    },
    LibraryLayout {
        package: StrRef,
        version: Option<StrRef>,
        family: StrRef,
        selection: LayoutSelection,
    },
    /// A third-party implementation a reviewed delegation rule forwards
    /// through, identified the way its family was selected: the crate
    /// and version its declaration file's cargo registry path spells.
    LibraryDelegation {
        package: StrRef,
        version: StrRef,
        /// The reviewed implementation family the version selected.
        family: StrRef,
        /// The declaration file the origin was read from, cut to its
        /// `registry/src/` tail (see [`crate::origin::registry_origin`]).
        source: StrRef,
        /// Line-table checksums corroborating the reviewed revision, when
        /// the unit's file table carried any. rustc's DWARF 4 builds carry
        /// none, and the list is then empty: the registry path is the
        /// evidence the rule runs on, a checksum a check on top of it.
        files: Vec<SourceFileEvidence>,
    },
    /// A third-party implementation fetched from git, which has no
    /// release to name: identified by the repository and revision its
    /// declaration file's checkout path records, each revision reviewed
    /// on its own.
    GitDelegation {
        /// The crate the review names; the checkout path does not.
        package: StrRef,
        repository: StrRef,
        revision: StrRef,
        family: StrRef,
        /// The declaration file the origin was read from, cut to its
        /// `git/checkouts/` tail (see [`crate::origin::git_origin`]).
        source: StrRef,
        /// Line-table checksums corroborating the reviewed revision.
        files: Vec<SourceFileEvidence>,
    },
}

#[derive(Copy, Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub enum LayoutSelection {
    ReviewedRange,
    BelowFloor,
    AboveReviewedRange,
    VersionUnknown,
}

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct SourceFileEvidence {
    pub file: StrRef,
    pub md5: [u8; 16],
}

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct SemanticIssue {
    pub kind: SemanticIssueKind,
    pub detail: Option<StrRef>,
}

#[derive(Copy, Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub enum SemanticIssueKind {
    NoRule,
    UnsupportedOrigin,
    MissingLayout,
    AmbiguousLayout,
    UnsupportedState,
    MultipleChildren,
    PossiblyUninitialized,
}

#[derive(Copy, Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub enum SchedulerClass {
    MultiThread,
    CurrentThread,
    LocalSet,
    Blocking,
}

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct SchedulerBinding {
    pub class: SchedulerClass,
    pub rule: SemanticRuleId,
}
