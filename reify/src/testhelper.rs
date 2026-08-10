//! The synthetic bundle shared by reify's tests.
//!
//! Hand-built rather than extracted: it pins the exact type graph the tests
//! need, so a render assertion cannot drift because an extractor changed what
//! it emits.

use exegesis::Encoding;
use exegesis::bundle::{
    Arm, BitField as BundleBitField, Bundle, BundleTypeId, DiscrDef, DiscrValue, DiscrValues,
    DisplayNode as BundleNode, DynFutureTable, FORMAT_VERSION, Field as BundleField,
    FieldRender as BundleFieldRender, InfraTypes, MapEntries as BundleMapEntries, MemberDef,
    MemberRef, Meta, Notation, ProvenanceTable, ScalarDecode as BundleScalarDecode, Selector,
    StaticsTable, Step, Stmt as BundleStmt, StrRef, StringInterner, TaskTable, TypeDef, TypeTable,
    ValueExpr, VariantDef, VariantShape, WalksTable,
};

use std::collections::BTreeMap;
use std::num::NonZeroU8;

/// A stand-in for a target's memory.
///
/// Render tests need three things from a process: bytes at an address, a
/// function symbol at an address, and the ability to make a read fail. Rather
/// than a bespoke `ReadFromProc` per test asserting on the exact address and
/// length it expects, describe the memory that should exist and let an
/// unsatisfiable read degrade the way it would against a real target.
///
/// Reads are served from any region that wholly contains them, so a formatter
/// that walks a structure field by field is served the same as one that reads
/// it whole -- an mpsc block read piecemeal by a `CustomList`, say.
#[derive(Default)]
pub struct FakeMem {
    regions: Vec<(u64, Vec<u8>)>,
    symbols: BTreeMap<u64, String>,
    unmapped: Unmapped,
    all_reads_fail: bool,
    no_bounds: bool,
}

/// What a read no region satisfies does.
#[derive(Default, Clone, Copy)]
pub enum Unmapped {
    /// Fail, as reading an unmapped page would. The renderer degrades.
    #[default]
    Fail,
    /// Panic, for a test asserting some address is never read at all -- an
    /// atomic's stored pointer, or a function pointer that must not be
    /// followed as data.
    Panic,
}

impl FakeMem {
    pub fn new() -> Self {
        Self::default()
    }

    /// Place `bytes` at `addr`. Any read wholly inside the region is served
    /// from it.
    pub fn at(mut self, addr: u64, bytes: impl Into<Vec<u8>>) -> Self {
        self.regions.push((addr, bytes.into()));
        self
    }

    /// Resolve `addr` to a function symbol, as a target with symbols would.
    pub fn symbol(mut self, addr: u64, name: &str) -> Self {
        self.symbols.insert(addr, name.to_owned());
        self
    }

    /// Panic rather than fail on a read nothing satisfies.
    pub fn panic_on_unmapped(mut self) -> Self {
        self.unmapped = Unmapped::Panic;
        self
    }

    /// Fail every read, mapped or not -- an exited process, or a snapshot
    /// that did not capture the pages.
    pub fn unreadable(mut self) -> Self {
        self.all_reads_fail = true;
        self
    }

    /// Decline to bound reads, the way a live process does: `readable_len`
    /// claims everything asked for, and a read past the regions fails
    /// outright rather than coming up short.
    pub fn no_bounds(mut self) -> Self {
        self.no_bounds = true;
        self
    }
}

impl crate::ReadFromProc for FakeMem {
    // Borrowed, like a mapped core lends its bytes: the tests then hold
    // the renderer to the lifetimes the cheapest real reader produces.
    fn read_bytes(&self, addr: u64, len: u64) -> crate::Result<std::borrow::Cow<'_, [u8]>> {
        if self.all_reads_fail {
            return Err(crate::Error::invalid_addr(addr));
        }
        for (base, bytes) in &self.regions {
            let Some(start) = addr.checked_sub(*base) else {
                continue;
            };
            let (Ok(start), Ok(len)) = (usize::try_from(start), usize::try_from(len)) else {
                continue;
            };
            if let Some(end) = start.checked_add(len)
                && end <= bytes.len()
            {
                return Ok(std::borrow::Cow::Borrowed(&bytes[start..end]));
            }
        }
        match self.unmapped {
            Unmapped::Fail => Err(crate::Error::invalid_addr(addr)),
            Unmapped::Panic => panic!("unexpected read of {len} bytes at {addr:#x}"),
        }
    }

    // A region bounds what can be read from it, the way a core's segment
    // does -- so a length that outruns the bytes in hand is cut to them
    // rather than failing the read outright.
    fn readable_len(&self, addr: u64, max: u64) -> u64 {
        if self.no_bounds {
            return max;
        }
        if self.all_reads_fail {
            return 0;
        }
        for (base, bytes) in &self.regions {
            let Some(start) = addr.checked_sub(*base) else {
                continue;
            };
            if start < bytes.len() as u64 {
                return (bytes.len() as u64 - start).min(max);
            }
        }
        0
    }

    fn function_symbol(&self, addr: u64) -> Option<String> {
        self.symbols.get(&addr).cloned()
    }
}

/// A [`ParseCtx`](crate::ParseCtx) over a [`FakeMem`], for the parsing and
/// owned-`TypeInfo` paths that take a context rather than a bare reader.
pub struct TestCtx {
    pub mem: FakeMem,
}

impl TestCtx {
    pub fn new(mem: FakeMem) -> Self {
        Self { mem }
    }
}

impl crate::ParseCtx for TestCtx {
    type Target = FakeMem;

    fn proc(&self) -> &FakeMem {
        &self.mem
    }
}

/// Bytes for a [`NODE`] value: `Node { value: u32 @0, next: *Node @8 }`.
pub fn node_bytes(value: u32, next: u64) -> Vec<u8> {
    let mut bytes = vec![0u8; 16];
    bytes[..4].copy_from_slice(&value.to_le_bytes());
    bytes[8..].copy_from_slice(&next.to_le_bytes());
    bytes
}

/// Bytes for a [`BTREE_LEAF`]: `LeafNode { len: u8 @0, keys: [MaybeUninit<u32>;
/// 2] @4, vals: [MaybeUninit<u32>; 2] @12 }`. Slots past `entries` keep the
/// `0xaa` fill, standing in for the uninitialized memory a real node has.
pub fn btree_leaf(entries: &[(u32, u32)]) -> Vec<u8> {
    let mut bytes = vec![0xaa; 20];
    bytes[0] = entries.len() as u8;
    for (i, (key, value)) in entries.iter().enumerate() {
        bytes[4 + i * 4..8 + i * 4].copy_from_slice(&key.to_le_bytes());
        bytes[12 + i * 4..16 + i * 4].copy_from_slice(&value.to_le_bytes());
    }
    bytes
}

/// Bytes for a [`BTREE_INTERNAL`]: `InternalNode { data: LeafNode @0, edges:
/// [*LeafNode; 3] @24 }`.
pub fn btree_internal(entries: &[(u32, u32)], edges: &[u64]) -> Vec<u8> {
    let mut bytes = vec![0xaa; 48];
    bytes[..20].copy_from_slice(&btree_leaf(entries));
    for (i, edge) in edges.iter().enumerate() {
        bytes[24 + i * 8..32 + i * 8].copy_from_slice(&edge.to_le_bytes());
    }
    bytes
}

/// Bytes for an mpsc [`BLOCK`]: `[u32; 4] values @0, start_index: usize @16,
/// next: *Block @24`. The queued-message walk reads a block field by field, so
/// this is placed as one region and served piecemeal.
pub fn mpsc_block(values: &[u32; 4], start_index: u64, next: u64) -> Vec<u8> {
    let mut bytes = u32s(values);
    bytes.extend_from_slice(&start_index.to_le_bytes());
    bytes.extend_from_slice(&next.to_le_bytes());
    bytes
}

/// Bytes for a tokio sync waiter -- `{ <state word>: usize @0, next: *Waiter
/// @8, waker: Option<Waker> @16 }` -- filling the 32 bytes the fixture's
/// waiter types declare. The waker's zeroed vtable word reads as `None`.
pub fn sync_waiter(state: u64, next: u64) -> Vec<u8> {
    let mut bytes = vec![0u8; 32];
    bytes[..8].copy_from_slice(&state.to_le_bytes());
    bytes[8..16].copy_from_slice(&next.to_le_bytes());
    bytes
}

/// A [`sync_waiter`] whose waker is armed: a nonzero vtable word selects the
/// `Some` variant, and `data` is the word a task waker keeps there — the
/// woken task's Header address.
pub fn sync_waiter_waking(state: u64, next: u64, data: u64) -> Vec<u8> {
    let mut bytes = sync_waiter(state, next);
    bytes[16..24].copy_from_slice(&0x9990u64.to_le_bytes());
    bytes[24..32].copy_from_slice(&data.to_le_bytes());
    bytes
}

/// Bytes for a [`MSG_WRAP`] value: the wrapped `Msg`'s tag byte and its
/// 8-byte payload word (`B`'s u64; the other variants read their own shapes
/// from the same storage).
pub fn msg_wrap(tag: u8, payload: u64) -> Vec<u8> {
    let mut bytes = vec![0u8; 16];
    bytes[0] = tag;
    bytes[8..].copy_from_slice(&payload.to_le_bytes());
    bytes
}

/// The [`StrRef`] a finished bundle interned for `name` — for tests splicing
/// a name-addressed selector into a built bundle, whose interner is gone.
/// Panics when the fixture never interned it.
pub fn strref(b: &Bundle, name: &str) -> StrRef {
    (0..b.strings.len() as u32)
        .map(StrRef)
        .find(|&r| b.strings.get(r) == Some(name))
        .unwrap_or_else(|| panic!("string {name:?} is not interned in the fixture bundle"))
}

/// Little-endian bytes for a sequence of `u32`s -- the shape most fixture
/// values take.
pub fn u32s(values: &[u32]) -> Vec<u8> {
    values.iter().flat_map(|v| v.to_le_bytes()).collect()
}

/// Little-endian bytes for a sequence of `u64`s, for pointer words and the
/// `(pointer, length, capacity)` triples a slice or string is read from.
pub fn u64s(values: &[u64]) -> Vec<u8> {
    values.iter().flat_map(|v| v.to_le_bytes()).collect()
}

/// Shorthand for a member-only [`Selector`], which is what most selectors in
/// these synthetic bundles are; one that crosses a pointer spells out
/// `Selector::members(..).deref()`.
pub fn sel(members: &[u32]) -> Selector {
    Selector::members(members)
}

/// Build a [`Selector`] over a member-*name* path — the addressing a detector
/// reaches for whenever the names are stable, and the one a fixture must also
/// exercise so resolution by name is covered.
pub fn nsel(names: &[StrRef]) -> Selector {
    Selector::named_path(names)
}

/// A [`BundleField`] for a real member at `index`, rendered structurally.
pub fn fmember(index: u32) -> BundleField {
    BundleField::member(MemberRef::Index(index))
}

/// A [`BundleField`] for the real member at `index`, keeping its name but
/// computing its value with `node`.
pub fn fcomputed(index: u32, node: BundleNode) -> BundleField {
    BundleField::computed(MemberRef::Index(index), node)
}

/// As [`fcomputed`], but addressing the member by name rather than position.
pub fn fcomputed_named(name: StrRef, node: BundleNode) -> BundleField {
    BundleField::computed(MemberRef::Named(name), node)
}

/// A [`BundleField`] synthesized under an explicit `label`.
pub fn fsynth(label: StrRef, node: BundleNode) -> BundleField {
    BundleField::Synth { label, node }
}

/// Build an enumerated bundle [`BundleBitField`] from pre-interned labels.
pub fn ebf(name: StrRef, shift: u8, width: u8, table: Vec<(u64, StrRef)>) -> BundleBitField {
    BundleBitField {
        name,
        shift,
        width: NonZeroU8::new(width),
        render: BundleFieldRender::Enum(table),
    }
}

/// Build an unsigned-integer tail bundle [`BundleBitField`] (`width: None`).
pub fn ubf(name: StrRef, shift: u8) -> BundleBitField {
    BundleBitField {
        name,
        shift,
        width: None,
        render: BundleFieldRender::Uint,
    }
}

// Compact builders for the CustomList value language used by the synthetic
// mpsc-queue bundle and its focused test.
pub fn vvar(id: u32) -> ValueExpr {
    ValueExpr::Var(id)
}
pub fn vconst(n: u64) -> ValueExpr {
    ValueExpr::Const(n)
}
pub fn vread(selector: Selector) -> ValueExpr {
    ValueExpr::Read(selector)
}
pub fn vadd(a: ValueExpr, b: ValueExpr) -> ValueExpr {
    ValueExpr::Add(Box::new(a), Box::new(b))
}
pub fn vsub(a: ValueExpr, b: ValueExpr) -> ValueExpr {
    ValueExpr::Sub(Box::new(a), Box::new(b))
}
pub fn vmul(a: ValueExpr, b: ValueExpr) -> ValueExpr {
    ValueExpr::Mul(Box::new(a), Box::new(b))
}
pub fn vlt(a: ValueExpr, b: ValueExpr) -> ValueExpr {
    ValueExpr::Lt(Box::new(a), Box::new(b))
}
pub fn vne(a: ValueExpr, b: ValueExpr) -> ValueExpr {
    ValueExpr::Ne(Box::new(a), Box::new(b))
}
pub fn vand(a: ValueExpr, b: ValueExpr) -> ValueExpr {
    ValueExpr::And(Box::new(a), Box::new(b))
}
pub fn vload(addr: ValueExpr) -> ValueExpr {
    ValueExpr::Load {
        addr: Box::new(addr),
        size: 8,
    }
}

/// The synthetic mpsc block-chain walk as a [`BundleNode::CustomList`],
/// mirroring what the extractor now emits. Block layout: values @0,
/// start_index @16, next @24; 4-byte slots, 4 per block. Loop vars are
/// 0 = cur (index), 1 = tail, 2 = block pointer. Reproduces `[20, 30]`.
pub fn chan_queued_node(element: BundleTypeId) -> BundleNode {
    let start = || vload(vadd(vvar(2), vconst(16)));
    BundleNode::CustomList {
        vars: vec![vread(sel(&[1])), vread(sel(&[0])), vread(sel(&[2]))],
        condition: vand(vlt(vvar(0), vvar(1)), vne(vvar(2), vconst(0))),
        body: vec![
            BundleStmt::Break {
                cond: vlt(vvar(0), start()),
            },
            BundleStmt::If {
                cond: vlt(vsub(vvar(0), start()), vconst(4)),
                then: vec![
                    BundleStmt::Emit {
                        at: vadd(vvar(2), vmul(vsub(vvar(0), start()), vconst(4))),
                    },
                    BundleStmt::Set {
                        var: 0,
                        value: vadd(vvar(0), vconst(1)),
                    },
                ],
                otherwise: vec![BundleStmt::Set {
                    var: 2,
                    value: vload(vadd(vvar(2), vconst(24))),
                }],
            },
        ],
        element,
    }
}

/// Declare fixture type ids, numbered in declaration order.
///
/// The ids are positions in the fixture's type table, so they used to be
/// written out by hand — a list of `BundleTypeId(37)` that had to be kept in
/// step with the order the definitions were appended in. Declaring them here
/// keeps the numbering implicit, and [`FixtureTypes::add`] checks each
/// definition against the id it claims, so a type inserted in one place and
/// not the other fails immediately instead of silently shifting every id
/// after it.
macro_rules! fixture_ids {
    ($($name:ident),* $(,)?) => { fixture_ids!(@each [] $($name)*); };
    (@each [$($prev:ident)*] $name:ident $($rest:ident)*) => {
        pub const $name: BundleTypeId = {
            // The id is how many names were declared before this one.
            const PRECEDING: &[&str] = &[$(stringify!($prev)),*];
            BundleTypeId(PRECEDING.len() as u32)
        };
        fixture_ids!(@each [$($prev)* $name] $($rest)*);
    };
    (@each [$($prev:ident)*]) => {};
}

/// A fixture's type table under construction.
///
/// Every definition is appended against the id it is meant to have, so the
/// ids declared by [`fixture_ids!`] and the definitions here cannot drift
/// apart unnoticed.
#[derive(Default)]
pub struct FixtureTypes {
    types: Vec<TypeDef>,
}

impl FixtureTypes {
    /// Append `def` as `claimed`, which must be the next id.
    pub fn add(&mut self, claimed: BundleTypeId, def: TypeDef) {
        assert_eq!(
            BundleTypeId(self.types.len() as u32),
            claimed,
            "fixture type definitions are out of step with their ids: \
             the definition appended here lands at {} but claims {}",
            self.types.len(),
            claimed.0,
        );
        self.types.push(def);
    }

    /// The finished table.
    pub fn finish(self) -> Vec<TypeDef> {
        self.types
    }
}

fixture_ids! {
    U32, U64, BOOL, U8, UNIT, POINT,
    MSG, OPT, WRAP, PTR, ARR, NODE,
    NODE_PTR, VTABLE_ARRAY, VTABLE_PTR, FAT_PTR, ATOMIC, ATOMIC_STORAGE,
    ATOMIC_PTR, LOOM_ATOMIC, LOOM_CELL, DYN_TRAIT, DYN_TRAIT_PTR, RAW_WAKER_VTABLE,
    FUNCTION_TARGET, FUNCTION_PTR, BTREE_MAP, BTREE_ROOT, BTREE_NODE_REF, BTREE_LEAF_PTR,
    BTREE_LEAF, MAYBE_U32, BTREE_SLOTS, BTREE_INTERNAL, BTREE_EDGES, IPV4_OCTETS,
    IPV4, IPV6_OCTETS, IPV6, U8_PTR, VEC, STR,
    STRING, RAW_MUTEX, NOTIFY, SEMAPHORE, BLOCK, BLOCK_VALUES,
    BLOCK_HEADER, WATCH_STATE, CHAN, CHAN_BLOCK, CHAN_BLOCK_HEADER, CHAN_BLOCK_PTR,
    RX_CHAN, RX_SEMAPHORE, ARC_INNER, ARC_INNER_PTR, RECEIVER, BOUNDED_SEM,
    BSEM_INNER, BSEM_MUTEX, BSEM_WAITLIST, BSEM_LIST, WAITER, WAITER_PTR,
    NOTIFY_MUTEX, NOTIFY_LIST, NOTIFY_WAITER, NOTIFY_WAITER_PTR, SLICE, WATCH_RECEIVER,
    WATCH_ARC_INNER, WATCH_ARC_INNER_PTR, WATCH_SHARED, PAIR,
    // Base and aggregate kinds that reach a `TypeClass` arm no other fixture
    // type does: the float, signed, character and odd-width integer
    // encodings, plus a C enumeration, a union and a sized opaque.
    F32, F64, I8, I16, I32, I64,
    CHAR, U24, COLOR, VAL_UNION, UNMODELLED, U16,
    U16_ARR,
    // A `uuid::Uuid`: the same `[u8; 16]` an `Ipv6Addr` is, so only the
    // notation separates what the two render as.
    UUID_BYTES, UUID,
    // A 32-byte digest: any length is hex, so it shares no length with the
    // notations that fix one.
    HASH_BYTES, HASH,
    // The waker a parked sync waiter registered: `Option<Waker>` niched on
    // the RawWaker's vtable word, whose `Waker` payload carries the alias
    // format the real emission attaches (the bare `data` pointer).
    UNIT_PTR, WAKER_VTABLE_PTR, TASK_RAW_WAKER, TASK_WAKER, OPT_WAKER,
    // Hosts for `Step::Variant` reads: a wrapper holding the tagged `Msg`,
    // and an outer struct reaching one across a pointer (plus the niche
    // `Opt` inline), so both local and cross-segment guards are exercised.
    MSG_WRAP, MSG_WRAP_PTR, GUARD_OUTER,
    // A struct with a member past 64 KiB, so member slicing is exercised
    // beyond the offsets a 16-bit computation can represent.
    BIG,
}

/// A hand-built mini-bundle exercising every TypeDef kind reify touches:
///
/// - `Point { x: u32 @0, y: u32 @4 }`
/// - `Msg` — tagged enum, u8 discr @0: `A(Point)@8 | B(u64)@8 | C(unit)@8`
/// - `Opt` — niche enum, u64 discr @0: `None(unit)=0 | Some(u64) default`
/// - `Wrap { inner: Point @0 }` — single-member wrapper for peel()
/// - `*Point`, `[u32; 3]`
pub fn test_bundle() -> Bundle {
    let mut strings = StringInterner::new();
    let mut s = |name: &str| strings.intern(name);

    let (u32n, u64n, booln, u8n, unitn) = (s("u32"), s("u64"), s("bool"), s("u8"), s("Unit"));
    let (pointn, xn, yn) = (s("Point"), s("x"), s("y"));
    let (msgn, an, bn, cn) = (s("Msg"), s("A"), s("B"), s("C"));
    let (optn, nonen, somen) = (s("Opt"), s("None"), s("Some"));
    let (wrapn, innern) = (s("Wrap"), s("inner"));
    let (noden, valuen, nextn) = (s("Node"), s("value"), s("next"));
    let (fatn, pointern, vtablen) = (s("FatPtr"), s("pointer"), s("vtable"));
    let dyn_traitn = s("dyn app::Trait");
    let raw_waker_vtablen = s("core::task::wake::RawWakerVTable");
    let unresolvedn = s("<unresolved>");
    let (clonen, waken, wake_by_refn, dropn) = (s("clone"), s("wake"), s("wake_by_ref"), s("drop"));
    let (task_wakern, task_raw_wakern, opt_wakern, wakern) = (
        s("core::task::wake::Waker"),
        s("core::task::wake::RawWaker"),
        s("Option<Waker>"),
        s("waker"),
    );
    let (atomicn, storagen, vn) = (s("Atomic<u32>"), s("AtomicStorage<u32>"), s("v"));
    let atomic_ptrn = s("Atomic<*mut Point>");
    let (loom_atomicn, loom_celln, tuple0n) =
        (s("AtomicU32"), s("LoomUnsafeCell<Point>"), s("__0"));
    let (pairn, tuple1n) = (s("Pair"), s("__1"));
    let (f32n, f64n) = (s("f32"), s("f64"));
    let (i8n, i16n, i32n, i64n) = (s("i8"), s("i16"), s("i32"), s("i64"));
    let (charn, u24n, u16n) = (s("char"), s("u24"), s("u16"));
    let (colorn, redn, greenn) = (s("Color"), s("Red"), s("Green"));
    let (val_unionn, intn, floatn) = (s("Val"), s("int"), s("float"));
    let unmodelledn = s("Unmodelled");
    let btree_mapn = s("alloc::collections::btree::map::BTreeMap<u32, u32>");
    let btree_rootn = s("Option<NodeRef>");
    let btree_node_refn = s("NodeRef");
    let btree_leafn = s("LeafNode");
    let maybe_u32n = s("MaybeUninit<u32>");
    let btree_internaln = s("InternalNode");
    let (rootn, lengthn, heightn, noden2, lenn, keysn, valsn, datan, edgesn) = (
        s("root"),
        s("length"),
        s("height"),
        s("node"),
        s("len"),
        s("keys"),
        s("vals"),
        s("data"),
        s("edges"),
    );
    let (uninitn, some2n, none2n) = (s("uninit"), s("Some"), s("None"));
    let (ipv4n, ipv6n, octetsn) = (
        s("core::net::ip_addr::Ipv4Addr"),
        s("core::net::ip_addr::Ipv6Addr"),
        s("octets"),
    );
    let (uuidn, uuid_bytesn) = (s("uuid::Uuid"), s("__0"));
    let hashn = s("tufaceous_artifact::artifact::ArtifactHash");
    let (vecn, ptrn, vec_lenn, capacityn) =
        (s("alloc::vec::Vec<u32>"), s("ptr"), s("len"), s("capacity"));
    let slicen = s("&[u32]");
    let (strn, stringn, data_ptrn, length2n) = (
        s("&str"),
        s("alloc::string::String"),
        s("data_ptr"),
        s("length"),
    );
    let (raw_mutexn, staten) = (s("parking_lot::raw_mutex::RawMutex"), s("state"));
    let (notifyn, waitersn) = (s("tokio::sync::notify::Notify"), s("waiters"));
    let (semaphoren, permitsn) = (s("tokio::sync::batch_semaphore::Semaphore"), s("permits"));
    let (blockn, block_headern, ready_slotsn, headerfieldn) = (
        s("tokio::sync::mpsc::block::Block<u32>"),
        s("BlockHeader"),
        s("ready_slots"),
        s("header"),
    );
    let valuesfieldn = s("values");
    let watch_staten = s("tokio::sync::watch::state::AtomicState");
    let (watch_receivern, watch_arc_innern, watch_sharedn, sharedn) = (
        s("tokio::sync::watch::Receiver<u32>"),
        s("alloc::sync::ArcInner<tokio::sync::watch::Shared<u32>>"),
        s("tokio::sync::watch::Shared<u32>"),
        s("shared"),
    );
    let (chann, chan_blockn, chan_block_headern) = (
        s("tokio::sync::mpsc::chan::Chan<u32>"),
        s("ChanBlock"),
        s("ChanBlockHeader"),
    );
    let (tailn, headn, indexn, start_indexn) = (s("tail"), s("head"), s("index"), s("start_index"));
    let (receivern, rx_semn, arc_innern) = (
        s("tokio::sync::mpsc::bounded::Receiver<u32>"),
        s("tokio::sync::mpsc::bounded::Semaphore"),
        s("alloc::sync::ArcInner<tokio::sync::mpsc::chan::Chan<u32>>"),
    );
    let (strongn, weakn, boundn, chanfieldn, semfieldn) = (
        s("strong"),
        s("weak"),
        s("bound"),
        s("chan"),
        s("semaphore"),
    );
    let (msg_wrapn, msgn2, guard_outern, wrapn2, optn2) =
        (s("MsgWrap"), s("msg"), s("GuardOuter"), s("wrap"), s("opt"));
    let bign = s("Big");

    // Labels for the sync-primitive `ScalarDecode` tables. Interned here so
    // the decode-building closures below can assemble tables from `Copy`
    // `StrRef`s without re-borrowing the interner.
    let (lockedl, parkedl, falsel, truel) = (s("locked"), s("parked"), s("false"), s("true"));
    let (statel, idlel, waitingl, notifiedl, generationl) = (
        s("state"),
        s("idle"),
        s("waiting"),
        s("notified"),
        s("generation"),
    );
    let (closedl, permitsl, versionl) = (s("closed"), s("permits"), s("version"));
    let (kindl, nonel, onel, alll, orderl, fifol, lifol) = (
        s("kind"),
        s("none"),
        s("one"),
        s("all"),
        s("order"),
        s("fifo"),
        s("lifo"),
    );
    let mutex_decode = || {
        BundleScalarDecode::Bits(vec![
            ebf(lockedl, 0, 1, vec![(0, falsel), (1, truel)]),
            ebf(parkedl, 1, 1, vec![(0, falsel), (1, truel)]),
        ])
    };
    let semaphore_permits_decode = || {
        BundleScalarDecode::Bits(vec![
            ebf(closedl, 0, 1, vec![(0, falsel), (1, truel)]),
            ubf(permitsl, 1),
        ])
    };
    let (bsem_mutexn, bsem_waitlistn, bsem_listn, waitern) = (
        s(
            "lock_api::mutex::Mutex<parking_lot::raw_mutex::RawMutex, tokio::sync::batch_semaphore::Waitlist>",
        ),
        s("tokio::sync::batch_semaphore::Waitlist"),
        s(
            "tokio::util::linked_list::LinkedList<tokio::sync::batch_semaphore::Waiter, tokio::sync::batch_semaphore::Waiter>",
        ),
        s("tokio::sync::batch_semaphore::Waiter"),
    );
    let (rawn, closedn, queuen) = (s("raw"), s("closed"), s("queue"));
    let (notify_mutexn, notify_listn, notify_waitern, notificationn) = (
        s(
            "lock_api::mutex::Mutex<parking_lot::raw_mutex::RawMutex, tokio::util::linked_list::LinkedList<tokio::sync::notify::Waiter, tokio::sync::notify::Waiter>>",
        ),
        s(
            "tokio::util::linked_list::LinkedList<tokio::sync::notify::Waiter, tokio::sync::notify::Waiter>",
        ),
        s("tokio::sync::notify::Waiter"),
        s("notification"),
    );

    let m = |name, ty, offset| MemberDef { name, ty, offset };
    let tag = |v: u128| Some(DiscrValues(vec![DiscrValue::Value(v)]));

    let mut types = FixtureTypes::default();
    types.add(
        U32,
        TypeDef::Base {
            name: u32n,
            size: 4,
            encoding: Encoding::Unsigned,
        },
    );
    types.add(
        U64,
        TypeDef::Base {
            name: u64n,
            size: 8,
            encoding: Encoding::Unsigned,
        },
    );
    types.add(
        BOOL,
        TypeDef::Base {
            name: booln,
            size: 1,
            encoding: Encoding::Boolean,
        },
    );
    types.add(
        U8,
        TypeDef::Base {
            name: u8n,
            size: 1,
            encoding: Encoding::Unsigned,
        },
    );
    types.add(
        UNIT,
        TypeDef::Struct {
            name: unitn,
            size: 0,
            members: vec![],
        },
    );
    types.add(
        POINT,
        TypeDef::Struct {
            name: pointn,
            size: 8,
            members: vec![m(xn, U32, 0), m(yn, U32, 4)],
        },
    );
    types.add(
        MSG,
        TypeDef::Enum {
            name: msgn,
            size: 16,
            shape: VariantShape {
                discr: Some(DiscrDef { offset: 0, ty: U8 }),
                variants: vec![
                    VariantDef {
                        name: an,
                        discr_values: tag(0),
                        payload: m(an, POINT, 8),
                        decl: None,
                        await_site: None,
                    },
                    VariantDef {
                        name: bn,
                        discr_values: tag(1),
                        payload: m(bn, U64, 8),
                        decl: None,
                        await_site: None,
                    },
                    VariantDef {
                        name: cn,
                        discr_values: tag(2),
                        payload: m(cn, UNIT, 8),
                        decl: None,
                        await_site: None,
                    },
                ],
            },
        },
    );
    types.add(
        OPT,
        TypeDef::Enum {
            name: optn,
            size: 8,
            shape: VariantShape {
                discr: Some(DiscrDef { offset: 0, ty: U64 }),
                variants: vec![
                    VariantDef {
                        name: nonen,
                        discr_values: tag(0),
                        payload: m(nonen, UNIT, 0),
                        decl: None,
                        await_site: None,
                    },
                    VariantDef {
                        name: somen,
                        discr_values: None,
                        payload: m(somen, U64, 0),
                        decl: None,
                        await_site: None,
                    },
                ],
            },
        },
    );
    types.add(
        WRAP,
        TypeDef::Struct {
            name: wrapn,
            size: 8,
            members: vec![m(innern, POINT, 0)],
        },
    );
    types.add(
        PTR,
        TypeDef::Pointer {
            name: None,
            target: POINT,
        },
    );
    types.add(
        ARR,
        TypeDef::Array {
            elem: U32,
            count: 3,
        },
    );
    types.add(
        NODE,
        TypeDef::Struct {
            name: noden,
            size: 16,
            members: vec![m(valuen, U32, 0), m(nextn, NODE_PTR, 8)],
        },
    );
    types.add(
        NODE_PTR,
        TypeDef::Pointer {
            name: None,
            target: NODE,
        },
    );
    types.add(
        VTABLE_ARRAY,
        TypeDef::Array {
            elem: U64,
            count: 3,
        },
    );
    types.add(
        VTABLE_PTR,
        TypeDef::Pointer {
            name: None,
            target: VTABLE_ARRAY,
        },
    );
    types.add(
        FAT_PTR,
        TypeDef::Struct {
            name: fatn,
            size: 16,
            members: vec![m(pointern, DYN_TRAIT_PTR, 0), m(vtablen, VTABLE_PTR, 8)],
        },
    );
    types.add(
        ATOMIC,
        TypeDef::Struct {
            name: atomicn,
            size: 4,
            members: vec![m(vn, ATOMIC_STORAGE, 0)],
        },
    );
    types.add(
        ATOMIC_STORAGE,
        TypeDef::Struct {
            name: storagen,
            size: 4,
            members: vec![m(valuen, U32, 0)],
        },
    );
    types.add(
        ATOMIC_PTR,
        TypeDef::Struct {
            name: atomic_ptrn,
            size: 8,
            members: vec![m(vn, PTR, 0)],
        },
    );
    types.add(
        LOOM_ATOMIC,
        TypeDef::Struct {
            name: loom_atomicn,
            size: 4,
            members: vec![m(innern, ATOMIC, 0)],
        },
    );
    types.add(
        LOOM_CELL,
        TypeDef::Struct {
            name: loom_celln,
            size: 8,
            members: vec![m(tuple0n, WRAP, 0)],
        },
    );
    types.add(
        DYN_TRAIT,
        TypeDef::Struct {
            name: dyn_traitn,
            size: 0,
            members: vec![],
        },
    );
    types.add(
        DYN_TRAIT_PTR,
        TypeDef::Pointer {
            name: None,
            target: DYN_TRAIT,
        },
    );
    types.add(
        RAW_WAKER_VTABLE,
        TypeDef::Struct {
            name: raw_waker_vtablen,
            size: 32,
            members: vec![
                m(clonen, PTR, 0),
                m(waken, PTR, 8),
                m(wake_by_refn, PTR, 16),
                m(dropn, PTR, 24),
            ],
        },
    );
    types.add(
        FUNCTION_TARGET,
        TypeDef::Opaque {
            name: unresolvedn,
            size: None,
        },
    );
    types.add(
        FUNCTION_PTR,
        TypeDef::Pointer {
            name: None,
            target: FUNCTION_TARGET,
        },
    );
    types.add(
        BTREE_MAP,
        TypeDef::Struct {
            name: btree_mapn,
            size: 24,
            members: vec![m(rootn, BTREE_ROOT, 0), m(lengthn, U64, 16)],
        },
    );
    types.add(
        BTREE_ROOT,
        TypeDef::Enum {
            name: btree_rootn,
            size: 16,
            shape: VariantShape {
                discr: Some(DiscrDef { offset: 0, ty: U64 }),
                variants: vec![
                    VariantDef {
                        name: none2n,
                        discr_values: tag(0),
                        payload: m(none2n, UNIT, 0),
                        decl: None,
                        await_site: None,
                    },
                    VariantDef {
                        name: some2n,
                        discr_values: None,
                        payload: m(some2n, BTREE_NODE_REF, 0),
                        decl: None,
                        await_site: None,
                    },
                ],
            },
        },
    );
    types.add(
        BTREE_NODE_REF,
        TypeDef::Struct {
            name: btree_node_refn,
            size: 16,
            members: vec![m(noden2, BTREE_LEAF_PTR, 0), m(heightn, U64, 8)],
        },
    );
    types.add(
        BTREE_LEAF_PTR,
        TypeDef::Pointer {
            name: None,
            target: BTREE_LEAF,
        },
    );
    types.add(
        BTREE_LEAF,
        TypeDef::Struct {
            name: btree_leafn,
            size: 20,
            members: vec![
                m(lenn, U8, 0),
                m(keysn, BTREE_SLOTS, 4),
                m(valsn, BTREE_SLOTS, 12),
            ],
        },
    );
    types.add(
        MAYBE_U32,
        TypeDef::Union {
            name: maybe_u32n,
            size: 4,
            members: vec![m(uninitn, UNIT, 0), m(valuen, U32, 0)],
        },
    );
    types.add(
        BTREE_SLOTS,
        TypeDef::Array {
            elem: MAYBE_U32,
            count: 2,
        },
    );
    types.add(
        BTREE_INTERNAL,
        TypeDef::Struct {
            name: btree_internaln,
            size: 48,
            members: vec![m(datan, BTREE_LEAF, 0), m(edgesn, BTREE_EDGES, 24)],
        },
    );
    types.add(
        BTREE_EDGES,
        TypeDef::Array {
            elem: BTREE_LEAF_PTR,
            count: 3,
        },
    );
    types.add(IPV4_OCTETS, TypeDef::Array { elem: U8, count: 4 });
    types.add(
        IPV4,
        TypeDef::Struct {
            name: ipv4n,
            size: 4,
            members: vec![m(octetsn, IPV4_OCTETS, 0)],
        },
    );
    types.add(
        IPV6_OCTETS,
        TypeDef::Array {
            elem: U8,
            count: 16,
        },
    );
    types.add(
        IPV6,
        TypeDef::Struct {
            name: ipv6n,
            size: 16,
            members: vec![m(octetsn, IPV6_OCTETS, 0)],
        },
    );
    types.add(
        U8_PTR,
        TypeDef::Pointer {
            name: None,
            target: U8,
        },
    );
    types.add(
        VEC,
        TypeDef::Struct {
            name: vecn,
            size: 24,
            members: vec![
                m(ptrn, U8_PTR, 0),
                m(vec_lenn, U64, 8),
                m(capacityn, U64, 16),
            ],
        },
    );
    types.add(
        STR,
        TypeDef::Struct {
            name: strn,
            size: 16,
            members: vec![m(data_ptrn, U8_PTR, 0), m(length2n, U64, 8)],
        },
    );
    types.add(
        STRING,
        TypeDef::Struct {
            name: stringn,
            size: 24,
            members: vec![
                m(ptrn, U8_PTR, 0),
                m(vec_lenn, U64, 8),
                m(capacityn, U64, 16),
            ],
        },
    );
    types.add(
        RAW_MUTEX,
        TypeDef::Struct {
            name: raw_mutexn,
            size: 1,
            members: vec![m(staten, U8, 0)],
        },
    );
    // Notify { state: usize @0, waiters: Mutex<LinkedList<Waiter>> @8 }
    // (the loom/UnsafeCell wrappers the detector navigates are collapsed
    // here — reify only needs the resolved offsets).
    types.add(
        NOTIFY,
        TypeDef::Struct {
            name: notifyn,
            size: 32,
            members: vec![m(staten, U64, 0), m(waitersn, NOTIFY_MUTEX, 8)],
        },
    );
    types.add(
        SEMAPHORE,
        TypeDef::Struct {
            name: semaphoren,
            size: 16,
            members: vec![m(permitsn, U64, 0), m(waitersn, U32, 8)],
        },
    );
    types.add(
        BLOCK,
        TypeDef::Struct {
            name: blockn,
            size: 24,
            members: vec![
                m(valuesfieldn, BLOCK_VALUES, 0),
                m(headerfieldn, BLOCK_HEADER, 16),
            ],
        },
    );
    types.add(
        BLOCK_VALUES,
        TypeDef::Array {
            elem: U32,
            count: 4,
        },
    );
    types.add(
        BLOCK_HEADER,
        TypeDef::Struct {
            name: block_headern,
            size: 8,
            members: vec![m(ready_slotsn, U64, 0)],
        },
    );
    types.add(
        WATCH_STATE,
        TypeDef::Struct {
            name: watch_staten,
            size: 8,
            members: vec![m(tuple0n, U64, 0)],
        },
    );
    // Chan { tail: usize @0, index: usize @8, head: *ChanBlock @16 }
    types.add(
        CHAN,
        TypeDef::Struct {
            name: chann,
            size: 24,
            members: vec![
                m(tailn, U64, 0),
                m(indexn, U64, 8),
                m(headn, CHAN_BLOCK_PTR, 16),
            ],
        },
    );
    // ChanBlock { values: [u32; 4] @0, header: ChanBlockHeader @16 }
    types.add(
        CHAN_BLOCK,
        TypeDef::Struct {
            name: chan_blockn,
            size: 32,
            members: vec![
                m(valuesfieldn, BLOCK_VALUES, 0),
                m(headerfieldn, CHAN_BLOCK_HEADER, 16),
            ],
        },
    );
    // ChanBlockHeader { start_index: usize @0, next: *ChanBlock @8 }
    types.add(
        CHAN_BLOCK_HEADER,
        TypeDef::Struct {
            name: chan_block_headern,
            size: 16,
            members: vec![m(start_indexn, U64, 0), m(nextn, CHAN_BLOCK_PTR, 8)],
        },
    );
    types.add(
        CHAN_BLOCK_PTR,
        TypeDef::Pointer {
            name: None,
            target: CHAN_BLOCK,
        },
    );
    // RxChan: tail @0, index @8, head @16, semaphore @24 (like Chan
    // but with the bounded semaphore appended).
    types.add(
        RX_CHAN,
        TypeDef::Struct {
            name: chann,
            size: 40,
            members: vec![
                m(tailn, U64, 0),
                m(indexn, U64, 8),
                m(headn, CHAN_BLOCK_PTR, 16),
                m(semfieldn, RX_SEMAPHORE, 24),
            ],
        },
    );
    // bounded::Semaphore { permits: usize @0, bound: usize @8 }.
    types.add(
        RX_SEMAPHORE,
        TypeDef::Struct {
            name: rx_semn,
            size: 16,
            members: vec![m(permitsn, U64, 0), m(boundn, U64, 8)],
        },
    );
    // ArcInner { strong: usize @0, weak: usize @8, data: RxChan @16 }.
    types.add(
        ARC_INNER,
        TypeDef::Struct {
            name: arc_innern,
            size: 56,
            members: vec![m(strongn, U64, 0), m(weakn, U64, 8), m(datan, RX_CHAN, 16)],
        },
    );
    types.add(
        ARC_INNER_PTR,
        TypeDef::Pointer {
            name: None,
            target: ARC_INNER,
        },
    );
    // Receiver { chan: *ArcInner @0 } (Rx/Arc/NonNull collapsed to the
    // single raw pointer the format actually navigates to).
    types.add(
        RECEIVER,
        TypeDef::Struct {
            name: receivern,
            size: 8,
            members: vec![m(chanfieldn, ARC_INNER_PTR, 0)],
        },
    );
    // bounded::Semaphore { semaphore: batch Semaphore @0, bound @48 }.
    types.add(
        BOUNDED_SEM,
        TypeDef::Struct {
            name: rx_semn,
            size: 56,
            members: vec![m(semfieldn, BSEM_INNER, 0), m(boundn, U64, 48)],
        },
    );
    // batch_semaphore::Semaphore { waiters: Mutex @0, permits @40 }.
    types.add(
        BSEM_INNER,
        TypeDef::Struct {
            name: semaphoren,
            size: 48,
            members: vec![m(waitersn, BSEM_MUTEX, 0), m(permitsn, U64, 40)],
        },
    );
    // Mutex { raw: RawMutex @0, data: Waitlist @8 } (the loom/UnsafeCell
    // wrappers the detector navigates are collapsed here — reify only
    // needs the resolved offsets).
    types.add(
        BSEM_MUTEX,
        TypeDef::Struct {
            name: bsem_mutexn,
            size: 40,
            members: vec![m(rawn, RAW_MUTEX, 0), m(datan, BSEM_WAITLIST, 8)],
        },
    );
    // Waitlist { queue: LinkedList @0, closed: bool @24 }.
    types.add(
        BSEM_WAITLIST,
        TypeDef::Struct {
            name: bsem_waitlistn,
            size: 32,
            members: vec![m(queuen, BSEM_LIST, 0), m(closedn, BOOL, 24)],
        },
    );
    // LinkedList { head: *Waiter @0, tail: *Waiter @8 }.
    types.add(
        BSEM_LIST,
        TypeDef::Struct {
            name: bsem_listn,
            size: 16,
            members: vec![m(headn, WAITER_PTR, 0), m(tailn, WAITER_PTR, 8)],
        },
    );
    // Waiter { state: usize @0 (permits needed), next: *Waiter @8,
    // waker: Option<Waker> @16 }.
    types.add(
        WAITER,
        TypeDef::Struct {
            name: waitern,
            size: 32,
            members: vec![
                m(staten, U64, 0),
                m(nextn, WAITER_PTR, 8),
                m(wakern, OPT_WAKER, 16),
            ],
        },
    );
    types.add(
        WAITER_PTR,
        TypeDef::Pointer {
            name: None,
            target: WAITER,
        },
    );
    // Notify's waiter mutex: Mutex { raw: RawMutex @0, data: LinkedList
    // @8 } (loom/UnsafeCell wrappers collapsed; unlike the batch
    // semaphore there is no Waitlist — the mutex guards the list directly).
    types.add(
        NOTIFY_MUTEX,
        TypeDef::Struct {
            name: notify_mutexn,
            size: 24,
            members: vec![m(rawn, RAW_MUTEX, 0), m(datan, NOTIFY_LIST, 8)],
        },
    );
    // LinkedList { head: *Waiter @0, tail: *Waiter @8 }.
    types.add(
        NOTIFY_LIST,
        TypeDef::Struct {
            name: notify_listn,
            size: 16,
            members: vec![
                m(headn, NOTIFY_WAITER_PTR, 0),
                m(tailn, NOTIFY_WAITER_PTR, 8),
            ],
        },
    );
    // Waiter { notification: usize @0, next: *Waiter @8,
    // waker: Option<Waker> @16 }.
    types.add(
        NOTIFY_WAITER,
        TypeDef::Struct {
            name: notify_waitern,
            size: 32,
            members: vec![
                m(notificationn, U64, 0),
                m(nextn, NOTIFY_WAITER_PTR, 8),
                m(wakern, OPT_WAKER, 16),
            ],
        },
    );
    types.add(
        NOTIFY_WAITER_PTR,
        TypeDef::Pointer {
            name: None,
            target: NOTIFY_WAITER,
        },
    );
    // &[u32] { data_ptr: *u8 @0, length: usize @8 } — a `(ptr, len)`
    // fat pointer with no capacity (the byte-erased pointer mirrors the
    // `Vec` type above; reify reads the pointer word regardless).
    types.add(
        SLICE,
        TypeDef::Struct {
            name: slicen,
            size: 16,
            members: vec![m(data_ptrn, U8_PTR, 0), m(length2n, U64, 8)],
        },
    );
    // watch::Receiver { shared: *ArcInner @0, version: usize @8 }.
    types.add(
        WATCH_RECEIVER,
        TypeDef::Struct {
            name: watch_receivern,
            size: 16,
            members: vec![m(sharedn, WATCH_ARC_INNER_PTR, 0), m(versionl, U64, 8)],
        },
    );
    // ArcInner { strong, weak, data: Shared<u32> }.
    types.add(
        WATCH_ARC_INNER,
        TypeDef::Struct {
            name: watch_arc_innern,
            size: 32,
            members: vec![
                m(strongn, U64, 0),
                m(weakn, U64, 8),
                m(datan, WATCH_SHARED, 16),
            ],
        },
    );
    types.add(
        WATCH_ARC_INNER_PTR,
        TypeDef::Pointer {
            name: None,
            target: WATCH_ARC_INNER,
        },
    );
    // The real Shared is much larger; only these two selector targets
    // matter to the resolved WatchReceiver node.
    types.add(
        WATCH_SHARED,
        TypeDef::Struct {
            name: watch_sharedn,
            size: 16,
            members: vec![m(staten, U64, 0), m(valuen, U32, 8)],
        },
    );
    // A two-field tuple struct: `Pair(u32, u32)`, fields `__0`/`__1`.
    types.add(
        PAIR,
        TypeDef::Struct {
            name: pairn,
            size: 8,
            members: vec![m(tuple0n, U32, 0), m(tuple1n, U32, 4)],
        },
    );
    // f32 @76, f64 @77 — the only `Encoding::Float` types in the fixture.
    types.add(
        F32,
        TypeDef::Base {
            name: f32n,
            size: 4,
            encoding: Encoding::Float,
        },
    );
    types.add(
        F64,
        TypeDef::Base {
            name: f64n,
            size: 8,
            encoding: Encoding::Float,
        },
    );
    // i8 @78 .. i64 @81 — every width the signed branch has a case for.
    types.add(
        I8,
        TypeDef::Base {
            name: i8n,
            size: 1,
            encoding: Encoding::Signed,
        },
    );
    types.add(
        I16,
        TypeDef::Base {
            name: i16n,
            size: 2,
            encoding: Encoding::Signed,
        },
    );
    types.add(
        I32,
        TypeDef::Base {
            name: i32n,
            size: 4,
            encoding: Encoding::Signed,
        },
    );
    types.add(
        I64,
        TypeDef::Base {
            name: i64n,
            size: 8,
            encoding: Encoding::Signed,
        },
    );
    // char @82 — a 4-byte Rust `char`.
    types.add(
        CHAR,
        TypeDef::Base {
            name: charn,
            size: 4,
            encoding: Encoding::UtfChar,
        },
    );
    // u24 @83 — a width with no case in the integer branch, so it falls
    // back to a hex dump.
    types.add(
        U24,
        TypeDef::Base {
            name: u24n,
            size: 3,
            encoding: Encoding::Unsigned,
        },
    );
    // Color @84 — a C-style enumeration over u32.
    types.add(
        COLOR,
        TypeDef::CEnum {
            name: colorn,
            size: 4,
            repr: U32,
            enumerators: vec![(redn, 0), (greenn, 1)],
        },
    );
    // Val @85 — a union of the two 8-byte reads of one word.
    types.add(
        VAL_UNION,
        TypeDef::Union {
            name: val_unionn,
            size: 8,
            members: vec![m(intn, U64, 0), m(floatn, F64, 0)],
        },
    );
    // Unmodelled @86 — an opaque the extractor could not model, but whose
    // size is known (the `<unresolved>` opaque above has none, so it is a
    // zero-sized type and never reaches the opaque display arm).
    types.add(
        UNMODELLED,
        TypeDef::Opaque {
            name: unmodelledn,
            size: Some(4),
        },
    );
    // u16 @87 and `[u16; 2]` @88 -- the one integer width the other
    // fixture types leave without a case, plain and in an array.
    types.add(
        U16,
        TypeDef::Base {
            name: u16n,
            size: 2,
            encoding: Encoding::Unsigned,
        },
    );
    types.add(
        U16_ARR,
        TypeDef::Array {
            elem: U16,
            count: 2,
        },
    );
    types.add(
        UUID_BYTES,
        TypeDef::Array {
            elem: U8,
            count: 16,
        },
    );
    types.add(
        UUID,
        TypeDef::Struct {
            name: uuidn,
            size: 16,
            members: vec![m(uuid_bytesn, UUID_BYTES, 0)],
        },
    );
    types.add(
        HASH_BYTES,
        TypeDef::Array {
            elem: U8,
            count: 32,
        },
    );
    types.add(
        HASH,
        TypeDef::Struct {
            name: hashn,
            size: 32,
            members: vec![m(uuid_bytesn, HASH_BYTES, 0)],
        },
    );
    // The waker a parked waiter registered, shaped the way std lays it out:
    // `Option<Waker>` niched on the RawWaker's vtable word (0 = None), the
    // Waker a single-member wrapper of RawWaker { vtable @0, data @8 }, and
    // `data` a pointer to the zero-sized `()` so it renders as its address.
    types.add(
        UNIT_PTR,
        TypeDef::Pointer {
            name: None,
            target: UNIT,
        },
    );
    types.add(
        WAKER_VTABLE_PTR,
        TypeDef::Pointer {
            name: None,
            target: RAW_WAKER_VTABLE,
        },
    );
    types.add(
        TASK_RAW_WAKER,
        TypeDef::Struct {
            name: task_raw_wakern,
            size: 16,
            members: vec![m(vtablen, WAKER_VTABLE_PTR, 0), m(datan, UNIT_PTR, 8)],
        },
    );
    types.add(
        TASK_WAKER,
        TypeDef::Struct {
            name: task_wakern,
            size: 16,
            members: vec![m(wakern, TASK_RAW_WAKER, 0)],
        },
    );
    types.add(
        OPT_WAKER,
        TypeDef::Enum {
            name: opt_wakern,
            size: 16,
            shape: VariantShape {
                discr: Some(DiscrDef { offset: 0, ty: U64 }),
                variants: vec![
                    VariantDef {
                        name: nonen,
                        discr_values: tag(0),
                        payload: m(nonen, UNIT, 0),
                        decl: None,
                        await_site: None,
                    },
                    VariantDef {
                        name: somen,
                        discr_values: None,
                        payload: m(somen, TASK_WAKER, 0),
                        decl: None,
                        await_site: None,
                    },
                ],
            },
        },
    );
    // MsgWrap { msg: Msg @0 } — a struct a variant-stepped selector starts
    // from, since a display program attaches to the wrapper rather than the
    // enum itself.
    types.add(
        MSG_WRAP,
        TypeDef::Struct {
            name: msg_wrapn,
            size: 16,
            members: vec![m(msgn2, MSG, 0)],
        },
    );
    types.add(
        MSG_WRAP_PTR,
        TypeDef::Pointer {
            name: None,
            target: MSG_WRAP,
        },
    );
    // GuardOuter { wrap: *MsgWrap @0, opt: Opt @8 } — reaches a tagged enum
    // across a pointer (a segment-1 guard) and a niche enum inline (a
    // segment-0 guard).
    types.add(
        GUARD_OUTER,
        TypeDef::Struct {
            name: guard_outern,
            size: 16,
            members: vec![m(wrapn2, MSG_WRAP_PTR, 0), m(optn2, OPT, 8)],
        },
    );
    // Big { tail: u32 @0x10000 } — a member whose offset does not fit in
    // sixteen bits, which member slicing must reach without truncating.
    types.add(
        BIG,
        TypeDef::Struct {
            name: bign,
            size: 0x10004,
            members: vec![m(tailn, U32, 0x10000)],
        },
    );
    let types = types.finish();

    // Field labels for the node-based `BoundedSemaphore` formatter (deduped
    // by the interner, so re-interning existing strings is harmless).
    let (mutexfl, closedfl, permitsfl, boundfl, queuefl, permits_neededfl) = (
        s("mutex"),
        s("closed"),
        s("permits"),
        s("bound"),
        s("queue"),
        s("permits_needed"),
    );
    let (queuedl, capacityl, freel) = (s("queued"), s("capacity"), s("free"));
    // watch::Receiver, composed from Variant + ValueExpr: the state/value
    // words live in `Shared<T>` reached across the `Arc` (shared ptr @0 ->
    // deref -> data @2 -> state @0 / value @1). closed is state & 1; unseen
    // is `version @1 != state & !1` (the published version).
    let (unseenl, some_arml, none_arml, false_arml, true_arml) =
        (s("unseen"), s("Some"), s("None"), s("false"), s("true"));
    let watch_cross = |tail: u32| {
        Selector(vec![
            Step::Member(MemberRef::Index(0)),
            Step::Deref,
            Step::Member(MemberRef::Index(2)),
            Step::Member(MemberRef::Index(tail)),
        ])
    };
    let watch_state_sel = watch_cross(0);
    let watch_receiver_node = BundleNode::Struct {
        fields: vec![
            fsynth(
                unseenl,
                BundleNode::Variant {
                    discriminant: ValueExpr::Ne(
                        Box::new(ValueExpr::Read(sel(&[1]))),
                        Box::new(ValueExpr::And(
                            Box::new(ValueExpr::Read(watch_state_sel.clone())),
                            Box::new(ValueExpr::Not(Box::new(ValueExpr::Const(1)))),
                        )),
                    ),
                    arms: vec![
                        Arm {
                            value: 0,
                            label: Some(none_arml),
                            payload: None,
                        },
                        Arm {
                            value: 1,
                            label: Some(some_arml),
                            payload: Some(Box::new(BundleNode::Alias {
                                at: watch_cross(1),
                                follow_pointers: true,
                            })),
                        },
                    ],
                    default: None,
                },
            ),
            fsynth(
                closedfl,
                BundleNode::Variant {
                    discriminant: ValueExpr::And(
                        Box::new(ValueExpr::Read(watch_state_sel)),
                        Box::new(ValueExpr::Const(1)),
                    ),
                    arms: vec![
                        Arm {
                            value: 0,
                            label: Some(false_arml),
                            payload: None,
                        },
                        Arm {
                            value: 1,
                            label: Some(true_arml),
                            payload: None,
                        },
                    ],
                    default: None,
                },
            ),
        ],
    };
    // A channel's synthetic `queued` field: the block-chain walk as a
    // CustomList (see `chan_queued_node`). Reused by the standalone Chan and
    // the Receiver.
    let chan_queued = || fsynth(queuedl, chan_queued_node(U32));
    let emptyl = s("");
    let bool_decode =
        || BundleScalarDecode::Bits(vec![ebf(emptyl, 0, 0, vec![(0, falsel), (1, truel)])]);

    let mut b = Bundle {
        meta: Meta {
            format_version: FORMAT_VERSION,
            ..Default::default()
        },
        strings: strings.finish(),
        types: TypeTable {
            types,
            debug_formats: std::collections::BTreeMap::from([
                (
                    WRAP,
                    BundleNode::Alias {
                        at: sel(&[0]),
                        follow_pointers: true,
                    },
                ),
                (
                    ATOMIC,
                    BundleNode::Alias {
                        at: sel(&[0, 0]),
                        follow_pointers: false,
                    },
                ),
                (
                    ATOMIC_PTR,
                    BundleNode::Alias {
                        at: sel(&[0]),
                        follow_pointers: false,
                    },
                ),
                (
                    LOOM_ATOMIC,
                    BundleNode::Alias {
                        at: sel(&[0]),
                        follow_pointers: true,
                    },
                ),
                (
                    LOOM_CELL,
                    BundleNode::Alias {
                        at: sel(&[0]),
                        follow_pointers: true,
                    },
                ),
                (
                    FAT_PTR,
                    BundleNode::DynPointer {
                        pointer: sel(&[0]),
                        vtable: sel(&[1]),
                        drop_in_place: 0,
                        size: 1,
                        align: 2,
                        tail_offset: 0,
                    },
                ),
                (
                    RAW_WAKER_VTABLE,
                    BundleNode::Struct {
                        fields: vec![
                            fcomputed(0, BundleNode::Symbol { at: sel(&[0]) }),
                            fcomputed(1, BundleNode::Symbol { at: sel(&[1]) }),
                            fcomputed(2, BundleNode::Symbol { at: sel(&[2]) }),
                            fcomputed(3, BundleNode::Symbol { at: sel(&[3]) }),
                        ],
                    },
                ),
                (FUNCTION_PTR, BundleNode::Symbol { at: sel(&[]) }),
                (
                    BTREE_MAP,
                    BundleNode::Map {
                        length: sel(&[1]),
                        key: U32,
                        value: U32,
                        entries: Box::new(BundleMapEntries::BTree {
                            root: sel(&[0]),
                            root_node: sel(&[]),
                            height: sel(&[1]),
                            node: sel(&[0]),
                            leaf: BTREE_LEAF,
                            leaf_len: sel(&[0]),
                            leaf_keys: sel(&[1]),
                            leaf_values: sel(&[2]),
                            internal: BTREE_INTERNAL,
                            internal_data: sel(&[0]),
                            internal_edges: sel(&[1]),
                            edge: sel(&[]),
                        }),
                    },
                ),
                (
                    IPV4,
                    BundleNode::Bytes {
                        at: sel(&[0]),
                        notation: Notation::IpAddr,
                    },
                ),
                (
                    IPV6,
                    BundleNode::Bytes {
                        at: sel(&[0]),
                        notation: Notation::IpAddr,
                    },
                ),
                (
                    UUID,
                    BundleNode::Bytes {
                        at: sel(&[0]),
                        notation: Notation::Uuid,
                    },
                ),
                (
                    HASH,
                    BundleNode::Bytes {
                        at: sel(&[0]),
                        notation: Notation::Hex,
                    },
                ),
                (
                    VEC,
                    BundleNode::Slice {
                        pointer: sel(&[0]),
                        length: sel(&[1]),
                        capacity: Some(sel(&[2])),
                        element: U32,
                    },
                ),
                (
                    SLICE,
                    BundleNode::Slice {
                        pointer: sel(&[0]),
                        length: sel(&[1]),
                        capacity: None,
                        element: U32,
                    },
                ),
                (
                    STR,
                    BundleNode::Str {
                        pointer: sel(&[0]),
                        length: sel(&[1]),
                        capacity: None,
                    },
                ),
                (
                    STRING,
                    BundleNode::Str {
                        pointer: sel(&[0]),
                        length: sel(&[1]),
                        capacity: Some(sel(&[2])),
                    },
                ),
                (
                    RAW_MUTEX,
                    BundleNode::Scalar {
                        at: sel(&[0]),
                        decode: mutex_decode(),
                    },
                ),
                // The way the real emission renders a Waker: the RawWaker's
                // `data` word alone, addressed by name and not followed. The
                // RawWaker carries the same reduction, since peeling an enum
                // payload dissolves the Waker wrapper into it.
                (
                    TASK_WAKER,
                    BundleNode::Alias {
                        at: nsel(&[wakern, datan]),
                        follow_pointers: false,
                    },
                ),
                (
                    TASK_RAW_WAKER,
                    BundleNode::Alias {
                        at: nsel(&[datan]),
                        follow_pointers: false,
                    },
                ),
                (
                    NOTIFY,
                    BundleNode::Struct {
                        fields: vec![
                            fsynth(
                                statel,
                                BundleNode::Scalar {
                                    at: sel(&[0]),
                                    decode: BundleScalarDecode::Bits(vec![
                                        ebf(
                                            statel,
                                            0,
                                            2,
                                            vec![(0, idlel), (1, waitingl), (2, notifiedl)],
                                        ),
                                        ubf(generationl, 2),
                                    ]),
                                },
                            ),
                            fsynth(
                                mutexfl,
                                BundleNode::Scalar {
                                    at: sel(&[1, 0, 0]),
                                    decode: mutex_decode(),
                                },
                            ),
                            fsynth(
                                queuefl,
                                BundleNode::List {
                                    head: sel(&[1, 1, 0]),
                                    next: sel(&[1]),
                                    node: Box::new(BundleNode::Struct {
                                        fields: vec![
                                            fsynth(
                                                notificationn,
                                                BundleNode::Scalar {
                                                    at: sel(&[0]),
                                                    decode: BundleScalarDecode::Bits(vec![
                                                        ebf(
                                                            kindl,
                                                            0,
                                                            2,
                                                            vec![(0, nonel), (1, onel), (2, alll)],
                                                        ),
                                                        ebf(
                                                            orderl,
                                                            2,
                                                            1,
                                                            vec![(0, fifol), (1, lifol)],
                                                        ),
                                                    ]),
                                                },
                                            ),
                                            BundleField::member(MemberRef::Named(wakern)),
                                        ],
                                    }),
                                    node_ty: NOTIFY_WAITER,
                                },
                            ),
                        ],
                    },
                ),
                (
                    SEMAPHORE,
                    BundleNode::Struct {
                        fields: vec![
                            fcomputed(
                                0,
                                BundleNode::Scalar {
                                    at: sel(&[0]),
                                    decode: semaphore_permits_decode(),
                                },
                            ),
                            fmember(1),
                        ],
                    },
                ),
                (
                    BLOCK,
                    BundleNode::Struct {
                        fields: vec![
                            fcomputed(
                                0,
                                BundleNode::SlotCount {
                                    bitmap: sel(&[1, 0]),
                                    slots: sel(&[0]),
                                },
                            ),
                            fmember(1),
                        ],
                    },
                ),
                (
                    WATCH_STATE,
                    BundleNode::Scalar {
                        at: sel(&[0]),
                        decode: BundleScalarDecode::Bits(vec![
                            ebf(closedl, 0, 1, vec![(0, falsel), (1, truel)]),
                            ubf(versionl, 1),
                        ]),
                    },
                ),
                (
                    // Chan: `queued` then its three members (tail, index, head).
                    CHAN,
                    BundleNode::Struct {
                        fields: vec![chan_queued(), fmember(0), fmember(1), fmember(2)],
                    },
                ),
                (
                    // RxChan: like Chan plus the bounded semaphore (member 3).
                    RX_CHAN,
                    BundleNode::Struct {
                        fields: vec![
                            chan_queued(),
                            fmember(0),
                            fmember(1),
                            fmember(2),
                            fmember(3),
                        ],
                    },
                ),
                (
                    // Receiver: a pointer hop to the RxChan (raw pointer @
                    // member 0; ArcInner → `data` @ member 2), rendered as
                    // the RxChan's own struct with `capacity`/`free` decoded
                    // from its semaphore (member 3: bound @1, permits @0)
                    // prepended.
                    RECEIVER,
                    BundleNode::Pointer {
                        at: sel(&[0]),
                        via: sel(&[2]),
                        then: Box::new(BundleNode::Struct {
                            fields: vec![
                                fsynth(
                                    capacityl,
                                    BundleNode::Scalar {
                                        at: sel(&[3, 1]),
                                        decode: BundleScalarDecode::Raw,
                                    },
                                ),
                                fsynth(
                                    freel,
                                    BundleNode::Scalar {
                                        at: sel(&[3, 0]),
                                        decode: semaphore_permits_decode(),
                                    },
                                ),
                                chan_queued(),
                                fmember(0),
                                fmember(1),
                                fmember(2),
                                fmember(3),
                            ],
                        }),
                    },
                ),
                (
                    BOUNDED_SEM,
                    BundleNode::Struct {
                        fields: vec![
                            fsynth(
                                mutexfl,
                                BundleNode::Scalar {
                                    at: sel(&[0, 0, 0, 0]),
                                    decode: mutex_decode(),
                                },
                            ),
                            fsynth(
                                closedfl,
                                BundleNode::Scalar {
                                    at: sel(&[0, 0, 1, 1]),
                                    decode: bool_decode(),
                                },
                            ),
                            fsynth(
                                permitsfl,
                                BundleNode::Scalar {
                                    at: sel(&[0, 1]),
                                    decode: semaphore_permits_decode(),
                                },
                            ),
                            fsynth(
                                boundfl,
                                BundleNode::Scalar {
                                    at: sel(&[1]),
                                    decode: BundleScalarDecode::Raw,
                                },
                            ),
                            fsynth(
                                queuefl,
                                BundleNode::List {
                                    head: sel(&[0, 0, 1, 0, 0]),
                                    next: sel(&[1]),
                                    node: Box::new(BundleNode::Struct {
                                        fields: vec![
                                            fsynth(
                                                permits_neededfl,
                                                BundleNode::Scalar {
                                                    at: sel(&[0]),
                                                    decode: BundleScalarDecode::Raw,
                                                },
                                            ),
                                            BundleField::member(MemberRef::Named(wakern)),
                                        ],
                                    }),
                                    node_ty: WAITER,
                                },
                            ),
                        ],
                    },
                ),
                (WATCH_RECEIVER, watch_receiver_node),
            ]),
            name_index: vec![(pointn, POINT)],
            ..Default::default()
        },
        tasks: TaskTable::default(),
        dyn_futures: DynFutureTable::default(),
        statics: StaticsTable::default(),
        walks: WalksTable::default(),
        infra: InfraTypes {
            header: U32,
            vtable: U32,
            trailer: U32,
            context: U32,
            scheduler_handle: U32,
            mt_handle: U32,
            location: U32,
            raw_waker_vtable: RAW_WAKER_VTABLE,
        },
        provenance: ProvenanceTable::default(),
    };
    b.types.build_normalized_index(&b.strings);
    b.validate().expect("test bundle must validate");
    b
}

// -----------------------------------------------------------------------
// Formatter IR (`DisplayNode`) scaffolding
// -----------------------------------------------------------------------

// Type ids for [`node_bundle`], dense from zero into its own type table.
fixture_ids! {
    N_U32, N_U64, N_U8, N_POINT, N_WAITER, N_WAITER_PTR,
    N_THING,
    // A one-byte struct whose whole format is a `Variant` with arms for 0 and
    // 1 and no default -- the only way to reach an unmatched discriminant,
    // which every other `Variant` in these fixtures computes a boolean for.
    N_CHOICE,
    // A struct whose whole format is `Elided`: it has a real member so the
    // ugly path has structure to show, and the formatted path must not
    // read it.
    N_LOGGER,
}

/// A self-contained bundle whose sole formatter is a [`BundleNode`] tree,
/// exercising every scaffolded node kind and field kind at once:
///
/// ```text
/// Thing {
///   state: <Scalar Bits>          // Synth field
///   flag:  <Scalar Raw>           // Member field with a computed value
///   point: Point { x, y }         // Member field (structural recursion)
///   queue: [Waiter { notification: <Scalar Bits> }, …]   // List of Struct
/// }
/// ```
///
/// Built separately from [`test_bundle`] so its layout can't perturb the
/// other tests' shared fixtures.
pub fn node_bundle() -> Bundle {
    let mut strings = StringInterner::new();
    let mut s = |name: &str| strings.intern(name);

    let (u32n, u64n, u8n) = (s("u32"), s("u64"), s("u8"));
    let (pointn, xn, yn) = (s("Point"), s("x"), s("y"));
    let (thingn, staten, flagn, pointfn, headn) =
        (s("Thing"), s("state"), s("flag"), s("point"), s("head"));
    let (waitern, notifn, nextn) = (s("Waiter"), s("notification"), s("next"));
    let (statel, idlel, waitingl, notifiedl, genl) = (
        s("state"),
        s("idle"),
        s("waiting"),
        s("notified"),
        s("generation"),
    );
    let (kindl, nonel, onel, alll, orderl, fifol, lifol) = (
        s("kind"),
        s("none"),
        s("one"),
        s("all"),
        s("order"),
        s("fifo"),
        s("lifo"),
    );
    let queuel = s("queue");
    let (choicen, tagn) = (s("Choice"), s("tag"));
    let (loggern, drainn) = (s("Logger"), s("drain"));

    let m = |name, ty, offset| MemberDef { name, ty, offset };

    let mut types = FixtureTypes::default();
    types.add(
        N_U32,
        TypeDef::Base {
            name: u32n,
            size: 4,
            encoding: Encoding::Unsigned,
        },
    );
    types.add(
        N_U64,
        TypeDef::Base {
            name: u64n,
            size: 8,
            encoding: Encoding::Unsigned,
        },
    );
    types.add(
        N_U8,
        TypeDef::Base {
            name: u8n,
            size: 1,
            encoding: Encoding::Unsigned,
        },
    );
    types.add(
        N_POINT,
        TypeDef::Struct {
            name: pointn,
            size: 8,
            members: vec![m(xn, N_U32, 0), m(yn, N_U32, 4)],
        },
    );
    types.add(
        N_WAITER,
        TypeDef::Struct {
            name: waitern,
            size: 16,
            members: vec![m(notifn, N_U64, 0), m(nextn, N_WAITER_PTR, 8)],
        },
    );
    types.add(
        N_WAITER_PTR,
        TypeDef::Pointer {
            name: None,
            target: N_WAITER,
        },
    );
    types.add(
        N_THING,
        TypeDef::Struct {
            name: thingn,
            size: 28,
            members: vec![
                m(staten, N_U64, 0),
                m(flagn, N_U8, 8),
                m(pointfn, N_POINT, 12),
                m(headn, N_WAITER_PTR, 20),
            ],
        },
    );
    // Choice { tag: u8 @0 } -- id 7.
    types.add(
        N_CHOICE,
        TypeDef::Struct {
            name: choicen,
            size: 1,
            members: vec![m(tagn, N_U8, 0)],
        },
    );
    types.add(
        N_LOGGER,
        TypeDef::Struct {
            name: loggern,
            size: 8,
            members: vec![m(drainn, N_U64, 0)],
        },
    );
    let types = types.finish();

    let state_decode = BundleScalarDecode::Bits(vec![
        ebf(
            statel,
            0,
            2,
            vec![(0, idlel), (1, waitingl), (2, notifiedl)],
        ),
        ubf(genl, 2),
    ]);
    let notif_decode = BundleScalarDecode::Bits(vec![
        ebf(kindl, 0, 2, vec![(0, nonel), (1, onel), (2, alll)]),
        ebf(orderl, 2, 1, vec![(0, fifol), (1, lifol)]),
    ]);

    let waiter_node = BundleNode::Struct {
        fields: vec![fsynth(
            notifn,
            BundleNode::Scalar {
                at: sel(&[0]),
                decode: notif_decode,
            },
        )],
    };
    let thing_node = BundleNode::Struct {
        fields: vec![
            fsynth(
                staten,
                BundleNode::Scalar {
                    at: sel(&[0]),
                    decode: state_decode,
                },
            ),
            // `flag` is reached by name, both as the field and inside the
            // node, where the rest of the fixture uses positions: the two
            // addressings must render identically.
            fcomputed_named(
                flagn,
                BundleNode::Scalar {
                    at: nsel(&[flagn]),
                    decode: BundleScalarDecode::Raw,
                },
            ),
            fmember(2),
            fsynth(
                queuel,
                BundleNode::List {
                    head: nsel(&[headn]),
                    next: sel(&[1]),
                    node: Box::new(waiter_node),
                    node_ty: N_WAITER,
                },
            ),
        ],
    };

    let choice_node = BundleNode::Variant {
        discriminant: ValueExpr::Read(sel(&[0])),
        arms: vec![
            Arm {
                value: 0,
                label: Some(nonel),
                payload: None,
            },
            Arm {
                value: 1,
                label: Some(onel),
                payload: None,
            },
        ],
        default: None,
    };

    let mut b = Bundle {
        meta: Meta {
            format_version: FORMAT_VERSION,
            ..Default::default()
        },
        strings: strings.finish(),
        types: TypeTable {
            types,
            debug_formats: std::collections::BTreeMap::from([
                (N_THING, thing_node),
                (N_CHOICE, choice_node),
                (N_LOGGER, BundleNode::Elided),
            ]),
            name_index: vec![],
            ..Default::default()
        },
        tasks: TaskTable::default(),
        dyn_futures: DynFutureTable::default(),
        statics: StaticsTable::default(),
        walks: WalksTable::default(),
        infra: InfraTypes {
            header: N_U32,
            vtable: N_U32,
            trailer: N_U32,
            context: N_U32,
            scheduler_handle: N_U32,
            mt_handle: N_U32,
            location: N_U32,
            raw_waker_vtable: N_U32,
        },
        provenance: ProvenanceTable::default(),
    };
    b.types.build_normalized_index(&b.strings);
    b.validate().expect("node bundle must validate");
    b
}

/// Lay out a `Thing` value's 28 bytes. `head` is the queue head word.
pub fn thing_bytes(state: u64, flag: u8, x: u32, y: u32, head: u64) -> Vec<u8> {
    let mut bytes = vec![0u8; 28];
    bytes[0..8].copy_from_slice(&state.to_le_bytes());
    bytes[8] = flag;
    bytes[12..16].copy_from_slice(&x.to_le_bytes());
    bytes[16..20].copy_from_slice(&y.to_le_bytes());
    bytes[20..28].copy_from_slice(&head.to_le_bytes());
    bytes
}

/// Lay out a `Waiter` node's 16 bytes: notification word + successor.
pub fn waiter_bytes(notification: u64, next: u64) -> Vec<u8> {
    let mut bytes = vec![0u8; 16];
    bytes[0..8].copy_from_slice(&notification.to_le_bytes());
    bytes[8..16].copy_from_slice(&next.to_le_bytes());
    bytes
}
