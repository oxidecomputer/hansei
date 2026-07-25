//! The synthetic bundle shared by reify's tests.
//!
//! Hand-built rather than extracted: it pins the exact type graph the tests
//! need, so a render assertion cannot drift because an extractor changed what
//! it emits.

use exegesis::Encoding;
use exegesis::bundle::{
    Arm, BitField as BundleBitField, Bundle, BundleTypeId, DiscrDef, DiscrValue, DiscrValues,
    DisplayNode as BundleNode, DynFutureTable, FORMAT_VERSION, Field as BundleField,
    FieldRender as BundleFieldRender, InfraTypes, MapEntries as BundleMapEntries, MemberDef, Meta,
    ProvenanceTable, ScalarDecode as BundleScalarDecode, Selector, StaticsTable, Step,
    Stmt as BundleStmt, StrRef, StringInterner, TaskTable, TypeDef, TypeTable, ValueExpr,
    VariantDef, VariantShape,
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
}

impl crate::ReadFromProc for FakeMem {
    fn read_bytes(&self, addr: u64, len: u64) -> crate::Result<Vec<u8>> {
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
                return Ok(bytes[start..end].to_vec());
            }
        }
        match self.unmapped {
            Unmapped::Fail => Err(crate::Error::invalid_addr(addr)),
            Unmapped::Panic => panic!("unexpected read of {len} bytes at {addr:#x}"),
        }
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
/// @8 }` -- padded to the 32 bytes the fixture's waiter types declare, so a
/// read of any prefix is served.
pub fn sync_waiter(state: u64, next: u64) -> Vec<u8> {
    let mut bytes = vec![0u8; 32];
    bytes[..8].copy_from_slice(&state.to_le_bytes());
    bytes[8..16].copy_from_slice(&next.to_le_bytes());
    bytes
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

/// Build a member-only [`Selector`] from member indices — the shape every
/// selector in these synthetic bundles has (Phase A emits no `Deref`).
pub fn sel(members: &[u32]) -> Selector {
    Selector::from(members.to_vec())
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

pub const U32: BundleTypeId = BundleTypeId(0);
pub const U64: BundleTypeId = BundleTypeId(1);
pub const BOOL: BundleTypeId = BundleTypeId(2);
pub const U8: BundleTypeId = BundleTypeId(3);
pub const UNIT: BundleTypeId = BundleTypeId(4);
pub const POINT: BundleTypeId = BundleTypeId(5);
pub const MSG: BundleTypeId = BundleTypeId(6);
pub const OPT: BundleTypeId = BundleTypeId(7);
pub const WRAP: BundleTypeId = BundleTypeId(8);
pub const PTR: BundleTypeId = BundleTypeId(9);
pub const ARR: BundleTypeId = BundleTypeId(10);
pub const NODE: BundleTypeId = BundleTypeId(11);
pub const NODE_PTR: BundleTypeId = BundleTypeId(12);
pub const VTABLE_ARRAY: BundleTypeId = BundleTypeId(13);
pub const VTABLE_PTR: BundleTypeId = BundleTypeId(14);
pub const FAT_PTR: BundleTypeId = BundleTypeId(15);
pub const ATOMIC: BundleTypeId = BundleTypeId(16);
pub const ATOMIC_STORAGE: BundleTypeId = BundleTypeId(17);
pub const ATOMIC_PTR: BundleTypeId = BundleTypeId(18);
pub const LOOM_ATOMIC: BundleTypeId = BundleTypeId(19);
pub const LOOM_CELL: BundleTypeId = BundleTypeId(20);
pub const DYN_TRAIT: BundleTypeId = BundleTypeId(21);
pub const DYN_TRAIT_PTR: BundleTypeId = BundleTypeId(22);
pub const RAW_WAKER_VTABLE: BundleTypeId = BundleTypeId(23);
pub const FUNCTION_TARGET: BundleTypeId = BundleTypeId(24);
pub const FUNCTION_PTR: BundleTypeId = BundleTypeId(25);
pub const BTREE_MAP: BundleTypeId = BundleTypeId(26);
pub const BTREE_ROOT: BundleTypeId = BundleTypeId(27);
pub const BTREE_NODE_REF: BundleTypeId = BundleTypeId(28);
pub const BTREE_LEAF_PTR: BundleTypeId = BundleTypeId(29);
pub const BTREE_LEAF: BundleTypeId = BundleTypeId(30);
pub const MAYBE_U32: BundleTypeId = BundleTypeId(31);
pub const BTREE_SLOTS: BundleTypeId = BundleTypeId(32);
pub const BTREE_INTERNAL: BundleTypeId = BundleTypeId(33);
pub const BTREE_EDGES: BundleTypeId = BundleTypeId(34);
pub const IPV4_OCTETS: BundleTypeId = BundleTypeId(35);
pub const IPV4: BundleTypeId = BundleTypeId(36);
pub const IPV6_OCTETS: BundleTypeId = BundleTypeId(37);
pub const IPV6: BundleTypeId = BundleTypeId(38);
pub const U8_PTR: BundleTypeId = BundleTypeId(39);
pub const VEC: BundleTypeId = BundleTypeId(40);
pub const STR: BundleTypeId = BundleTypeId(41);
pub const STRING: BundleTypeId = BundleTypeId(42);
pub const RAW_MUTEX: BundleTypeId = BundleTypeId(43);
pub const NOTIFY: BundleTypeId = BundleTypeId(44);
pub const SEMAPHORE: BundleTypeId = BundleTypeId(45);
pub const BLOCK: BundleTypeId = BundleTypeId(46);
pub const BLOCK_VALUES: BundleTypeId = BundleTypeId(47);
pub const BLOCK_HEADER: BundleTypeId = BundleTypeId(48);
pub const WATCH_STATE: BundleTypeId = BundleTypeId(49);
pub const CHAN: BundleTypeId = BundleTypeId(50);
pub const CHAN_BLOCK: BundleTypeId = BundleTypeId(51);
pub const CHAN_BLOCK_HEADER: BundleTypeId = BundleTypeId(52);
pub const CHAN_BLOCK_PTR: BundleTypeId = BundleTypeId(53);
pub const RX_CHAN: BundleTypeId = BundleTypeId(54);
pub const RX_SEMAPHORE: BundleTypeId = BundleTypeId(55);
pub const ARC_INNER: BundleTypeId = BundleTypeId(56);
pub const ARC_INNER_PTR: BundleTypeId = BundleTypeId(57);
pub const RECEIVER: BundleTypeId = BundleTypeId(58);
pub const BOUNDED_SEM: BundleTypeId = BundleTypeId(59);
pub const BSEM_INNER: BundleTypeId = BundleTypeId(60);
pub const BSEM_MUTEX: BundleTypeId = BundleTypeId(61);
pub const BSEM_WAITLIST: BundleTypeId = BundleTypeId(62);
pub const BSEM_LIST: BundleTypeId = BundleTypeId(63);
pub const WAITER: BundleTypeId = BundleTypeId(64);
pub const WAITER_PTR: BundleTypeId = BundleTypeId(65);
pub const NOTIFY_MUTEX: BundleTypeId = BundleTypeId(66);
pub const NOTIFY_LIST: BundleTypeId = BundleTypeId(67);
pub const NOTIFY_WAITER: BundleTypeId = BundleTypeId(68);
pub const NOTIFY_WAITER_PTR: BundleTypeId = BundleTypeId(69);
pub const SLICE: BundleTypeId = BundleTypeId(70);
pub const WATCH_RECEIVER: BundleTypeId = BundleTypeId(71);
pub const WATCH_ARC_INNER: BundleTypeId = BundleTypeId(72);
pub const WATCH_ARC_INNER_PTR: BundleTypeId = BundleTypeId(73);
pub const WATCH_SHARED: BundleTypeId = BundleTypeId(74);
pub const PAIR: BundleTypeId = BundleTypeId(75);
// Base and aggregate kinds that reach a `TypeClass` arm no other fixture type
// does: the float, signed, character and odd-width integer encodings, plus a
// C enumeration, a union and a sized opaque.
pub const F32: BundleTypeId = BundleTypeId(76);
pub const F64: BundleTypeId = BundleTypeId(77);
pub const I8: BundleTypeId = BundleTypeId(78);
pub const I16: BundleTypeId = BundleTypeId(79);
pub const I32: BundleTypeId = BundleTypeId(80);
pub const I64: BundleTypeId = BundleTypeId(81);
pub const CHAR: BundleTypeId = BundleTypeId(82);
pub const U24: BundleTypeId = BundleTypeId(83);
pub const COLOR: BundleTypeId = BundleTypeId(84);
pub const VAL_UNION: BundleTypeId = BundleTypeId(85);
pub const UNMODELLED: BundleTypeId = BundleTypeId(86);
pub const U16: BundleTypeId = BundleTypeId(87);
pub const U16_ARR: BundleTypeId = BundleTypeId(88);

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

    let types = vec![
        TypeDef::Base {
            name: u32n,
            size: 4,
            encoding: Encoding::Unsigned,
        },
        TypeDef::Base {
            name: u64n,
            size: 8,
            encoding: Encoding::Unsigned,
        },
        TypeDef::Base {
            name: booln,
            size: 1,
            encoding: Encoding::Boolean,
        },
        TypeDef::Base {
            name: u8n,
            size: 1,
            encoding: Encoding::Unsigned,
        },
        TypeDef::Struct {
            name: unitn,
            size: 0,
            members: vec![],
        },
        TypeDef::Struct {
            name: pointn,
            size: 8,
            members: vec![m(xn, U32, 0), m(yn, U32, 4)],
        },
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
                    },
                    VariantDef {
                        name: bn,
                        discr_values: tag(1),
                        payload: m(bn, U64, 8),
                        decl: None,
                    },
                    VariantDef {
                        name: cn,
                        discr_values: tag(2),
                        payload: m(cn, UNIT, 8),
                        decl: None,
                    },
                ],
            },
        },
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
                    },
                    VariantDef {
                        name: somen,
                        discr_values: None,
                        payload: m(somen, U64, 0),
                        decl: None,
                    },
                ],
            },
        },
        TypeDef::Struct {
            name: wrapn,
            size: 8,
            members: vec![m(innern, POINT, 0)],
        },
        TypeDef::Pointer {
            name: None,
            target: POINT,
        },
        TypeDef::Array {
            elem: U32,
            count: 3,
        },
        TypeDef::Struct {
            name: noden,
            size: 16,
            members: vec![m(valuen, U32, 0), m(nextn, NODE_PTR, 8)],
        },
        TypeDef::Pointer {
            name: None,
            target: NODE,
        },
        TypeDef::Array {
            elem: U64,
            count: 3,
        },
        TypeDef::Pointer {
            name: None,
            target: VTABLE_ARRAY,
        },
        TypeDef::Struct {
            name: fatn,
            size: 16,
            members: vec![m(pointern, DYN_TRAIT_PTR, 0), m(vtablen, VTABLE_PTR, 8)],
        },
        TypeDef::Struct {
            name: atomicn,
            size: 4,
            members: vec![m(vn, ATOMIC_STORAGE, 0)],
        },
        TypeDef::Struct {
            name: storagen,
            size: 4,
            members: vec![m(valuen, U32, 0)],
        },
        TypeDef::Struct {
            name: atomic_ptrn,
            size: 8,
            members: vec![m(vn, PTR, 0)],
        },
        TypeDef::Struct {
            name: loom_atomicn,
            size: 4,
            members: vec![m(innern, ATOMIC, 0)],
        },
        TypeDef::Struct {
            name: loom_celln,
            size: 8,
            members: vec![m(tuple0n, WRAP, 0)],
        },
        TypeDef::Struct {
            name: dyn_traitn,
            size: 0,
            members: vec![],
        },
        TypeDef::Pointer {
            name: None,
            target: DYN_TRAIT,
        },
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
        TypeDef::Opaque {
            name: unresolvedn,
            size: None,
        },
        TypeDef::Pointer {
            name: None,
            target: FUNCTION_TARGET,
        },
        TypeDef::Struct {
            name: btree_mapn,
            size: 24,
            members: vec![m(rootn, BTREE_ROOT, 0), m(lengthn, U64, 16)],
        },
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
                    },
                    VariantDef {
                        name: some2n,
                        discr_values: None,
                        payload: m(some2n, BTREE_NODE_REF, 0),
                        decl: None,
                    },
                ],
            },
        },
        TypeDef::Struct {
            name: btree_node_refn,
            size: 16,
            members: vec![m(noden2, BTREE_LEAF_PTR, 0), m(heightn, U64, 8)],
        },
        TypeDef::Pointer {
            name: None,
            target: BTREE_LEAF,
        },
        TypeDef::Struct {
            name: btree_leafn,
            size: 20,
            members: vec![
                m(lenn, U8, 0),
                m(keysn, BTREE_SLOTS, 4),
                m(valsn, BTREE_SLOTS, 12),
            ],
        },
        TypeDef::Union {
            name: maybe_u32n,
            size: 4,
            members: vec![m(uninitn, UNIT, 0), m(valuen, U32, 0)],
        },
        TypeDef::Array {
            elem: MAYBE_U32,
            count: 2,
        },
        TypeDef::Struct {
            name: btree_internaln,
            size: 48,
            members: vec![m(datan, BTREE_LEAF, 0), m(edgesn, BTREE_EDGES, 24)],
        },
        TypeDef::Array {
            elem: BTREE_LEAF_PTR,
            count: 3,
        },
        TypeDef::Array { elem: U8, count: 4 },
        TypeDef::Struct {
            name: ipv4n,
            size: 4,
            members: vec![m(octetsn, IPV4_OCTETS, 0)],
        },
        TypeDef::Array {
            elem: U8,
            count: 16,
        },
        TypeDef::Struct {
            name: ipv6n,
            size: 16,
            members: vec![m(octetsn, IPV6_OCTETS, 0)],
        },
        TypeDef::Pointer {
            name: None,
            target: U8,
        },
        TypeDef::Struct {
            name: vecn,
            size: 24,
            members: vec![
                m(ptrn, U8_PTR, 0),
                m(vec_lenn, U64, 8),
                m(capacityn, U64, 16),
            ],
        },
        TypeDef::Struct {
            name: strn,
            size: 16,
            members: vec![m(data_ptrn, U8_PTR, 0), m(length2n, U64, 8)],
        },
        TypeDef::Struct {
            name: stringn,
            size: 24,
            members: vec![
                m(ptrn, U8_PTR, 0),
                m(vec_lenn, U64, 8),
                m(capacityn, U64, 16),
            ],
        },
        TypeDef::Struct {
            name: raw_mutexn,
            size: 1,
            members: vec![m(staten, U8, 0)],
        },
        // Notify { state: usize @0, waiters: Mutex<LinkedList<Waiter>> @8 }
        // (the loom/UnsafeCell wrappers the detector navigates are collapsed
        // here — reify only needs the resolved offsets).
        TypeDef::Struct {
            name: notifyn,
            size: 32,
            members: vec![m(staten, U64, 0), m(waitersn, NOTIFY_MUTEX, 8)],
        },
        TypeDef::Struct {
            name: semaphoren,
            size: 16,
            members: vec![m(permitsn, U64, 0), m(waitersn, U32, 8)],
        },
        TypeDef::Struct {
            name: blockn,
            size: 24,
            members: vec![
                m(valuesfieldn, BLOCK_VALUES, 0),
                m(headerfieldn, BLOCK_HEADER, 16),
            ],
        },
        TypeDef::Array {
            elem: U32,
            count: 4,
        },
        TypeDef::Struct {
            name: block_headern,
            size: 8,
            members: vec![m(ready_slotsn, U64, 0)],
        },
        TypeDef::Struct {
            name: watch_staten,
            size: 8,
            members: vec![m(tuple0n, U64, 0)],
        },
        // Chan { tail: usize @0, index: usize @8, head: *ChanBlock @16 }
        TypeDef::Struct {
            name: chann,
            size: 24,
            members: vec![
                m(tailn, U64, 0),
                m(indexn, U64, 8),
                m(headn, CHAN_BLOCK_PTR, 16),
            ],
        },
        // ChanBlock { values: [u32; 4] @0, header: ChanBlockHeader @16 }
        TypeDef::Struct {
            name: chan_blockn,
            size: 32,
            members: vec![
                m(valuesfieldn, BLOCK_VALUES, 0),
                m(headerfieldn, CHAN_BLOCK_HEADER, 16),
            ],
        },
        // ChanBlockHeader { start_index: usize @0, next: *ChanBlock @8 }
        TypeDef::Struct {
            name: chan_block_headern,
            size: 16,
            members: vec![m(start_indexn, U64, 0), m(nextn, CHAN_BLOCK_PTR, 8)],
        },
        TypeDef::Pointer {
            name: None,
            target: CHAN_BLOCK,
        },
        // RxChan: tail @0, index @8, head @16, semaphore @24 (like Chan
        // but with the bounded semaphore appended).
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
        // bounded::Semaphore { permits: usize @0, bound: usize @8 }.
        TypeDef::Struct {
            name: rx_semn,
            size: 16,
            members: vec![m(permitsn, U64, 0), m(boundn, U64, 8)],
        },
        // ArcInner { strong: usize @0, weak: usize @8, data: RxChan @16 }.
        TypeDef::Struct {
            name: arc_innern,
            size: 56,
            members: vec![m(strongn, U64, 0), m(weakn, U64, 8), m(datan, RX_CHAN, 16)],
        },
        TypeDef::Pointer {
            name: None,
            target: ARC_INNER,
        },
        // Receiver { chan: *ArcInner @0 } (Rx/Arc/NonNull collapsed to the
        // single raw pointer the format actually navigates to).
        TypeDef::Struct {
            name: receivern,
            size: 8,
            members: vec![m(chanfieldn, ARC_INNER_PTR, 0)],
        },
        // bounded::Semaphore { semaphore: batch Semaphore @0, bound @48 }.
        TypeDef::Struct {
            name: rx_semn,
            size: 56,
            members: vec![m(semfieldn, BSEM_INNER, 0), m(boundn, U64, 48)],
        },
        // batch_semaphore::Semaphore { waiters: Mutex @0, permits @40 }.
        TypeDef::Struct {
            name: semaphoren,
            size: 48,
            members: vec![m(waitersn, BSEM_MUTEX, 0), m(permitsn, U64, 40)],
        },
        // Mutex { raw: RawMutex @0, data: Waitlist @8 } (the loom/UnsafeCell
        // wrappers the detector navigates are collapsed here — reify only
        // needs the resolved offsets).
        TypeDef::Struct {
            name: bsem_mutexn,
            size: 40,
            members: vec![m(rawn, RAW_MUTEX, 0), m(datan, BSEM_WAITLIST, 8)],
        },
        // Waitlist { queue: LinkedList @0, closed: bool @24 }.
        TypeDef::Struct {
            name: bsem_waitlistn,
            size: 32,
            members: vec![m(queuen, BSEM_LIST, 0), m(closedn, BOOL, 24)],
        },
        // LinkedList { head: *Waiter @0, tail: *Waiter @8 }.
        TypeDef::Struct {
            name: bsem_listn,
            size: 16,
            members: vec![m(headn, WAITER_PTR, 0), m(tailn, WAITER_PTR, 8)],
        },
        // Waiter { state: usize @0 (permits needed), next: *Waiter @8 }.
        TypeDef::Struct {
            name: waitern,
            size: 32,
            members: vec![m(staten, U64, 0), m(nextn, WAITER_PTR, 8)],
        },
        TypeDef::Pointer {
            name: None,
            target: WAITER,
        },
        // Notify's waiter mutex: Mutex { raw: RawMutex @0, data: LinkedList
        // @8 } (loom/UnsafeCell wrappers collapsed; unlike the batch
        // semaphore there is no Waitlist — the mutex guards the list directly).
        TypeDef::Struct {
            name: notify_mutexn,
            size: 24,
            members: vec![m(rawn, RAW_MUTEX, 0), m(datan, NOTIFY_LIST, 8)],
        },
        // LinkedList { head: *Waiter @0, tail: *Waiter @8 }.
        TypeDef::Struct {
            name: notify_listn,
            size: 16,
            members: vec![
                m(headn, NOTIFY_WAITER_PTR, 0),
                m(tailn, NOTIFY_WAITER_PTR, 8),
            ],
        },
        // Waiter { notification: usize @0, next: *Waiter @8 }.
        TypeDef::Struct {
            name: notify_waitern,
            size: 32,
            members: vec![m(notificationn, U64, 0), m(nextn, NOTIFY_WAITER_PTR, 8)],
        },
        TypeDef::Pointer {
            name: None,
            target: NOTIFY_WAITER,
        },
        // &[u32] { data_ptr: *u8 @0, length: usize @8 } — a `(ptr, len)`
        // fat pointer with no capacity (the byte-erased pointer mirrors the
        // `Vec` type above; reify reads the pointer word regardless).
        TypeDef::Struct {
            name: slicen,
            size: 16,
            members: vec![m(data_ptrn, U8_PTR, 0), m(length2n, U64, 8)],
        },
        // watch::Receiver { shared: *ArcInner @0, version: usize @8 }.
        TypeDef::Struct {
            name: watch_receivern,
            size: 16,
            members: vec![m(sharedn, WATCH_ARC_INNER_PTR, 0), m(versionl, U64, 8)],
        },
        // ArcInner { strong, weak, data: Shared<u32> }.
        TypeDef::Struct {
            name: watch_arc_innern,
            size: 32,
            members: vec![
                m(strongn, U64, 0),
                m(weakn, U64, 8),
                m(datan, WATCH_SHARED, 16),
            ],
        },
        TypeDef::Pointer {
            name: None,
            target: WATCH_ARC_INNER,
        },
        // The real Shared is much larger; only these two selector targets
        // matter to the resolved WatchReceiver node.
        TypeDef::Struct {
            name: watch_sharedn,
            size: 16,
            members: vec![m(staten, U64, 0), m(valuen, U32, 8)],
        },
        // A two-field tuple struct: `Pair(u32, u32)`, fields `__0`/`__1`.
        TypeDef::Struct {
            name: pairn,
            size: 8,
            members: vec![m(tuple0n, U32, 0), m(tuple1n, U32, 4)],
        },
        // f32 @76, f64 @77 — the only `Encoding::Float` types in the fixture.
        TypeDef::Base {
            name: f32n,
            size: 4,
            encoding: Encoding::Float,
        },
        TypeDef::Base {
            name: f64n,
            size: 8,
            encoding: Encoding::Float,
        },
        // i8 @78 .. i64 @81 — every width the signed branch has a case for.
        TypeDef::Base {
            name: i8n,
            size: 1,
            encoding: Encoding::Signed,
        },
        TypeDef::Base {
            name: i16n,
            size: 2,
            encoding: Encoding::Signed,
        },
        TypeDef::Base {
            name: i32n,
            size: 4,
            encoding: Encoding::Signed,
        },
        TypeDef::Base {
            name: i64n,
            size: 8,
            encoding: Encoding::Signed,
        },
        // char @82 — a 4-byte Rust `char`.
        TypeDef::Base {
            name: charn,
            size: 4,
            encoding: Encoding::UtfChar,
        },
        // u24 @83 — a width with no case in the integer branch, so it falls
        // back to a hex dump.
        TypeDef::Base {
            name: u24n,
            size: 3,
            encoding: Encoding::Unsigned,
        },
        // Color @84 — a C-style enumeration over u32.
        TypeDef::CEnum {
            name: colorn,
            size: 4,
            repr: U32,
            enumerators: vec![(redn, 0), (greenn, 1)],
        },
        // Val @85 — a union of the two 8-byte reads of one word.
        TypeDef::Union {
            name: val_unionn,
            size: 8,
            members: vec![m(intn, U64, 0), m(floatn, F64, 0)],
        },
        // Unmodelled @86 — an opaque the extractor could not model, but whose
        // size is known (the `<unresolved>` opaque above has none, so it is a
        // zero-sized type and never reaches the opaque display arm).
        TypeDef::Opaque {
            name: unmodelledn,
            size: Some(4),
        },
        // u16 @87 and `[u16; 2]` @88 -- the one integer width the other
        // fixture types leave without a case, plain and in an array.
        TypeDef::Base {
            name: u16n,
            size: 2,
            encoding: Encoding::Unsigned,
        },
        TypeDef::Array {
            elem: U16,
            count: 2,
        },
    ];

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
            Step::Member(0),
            Step::Deref,
            Step::Member(2),
            Step::Member(tail),
        ])
    };
    let watch_state_sel = watch_cross(0);
    let watch_receiver_node = BundleNode::Struct {
        fields: vec![
            BundleField::Named {
                label: unseenl,
                node: BundleNode::Variant {
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
            },
            BundleField::Named {
                label: closedfl,
                node: BundleNode::Variant {
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
            },
        ],
    };
    // A channel's synthetic `queued` field: the block-chain walk as a
    // CustomList (see `chan_queued_node`). Reused by the standalone Chan and
    // the Receiver.
    let chan_queued = || BundleField::Named {
        label: queuedl,
        node: chan_queued_node(U32),
    };
    let emptyl = s("");
    let bool_decode =
        || BundleScalarDecode::Bits(vec![ebf(emptyl, 0, 0, vec![(0, falsel), (1, truel)])]);

    let b = Bundle {
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
                            BundleField::Override {
                                index: 0,
                                node: BundleNode::Symbol { at: sel(&[0]) },
                            },
                            BundleField::Override {
                                index: 1,
                                node: BundleNode::Symbol { at: sel(&[1]) },
                            },
                            BundleField::Override {
                                index: 2,
                                node: BundleNode::Symbol { at: sel(&[2]) },
                            },
                            BundleField::Override {
                                index: 3,
                                node: BundleNode::Symbol { at: sel(&[3]) },
                            },
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
                (IPV4, BundleNode::IpAddr { octets: sel(&[0]) }),
                (IPV6, BundleNode::IpAddr { octets: sel(&[0]) }),
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
                (
                    NOTIFY,
                    BundleNode::Struct {
                        fields: vec![
                            BundleField::Named {
                                label: statel,
                                node: BundleNode::Scalar {
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
                            },
                            BundleField::Named {
                                label: mutexfl,
                                node: BundleNode::Scalar {
                                    at: sel(&[1, 0, 0]),
                                    decode: mutex_decode(),
                                },
                            },
                            BundleField::Named {
                                label: queuefl,
                                node: BundleNode::List {
                                    head: sel(&[1, 1, 0]),
                                    next: sel(&[1]),
                                    node: Box::new(BundleNode::Struct {
                                        fields: vec![BundleField::Named {
                                            label: notificationn,
                                            node: BundleNode::Scalar {
                                                at: sel(&[0]),
                                                decode: BundleScalarDecode::Bits(vec![
                                                    ebf(
                                                        kindl,
                                                        0,
                                                        2,
                                                        vec![(0, nonel), (1, onel), (2, alll)],
                                                    ),
                                                    ebf(orderl, 2, 1, vec![(0, fifol), (1, lifol)]),
                                                ]),
                                            },
                                        }],
                                    }),
                                    node_ty: NOTIFY_WAITER,
                                },
                            },
                        ],
                    },
                ),
                (
                    SEMAPHORE,
                    BundleNode::Struct {
                        fields: vec![
                            BundleField::Override {
                                index: 0,
                                node: BundleNode::Scalar {
                                    at: sel(&[0]),
                                    decode: semaphore_permits_decode(),
                                },
                            },
                            BundleField::Member(1),
                        ],
                    },
                ),
                (
                    BLOCK,
                    BundleNode::Struct {
                        fields: vec![
                            BundleField::Override {
                                index: 0,
                                node: BundleNode::SlotCount {
                                    bitmap: sel(&[1, 0]),
                                    slots: sel(&[0]),
                                },
                            },
                            BundleField::Member(1),
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
                        fields: vec![
                            chan_queued(),
                            BundleField::Member(0),
                            BundleField::Member(1),
                            BundleField::Member(2),
                        ],
                    },
                ),
                (
                    // RxChan: like Chan plus the bounded semaphore (member 3).
                    RX_CHAN,
                    BundleNode::Struct {
                        fields: vec![
                            chan_queued(),
                            BundleField::Member(0),
                            BundleField::Member(1),
                            BundleField::Member(2),
                            BundleField::Member(3),
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
                                BundleField::Named {
                                    label: capacityl,
                                    node: BundleNode::Scalar {
                                        at: sel(&[3, 1]),
                                        decode: BundleScalarDecode::Raw,
                                    },
                                },
                                BundleField::Named {
                                    label: freel,
                                    node: BundleNode::Scalar {
                                        at: sel(&[3, 0]),
                                        decode: semaphore_permits_decode(),
                                    },
                                },
                                chan_queued(),
                                BundleField::Member(0),
                                BundleField::Member(1),
                                BundleField::Member(2),
                                BundleField::Member(3),
                            ],
                        }),
                    },
                ),
                (
                    BOUNDED_SEM,
                    BundleNode::Struct {
                        fields: vec![
                            BundleField::Named {
                                label: mutexfl,
                                node: BundleNode::Scalar {
                                    at: sel(&[0, 0, 0, 0]),
                                    decode: mutex_decode(),
                                },
                            },
                            BundleField::Named {
                                label: closedfl,
                                node: BundleNode::Scalar {
                                    at: sel(&[0, 0, 1, 1]),
                                    decode: bool_decode(),
                                },
                            },
                            BundleField::Named {
                                label: permitsfl,
                                node: BundleNode::Scalar {
                                    at: sel(&[0, 1]),
                                    decode: semaphore_permits_decode(),
                                },
                            },
                            BundleField::Named {
                                label: boundfl,
                                node: BundleNode::Scalar {
                                    at: sel(&[1]),
                                    decode: BundleScalarDecode::Raw,
                                },
                            },
                            BundleField::Named {
                                label: queuefl,
                                node: BundleNode::List {
                                    head: sel(&[0, 0, 1, 0, 0]),
                                    next: sel(&[1]),
                                    node: Box::new(BundleNode::Struct {
                                        fields: vec![BundleField::Named {
                                            label: permits_neededfl,
                                            node: BundleNode::Scalar {
                                                at: sel(&[0]),
                                                decode: BundleScalarDecode::Raw,
                                            },
                                        }],
                                    }),
                                    node_ty: WAITER,
                                },
                            },
                        ],
                    },
                ),
                (WATCH_RECEIVER, watch_receiver_node),
            ]),
            name_index: vec![(pointn, POINT)],
        },
        tasks: TaskTable::default(),
        dyn_futures: DynFutureTable::default(),
        statics: StaticsTable::default(),
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
    b.validate().expect("test bundle must validate");
    b
}

// -----------------------------------------------------------------------
// Formatter IR (`DisplayNode`) scaffolding
// -----------------------------------------------------------------------

// Type ids for [`node_bundle`], dense from zero into its own type table.
pub const N_U32: BundleTypeId = BundleTypeId(0);
pub const N_U64: BundleTypeId = BundleTypeId(1);
pub const N_U8: BundleTypeId = BundleTypeId(2);
pub const N_POINT: BundleTypeId = BundleTypeId(3);
pub const N_WAITER: BundleTypeId = BundleTypeId(4);
pub const N_WAITER_PTR: BundleTypeId = BundleTypeId(5);
pub const N_THING: BundleTypeId = BundleTypeId(6);
/// A one-byte struct whose whole format is a `Variant` with arms for 0 and 1
/// and no default -- the only way to reach an unmatched discriminant, which
/// every other `Variant` in these fixtures computes a boolean for.
pub const N_CHOICE: BundleTypeId = BundleTypeId(7);

/// A self-contained bundle whose sole formatter is a [`BundleNode`] tree,
/// exercising every scaffolded node kind and field kind at once:
///
/// ```text
/// Thing {
///   state: <Scalar Bits>          // Named field
///   flag:  <Scalar Raw>           // Override field (reuses member 1's name)
///   point: Point { x, y }         // Member field (structural recursion)
///   queue: [Waiter { notification: <Scalar Bits> }, …]   // List of Struct
/// }
/// ```
///
/// Built separately from [`test_bundle`] so its layout can't perturb the
/// other tests' shared fixtures.
pub fn node_bundle() -> Bundle {
    use BundleField::{Member, Named, Override};

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

    let m = |name, ty, offset| MemberDef { name, ty, offset };

    let types = vec![
        TypeDef::Base {
            name: u32n,
            size: 4,
            encoding: Encoding::Unsigned,
        },
        TypeDef::Base {
            name: u64n,
            size: 8,
            encoding: Encoding::Unsigned,
        },
        TypeDef::Base {
            name: u8n,
            size: 1,
            encoding: Encoding::Unsigned,
        },
        TypeDef::Struct {
            name: pointn,
            size: 8,
            members: vec![m(xn, N_U32, 0), m(yn, N_U32, 4)],
        },
        TypeDef::Struct {
            name: waitern,
            size: 16,
            members: vec![m(notifn, N_U64, 0), m(nextn, N_WAITER_PTR, 8)],
        },
        TypeDef::Pointer {
            name: None,
            target: N_WAITER,
        },
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
        // Choice { tag: u8 @0 } -- id 7.
        TypeDef::Struct {
            name: choicen,
            size: 1,
            members: vec![m(tagn, N_U8, 0)],
        },
    ];

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
        fields: vec![Named {
            label: notifn,
            node: BundleNode::Scalar {
                at: sel(&[0]),
                decode: notif_decode,
            },
        }],
    };
    let thing_node = BundleNode::Struct {
        fields: vec![
            Named {
                label: staten,
                node: BundleNode::Scalar {
                    at: sel(&[0]),
                    decode: state_decode,
                },
            },
            Override {
                index: 1,
                node: BundleNode::Scalar {
                    at: sel(&[1]),
                    decode: BundleScalarDecode::Raw,
                },
            },
            Member(2),
            Named {
                label: queuel,
                node: BundleNode::List {
                    head: sel(&[3]),
                    next: sel(&[1]),
                    node: Box::new(waiter_node),
                    node_ty: N_WAITER,
                },
            },
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

    let b = Bundle {
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
            ]),
            name_index: vec![],
        },
        tasks: TaskTable::default(),
        dyn_futures: DynFutureTable::default(),
        statics: StaticsTable::default(),
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
