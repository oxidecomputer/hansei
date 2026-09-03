// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! The generated program's shape: a seeded random tree over the
//! combinator grammar the census walks, bounded so every program stays
//! inside the census's own limits and the fixture registry's capacity.
//!
//! The grammar splits by census visibility, which decides who registers
//! what (see `emit`):
//!
//! - **Row-producing** nodes — a held coroutine, a dyn box, a
//!   `FuturesUnordered`, a `JoinSet` — register an expectation for the
//!   census row they must produce.
//! - **Interior** nodes — tuples, options, wrapper structs, and the
//!   combinators themselves (the locals scan descends through a held
//!   one; an awaited one is chain interior) — register nothing of
//!   their own: they exist to stress descent, dedup, and the chain
//!   walk, and are observed through the rows found through them.
//!
//! Two shapes are deliberately absent, both learned from the first
//! soak. A future's *address* is only well-defined where something
//! pins it: a bare `oneshot::Receiver` held as a local is small,
//! immutable, and Unpin, so the optimizer may keep two copies and the
//! registered address can name the one the debug info does not follow
//! (the channels fixture pins that row shape by hand, behind a real
//! Pin). And a park combinator's *sized* interior — its arms, a
//! `pin!`ed awaitee, the pin reference itself — is census rows at
//! addresses in the frame's await machinery, present or absent at the
//! debug info's whim; the emitted park combinators close over
//! zero-sized `pending()` arms instead, which the scan skips by size.
//!
//! Two contexts constrain what can appear where, both consequences of
//! the unresumed-coroutine rule (a never-polled future's frame carries
//! only its arguments):
//!
//! - A **running body** (a driver task, a polled set's child, a
//!   join-set member) builds locals live across its park, so it can
//!   register their addresses; anything may appear there.
//! - An **argument** carried by a never-polled holder can register
//!   nothing by address, so only shapes whose finds are expressible as
//!   `held_in` (coroutine leaves under pure wrappers) may appear, and
//!   holders do not nest — a find two held hops in has no registrable
//!   key.
//!
//! Likewise a never-polled `FuturesUnordered`'s children are plain
//! leaves: their bodies never run, so they could register nothing, and
//! the set's own count is the only claim made about them.

/// The registry's write side holds 64 entries; staying well under
/// leaves room for a fixture edit without re-deriving budgets.
pub const MAX_REGS: usize = 48;

/// Running bodies per program (each parks a frame the census walks).
pub const MAX_BODIES: usize = 12;

/// Fixed-width two-digit ids keep every registered name
/// substring-unique, so the count of named functions must stay below
/// 100.
pub const MAX_NAMES: usize = 100;

/// xorshift64* — the same tiny PRNG family the fault campaign uses;
/// seeded through splitmix so small seeds do not correlate.
pub struct Rng(u64);

impl Rng {
    pub fn new(seed: u64) -> Self {
        let mut z = seed.wrapping_add(0x9E37_79B9_7F4A_7C15);
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        Rng((z ^ (z >> 31)) | 1)
    }

    pub fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    pub fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }

    pub fn range(&mut self, lo: u64, hi: u64) -> u64 {
        lo + self.below(hi - lo + 1)
    }

    /// Pick by weight from `(weight, key)` rows.
    pub fn weighted(&mut self, rows: &[(u32, u32)]) -> u32 {
        let total: u64 = rows.iter().map(|&(w, _)| w as u64).sum();
        let mut at = self.below(total);
        for &(w, key) in rows {
            if at < w as u64 {
                return key;
            }
            at -= w as u64;
        }
        unreachable!("weights sum to total");
    }
}

/// What a leaf coroutine parks on. Every one of these pends forever in
/// a generated program: the notify is never notified, the oneshot
/// sender is leaked, the semaphore has no permits, the timer's deadline
/// is years out.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Park {
    Notify,
    Oneshot,
    Semaphore,
    Timer,
}

/// A leaf coroutine: `async fn leaf_<id>` awaiting its park primitive.
#[derive(Debug)]
pub struct Leaf {
    pub id: usize,
    pub park: Park,
}

/// A value a running body builds and holds across its park.
#[derive(Debug)]
pub enum Value {
    /// A bare coroutine — a held-future row at its own slot.
    Leaf(Leaf),
    /// `async fn holder_<id>(inner: F, ..)` — a held row at its slot,
    /// with the argument's coroutines registered `held_in` through it.
    Holder { id: usize, arg: Box<Value> },
    /// `Pin<Box<dyn Future>>` around a leaf — a dyn row whose slot is
    /// the box and whose addr re-roots at the referent.
    BoxedDyn(Leaf),
    /// `(value, scalar)` — interior.
    Tuple(Box<Value>, u64),
    /// `Some(value)` — interior, reached through the active variant.
    Opt(Box<Value>),
    /// `GfWrap { inner, tag }` — a hand-written non-Future struct.
    Wrap(Box<Value>, u64),
    /// `GfSel<N> { a, b, .. }` — a held select combinator: interior.
    /// The locals scan descends through it like any aggregate; only
    /// the coroutines inside are rows.
    Sel(Vec<Value>),
    /// `GfJoi<N> { a, b, .. }` — a held join combinator; same rules.
    Joi(Vec<Value>),
    /// A never-polled `FuturesUnordered` of `count` copies of one leaf.
    Set { count: usize, child: Leaf },
    /// A `JoinSet` whose members are spawned running bodies.
    JSet { members: Vec<Body> },
}

/// How a running body parks.
#[derive(Debug)]
pub enum ParkPoint {
    /// Await the primitive directly in the body.
    Primitive(Park),
    /// Await a hand-written combinator over `arms` copies of
    /// `std::future::pending::<u64>()` — the chain-walk stress: the
    /// body's chain passes through the hand-written combinator. The
    /// arms are zero-sized on purpose: a chain frame's sized locals
    /// are census rows at addresses no fixture can register (the
    /// awaitee lives in the frame's await slot), and a ZST produces
    /// no row.
    Combinator { select: bool, arms: usize },
    /// Await a `FuturesUnordered` of `count` copies of one child body —
    /// the children run, register their own state, and park.
    PolledSet { count: usize, child: Box<Body> },
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum BodyKind {
    /// Spawned by main; registers a `task` expectation.
    Driver,
    /// A polled set's child; not a task, registers only its holdings.
    SetChild,
    /// A join-set member; a real task, registers a `task` expectation.
    Member,
}

/// One running body: an async fn that builds `locals`, registers them,
/// reports in, and parks at `park` with the locals live across it.
#[derive(Debug)]
pub struct Body {
    pub id: usize,
    pub kind: BodyKind,
    pub locals: Vec<Value>,
    pub park: ParkPoint,
}

#[derive(Debug)]
pub struct Program {
    pub seed: u64,
    pub drivers: Vec<Body>,
}

/// Generation state: the PRNG plus the budgets that keep a program
/// inside the registry's capacity and the census's walk limits.
///
/// The running budgets are a soft guide — a deep subtree can overrun
/// them, because every terminal registers something. [`generate`]
/// recomputes the exact cost afterwards and retries with a higher
/// `shrink` (tighter caps, fewer expensive shapes) until the program
/// fits; the retry chain is part of the seed's deterministic output.
struct Gen {
    rng: Rng,
    next_id: usize,
    /// Runtime registrations still affordable. A polled set's child
    /// body registers once *per instance*, so its cost multiplies.
    regs_left: usize,
    bodies_left: usize,
    shrink: usize,
}

impl Gen {
    fn id(&mut self) -> usize {
        let id = self.next_id;
        self.next_id += 1;
        id
    }

    fn leaf(&mut self) -> Leaf {
        let park = match self.rng.weighted(&[(4, 0), (2, 1), (2, 2), (2, 3)]) {
            0 => Park::Notify,
            1 => Park::Oneshot,
            2 => Park::Semaphore,
            _ => Park::Timer,
        };
        Leaf {
            id: self.id(),
            park,
        }
    }

    /// A value in argument context: what a never-polled holder may
    /// carry: a bare coroutine leaf, the one shape whose interior find
    /// is expressible as `held_in(holder, leaf)`. A combinator here
    /// would be a held row of its own (it implements `Future`), and
    /// its arms attribute through *its* row rather than the holder's —
    /// a chain the slot-keyed registry cannot spell, as the first soak
    /// demonstrated.
    fn arg_value(&mut self, _depth: usize) -> Value {
        Value::Leaf(self.leaf_charged())
    }

    fn leaf_charged(&mut self) -> Leaf {
        self.regs_left = self.regs_left.saturating_sub(1);
        self.leaf()
    }

    /// A value in a running body: any shape, budget permitting.
    fn value(&mut self, depth: usize, body_depth: usize) -> Value {
        if self.regs_left == 0 {
            // The soft budget dried up mid-subtree; terminate with the
            // cheapest registering shape and let the exact recount in
            // `generate` decide whether the overrun needs a retry.
            return Value::Leaf(self.leaf_charged());
        }
        let deeper = depth < 3usize.saturating_sub(self.shrink);
        let can_body =
            self.shrink == 0 && body_depth < 2 && self.bodies_left > 1 && self.regs_left > 3;
        let mut rows: Vec<(u32, u32)> = vec![(12, 0), (6, 1), (4, 2)];
        if deeper {
            rows.extend_from_slice(&[(4, 3), (3, 4), (3, 5), (2, 6), (2, 7)]);
        }
        if depth < 2 && self.shrink < 2 && self.regs_left > 2 {
            rows.push((4, 8));
        }
        if depth < 2 && can_body {
            rows.push((3, 9));
        }
        match self.rng.weighted(&rows) {
            0 => Value::Leaf(self.leaf_charged()),
            1 => {
                // The holder itself plus at least one held_in.
                self.regs_left = self.regs_left.saturating_sub(1);
                Value::Holder {
                    id: self.id(),
                    arg: Box::new(self.arg_value(0)),
                }
            }
            2 => Value::BoxedDyn(self.leaf_charged()),
            3 => Value::Tuple(
                Box::new(self.value(depth + 1, body_depth)),
                self.rng.below(100),
            ),
            4 => Value::Opt(Box::new(self.value(depth + 1, body_depth))),
            5 => Value::Wrap(
                Box::new(self.value(depth + 1, body_depth)),
                self.rng.below(100),
            ),
            sel @ (6 | 7) => {
                let n = self.rng.range(2, 3) as usize;
                let arms = (0..n).map(|_| self.value(depth + 1, body_depth)).collect();
                if sel == 6 {
                    Value::Sel(arms)
                } else {
                    Value::Joi(arms)
                }
            }
            8 => {
                self.regs_left = self.regs_left.saturating_sub(1);
                Value::Set {
                    count: self.rng.range(1, 3) as usize,
                    child: self.leaf(),
                }
            }
            9 => {
                self.regs_left = self.regs_left.saturating_sub(1);
                let n = self.rng.range(1, 2) as usize;
                let mut members = Vec::new();
                for _ in 0..n {
                    if self.bodies_left > 0 && self.regs_left > 1 {
                        members.push(self.body(BodyKind::Member, body_depth + 1));
                    }
                }
                if members.is_empty() {
                    Value::Leaf(self.leaf_charged())
                } else {
                    Value::JSet { members }
                }
            }
            _ => unreachable!(),
        }
    }

    fn body(&mut self, kind: BodyKind, body_depth: usize) -> Body {
        self.bodies_left = self.bodies_left.saturating_sub(1);
        if kind != BodyKind::SetChild {
            // The task registration.
            self.regs_left = self.regs_left.saturating_sub(1);
        }
        let id = self.id();
        let min_locals = if kind == BodyKind::Driver { 1 } else { 0 };
        let max_locals = 3u64.saturating_sub(self.shrink as u64).max(min_locals);
        let n = self.rng.range(min_locals, max_locals) as usize;
        let mut locals = Vec::new();
        for _ in 0..n {
            if self.regs_left > 0 {
                locals.push(self.value(0, body_depth));
            }
        }
        let park = self.park_point(body_depth);
        Body {
            id,
            kind,
            locals,
            park,
        }
    }

    fn park_point(&mut self, body_depth: usize) -> ParkPoint {
        let can_set =
            self.shrink == 0 && body_depth < 2 && self.bodies_left > 1 && self.regs_left > 4;
        let mut rows: Vec<(u32, u32)> = vec![(8, 0), (4, 1)];
        if can_set {
            rows.push((6, 2));
        }
        match self.rng.weighted(&rows) {
            0 => {
                let park = match self.rng.weighted(&[(4, 0), (2, 1), (2, 2), (2, 3)]) {
                    0 => Park::Notify,
                    1 => Park::Oneshot,
                    2 => Park::Semaphore,
                    _ => Park::Timer,
                };
                ParkPoint::Primitive(park)
            }
            1 => ParkPoint::Combinator {
                select: self.rng.below(2) == 0,
                arms: self.rng.range(2, 3) as usize,
            },
            2 => {
                // Each of `count` instances registers the child's whole
                // slate at runtime, so the child generates under an
                // even share of what is left and its use is charged
                // per instance.
                let count = self.rng.range(1, 3) as usize;
                let before_regs = self.regs_left.saturating_sub(1);
                let before_bodies = self.bodies_left;
                self.regs_left = before_regs / count;
                self.bodies_left = before_bodies.saturating_sub(1) / count;
                let child = self.body(BodyKind::SetChild, body_depth + 1);
                let used_regs = (before_regs / count) - self.regs_left;
                let used_bodies = (before_bodies.saturating_sub(1) / count) - self.bodies_left;
                self.regs_left = before_regs - count * used_regs;
                self.bodies_left = before_bodies - count * used_bodies;
                ParkPoint::PolledSet {
                    count,
                    child: Box::new(child),
                }
            }
            _ => unreachable!(),
        }
    }
}

pub fn generate(seed: u64) -> Program {
    // The running budgets are soft (see `Gen`); retry with tighter
    // caps until the exact recount fits. The last level generates the
    // minimal program — one driver, one leaf, a primitive park — which
    // always fits.
    for shrink in 0..=3 {
        let mut g = Gen {
            rng: Rng::new(seed),
            next_id: 0,
            regs_left: MAX_REGS,
            bodies_left: MAX_BODIES,
            shrink,
        };
        let n = if shrink == 0 { g.rng.range(1, 2) } else { 1 } as usize;
        let drivers: Vec<Body> = (0..n).map(|_| g.body(BodyKind::Driver, 0)).collect();
        let p = Program { seed, drivers };
        if registrations(&p) <= MAX_REGS && total_bodies(&p) <= MAX_BODIES && g.next_id <= MAX_NAMES
        {
            return p;
        }
    }
    unreachable!("the fully shrunk program is minimal and always fits");
}

/// How many entries this program writes into the registry at runtime —
/// the emit side's claim, recomputed from the tree so a budgeting bug
/// in [`Gen`] fails a test rather than overflowing the registry.
pub fn registrations(p: &Program) -> usize {
    p.drivers.iter().map(regs_of_body).sum()
}

fn regs_of_body(b: &Body) -> usize {
    let task = if b.kind == BodyKind::SetChild { 0 } else { 1 };
    let locals: usize = b.locals.iter().map(regs_of_value).sum();
    let park = match &b.park {
        ParkPoint::Primitive(_) | ParkPoint::Combinator { .. } => 0,
        ParkPoint::PolledSet { count, child } => 1 + count * regs_of_body(child),
    };
    task + locals + park
}

fn regs_of_value(v: &Value) -> usize {
    match v {
        Value::Leaf(_) | Value::BoxedDyn(_) => 1,
        Value::Holder { arg, .. } => 1 + regs_of_value(arg),
        Value::Tuple(inner, _) | Value::Opt(inner) | Value::Wrap(inner, _) => regs_of_value(inner),
        Value::Sel(arms) | Value::Joi(arms) => arms.iter().map(regs_of_value).sum(),
        Value::Set { .. } => 1,
        Value::JSet { members } => 1 + members.iter().map(regs_of_body).sum::<usize>(),
    }
}

/// How many running bodies report in before main prints READY.
pub fn total_bodies(p: &Program) -> usize {
    p.drivers.iter().map(bodies_of).sum()
}

fn bodies_of(b: &Body) -> usize {
    let locals: usize = b.locals.iter().map(bodies_of_value).sum::<usize>();
    let park = match &b.park {
        ParkPoint::Primitive(_) | ParkPoint::Combinator { .. } => 0,
        ParkPoint::PolledSet { count, child } => count * bodies_of(child),
    };
    1 + locals + park
}

fn bodies_of_value(v: &Value) -> usize {
    match v {
        Value::JSet { members } => members.iter().map(bodies_of).sum(),
        Value::Tuple(inner, _) | Value::Opt(inner) | Value::Wrap(inner, _) => {
            bodies_of_value(inner)
        }
        Value::Sel(arms) | Value::Joi(arms) => arms.iter().map(bodies_of_value).sum(),
        Value::Holder { .. } | Value::Leaf(_) | Value::BoxedDyn(_) | Value::Set { .. } => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generation_is_deterministic() {
        let a = format!("{:?}", generate(42));
        let b = format!("{:?}", generate(42));
        assert_eq!(a, b);
    }

    #[test]
    fn test_seeds_differ() {
        let a = format!("{:?}", generate(1));
        let b = format!("{:?}", generate(2));
        assert_ne!(a, b);
    }

    #[test]
    fn test_every_program_respects_the_budgets() {
        for seed in 0..500 {
            let p = generate(seed);
            let regs = registrations(&p);
            assert!(
                regs <= MAX_REGS,
                "seed {seed}: {regs} registrations over the {MAX_REGS} budget"
            );
            let bodies = total_bodies(&p);
            assert!(
                bodies <= MAX_BODIES,
                "seed {seed}: {bodies} bodies over the {MAX_BODIES} budget"
            );
            assert!(bodies >= 1);
            let names = p.drivers.len(); // at least the drivers exist
            assert!(names >= 1);
        }
    }

    /// The whole point of the generator: across a modest seed range,
    /// every grammar production actually occurs somewhere. A weight
    /// edit that silently stops producing a shape fails here.
    #[test]
    fn test_the_seed_space_produces_every_shape() {
        let (mut holder, mut boxed, mut set, mut jset, mut polled, mut comb) =
            (false, false, false, false, false, false);
        let (mut tup, mut opt, mut wrap, mut sel, mut joi) = (false, false, false, false, false);
        fn walk_value(v: &Value, f: &mut dyn FnMut(&Value)) {
            f(v);
            match v {
                Value::Holder { arg, .. } => walk_value(arg, f),
                Value::Tuple(i, _) | Value::Opt(i) | Value::Wrap(i, _) => walk_value(i, f),
                Value::Sel(arms) | Value::Joi(arms) => arms.iter().for_each(|a| walk_value(a, f)),
                Value::JSet { members } => members
                    .iter()
                    .flat_map(|m| m.locals.iter())
                    .for_each(|l| walk_value(l, f)),
                _ => {}
            }
        }
        for seed in 0..300 {
            let p = generate(seed);
            let mut stack: Vec<&Body> = p.drivers.iter().collect();
            while let Some(b) = stack.pop() {
                match &b.park {
                    ParkPoint::PolledSet { child, .. } => {
                        polled = true;
                        stack.push(child);
                    }
                    ParkPoint::Combinator { .. } => comb = true,
                    ParkPoint::Primitive(_) => {}
                }
                for l in &b.locals {
                    walk_value(l, &mut |v: &Value| match v {
                        Value::Holder { .. } => holder = true,
                        Value::BoxedDyn(_) => boxed = true,
                        Value::Set { .. } => set = true,
                        Value::JSet { .. } => jset = true,
                        Value::Tuple(..) => tup = true,
                        Value::Opt(_) => opt = true,
                        Value::Wrap(..) => wrap = true,
                        Value::Sel(_) => sel = true,
                        Value::Joi(_) => joi = true,
                        Value::Leaf(_) => {}
                    });
                    // Members' own parks and nested bodies.
                    walk_value(l, &mut |v: &Value| {
                        if let Value::JSet { members } = v {
                            for m in members {
                                if let ParkPoint::Combinator { .. } = m.park {
                                    comb = true;
                                }
                            }
                        }
                    });
                }
            }
        }
        for (name, hit) in [
            ("holder", holder),
            ("boxed_dyn", boxed),
            ("unpolled set", set),
            ("join set", jset),
            ("polled set", polled),
            ("park combinator", comb),
            ("tuple", tup),
            ("option", opt),
            ("wrapper", wrap),
            ("select", sel),
            ("join", joi),
        ] {
            assert!(hit, "no seed in 0..300 produced a {name}");
        }
    }
}
