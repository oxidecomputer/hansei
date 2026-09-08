// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use crate::tokio::bundle::Context;
use crate::tokio::contract::{Walked, execute_steps};
use crate::tokio::observe::ReadContext;

use anyhow::{Context as _, Result, anyhow, bail, ensure};
use hansei_bundle::{Continuation, FutureTarget, PollAction, PollProgram};
use proc::Target;
use reify::Value;

pub const SYMBOL: &str = "HANSEI_DELEGATION_CASES";

pub const NAMES: [&str; 11] = [
    "gated",
    "previously-polled",
    "enum-retained",
    "raw-pointer",
    "reference",
    "boxed",
    "dynamic",
    "instrumented",
    "holder",
    "handle",
    "alias",
];

/// How many times each case's child was polled, which the fixture
/// asserts against its own expectation before it parks.
const CHILD_POLLS: [u64; NAMES.len()] = [0, 1, 0, 0, 1, 1, 1, 1, 0, 0, 0];

#[derive(Debug)]
pub struct Case {
    pub name: &'static str,
    pub root: u64,
    pub root_size: u64,
    pub child: u64,
    pub child_size: u64,
    pub parent_polls: u64,
    pub child_polls: u64,
}

/// Read the fixture's independent poll registry and the exact registered
/// values. The latter reads let the semantic tests inspect the same stable
/// addresses even where no program visits a retained child.
pub fn read_from<T: Target>(target: &T) -> Option<Result<Vec<Case>>> {
    let symbol = target.lookup_symbol_by_name(SYMBOL)?;
    Some((|| {
        let bytes = super::expect::read_run(target, symbol.st_value, NAMES.len() as u64 * 8 * 8)?;
        let mut cases = Vec::new();
        for (index, row) in bytes.as_chunks::<64>().0.iter().enumerate() {
            let fields: Vec<_> = row
                .as_chunks::<8>()
                .0
                .iter()
                .map(|word| u64::from_le_bytes(*word))
                .collect();
            ensure!(
                fields[7] == 1,
                "{} has no post-poll acknowledgement",
                NAMES[index]
            );
            ensure!(
                fields[4] == if index == 1 { 2 } else { 1 },
                "unexpected parent poll count"
            );
            let expected = CHILD_POLLS[index];
            ensure!(
                fields[5] == expected && fields[6] == expected,
                "unexpected child poll count"
            );
            for (address, size) in [(fields[0], fields[1]), (fields[2], fields[3])] {
                ensure!(
                    address != 0
                        && size > 0
                        && size <= 65536
                        && address.checked_add(size).is_some(),
                    "invalid registered value"
                );
                super::expect::read_run(target, address, size)?;
            }
            cases.push(Case {
                name: NAMES[index],
                root: fields[0],
                root_size: fields[1],
                child: fields[2],
                child_size: fields[3],
                parent_polls: fields[4],
                child_polls: fields[5],
            });
        }
        Ok(cases)
    })())
}

/// Where one bound direct delegation led, followed over target memory.
#[derive(Debug)]
pub enum Followed<'b> {
    /// A static delegate: the value at the route's end, of the type the
    /// program declared.
    Static { value: Value<'b>, exclusive: bool },
    /// A dynamic delegate: the data pointer's word. The concrete type
    /// behind it is the vtable join's to name, not this seam's.
    Dynamic { data: u64, exclusive: bool },
}

/// Follow the one direct delegation `value`'s type binds, literally,
/// over the target — the way a fixture test checks an emitted program
/// against the addresses the program registered. A test seam only: the
/// production continuation engine and its guards are a later phase's.
/// A type with no bound direct delegation is an error naming why.
pub fn follow<'b, T: Target>(ctx: &Context<'b, T>, value: Value<'b>) -> Result<Followed<'b>> {
    let record = ctx
        .type_semantics(value.ty.id())
        .ok_or_else(|| anyhow!("{} has no semantic record", value.ty.name()))?;
    let facts = record
        .future
        .as_ref()
        .ok_or_else(|| anyhow!("{} is not a future", value.ty.name()))?;
    let (target, exclusive) = match &facts.continuation {
        Continuation::Bound {
            program: PollProgram::Direct(PollAction::Delegate { target, exclusive }),
            ..
        } => (target, *exclusive),
        Continuation::Unknown(issue) => {
            bail!(
                "{}: continuation unknown ({:?})",
                value.ty.name(),
                issue.kind
            )
        }
        other => bail!("{}: not a direct delegation: {other:?}", value.ty.name()),
    };
    let at = |root: Value<'b>, steps: &[hansei_bundle::Step]| -> Result<Value<'b>> {
        match execute_steps(ctx, &ReadContext::none(), root, steps)? {
            Walked::At(value) => Ok(value),
            Walked::Inactive(name) => bail!("variant {name} is not active"),
            Walked::Null => bail!("null pointer on the route"),
        }
    };
    match target {
        FutureTarget::Value(path) => {
            let landed = at(value, &path.steps).context("static delegate")?;
            ensure!(
                landed.ty.id() == path.target,
                "the route landed on {} rather than the declared target",
                landed.ty.name()
            );
            Ok(Followed::Static {
                value: landed,
                exclusive,
            })
        }
        FutureTarget::Dynamic { pointer, layout } => {
            let wide = at(value, &pointer.steps).context("wide pointer")?;
            ensure!(wide.ty.id() == pointer.target, "the wide pointer moved");
            let data = at(wide, &layout.data.steps).context("data pointer")?;
            let word: [u8; 8] = data
                .bytes
                .get(..8)
                .and_then(|b| b.try_into().ok())
                .ok_or_else(|| anyhow!("short data pointer"))?;
            Ok(Followed::Dynamic {
                data: u64::from_le_bytes(word),
                exclusive,
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testkit::fake::FakeTarget;

    /// Where the fake registry's rows end: the sixteen bytes after them
    /// are the one registered root and child, and nothing past those
    /// is mapped.
    const TAIL: u64 = 0x1000 + NAMES.len() as u64 * 64;

    fn memory() -> FakeTarget {
        let mut bytes = Vec::new();
        for (index, &count) in CHILD_POLLS.iter().enumerate() {
            for word in [
                TAIL,
                8,
                TAIL + 8,
                8,
                if index == 1 { 2 } else { 1 },
                count,
                count,
                1,
            ] {
                bytes.extend(word.to_le_bytes());
            }
        }
        bytes.extend([0; 16]);
        FakeTarget {
            base: 0x1000,
            bytes,
            has_symbol: true,
            seam: None,
        }
    }

    #[test]
    fn test_poll_registry_requires_post_poll_counts_and_readable_values() {
        let target = memory();
        assert_eq!(read_from(&target).unwrap().unwrap().len(), NAMES.len());
        for (field, value) in [
            (0, 0),
            (1, 0),
            (1, 65537),
            (2, TAIL + 0x10),
            (4, 2),
            (5, 1),
            (6, 1),
            (7, 0),
        ] {
            let mut target = memory();
            target.bytes[field * 8..field * 8 + 8].copy_from_slice(&value.to_le_bytes());
            assert!(
                read_from(&target).unwrap().is_err(),
                "field {field} accepted {value}"
            );
        }
        let mut absent = memory();
        absent.has_symbol = false;
        assert!(read_from(&absent).is_none());
    }
}
