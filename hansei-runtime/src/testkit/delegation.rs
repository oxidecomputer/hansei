// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use anyhow::{Result, ensure};
use proc::Target;

pub const SYMBOL: &str = "HANSEI_DELEGATION_CASES";

pub const NAMES: [&str; 8] = [
    "gated",
    "previously-polled",
    "enum-retained",
    "raw-pointer",
    "reference",
    "boxed",
    "dynamic",
    "instrumented",
];

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
/// values. The latter reads let later semantic tests inspect the same stable
/// addresses even when the legacy walker never visits a retained child.
pub fn read_from<T: Target>(target: &T) -> Option<Result<Vec<Case>>> {
    let symbol = target.lookup_symbol_by_name(SYMBOL)?;
    Some((|| {
        let bytes = super::expect::read_run(target, symbol.st_value, 8 * 8 * 8)?;
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
            let expected = [0, 1, 0, 0, 1, 1, 1, 1][index];
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testkit::fake::FakeTarget;

    fn memory() -> FakeTarget {
        let mut bytes = Vec::new();
        for index in 0..8 {
            let count = [0, 1, 0, 0, 1, 1, 1, 1][index];
            for word in [
                0x1200u64,
                8,
                0x1208,
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
        assert_eq!(read_from(&target).unwrap().unwrap().len(), 8);
        for (field, value) in [
            (0, 0),
            (1, 0),
            (1, 65537),
            (2, 0x1210),
            (4, 2),
            (5, 1),
            (6, 1),
            (7, 0),
        ] {
            let mut target = memory();
            target.bytes[field * 8..field * 8 + 8].copy_from_slice(&(value as u64).to_le_bytes());
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
