// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use anyhow::{Result, ensure};
use hansei_bundle::{BundleTypeId, TypeSemantics};

/// Context-owned lookup positions; serialized records remain sparse wire data.
pub(super) struct SemanticIndex(Vec<u32>);

impl SemanticIndex {
    pub(super) fn new(type_count: usize, records: &[TypeSemantics]) -> Result<Self> {
        ensure!(
            u32::try_from(type_count).is_ok(),
            "too many types for semantic index"
        );
        ensure!(
            u32::try_from(records.len()).is_ok(),
            "too many semantic records"
        );
        let mut positions = vec![u32::MAX; type_count];
        for (index, record) in records.iter().enumerate() {
            let slot = positions
                .get_mut(record.ty.0 as usize)
                .ok_or_else(|| anyhow::anyhow!("semantic type id out of range"))?;
            ensure!(*slot == u32::MAX, "duplicate semantic type id");
            *slot = index as u32;
        }
        Ok(Self(positions))
    }

    pub(super) fn get(&self, ty: BundleTypeId) -> Option<usize> {
        let position = *self.0.get(ty.0 as usize)?;
        (position != u32::MAX).then_some(position as usize)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use hansei_bundle::StoragePolicy;

    fn record(id: u32) -> TypeSemantics {
        TypeSemantics {
            ty: BundleTypeId(id),
            storage: StoragePolicy::DeclaredMembers,
            future: None,
            coroutine: None,
            access: None,
            resource: None,
            container: None,
            select: None,
            http: None,
            request: None,
            table: None,
            pool: None,
            io_route: None,
            io: None,
            refcount: None,
            lock: None,
            acquires_for: None,
            coroutine_kind: None,
            issues: Vec::new(),
        }
    }

    #[test]
    fn test_sparse_semantic_index_preserves_absent_and_boundary_ids() {
        let index = SemanticIndex::new(5, &[record(1), record(4)]).unwrap();
        assert_eq!(index.get(BundleTypeId(0)), None);
        assert_eq!(index.get(BundleTypeId(1)), Some(0));
        assert_eq!(index.get(BundleTypeId(3)), None);
        assert_eq!(index.get(BundleTypeId(4)), Some(1));
        assert_eq!(index.get(BundleTypeId(5)), None);
        assert_eq!(index.get(BundleTypeId(u32::MAX)), None);
        assert_eq!(
            SemanticIndex::new(0, &[]).unwrap().get(BundleTypeId(0)),
            None
        );
    }

    #[test]
    fn test_semantic_index_refuses_invalid_records_before_lookup() {
        assert!(SemanticIndex::new(2, &[record(2)]).is_err());
        assert!(SemanticIndex::new(2, &[record(1), record(1)]).is_err());
        if let Some(too_many) = (u32::MAX as usize).checked_add(1) {
            assert!(SemanticIndex::new(too_many, &[]).is_err());
        }
    }
}
