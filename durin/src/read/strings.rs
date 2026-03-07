use crate::read::{Error, Result};
use crate::{CtfHeader, StrId, StringTableType};

use std::collections::HashSet;
use std::fmt;

/// An unvalidated table containing all strings present in the CTF file.
#[derive(Clone, PartialEq, Eq)]
pub(super) struct UncheckedStringTable {
    inner: Vec<u8>,
    valid_ids: HashSet<StrId>,
}

impl UncheckedStringTable {
    pub fn new(header: &CtfHeader, data: &[u8]) -> Self {
        let str_start = header.stroff as usize;
        let str_end = str_start + header.strlen as usize;

        Self {
            inner: data[str_start..str_end].to_vec(),
            valid_ids: HashSet::new(),
        }
    }

    /// Retrieve a StrId from the table, confirming it has a valid index, is
    /// correctly encoded, and is in the internal table.
    pub fn get_checked(&self, id: StrId) -> Result<&str> {
        if matches!(id.table(), StringTableType::External) {
            return Err(Error::external_str(id));
        }

        let bytes = self
            .inner
            .get(id.offset() as usize..)
            .ok_or_else(|| Error::missing_str(id))?;

        let Some(substr) = bytes.split(|&b| b == 0).next() else {
            return Err(Error::unterminated_str(id));
        };

        str::from_utf8(substr).map_err(|_| Error::invalid_str_encoding(id))
    }

    /// Confirms a `StrId` has a valid index, is correctly encoded, and is in the
    /// internal table. The validated `StrId` will be marked as safe for use.
    pub fn check(&mut self, id: StrId) -> Result<()> {
        let _ = self.get_checked(id)?;
        self.valid_ids.insert(id);

        Ok(())
    }
}

/// An table containing all strings present in the CTF file. All `StrIds` in the
/// file have been confirmed to be have a valid index, UTF-8 encoded, and in the
/// internal string table.
#[derive(Clone, PartialEq, Eq)]
pub struct StringTable {
    inner: Vec<u8>,
    valid_ids: HashSet<StrId>,
}

impl StringTable {
    /// Retrieve a string from the string table. Only internal tables are
    /// supported.
    pub fn get(&self, id: StrId) -> &str {
        if !self.valid_ids.contains(&id) {
            // PANIC: This unknown `StrId` must have come from another
            // `CtfReader` or unsafe shenanigans, we do not provide a public
            // constructor.
            panic!("string index {} was not confirmed to be valid", id.get());
        }

        // SAFETY: We know this StrId has been validated.
        let raw = unsafe { self.get_unchecked(id) };
        raw.split("@@").next().unwrap_or(raw)
    }

    /// Get the original string from the table without stripping our `@@`
    /// suffixes for large enum values.
    pub(crate) fn get_raw(&self, id: StrId) -> &str {
        // SAFETY: We confirmed all StrIds prior to construction.
        unsafe { self.get_unchecked(id) }
    }

    /// SAFETY: This may only be called after all StrIds have been validated.
    unsafe fn get_unchecked(&self, id: StrId) -> &str {
        // SAFETY: We've confirmed that all StrIds present are valid. No public
        // constructor is available for users to create an invalid id. We hold
        // exclusive access to the table state in memory.
        let bytes = unsafe { self.inner.get_unchecked(id.offset() as usize..) };

        // UNWRAP: We've already confirmed all string offsets used are
        // null-terminated.
        let substr = bytes.split(|&b| b == 0).next().unwrap();

        // SAFETY: We've already confirmed this str is valid UTF-8.
        unsafe { str::from_utf8_unchecked(substr) }
    }

    /// Returns a slice containing the raw bytes of the `StringTable`.
    pub fn inner(&self) -> &[u8] {
        &self.inner
    }
}

impl From<UncheckedStringTable> for StringTable {
    fn from(value: UncheckedStringTable) -> Self {
        Self {
            inner: value.inner,
            valid_ids: value.valid_ids,
        }
    }
}

impl fmt::Debug for StringTable {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let iter = self
            .inner
            .split(|&b| b == 0)
            .map(|s| str::from_utf8(s).unwrap());
        f.debug_map().entries(iter.enumerate()).finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_strings_load() {
        let data = b"\0hello\0world\0".to_vec();
        let mut unchecked = UncheckedStringTable {
            inner: data,
            valid_ids: HashSet::new(),
        };

        let first_id = StrId::from_u32(1).unwrap();
        let second_id = StrId::from_u32(7).unwrap();

        unchecked.check(first_id).unwrap();
        unchecked.check(second_id).unwrap();

        let checked: StringTable = unchecked.into();

        assert_eq!(checked.get(first_id), "hello");
        assert_eq!(checked.get(second_id), "world");
    }

    #[test]
    #[should_panic]
    fn test_strings_invalid_id_fails() {
        let data = b"\0hello\0".to_vec();
        let mut unchecked = UncheckedStringTable {
            inner: data,
            valid_ids: HashSet::new(),
        };

        let first_id = StrId::from_u32(1).unwrap();
        let bad_id = StrId::from_u32(2).unwrap();

        unchecked.check(first_id).unwrap();
        let checked: StringTable = unchecked.into();

        assert_eq!(checked.get(first_id), "hello");
        checked.get(bad_id);
    }
}
