use crate::{CtfHeader, Error, Result, StrId, StringTableType};

use std::fmt;

/// An unvalidated table containing all strings present in the CTF file.
#[derive(Clone, PartialEq, Eq, Hash)]
pub(super) struct UncheckedStringTable {
    inner: Vec<u8>,
}

impl UncheckedStringTable {
    pub fn new(header: &CtfHeader, data: &[u8]) -> Self {
        let str_start = header.stroff as usize;
        let str_end = str_start + header.strlen as usize;

        Self {
            inner: data[str_start..str_end].to_vec(),
        }
    }

    /// Retrieve a StrId from the table, confirming it has a valid index, is
    /// correctly encoded, and is in the internal table.
    pub fn get_checked<'a>(&'a self, id: StrId) -> Result<&'a str> {
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

    /// Confirm a StrId has a valid index, is correctly encoded, and is in the
    /// internal table.
    pub fn check<'a>(&'a self, id: StrId) -> Result<()> {
        let _ = self.get_checked(id)?;

        Ok(())
    }
}

/// An table containing all strings present in the CTF file. All `StrIds` in the
/// file have been confirmed to be have a valid index, UTF-8 encoded, and in the
/// internal string table.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct StringTable {
    inner: Vec<u8>,
}

impl StringTable {
    /// Retrieve a string from the string table. Only internal tables are
    /// supported.
    pub fn get<'a>(&'a self, id: StrId) -> &'a str {
        // SAFETY: We confirmed all StrIds prior to construction.
        unsafe { self.get_unchecked(id) }
    }

    /// SAFETY: This may only be called after all StrIds have been validated.
    unsafe fn get_unchecked<'a>(&'a self, id: StrId) -> &'a str {
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
}

impl From<UncheckedStringTable> for StringTable {
    fn from(value: UncheckedStringTable) -> Self {
        Self { inner: value.inner }
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
