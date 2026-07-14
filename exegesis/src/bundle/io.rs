//! Bundle framing and (de)serialization.
//!
//! On disk a bundle is a small uncompressed header — 8 magic bytes and a
//! little-endian u32 format version, so `file`-style sniffing and fast
//! rejection work without decompressing anything — followed by a single
//! zstd frame containing the postcard-encoded [`Bundle`].
//!
//! There is no cross-version compatibility: a bundle is read by the same
//! tool version that wrote it (`format_version` bumps freely).

use crate::bundle::schema::{
    Bundle, BundleTypeId, StaticsTable, TypeDef, strip_llvm_suffix,
};
use crate::bundle::strings::StrRef;

use std::fs::File;
use std::io::{BufReader, BufWriter, Read, Write};
use std::path::Path;

/// Leading bytes of every bundle file.
pub const MAGIC: [u8; 8] = *b"exegesis";

/// The current bundle format version. Bump on any schema change, including
/// indirect ones (e.g. new [`crate::raw_types::Encoding`] variants).
pub const FORMAT_VERSION: u32 = 1;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(thiserror::Error, Debug)]
#[non_exhaustive]
pub enum Error {
    #[error("bundle i/o failed")]
    Io(#[from] std::io::Error),
    #[error("not a bundle file (bad magic)")]
    BadMagic,
    #[error("bundle format version {found} unsupported (this tool reads version {expected})")]
    VersionMismatch { found: u32, expected: u32 },
    #[error("failed to decode bundle payload")]
    Decode(#[source] postcard::Error),
    #[error("failed to encode bundle payload")]
    Encode(#[source] postcard::Error),
    #[error("corrupt bundle: {0}")]
    Corrupt(String),
}

impl Bundle {
    /// Serialize into `w`: header, then zstd-compressed postcard payload.
    ///
    /// Performs no validation, so tests can craft intentionally-broken
    /// bundles; use [`Bundle::save`] for the checked path.
    pub fn write_to<W: Write>(&self, mut w: W) -> Result<()> {
        w.write_all(&MAGIC)?;
        w.write_all(&FORMAT_VERSION.to_le_bytes())?;
        let payload = postcard::to_allocvec(self).map_err(Error::Encode)?;
        zstd::stream::copy_encode(payload.as_slice(), &mut w, zstd::DEFAULT_COMPRESSION_LEVEL)?;
        Ok(())
    }

    /// Validate and write the bundle to `path`.
    pub fn save(&self, path: &Path) -> Result<()> {
        self.validate()?;
        let mut w = BufWriter::new(File::create(path)?);
        self.write_to(&mut w)?;
        w.flush()?;
        Ok(())
    }

    /// Deserialize a bundle from `r`, verifying framing, format version,
    /// and internal consistency ([`Bundle::validate`]).
    pub fn read_from<R: Read>(mut r: R) -> Result<Self> {
        let mut header = [0u8; MAGIC.len() + size_of::<u32>()];
        r.read_exact(&mut header)?;
        if header[..MAGIC.len()] != MAGIC {
            return Err(Error::BadMagic);
        }
        let found = u32::from_le_bytes(header[MAGIC.len()..].try_into().unwrap());
        if found != FORMAT_VERSION {
            return Err(Error::VersionMismatch { found, expected: FORMAT_VERSION });
        }
        let payload = zstd::stream::decode_all(r)?;
        let bundle: Bundle = postcard::from_bytes(&payload).map_err(Error::Decode)?;
        bundle.validate()?;
        Ok(bundle)
    }

    /// Load a bundle from `path`.
    pub fn load(path: &Path) -> Result<Self> {
        Self::read_from(BufReader::new(File::open(path)?))
    }

    /// Check every cross-reference in the bundle, so that readers may index
    /// tables without per-access bounds checks. A failure here means the
    /// bundle is corrupt or was produced by a buggy extractor; the error
    /// says which table and index.
    pub fn validate(&self) -> Result<()> {
        let corrupt = |msg: String| Err(Error::Corrupt(msg));

        if self.meta.format_version != FORMAT_VERSION {
            return corrupt(format!(
                "meta.format_version {} != framing version {FORMAT_VERSION}",
                self.meta.format_version
            ));
        }
        if !self.strings.is_well_formed() {
            return corrupt("string table offsets malformed".into());
        }

        let check_str = |what: &str, r: StrRef| match self.strings.get(r) {
            Some(_) => Ok(()),
            None => corrupt(format!("{what}: string ref {} out of range", r.0)),
        };
        let check_ty = |what: &str, id: BundleTypeId| {
            if (id.0 as usize) < self.types.types.len() {
                Ok(())
            } else {
                corrupt(format!("{what}: type id {} out of range", id.0))
            }
        };
        let check_member =
            |what: &str, m: &crate::bundle::schema::MemberDef| -> Result<()> {
                check_str(what, m.name)?;
                check_ty(what, m.ty)
            };

        for (i, def) in self.types.types.iter().enumerate() {
            let what = &format!("type {i}");
            match def {
                TypeDef::Base { name, .. } | TypeDef::Opaque { name, .. } => {
                    check_str(what, *name)?;
                }
                TypeDef::Pointer { name, target } => {
                    if let Some(name) = name {
                        check_str(what, *name)?;
                    }
                    check_ty(what, *target)?;
                }
                TypeDef::Array { elem, .. } => check_ty(what, *elem)?,
                TypeDef::Struct { name, members, .. }
                | TypeDef::Union { name, members, .. } => {
                    check_str(what, *name)?;
                    for m in members {
                        check_member(what, m)?;
                    }
                }
                TypeDef::Enum { name, shape, .. } => {
                    check_str(what, *name)?;
                    if let Some(d) = &shape.discr {
                        check_ty(what, d.ty)?;
                    }
                    for v in &shape.variants {
                        check_str(what, v.name)?;
                        check_member(what, &v.payload)?;
                        if let Some(loc) = &v.decl {
                            check_str(what, loc.file)?;
                        }
                    }
                }
                TypeDef::CEnum { name, repr, enumerators, .. } => {
                    check_str(what, *name)?;
                    check_ty(what, *repr)?;
                    for (ename, _) in enumerators {
                        check_str(what, *ename)?;
                    }
                }
            }
        }

        let mut prev: Option<&str> = None;
        for &(r, id) in &self.types.name_index {
            check_str("name index", r)?;
            check_ty("name index", id)?;
            let name = self.strings.get(r).unwrap();
            if prev.is_some_and(|p| p > name) {
                return corrupt(format!("name index not sorted at {name:?}"));
            }
            prev = Some(name);
        }

        for (sym, id) in &self.tasks.by_symbol {
            if sym != strip_llvm_suffix(sym) {
                return corrupt(format!("task table key {sym:?} has .llvm suffix"));
            }
            if (id.0 as usize) >= self.tasks.entries.len() {
                return corrupt(format!("task table: entry id {} out of range", id.0));
            }
        }
        for (i, e) in self.tasks.entries.iter().enumerate() {
            let what = &format!("task entry {i}");
            check_ty(what, e.future)?;
            check_ty(what, e.cell)?;
            check_ty(what, e.stage)?;
            check_ty(what, e.scheduler)?;
            check_str(what, e.display_name)?;
        }

        for (sym, id) in &self.dyn_futures.by_symbol {
            if sym != strip_llvm_suffix(sym) {
                return corrupt(format!("dyn future key {sym:?} has .llvm suffix"));
            }
            check_ty("dyn future table", *id)?;
        }

        let StaticsTable { entries: _ } = &self.statics; // plain strings, nothing to check

        let infra = &self.infra;
        for (what, id) in [
            ("infra.header", infra.header),
            ("infra.vtable", infra.vtable),
            ("infra.trailer", infra.trailer),
            ("infra.context", infra.context),
            ("infra.scheduler_handle", infra.scheduler_handle),
            ("infra.mt_handle", infra.mt_handle),
            ("infra.location", infra.location),
            ("infra.raw_waker_vtable", infra.raw_waker_vtable),
        ] {
            check_ty(what, id)?;
        }

        if self.provenance.entries.len() != self.tasks.entries.len() {
            return corrupt(format!(
                "provenance has {} entries for {} task entries",
                self.provenance.entries.len(),
                self.tasks.entries.len()
            ));
        }
        for (i, p) in self.provenance.entries.iter().enumerate() {
            if let Some(loc) = &p.decl {
                check_str(&format!("provenance {i}"), loc.file)?;
            }
        }

        Ok(())
    }
}
