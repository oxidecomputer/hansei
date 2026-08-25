//! A typed view over a buffer of target memory: [`Value`] pairs a bundle
//! type with the bytes of one value and the address they were read from, and
//! navigates the value's structure -- members, pointees, array elements, enum
//! variants -- without rendering anything.
//!
//! The bytes are borrowed, never owned: every read the target serves is a
//! window into memory it already holds mapped (see
//! [`proc::Target::read_bytes`]), so a view costs a pointer
//! and a length and copies nothing.

use crate::debug_type::{DisplayNode, TypeKind, bundle_variant_error};
use crate::elements::Elements;
use crate::parse::ParseWithDbgInfo;
use crate::{Error, Result};
use proc::Target;

use hansei_bundle::{BundleType, BundleTypeId, VariantError};

use foldhash::HashMap;
use std::fmt;
use std::rc::Rc;

/// Memos for a walk that reads many values through their display
/// programs — a recorded walk visits millions of values but only
/// thousands of distinct types and a handful of vtables:
///
/// - the *resolved* display node per type, so selector resolution runs
///   once per type instead of once per value (the parse-path analog of
///   the renderer's format cache);
/// - the concrete pointee type per vtable address, so the symbol
///   resolution and demangling behind the dyn join run once per vtable
///   instead of once per trait-object value.
///
/// Owned by the walk, passed to the `*_with` readers on [`Value`].
#[derive(Default)]
pub struct WalkCache<'a> {
    pub(crate) nodes: HashMap<BundleTypeId, Option<Rc<DisplayNode<'a>>>>,
    pub(crate) pointees: HashMap<u64, Option<BundleTypeId>>,
}

impl<'a> WalkCache<'a> {
    pub fn new() -> Self {
        Self::default()
    }

    /// The resolved display node for `ty`, memoized — negative answers
    /// included.
    pub(crate) fn node(&mut self, ty: BundleType<'a>) -> Option<Rc<DisplayNode<'a>>> {
        self.nodes
            .entry(ty.id())
            .or_insert_with(|| DisplayNode::resolve(ty).map(Rc::new))
            .clone()
    }
}

#[derive(Copy, Clone)]
pub struct Value<'a> {
    pub ty: BundleType<'a>,
    pub addr: u64,
    pub bytes: &'a [u8],
}

impl<'a> Eq for Value<'a> {}

impl<'a> PartialEq for Value<'a> {
    fn eq(&self, other: &Self) -> bool {
        self.ty == other.ty && self.addr == other.addr && self.bytes == other.bytes
    }
}

impl<'a> Value<'a> {
    /// Wrap an already-read buffer. Useful when the bytes come from
    /// somewhere other than an open target (tests, byte fixtures).
    pub fn new(ty: BundleType<'a>, addr: u64, bytes: &'a [u8]) -> Self {
        Self { ty, addr, bytes }
    }

    /// Read the type directly at the address provided.
    pub fn read<T: Target>(proc: &'a T, ty: BundleType<'a>, addr: u64) -> Result<Self> {
        let bytes = crate::target::read_bytes(proc, addr, ty.size())?;

        Ok(Self { ty, addr, bytes })
    }

    /// The `ty`-typed view at `offset` within this value — the slicing every
    /// member access, variant selection and decode shares. Fails when the
    /// value's bytes do not cover the range; the view comes back unpeeled.
    fn view_at(&self, offset: u64, ty: BundleType<'a>) -> Result<Value<'a>> {
        let bytes = usize::try_from(offset)
            .ok()
            .zip(usize::try_from(ty.size()).ok())
            .and_then(|(start, size)| self.bytes.get(start..start.checked_add(size)?));
        let Some(bytes) = bytes else {
            return Err(Error::invalid_member_range(
                offset,
                offset.saturating_add(ty.size()),
                self.bytes.len() as u64,
            ));
        };
        Ok(Value {
            ty,
            addr: self.addr + offset,
            bytes,
        })
    }

    pub fn try_member(&self, name: &str) -> Result<Option<Value<'a>>> {
        let Some(member) = self.ty.member(name) else {
            return Ok(None);
        };
        Ok(Some(self.view_at(member.offset(), member.ty())?.peel()))
    }

    pub fn member(&self, name: &str) -> Result<Value<'a>> {
        let Some(member) = self.try_member(name)? else {
            return Err(Error::no_member(
                self.ty.name().to_string(),
                name.to_string(),
            ));
        };

        Ok(member)
    }

    /// The pointee, read from the target and peeled. A read the target
    /// refuses is an error naming the pointee's address — the address that
    /// failed — not this value's own.
    pub fn deref_ptr<T: Target>(&self, proc: &'a T) -> Result<Value<'a>> {
        let Some(target_ty) = self.peel().ty.pointer_target() else {
            return Err(Error::unexpected_type(
                self.ty.kind(),
                TypeKind::Pointer,
                format!("{} ({:?})", self.ty.name(), self.ty),
            ));
        };

        let Some(&bytes) = self.bytes.first_chunk::<8>() else {
            return Err(Error::unexpected_len(self.bytes.len() as u32, 8));
        };

        let addr = u64::from_le_bytes(bytes);
        let bytes = crate::target::read_bytes(proc, addr, target_ty.size())?;

        // Remove any wrapper types.
        Ok(Value {
            ty: target_ty,
            addr,
            bytes,
        }
        .peel())
    }

    pub fn is_enum(&self) -> bool {
        self.ty.active_variant(self.bytes).is_some()
    }

    pub fn try_select_variant(&self, name: &str) -> Result<Option<Value<'a>>> {
        let Some(result) = self.ty.check_variant(self.bytes, name) else {
            return Err(Error::not_an_enum(self.ty.name().to_string()));
        };
        let Some((var_ty, offset)) = result.map_err(|e| match e {
            VariantError::NoSuchVariant => {
                Error::no_variant(self.ty.name().to_string(), name.to_string())
            }
            other => bundle_variant_error(&self.ty, other),
        })?
        else {
            return Ok(None);
        };

        Ok(Some(self.view_at(offset, var_ty)?.peel()))
    }

    pub fn select_variant(&self, name: &str) -> Result<Value<'a>> {
        let Some(info) = self.try_select_variant(name)? else {
            return Err(Error::unexpected_variant(name.to_string()));
        };

        Ok(info)
    }

    // `impl Target` rather than a named parameter so `parse::<u64>(…)`
    // keeps naming only `V`: turbofish must supply every named generic.
    pub fn parse<V: ParseWithDbgInfo<'a>>(&self, proc: &'a impl Target) -> Result<V> {
        V::parse_with_dbg(proc, self).map_err(|e| Error::parse_type(self.ty.name()).with_source(e))
    }

    /// The elements of a sequence-shaped value — an owned `Vec`, a boxed or
    /// borrowed slice, an inline array — read and addressed; see
    /// [`Elements`].
    pub fn elements<T: Target>(&self, proc: &'a T) -> Result<Elements<'a>> {
        Elements::of(self, proc)
    }

    /// The UTF-8 buffer behind a string-shaped value — a `String`, a `&str`,
    /// an owned path — as `(base address, bytes served, length claimed
    /// beyond them)`. Same header validation as [`Value::elements`], and the
    /// same refusal to believe a length further than the target corroborates
    /// it: the claim is `Some` exactly when the buffer came up short.
    pub fn utf8_buffer<T: Target>(&self, proc: &'a T) -> Result<(u64, &'a [u8], Option<u64>)> {
        let (base, buffer) = crate::elements::utf8(self, proc)?;
        Ok((base, buffer.bytes, buffer.claimed))
    }

    /// A trait-object wide pointer's concrete pointee: the type recovered
    /// from the vtable's function symbols (corroborated against the vtable's
    /// size word) and the address the erased value lives at — past the sized
    /// header when the pointer targets an unsized wrapper such as
    /// `ArcInner<dyn Trait>`. `None` whenever the answer would be a guess:
    /// no `DynPointer` display program on the type, a null or unreadable
    /// pointer or vtable, disagreeing or unresolvable symbols, or a
    /// zero-sized concrete type.
    pub fn dyn_pointee<T: Target>(&self, proc: &'a T) -> Option<(BundleType<'a>, u64)> {
        self.dyn_pointee_with(proc, &mut WalkCache::new())
    }

    /// [`Value::dyn_pointee`], memoized through `cache`: the node
    /// resolution per type, and the whole symbol join per vtable address —
    /// one vtable always erases the same concrete type.
    pub fn dyn_pointee_with<T: Target>(
        &self,
        proc: &'a T,
        cache: &mut WalkCache<'a>,
    ) -> Option<(BundleType<'a>, u64)> {
        crate::render::dyn_pointee_cached(self, proc, cache)
    }

    /// [`Value::elements`], with the display-program resolution memoized
    /// through `cache`.
    pub fn elements_with<T: Target>(
        &self,
        proc: &'a T,
        cache: &mut WalkCache<'a>,
    ) -> Result<Elements<'a>> {
        let node = cache.node(self.ty);
        Elements::with_node(self, proc, node.as_deref())
    }

    /// [`Value::utf8_buffer`], with the display-program resolution
    /// memoized through `cache`.
    pub fn utf8_buffer_with<T: Target>(
        &self,
        proc: &'a T,
        cache: &mut WalkCache<'a>,
    ) -> Result<(u64, &'a [u8], Option<u64>)> {
        let node = cache.node(self.ty);
        let (base, buffer) = crate::elements::utf8_with_node(self, proc, node.as_deref())?;
        Ok((base, buffer.bytes, buffer.claimed))
    }

    /// The active variant and its payload as declared — no peel. A
    /// caller that classifies values by their own type must see
    /// `Some(JoinSet<_>)` as the `Some` struct carrying a `JoinSet`:
    /// [`Self::active_variant`]'s peel descends single-sized-member
    /// wrappers, which walks straight *through* a `JoinSet` or
    /// `Receiver` payload into its interior before any name test can
    /// run.
    pub fn active_variant_raw(&self) -> Result<(&'a str, Value<'a>)> {
        let active = self
            .ty
            .active_variant(self.bytes)
            .ok_or_else(|| Error::not_an_enum(self.ty.name().to_string()))?
            .map_err(|e| bundle_variant_error(&self.ty, e))?;

        Ok((active.name, self.view_at(active.offset, active.ty)?))
    }

    pub fn active_variant(&self) -> Result<(&'a str, Value<'a>)> {
        let (name, payload) = self.active_variant_raw()?;
        Ok((name, payload.peel()))
    }

    /// Check if the type is a wrapper struct, and return its inner type if it
    /// is. These are defined as a struct with only a single sized member. The
    /// buffer will be adjusted if the member is smaller than the parent
    /// struct.
    ///
    /// Peeling stops early at a member the buffer cannot cover, returning the
    /// outermost type whose bytes are intact rather than descending past the
    /// end of the value.
    pub fn peel(self) -> Value<'a> {
        let mut info = self;

        loop {
            // A type whose own display format is a leaf (a `Str`, a `Slice`, …)
            // must render through that format, not be peeled into its
            // representation. Without this, a `String`/`Utf8PathBuf` payload — a
            // single-member wrapper around `Vec<u8>` — peels past its `Str`
            // format down to the inner `Vec`, rendering as a byte slice instead
            // of a string. A transparent `Alias` format is not a leaf, so peeling
            // still descends through atomics and newtype wrappers.
            if info.ty.is_display_leaf() {
                break;
            }

            if info.ty.kind() != TypeKind::Struct {
                break;
            }

            let members = info.ty.members();

            // Zero-sized struct members have no impact on memory layout
            // and can be ignored. Check if there is only one sized member, and
            // peel to it if yes.
            let mut iter = members.map(|m| (m, m.ty())).filter(|(_m, t)| t.size() > 0);

            let (member, mem_ty) = match (iter.next(), iter.next()) {
                (Some((member, mem_ty)), None) => (member, mem_ty),
                _ => break,
            };

            let start = member.offset() as usize;
            let end = start + mem_ty.size() as usize;

            // A member the buffer does not cover means the bytes in hand are
            // not the whole value — a short read, most often. Stop at the
            // outermost type whose bytes are intact and let the caller see a
            // buffer too short for its type, which the renderer reports as
            // `<truncated>`.
            let Some(bytes) = info.bytes.get(start..end) else {
                break;
            };
            info.bytes = bytes;
            info.addr += start as u64;
            info.ty = mem_ty;
        }

        info
    }
}

impl<'a> fmt::Debug for Value<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Value")
            .field("ty", &self.ty)
            .field("addr", &format_args!("{:#x}", self.addr))
            .field("bytes", &self.bytes)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use crate::Value;
    use crate::testhelper::*;
    use crate::value::WalkCache;

    use hansei_bundle::{BundleView, TypeDef};

    /// The uncached readers answer exactly as their `_with` spellings do:
    /// `utf8_buffer` surfaces the buffer's base, the served bytes and the
    /// shortfall, and `dyn_pointee` resolves a trait object's concrete
    /// pointee — the plain spellings are the one-shot entries, so they
    /// must not drift from the memoized ones.
    #[test]
    fn test_utf8_buffer_and_dyn_pointee_read_uncached() {
        let mut b = test_bundle();
        let TypeDef::Array { count, .. } = &mut b.types.types[VTABLE_ARRAY.0 as usize] else {
            panic!("vtable is not an array");
        };
        *count = 4;
        b.validate().expect("expanded vtable must validate");
        let v = BundleView::new(&b);
        let mem = FakeMem::new()
            .at(0x2000, b"hello".to_vec())
            .at(0x1234, u32s(&[1, 2]))
            .at(0x3000, u64s(&[0, 8, 8, 0x4000]))
            .symbol(0x4000, "<Point as app::Trait>::run");

        // String { ptr, len, capacity }: base and bytes come back whole,
        // and a claim past what the target serves is reported, not
        // silently cut.
        let whole = u64s(&[0x2000, 5, 8]);
        let s = Value::new(v.ty(STRING).unwrap(), 0x1000, &whole);
        assert_eq!(s.utf8_buffer(&mem).unwrap(), (0x2000, &b"hello"[..], None));
        let short = u64s(&[0x2000, 500, 500]);
        let s = Value::new(v.ty(STRING).unwrap(), 0x1000, &short);
        assert_eq!(
            s.utf8_buffer(&mem).unwrap(),
            (0x2000, &b"hello"[..], Some(500))
        );

        // The dyn join: the vtable's method symbol names Point, the size
        // word corroborates it, and the pointee lands at the data pointer.
        let fat = u64s(&[0x1234, 0x3000]);
        let value = Value::new(v.ty(FAT_PTR).unwrap(), 0, &fat);
        let (concrete, addr) = value.dyn_pointee(&mem).expect("the join resolves");
        assert_eq!((concrete.name(), addr), ("Point", 0x1234));
        // And the memoized spelling answers the same through a cache.
        let mut cache = WalkCache::new();
        let (concrete, addr) = value.dyn_pointee_with(&mem, &mut cache).unwrap();
        assert_eq!((concrete.name(), addr), ("Point", 0x1234));
    }

    /// `peel` descends through single-member wrappers, and stops at the last
    /// type the buffer covers. A value read short must not take it past the end
    /// of the bytes in hand -- it used to slice unconditionally and panic.
    #[test]
    fn test_peel_stops_at_a_buffer_it_cannot_cover() {
        let b = test_bundle();
        let v = BundleView::new(&b);
        let wrap = v.ty(WRAP).unwrap();

        // `Wrap { inner: Point @0 }`, with all 8 bytes, peels to the Point.
        let full: Vec<u8> = [3u32, 4u32].iter().flat_map(|x| x.to_le_bytes()).collect();
        let peeled = Value::new(wrap, 0, &full).peel();
        assert_eq!(peeled.ty.name(), "Point");
        assert_eq!(format!("{}", peeled.display()), "Point { x: 3, y: 4 }");

        // Short of that, peeling stops at Wrap and the renderer reports the
        // buffer rather than reading past it.
        for len in 0..8 {
            let short = &full[..len];
            let peeled = Value::new(wrap, 0, short).peel();
            assert_eq!(peeled.ty.name(), "Wrap", "{len} bytes");
            assert_eq!(peeled.bytes.len(), len, "{len} bytes");
            assert_eq!(
                format!("{}", peeled.display()),
                "<truncated>",
                "{len} bytes"
            );
        }
    }

    /// A value read from the target lends the bytes the read served, and
    /// navigates them the same way one wrapped around bytes in hand does.
    #[test]
    fn test_a_value_reads_and_navigates() {
        let b = test_bundle();
        let v = BundleView::new(&b);
        let point_bytes = u32s(&[1, 2]);
        let mem = FakeMem::new().at(0x1000, point_bytes.clone());

        let info =
            Value::read(&mem, v.ty(POINT).unwrap(), 0x1000).expect("Point reads from the target");
        assert_eq!(info.addr, 0x1000);
        assert_eq!(info.bytes, &point_bytes[..]);
        assert_eq!(format!("{}", info.display()), "Point { x: 1, y: 2 }");

        // Members, sliced out of the bytes the read lent.
        assert_eq!(format!("{}", info.member("y").unwrap().display()), "2");
        assert!(info.try_member("nope").unwrap().is_none());
        assert!(info.member("nope").is_err());

        // A read that fails surfaces as an error rather than an empty value.
        let dead_mem = FakeMem::new().unreadable();
        assert!(Value::read(&dead_mem, v.ty(POINT).unwrap(), 0x1000).is_err());
    }

    /// Pointer and variant navigation from a value read at an address,
    /// including variant selection's `try_` spelling, which answers
    /// `Ok(None)` for an inactive variant rather than erroring.
    #[test]
    fn test_a_value_derefs_and_selects_variants() {
        let b = test_bundle();
        let v = BundleView::new(&b);
        let mem = FakeMem::new()
            .at(0x1000, u64s(&[0x2000]))
            .at(0x2000, u32s(&[3, 4]));

        // `*Point` at 0x1000 points at a Point at 0x2000.
        let ptr = Value::read(&mem, v.ty(PTR).unwrap(), 0x1000).unwrap();
        let pointee = ptr.deref_ptr(&mem).expect("deref reads the pointee");
        assert_eq!(pointee.addr, 0x2000);
        assert_eq!(format!("{}", pointee.display()), "Point { x: 3, y: 4 }");

        // A pointee the target refuses is an error naming the address that
        // failed, not the pointer's own location.
        let dead = FakeMem::new().unreadable();
        let err = ptr.deref_ptr(&dead).expect_err("unreadable pointee");
        assert!(format!("{err}").contains("0x2000"), "{err}");

        // Dereferencing something that is not a pointer is an error.
        let point = Value::read(&mem, v.ty(POINT).unwrap(), 0x2000).unwrap();
        assert!(point.deref_ptr(&mem).is_err());

        // Variant selection: Opt is a niche enum, so 42 is `Some`.
        let mem = FakeMem::new().at(0x3000, u64s(&[42]));
        let opt = Value::read(&mem, v.ty(OPT).unwrap(), 0x3000).unwrap();
        assert_eq!(
            format!("{}", opt.select_variant("Some").unwrap().display()),
            "42"
        );
        assert!(opt.try_select_variant("None").unwrap().is_none());
        // A name the enum does not have is an error, not an inactive variant.
        assert!(opt.select_variant("Nope").is_err());
    }

    /// Element iteration over an owned array, whose elements are its own
    /// bytes, and over a fat pointer, whose elements are read through the
    /// target -- one call for both.
    #[test]
    fn test_a_value_iterates_elements() {
        let b = test_bundle();
        let v = BundleView::new(&b);
        let mem = FakeMem::new()
            .at(0x1000, u32s(&[10, 20, 30]))
            .at(0x4000, u64s(&[0x5000, 3]))
            .at(0x5000, u32s(&[7, 8, 9]));

        let arr = Value::read(&mem, v.ty(ARR).unwrap(), 0x1000).unwrap();
        let elements = arr.elements(&mem).expect("array elements");
        assert_eq!(elements.len(), 3);
        assert_eq!(elements.truncated(), None);
        let shown: Vec<String> = elements
            .iter()
            .map(|e| format!("{}", e.display()))
            .collect();
        assert_eq!(shown, ["10", "20", "30"]);

        // The fixture's `&[u32]` is (data_ptr: *u8, length), byte-erased as a
        // `Vec`'s is; its elements are `u32` because its display program says
        // so, addressed from the buffer they were read from rather than from
        // the fat pointer.
        let slice = Value::read(&mem, v.ty(SLICE).unwrap(), 0x4000).unwrap();
        let seen: Vec<(u64, String)> = slice
            .elements(&mem)
            .expect("slice elements")
            .iter()
            .map(|e| (e.addr, format!("{}", e.display())))
            .collect();
        assert_eq!(
            seen,
            [
                (0x5000, "7".to_owned()),
                (0x5004, "8".to_owned()),
                (0x5008, "9".to_owned())
            ]
        );
    }

    /// A value parsed straight off an owned buffer.
    #[test]
    fn test_a_value_parses() {
        let b = test_bundle();
        let v = BundleView::new(&b);
        let mem = FakeMem::new().at(0x1000, u32s(&[1, 2]));
        let point = Value::read(&mem, v.ty(POINT).unwrap(), 0x1000).unwrap();
        assert_eq!(point.member("x").unwrap().parse::<u32>(&mem).unwrap(), 1);
        assert_eq!(point.parse::<u32>(&mem).ok(), None, "Point is not a u32");
    }

    /// A member past 64 KiB is sliced at its real offset. The member range
    /// used to be computed in `u16`, so an offset like `Big::tail`'s 0x10000
    /// wrapped to zero and the wrong bytes were served without an error.
    #[test]
    fn test_member_past_64k_is_sliced_at_its_real_offset() {
        let b = test_bundle();
        let v = BundleView::new(&b);
        let mut bytes = vec![0u8; 0x10004];
        bytes[0x10000..].copy_from_slice(&7u32.to_le_bytes());
        let big = Value::new(v.ty(BIG).unwrap(), 0x1000, &bytes);

        let tail = big.member("tail").expect("tail is addressable");
        assert_eq!(tail.addr, 0x1000 + 0x10000);
        assert_eq!(format!("{}", tail.display()), "7");

        // Short of the member, the range is reported rather than misread.
        let short = Value::new(v.ty(BIG).unwrap(), 0x1000, &bytes[..0x10000]);
        assert!(short.member("tail").is_err());
    }

    /// Equality and `Debug`, the two things a caller does with a view
    /// besides navigating it.
    #[test]
    fn test_values_compare_and_format() {
        let b = test_bundle();
        let v = BundleView::new(&b);
        let bytes = u32s(&[1, 2]);
        let point = Value::new(v.ty(POINT).unwrap(), 0x1000, &bytes);

        // Equality is over the type, address and bytes together.
        assert_eq!(point, Value::new(v.ty(POINT).unwrap(), 0x1000, &bytes));
        assert_ne!(point, Value::new(v.ty(POINT).unwrap(), 0x2000, &bytes));
        let other = u32s(&[9, 9]);
        assert_ne!(point, Value::new(v.ty(POINT).unwrap(), 0x1000, &other));

        // `Debug` shows the address in hex, unlike `Display`.
        let shown = format!("{point:?}");
        assert!(shown.contains("Value"), "{shown}");
        assert!(shown.contains("0x1000"), "{shown}");
    }
}
