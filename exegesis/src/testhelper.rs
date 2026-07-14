use gimli::{EndianSlice, RunTimeEndian};
use object::read::archive::ArchiveFile;
use object::{Object, ObjectSection, ObjectSymbol, RelocationKind, RelocationTarget};
use tempfile::TempDir;

use std::borrow::Cow;
use std::fs;
use std::path::Path;
use std::process::Command;
use std::sync::OnceLock;

// 1.97.0: first release with v0 symbol mangling by default, so linkage
// names in fixtures match what the bundle join tables will see. Bumping
// the pin is a deliberate change — these tests double as the canary for
// DWARF-shape and mangling drift across toolchains.
const TOOLCHAIN: &str = r#"
[toolchain]
channel = "1.97.0"
profile = "default"
"#;

const SHARED_PROJ: &str = "testlib";
const SHARED_SRC: &str = r##"
#![no_std]

pub mod qux {
    #[derive(Debug)]
    pub struct Foo<T> {
        a: T,
        b: T,
    }

    static X: u32 = 5;

    pub fn bar(x: &Foo<u64>) -> u64 {
        let a = X;
        let b = x.a + x.b + a as u64;
        b
    }
}

pub mod shapes {
    #[repr(C)]
    pub struct Point {
        pub x: i32,
        pub y: i32,
    }

    #[repr(C)]
    pub struct Mixed {
        pub flag: bool,
        pub count: u32,
        pub value: f64,
        pub letter: u8,
    }

    pub struct Wrapper {
        pub inner: *const Point,
    }

    unsafe impl Sync for Wrapper {}

    pub struct Empty;

    pub static GLOBAL_COUNT: u32 = 42;
    pub static ORIGIN: Point = Point { x: 0, y: 0 };
    pub static MIXED: Mixed = Mixed { flag: true, count: 1, value: 2.0, letter: b'a' };
    pub static WRAP: Wrapper = Wrapper { inner: core::ptr::null() };
    pub static EMPTY: Empty = Empty;

    pub fn add_points(a: &Point, b: &Point) -> Point {
        Point {
            x: a.x + b.x,
            y: a.y + b.y,
        }
    }

    pub fn noop() {}

    pub fn multi_param(flag: bool, count: u32, value: f64) -> bool {
        if flag { count > 0 } else { value > 0.0 }
    }
}

pub mod outer {
    pub mod inner {
        pub struct Deep {
            pub val: u64,
        }

        pub static DEEP_VAL: u64 = 99;
        pub static DEEP_S: Deep = Deep { val: 1 };

        pub fn deep_fn(x: u64) -> u64 {
            x + 1
        }
    }
}

pub mod enums {
    /// Enum with payload variants (tuple + struct).
    pub enum Shape {
        Circle(f64),
        Rect { w: f64, h: f64 },
    }

    /// Single-variant enum.
    pub enum Single {
        Only(u64),
    }

    /// Multi-variant enum with mixed payloads. At least one variant
    /// must carry data so rustc emits DW_TAG_structure_type with
    /// DW_TAG_variant_part (rather than DW_TAG_enumeration_type).
    pub enum Message {
        Quit(u8),
        Echo(u64),
        Move { x: i32, y: i32 },
    }

    /// Niche-optimized enum with a u128 payload.
    pub enum Large {
        Empty,
        Big(u128),
    }

    /// repr(u8) enum with payloads: forces the discriminant type to u8
    /// while keeping it a tagged union in DWARF.
    #[repr(u8)]
    pub enum SmallTagged {
        A(u32) = 0,
        B(u64) = 1,
    }

    /// Niche-optimized enum: Option<&T> uses the null pointer as the
    /// None discriminant, so the variant_part has no DW_TAG_member for
    /// the discriminant.
    pub struct NicheHolder {
        pub opt_ref: core::option::Option<core::num::NonZeroU64>,
    }

    /// C-style enum: all unit variants, no payloads.
    pub enum Color {
        Red,
        Green,
        Blue,
    }

    /// C-style enum with explicit repr and values.
    #[repr(u8)]
    pub enum SmallEnum {
        A = 0,
        B = 1,
        C = 2,
    }

    // Force DWARF emission with statics.
    pub static SHAPE: Shape = Shape::Circle(1.0);
    pub static SINGLE: Single = Single::Only(42);
    pub static MESSAGE: Message = Message::Quit(0);
    pub static LARGE: Large = Large::Big(u128::MAX);
    pub static SMALL_TAGGED: SmallTagged = SmallTagged::A(1);
    pub static COLOR: Color = Color::Red;
    pub static SMALL: SmallEnum = SmallEnum::A;
    pub static NICHE: NicheHolder = NicheHolder {
        opt_ref: core::option::Option::None,
    };
}

pub mod generics {
    pub struct Pair<A, B> {
        pub first: A,
        pub second: B,
    }

    pub enum Either<L, R> {
        Left(L),
        Right(R),
    }

    pub fn swap<A, B>(p: Pair<A, B>) -> Pair<B, A> {
        Pair { first: p.second, second: p.first }
    }

    pub static PAIR: Pair<u32, u64> = Pair { first: 1, second: 2 };
    pub static EITHER: Either<u32, u64> = Either::Left(1);

    // Forces monomorphization of swap::<u32, u64>.
    pub fn use_swap() -> Pair<u64, u32> {
        swap(Pair { first: 3, second: 4 })
    }
}

pub mod blobs {
    /// A plain union, plus a generic one to carry template params.
    pub union IntOrFloat {
        pub i: u32,
        pub f: f32,
    }

    pub union Slot<T: Copy> {
        pub empty: (),
        pub value: T,
    }

    /// Arrays as members, in two sizes plus a repeated element type to
    /// exercise array dedup by (element, count).
    pub struct Buffers {
        pub bytes: [u8; 16],
        pub more_bytes: [u8; 16],
        pub words: [u64; 3],
    }

    pub static EITHER_NUM: IntOrFloat = IntOrFloat { i: 7 };
    pub static SLOT: Slot<u32> = Slot { value: 5 };
    pub static BUFS: Buffers = Buffers {
        bytes: [0; 16],
        more_bytes: [1; 16],
        words: [2; 3],
    };
    pub static RAW_TABLE: [u32; 4] = [1, 2, 3, 4];
}

pub mod asyncs {
    /// Leaf async fn: no awaits, but still compiled to a coroutine type.
    pub async fn leaf(x: u32) -> u32 {
        x + 1
    }

    /// One await point; its coroutine holds leaf's env as an __awaitee.
    pub async fn chain(x: u32) -> u32 {
        leaf(x).await + 1
    }

    // Forces codegen of both async state machines.
    pub fn make() -> impl core::future::Future<Output = u32> {
        chain(5)
    }
}
"##;

/// The fixture source, for tests that assert on declaration coordinates.
pub fn shared_src() -> &'static str {
    SHARED_SRC
}

/// Scaffold a Rust lib crate, write the given source, and build it.
///
/// Returns the `TempDir` whose path contains `proj_name/target/debug/deps/`.
pub fn build_lib(proj_name: &str, src: &str) -> TempDir {
    let t = TempDir::new().unwrap();
    let new_status = Command::new("cargo")
        .current_dir(t.path())
        .arg("new")
        .arg("--lib")
        .arg("--quiet")
        .arg(proj_name)
        .status()
        .unwrap();
    assert!(new_status.success());

    fs::write(t.path().join(proj_name).join("src").join("lib.rs"), src).unwrap();
    fs::write(
        t.path().join(proj_name).join("rust-toolchain.toml"),
        TOOLCHAIN,
    )
    .unwrap();

    // Force a single codegen unit so all types land in one .o file.
    let cargo_toml = t.path().join(proj_name).join("Cargo.toml");
    let mut manifest = fs::read_to_string(&cargo_toml).unwrap();
    manifest.push_str("\n[profile.dev]\ncodegen-units = 1\n");
    fs::write(&cargo_toml, manifest).unwrap();

    let build_status = Command::new("cargo")
        .current_dir(t.path().join(proj_name))
        .arg("build")
        .arg("--quiet")
        .status()
        .unwrap();
    assert!(build_status.success());

    t
}

/// Extract the `.o` bytes from the `.rlib` in `base/proj_name/target/debug/deps/`.
///
/// Library crates produce an `.rlib` (an `ar` archive containing `.o`
/// files). The `.o` files always contain DWARF on every platform —
/// split-debuginfo only affects linked binaries, so no platform-specific
/// handling is needed here.
pub fn read_rlib_object(base: &Path, proj_name: &str) -> Vec<u8> {
    let deps_dir = base
        .join(proj_name)
        .join("target")
        .join("debug")
        .join("deps");
    let prefix = format!("lib{proj_name}-");

    let rlib_path = fs::read_dir(&deps_dir)
        .unwrap()
        .filter_map(|e| e.ok())
        .find(|e| {
            let name = e.file_name();
            let name = name.to_string_lossy();
            name.starts_with(&prefix) && name.ends_with(".rlib")
        })
        .unwrap_or_else(|| panic!("no .rlib found in {}", deps_dir.display()))
        .path();

    let rlib_data = fs::read(&rlib_path).unwrap();
    let archive = ArchiveFile::parse(&*rlib_data).unwrap();

    for member in archive.members() {
        let member = member.unwrap();
        let name = String::from_utf8_lossy(member.name());
        if name.ends_with(".o") || name.ends_with(".obj") {
            return member.data(&*rlib_data).unwrap().to_vec();
        }
    }

    panic!("no object file found in {}", rlib_path.display());
}

static SHARED_OBJ_BYTES: OnceLock<Vec<u8>> = OnceLock::new();

fn shared_obj_bytes() -> &'static [u8] {
    SHARED_OBJ_BYTES.get_or_init(|| {
        let t = build_lib(SHARED_PROJ, SHARED_SRC);
        read_rlib_object(t.path(), SHARED_PROJ)
    })
}

/// Owns the parsed DWARF sections and provides a `Dwarf` view on demand.
pub struct TestDwarf {
    dwarf_sections: gimli::DwarfSections<Cow<'static, [u8]>>,
    endian: RunTimeEndian,
}

impl TestDwarf {
    pub fn dwarf(&self) -> gimli::Dwarf<EndianSlice<'_, RunTimeEndian>> {
        self.dwarf_sections
            .borrow(|section| EndianSlice::new(Cow::as_ref(section), self.endian))
    }
}

/// Resolve the relocations of a debug section in an ELF relocatable object.
///
/// In ELF `.o` files, cross-section DWARF references (e.g. `DW_FORM_strp`
/// offsets into `.debug_str`) are zero-filled placeholders paired with
/// `.rela.debug_*` entries; without applying them every name resolves to
/// offset 0. Mach-O objects carry resolved values, so this is ELF-only.
fn apply_relocations<'d>(
    obj: &object::File,
    section: &object::Section,
    data: Cow<'d, [u8]>,
) -> Cow<'d, [u8]> {
    let mut relocations = section.relocations().peekable();
    if relocations.peek().is_none() {
        return data;
    }

    let le = obj.is_little_endian();
    let mut bytes = data.into_owned();
    for (offset, reloc) in relocations {
        if reloc.kind() != RelocationKind::Absolute {
            continue;
        }
        let base = match reloc.target() {
            RelocationTarget::Symbol(idx) => {
                obj.symbol_by_index(idx).map(|s| s.address()).unwrap_or(0)
            }
            RelocationTarget::Section(idx) => {
                obj.section_by_index(idx).map(|s| s.address()).unwrap_or(0)
            }
            _ => continue,
        };
        let value = base.wrapping_add(reloc.addend() as u64);
        let offset = offset as usize;
        match reloc.size() {
            32 => {
                if let Some(b) = bytes.get_mut(offset..offset + 4) {
                    let v = value as u32;
                    b.copy_from_slice(&if le { v.to_le_bytes() } else { v.to_be_bytes() });
                }
            }
            64 => {
                if let Some(b) = bytes.get_mut(offset..offset + 8) {
                    b.copy_from_slice(&if le {
                        value.to_le_bytes()
                    } else {
                        value.to_be_bytes()
                    });
                }
            }
            _ => {}
        }
    }
    Cow::Owned(bytes)
}

fn make_test_dwarf(obj_bytes: &'static [u8]) -> TestDwarf {
    let obj = object::File::parse(obj_bytes).unwrap();
    let endian = if obj.is_little_endian() {
        RunTimeEndian::Little
    } else {
        RunTimeEndian::Big
    };
    let is_elf = matches!(obj.format(), object::BinaryFormat::Elf);

    let load_section = |id: gimli::SectionId| -> std::result::Result<Cow<'static, [u8]>, Box<dyn std::error::Error>> {
        Ok(match obj.section_by_name(id.name()) {
            Some(section) => {
                let data = section.uncompressed_data()?;
                if is_elf {
                    apply_relocations(&obj, &section, data)
                } else {
                    data
                }
            }
            None => Cow::Borrowed(&[]),
        })
    };

    let dwarf_sections = gimli::DwarfSections::load(load_section).unwrap();
    TestDwarf {
        dwarf_sections,
        endian,
    }
}

/// Build the shared test artifact once and return a `TestDwarf` from the
/// cached object bytes. Call `.dwarf()` on the result to get a
/// `gimli::Dwarf` reference.
pub fn get_test_dwarf() -> TestDwarf {
    make_test_dwarf(shared_obj_bytes())
}
