use felak::DwReader;

use tracing_subscriber::{EnvFilter, fmt, prelude::*};

use gimli::RunTimeEndian;
use memmap2::Mmap;
use mimalloc::MiMalloc;
use object::{Object, ObjectSection};

use std::borrow::Cow;
use std::env;
use std::fs::File;

#[global_allocator]
static GLOBAL: MiMalloc = MiMalloc;

fn main() {
    tracing_subscriber::registry()
        .with(fmt::layer())
        .with(EnvFilter::from_default_env())
        .init();

    let args: Vec<_> = env::args().collect();
    let path = &args[1];
    let f = File::open(path).unwrap();
    let obj_bytes = unsafe { Mmap::map(&f) }.unwrap();

    let obj = object::File::parse(&*obj_bytes).unwrap();
    let endian = if obj.is_little_endian() {
        RunTimeEndian::Little
    } else {
        RunTimeEndian::Big
    };

    let load_section =
        |id: gimli::SectionId| -> std::result::Result<Cow<[u8]>, Box<dyn std::error::Error>> {
            Ok(match obj.section_by_name(id.name()) {
                Some(section) => section.uncompressed_data()?,
                None => Cow::Borrowed(&[]),
            })
        };

    let borrow_section = |section| gimli::EndianSlice::new(Cow::as_ref(section), endian);

    let dwarf_sections = gimli::DwarfSections::load(&load_section).unwrap();
    let dwarf = dwarf_sections.borrow(borrow_section);

    let dw = DwReader::read_types(&dwarf, Default::default()).unwrap();
    println!("{} total types", dw.types.len());
    println!("{} total statics", dw.variables.len());
    // for s in &ty.variables {
    //     dbg!(s);
    // }
    println!("{} dup strings", dw.strings.dups_found());
    println!("{} total strings", dw.strings.len());

    let view = dw.view();
    let t = view
        .find_var("tokio::runtime::context::CONTEXT::{closure#0}::VAL")
        .unwrap();
    dbg!(t);
    dbg!(t.ty());
    for member in t.ty().members() {
        dbg!(member);
    }
    std::mem::forget(dw);
    //dbg!(ty);
}
