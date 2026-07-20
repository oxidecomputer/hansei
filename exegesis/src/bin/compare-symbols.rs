//! Compare exact and crate-disambiguator-independent v0 symbol names.

use exegesis::symbols::{NormalizedSymbols, normalized_symbol_index};

use clap::Parser;
use object::{Object, ObjectSymbol};

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

#[derive(Parser)]
struct Args {
    /// First ELF or Mach-O binary.
    left: PathBuf,
    /// Second ELF or Mach-O binary.
    right: PathBuf,
    /// Retain only normalized names containing this text.
    #[arg(long)]
    filter: Option<String>,
    /// Print this many representative ambiguous buckets.
    #[arg(long, default_value_t = 0)]
    show_ambiguous: usize,
}

fn read_symbols(path: &Path) -> Result<NormalizedSymbols, Box<dyn std::error::Error>> {
    let bytes = std::fs::read(path)?;
    let object = object::File::parse(&*bytes)?;
    Ok(normalized_symbol_index(
        object
            .symbols()
            .chain(object.dynamic_symbols())
            .filter_map(|symbol| symbol.name().ok()),
    ))
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    let mut left_index = read_symbols(&args.left)?;
    let mut right_index = read_symbols(&args.right)?;
    if let Some(filter) = &args.filter {
        left_index.retain(|key, _| key.contains(filter));
        right_index.retain(|key, _| key.contains(filter));
    }
    let left_raw: BTreeSet<&str> = left_index.values().flatten().map(String::as_str).collect();
    let right_raw: BTreeSet<&str> = right_index.values().flatten().map(String::as_str).collect();

    let exact = left_raw.intersection(&right_raw).count();
    let normalized = left_index
        .keys()
        .filter(|key| right_index.contains_key(*key))
        .count();
    let left_collisions = left_index
        .values()
        .filter(|values| values.len() > 1)
        .count();
    let right_collisions = right_index
        .values()
        .filter(|values| values.len() > 1)
        .count();
    let ambiguous_matches = left_index
        .iter()
        .filter(|(key, left)| {
            right_index
                .get(*key)
                .is_some_and(|right| left.len() > 1 || right.len() > 1)
        })
        .count();

    println!(
        "left:               {} v0 symbols, {} normalized keys",
        left_raw.len(),
        left_index.len()
    );
    println!(
        "right:              {} v0 symbols, {} normalized keys",
        right_raw.len(),
        right_index.len()
    );
    println!("exact raw matches:  {exact}");
    println!("normalized matches: {normalized}");
    println!("left collisions:    {left_collisions}");
    println!("right collisions:   {right_collisions}");
    println!("ambiguous matches:  {ambiguous_matches}");

    for (key, left) in left_index
        .iter()
        .filter(|(key, left)| {
            right_index
                .get(*key)
                .is_some_and(|right| left.len() > 1 || right.len() > 1)
        })
        .take(args.show_ambiguous)
    {
        let right = &right_index[key];
        println!("\n{key}");
        print_bucket("left", left);
        print_bucket("right", right);
    }
    Ok(())
}

fn print_bucket(label: &str, symbols: &[String]) {
    println!("  {label} ({}):", symbols.len());
    for symbol in symbols.iter().take(4) {
        println!("    {symbol}");
    }
    if symbols.len() > 4 {
        println!("    ... {} more", symbols.len() - 4);
    }
}
