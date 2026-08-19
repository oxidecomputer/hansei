//! genfix — emit a generated census fixture program.
//!
//! `genfix --seed N` prints a complete `test-programs` fixture source
//! to stdout: a seeded random combinator tree over the shapes the
//! future census walks, registering its own ground truth through
//! `census_expect` as it builds. The soak loop
//! (`test-programs/genfix/soak.sh`) writes it into
//! `test-programs/src/bin/`, captures a snapshot pair from it, and
//! diffs the census against the registry; a deterministically failing
//! seed's source is checked in as a quarantined fixture.

mod emit;
mod tree;

fn main() {
    let mut args = std::env::args().skip(1);
    let mut seed: Option<u64> = None;
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--seed" => {
                let value = args.next().unwrap_or_else(|| usage("--seed needs a value"));
                seed = Some(
                    value
                        .parse()
                        .unwrap_or_else(|_| usage("--seed takes an unsigned integer")),
                );
            }
            other => usage(&format!("unknown argument `{other}`")),
        }
    }
    let Some(seed) = seed else {
        usage("--seed is required");
    };
    print!("{}", emit::emit(&tree::generate(seed)));
}

fn usage(problem: &str) -> ! {
    eprintln!("genfix: {problem}\nusage: genfix --seed N");
    std::process::exit(2);
}
