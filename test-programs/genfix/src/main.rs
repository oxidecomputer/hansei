// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

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
//!
//! `--churn` emits the same tree as a workload that never settles —
//! every future completes shortly and is rebuilt, nothing registers —
//! for the churn capture loop (`test-programs/genfix/churn.sh`), whose
//! captures are taken at arbitrary instants and judged by the safety
//! oracle alone.

mod emit;
mod tree;

fn main() {
    let mut args = std::env::args().skip(1);
    let mut seed: Option<u64> = None;
    let mut mode = emit::Mode::Parked;
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
            "--churn" => mode = emit::Mode::Churn,
            other => usage(&format!("unknown argument `{other}`")),
        }
    }
    let Some(seed) = seed else {
        usage("--seed is required");
    };
    print!("{}", emit::emit(&tree::generate(seed), mode));
}

fn usage(problem: &str) -> ! {
    eprintln!("genfix: {problem}\nusage: genfix --seed N [--churn]");
    std::process::exit(2);
}
