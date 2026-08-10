// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Print the walk-contract report for a bundle: which navigation paths
//! resolve against its type graph, which alternative spellings bound,
//! and what is absent or broken. Runs anywhere a bundle loads — no
//! target process needed.
//!
//! Usage: `cargo run -p hansei-runtime --example contract_report -- <bundle>`

use exegesis::bundle::{Bundle, BundleView};
use hansei_runtime::tokio::contract::verify_walk_contract;

fn main() -> anyhow::Result<()> {
    let path = std::env::args()
        .nth(1)
        .ok_or_else(|| anyhow::anyhow!("usage: contract_report <bundle>"))?;
    let bundle = Bundle::load(std::path::Path::new(&path))?;
    let view = BundleView::new(&bundle);
    print!("{}", verify_walk_contract(&view));
    Ok(())
}
