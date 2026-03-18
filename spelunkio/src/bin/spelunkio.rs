// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use anyhow::Result;
use camino::Utf8PathBuf;
use clap::Parser;

#[derive(Parser)]
#[command(about = "Interactive corefile explorer")]
struct Args {
    /// Path to the core file.
    corefile: Utf8PathBuf,
    /// Path to the ELF binary.
    elf_binary: Utf8PathBuf,
}

fn main() -> Result<()> {
    let args = Args::parse();
    let dbg = spelunkio::Dbg::new(args.corefile, args.elf_binary)?;
    spelunkio::run(dbg)
}
