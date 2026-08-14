//! The `runtime` command: a runtime's own state, read straight through
//! the bundle's layouts.

use crate::threads::render;
use crate::{RenderOpts, RuntimeField, Session};

use anyhow::Result;

use std::io;

/// Render one of the runtime handle's fields out of the target: the
/// scheduler state the workers share, or the drivers they park on.
///
/// Both are read straight through the bundle's layouts rather than into
/// a hand-written mirror of tokio's structs, so a field tokio adds shows
/// up without hansei being taught about it.
pub(crate) fn exec_runtime_field(
    session: &Session<'_>,
    field: RuntimeField,
    opts: RenderOpts,
    out: &mut dyn io::Write,
) -> Result<()> {
    let member = match field {
        RuntimeField::Drivers => "driver",
        RuntimeField::Shared => "shared",
    };
    // The bundle's `Elided` formats hide the runtime graph from *user*
    // values; these commands exist to show the runtime's own insides, so
    // they must never apply here — a new elided row must not be able to
    // blank part of this output.
    let no_elide = reify::ElideOverride {
        no_elide: true,
        types: Vec::new(),
    };
    // Both scheduler flavors' handles carry these members: one section
    // per discovered runtime, headed only when there is more than one.
    for (i, rt) in session.runtimes.iter().enumerate() {
        if session.runtimes.len() > 1 {
            if i > 0 {
                writeln!(out)?;
            }
            writeln!(out, "runtime {i} ({}):", rt.flavor)?;
        }
        let value = rt.handle.member(member)?;
        writeln!(
            out,
            "{:#}",
            render(session, &value, opts).elide_override(&no_elide)
        )?;
    }
    Ok(())
}
