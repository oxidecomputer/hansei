//! The `print` command: memory at an address rendered as a named type
//! — the inverse of `whatis`, for reading a structure the listings only
//! point at.

use crate::{RenderOpts, Session, types};

use anyhow::{Context as _, Result};

use std::io;

/// Read one value of `spec`'s type at `addr` and render it the way
/// every other value is rendered. The address says where and the type
/// says how, and nothing checks one against the other: printing the
/// wrong type at an address renders that memory as the type asked for,
/// which is sometimes exactly the point.
pub(crate) fn exec_print<T: proc::Target>(
    session: &Session<'_, T>,
    addr: u64,
    spec: &str,
    render: RenderOpts,
    out: &mut dyn io::Write,
) -> Result<()> {
    let ctx = &session.ctx;
    let ty = types::resolve_type_spec(&ctx.view, &session.impl_fold, spec)?;
    let value = reify::Value::read(ctx.proc, ty, addr).with_context(|| {
        format!(
            "failed to read the {} byte(s) of {} at {addr:#x}",
            ty.size(),
            ty.name()
        )
    })?;
    let mut disp = value
        .display_from_target(ctx.proc, render.depth)
        .max_str_len(Some(render.max_string_len))
        .max_array_len(Some(render.max_array_values));
    let heap = session.heap_view();
    if let Some(view) = &heap {
        disp = disp.heap(view);
    }
    if render.ugly {
        disp = disp.ugly();
    }
    writeln!(out, "{disp:#}")?;
    Ok(())
}
