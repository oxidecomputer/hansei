//! The `print` command: memory rendered as a typed value, and paths
//! into it — the answer to every `...` the renderer elides.

use crate::{RenderOpts, Session, cursor, types};

use anyhow::{Context as _, Result, anyhow, bail};
use reify::path::{Node, Resolved};

use std::io;

/// What the leading arguments named the root to be.
#[derive(Debug)]
enum Root<'w> {
    /// No address: the cursor's current frame.
    Cursor,
    /// `$_`, with an optional explicit type.
    LastAddr(Option<&'w str>),
    /// An address, whose type is required.
    Addr(u64, &'w str),
}

/// Resolve the root the arguments name, apply the path steps to it,
/// and render what they reach the way every other value is rendered.
pub(crate) fn exec_print<T: proc::Target>(
    session: &Session<'_, T>,
    args: &[String],
    render: RenderOpts,
    out: &mut dyn io::Write,
) -> Result<()> {
    let (root, path) = parse_args(args)?;
    let steps = reify::path::parse(&path)?;
    let root = root_value(session, root)?;
    let results = reify::path::resolve(session.ctx.proc, root, &steps)?;
    match results.as_slice() {
        [] => writeln!(out, "0 values")?,
        [one] if one.label.is_empty() => write_result(session, one, render, out)?,
        many => {
            for r in many {
                write!(out, "{} ", r.label)?;
                write_result(session, r, render, out)?;
            }
        }
    }
    Ok(())
}

/// The value the root spelling names.
fn root_value<'b, T: proc::Target>(
    session: &Session<'b, T>,
    root: Root<'_>,
) -> Result<reify::Value<'b>> {
    Ok(match root {
        Root::Cursor => cursor::frame_value(session)?,
        Root::Addr(addr, spec) => read_at(session, addr, spec)?,
        Root::LastAddr(spec) => {
            let addr = session.cursor.borrow().last_addr.ok_or_else(|| {
                anyhow!("$_ is unset: no cursor stands; `task`, `future` or `thread` selects one")
            })?;
            match spec {
                Some(spec) => read_at(session, addr, spec)?,
                // No type given: the default is the frame the cursor
                // stands at, which a thread-only cursor does not have.
                None if session.cursor.borrow().root.is_none() => bail!(
                    "$_ here is the lwp's stack pointer, with no default type; \
                     name one: `print $_ \"<Type>\"`"
                ),
                None => cursor::frame_value(session)?,
            }
        }
    })
}

/// The member names a `.` step could take next, for the prompt: `args`
/// are `print`'s arguments up to and including the `.` under the
/// cursor, so the root they name is resolved through the path before
/// it and asked what it has. A path that fans out over a range offers
/// the union of what each element has.
pub(crate) fn path_members<T: proc::Target>(
    session: &Session<'_, T>,
    args: &[String],
) -> Result<Vec<String>> {
    // The trailing `.` opens the step being typed; the path before it
    // is what resolves.
    let mut args = args.to_vec();
    if let Some(last) = args.last_mut()
        && let Some(before) = last.strip_suffix('.')
    {
        *last = before.to_string();
        if last.is_empty() {
            args.pop();
        }
    }
    let (root, path) = parse_args(&args)?;
    let steps = reify::path::parse(&path)?;
    let root = root_value(session, root)?;
    let mut names = Vec::new();
    for r in reify::path::resolve(session.ctx.proc, root, &steps)? {
        for name in reify::path::member_names(session.ctx.proc, &r.node) {
            if !names.contains(&name) {
                names.push(name);
            }
        }
    }
    Ok(names)
}

/// Read one value of `spec`'s type at `addr`. The address says where
/// and the type says how, and nothing checks one against the other:
/// printing the wrong type at an address renders that memory as the
/// type asked for, which is sometimes exactly the point.
fn read_at<'b, T: proc::Target>(
    session: &Session<'b, T>,
    addr: u64,
    spec: &str,
) -> Result<reify::Value<'b>> {
    let ctx = &session.ctx;
    let ty = types::resolve_type_spec(&ctx.view, &session.impl_fold, spec)?;
    reify::Value::read(ctx.proc, ty, addr).with_context(|| {
        format!(
            "failed to read the {} byte(s) of {} at {addr:#x}",
            ty.size(),
            ty.name()
        )
    })
}

/// Split the arguments into the root spelling and the concatenated
/// path. A path token starts with `.`, `[` or `*`; everything before
/// the first one is the root.
fn parse_args(args: &[String]) -> Result<(Root<'_>, String)> {
    let is_path = |s: &String| s.starts_with(['.', '[', '*']);
    let mut rest = args;
    let root = match rest.first() {
        None => Root::Cursor,
        Some(first) if is_path(first) => Root::Cursor,
        Some(first) if first == "$_" => {
            rest = &rest[1..];
            match rest.first() {
                Some(ty) if !is_path(ty) => {
                    rest = &rest[1..];
                    Root::LastAddr(Some(ty))
                }
                _ => Root::LastAddr(None),
            }
        }
        Some(addr) if addr.starts_with("0x") || addr.starts_with("0X") => {
            let parsed = crate::parse_hex_addr(addr).map_err(|e| anyhow!(e))?;
            rest = &rest[1..];
            match rest.first() {
                Some(ty) if !is_path(ty) => {
                    rest = &rest[1..];
                    Root::Addr(parsed, ty)
                }
                _ => bail!(
                    "an address needs a type: `print {addr} \"<Type>\"` \
                     (quote a name holding spaces); `print` alone renders the cursor frame"
                ),
            }
        }
        Some(other) => bail!(
            "`print` takes an address (0x…), `$_`, or a path starting with \
             `.`, `[` or `*`; got {other:?}"
        ),
    };
    let mut path = String::new();
    for t in rest {
        if !is_path(t) {
            bail!("a path step starts with `.`, `[` or `*`; got {t:?}");
        }
        path.push_str(t);
    }
    Ok((root, path))
}

/// Render one resolved node: a value as `print` always rendered one,
/// a map entry as the `key: value` line the map itself prints.
fn write_result<T: proc::Target>(
    session: &Session<'_, T>,
    r: &Resolved<'_>,
    render: RenderOpts,
    out: &mut dyn io::Write,
) -> Result<()> {
    let heap = session.heap_view();
    // Written rather than returned: a closure cannot hand back a
    // display borrowing its argument, so the borrow ends in here.
    let show = |v: &reify::Value<'_>, pretty: bool, out: &mut dyn io::Write| -> Result<()> {
        let mut disp = v
            .display_from_target(session.ctx.proc, render.depth)
            .max_str_len(Some(render.max_string_len))
            .max_array_len(Some(render.max_array_values));
        if let Some(view) = &heap {
            disp = disp.heap(view);
        }
        if render.ugly {
            disp = disp.ugly();
        }
        match pretty {
            true => write!(out, "{disp:#}")?,
            false => write!(out, "{disp}")?,
        }
        Ok(())
    };
    match &r.node {
        Node::Value(v) => show(v, true, out)?,
        Node::Entry { key, value } => {
            show(key, false, out)?;
            write!(out, ": ")?;
            show(value, true, out)?;
        }
    }
    writeln!(out)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn w(args: &[&str]) -> Vec<String> {
        args.iter().map(|s| s.to_string()).collect()
    }

    /// Each root spelling parses to its form with the path tokens
    /// concatenated behind it; what fits no form refuses naming the
    /// grammar.
    #[test]
    fn test_parse_args_splits_root_from_path() {
        assert!(matches!(parse_args(&[]).unwrap(), (Root::Cursor, p) if p.is_empty()));
        assert!(matches!(
            parse_args(&w(&[".a", "[0..2]", "*"])).unwrap(),
            (Root::Cursor, p) if p == ".a[0..2]*"
        ));
        assert!(matches!(
            parse_args(&w(&["$_"])).unwrap(),
            (Root::LastAddr(None), p) if p.is_empty()
        ));
        assert!(matches!(
            parse_args(&w(&["$_", "u64", ".x"])).unwrap(),
            (Root::LastAddr(Some("u64")), p) if p == ".x"
        ));
        assert!(matches!(
            parse_args(&w(&["$_", ".x"])).unwrap(),
            (Root::LastAddr(None), p) if p == ".x"
        ));
        assert!(matches!(
            parse_args(&w(&["0x7f10", "Vec<(u64, u64)>", ".a", "[3]"])).unwrap(),
            (Root::Addr(0x7f10, "Vec<(u64, u64)>"), p) if p == ".a[3]"
        ));

        let err = parse_args(&w(&["0x7f10"])).unwrap_err();
        assert!(err.to_string().contains("needs a type"), "{err}");
        let err = parse_args(&w(&["0x7f10", ".a"])).unwrap_err();
        assert!(err.to_string().contains("needs a type"), "{err}");
        let err = parse_args(&w(&["u64"])).unwrap_err();
        assert!(err.to_string().contains("takes an address"), "{err}");
        let err = parse_args(&w(&["0x7f10", "u64", "stray"])).unwrap_err();
        assert!(err.to_string().contains("path step"), "{err}");
    }

    /// Over a fixture pair, the names offered after a `.` are the
    /// cursor frame's locals as `locals` lists them — no compiler
    /// slots — and, one step down, the members of the local named,
    /// followed through its pointers. What no path reaches is an
    /// error, as `print` would say.
    #[test]
    fn test_path_members_list_the_frame_and_its_locals_members() {
        use crate::offline::session_args;
        use crate::{Session, TraceTarget};
        use hansei_runtime::testkit;
        let (bundle, snapshot) = testkit::load("illumos", "simple-await");
        let args = session_args("illumos", "simple-await");
        let session = Session::attach(&snapshot, &bundle, &args).expect("the pair attaches");
        let id = session.tasks.tasks[0]
            .task_id
            .expect("the fixture's tasks carry ids");
        cursor::select_task(&session, TraceTarget::Task(id)).expect("the task selects");
        let members = |args: &[&str]| path_members(&session, &w(args));

        // #0 is the leaf, a oneshot receiver: its one member, and —
        // since `.strong` resolves at the root through that single
        // member, the Option and the Arc — everything reachable that
        // way, which is exactly what one step in offers.
        let root = members(&["."]).unwrap();
        assert_eq!(root[0], "inner", "{root:?}");
        for expected in ["None", "Some", "strong", "weak", "data", "state", "value"] {
            assert!(root.iter().any(|n| n == expected), "{root:?}");
        }
        assert_eq!(members(&[".inner."]).unwrap(), root[1..]);

        // #1 holds the source-level locals `locals` lists: the
        // awaitee and the liveness slots stay out.
        session.cursor.borrow_mut().frame = 1;
        let locals = members(&["."]).unwrap();
        for expected in ["count", "labels", "values", "boxed", "first"] {
            assert!(locals.iter().any(|n| n == expected), "{locals:?}");
        }
        assert!(!locals.iter().any(|n| n.starts_with("__")), "{locals:?}");
        assert_eq!(
            members(&[".values."]).unwrap(),
            members(&[".values", "."]).unwrap()
        );
        assert!(members(&[".values."]).unwrap().iter().any(|n| n == "len"));
        // A `$_` root reads the same frame.
        assert_eq!(members(&["$_", "."]).unwrap(), locals);

        let err = members(&[".no_such."]).expect_err("no such local");
        assert!(err.to_string().contains("no_such"), "{err}");
        let err = members(&["[0]."]).expect_err("the frame is not a sequence");
        assert!(!err.to_string().is_empty());
    }
}
