//! The `print` command: a local of the cursor frame rendered as a
//! typed value, and paths into it — the answer to every `...` the
//! renderer elides.

use crate::{RenderOpts, Session, cursor};

use anyhow::{Result, bail};
use reify::path::{Node, Resolved};

use std::io;

/// Resolve the path the arguments name against the cursor frame, and
/// render what it reaches the way every other value is rendered.
pub(crate) fn exec_print<T: proc::Target>(
    session: &Session<'_, T>,
    args: &[String],
    render: RenderOpts,
    out: &mut dyn io::Write,
) -> Result<()> {
    let path = parse_path(args)?;
    let steps = reify::path::parse(&path)?;
    let root = cursor::frame_value(session)?;
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

/// The names a step could take next, for the prompt: `args` are
/// `print`'s arguments up to and including the `.` under the cursor —
/// none at all for the local being typed — so the path before it is
/// resolved against the cursor frame and asked what it has. A path
/// that fans out over a range offers the union of what each element
/// has.
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
    let path = parse_path(&args)?;
    let steps = reify::path::parse(&path)?;
    let root = cursor::frame_value(session)?;
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

/// Join the arguments into one path from the cursor frame. The first
/// word names a local — the frame's member of that name, which a
/// leading `.` may spell out — and may carry steps behind it
/// (`values[..10]`); every later word is a step, starting with `.`,
/// `[` or `*`. No word is an address: the frame is the only root.
fn parse_path(args: &[String]) -> Result<String> {
    let is_step = |s: &str| s.starts_with(['.', '[', '*']);
    let Some((first, rest)) = args.split_first() else {
        return Ok(String::new());
    };
    let mut path = match first.as_str() {
        f if f.starts_with('.') => f.to_string(),
        f if f.starts_with("0x") || f.starts_with("0X") => bail!(
            "`print` renders the cursor frame's locals, not an address: \
             `locals` lists them, `whatis {f}` says what stands at the address"
        ),
        f if is_step(f) => bail!("`print` starts at a local's name; `{f}` is a step with none"),
        "" => bail!("`print` starts at a local's name; got an empty word"),
        f => format!(".{f}"),
    };
    for t in rest {
        if !is_step(t) {
            bail!("a path step starts with `.`, `[` or `*`; got {t:?}");
        }
        path.push_str(t);
    }
    Ok(path)
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

    /// The first word is the local, with or without its `.`, and the
    /// steps behind it — in the same word or the next ones — join it;
    /// an address, a step with no local before it, or a word that is
    /// no step refuses naming the grammar.
    #[test]
    fn test_parse_path_roots_at_a_local() {
        assert_eq!(parse_path(&[]).unwrap(), "");
        assert_eq!(parse_path(&w(&["my_vec[..10]"])).unwrap(), ".my_vec[..10]");
        assert_eq!(
            parse_path(&w(&["foo", "[0..2]", "*"])).unwrap(),
            ".foo[0..2]*"
        );
        assert_eq!(parse_path(&w(&["foo.x", ".y"])).unwrap(), ".foo.x.y");
        assert_eq!(parse_path(&w(&[".foo", ".x"])).unwrap(), ".foo.x");

        let err = parse_path(&w(&["0x7f10"])).unwrap_err();
        assert!(err.to_string().contains("not an address"), "{err}");
        let err = parse_path(&w(&["0x7f10", "u64"])).unwrap_err();
        assert!(err.to_string().contains("not an address"), "{err}");
        let err = parse_path(&w(&["[0]"])).unwrap_err();
        assert!(err.to_string().contains("local's name"), "{err}");
        let err = parse_path(&w(&["*"])).unwrap_err();
        assert!(err.to_string().contains("local's name"), "{err}");
        let err = parse_path(&w(&["foo", "stray"])).unwrap_err();
        assert!(err.to_string().contains("path step"), "{err}");
    }

    /// `print` reads the cursor frame: a thread cursor has none, and
    /// a local's bare name and its `.`-spelled path render the same
    /// value.
    #[test]
    fn test_print_roots_at_the_cursor_frame() {
        use crate::offline::session_args;
        use crate::{Session, TraceTarget};
        use hansei_runtime::testkit;
        let (bundle, snapshot) = testkit::load("linux", "nested-await");
        let args = session_args("linux", "nested-await");
        let session = Session::attach(&snapshot, &bundle, &args).expect("the pair attaches");
        let render = || RenderOpts {
            depth: 3,
            ugly: false,
            max_string_len: 64,
            max_array_values: 8,
        };

        let lwp = session.lwps.first().expect("lwps recorded").tid;
        cursor::select_thread(&session, lwp).expect("the lwp selects");
        assert!(
            session.cursor.borrow().root.is_none(),
            "a parked capture polls nothing"
        );
        let err = exec_print(&session, &w(&["inner"]), render(), &mut Vec::new())
            .expect_err("no frame to read");
        assert!(err.to_string().contains("no task selected"), "{err}");

        let id = session
            .tasks
            .tasks
            .first()
            .and_then(|t| t.task_id)
            .expect("the fixture's tasks carry ids");
        cursor::select_task(&session, TraceTarget::Task(id)).expect("the task selects");
        let mut bare = Vec::new();
        exec_print(&session, &w(&["inner"]), render(), &mut bare).expect("the local renders");
        assert!(!bare.is_empty());
        let mut dotted = Vec::new();
        exec_print(&session, &w(&[".inner"]), render(), &mut dotted).expect("the path renders");
        assert_eq!(bare, dotted);
    }

    /// Over a fixture pair, the names offered for the first word are
    /// the cursor frame's locals as `locals` lists them — no compiler
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
        let root = members(&[]).unwrap();
        assert_eq!(root[0], "inner", "{root:?}");
        for expected in ["None", "Some", "strong", "weak", "data", "state", "value"] {
            assert!(root.iter().any(|n| n == expected), "{root:?}");
        }
        assert_eq!(members(&["inner."]).unwrap(), root[1..]);
        // The spelled-out `.` reads the same frame.
        assert_eq!(members(&["."]).unwrap(), root);

        // #1 holds the source-level locals `locals` lists: the
        // awaitee and the liveness slots stay out.
        session.cursor.borrow_mut().frame = 1;
        let locals = members(&[]).unwrap();
        for expected in ["count", "labels", "values", "boxed", "first"] {
            assert!(locals.iter().any(|n| n == expected), "{locals:?}");
        }
        assert!(!locals.iter().any(|n| n.starts_with("__")), "{locals:?}");
        assert_eq!(
            members(&["values."]).unwrap(),
            members(&["values", "."]).unwrap()
        );
        assert!(members(&["values."]).unwrap().iter().any(|n| n == "len"));

        let err = members(&["no_such."]).expect_err("no such local");
        assert!(err.to_string().contains("no_such"), "{err}");
        let err = members(&["[0]."]).expect_err("a step is no local");
        assert!(err.to_string().contains("local's name"), "{err}");
    }
}
