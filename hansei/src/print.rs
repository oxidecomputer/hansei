//! The `print` command: a local of the cursor frame, or memory at an
//! address read as a named type, rendered as a typed value, and paths
//! into it — the answer to every `...` the renderer elides.

use crate::{RenderOpts, Session, cursor, types};

use anyhow::{Context as _, Result, anyhow, bail};
use reify::path::{Node, Resolved};

use std::io;

/// Where a `print` starts.
#[derive(Debug, PartialEq, Eq)]
enum Root<'w> {
    /// The cursor frame, whose locals the path names.
    Frame,
    /// Memory at an address, read as the type named.
    Addr(u64, &'w str),
}

/// Resolve the root and path the arguments name, and render what they
/// reach the way every other value is rendered.
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
    match root {
        Root::Frame => cursor::frame_value(session),
        Root::Addr(addr, spec) => read_at(session, addr, spec),
    }
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

/// The names a step could take next, for the prompt: `args` are
/// `print`'s arguments up to and including the `.` under the cursor —
/// none at all for the local being typed — so the root and the path
/// before it are resolved and asked what they have. A path that fans
/// out over a range offers the union of what each element has.
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

/// Whether a word is an address rather than a local's name: a `0x`
/// prefix, which no Rust identifier starts with.
pub(crate) fn is_address(word: &str) -> bool {
    word.starts_with("0x") || word.starts_with("0X")
}

/// Split the arguments into the root and one concatenated path. An
/// address first is followed by the type to read it as, one word —
/// quoted where the name holds a space or a `;` — and then steps. A
/// type may itself start with `[` or `*` (an array, a raw pointer),
/// so only a `.` word, which no type starts with, is a step where
/// the type should stand. Otherwise the first word names a local — the frame's member of
/// that name, which a leading `.` may spell out — and may carry steps
/// behind it (`values[..10]`). Every later word is a step, starting
/// with `.`, `[` or `*`.
fn parse_args(args: &[String]) -> Result<(Root<'_>, String)> {
    let is_step = |s: &str| s.starts_with(['.', '[', '*']);
    let Some((first, rest)) = args.split_first() else {
        return Ok((Root::Frame, String::new()));
    };
    let (root, mut path, rest) = match first.as_str() {
        f if f.starts_with('.') => (Root::Frame, f.to_string(), rest),
        f if is_address(f) => {
            let addr = crate::parse_hex_addr(f).map_err(|e| anyhow!(e))?;
            match rest.split_first() {
                Some((ty, rest)) if !ty.is_empty() && !ty.starts_with('.') => {
                    (Root::Addr(addr, ty), String::new(), rest)
                }
                _ => bail!(
                    "an address needs a type: `print {f} \"<Type>\"` (quote a name \
                     holding spaces or `;`); `whatis {f}` says what stands there"
                ),
            }
        }
        f if is_step(f) => bail!("`print` starts at a local's name; `{f}` is a step with none"),
        "" => bail!("`print` starts at a local's name; got an empty word"),
        f => (Root::Frame, format!(".{f}"), rest),
    };
    for t in rest {
        if !is_step(t) {
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

    /// The first word is the local, with or without its `.`, and the
    /// steps behind it — in the same word or the next ones — join it;
    /// a step with no local before it, or a word that is no step,
    /// refuses naming the grammar.
    #[test]
    fn test_parse_args_roots_at_a_local() {
        let local = |args: &[&str]| {
            let args = w(args);
            let (root, path) = parse_args(&args).unwrap();
            assert_eq!(root, Root::Frame);
            path
        };
        assert_eq!(local(&[]), "");
        assert_eq!(local(&["my_vec[..10]"]), ".my_vec[..10]");
        assert_eq!(local(&["foo", "[0..2]", "*"]), ".foo[0..2]*");
        assert_eq!(local(&["foo.x", ".y"]), ".foo.x.y");
        assert_eq!(local(&[".foo", ".x"]), ".foo.x");

        let err = parse_args(&w(&["[0]"])).unwrap_err();
        assert!(err.to_string().contains("local's name"), "{err}");
        let err = parse_args(&w(&["*"])).unwrap_err();
        assert!(err.to_string().contains("local's name"), "{err}");
        let err = parse_args(&w(&["foo", "stray"])).unwrap_err();
        assert!(err.to_string().contains("path step"), "{err}");
    }

    /// An address roots the print at memory, and the word after it is
    /// the type — whole, however many spaces the tokenizer let
    /// through — with the steps behind; an address with no type, or
    /// with a step where the type should stand, is refused.
    #[test]
    fn test_parse_args_roots_at_an_address_with_its_type() {
        assert_eq!(
            parse_args(&w(&["0x7f10", "Vec<(u64, u64)>", ".a", "[3]"])).unwrap(),
            (Root::Addr(0x7f10, "Vec<(u64, u64)>"), ".a[3]".to_string())
        );
        assert_eq!(
            parse_args(&w(&["0X10", "[u8; 4]"])).unwrap(),
            (Root::Addr(0x10, "[u8; 4]"), String::new())
        );
        assert_eq!(
            parse_args(&w(&["0x10", "*const u8", "*"])).unwrap(),
            (Root::Addr(0x10, "*const u8"), "*".to_string())
        );

        let err = parse_args(&w(&["0x7f10"])).unwrap_err();
        assert!(err.to_string().contains("needs a type"), "{err}");
        let err = parse_args(&w(&["0x7f10", ".a"])).unwrap_err();
        assert!(err.to_string().contains("needs a type"), "{err}");
        let err = parse_args(&w(&["0xzz", "u64"])).unwrap_err();
        assert!(err.to_string().contains("invalid hex"), "{err}");
        let err = parse_args(&w(&["0x7f10", "u64", "stray"])).unwrap_err();
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

    /// An address and a type read the same memory the local does —
    /// the local's own address and type name, spelled by hand, render
    /// its value — a type id serves as the type, and memory the target
    /// does not hold, or a type it does not record, refuses saying so.
    #[test]
    fn test_print_reads_an_address_as_a_named_type() {
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
        let id = session
            .tasks
            .tasks
            .first()
            .and_then(|t| t.task_id)
            .expect("the fixture's tasks carry ids");
        cursor::select_task(&session, TraceTarget::Task(id)).expect("the task selects");
        let print = |args: &[&str]| {
            let mut out = Vec::new();
            exec_print(&session, &w(args), render(), &mut out).map(|()| out)
        };

        let frame = cursor::frame_value(&session).expect("the frame reads");
        let inner = frame.member("inner").expect("the local reads");
        let addr = format!("{:#x}", inner.addr);
        let by_local = print(&["inner"]).expect("the local renders");
        let by_name = print(&[&addr, inner.ty.name()]).expect("the address renders");
        assert_eq!(by_local, by_name);
        let by_id = print(&[&addr, &inner.ty.id().0.to_string()]).expect("the id renders");
        assert_eq!(by_local, by_id);

        let err = print(&["0x10", inner.ty.name()]).expect_err("nothing is mapped at 0x10");
        assert!(err.to_string().contains("failed to read"), "{err}");
        let err = print(&[&addr, "no::such::Type"]).expect_err("no such type");
        assert!(err.to_string().contains("no type named"), "{err}");
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
        // since a step at the root reads through that single member
        // — the Option's live variant, where the listing stops: the
        // Arc behind it is reached as `.Some`, and offered there.
        let root = members(&[]).unwrap();
        assert_eq!(root, ["inner", "Some"]);
        assert_eq!(members(&["inner."]).unwrap(), root[1..]);
        let behind = members(&["inner.Some."]).unwrap();
        for expected in ["strong", "weak", "data", "state", "value"] {
            assert!(behind.iter().any(|n| n == expected), "{behind:?}");
        }
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
