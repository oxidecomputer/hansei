// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! `hansei.so`: hansei's tokio analysis as an mdb module.
//!
//! ```text
//! > ::load hansei.so
//! > ::tokio_attach                          (or let the first dcmd do it)
//! > ::walk tokio_task | ::tokio_task -w state idle
//! > ::tokio_tasks -w waiting-on semaphore | ::tokio_trace
//! > ::hansei graph
//! ```
//!
//! The module reads the target through mdb ([`target::MdbTarget`]), so
//! it works wherever mdb does — a core file or a live process — and its
//! dcmds take and give addresses like any other, so they compose with
//! mdb's own: a task's address is its header, the start of its
//! allocation, which `::whatis` and friends understand too.
//!
//! The session is built once and kept. A live process that has run
//! since is a different target: `::tokio_attach` again.

mod ffi;
mod target;
#[cfg(not(target_os = "illumos"))]
mod testhost;

use ffi::*;
use target::{MdbTarget, mdb_lock};

use anyhow::{Context as _, Result, anyhow};
use hansei::Session;
use hansei::embed::{self, Options, TaskRef};
use hansei_bundle::Bundle;

use std::cell::RefCell;
use std::collections::HashMap;
use std::ffi::{CStr, CString, c_int, c_uint};
use std::mem::ManuallyDrop;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::path::PathBuf;

// ---------------------------------------------------------------------
// Output
//
// mdb may leave a dcmd by longjmp from inside `mdb_printf` (an
// interrupt, `q` at the pager). Rust frames it unwinds that way run no
// destructors, so nothing here prints while holding a lock or a
// borrow: every dcmd computes its whole answer first, lets go of the
// session, and only then prints.

fn print(text: &str) {
    for line in text.split_inclusive('\n') {
        let c = CString::new(line.replace('\0', "\\0")).unwrap_or_default();
        let _g = mdb_lock();
        unsafe { mdb_printf(c"%s".as_ptr(), c.as_ptr()) };
    }
}

fn warn(text: &str) {
    let c = CString::new(text.replace('\0', "\\0")).unwrap_or_default();
    let _g = mdb_lock();
    unsafe { mdb_warn(c"%s\n".as_ptr(), c.as_ptr()) };
}

// ---------------------------------------------------------------------
// The session

/// A session with everything it borrows, owned together. The session
/// borrows the target, the bundle and the options for `'static` because
/// they are leaked here and reclaimed only after it is dropped.
struct Attached {
    session: ManuallyDrop<Session<'static, MdbTarget>>,
    target: *mut MdbTarget,
    options: *mut Options,
    /// What the attach read its tokio info from.
    bundle_path: PathBuf,
    /// The last `::tokio_task` filter, so a pipe of many addresses
    /// selects once rather than once per address.
    selection: RefCell<Option<(Filters, Vec<TaskRef>)>>,
}

impl Drop for Attached {
    fn drop(&mut self) {
        unsafe {
            ManuallyDrop::drop(&mut self.session);
            drop(Box::from_raw(self.target));
            drop(Box::from_raw(self.options));
        }
    }
}

thread_local! {
    /// mdb calls every dcmd on its one thread, so the session lives there.
    static SESSION: RefCell<Option<Attached>> = const { RefCell::new(None) };
    /// Bundles by the file they came from, kept for the life of the
    /// module: a re-attach (a live process that ran on) reuses the
    /// tokio info rather than extracting it again.
    static BUNDLES: RefCell<HashMap<PathBuf, &'static Bundle>> = RefCell::new(HashMap::new());
}

fn attach(flags: &[String]) -> Result<String> {
    // Drop any session first: its target describes a moment that has
    // passed, and the new one should not have to share memory with it.
    SESSION.with(|s| s.borrow_mut().take());

    // Value rendering fans out over rayon; reads funnel through one
    // lock into mdb anyway, so a few threads are plenty.
    let _ = rayon::ThreadPoolBuilder::new()
        .num_threads(
            std::thread::available_parallelism()
                .map_or(1, |n| n.get())
                .min(4),
        )
        .thread_name(|i| format!("hansei-{i}"))
        .build_global();

    let target = MdbTarget::new().context("failed to read the target through mdb")?;
    let exec = target
        .exec()
        .map(|o| o.path.clone())
        .ok_or_else(|| anyhow!("mdb names no executable for this target"))?;

    // Without a named source of tokio info, extract it from the
    // executable mdb has open — the right answer whenever the program
    // was built with debug info, as a hansei target must be.
    let mut flags = flags.to_vec();
    if !flags.iter().any(|f| {
        matches!(f.as_str(), "--tokio-info" | "-t" | "--debug-info" | "-d")
            || f.starts_with("--tokio-info=")
            || f.starts_with("--debug-info=")
    }) {
        flags.push("--debug-info".into());
        flags.push(exec.clone());
    }
    let options = Options::parse(&exec, &flags)?;
    let bundle_path = options.bundle_path().to_path_buf();
    let bundle = match BUNDLES.with(|b| b.borrow().get(&bundle_path).copied()) {
        Some(bundle) => bundle,
        None => {
            let bundle: &'static Bundle = Box::leak(Box::new(options.load_bundle()?));
            BUNDLES.with(|b| b.borrow_mut().insert(bundle_path.clone(), bundle));
            bundle
        }
    };

    let target = Box::into_raw(Box::new(target));
    let options = Box::into_raw(Box::new(options));
    let session = unsafe { embed::attach(&*target, bundle, &*options) };
    let session = match session {
        Ok(session) => session,
        Err(e) => {
            unsafe {
                drop(Box::from_raw(target));
                drop(Box::from_raw(options));
            }
            return Err(e);
        }
    };
    let tasks = embed::tasks(&session, &[], &[])?.len();
    let attached = Attached {
        session: ManuallyDrop::new(session),
        target,
        options,
        bundle_path,
        selection: RefCell::new(None),
    };
    let summary = format!(
        "hansei: attached to {exec}: {tasks} task{} (tokio info from {})\n",
        if tasks == 1 { "" } else { "s" },
        attached.bundle_path.display()
    );
    SESSION.with(|s| *s.borrow_mut() = Some(attached));
    Ok(summary)
}

/// Run `f` against the session, attaching with the defaults first if
/// nothing is attached. Returns what attaching printed, if it did.
fn with_session<R>(f: impl FnOnce(&Attached) -> Result<R>) -> Result<(Option<String>, R)> {
    let attached_now = match SESSION.with(|s| s.borrow().is_some()) {
        true => None,
        false => Some(attach(&[])?),
    };
    SESSION.with(|s| {
        let s = s.borrow();
        let attached = s.as_ref().expect("attached above");
        Ok((attached_now, f(attached)?))
    })
}

/// Run a hansei command line, capturing its answer.
fn run(attached: &Attached, line: &str) -> Result<String> {
    let mut out = Vec::new();
    embed::run(&attached.session, line, &mut out)?;
    Ok(String::from_utf8_lossy(&out).into_owned())
}

// ---------------------------------------------------------------------
// Arguments

/// The dcmd's arguments as words: strings as given, numbers in hex, as
/// mdb would spell them back.
unsafe fn words(argc: c_int, argv: *const mdb_arg_t) -> Vec<String> {
    (0..argc.max(0) as usize)
        .map(|i| {
            let a = unsafe { &*argv.add(i) };
            match a.a_type {
                MDB_TYPE_STRING => unsafe { CStr::from_ptr(a.a_un.a_str) }
                    .to_string_lossy()
                    .into_owned(),
                MDB_TYPE_CHAR => char::from(unsafe { a.a_un.a_char } as u8).to_string(),
                _ => format!("{:#x}", unsafe { a.a_un.a_val }),
            }
        })
        .collect()
}

/// The `tasks` filter flags a dcmd takes, as hansei spells them:
/// `-w FIELD ARG` / `--with FIELD ARG` keep, `-W` / `--without` drop.
#[derive(Default, Clone, PartialEq)]
struct Filters {
    with: Vec<String>,
    without: Vec<String>,
}

impl Filters {
    fn is_empty(&self) -> bool {
        self.with.is_empty() && self.without.is_empty()
    }
}

fn quote(word: &str) -> String {
    if word
        .chars()
        .any(|c| c.is_whitespace() || c == ';' || c == '"')
    {
        format!("\"{}\"", word.replace('"', "\\\""))
    } else {
        word.to_string()
    }
}

/// Split filter flags from the rest. `None` is a usage error.
fn parse_filters(words: &[String], switches: &[&str]) -> Option<(Filters, Vec<String>)> {
    let mut filters = Filters::default();
    let mut rest = Vec::new();
    let mut i = 0;
    while i < words.len() {
        match words[i].as_str() {
            "-w" | "--with" | "-W" | "--without" => {
                let pair = words.get(i + 1..i + 3)?;
                let list = match words[i].as_str() {
                    "-w" | "--with" => &mut filters.with,
                    _ => &mut filters.without,
                };
                list.extend(pair.iter().cloned());
                i += 3;
            }
            s if switches.contains(&s) => {
                rest.push(s.to_string());
                i += 1;
            }
            _ => return None,
        }
    }
    Some((filters, rest))
}

/// The tasks a filter keeps, from the last selection when the filter
/// is the same one.
fn select(attached: &Attached, filters: &Filters) -> Result<Vec<TaskRef>> {
    if let Some((last, tasks)) = attached.selection.borrow().as_ref()
        && last == filters
    {
        return Ok(tasks.clone());
    }
    let tasks = embed::tasks(&attached.session, &filters.with, &filters.without)?;
    *attached.selection.borrow_mut() = Some((filters.clone(), tasks.clone()));
    Ok(tasks)
}

/// Run a dcmd body: errors become `DCMD_ERR` with mdb's warning, and a
/// panic never crosses into mdb.
fn guard(f: impl FnOnce() -> Result<(c_int, String)>) -> c_int {
    let result = catch_unwind(AssertUnwindSafe(f));
    match result {
        Ok(Ok((rc, text))) => {
            print(&text);
            rc
        }
        Ok(Err(e)) => {
            warn(&format!("hansei: {e:#}"));
            DCMD_ERR
        }
        Err(_) => {
            warn("hansei: internal error (panic); the session may need ::tokio_attach");
            DCMD_ERR
        }
    }
}

fn hdrspec(flags: c_uint) -> bool {
    flags & DCMD_LOOPFIRST != 0 || flags & DCMD_LOOP == 0
}

// ---------------------------------------------------------------------
// dcmds

unsafe extern "C" fn dcmd_attach(
    _addr: usize,
    flags: c_uint,
    argc: c_int,
    argv: *const mdb_arg_t,
) -> c_int {
    let words = unsafe { words(argc, argv) };
    guard(|| {
        if flags & DCMD_ADDRSPEC != 0 {
            return Ok((DCMD_USAGE, String::new()));
        }
        Ok((DCMD_OK, attach(&words)?))
    })
}

unsafe extern "C" fn dcmd_detach(
    _addr: usize,
    flags: c_uint,
    argc: c_int,
    _argv: *const mdb_arg_t,
) -> c_int {
    guard(|| {
        if flags & DCMD_ADDRSPEC != 0 || argc != 0 {
            return Ok((DCMD_USAGE, String::new()));
        }
        let had = SESSION.with(|s| s.borrow_mut().take()).is_some();
        let text = if had {
            "hansei: detached\n"
        } else {
            "hansei: not attached\n"
        };
        Ok((DCMD_OK, text.to_string()))
    })
}

unsafe extern "C" fn dcmd_hansei(
    addr: usize,
    flags: c_uint,
    argc: c_int,
    argv: *const mdb_arg_t,
) -> c_int {
    let words = unsafe { words(argc, argv) };
    guard(|| {
        if words.is_empty() {
            return Ok((DCMD_USAGE, String::new()));
        }
        let mut line = words.iter().map(|w| quote(w)).collect::<Vec<_>>().join(" ");
        // An address in front is the command's target: `addr::hansei
        // trace` asks about the task at addr.
        if flags & DCMD_ADDRSPEC != 0 {
            line.push_str(&format!(" {addr:#x}"));
        }
        let (attached_now, text) = with_session(|a| run(a, &line))?;
        Ok((DCMD_OK, attached_now.unwrap_or_default() + &text))
    })
}

unsafe extern "C" fn dcmd_tasks(
    _addr: usize,
    flags: c_uint,
    argc: c_int,
    argv: *const mdb_arg_t,
) -> c_int {
    let words = unsafe { words(argc, argv) };
    guard(|| {
        if flags & DCMD_ADDRSPEC != 0 {
            return Ok((DCMD_USAGE, String::new()));
        }
        let (attached_now, text) = if flags & DCMD_PIPE_OUT != 0 {
            // Into a pipe go addresses, so only the filters mean
            // anything; a grouping or a limit would be a different
            // question.
            let Some((filters, _)) = parse_filters(&words, &[]) else {
                return Ok((DCMD_USAGE, String::new()));
            };
            with_session(|a| {
                Ok(select(a, &filters)?
                    .iter()
                    .map(|t| format!("{:#x}\n", t.addr))
                    .collect())
            })?
        } else {
            // To the screen it is hansei's `tasks`, every flag its own
            // (`-l`, `-g type`, `--exec trace`).
            let line: String = words.iter().map(|w| format!(" {}", quote(w))).collect();
            with_session(|a| run(a, &format!("tasks{line}")))?
        };
        Ok((DCMD_OK, attached_now.unwrap_or_default() + &text))
    })
}

unsafe extern "C" fn dcmd_task(
    addr: usize,
    flags: c_uint,
    argc: c_int,
    argv: *const mdb_arg_t,
) -> c_int {
    let words = unsafe { words(argc, argv) };
    guard(|| {
        if flags & DCMD_ADDRSPEC == 0 {
            return Ok((DCMD_USAGE, String::new()));
        }
        let Some((filters, switches)) = parse_filters(&words, &["-v"]) else {
            return Ok((DCMD_USAGE, String::new()));
        };
        let verbose = switches.iter().any(|s| s == "-v");
        let addr = addr as u64;
        let (attached_now, text) = with_session(|a| {
            let kept = select(a, &filters)?;
            let task = kept.iter().find(|t| t.addr == addr);
            if flags & DCMD_PIPE_OUT != 0 {
                return Ok(task.map(|t| format!("{:#x}\n", t.addr)).unwrap_or_default());
            }
            match task {
                Some(_) if verbose => run(a, &format!("task {addr:#x}")),
                Some(t) => Ok(row(
                    t,
                    &widths(&select(a, &Filters::default())?),
                    hdrspec(flags),
                )),
                // Kept out by a filter: say nothing, as a filter should.
                None if !filters.is_empty() => Ok(String::new()),
                // Not a header: an address inside a task's allocation
                // still names it, which hansei resolves itself.
                None => run(a, &format!("task {addr:#x}")),
            }
        })?;
        Ok((DCMD_OK, attached_now.unwrap_or_default() + &text))
    })
}

/// Column widths for one-row-per-task output, fitted to every task
/// the session holds: a pipe prints its rows one call at a time, so the
/// widths must not depend on which rows the pipe happens to carry.
struct Widths {
    id: usize,
    state: usize,
    awaiting: usize,
    waiting: usize,
}

fn widths(all: &[TaskRef]) -> Widths {
    let w =
        |f: &dyn Fn(&TaskRef) -> usize, min: usize| all.iter().map(f).max().unwrap_or(0).max(min);
    Widths {
        id: w(&|t| t.id.map_or(1, |id| id.to_string().len()), 2),
        state: w(&|t| t.state.len(), 5),
        awaiting: w(&|t| t.awaiting_at.as_deref().map_or(1, str::len), 11),
        waiting: w(&|t| t.waiting_on.len(), 10),
    }
}

fn row(t: &TaskRef, w: &Widths, header: bool) -> String {
    let mut out = String::new();
    if header {
        out.push_str(&format!(
            "{:<18} {:>id$}  {:<state$}  {:<awaiting$}  {:<waiting$}  {}\n",
            "TASK",
            "ID",
            "STATE",
            "AWAITING AT",
            "WAITING ON",
            "FUTURE",
            id = w.id,
            state = w.state,
            awaiting = w.awaiting,
            waiting = w.waiting,
        ));
    }
    out.push_str(&format!(
        "{:<18} {:>id$}  {:<state$}  {:<awaiting$}  {:<waiting$}  {}\n",
        format!("{:#x}", t.addr),
        t.id.map_or("-".to_string(), |id| id.to_string()),
        t.state,
        t.awaiting_at.as_deref().unwrap_or("-"),
        t.waiting_on,
        t.future,
        id = w.id,
        state = w.state,
        awaiting = w.awaiting,
        waiting = w.waiting,
    ));
    out
}

unsafe extern "C" fn dcmd_trace(
    addr: usize,
    flags: c_uint,
    argc: c_int,
    argv: *const mdb_arg_t,
) -> c_int {
    let words = unsafe { words(argc, argv) };
    guard(|| {
        if flags & DCMD_ADDRSPEC == 0 {
            return Ok((DCMD_USAGE, String::new()));
        }
        let extra: String = words.iter().map(|w| format!(" {}", quote(w))).collect();
        let addr = addr as u64;
        let (attached_now, text) = with_session(|a| {
            let all = select(a, &Filters::default())?;
            match all.iter().find(|t| t.addr == addr) {
                // A heading of our own, since a pipe may trace many: the
                // trace itself starts at frame #0.
                Some(t) => {
                    let target = t.id.map_or(format!("{addr:#x}"), |id| id.to_string());
                    let heading = format!(
                        "task {} ({addr:#x}): {}\n",
                        t.id.map_or("?".into(), |id| id.to_string()),
                        t.future
                    );
                    let trace = match t.id {
                        Some(_) => run(a, &format!("trace {target}{extra}"))?,
                        None => run(a, &format!("task {addr:#x} ; trace{extra}"))?,
                    };
                    Ok(heading + &trace)
                }
                // Not a header: let hansei find the task whose
                // allocation holds the address, and say what it chose.
                None => run(a, &format!("task {addr:#x} ; trace{extra}")),
            }
        })?;
        Ok((DCMD_OK, attached_now.unwrap_or_default() + &text))
    })
}

// ---------------------------------------------------------------------
// Walkers

struct TaskWalk {
    addrs: Vec<u64>,
    next: usize,
}

unsafe extern "C" fn walk_task_init(wsp: *mut mdb_walk_state_t) -> c_int {
    let result = catch_unwind(|| {
        with_session(|a| {
            Ok(embed::tasks(&a.session, &[], &[])?
                .iter()
                .map(|t| t.addr)
                .collect::<Vec<_>>())
        })
    });
    let (attached_now, addrs) = match result {
        Ok(Ok(v)) => v,
        Ok(Err(e)) => {
            warn(&format!("hansei: {e:#}"));
            return WALK_ERR;
        }
        Err(_) => {
            warn("hansei: internal error (panic)");
            return WALK_ERR;
        }
    };
    if let Some(text) = attached_now {
        print(&text);
    }
    let walk = Box::new(TaskWalk { addrs, next: 0 });
    unsafe { (*wsp).walk_data = Box::into_raw(walk).cast() };
    WALK_NEXT
}

unsafe extern "C" fn walk_task_step(wsp: *mut mdb_walk_state_t) -> c_int {
    let wsp = unsafe { &mut *wsp };
    let walk = unsafe { &mut *wsp.walk_data.cast::<TaskWalk>() };
    let Some(&addr) = walk.addrs.get(walk.next) else {
        return WALK_DONE;
    };
    walk.next += 1;
    match wsp.walk_callback {
        Some(cb) => unsafe { cb(addr as usize, std::ptr::null(), wsp.walk_cbdata) },
        None => WALK_NEXT,
    }
}

unsafe extern "C" fn walk_task_fini(wsp: *mut mdb_walk_state_t) {
    let data = unsafe { (*wsp).walk_data };
    if !data.is_null() {
        drop(unsafe { Box::from_raw(data.cast::<TaskWalk>()) });
    }
}

// ---------------------------------------------------------------------
// Help

unsafe extern "C" fn help_attach() {
    print(concat!(
        "Attach hansei to the target mdb has open, reading it through mdb.\n",
        "Takes hansei's session flags: --tokio-info FILE (from `hansei tokio-info\n",
        "extract`) or --debug-info FILE; with neither, tokio info is extracted from\n",
        "the executable itself. Also --best-effort, --runtime N, --config K V, ...\n\n",
        "Other dcmds attach with the defaults on first use. Re-run after a live\n",
        "process has run: the session describes the moment it was taken.\n",
    ));
}

unsafe extern "C" fn help_hansei() {
    print(concat!(
        "Run any hansei session command; the output is hansei's own.\n",
        "  ::hansei census\n",
        "  ::hansei graph\n",
        "  ::hansei threads\n",
        "  ::hansei trace 12 -v\n",
        "  addr::hansei whatis        (an address in front becomes the last word)\n",
        "`::hansei help` lists every command.\n",
    ));
}

unsafe extern "C" fn help_tasks() {
    print(concat!(
        "List tokio tasks, as hansei's `tasks` does, filtered by\n",
        "  -w FIELD ARG   keep tasks whose FIELD matches ARG (--with)\n",
        "  -W FIELD ARG   drop them (--without)\n",
        "Fields: type, awaiting, waiting-on, spawned, defined, state (regexes);\n",
        "rt, lwp, id (exact); holds, sets, futures ('>N', '<N', '=N').\n",
        "Any other `tasks` flag works too when printing: -l N, -g FIELD, --exec CMD.\n\n",
        "Piped, it emits each kept task's address (filters only):\n",
        "  ::tokio_tasks -w waiting-on semaphore | ::tokio_trace\n",
    ));
}

unsafe extern "C" fn help_task() {
    print(concat!(
        "Describe the task at addr (its header, as ::walk tokio_task gives).\n",
        "  -v             hansei's full `task` view instead of one row\n",
        "  -w/-W F ARG    filter, as ::tokio_tasks; piped, kept addresses pass on\n\n",
        "  ::walk tokio_task | ::tokio_task\n",
        "  ::walk tokio_task | ::tokio_task -w state idle -W type heartbeat | ::tokio_trace\n",
        "An address inside a task's allocation also names it.\n",
    ));
}

unsafe extern "C" fn help_trace() {
    print(concat!(
        "Print the async backtrace of the task at addr: each await, outermost\n",
        "last, with its source line. Further arguments go to hansei's `trace`\n",
        "(-v for locals, --native to merge the polling thread's own frames).\n",
    ));
}

// ---------------------------------------------------------------------
// Linkage

struct Sync<T>(T);
unsafe impl<T> std::marker::Sync for Sync<T> {}

const fn dcmd(
    name: &'static CStr,
    usage: &'static CStr,
    descr: &'static CStr,
    f: mdb_dcmd_f,
    help: unsafe extern "C" fn(),
) -> mdb_dcmd_t {
    mdb_dcmd_t {
        dc_name: name.as_ptr(),
        dc_usage: usage.as_ptr(),
        dc_descr: descr.as_ptr(),
        dc_funcp: Some(f),
        dc_help: Some(help),
        dc_tabp: std::ptr::null(),
    }
}

const NO_DCMD: mdb_dcmd_t = mdb_dcmd_t {
    dc_name: std::ptr::null(),
    dc_usage: std::ptr::null(),
    dc_descr: std::ptr::null(),
    dc_funcp: None,
    dc_help: None,
    dc_tabp: std::ptr::null(),
};

static DCMDS: Sync<[mdb_dcmd_t; 7]> = Sync([
    dcmd(
        c"tokio_attach",
        c"[hansei flags]",
        c"attach hansei to this target",
        dcmd_attach,
        help_attach,
    ),
    dcmd(
        c"tokio_detach",
        c"",
        c"drop the hansei session",
        dcmd_detach,
        help_attach,
    ),
    dcmd(
        c"hansei",
        c"command [args]",
        c"run a hansei session command",
        dcmd_hansei,
        help_hansei,
    ),
    dcmd(
        c"tokio_tasks",
        c"[-w field arg] [-W field arg] [tasks flags]",
        c"list tokio tasks",
        dcmd_tasks,
        help_tasks,
    ),
    dcmd(
        c"tokio_task",
        c":[-v] [-w field arg] [-W field arg]",
        c"describe a tokio task",
        dcmd_task,
        help_task,
    ),
    dcmd(
        c"tokio_trace",
        c":[-v] [--native]",
        c"async backtrace of a tokio task",
        dcmd_trace,
        help_trace,
    ),
    NO_DCMD,
]);

static WALKERS: Sync<[mdb_walker_t; 2]> = Sync([
    mdb_walker_t {
        walk_name: c"tokio_task".as_ptr(),
        walk_descr: c"walk every tokio task hansei finds, by header address".as_ptr(),
        walk_init: Some(walk_task_init),
        walk_step: Some(walk_task_step),
        walk_fini: Some(walk_task_fini),
        walk_init_arg: std::ptr::null_mut(),
    },
    mdb_walker_t {
        walk_name: std::ptr::null(),
        walk_descr: std::ptr::null(),
        walk_init: None,
        walk_step: None,
        walk_fini: None,
        walk_init_arg: std::ptr::null_mut(),
    },
]);

static MODINFO: Sync<mdb_modinfo_t> = Sync(mdb_modinfo_t {
    mi_dvers: MDB_API_VERSION,
    mi_dcmds: &DCMDS.0 as *const _ as *const mdb_dcmd_t,
    mi_walkers: &WALKERS.0 as *const _ as *const mdb_walker_t,
});

#[unsafe(no_mangle)]
pub extern "C" fn _mdb_init() -> *const mdb_modinfo_t {
    &MODINFO.0
}

#[unsafe(no_mangle)]
pub extern "C" fn _mdb_fini() {
    let _ = catch_unwind(|| SESSION.with(|s| s.borrow_mut().take()));
}
