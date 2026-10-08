# mdb-hansei

hansei inside mdb: a dmod that runs hansei's tokio analysis on whatever
mdb has open, a core file or a live process, with dcmds and a walker
that take and give addresses like any other.

```
> ::load /path/to/hansei.so
> ::walk tokio_task | ::tokio_task
TASK               ID  STATE  AWAITING AT      WAITING ON  FUTURE
0x562436589880      3  idle   src/main.rs:110  io          async fn hansei_example::listener
0x562436589b80      4  idle   src/main.rs:139  semaphore   async fn hansei_example::producer
...
> ::tokio_tasks -w waiting-on semaphore | ::tokio_trace
task 4 (0x562436589b80): async fn hansei_example::producer
#0  future        tokio::sync::batch_semaphore::Acquire
      waiting on a tokio::sync::mpsc bounded channel (semaphore 0x562436589640): ...
...
> ::hansei graph
```

## Building

```
cargo build --release -p mdb-hansei
cp target/release/libmdb_hansei.so hansei.so    # mdb names a module after its file
```

## dcmds and walkers

| | |
|---|---|
| `::tokio_attach [flags]` | Attach to the target. Takes hansei's session flags (`--tokio-info FILE`, `--debug-info FILE`, `--best-effort`, `--runtime N`, `--config K V`). With no tokio info named, it is extracted from the executable mdb has open. Every other dcmd attaches with the defaults on first use. |
| `::tokio_detach` | Drop the session. |
| `::hansei CMD [args]` | Any hansei session command, answered as hansei answers it: `census`, `graph`, `threads`, `trace 12 -v`, `print …`. An address in front (`addr::hansei whatis`) is passed as the last word. |
| `::tokio_tasks [-w F A] [-W F A] [tasks flags]` | hansei's `tasks`. Piped, it emits the kept tasks' addresses. |
| `addr::tokio_task [-v] [-w F A] [-W F A]` | One row per task (`-v`: hansei's full `task` view). With filters it passes on only the tasks they keep, so it works as a filter stage in a pipe. |
| `addr::tokio_trace [-v] [--native]` | The task's async backtrace. |
| `::walk tokio_task` | Every task hansei finds, by header address. That is the start of the task's allocation, so `::whatis` and the rest of mdb understand it too. |

Native code, from DWARF, with no hansei session needed:

| | |
|---|---|
| `addr::whatline` | Function and `file:line:col` at an address, with every frame inlined there. Objects without DWARF (libc) give their symbol only. |
| `addr::srclist [-n N]` | The source around an address, its line marked. |
| `[fp]::srcstack [-t LWP] [-p PC]` | `$C` with source lines: every frame's file:line, a return address resolved to the line of its call. Piped, it emits each frame's pc. |
| `::srcpath [-c] [-d DIR] [-s FROM=TO]` | Where `::srclist` looks for sources that moved, e.g. `-s /rustc/<hash>=$(rustc --print sysroot)/lib/rustlib/src/rust` for std. |

`-w FIELD ARG` / `-W FIELD ARG` are `tasks --with` / `--without`. The fields are
`type`, `awaiting`, `waiting-on`, `spawned`, `defined`, `state` (regexes), `rt`,
`lwp`, `id` (exact), and `holds`, `sets`, `futures` (`'>N'`).

## How it reads the target

`MdbTarget` implements `proc::Target` over mdb (see `src/target.rs`):

- **Memory and symbols** come through the module API (`mdb_vread`,
  `mdb_lookup_by_*`, `mdb_symbol_iter`, `mdb_object_iter`).
- **Lwps, the fatal signal, the agent lwp and the executable's path** come from the
  `lwpstatus`, `pstatus` and `psinfo` target data mdb exports. These are the same
  `/proc` structures an illumos core's notes carry, and they are decoded by the
  same code (`proc::coredump::illumos::procfs`).
- **The mapping table** comes from `Pmapping_iter` on the libproc handle mdb exports
  as `pshandle`.

mdb is single-threaded and hansei renders in parallel, so every call into mdb or
libproc is serialized. Memory is read in 64 KiB chunks and kept for the life of the
session.

The session is a snapshot. After a live process runs again, `::tokio_attach` again.

## Testing off illumos

`mdbmock` (`mock/`) stands in for mdb's proc target over a **Linux** core. It loads
the module the way mdb does, answers the same mdb and libproc calls (target data in
illumos's own layouts), and runs `::walk … | ::dcmd` pipelines with mdb's pipe flags:

```
mdbmock --core CORE --binary BIN --dmod hansei.so \
    '::walk tokio_task | ::tokio_task -w state idle' '::hansei graph'
```

Against a gcore of `example/`, every `::hansei CMD` answer matched
`hansei --core … -e CMD` byte for byte: `census`, `tasks`, `threads`, `runtimes`,
`graph`, `futures`, `task`, `trace` (with `-v` and `--native`), `whatis`,
`thread N`, and `tasks --exec`. The one exception is `info`, whose process facts
this target does not supply yet.

The mock answers one thing illumos never needs: Linux's native TLS, via the
`mdbmock_tls_var_addr` export.

## Not yet done

- `process_facts` (for `info`): mdb has `::status`, `::pargs` and `::penv` meanwhile.
- **Warnings go straight to stderr.** hansei prints some warnings there itself (a
  degraded walk, a census that skipped a local), so they appear outside mdb's own
  output stream.
- **Interrupting a long attach doesn't work.** mdb can leave a dcmd by `longjmp`.
  The module never holds a lock or a borrow while printing, so that is safe once
  output starts, but a long attach or extraction can't be interrupted.
- **Not verified under real mdb on illumos yet.** The module API and libproc
  declarations follow illumos-gate's headers (`mdb_modapi.h` API version 5,
  `procfs.h`), but only the Linux mock has run them.
