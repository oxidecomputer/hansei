// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! The `dump` command: target memory as raw bytes, laid out the way
//! hexyl lays out a file — the position, two eight-byte hex panels and
//! a character panel naming each byte's kind — for what `print` cannot
//! show: memory no type describes, and a value's bytes rather than
//! its rendering.

use crate::Session;
use crate::output::{ByteKind, Theme};
use crate::print;

use anyhow::{Result, anyhow, bail};
use reify::path::{Node, Resolved};

use std::io;

/// How many bytes a bare address dumps when no `--length` says.
const DEFAULT_LENGTH: u64 = 256;

/// Bytes on one line, and in each of its two panels.
const LINE: usize = 16;
const PANEL: usize = 8;

/// The unit memory is read in: a chunk that fails whole is retried a
/// byte at a time, to find where the readable run ends.
const CHUNK: u64 = 4096;

/// How a `dump` lays its bytes out.
#[derive(Copy, Clone, Debug)]
pub(crate) struct DumpOpts {
    /// The bytes to dump, overriding the extent the target names.
    pub(crate) length: Option<u64>,
    /// Bytes per hex group, each group printed as one little-endian
    /// number: 1, 2, 4 or 8.
    pub(crate) group: usize,
    /// Whether a run of lines identical to the one before it prints as
    /// a single `*` line.
    pub(crate) squeeze: bool,
}

/// Dump the memory the arguments name: a bare address, the bytes at it
/// for `--length` (or [`DEFAULT_LENGTH`]); otherwise a value reached the
/// way `print` reaches one, whose extent is its buffer where it keeps
/// its contents in one, and its own bytes where it does not.
pub(crate) fn exec_dump<T: proc::Target>(
    session: &Session<'_, T>,
    args: &[String],
    opts: DumpOpts,
    theme: Theme,
    out: &mut dyn io::Write,
) -> Result<()> {
    let (addr, extent) = extent(session, args)?;
    let len = opts.length.unwrap_or(extent);
    let proc = session.ctx.proc;
    let (bytes, failure) = read_run(|at, n| Ok(proc.read_bytes(at, n)?), addr, len);
    if let Some((at, err)) = &failure
        && bytes.is_empty()
    {
        bail!("failed to read {at:#x}: {err:#}");
    }
    for line in render(addr, &bytes, opts, theme) {
        writeln!(out, "{line}")?;
    }
    if let Some((at, err)) = failure {
        writeln!(
            out,
            "{} of {len} bytes shown; failed to read {at:#x}: {err:#}",
            bytes.len()
        )?;
    }
    Ok(())
}

/// Where the arguments' memory starts and how many bytes it takes.
fn extent<T: proc::Target>(session: &Session<'_, T>, args: &[String]) -> Result<(u64, u64)> {
    if let [first, rest @ ..] = args
        && print::is_address(first)
    {
        let addr = crate::parse_hex_addr(first).map_err(|e| anyhow!(e))?;
        match rest.first() {
            None => return Ok((addr, DEFAULT_LENGTH)),
            Some(step) if step.starts_with('.') => bail!(
                "a path from an address needs the type to read it as: \
                 `dump {first} \"<Type>\" {step}`"
            ),
            Some(_) => {}
        }
    }
    let (root, path) = print::parse_args(args)?;
    let steps = reify::path::parse(&path)?;
    let root = print::root_value(session, root)?;
    let results = reify::path::resolve(session.ctx.proc, root, &steps)?;
    match results.as_slice() {
        [] => bail!("the path selects nothing to dump"),
        [one] if one.label.is_empty() => value_extent(one),
        run => run_extent(run),
    }
}

/// One value's extent: the buffer a `Vec`, a slice or a string keeps
/// its contents in — the value itself, or the one a transparent
/// wrapper around it holds — and otherwise the value's own bytes.
fn value_extent(r: &Resolved<'_>) -> Result<(u64, u64)> {
    let Node::Value(v) = &r.node else {
        bail!("a map entry is a key and a value, not one run of memory");
    };
    for candidate in [*v, v.peel()] {
        if let Some(buffer) = candidate.buffer() {
            return buffer.map_err(|e| anyhow!(e));
        }
    }
    Ok((v.addr, v.ty.size()))
}

/// A range's extent: the run its elements' own bytes make, which a
/// sequence's elements always do.
fn run_extent(run: &[Resolved<'_>]) -> Result<(u64, u64)> {
    let mut values = Vec::with_capacity(run.len());
    for r in run {
        match &r.node {
            Node::Value(v) => values.push(v),
            Node::Entry { .. } => {
                bail!("a map's entries are keys and values, not one run of memory")
            }
        }
    }
    let (first, last) = (values[0], values[values.len() - 1]);
    for pair in values.windows(2) {
        if pair[0].addr.checked_add(pair[0].ty.size()) != Some(pair[1].addr) {
            bail!(
                "the path's values do not make one run of memory: {} ends at {:#x} and {} starts \
                 at {:#x}",
                pair[0].ty.name(),
                pair[0].addr.wrapping_add(pair[0].ty.size()),
                pair[1].ty.name(),
                pair[1].addr
            );
        }
    }
    Ok((first.addr, last.addr + last.ty.size() - first.addr))
}

/// Read up to `len` bytes at `addr` through `read`: the readable run
/// from `addr`, and where and why it stopped short, if it did. A run
/// is read a chunk at a time; a chunk that fails whole — a core segment
/// or a snapshot's captured run ending inside it — is read a byte at a
/// time to find the last readable byte.
fn read_run<'t>(
    read: impl Fn(u64, u64) -> Result<&'t [u8]>,
    addr: u64,
    len: u64,
) -> (Vec<u8>, Option<(u64, anyhow::Error)>) {
    let end = addr.saturating_add(len);
    let mut bytes = Vec::with_capacity(len.min(1 << 20) as usize);
    let mut at = addr;
    while at < end {
        let chunk = (end - at).min(CHUNK - at % CHUNK);
        if let Ok(run) = read(at, chunk) {
            bytes.extend_from_slice(run);
            at += chunk;
            continue;
        }
        for _ in 0..chunk {
            match read(at, 1) {
                Ok(run) => bytes.extend_from_slice(run),
                Err(e) => return (bytes, Some((at, e))),
            }
            at += 1;
        }
    }
    (bytes, None)
}

/// The dump of `bytes`, read at `addr`, as hexyl lays it out: one line
/// per sixteen bytes between a top and a bottom border.
fn render(addr: u64, bytes: &[u8], opts: DumpOpts, theme: Theme) -> Vec<String> {
    let end = addr.wrapping_add(bytes.len() as u64);
    let layout = Layout {
        position: format!("{end:x}").len().max(8),
        hex: 1 + (PANEL / opts.group) * (2 * opts.group + 1),
        group: opts.group,
        theme,
    };
    let mut lines = vec![layout.border('┌', '┬', '┐')];
    if bytes.is_empty() {
        lines.push(layout.no_content());
    }
    let mut previous: Option<&[u8]> = None;
    let mut squeezing = false;
    for (i, line) in bytes.chunks(LINE).enumerate() {
        if opts.squeeze && line.len() == LINE && previous == Some(line) {
            if !squeezing {
                lines.push(layout.squeezed());
                squeezing = true;
            }
            continue;
        }
        squeezing = false;
        lines.push(layout.line(addr.wrapping_add((i * LINE) as u64), line));
        previous = Some(line);
    }
    // A squeeze that runs to the end says where the dump ends, since no
    // line after it does.
    if squeezing {
        lines.push(layout.line(end, &[]));
    }
    lines.push(layout.border('└', '┴', '┘'));
    lines
}

/// The widths one dump's lines share.
struct Layout {
    /// Hex digits in the position column.
    position: usize,
    /// Characters in each hex panel.
    hex: usize,
    group: usize,
    theme: Theme,
}

impl Layout {
    fn border(&self, left: char, join: char, right: char) -> String {
        let bar = |n: usize| "─".repeat(n);
        format!(
            "{left}{}{join}{}{join}{}{join}{}{join}{}{right}",
            bar(self.position),
            bar(self.hex),
            bar(self.hex),
            bar(PANEL),
            bar(PANEL)
        )
    }

    /// One line of bytes at `pos`, however many of its sixteen there
    /// are; the missing ones are blank.
    fn line(&self, pos: u64, bytes: &[u8]) -> String {
        let (left, right) = bytes.split_at(bytes.len().min(PANEL));
        let position = format!("{pos:0width$x}", width = self.position);
        format!(
            "│{}│{}┊{}│{}┊{}│",
            self.theme.offset(&position),
            self.hex_panel(left),
            self.hex_panel(right),
            self.char_panel(left),
            self.char_panel(right)
        )
    }

    /// The line standing for a run of lines identical to the one above.
    fn squeezed(&self) -> String {
        format!(
            "│{}{}│{}┊{}│{}┊{}│",
            self.theme.offset("*"),
            " ".repeat(self.position - 1),
            " ".repeat(self.hex),
            " ".repeat(self.hex),
            " ".repeat(PANEL),
            " ".repeat(PANEL)
        )
    }

    /// The one line of a dump with no bytes in it.
    fn no_content(&self) -> String {
        format!(
            "│{}│{:<hex$}│{}│{}│{}│",
            " ".repeat(self.position),
            " No content",
            " ".repeat(self.hex),
            " ".repeat(PANEL),
            " ".repeat(PANEL),
            hex = self.hex
        )
    }

    /// Up to eight bytes in hex, in groups, each group's bytes printed
    /// last first: the little-endian number the group holds.
    fn hex_panel(&self, bytes: &[u8]) -> String {
        let mut runs = Runs::new(self.theme);
        runs.plain(" ");
        for group in 0..PANEL / self.group {
            let start = (group * self.group).min(bytes.len());
            let end = (start + self.group).min(bytes.len());
            let held = &bytes[start..end];
            for &b in held.iter().rev() {
                runs.byte(b, &format!("{b:02x}"));
            }
            runs.plain(&" ".repeat(2 * (self.group - held.len()) + 1));
        }
        runs.finish()
    }

    /// Up to eight bytes as the characters hexyl names them by.
    fn char_panel(&self, bytes: &[u8]) -> String {
        let mut runs = Runs::new(self.theme);
        for &b in bytes {
            runs.byte(b, glyph(b).encode_utf8(&mut [0; 4]));
        }
        runs.plain(&" ".repeat(PANEL - bytes.len()));
        runs.finish()
    }
}

/// A panel's text, styled a run at a time: consecutive bytes of one
/// kind share one hue, and the spacing after a byte takes the byte's.
struct Runs {
    theme: Theme,
    out: String,
    run: String,
    kind: Option<ByteKind>,
}

impl Runs {
    fn new(theme: Theme) -> Self {
        Runs {
            theme,
            out: String::new(),
            run: String::new(),
            kind: None,
        }
    }

    fn byte(&mut self, b: u8, text: &str) {
        let kind = kind(b);
        if self.kind != Some(kind) {
            self.flush();
            self.kind = Some(kind);
        }
        self.run.push_str(text);
    }

    fn plain(&mut self, text: &str) {
        self.run.push_str(text);
    }

    fn flush(&mut self) {
        let run = std::mem::take(&mut self.run);
        match self.kind {
            Some(kind) => self.out.push_str(&self.theme.byte(kind, &run)),
            None => self.out.push_str(&run),
        }
    }

    fn finish(mut self) -> String {
        self.flush();
        self.out
    }
}

fn kind(b: u8) -> ByteKind {
    match b {
        0 => ByteKind::Null,
        b if b.is_ascii_graphic() => ByteKind::Printable,
        b if b.is_ascii() => ByteKind::OtherAscii,
        _ => ByteKind::NonAscii,
    }
}

/// hexyl's default character table: printable ASCII as itself, `⋄`
/// for a null byte, a space as a space and other ASCII whitespace as
/// `_`, `•` for the rest of ASCII, and `×` for anything past it.
fn glyph(b: u8) -> char {
    match b {
        0 => '⋄',
        b' ' => ' ',
        b if b.is_ascii_graphic() => b as char,
        b if b.is_ascii_whitespace() => '_',
        b if b.is_ascii() => '•',
        _ => '×',
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every kind of byte hexyl tells apart: printable ASCII, a null,
    /// the space and other whitespace, the control characters and the
    /// bytes past ASCII, ending partway through a line.
    const SAMPLE: &[u8] =
        b"onfig.toml\0_=*663*/usr/bin/ctrun\0PATH=/usr/sbin:\x01\x02\xff\xfe\n\t  end";

    fn opts(group: usize, squeeze: bool) -> DumpOpts {
        DumpOpts {
            length: None,
            group,
            squeeze,
        }
    }

    fn plain(addr: u64, bytes: &[u8], opts: DumpOpts) -> String {
        render(addr, bytes, opts, Theme::plain()).join("\n")
    }

    /// Byte for byte what `hexyl --color=never -o 0x7a55458` prints
    /// for the same bytes: the positions, both panels, the glyphs, and
    /// a last line padded out where the bytes end.
    #[test]
    fn test_render_matches_hexyl_one_byte_at_a_time() {
        let expected = "\
┌────────┬─────────────────────────┬─────────────────────────┬────────┬────────┐
│07a55458│ 6f 6e 66 69 67 2e 74 6f ┊ 6d 6c 00 5f 3d 2a 36 36 │onfig.to┊ml⋄_=*66│
│07a55468│ 33 2a 2f 75 73 72 2f 62 ┊ 69 6e 2f 63 74 72 75 6e │3*/usr/b┊in/ctrun│
│07a55478│ 00 50 41 54 48 3d 2f 75 ┊ 73 72 2f 73 62 69 6e 3a │⋄PATH=/u┊sr/sbin:│
│07a55488│ 01 02 ff fe 0a 09 20 20 ┊ 65 6e 64                │••××__  ┊end     │
└────────┴─────────────────────────┴─────────────────────────┴────────┴────────┘";
        assert_eq!(plain(0x7a55458, SAMPLE, opts(1, true)), expected);
    }

    /// Grouped, each group reads as the little-endian number it holds,
    /// as `hexyl -g N -e` prints it; a group the bytes end inside
    /// prints what it holds, last byte first, padded after.
    #[test]
    fn test_render_groups_as_little_endian_numbers() {
        let two = "\
┌────────┬─────────────────────┬─────────────────────┬────────┬────────┐
│07a55458│ 6e6f 6966 2e67 6f74 ┊ 6c6d 5f00 2a3d 3636 │onfig.to┊ml⋄_=*66│
│07a55468│ 2a33 752f 7273 622f ┊ 6e69 632f 7274 6e75 │3*/usr/b┊in/ctrun│
│07a55478│ 5000 5441 3d48 752f ┊ 7273 732f 6962 3a6e │⋄PATH=/u┊sr/sbin:│
│07a55488│ 0201 feff 090a 2020 ┊ 6e65 64             │••××__  ┊end     │
└────────┴─────────────────────┴─────────────────────┴────────┴────────┘";
        let four = "\
┌────────┬───────────────────┬───────────────────┬────────┬────────┐
│07a55458│ 69666e6f 6f742e67 ┊ 5f006c6d 36362a3d │onfig.to┊ml⋄_=*66│
│07a55468│ 752f2a33 622f7273 ┊ 632f6e69 6e757274 │3*/usr/b┊in/ctrun│
│07a55478│ 54415000 752f3d48 ┊ 732f7273 3a6e6962 │⋄PATH=/u┊sr/sbin:│
│07a55488│ feff0201 2020090a ┊ 646e65            │••××__  ┊end     │
└────────┴───────────────────┴───────────────────┴────────┴────────┘";
        let eight = "\
┌────────┬──────────────────┬──────────────────┬────────┬────────┐
│07a55458│ 6f742e6769666e6f ┊ 36362a3d5f006c6d │onfig.to┊ml⋄_=*66│
│07a55468│ 622f7273752f2a33 ┊ 6e757274632f6e69 │3*/usr/b┊in/ctrun│
│07a55478│ 752f3d4854415000 ┊ 3a6e6962732f7273 │⋄PATH=/u┊sr/sbin:│
│07a55488│ 2020090afeff0201 ┊ 646e65           │••××__  ┊end     │
└────────┴──────────────────┴──────────────────┴────────┴────────┘";
        assert_eq!(plain(0x7a55458, SAMPLE, opts(2, true)), two);
        assert_eq!(plain(0x7a55458, SAMPLE, opts(4, true)), four);
        assert_eq!(plain(0x7a55458, SAMPLE, opts(8, true)), eight);
    }

    /// A run of lines identical to the one before prints as one `*`
    /// line, as hexyl squeezes one; the run need not be zeros, and one
    /// running to the end is closed by a line giving the end position.
    /// Unsqueezed, every line prints.
    #[test]
    fn test_render_squeezes_repeated_lines() {
        let mut bytes = vec![0u8; 100];
        bytes.extend_from_slice(b"abc");
        bytes.extend_from_slice(&[0; 64]);
        let squeezed = "\
┌────────┬─────────────────────────┬─────────────────────────┬────────┬────────┐
│00000000│ 00 00 00 00 00 00 00 00 ┊ 00 00 00 00 00 00 00 00 │⋄⋄⋄⋄⋄⋄⋄⋄┊⋄⋄⋄⋄⋄⋄⋄⋄│
│*       │                         ┊                         │        ┊        │
│00000060│ 00 00 00 00 61 62 63 00 ┊ 00 00 00 00 00 00 00 00 │⋄⋄⋄⋄abc⋄┊⋄⋄⋄⋄⋄⋄⋄⋄│
│00000070│ 00 00 00 00 00 00 00 00 ┊ 00 00 00 00 00 00 00 00 │⋄⋄⋄⋄⋄⋄⋄⋄┊⋄⋄⋄⋄⋄⋄⋄⋄│
│*       │                         ┊                         │        ┊        │
│000000a0│ 00 00 00 00 00 00 00    ┊                         │⋄⋄⋄⋄⋄⋄⋄ ┊        │
└────────┴─────────────────────────┴─────────────────────────┴────────┴────────┘";
        assert_eq!(plain(0, &bytes, opts(1, true)), squeezed);
        let all = plain(0, &bytes, opts(1, false));
        assert!(!all.contains('*'), "{all}");
        assert_eq!(all.lines().count(), 2 + bytes.len().div_ceil(LINE));

        let mut repeated = b"AAAAAAAAAAAAAAAA".repeat(3);
        repeated.extend_from_slice(&[0; 32]);
        let squeezed = "\
┌────────┬─────────────────────────┬─────────────────────────┬────────┬────────┐
│00000000│ 41 41 41 41 41 41 41 41 ┊ 41 41 41 41 41 41 41 41 │AAAAAAAA┊AAAAAAAA│
│*       │                         ┊                         │        ┊        │
│00000030│ 00 00 00 00 00 00 00 00 ┊ 00 00 00 00 00 00 00 00 │⋄⋄⋄⋄⋄⋄⋄⋄┊⋄⋄⋄⋄⋄⋄⋄⋄│
│*       │                         ┊                         │        ┊        │
│00000050│                         ┊                         │        ┊        │
└────────┴─────────────────────────┴─────────────────────────┴────────┴────────┘";
        assert_eq!(plain(0, &repeated, opts(1, true)), squeezed);
    }

    /// No bytes prints hexyl's empty box; an address past eight hex
    /// digits widens the position column to hold it whole.
    #[test]
    fn test_render_empty_and_wide_positions() {
        let empty = "\
┌────────┬─────────────────────────┬─────────────────────────┬────────┬────────┐
│        │ No content              │                         │        │        │
└────────┴─────────────────────────┴─────────────────────────┴────────┴────────┘";
        assert_eq!(plain(0x1000, &[], opts(1, true)), empty);

        let wide = plain(0xfffff1ffffdffef0, b"hi", opts(1, true));
        assert!(
            wide.lines()
                .nth(1)
                .unwrap()
                .starts_with("│fffff1ffffdffef0│ 68 69 "),
            "{wide}"
        );
        assert!(wide.starts_with(&format!("┌{}┬", "─".repeat(16))), "{wide}");
    }

    /// Styled, each run of one kind of byte takes its hexyl hue, in the
    /// hex panel and the character panel alike, and the position its
    /// bright black; the text between the escapes is the plain line.
    #[test]
    fn test_render_styles_bytes_by_kind() {
        let styled = render(0, b"ab\0 \xff", opts(1, true), Theme::forced());
        let line = &styled[1];
        assert!(line.contains("\x1b[90m00000000\x1b[0m"), "{line:?}");
        assert!(line.contains("\x1b[36m61 62 \x1b[0m"), "{line:?}");
        assert!(line.contains("\x1b[90m00 \x1b[0m"), "{line:?}");
        assert!(line.contains("\x1b[32m20 \x1b[0m"), "{line:?}");
        assert!(line.contains("\x1b[33mff "), "{line:?}");
        assert!(
            line.contains("\x1b[36mab\x1b[0m\x1b[90m⋄\x1b[0m"),
            "{line:?}"
        );
        let escapes = regex::Regex::new("\x1b\\[[0-9]+m").unwrap();
        let unstyled = escapes.replace_all(line, "");
        assert_eq!(
            unstyled,
            plain(0, b"ab\0 \xff", opts(1, true))
                .lines()
                .nth(1)
                .unwrap()
        );
    }

    /// A read that fails whole is retried a byte at a time: the run
    /// stops at the first byte the target cannot serve, across chunk
    /// boundaries, and says where; a run it serves whole has no
    /// failure.
    #[test]
    fn test_read_run_stops_at_the_first_unreadable_byte() {
        let base = 0x10_0f00u64;
        let memory: Vec<u8> = (0..5000u32).map(|i| i as u8).collect();
        let read = |at: u64, n: u64| -> Result<&[u8]> {
            let start = at.checked_sub(base).ok_or_else(|| anyhow!("below"))? as usize;
            memory
                .get(start..start + n as usize)
                .ok_or_else(|| anyhow!("not mapped"))
        };
        let (bytes, failure) = read_run(read, base, 6000);
        assert_eq!(bytes, memory);
        let (at, err) = failure.expect("the run ends short");
        assert_eq!(at, base + 5000);
        assert_eq!(err.to_string(), "not mapped");

        let (bytes, failure) = read_run(read, base + 10, 4096);
        assert_eq!(bytes, memory[10..4106]);
        assert!(failure.is_none());

        let (bytes, failure) = read_run(read, base - 1, 16);
        assert!(bytes.is_empty());
        assert_eq!(failure.expect("nothing reads").0, base - 1);
    }

    /// Over a fixture's frame, a value dumps its contents where it
    /// keeps them: a `Vec`'s and a string's buffer, a range's run of
    /// elements, a scalar's own bytes; `--length` overrides the extent.
    /// A map's entries, and a path from an untyped address, are
    /// refused.
    #[test]
    fn test_dump_finds_a_values_bytes() {
        use crate::offline::session_args;
        use crate::{TraceTarget, cursor};
        use hansei_runtime::testkit;
        let (bundle, core) = testkit::load(testkit::set_or_any("illumos"), "simple-await");
        let args = session_args(testkit::set_or_any("illumos"), "simple-await");
        let session = Session::attach(&core, &bundle, &args).expect("the pair attaches");
        let id = session.tasks.tasks[0]
            .task_id
            .expect("the fixture's tasks carry ids");
        cursor::select_task(&session, TraceTarget::Task(id)).expect("the task selects");
        session.cursor.borrow_mut().frame = 1;
        let dump = |words: &[&str], length: Option<u64>| {
            let words: Vec<String> = words.iter().map(|w| w.to_string()).collect();
            let opts = DumpOpts {
                length,
                ..opts(1, true)
            };
            let mut out = Vec::new();
            exec_dump(&session, &words, opts, Theme::plain(), &mut out)
                .map(|()| String::from_utf8(out).unwrap())
        };
        let frame = cursor::frame_value(&session).expect("the frame reads");
        let values = frame.member("values").expect("the local reads");
        let (buffer, len) = values
            .buffer()
            .expect("a Vec keeps a buffer")
            .expect("its header decodes");
        assert_eq!(len, 12, "three u32s");

        let vec = dump(&["values"], None).unwrap();
        assert_eq!(
            vec.lines().nth(1).unwrap(),
            format!(
                "│{buffer:08x}│ 05 00 00 00 08 00 00 00 ┊ 0d 00 00 00{} │•⋄⋄⋄•⋄⋄⋄┊_⋄⋄⋄    │",
                " ".repeat(12)
            ),
        );
        let range = dump(&["values[1..3]"], None).unwrap();
        assert!(
            range
                .lines()
                .nth(1)
                .unwrap()
                .starts_with(&format!("│{:08x}│ 08 00 00 00 0d 00 00 00 ┊", buffer + 4)),
            "{range}"
        );
        let string = dump(&["owned"], None).unwrap();
        assert!(string.contains("│owned_te┊xt      │"), "{string}");
        let count = frame.member("count").expect("the local reads");
        let scalar = dump(&["count"], None).unwrap();
        assert!(
            scalar.contains(&format!("│{:08x}│ 03 00 00 00    ", count.addr)),
            "{scalar}"
        );
        let cut = dump(&["values"], Some(2)).unwrap();
        assert!(cut.contains("│ 05 00                   ┊"), "{cut}");

        let err = dump(&["labels[..2]"], None).expect_err("entries are no run");
        assert!(err.to_string().contains("map's entries"), "{err}");
        let err = dump(&["0x10", ".a"], None).expect_err("no type to read");
        assert!(err.to_string().contains("needs the type"), "{err}");
        let err = dump(&["0x10"], None).expect_err("nothing at 0x10");
        assert!(err.to_string().contains("failed to read 0x10"), "{err}");
    }

    /// A dump that runs past the end of readable memory shows what the
    /// target holds and says where the rest failed.
    #[test]
    fn test_dump_shows_the_readable_prefix() {
        use crate::offline::session_args;
        use crate::{TraceTarget, cursor};
        use hansei_runtime::testkit;
        let (bundle, core) = testkit::load(testkit::set_or_any("illumos"), "simple-await");
        let args = session_args(testkit::set_or_any("illumos"), "simple-await");
        let session = Session::attach(&core, &bundle, &args).expect("the pair attaches");
        let id = session.tasks.tasks[0]
            .task_id
            .expect("the fixture's tasks carry ids");
        cursor::select_task(&session, TraceTarget::Task(id)).expect("the task selects");
        session.cursor.borrow_mut().frame = 1;
        let frame = cursor::frame_value(&session).expect("the frame reads");
        let (buffer, _) = frame.member("values").unwrap().buffer().unwrap().unwrap();
        // Where readable memory past the buffer ends. `readable_len`
        // answers one run at a time, and a core's heap goes on across
        // the boundary between two of its segments, so walk them.
        let mut end = buffer;
        loop {
            match proc::Target::readable_len(session.ctx.proc, end, 1 << 20) {
                0 => break,
                n => end += n,
            }
        }
        // From a little short of it, so the dump stays small however
        // far the heap runs.
        let start = end.saturating_sub(64).max(buffer);
        let readable = end - start;
        let words = vec![format!("{start:#x}")];
        let opts = DumpOpts {
            length: Some(readable + 64),
            ..opts(1, false)
        };
        let mut out = Vec::new();
        exec_dump(&session, &words, opts, Theme::plain(), &mut out).expect("the prefix dumps");
        let out = String::from_utf8(out).unwrap();
        let last = out.lines().last().unwrap();
        assert_eq!(
            last.split(';').next().unwrap(),
            format!("{readable} of {} bytes shown", readable + 64),
            "{out}"
        );
        assert!(last.contains(&format!("failed to read {end:#x}")), "{out}");
    }

    /// Lengths are decimal or 0x-hex; a group is a number's width.
    #[test]
    fn test_parse_length_and_group_size() {
        assert_eq!(crate::parse_length("64"), Ok(64));
        assert_eq!(crate::parse_length("0x40"), Ok(64));
        assert!(crate::parse_length("4k").is_err());
        for n in [1, 2, 4, 8] {
            assert_eq!(crate::parse_group_size(&n.to_string()), Ok(n));
        }
        for bad in ["0", "3", "16", "x"] {
            assert!(crate::parse_group_size(bad).is_err(), "{bad}");
        }
    }
}
