// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! The `connections` listing: every HTTP connection the target holds,
//! a row apiece, read from the connection resources the wait analysis
//! and the census observed — the verdict's words and the facts beside
//! them (the peer, the handler, the read buffer, an armed timer's
//! deadline), which the task block does not have room to say.

use crate::runtimes::RowOwner;
use crate::tasks::{Cmp, EMPTY_BUCKET, alternatives, distinct_values, listing_footer, task_id};
use crate::{Session, output, print_warnings};

use anyhow::{Context as _, Result, anyhow};
use hansei_bundle::names::ImplFold;
use hansei_bundle::{HttpRole, names};
use hansei_runtime::tokio::assess::{client_phase, server_phase};
use hansei_runtime::tokio::bundle::{HttpPhase, HttpVersion, deadline_text, http_kind_word};
use hansei_runtime::tokio::observe::ResourceObservation;
use hansei_runtime::tokio::{RawInstant, census};

use std::collections::BTreeMap;
use std::io;

/// One row of the listing: a connection the target holds, as its
/// dispatcher's words were read.
#[derive(Clone, Debug)]
pub(crate) struct ConnRow {
    /// The `Conn`'s address — the wrapper's own for a connection still
    /// choosing its version — which is what a filter names.
    pub(crate) addr: u64,
    /// The task driving the connection, as an index and as `tasks`
    /// names it.
    pub(crate) owner: usize,
    pub(crate) task: String,
    pub(crate) rt: RowOwner,
    pub(crate) role: HttpRole,
    pub(crate) version: Option<HttpVersion>,
    /// The phase the verdict decided, or `None` where the words did
    /// not decide one.
    pub(crate) phase: Option<HttpPhase>,
    /// The method of the message in flight, `None` between exchanges.
    pub(crate) method: Option<String>,
    /// The peer's address, where the service the server drives keeps
    /// one under a reviewed convention.
    pub(crate) peer: Option<String>,
    /// A server's running handler, by its future type.
    pub(crate) handler: Option<String>,
    /// The read buffer's fill and capacity.
    pub(crate) read_buf: Option<(u64, u64)>,
    /// The header-read timer's deadline, where the server has armed
    /// one and the task holds it.
    pub(crate) deadline: Option<String>,
}

impl ConnRow {
    fn role_word(&self) -> &'static str {
        match self.role {
            HttpRole::Client => "client",
            HttpRole::Server => "server",
        }
    }

    fn version_word(&self) -> Option<&'static str> {
        self.version.map(|version| match version {
            HttpVersion::Http1 => "http1",
        })
    }

    fn phase_word(&self) -> Option<&'static str> {
        self.phase.map(|phase| phase.word())
    }

    /// The `BUF` cell: bytes read and not yet parsed over the capacity.
    fn buffer_cell(&self) -> Option<String> {
        self.read_buf.map(|(len, cap)| format!("{len}/{cap}"))
    }

    /// How the row names itself in a bucket's sample: the kind word
    /// and the address, as the task block's line opens.
    fn label(&self) -> String {
        format!(
            "{} {:#x}",
            http_kind_word(self.role, self.version),
            self.addr
        )
    }
}

/// The rows over a session: every connection resource the tasks' own
/// chains end in, then every one the census found held in a frame —
/// a connection behind a wrapper no rule delegates through — in task
/// order, each connection once.
pub(crate) fn rows<'s, T: proc::Target>(session: &'s Session<'_, T>) -> &'s [ConnRow] {
    session.conn_rows.get_or_init(|| build_rows(session))
}

fn build_rows<T: proc::Target>(session: &Session<'_, T>) -> Vec<ConnRow> {
    let census = session.census();
    let stopped = session.registries.stopped;
    let mut rows: Vec<ConnRow> = Vec::new();
    let mut seen = std::collections::HashSet::new();
    let mut push = |owner: usize, observation: &ResourceObservation| {
        let Some(row) = row_of(session, owner, observation, census, stopped) else {
            return;
        };
        if seen.insert(row.addr) {
            rows.push(row);
        }
    };
    for (owner, wait) in session.analysis().waits.iter().enumerate() {
        if let Some(observation) = &wait.observation {
            push(owner, observation);
        }
    }
    for held in &census.held {
        if let Some(observation) = &held.observation {
            push(held.owner, observation);
        }
    }
    for set in &census.sets {
        for child in &set.children {
            if let Some(observation) = &child.observation {
                push(set.owner, observation);
            }
        }
    }
    rows.sort_by_key(|row| (row.owner, row.addr));
    rows
}

/// One connection's row from the observation its chain ended in, or
/// `None` for an observation of some other resource.
fn row_of<T: proc::Target>(
    session: &Session<'_, T>,
    owner: usize,
    observation: &ResourceObservation,
    census: &census::FutureCensus,
    stopped: Option<RawInstant>,
) -> Option<ConnRow> {
    let list = &session.tasks;
    let base = ConnRow {
        addr: 0,
        owner,
        task: task_id(list, owner),
        rt: RowOwner::of(&list.tasks[owner], &session.owners),
        role: HttpRole::Server,
        version: None,
        phase: None,
        method: None,
        peer: None,
        handler: None,
        read_buf: None,
        deadline: None,
    };
    conn_row(
        base,
        observation,
        held_deadline(census, owner),
        stopped,
        &session.impl_fold,
    )
}

/// Fill `base` — the row's task cells — from the observation: the
/// negotiating wrapper's address and phase, or the connection's words
/// with the facts beside them. `held` is the deadline of a timer the
/// task holds, which is the header-read timer's when the server has
/// armed one and nothing otherwise.
fn conn_row(
    base: ConnRow,
    observation: &ResourceObservation,
    held: Option<RawInstant>,
    stopped: Option<RawInstant>,
    impls: &ImplFold,
) -> Option<ConnRow> {
    match observation {
        // A wrapper still reading the first bytes has no version, no
        // words and no service to hold a peer: the phase is all.
        ResourceObservation::HttpNegotiating(negotiating) => Some(ConnRow {
            addr: negotiating.wrapper.addr,
            role: HttpRole::Server,
            version: None,
            phase: Some(HttpPhase::Negotiating),
            method: None,
            peer: None,
            handler: None,
            read_buf: None,
            deadline: None,
            ..base
        }),
        ResourceObservation::HttpConn(http) => {
            let phase = match http.role {
                HttpRole::Client => client_phase(http),
                HttpRole::Server => server_phase(http),
            }
            .ok()
            .map(|(phase, _)| phase);
            let server = http.server.as_ref();
            let deadline = server
                .filter(|server| server.header_read_timer_running)
                .and(held)
                .map(|deadline| deadline_text(deadline, stopped));
            Some(ConnRow {
                addr: http.conn,
                role: http.role,
                version: Some(HttpVersion::Http1),
                phase,
                method: http.method.clone(),
                peer: server.and_then(|server| server.peer.clone()),
                handler: server.and_then(|server| {
                    server
                        .handler
                        .as_deref()
                        .map(|handler| names::display_future_name(handler, impls))
                }),
                read_buf: http.read_buf,
                deadline,
                ..base
            })
        }
        _ => None,
    }
}

/// The deadline of a timer the task holds in its own frames — the
/// header-read sleep the server arms — where the census found one.
fn held_deadline(census: &census::FutureCensus, owner: usize) -> Option<RawInstant> {
    census
        .held
        .iter()
        .filter(|held| held.owner == owner)
        .find_map(|held| match &held.observation {
            Some(ResourceObservation::Timer(timer)) => timer.deadline,
            _ => None,
        })
}

/// One row's table cells, in column order.
fn row_cells(row: &ConnRow, groups: bool) -> Vec<String> {
    let dash = || "—".to_string();
    let mut cells = vec![format!("{:#x}", row.addr), row.task.clone()];
    if groups {
        cells.push(row.rt.cell());
    }
    cells.extend([
        row.role_word().to_string(),
        row.version_word().map_or_else(dash, str::to_string),
        row.phase_word().map_or_else(dash, str::to_string),
        row.method.clone().unwrap_or_else(dash),
        row.peer.clone().unwrap_or_else(dash),
        row.buffer_cell().unwrap_or_else(dash),
        row.deadline.clone().unwrap_or_else(dash),
        row.handler.clone().unwrap_or_else(dash),
    ]);
    cells
}

/// Print the listing: one row per connection, the handler's type last
/// since it is the one cell that runs wide, and the count under it.
fn print_table(
    rows: &[&ConnRow],
    groups: bool,
    limit: Option<usize>,
    fit: Option<usize>,
    theme: output::Theme,
    out: &mut dyn io::Write,
) -> Result<()> {
    let shown = limit.unwrap_or(rows.len()).min(rows.len());
    let mut header = vec!["ADDR", "TASK"];
    if groups {
        header.push("RT");
    }
    header.extend([
        "ROLE", "VER", "PHASE", "METHOD", "PEER", "BUF", "DEADLINE", "HANDLER",
    ]);
    let columns = header.len();
    let mut table = output::Table::new(columns)
        .header(header)
        .truncatable(columns - 1)
        .fit(fit)
        .theme(theme);
    for row in &rows[..shown] {
        table.row(row_cells(row, groups));
    }
    if !table.is_empty() {
        table.write(out)?;
    }
    writeln!(out, "{}", listing_footer(rows.len(), shown, "connection"))?;
    Ok(())
}

/// Everything the `connections` command was asked.
pub(crate) struct ConnectionsCmd {
    pub(crate) limit: Option<usize>,
    pub(crate) with: Vec<String>,
    pub(crate) without: Vec<String>,
    pub(crate) group: Option<String>,
}

/// One filterable field of the connection population — what `--with`,
/// `--without` and `--group` name.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum Field {
    /// The driving task's id — exact.
    Task,
    /// The owner's group index `runtimes` prints — exact.
    Rt,
    /// The address — exact.
    Addr,
    /// `client` or `server`.
    Role,
    /// The version word, `http1`.
    Version,
    /// The phase as the bucket names it.
    Phase,
    /// The method in flight.
    Method,
    /// The peer's address as printed.
    Peer,
    /// The running handler's type.
    Handler,
    /// The bytes read and not yet parsed — compared.
    Buffered,
}

impl Field {
    const NAMES: [(&'static str, Field); 10] = [
        ("task", Field::Task),
        ("rt", Field::Rt),
        ("addr", Field::Addr),
        ("role", Field::Role),
        ("version", Field::Version),
        ("phase", Field::Phase),
        ("method", Field::Method),
        ("peer", Field::Peer),
        ("handler", Field::Handler),
        ("buffered", Field::Buffered),
    ];

    /// Every field name, in the order the errors list them.
    pub(crate) fn names() -> impl Iterator<Item = &'static str> {
        Self::NAMES.iter().map(|(n, _)| *n)
    }

    fn parse(name: &str) -> Result<Field> {
        Self::NAMES
            .iter()
            .find(|(n, _)| *n == name)
            .map(|(_, f)| *f)
            .ok_or_else(|| {
                anyhow!(
                    "no field {name:?}; the fields are {}",
                    Self::NAMES.map(|(n, _)| n).join(", ")
                )
            })
    }

    fn name(self) -> &'static str {
        Self::NAMES
            .iter()
            .find(|(_, f)| *f == self)
            .map(|(n, _)| *n)
            .expect("every field is named")
    }

    fn is_pattern(self) -> bool {
        matches!(
            self,
            Field::Role
                | Field::Version
                | Field::Phase
                | Field::Method
                | Field::Peer
                | Field::Handler
        )
    }

    /// The spelled value a row holds for the field — `None` where the
    /// row has nothing in the column.
    fn text(self, row: &ConnRow) -> Option<String> {
        match self {
            Field::Task => Some(row.task.clone()),
            Field::Rt => Some(row.rt.cell()),
            Field::Addr => Some(format!("{:#x}", row.addr)),
            Field::Role => Some(row.role_word().to_string()),
            Field::Version => row.version_word().map(str::to_string),
            Field::Phase => row.phase_word().map(str::to_string),
            Field::Method => row.method.clone(),
            Field::Peer => row.peer.clone(),
            Field::Handler => row.handler.clone(),
            Field::Buffered => row.read_buf.map(|(len, _)| len.to_string()),
        }
    }

    /// The distinct values the rows hold for the field, or `None` for
    /// the count the argument compares against.
    fn values(self, rows: &[ConnRow]) -> Option<Vec<String>> {
        match self {
            Field::Buffered => None,
            _ => Some(distinct_values(rows.iter().map(|row| self.text(row)))),
        }
    }
}

/// The values the target holds for `field`, for the prompt to offer
/// after `--with FIELD` (see `tasks::field_values`).
pub(crate) fn field_values<T: proc::Target>(
    session: &Session<'_, T>,
    field: &str,
) -> Option<(Vec<String>, bool)> {
    let field = Field::parse(field).ok()?;
    Some((field.values(rows(session))?, field.is_pattern()))
}

/// How one clause matches its field's value.
#[derive(Debug)]
enum Matcher {
    Pattern(crate::pattern::Pattern),
    /// Exact text: the task id, the owner cell, the address.
    Exact(String),
    /// `'>N'` / `'<N'` / `'=N'`: the buffered count.
    Cmp(Cmp),
}

#[derive(Debug)]
struct Clause {
    field: Field,
    matchers: Vec<Matcher>,
    negate: bool,
}

fn parse_clauses(with: &[String], without: &[String], handles: &[u64]) -> Result<Vec<Clause>> {
    let mut clauses = Vec::new();
    for (specs, negate) in [(with, false), (without, true)] {
        let flag = if negate { "--without" } else { "--with" };
        for [name, spec] in specs.as_chunks::<2>().0 {
            let field = Field::parse(name).with_context(|| flag.to_string())?;
            let matchers = alternatives(spec)
                .and_then(|alts| {
                    alts.iter()
                        .map(|alt| matcher(field, alt, handles))
                        .collect()
                })
                .with_context(|| format!("{flag} {}", field.name()))?;
            clauses.push(Clause {
                field,
                matchers,
                negate,
            });
        }
    }
    Ok(clauses)
}

/// The matcher one field's argument compiles to: an address is held to
/// the `0x` form the listing prints, an owner to the group cell
/// `runtimes` numbers (the `?`/`!` marks, or the words for them).
fn matcher(field: Field, arg: &str, handles: &[u64]) -> Result<Matcher> {
    Ok(match field {
        Field::Task => Matcher::Exact(arg.to_string()),
        Field::Rt => Matcher::Exact(crate::tasks::resolve_rt(arg, handles)?.cell()),
        Field::Addr => {
            let digits = arg
                .strip_prefix("0x")
                .or_else(|| arg.strip_prefix("0X"))
                .ok_or_else(|| {
                    anyhow!("an addr is the 0x address a connections row prints, got {arg:?}")
                })?;
            let addr = u64::from_str_radix(digits, 16)
                .map_err(|e| anyhow!("invalid address {arg:?}: {e}"))?;
            Matcher::Exact(format!("{addr:#x}"))
        }
        Field::Buffered => Matcher::Cmp(Cmp::parse(arg)?),
        _ => Matcher::Pattern(crate::pattern::Pattern::new(arg)?),
    })
}

fn survives(clause: &Clause, row: &ConnRow) -> bool {
    let text = clause.field.text(row);
    let hit = clause.matchers.iter().any(|matcher| match matcher {
        Matcher::Pattern(p) => text.as_deref().is_some_and(|t| p.is_match(t)),
        Matcher::Exact(value) => text.as_deref() == Some(value.as_str()),
        Matcher::Cmp(cmp) => row
            .read_buf
            .is_some_and(|(len, _)| cmp.matches(len as usize)),
    });
    hit != clause.negate
}

/// Up to three member labels and `…` — the sample a bucket row
/// carries.
fn member_sample(rows: &[ConnRow], members: &[usize]) -> String {
    let labels: Vec<String> = members.iter().take(3).map(|&i| rows[i].label()).collect();
    match members.len() > labels.len() {
        true => format!("{}, …", labels.join(", ")),
        false => labels.join(", "),
    }
}

/// Every connection the target holds, one table row each; the filter
/// clauses narrow the listing, `--group` tallies it.
pub(crate) fn exec_connections<T: proc::Target>(
    session: &Session<'_, T>,
    cmd: ConnectionsCmd,
    theme: output::Theme,
    out: &mut dyn io::Write,
) -> Result<()> {
    let group = cmd
        .group
        .as_deref()
        .map(Field::parse)
        .transpose()
        .context("--group")?;
    let handles: Vec<u64> = session.runtimes.iter().map(|rt| rt.handle.addr).collect();
    let clauses = parse_clauses(&cmd.with, &cmd.without, &handles)?;

    let rows = rows(session);
    let survivors: Vec<usize> = (0..rows.len())
        .filter(|&i| clauses.iter().all(|c| survives(c, &rows[i])))
        .collect();

    if let Some(field) = group {
        return exec_group(
            rows,
            field,
            &survivors,
            cmd.limit,
            session.fit_width(theme),
            theme,
            out,
        );
    }
    let groups = session.owner_column();
    let selected: Vec<&ConnRow> = survivors.iter().map(|&i| &rows[i]).collect();
    print_table(
        &selected,
        groups,
        cmd.limit,
        session.fit_width(theme),
        theme,
        out,
    )?;
    print_warnings(&session.tasks.errors)?;
    Ok(())
}

/// `--group FIELD`: bucket the surviving rows by the field's spelled
/// value and print `COUNT VALUE` rows, most numerous first (ties in
/// value order), each with up to three member labels. `--limit` cuts
/// buckets.
fn exec_group(
    rows: &[ConnRow],
    field: Field,
    survivors: &[usize],
    limit: Option<usize>,
    fit: Option<usize>,
    theme: output::Theme,
    out: &mut dyn io::Write,
) -> Result<()> {
    let mut grouped: BTreeMap<String, Vec<usize>> = BTreeMap::new();
    for &index in survivors {
        let value = field
            .text(&rows[index])
            .unwrap_or_else(|| EMPTY_BUCKET.to_string());
        grouped.entry(value).or_default().push(index);
    }
    let mut buckets: Vec<(String, Vec<usize>)> = grouped.into_iter().collect();
    buckets.sort_by_key(|(_, members)| std::cmp::Reverse(members.len()));
    let shown = limit.unwrap_or(buckets.len()).min(buckets.len());

    let heading = field.name().to_uppercase();
    let mut table = output::Table::new(3)
        .align_right(0)
        .header(["COUNT".to_string(), heading, "CONNECTIONS".to_string()])
        .truncatable(1)
        .fit(fit)
        .theme(theme);
    for (value, members) in &buckets[..shown] {
        table.row([
            members.len().to_string(),
            value.clone(),
            member_sample(rows, members),
        ]);
    }
    if !table.is_empty() {
        table.write(out)?;
    }
    writeln!(out, "{}", listing_footer(buckets.len(), shown, "group"))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    use hansei_runtime::tokio::TaskAddr;
    use hansei_runtime::tokio::assess::ContinuationStatus;
    use hansei_runtime::tokio::observe::{
        HttpConnObservation, HttpNegotiatingObservation, HttpReading, HttpServerObservation,
        HttpWriting, JoinObservation, KeepAlive, TimerObservation, TimerRegistrationState,
        ValueKey,
    };

    fn row(addr: u64, role: HttpRole, phase: Option<HttpPhase>) -> ConnRow {
        ConnRow {
            addr,
            owner: 0,
            task: "7".to_string(),
            rt: RowOwner::Group(0),
            role,
            version: Some(HttpVersion::Http1),
            phase,
            method: Some("GET".to_string()),
            peer: Some("[fd00::25]:57400".to_string()),
            handler: None,
            read_buf: Some((12, 8192)),
            deadline: None,
        }
    }

    /// Every field selects: the patterns over their spelled values, the
    /// exact ones held to the listing's own spelling, the count compared.
    #[test]
    fn test_clauses_select_by_every_field() {
        let rows = [
            row(0x10, HttpRole::Client, Some(HttpPhase::AwaitingResponse)),
            row(0x20, HttpRole::Server, Some(HttpPhase::Idle)),
            ConnRow {
                version: None,
                method: None,
                peer: None,
                read_buf: None,
                ..row(0x30, HttpRole::Server, Some(HttpPhase::Negotiating))
            },
            // A task and an owner whose spellings contain the others':
            // the exact fields must not read as patterns.
            ConnRow {
                task: "17".to_string(),
                rt: RowOwner::Group(10),
                ..row(0x40, HttpRole::Client, Some(HttpPhase::Closing))
            },
        ];
        let select = |with: &[&str]| -> Vec<u64> {
            let with: Vec<String> = with.iter().map(|s| s.to_string()).collect();
            let clauses = parse_clauses(&with, &[], &[]).unwrap();
            rows.iter()
                .filter(|row| clauses.iter().all(|c| survives(c, row)))
                .map(|row| row.addr)
                .collect()
        };
        assert_eq!(select(&["role", "client"]), [0x10, 0x40]);
        assert_eq!(select(&["role", "server"]), [0x20, 0x30]);
        assert_eq!(select(&["version", "http1"]), [0x10, 0x20, 0x40]);
        assert_eq!(select(&["phase", "awaiting"]), [0x10]);
        assert_eq!(select(&["phase", "idle,negotiating"]), [0x20, 0x30]);
        assert_eq!(select(&["method", "get"]), [0x10, 0x20, 0x40]);
        assert_eq!(select(&["peer", "fd00"]), [0x10, 0x20, 0x40]);
        assert_eq!(select(&["addr", "0x20"]), [0x20]);
        assert_eq!(select(&["task", "7"]), [0x10, 0x20, 0x30]);
        assert_eq!(select(&["task", "17"]), [0x40]);
        assert_eq!(select(&["rt", "0"]), [0x10, 0x20, 0x30]);
        assert_eq!(select(&["rt", "10"]), [0x40]);
        assert_eq!(select(&["buffered", ">0"]), [0x10, 0x20, 0x40]);
        assert_eq!(select(&["buffered", "=0"]), []);
        // A row with nothing in the column never matches a pattern.
        assert_eq!(select(&["method", "."]), [0x10, 0x20, 0x40]);
        // `--without` keeps the misses.
        let without = ["role".to_string(), "server".to_string()];
        let clauses = parse_clauses(&[], &without, &[]).unwrap();
        let kept: Vec<u64> = rows
            .iter()
            .filter(|row| clauses.iter().all(|c| survives(c, row)))
            .map(|row| row.addr)
            .collect();
        assert_eq!(kept, [0x10, 0x40]);
    }

    #[test]
    fn test_malformed_clauses_are_refused() {
        let refused = |with: &[&str]| {
            let with: Vec<String> = with.iter().map(|s| s.to_string()).collect();
            format!("{:#}", parse_clauses(&with, &[], &[]).unwrap_err())
        };
        assert!(refused(&["nope", "x"]).contains("no field \"nope\""));
        assert!(refused(&["addr", "20"]).contains("0x address"));
        assert!(refused(&["buffered", "many"]).contains("'>N', '<N' or '=N'"));
    }

    /// The cells spell the row: a dash where a column is empty, the
    /// buffer as fill over capacity, the owner only when asked.
    #[test]
    fn test_cells_spell_the_row() {
        let full = row(0x10, HttpRole::Client, Some(HttpPhase::AwaitingResponse));
        assert_eq!(
            row_cells(&full, true),
            [
                "0x10",
                "7",
                "0",
                "client",
                "http1",
                "awaiting response",
                "GET",
                "[fd00::25]:57400",
                "12/8192",
                "—",
                "—"
            ]
        );
        let bare = ConnRow {
            version: None,
            method: None,
            peer: None,
            read_buf: None,
            deadline: Some("deadline +29.981s".to_string()),
            handler: Some("app::handle".to_string()),
            ..row(0x30, HttpRole::Server, None)
        };
        assert_eq!(
            row_cells(&bare, false),
            [
                "0x30",
                "7",
                "server",
                "—",
                "—",
                "—",
                "—",
                "—",
                "deadline +29.981s",
                "app::handle"
            ]
        );
        assert_eq!(full.label(), "http1 client 0x10");
        assert_eq!(bare.label(), "http server 0x30");
    }

    fn key(addr: u64) -> ValueKey {
        ValueKey {
            addr,
            ty: hansei_bundle::BundleTypeId(3),
        }
    }

    fn instant(secs: u64) -> RawInstant {
        RawInstant {
            tv_sec: secs,
            tv_nsec: 0,
        }
    }

    fn server_observation(header_read_timer_running: bool) -> ResourceObservation {
        ResourceObservation::HttpConn(Box::new(HttpConnObservation {
            dispatcher: key(0x7b78948),
            conn: 0x7b78948,
            role: HttpRole::Server,
            keep_alive: KeepAlive::Idle,
            reading: HttpReading::Init,
            writing: HttpWriting::Init,
            method: None,
            is_closing: false,
            read_buf: Some((0, 8192)),
            client: None,
            server: Some(HttpServerObservation {
                in_flight: false,
                handler: Some("app::handle::{async_fn_env#0}".to_string()),
                header_read_timer_running,
                peer: Some("[fd00::25]:57400".to_string()),
            }),
        }))
    }

    /// The facts beside the verdict reach the row: the peer, the
    /// handler as a future is named, the buffer, and the deadline of
    /// the held timer — only while the header-read timer is armed. A
    /// negotiating wrapper is a row at its own address with no words;
    /// any other observation is no row.
    #[test]
    fn test_the_observation_fills_the_row() {
        // The base carries a sentinel in every cell the observation
        // fills, so a cell the arm left to the base is told from one
        // it set.
        let base = ConnRow {
            version: Some(HttpVersion::Http1),
            phase: Some(HttpPhase::Closing),
            method: Some("SENTINEL".to_string()),
            peer: Some("SENTINEL".to_string()),
            handler: Some("SENTINEL".to_string()),
            read_buf: Some((1, 1)),
            deadline: Some("SENTINEL".to_string()),
            ..row(0, HttpRole::Client, None)
        };
        let impls = ImplFold::default();
        let held = Some(instant(130));
        let stopped = Some(instant(100));
        let armed = conn_row(
            base.clone(),
            &server_observation(true),
            held,
            stopped,
            &impls,
        )
        .unwrap();
        assert_eq!(armed.addr, 0x7b78948);
        assert_eq!(armed.role, HttpRole::Server);
        assert_eq!(armed.version, Some(HttpVersion::Http1));
        assert_eq!(armed.phase, Some(HttpPhase::Idle));
        assert_eq!(armed.method, None);
        assert_eq!(armed.peer.as_deref(), Some("[fd00::25]:57400"));
        assert_eq!(armed.handler.as_deref(), Some("async fn app::handle"));
        assert_eq!(armed.read_buf, Some((0, 8192)));
        assert_eq!(armed.deadline.as_deref(), Some("deadline +30.000s"));
        // The task's cells come from the base.
        assert_eq!(armed.task, "7");
        let idle = conn_row(
            base.clone(),
            &server_observation(false),
            held,
            stopped,
            &impls,
        )
        .unwrap();
        assert_eq!(idle.deadline, None);
        let unheld = conn_row(
            base.clone(),
            &server_observation(true),
            None,
            stopped,
            &impls,
        )
        .unwrap();
        assert_eq!(unheld.deadline, None);
        let negotiating = conn_row(
            base.clone(),
            &ResourceObservation::HttpNegotiating(HttpNegotiatingObservation {
                wrapper: key(0x12345),
            }),
            held,
            stopped,
            &impls,
        )
        .unwrap();
        assert_eq!(negotiating.addr, 0x12345);
        assert_eq!(negotiating.role, HttpRole::Server);
        assert_eq!(negotiating.phase, Some(HttpPhase::Negotiating));
        assert_eq!(negotiating.version, None);
        assert_eq!(negotiating.method, None);
        assert_eq!(negotiating.peer, None);
        assert_eq!(negotiating.handler, None);
        assert_eq!(negotiating.read_buf, None);
        assert_eq!(negotiating.deadline, None);
        assert_eq!(negotiating.label(), "http server 0x12345");
        let other = ResourceObservation::Join(JoinObservation {
            handle: key(0x1),
            header: TaskAddr(0x1),
        });
        assert!(conn_row(base, &other, held, stopped, &impls).is_none());
    }

    /// The held deadline is the owner's own timer find and nothing
    /// else: another task's timer, or the owner's join, is not it.
    #[test]
    fn test_the_held_deadline_is_the_owners_timer() {
        let timer = |owner: usize, deadline: Option<RawInstant>| census::HeldFuture {
            owner,
            frame: 0,
            local: "sleep".to_string(),
            via: None,
            slot: 0x100,
            addr: 0x100,
            ty: hansei_bundle::BundleTypeId(0),
            depth: 1,
            frames: Vec::new(),
            future: "hyper_util::rt::tokio::TokioSleep".to_string(),
            state: None,
            waiting_on: None,
            wait: None,
            observation: Some(ResourceObservation::Timer(TimerObservation {
                future: key(0x100),
                deadline,
                state: TimerRegistrationState::Deregistered,
            })),
            continuation: ContinuationStatus::Primitive,
        };
        let join = census::HeldFuture {
            observation: Some(ResourceObservation::Join(JoinObservation {
                handle: key(0x1),
                header: TaskAddr(0x1),
            })),
            ..timer(0, None)
        };
        let census = census::FutureCensus::from_finds(
            vec![join, timer(1, Some(instant(5))), timer(0, Some(instant(9)))],
            Vec::new(),
            Vec::new(),
        );
        assert_eq!(held_deadline(&census, 0), Some(instant(9)));
        assert_eq!(held_deadline(&census, 1), Some(instant(5)));
        assert_eq!(held_deadline(&census, 2), None);
    }

    /// A bucket's sample names up to three members and marks the rest.
    #[test]
    fn test_a_bucket_sample_is_three_members_and_a_mark() {
        let rows: Vec<ConnRow> = (0..4)
            .map(|i| row(0x10 * (i + 1), HttpRole::Client, None))
            .collect();
        assert_eq!(
            member_sample(&rows, &[0, 1, 2]),
            "http1 client 0x10, http1 client 0x20, http1 client 0x30"
        );
        assert_eq!(
            member_sample(&rows, &[0, 1, 2, 3]),
            "http1 client 0x10, http1 client 0x20, http1 client 0x30, …"
        );
    }

    /// The fields' values over a real pair: the patterns' spelled
    /// values most frequent first, an exact field's flagged as no
    /// pattern, the compared field offering nothing.
    #[test]
    fn test_fields_offer_their_values_over_a_pair() {
        use crate::offline::session_args;
        use hansei_runtime::testkit;
        let (bundle, snapshot) = testkit::load("illumos", "http-conns");
        let args = session_args("illumos", "http-conns");
        let session = Session::attach(&snapshot, &bundle, &args).expect("the pair attaches");
        assert_eq!(
            field_values(&session, "role"),
            Some((vec!["server".to_string(), "client".to_string()], true))
        );
        let (phases, pattern) = field_values(&session, "phase").unwrap();
        assert!(pattern);
        assert_eq!(phases[0], "idle");
        assert_eq!(phases.len(), 4, "{phases:?}");
        let (addrs, pattern) = field_values(&session, "addr").unwrap();
        assert!(!pattern);
        assert_eq!(addrs.len(), 5, "{addrs:?}");
        assert!(addrs.iter().all(|a| a.starts_with("0x")), "{addrs:?}");
        assert_eq!(field_values(&session, "buffered"), None);
        assert_eq!(field_values(&session, "colour"), None);
    }

    #[test]
    fn test_fields_offer_their_values() {
        let rows = [
            row(0x10, HttpRole::Client, Some(HttpPhase::Idle)),
            row(0x20, HttpRole::Server, Some(HttpPhase::Idle)),
        ];
        assert_eq!(Field::Role.values(&rows).unwrap(), ["client", "server"]);
        assert_eq!(Field::Phase.values(&rows).unwrap(), ["idle"]);
        assert_eq!(Field::Buffered.values(&rows), None);
        assert!(Field::Peer.is_pattern());
        assert!(!Field::Addr.is_pattern());
        let names: Vec<&str> = Field::names().collect();
        assert_eq!(names.len(), 10);
        for name in names {
            assert_eq!(Field::parse(name).unwrap().name(), name);
        }
    }
}
