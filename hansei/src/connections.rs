// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! The `connections` listing: every connection the target holds, a row
//! apiece, read from what the wait analysis and the census observed —
//! an HTTP connection's resource, with the verdict's words and the facts
//! beside them (the peer, the accepting server, the task that sent a
//! client's request, the read buffer, an armed timer's deadline and how
//! long an idle server has waited), and every other socket a pending
//! read or write reaches through its stream's route, with the TLS
//! connection the route crossed where it crossed one — which the task
//! block does not have room to say.

use crate::runtimes::RowOwner;
use crate::tasks::{Cmp, EMPTY_BUCKET, alternatives, distinct_values, listing_footer, task_id};
use crate::{Session, output, print_warnings};

use anyhow::{Context as _, Result, anyhow};
use hansei_bundle::{HttpRole, IoSocket};
use hansei_runtime::tokio::assess::{client_phase, http_caller, server_phase};
use hansei_runtime::tokio::bundle::{HttpCaller, HttpPhase, TaskList, TlsVerdict, deadline_text};
use hansei_runtime::tokio::observe::{HttpRequestObservation, PoolPeers, ResourceObservation};
use hansei_runtime::tokio::wakers::Owner;
use hansei_runtime::tokio::{RawInstant, attribution, census};

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::io;
use std::time::Duration;

/// One row of the listing: a connection the target holds, as its
/// dispatcher's words were read.
#[derive(Clone, Debug)]
pub(crate) struct ConnRow {
    /// The `Conn`'s address — the wrapper's own for a connection still
    /// choosing its version — or, for a socket read through a stream,
    /// its registration's, which tells one connection from another and
    /// orders a task's rows; nothing else prints it, so no cell does.
    pub(crate) addr: u64,
    /// The task driving the connection, as an index and as `tasks`
    /// names it.
    pub(crate) owner: usize,
    pub(crate) task: String,
    pub(crate) rt: RowOwner,
    /// What the connection speaks on top of its socket.
    pub(crate) proto: Proto,
    /// Which end the target is: the HTTP role, or the TLS side. `None`
    /// for a bare socket, which says neither.
    pub(crate) role: Option<HttpRole>,
    /// The phase the verdict decided, or `None` where the words did
    /// not decide one.
    pub(crate) phase: Option<RowPhase>,
    /// The method of the message in flight, `None` between exchanges.
    pub(crate) method: Option<String>,
    /// The peer's address, where the service the server drives keeps
    /// one under a reviewed convention.
    pub(crate) peer: Option<String>,
    /// The context type of the server that accepted the connection,
    /// where its service names one under a reviewed convention.
    pub(crate) server: Option<String>,
    /// How long an idle server connection has waited for the next
    /// request head, where its header-read timer says.
    pub(crate) idle_for: Option<Duration>,
    /// The read buffer's fill and capacity: hyper's, or the TLS
    /// connection's deframer — bytes read off the socket and not yet
    /// parsed either way. A buffered stream on the way keeps its own,
    /// which this is not.
    pub(crate) read_buf: Option<(u64, u64)>,
    /// The header-read timer's deadline, where the server has armed
    /// one and the task holds it.
    pub(crate) deadline: Option<String>,
    /// The request behind the connection: what the server's handler is
    /// running for, or what the client's caller sent, where either was
    /// read.
    pub(crate) request: Option<RequestLine>,
    /// The task that sent a client's request in flight, as `tasks`
    /// names it: the task awaiting the response, or the one polling
    /// the set whose child awaits it.
    pub(crate) caller: Option<String>,
}

/// A request as the census read it: its method and its target's text,
/// kept apart so the listing can print the method in its own column
/// beside the text.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct RequestLine {
    pub(crate) method: Option<String>,
    pub(crate) text: Option<String>,
}

impl From<&HttpRequestObservation> for RequestLine {
    fn from(request: &HttpRequestObservation) -> Self {
        RequestLine {
            method: request.method.clone(),
            text: request.text.clone(),
        }
    }
}

impl std::fmt::Display for RequestLine {
    /// The whole line, as a block prints it and as
    /// [`HttpRequestObservation`] prints itself: `GET /park`.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.method.as_deref().unwrap_or("request"))?;
        if let Some(text) = &self.text {
            write!(f, " {text}")?;
        }
        Ok(())
    }
}

/// What a connection speaks on top of its socket: HTTP/1 through
/// hyper, TLS through rustls, or nothing a reviewed rule reads — the
/// socket's own kind.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub(crate) enum Proto {
    Http1,
    Tls,
    Tcp,
    Unix,
}

impl Proto {
    fn word(self) -> &'static str {
        match self {
            Proto::Http1 => "http1",
            Proto::Tls => "tls",
            Proto::Tcp => "tcp",
            Proto::Unix => "unix",
        }
    }
}

/// Where a connection stands: an HTTP connection's phase, a TLS
/// connection's verdict, or — for a bare socket, which keeps no words
/// of its own — `open`, since a task reads or writes it.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub(crate) enum RowPhase {
    Http(HttpPhase),
    Tls(TlsVerdict),
    Open,
}

impl RowPhase {
    fn word(self) -> &'static str {
        match self {
            RowPhase::Http(phase) => phase.word(),
            RowPhase::Tls(verdict) => verdict.word(),
            RowPhase::Open => "open",
        }
    }
}

impl ConnRow {
    fn role_word(&self) -> Option<&'static str> {
        self.role.map(|role| match role {
            HttpRole::Client => "client",
            HttpRole::Server => "server",
        })
    }

    /// The `METHOD` cell: the message in flight's, or — where the
    /// connection's words did not keep one — the request's, so that
    /// the `REQUEST` cell beside it can leave the method off.
    fn method_word(&self) -> Option<&str> {
        match &self.method {
            Some(method) => Some(method),
            None => self.request.as_ref()?.method.as_deref(),
        }
    }

    /// The `REQUEST` cell: the target's text alone, the URL or the
    /// path — the method is `METHOD`'s, the cell to its left.
    fn request_text(&self) -> Option<&str> {
        self.request.as_ref()?.text.as_deref()
    }

    fn phase_word(&self) -> Option<&'static str> {
        self.phase.map(RowPhase::word)
    }

    /// The `PHASE` cell: the phase's word, with how long an idle server
    /// connection has waited beside it — `idle (19ms)`.
    fn phase_cell(&self) -> Option<String> {
        let word = self.phase_word()?;
        Some(match (self.phase, self.idle_for) {
            (Some(RowPhase::Http(HttpPhase::Idle)), Some(idle)) => {
                format!("{word} ({})", duration_text(idle))
            }
            _ => word.to_string(),
        })
    }

    /// The `BUF` cell: bytes read and not yet parsed over the capacity.
    fn buffer_cell(&self) -> Option<String> {
        self.read_buf.map(|(len, cap)| format!("{len}/{cap}"))
    }

    /// The `DEADLINE` cell: the timer's deadline as the task block
    /// prints it, less the word the column's header already says —
    /// `+29.981s`.
    fn deadline_cell(&self) -> Option<String> {
        let deadline = self.deadline.as_deref()?;
        Some(
            deadline
                .strip_prefix("deadline ")
                .unwrap_or(deadline)
                .to_string(),
        )
    }

    /// How the row names itself in a bucket's sample: the role — the
    /// protocol where it has none — and the task driving it: `client
    /// task 7`, `tcp task 9`.
    fn label(&self) -> String {
        let what = self.role_word().unwrap_or(self.proto.word());
        format!("{what} task {}", self.task)
    }
}

/// The rows over a session: every connection resource the tasks' own
/// chains end in, then every one the census found held in a frame —
/// a connection behind a wrapper no rule delegates through — and every
/// socket a pending read or write on either reaches, in task order,
/// each connection once: a socket's reads and writes are one row.
pub(crate) fn rows<'s, T: proc::Target>(session: &'s Session<'_, T>) -> &'s [ConnRow] {
    session.conn_rows.get_or_init(|| build_rows(session))
}

fn build_rows<T: proc::Target>(session: &Session<'_, T>) -> Vec<ConnRow> {
    let census = session.census();
    let requests = RequestIndex::of(census);
    let stopped = session.registries.stopped;
    let mut rows: Vec<ConnRow> = Vec::new();
    let mut seen = std::collections::HashSet::new();
    let mut push = |owner: usize, observation: &ResourceObservation| {
        let Some(row) = row_of(session, owner, observation, census, &requests, stopped) else {
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
    requests: &RequestIndex,
    stopped: Option<RawInstant>,
) -> Option<ConnRow> {
    let list = &session.tasks;
    let base = ConnRow {
        addr: 0,
        owner,
        task: task_id(list, owner),
        rt: RowOwner::of(&list.tasks[owner], &session.owners),
        proto: Proto::Http1,
        role: None,
        phase: None,
        method: None,
        peer: None,
        server: None,
        idle_for: None,
        read_buf: None,
        deadline: None,
        request: None,
        caller: None,
    };
    let request_of =
        |caller: &HttpCaller| caller_request_line(list, requests, session.attribution(), caller);
    let caller_of = |caller: &HttpCaller| caller_task(list, census, session.attribution(), caller);
    conn_row(
        base,
        observation,
        header_read_deadline(census, observation),
        stopped,
        &request_of,
        &caller_of,
        &census.pool_peers,
    )
}

/// The requests the census read, by who holds them: a task's finds, a
/// set child's chain and every find under it, a held find's chain and
/// every find under it. Built in one pass over the census, since a
/// listing asks it of every connection on a target and a walk of the
/// finds per connection would square the work.
#[derive(Default)]
pub(crate) struct RequestIndex {
    by_task: HashMap<usize, BTreeSet<RequestLine>>,
    by_child: HashMap<(usize, usize), BTreeSet<RequestLine>>,
    by_held: HashMap<usize, BTreeSet<RequestLine>>,
}

impl RequestIndex {
    pub(crate) fn of(census: &census::FutureCensus) -> Self {
        let mut index = RequestIndex::default();
        for (i, held) in census.held.iter().enumerate() {
            let Some(request) = &held.request else {
                continue;
            };
            let line = RequestLine::from(request);
            index.by_held.entry(i).or_default().insert(line.clone());
            if index.record_up(census, held.via, &line) {
                index.by_task.entry(held.owner).or_default().insert(line);
            }
        }
        for (set, futures) in census.sets.iter().enumerate() {
            for (child, found) in futures.children.iter().enumerate() {
                if let Some(request) = &found.request {
                    let line = RequestLine::from(request);
                    index
                        .by_child
                        .entry((set, child))
                        .or_default()
                        .insert(line.clone());
                    index.record_up(census, futures.via, &line);
                }
            }
        }
        index
    }

    /// Record `line` against every holder from `via` up toward the task,
    /// and say whether it got there. A request the census read a few
    /// chains down — reqwest's request behind the box a caller's future
    /// keeps, that future inside a set child — is the child's, and every
    /// find's above it, as much as the chain it was read from. The walk
    /// stops at a holder that reads a request of its own: that is the
    /// same exchange seen further out — reqwest's request, around the
    /// one hyper-util's client rewrote its target from — and the
    /// outermost reading names it to everything above.
    fn record_up(
        &mut self,
        census: &census::FutureCensus,
        mut via: Option<census::Via>,
        line: &RequestLine,
    ) -> bool {
        // The `via` links form a tree toward the task, so the walk ends
        // within the census's own length; the bound keeps a malformed
        // one from looping.
        for _ in 0..=census.held.len() + census.sets.len() {
            match via {
                None => return true,
                Some(census::Via::Held(parent)) => {
                    let Some(held) = census.held.get(parent) else {
                        return false;
                    };
                    if held.request.is_some() {
                        return false;
                    }
                    self.by_held.entry(parent).or_default().insert(line.clone());
                    via = held.via;
                }
                Some(census::Via::SetChild { set, child }) => {
                    let Some(futures) = census.sets.get(set) else {
                        return false;
                    };
                    if futures
                        .children
                        .get(child)
                        .is_some_and(|found| found.request.is_some())
                    {
                        return false;
                    }
                    self.by_child
                        .entry((set, child))
                        .or_default()
                        .insert(line.clone());
                    via = futures.via;
                }
            }
        }
        false
    }

    /// The one request among `requests`; several name none.
    fn unique(requests: Option<&BTreeSet<RequestLine>>) -> Option<RequestLine> {
        let requests = requests?;
        match requests.len() {
            1 => requests.iter().next().cloned(),
            _ => None,
        }
    }

    /// The one request a held find carries: read off its own chain, or
    /// off the finds under it — a caller's future awaiting reqwest's
    /// request holds it one chain down, behind the box the client put
    /// it in. A find with several under it names none.
    pub(crate) fn of_held(&self, index: usize) -> Option<String> {
        Self::unique(self.by_held.get(&index)).map(|line| line.to_string())
    }

    /// The one request among an owner's finds: a task's held finds, or a
    /// set child's own chain and the finds under it.
    fn of_owner(&self, owner: Owner) -> Option<RequestLine> {
        match owner {
            Owner::Task { index, .. } => Self::unique(self.by_task.get(&index)),
            Owner::Child { set, child } => Self::unique(self.by_child.get(&(set, child))),
        }
    }
}

/// The request a connection's caller holds, as the census read it: the
/// caller's own in-flight request where it is a task with one, the
/// child's where it is a set child the sweep placed. A caller holding
/// several in flight names none — the connection cannot tell which is
/// its — and a caller nothing places names none either.
pub(crate) fn caller_request(
    list: &TaskList,
    requests: &RequestIndex,
    slots: &attribution::Attributed,
    caller: &HttpCaller,
) -> Option<String> {
    caller_request_line(list, requests, slots, caller).map(|line| line.to_string())
}

/// [`caller_request`] with the method and the text kept apart.
fn caller_request_line(
    list: &TaskList,
    requests: &RequestIndex,
    slots: &attribution::Attributed,
    caller: &HttpCaller,
) -> Option<RequestLine> {
    let owner = match caller {
        HttpCaller::Task(task) => Owner::Task {
            header: task.addr.0,
            index: list.tasks.iter().position(|t| t.addr == task.addr)?,
        },
        HttpCaller::NotATask {
            cell: Some(cell), ..
        } => slots.at(*cell)?.owner,
        _ => return None,
    };
    requests.of_owner(owner)
}

/// The task a connection's caller is, or is polled by, as `tasks`
/// names it: the caller itself where it is a task, the task polling
/// the set where it is a set child the sweep placed. A caller nothing
/// places — gone, never parked, a waker no slot covers — names none.
fn caller_task(
    list: &TaskList,
    census: &census::FutureCensus,
    slots: &attribution::Attributed,
    caller: &HttpCaller,
) -> Option<String> {
    let index = match caller {
        HttpCaller::Task(task) => list.tasks.iter().position(|t| t.addr == task.addr)?,
        HttpCaller::NotATask {
            cell: Some(cell), ..
        } => match slots.at(*cell)?.owner {
            Owner::Task { index, .. } => index,
            Owner::Child { set, .. } => census.sets.get(set)?.owner,
        },
        _ => return None,
    };
    Some(task_id(list, index))
}

/// Fill `base` — the row's task cells — from the observation: the
/// negotiating wrapper's address and phase, or the connection's words
/// with the facts beside them. `held` is the deadline of the
/// connection's own header-read timer, where the census found it;
/// `request_of` and `caller_of` name what a client's caller sent and
/// which task it is; `pools` names a client connection's far end by
/// the pool it belongs to.
fn conn_row(
    base: ConnRow,
    observation: &ResourceObservation,
    held: Option<RawInstant>,
    stopped: Option<RawInstant>,
    request_of: &dyn Fn(&HttpCaller) -> Option<RequestLine>,
    caller_of: &dyn Fn(&HttpCaller) -> Option<String>,
    pools: &PoolPeers,
) -> Option<ConnRow> {
    match observation {
        // A wrapper still reading the first bytes has no version, no
        // words and no service to hold a peer: the phase is all.
        ResourceObservation::HttpNegotiating(negotiating) => Some(ConnRow {
            addr: negotiating.wrapper.addr,
            proto: Proto::Http1,
            role: Some(HttpRole::Server),
            phase: Some(RowPhase::Http(HttpPhase::Negotiating)),
            method: None,
            peer: None,
            server: None,
            idle_for: None,
            read_buf: None,
            deadline: None,
            request: None,
            caller: None,
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
            // A client's caller, while it has a request in flight: the
            // one the response callback names, as the verdict names it.
            let caller = match (http.role, phase) {
                (
                    HttpRole::Client,
                    Some(HttpPhase::AwaitingResponse | HttpPhase::SendingBody(_)),
                ) => http
                    .client
                    .as_ref()
                    .and_then(|client| client.callback.as_ref())
                    .map(http_caller),
                _ => None,
            };
            // The request: the handler's for a server, the caller's for a
            // client.
            let request = match http.role {
                HttpRole::Server => server
                    .and_then(|server| server.request.as_ref())
                    .map(RequestLine::from),
                HttpRole::Client => caller.as_ref().and_then(request_of),
            };
            let armed = server.filter(|server| server.header_read_timer_running);
            let deadline = armed
                .and(held)
                .map(|deadline| deadline_text(deadline, stopped));
            // hyper arms the header-read timer for the timeout from when
            // the connection starts waiting for a head, so an idle
            // server has waited the timeout less what the timer has
            // left at the capture — where the core records when that
            // was.
            let idle_for = match (phase, armed, held, stopped) {
                (Some(HttpPhase::Idle), Some(server), Some(deadline), Some(stopped)) => server
                    .header_read_timeout
                    .and_then(|timeout| waited(timeout, deadline, stopped)),
                _ => None,
            };
            // The peer: the socket's, where a server's service keeps
            // it; the pool key's authority for a client, where the
            // census reached the pool holding the connection's sender.
            let peer = match http.role {
                HttpRole::Server => server.and_then(|server| server.peer.clone()),
                HttpRole::Client => http
                    .client
                    .as_ref()
                    .and_then(|client| client.want)
                    .and_then(|want| pools.authority(want))
                    .map(str::to_string),
            };
            Some(ConnRow {
                addr: http.conn,
                proto: Proto::Http1,
                role: Some(http.role),
                phase: phase.map(RowPhase::Http),
                method: http.method.clone(),
                peer,
                server: server.and_then(|server| server.context.clone()),
                idle_for,
                read_buf: http.read_buf,
                deadline,
                request,
                caller: caller.as_ref().and_then(caller_of),
                ..base
            })
        }
        // A read or write whose route ended at a socket: the socket's
        // row, keyed by its registration, with the TLS connection the
        // route crossed where it crossed one. A readiness await names
        // no stream — a listener's accept, a bare readiness — and is
        // no connection.
        ResourceObservation::Io(io) => {
            let socket = io.socket?;
            let tls = io.tls.as_ref().map(|tls| tls.as_ref().ok());
            let proto = match (tls.is_some(), socket) {
                (true, _) => Proto::Tls,
                (false, IoSocket::TcpStream) => Proto::Tcp,
                (false, IoSocket::UnixStream) => Proto::Unix,
            };
            let reading = tls.flatten();
            Some(ConnRow {
                addr: io.scheduled_io.addr,
                proto,
                role: reading.and_then(|reading| match reading.side.as_str() {
                    "Client" => Some(HttpRole::Client),
                    "Server" => Some(HttpRole::Server),
                    _ => None,
                }),
                // A TLS connection whose words did not read has no
                // verdict; a bare socket is open for as long as a task
                // reads or writes it.
                phase: match tls {
                    Some(reading) => reading.map(|reading| RowPhase::Tls(reading.verdict())),
                    None => Some(RowPhase::Open),
                },
                peer: io.peer.as_ref().and_then(|peer| peer.clone().ok()),
                read_buf: reading.map(|reading| reading.deframer),
                ..base
            })
        }
        _ => None,
    }
}

/// How long a timer armed for `timeout` has run by `stopped`, given
/// the `deadline` it was armed for: `None` where the deadline lies
/// further off than the timeout, which no timer armed for it can.
fn waited(timeout: Duration, deadline: RawInstant, stopped: RawInstant) -> Option<Duration> {
    let ns = |i: RawInstant| i.tv_sec as i128 * 1_000_000_000 + i.tv_nsec as i128;
    let waited = timeout.as_nanos() as i128 - (ns(deadline) - ns(stopped));
    u64::try_from(waited).ok().map(Duration::from_nanos)
}

/// A duration as the listing prints one: milliseconds under a second,
/// seconds to the millisecond above it — `19ms`, `4.250s`.
fn duration_text(duration: Duration) -> String {
    let ms = duration.as_millis();
    if ms < 1000 {
        format!("{ms}ms")
    } else {
        format!("{}.{:03}s", ms / 1000, ms % 1000)
    }
}

/// The deadline of a server connection's own header-read timer: the
/// census's find at the address the connection's box points to, which
/// no other timer the task holds can be.
fn header_read_deadline(
    census: &census::FutureCensus,
    observation: &ResourceObservation,
) -> Option<RawInstant> {
    let ResourceObservation::HttpConn(http) = observation else {
        return None;
    };
    let timer = http.server.as_ref()?.header_read_timer?;
    census
        .held
        .iter()
        .filter(|held| held.addr == timer)
        .find_map(|held| match &held.observation {
            Some(ResourceObservation::Timer(timer)) => timer.deadline,
            _ => None,
        })
}

/// One row's table cells, in column order.
fn row_cells(row: &ConnRow) -> Vec<String> {
    let dash = || "—".to_string();
    vec![
        row.task.clone(),
        row.caller.clone().unwrap_or_else(dash),
        row.proto.word().to_string(),
        row.role_word().map_or_else(dash, str::to_string),
        row.phase_cell().unwrap_or_else(dash),
        row.deadline_cell().unwrap_or_else(dash),
        row.buffer_cell().unwrap_or_else(dash),
        row.peer.clone().unwrap_or_else(dash),
        row.server.clone().unwrap_or_else(dash),
        row.method_word().map_or_else(dash, str::to_string),
        row.request_text().map_or_else(dash, str::to_string),
    ]
}

/// Print the listing: one row per connection, the caller beside the
/// task driving it so the two read as who asked and who carries it,
/// the request last since a URL is the one cell that runs wide, its
/// method just before it so the two read as the request line, and the
/// count under it. The deadline follows the phase it times, the buffer
/// the deadline. The
/// runtime is the task's to say, under `tasks`: a target seldom holds
/// more than one, so the column would repeat one value down the page.
fn print_table(
    rows: &[&ConnRow],
    limit: Option<usize>,
    fit: Option<usize>,
    theme: output::Theme,
    out: &mut dyn io::Write,
) -> Result<()> {
    let shown = limit.unwrap_or(rows.len()).min(rows.len());
    let header = [
        "TASK", "CALLER", "PROTO", "ROLE", "PHASE", "DEADLINE", "BUF", "PEER", "SERVER", "METHOD",
        "REQUEST",
    ];
    let columns = header.len();
    let mut table = output::Table::new(columns)
        .header(header)
        .truncatable(columns - 1)
        .fit(fit)
        .theme(theme);
    for row in &rows[..shown] {
        table.row(row_cells(row));
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
    /// `http1`, `tls`, `tcp` or `unix`.
    Proto,
    /// `client` or `server`.
    Role,
    /// The phase as the bucket names it.
    Phase,
    /// The method in flight.
    Method,
    /// The peer's address as printed.
    Peer,
    /// The accepting server's context type.
    Server,
    /// The task that sent a client's request in flight — exact.
    Caller,
    /// The request behind the connection, as printed.
    Request,
    /// The bytes read and not yet parsed — compared.
    Buffered,
}

impl Field {
    const NAMES: [(&'static str, Field); 11] = [
        ("task", Field::Task),
        ("rt", Field::Rt),
        ("proto", Field::Proto),
        ("role", Field::Role),
        ("phase", Field::Phase),
        ("method", Field::Method),
        ("peer", Field::Peer),
        ("server", Field::Server),
        ("caller", Field::Caller),
        ("request", Field::Request),
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
            Field::Proto
                | Field::Role
                | Field::Phase
                | Field::Method
                | Field::Peer
                | Field::Server
                | Field::Request
        )
    }

    /// The spelled value a row holds for the field — `None` where the
    /// row has nothing in the column.
    fn text(self, row: &ConnRow) -> Option<String> {
        match self {
            Field::Task => Some(row.task.clone()),
            Field::Rt => Some(row.rt.cell()),
            Field::Proto => Some(row.proto.word().to_string()),
            Field::Role => row.role_word().map(str::to_string),
            Field::Phase => row.phase_word().map(str::to_string),
            Field::Method => row.method_word().map(str::to_string),
            Field::Peer => row.peer.clone(),
            Field::Server => row.server.clone(),
            Field::Caller => row.caller.clone(),
            Field::Request => row.request_text().map(str::to_string),
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
    /// Exact text: a task id, the owner cell.
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

/// The matcher one field's argument compiles to: an owner is held to
/// the group cell `runtimes` numbers (the `?`/`!` marks, or the words
/// for them).
fn matcher(field: Field, arg: &str, handles: &[u64]) -> Result<Matcher> {
    Ok(match field {
        Field::Task | Field::Caller => Matcher::Exact(arg.to_string()),
        Field::Rt => Matcher::Exact(crate::tasks::resolve_rt(arg, handles)?.cell()),
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
    let selected: Vec<&ConnRow> = survivors.iter().map(|&i| &rows[i]).collect();
    print_table(&selected, cmd.limit, session.fit_width(theme), theme, out)?;
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
    use hansei_runtime::tokio::bundle::OneshotState;
    use hansei_runtime::tokio::observe::{
        HttpClientObservation, HttpConnObservation, HttpNegotiatingObservation, HttpReading,
        HttpRequestObservation, HttpServerObservation, HttpWriting, JoinObservation, KeepAlive,
        OneshotObservation, TimerObservation, TimerRegistrationState, ValueKey,
    };

    fn row(addr: u64, role: HttpRole, phase: Option<HttpPhase>) -> ConnRow {
        ConnRow {
            addr,
            owner: 0,
            task: "7".to_string(),
            rt: RowOwner::Group(0),
            proto: Proto::Http1,
            role: Some(role),
            phase: phase.map(RowPhase::Http),
            method: Some("GET".to_string()),
            peer: Some("[fd00::25]:57400".to_string()),
            server: None,
            idle_for: None,
            read_buf: Some((12, 8192)),
            deadline: None,
            request: None,
            caller: None,
        }
    }

    /// Every field selects: the patterns over their spelled values, the
    /// exact ones held to the listing's own spelling, the count compared.
    #[test]
    fn test_clauses_select_by_every_field() {
        let rows = [
            ConnRow {
                caller: Some("17".to_string()),
                ..row(0x10, HttpRole::Client, Some(HttpPhase::AwaitingResponse))
            },
            // An idle server with its wait in the cell: the phase field
            // is the word alone.
            ConnRow {
                server: Some("app::Context".to_string()),
                idle_for: Some(Duration::from_millis(19)),
                ..row(0x20, HttpRole::Server, Some(HttpPhase::Idle))
            },
            ConnRow {
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
        assert_eq!(select(&["phase", "awaiting"]), [0x10]);
        assert_eq!(select(&["phase", "idle,negotiating"]), [0x20, 0x30]);
        assert_eq!(select(&["phase", "^idle$"]), [0x20]);
        assert_eq!(select(&["server", "context"]), [0x20]);
        assert_eq!(select(&["method", "get"]), [0x10, 0x20, 0x40]);
        assert_eq!(select(&["peer", "fd00"]), [0x10, 0x20, 0x40]);
        assert_eq!(select(&["task", "7"]), [0x10, 0x20, 0x30]);
        assert_eq!(select(&["task", "17"]), [0x40]);
        // The caller is exact too, and apart from the driving task.
        assert_eq!(select(&["caller", "17"]), [0x10]);
        assert_eq!(select(&["caller", "7"]), []);
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
        // The address and the version are no fields: no cell prints
        // either.
        assert!(refused(&["addr", "0x20"]).contains("no field \"addr\""));
        assert!(refused(&["version", "http1"]).contains("no field \"version\""));
        assert!(refused(&["buffered", "many"]).contains("'>N', '<N' or '=N'"));
    }

    fn line(method: Option<&str>, text: Option<&str>) -> RequestLine {
        RequestLine {
            method: method.map(str::to_string),
            text: text.map(str::to_string),
        }
    }

    /// The cells print the row: a dash where a column is empty, the
    /// buffer as fill over capacity, the deadline without the word its
    /// header says, the method beside the request's text and not in
    /// it; no address, owner or version.
    #[test]
    fn test_cells_print_the_row() {
        let full = ConnRow {
            request: Some(line(Some("GET"), Some("http://one/park"))),
            caller: Some("621".to_string()),
            ..row(0x10, HttpRole::Client, Some(HttpPhase::AwaitingResponse))
        };
        assert_eq!(
            row_cells(&full),
            [
                "7",
                "621",
                "http1",
                "client",
                "awaiting response",
                "—",
                "12/8192",
                "[fd00::25]:57400",
                "—",
                "GET",
                "http://one/park"
            ]
        );
        // The method is the connection's where its words keep one, and
        // the request's where they do not; a request whose text did
        // not read leaves its cell empty.
        for (method, request, cells) in [
            (Some("GET"), line(Some("POST"), None), ["GET", "—"]),
            (None, line(Some("POST"), Some("/park")), ["POST", "/park"]),
            (None, line(None, Some("/park")), ["—", "/park"]),
        ] {
            let at = ConnRow {
                method: method.map(str::to_string),
                request: Some(request),
                ..full.clone()
            };
            assert_eq!(row_cells(&at)[9..], cells);
        }
        let bare = ConnRow {
            method: None,
            peer: None,
            read_buf: None,
            deadline: Some("deadline +29.981s".to_string()),
            server: Some("app::Context".to_string()),
            ..row(0x30, HttpRole::Server, None)
        };
        assert_eq!(
            row_cells(&bare),
            [
                "7",
                "—",
                "http1",
                "server",
                "—",
                "+29.981s",
                "—",
                "—",
                "app::Context",
                "—",
                "—"
            ]
        );
        // Every form `deadline_text` takes loses the word and nothing
        // else.
        for (text, cell) in [
            ("deadline +29.981s", "+29.981s"),
            ("overdue by 0.500s", "overdue by 0.500s"),
            (
                "deadline 12.345s on the target's monotonic clock",
                "12.345s on the target's monotonic clock",
            ),
        ] {
            let at = ConnRow {
                deadline: Some(text.to_string()),
                ..bare.clone()
            };
            assert_eq!(row_cells(&at)[5], cell);
        }
        assert_eq!(full.label(), "client task 7");
        assert_eq!(bare.label(), "server task 7");
        // An idle server's wait follows its phase, milliseconds under a
        // second and seconds to the millisecond above; a wait beside
        // any other phase is not printed.
        let waited = |phase, ms| ConnRow {
            idle_for: Some(Duration::from_millis(ms)),
            ..row(0x40, HttpRole::Server, Some(phase))
        };
        for (phase, ms, cell) in [
            (HttpPhase::Idle, 0, "idle (0ms)"),
            (HttpPhase::Idle, 19, "idle (19ms)"),
            (HttpPhase::Idle, 999, "idle (999ms)"),
            (HttpPhase::Idle, 1000, "idle (1.000s)"),
            (HttpPhase::Idle, 4250, "idle (4.250s)"),
            (HttpPhase::HandlingRequest, 19, "handling request"),
        ] {
            assert_eq!(row_cells(&waited(phase, ms))[4], cell);
        }
    }

    /// A timer armed for the timeout has run the timeout less what it
    /// has left, to the nanosecond — and one whose deadline is further
    /// off than the timeout was not armed for it.
    #[test]
    fn test_the_wait_is_the_timeout_less_what_the_timer_has_left() {
        let at = |tv_sec, tv_nsec| RawInstant { tv_sec, tv_nsec };
        let timeout = Duration::from_secs(30);
        assert_eq!(
            waited(timeout, at(129, 981_000_000), at(100, 0)),
            Some(Duration::from_millis(19))
        );
        assert_eq!(
            waited(timeout, at(130, 0), at(100, 0)),
            Some(Duration::ZERO)
        );
        // Overdue: the wait runs past the timeout.
        assert_eq!(
            waited(timeout, at(99, 999_999_999), at(100, 0)),
            Some(Duration::from_nanos(30_000_000_001))
        );
        assert_eq!(waited(timeout, at(130, 1), at(100, 0)), None);
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

    fn server_observation(header_read_timer_running: bool) -> HttpConnObservation {
        HttpConnObservation {
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
                header_read_timer_running,
                header_read_timeout: Some(Duration::from_secs(30)),
                header_read_timer: Some(0x100),
                peer: Some("[fd00::25]:57400".to_string()),
                context: Some("app::Context".to_string()),
                request: None,
            }),
        }
    }

    /// The facts beside the verdict reach the row: the peer, the
    /// server's context, the buffer, and the deadline of the held timer
    /// — only while the header-read timer is armed — with the wait an
    /// idle server's timer says beside it. A negotiating wrapper is a
    /// row at its own address with no words; any other observation is
    /// no row.
    #[test]
    fn test_the_observation_fills_the_row() {
        // The base carries a sentinel in every cell the observation
        // fills, so a cell the arm left to the base is told from one
        // it set.
        let base = ConnRow {
            phase: Some(RowPhase::Http(HttpPhase::Closing)),
            method: Some("SENTINEL".to_string()),
            peer: Some("SENTINEL".to_string()),
            server: Some("SENTINEL".to_string()),
            idle_for: Some(Duration::from_secs(7)),
            read_buf: Some((1, 1)),
            deadline: Some("SENTINEL".to_string()),
            request: Some(line(Some("SENTINEL"), Some("SENTINEL"))),
            caller: Some("SENTINEL".to_string()),
            ..row(0, HttpRole::Client, None)
        };
        let held = Some(RawInstant {
            tv_sec: 129,
            tv_nsec: 981_000_000,
        });
        let stopped = Some(instant(100));
        // Every caller is task 621 and sent `GET /park`, so a row
        // without them was not asked.
        let request_of = |_: &HttpCaller| Some(line(Some("GET"), Some("/park")));
        let caller_of = |_: &HttpCaller| Some("621".to_string());
        // A pool that names the connection whose receiver shares
        // `0xabc0`, and names it for a server too: a server's peer is
        // its service's, whatever a pool says.
        let pools = PoolPeers(HashMap::from([
            (0xabc0, "127.0.0.1:8080".to_string()),
            (0x7b78948, "pool.example:80".to_string()),
        ]));
        let fill = |observation: HttpConnObservation, held, stopped| {
            let observation = ResourceObservation::HttpConn(Box::new(observation));
            conn_row(
                base.clone(),
                &observation,
                held,
                stopped,
                &request_of,
                &caller_of,
                &pools,
            )
            .unwrap()
        };
        let armed = fill(server_observation(true), held, stopped);
        assert_eq!(armed.addr, 0x7b78948);
        assert_eq!(armed.role, Some(HttpRole::Server));
        assert_eq!(armed.phase, Some(RowPhase::Http(HttpPhase::Idle)));
        assert_eq!(armed.method, None);
        assert_eq!(armed.peer.as_deref(), Some("[fd00::25]:57400"));
        assert_eq!(armed.server.as_deref(), Some("app::Context"));
        assert_eq!(armed.idle_for, Some(Duration::from_millis(19)));
        assert_eq!(armed.read_buf, Some((0, 8192)));
        assert_eq!(armed.deadline.as_deref(), Some("deadline +29.981s"));
        assert_eq!(armed.request, None);
        // A server has no caller: its request is the handler's.
        assert_eq!(armed.caller, None);
        // The task's cells come from the base.
        assert_eq!(armed.task, "7");
        // The timer disarmed or not held leaves no deadline and no
        // wait; without the core's stop time, or a timeout, the
        // deadline stands and the wait is unknown.
        let idle = fill(server_observation(false), held, stopped);
        assert_eq!((idle.deadline, idle.idle_for), (None, None));
        let unheld = fill(server_observation(true), None, stopped);
        assert_eq!((unheld.deadline, unheld.idle_for), (None, None));
        let unstopped = fill(server_observation(true), held, None);
        assert!(unstopped.deadline.is_some());
        assert_eq!(unstopped.idle_for, None);
        let mut untimed = server_observation(true);
        untimed.server.as_mut().unwrap().header_read_timeout = None;
        let untimed = fill(untimed, held, stopped);
        assert!(untimed.deadline.is_some());
        assert_eq!(untimed.idle_for, None);
        // A server not idle has waited for no head, whatever its timer.
        let mut handling = server_observation(true);
        handling.server.as_mut().unwrap().in_flight = true;
        let handling = fill(handling, held, stopped);
        assert_eq!(
            handling.phase,
            Some(RowPhase::Http(HttpPhase::HandlingRequest))
        );
        assert_eq!(handling.idle_for, None);
        // A client's peer is the authority of the pool key its sender
        // is kept under, found by the want pointer its receiver shares;
        // a connection no pool the census reached names, or whose
        // pointer did not read, has none.
        let client = |want| HttpConnObservation {
            role: HttpRole::Client,
            client: Some(HttpClientObservation {
                callback: None,
                rx: None,
                want,
            }),
            server: None,
            ..server_observation(false)
        };
        assert_eq!(
            fill(client(Some(0xabc0)), held, stopped).peer.as_deref(),
            Some("127.0.0.1:8080")
        );
        assert_eq!(fill(client(Some(0xdef0)), held, stopped).peer, None);
        assert_eq!(fill(client(None), held, stopped).peer, None);
        // A client between exchanges has no caller and no request; one
        // with a request in flight has the caller its callback names,
        // and what that caller sent.
        let idle = fill(client(Some(0xabc0)), held, stopped);
        assert_eq!(idle.phase, Some(RowPhase::Http(HttpPhase::Idle)));
        assert_eq!((idle.caller, idle.request), (None, None));
        let mut in_flight = client(Some(0xabc0));
        in_flight.client.as_mut().unwrap().callback = Some(OneshotObservation {
            future: key(0x500),
            arc: key(0x500),
            inner: 0x510,
            state: OneshotState {
                word: 0,
                value_present: Some(false),
            },
            rx_waker: None,
            tx_waker: None,
            rx_task_at: Some(0x520),
            tx_task_at: Some(0x510),
        });
        let in_flight = fill(in_flight, held, stopped);
        assert_eq!(
            in_flight.phase,
            Some(RowPhase::Http(HttpPhase::AwaitingResponse))
        );
        assert_eq!(in_flight.caller.as_deref(), Some("621"));
        assert_eq!(in_flight.request, Some(line(Some("GET"), Some("/park"))));
        let negotiating = conn_row(
            base.clone(),
            &ResourceObservation::HttpNegotiating(HttpNegotiatingObservation {
                wrapper: key(0x12345),
            }),
            held,
            stopped,
            &request_of,
            &caller_of,
            &pools,
        )
        .unwrap();
        assert_eq!(negotiating.addr, 0x12345);
        assert_eq!(negotiating.role, Some(HttpRole::Server));
        assert_eq!(
            negotiating.phase,
            Some(RowPhase::Http(HttpPhase::Negotiating))
        );
        assert_eq!(negotiating.method, None);
        assert_eq!(negotiating.peer, None);
        assert_eq!(negotiating.server, None);
        assert_eq!(negotiating.idle_for, None);
        assert_eq!(negotiating.read_buf, None);
        assert_eq!(negotiating.deadline, None);
        assert_eq!(negotiating.request, None);
        assert_eq!(negotiating.caller, None);
        assert_eq!(negotiating.label(), "server task 7");
        let other = ResourceObservation::Join(JoinObservation {
            handle: key(0x1),
            header: TaskAddr(0x1),
        });
        assert!(
            conn_row(
                base.clone(),
                &other,
                held,
                stopped,
                &request_of,
                &caller_of,
                &pools
            )
            .is_none()
        );
    }

    /// A read or write whose route ended at a socket is that socket's
    /// row, keyed by its registration: a TLS connection's side, verdict,
    /// deframer and peer where the route crossed one, a bare socket
    /// open and saying nothing else; a readiness await is no row.
    #[test]
    fn test_a_socket_read_through_its_stream_is_a_row() {
        use hansei_runtime::tokio::bundle::{Interest, TlsReading};
        use hansei_runtime::tokio::observe::IoObservation;
        let base = row(0, HttpRole::Client, None);
        let tls = TlsReading {
            side: "Server".to_string(),
            version: Some("TLSv1_3".to_string()),
            failed: false,
            may_send_application_data: true,
            may_receive_application_data: true,
            has_sent_close_notify: false,
            has_received_close_notify: false,
            has_seen_eof: false,
            sent_fatal_alert: false,
            read_seq: 4,
            write_seq: 3,
            deframer: (5, 4096),
            stream_state: "Stream".to_string(),
        };
        let io = |socket, tls, peer| {
            ResourceObservation::Io(IoObservation {
                future: key(0x1),
                operation: hansei_bundle::IoOperationKind::ReadExact,
                scheduled_io: key(0x6500),
                interest: Interest::READABLE,
                waiter_node: None,
                remaining: None,
                readiness_state: None,
                waiter_ready: None,
                route: vec![key(0x2)],
                fd: Some(80),
                tls,
                socket,
                peer,
            })
        };
        let fill = |observation: ResourceObservation| {
            conn_row(
                base.clone(),
                &observation,
                None,
                None,
                &|_| None,
                &|_| None,
                &PoolPeers::default(),
            )
        };
        let sprockets = fill(io(
            Some(IoSocket::TcpStream),
            Some(Ok(tls.clone())),
            Some(Ok("PDV2:913-0000023".to_string())),
        ))
        .unwrap();
        assert_eq!(sprockets.addr, 0x6500);
        assert_eq!(sprockets.proto, Proto::Tls);
        assert_eq!(sprockets.role, Some(HttpRole::Server));
        assert_eq!(
            sprockets.phase,
            Some(RowPhase::Tls(TlsVerdict::Established))
        );
        assert_eq!(sprockets.read_buf, Some((5, 4096)));
        assert_eq!(sprockets.peer.as_deref(), Some("PDV2:913-0000023"));
        assert_eq!(sprockets.method, Some("GET".to_string()), "the base's");
        assert_eq!(sprockets.label(), "server task 7");
        assert_eq!(
            row_cells(&sprockets)[2..7],
            ["tls", "server", "established", "—", "5/4096"]
        );
        // Words that did not read: still TLS, with nothing to say.
        let unread = fill(io(
            Some(IoSocket::TcpStream),
            Some(Err("unreadable".to_string())),
            Some(Err("unreadable".to_string())),
        ))
        .unwrap();
        assert_eq!(
            (unread.proto, unread.role, unread.phase, unread.read_buf),
            (Proto::Tls, None, None, None)
        );
        assert_eq!(unread.peer, None);
        // A bare socket: its kind, open, and nothing else of its own.
        let tcp = fill(io(Some(IoSocket::TcpStream), None, None)).unwrap();
        assert_eq!(
            (
                tcp.proto,
                tcp.role,
                tcp.phase,
                tcp.read_buf,
                tcp.peer.clone()
            ),
            (Proto::Tcp, None, Some(RowPhase::Open), None, None)
        );
        assert_eq!(tcp.label(), "tcp task 7");
        assert_eq!(row_cells(&tcp)[2..4], ["tcp", "—"]);
        let unix = fill(io(Some(IoSocket::UnixStream), None, None)).unwrap();
        assert_eq!(unix.proto, Proto::Unix);
        // A readiness await names no stream.
        assert!(fill(io(None, None, None)).is_none());
    }

    /// A caller that is no task is placed by the waker sweep's slot at
    /// the cell its waker was read from, and names that child's
    /// request; no cell, or a cell no slot covers, places nothing.
    #[test]
    fn test_a_caller_that_is_no_task_is_placed_by_its_waker_cell() {
        use hansei_runtime::tokio::attribution::{Attributed, AttributedSlot, Attribution, Reach};
        let requests = RequestIndex {
            by_child: HashMap::from([((0, 1), BTreeSet::from([line(Some("GET"), Some("/one"))]))]),
            ..RequestIndex::default()
        };
        let slots = Attributed::from_slots(vec![AttributedSlot {
            hit: 0,
            slot: 0x6010,
            owner: Owner::Child { set: 0, child: 1 },
            attribution: Attribution::Unknown,
            within: None,
            through: Vec::new(),
            aliases: Vec::new(),
            reach: Reach::Unlocated,
        }]);
        let list = TaskList::new(Vec::new());
        let caller = |cell| HttpCaller::NotATask {
            vtable: 0xeeb0,
            cell,
        };
        let request = |cell| caller_request(&list, &requests, &slots, &caller(cell));
        assert_eq!(request(Some(0x6010)).as_deref(), Some("GET /one"));
        assert_eq!(request(Some(0x7000)), None);
        assert_eq!(request(None), None);
    }

    /// The caller's task is the caller where it is a task, the task a
    /// slot's owner is, or the task polling the set a placed child is
    /// in; a task the list does not hold, a cell no slot covers, and a
    /// caller with no waker to place name none.
    #[test]
    fn test_the_caller_is_its_task_or_the_one_polling_its_set() {
        use hansei_runtime::tokio::TaskState;
        use hansei_runtime::tokio::attribution::{Attributed, AttributedSlot, Attribution, Reach};
        use hansei_runtime::tokio::bundle::{FutureInfo, OwnerResolution, Task, TaskKind};
        use hansei_runtime::tokio::graph::TaskRef;

        let task = |id: u64| Task {
            addr: TaskAddr(0x1000 + id * 0x100),
            state: TaskState(1 << 6),
            owner_id: Some(1),
            task_id: Some(id),
            spawn_location: None,
            future: FutureInfo::Unknown { poll_symbol: None },
            kind: TaskKind::Async,
            owner: OwnerResolution::Unknown,
        };
        let list = TaskList::new(vec![task(621), task(2438)]);
        // Set 0 is polled by the second task, 2438.
        let census = census::FutureCensus::from_finds(
            vec![],
            vec![census::FutureSet {
                owner: 1,
                frame: 0,
                local: "set".to_string(),
                via: None,
                addr: 0x3000,
                ty: hansei_bundle::BundleTypeId(0),
                children: Vec::new(),
            }],
            vec![],
        );
        let slot = |slot, owner| AttributedSlot {
            hit: 0,
            slot,
            owner,
            attribution: Attribution::Unknown,
            within: None,
            through: Vec::new(),
            aliases: Vec::new(),
            reach: Reach::Unlocated,
        };
        let slots = Attributed::from_slots(vec![
            slot(0x6010, Owner::Child { set: 0, child: 3 }),
            slot(
                0x6020,
                Owner::Task {
                    header: 0x1000 + 621 * 0x100,
                    index: 0,
                },
            ),
        ]);
        let of = |caller: HttpCaller| caller_task(&list, &census, &slots, &caller);
        let parked = |id: u64| {
            HttpCaller::Task(TaskRef {
                addr: TaskAddr(0x1000 + id * 0x100),
                task_id: Some(id),
            })
        };
        let placed = |cell| HttpCaller::NotATask {
            vtable: 0xeeb0,
            cell,
        };
        assert_eq!(of(parked(621)).as_deref(), Some("621"));
        assert_eq!(of(parked(9)), None);
        assert_eq!(of(placed(Some(0x6010))).as_deref(), Some("2438"));
        assert_eq!(of(placed(Some(0x6020))).as_deref(), Some("621"));
        assert_eq!(of(placed(Some(0x7000))), None);
        assert_eq!(of(placed(None)), None);
        for unplaced in [HttpCaller::Gone, HttpCaller::Unparked, HttpCaller::Unread] {
            assert_eq!(of(unplaced), None);
        }
    }

    /// The deadline is the connection's own timer's, found at the
    /// address its box points to: another timer the same task holds —
    /// listed first — is not it, nor is a find at that address that is
    /// no timer, and a server with no timer has no deadline.
    #[test]
    fn test_the_deadline_is_the_connections_own_timer() {
        let timer = |addr: u64, deadline: Option<RawInstant>| census::HeldFuture {
            owner: 0,
            frame: 0,
            local: "sleep".to_string(),
            via: None,
            slot: addr,
            addr,
            ty: hansei_bundle::BundleTypeId(0),
            depth: 1,
            frames: Vec::new(),
            future: hansei_bundle::BundleTypeId(1),
            state: None,
            waiting_on: None,
            wait: None,
            observation: Some(ResourceObservation::Timer(TimerObservation {
                future: key(addr),
                deadline,
                state: TimerRegistrationState::Deregistered,
            })),
            continuation: ContinuationStatus::Primitive,
            request: None,
        };
        let join = census::HeldFuture {
            observation: Some(ResourceObservation::Join(JoinObservation {
                handle: key(0x1),
                header: TaskAddr(0x1),
            })),
            ..timer(0x300, None)
        };
        let census = census::FutureCensus::from_finds(
            vec![
                timer(0x200, Some(instant(5))),
                join,
                timer(0x100, Some(instant(9))),
            ],
            Vec::new(),
            Vec::new(),
        );
        let at = |timer: Option<u64>| {
            let mut observation = server_observation(true);
            observation.server.as_mut().unwrap().header_read_timer = timer;
            header_read_deadline(
                &census,
                &ResourceObservation::HttpConn(Box::new(observation)),
            )
        };
        assert_eq!(at(Some(0x100)), Some(instant(9)));
        assert_eq!(at(Some(0x300)), None);
        assert_eq!(at(Some(0x400)), None);
        assert_eq!(at(None), None);
        // A negotiating wrapper has no timer to look up.
        let negotiating = ResourceObservation::HttpNegotiating(HttpNegotiatingObservation {
            wrapper: key(0x100),
        });
        assert_eq!(header_read_deadline(&census, &negotiating), None);
    }

    /// A request the census read under a set child — behind the box a
    /// caller's future keeps, one chain down from the child's own — is
    /// the child's, and every find's above it up to the task; a holder
    /// with several under it names none.
    #[test]
    fn test_a_request_under_a_child_names_the_child_and_the_finds_above() {
        fn request(text: &str) -> HttpRequestObservation {
            HttpRequestObservation {
                at: key(0x100),
                method: Some("GET".to_string()),
                target: hansei_bundle::HttpRequestTarget::Url,
                text: Some(text.to_string()),
            }
        }
        fn find(
            via: Option<census::Via>,
            request: Option<HttpRequestObservation>,
        ) -> census::HeldFuture {
            census::HeldFuture {
                owner: 0,
                frame: 0,
                local: "fut".to_string(),
                via,
                slot: 0x100,
                addr: 0x100,
                ty: hansei_bundle::BundleTypeId(0),
                depth: 1,
                frames: Vec::new(),
                future: hansei_bundle::BundleTypeId(1),
                state: None,
                waiting_on: None,
                wait: None,
                observation: None,
                request,
                continuation: ContinuationStatus::Primitive,
            }
        }
        fn set_child(request: Option<HttpRequestObservation>) -> census::SetChild {
            census::SetChild {
                node: 0x2000,
                depth: 1,
                future: Some(hansei_bundle::BundleTypeId(2)),
                root: None,
                state: None,
                waiting_on: None,
                wait: None,
                observation: None,
                request,
                continuation: ContinuationStatus::Primitive,
            }
        }
        fn set(via: Option<census::Via>, children: Vec<census::SetChild>) -> census::FutureSet {
            census::FutureSet {
                owner: 0,
                frame: 0,
                local: "set".to_string(),
                via,
                addr: 0x3000,
                ty: hansei_bundle::BundleTypeId(3),
                children,
            }
        }
        let child_of = |set, child| Some(census::Via::SetChild { set, child });
        let under = |held| Some(census::Via::Held(held));
        let census = census::FutureCensus::from_finds(
            vec![
                // 0: the caller's future inside set 0's first child, and
                // 1: the request behind the box it keeps.
                find(child_of(0, 0), None),
                find(under(0), Some(request("http://one/"))),
                // 2: a task's own find holding set 1, whose child reads
                // its request on its own chain.
                find(None, None),
                // 3: the future inside set 0's second child; 4 and 5:
                // two requests under it.
                find(child_of(0, 1), None),
                find(under(3), Some(request("http://two/"))),
                find(under(3), Some(request("http://three/"))),
            ],
            vec![
                set(None, vec![set_child(None), set_child(None)]),
                set(under(2), vec![set_child(Some(request("http://four/")))]),
            ],
            vec![],
        );
        let index = RequestIndex::of(&census);
        let child = |set, child| Owner::Child { set, child };
        assert_eq!(
            index.of_owner(child(0, 0)),
            Some(line(Some("GET"), Some("http://one/")))
        );
        assert_eq!(index.of_held(0).as_deref(), Some("GET http://one/"));
        assert_eq!(index.of_held(1).as_deref(), Some("GET http://one/"));
        // The nested set's child names the find that holds the set.
        assert_eq!(
            index.of_owner(child(1, 0)),
            Some(line(Some("GET"), Some("http://four/")))
        );
        assert_eq!(index.of_held(2).as_deref(), Some("GET http://four/"));
        // Two under one child: neither the child nor the future between
        // names one; each request's own find still does.
        assert_eq!(index.of_owner(child(0, 1)), None);
        assert_eq!(index.of_held(3), None);
        assert_eq!(index.of_held(4).as_deref(), Some("GET http://two/"));
        // The task's own finds carry three: it names none.
        let task = Owner::Task {
            header: 0,
            index: 0,
        };
        assert_eq!(index.of_owner(task), None);

        // A chain as long as the census allows still reaches its top:
        // two links over three finds and no set, and two links over one
        // find and one set.
        let census = census::FutureCensus::from_finds(
            vec![
                find(None, None),
                find(under(0), None),
                find(under(1), Some(request("http://five/"))),
            ],
            vec![],
            vec![],
        );
        let index = RequestIndex::of(&census);
        assert_eq!(index.of_held(0).as_deref(), Some("GET http://five/"));
        let census = census::FutureCensus::from_finds(
            vec![find(None, None)],
            vec![set(under(0), vec![set_child(Some(request("http://six/")))])],
            vec![],
        );
        let index = RequestIndex::of(&census);
        assert_eq!(index.of_held(0).as_deref(), Some("GET http://six/"));

        // A request read under a find that reads its own is that one
        // seen further in — hyper-util's rewritten target under
        // reqwest's URL: it names the finds up to that one, and the
        // outer reading alone names that find and everything above it.
        let census = census::FutureCensus::from_finds(
            vec![
                find(None, Some(request("http://seven/park"))),
                find(under(0), None),
                find(under(1), Some(request("/park"))),
            ],
            vec![set(under(2), vec![set_child(Some(request("/child")))])],
            vec![],
        );
        let index = RequestIndex::of(&census);
        assert_eq!(index.of_held(0).as_deref(), Some("GET http://seven/park"));
        assert_eq!(index.of_held(1).as_deref(), Some("GET /park"));
        assert_eq!(index.of_held(2).as_deref(), Some("GET /park"));
        assert_eq!(
            index.of_owner(child(0, 0)).map(|line| line.to_string()),
            Some("GET /child".to_string())
        );
        assert_eq!(
            index.of_owner(task).map(|line| line.to_string()),
            Some("GET http://seven/park".to_string())
        );
    }

    /// A bucket's sample names up to three members and marks the rest.
    #[test]
    fn test_a_bucket_sample_is_three_members_and_a_mark() {
        let rows: Vec<ConnRow> = (0..4)
            .map(|i| ConnRow {
                task: (i + 1).to_string(),
                ..row(0x10 * (i + 1), HttpRole::Client, None)
            })
            .collect();
        assert_eq!(
            member_sample(&rows, &[0, 1, 2]),
            "client task 1, client task 2, client task 3"
        );
        assert_eq!(
            member_sample(&rows, &[0, 1, 2, 3]),
            "client task 1, client task 2, client task 3, …"
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
        assert!(phases.contains(&"idle".to_string()), "{phases:?}");
        assert_eq!(phases.len(), 4, "{phases:?}");
        let (tasks, pattern) = field_values(&session, "task").unwrap();
        assert!(!pattern);
        assert_eq!(tasks.len(), 9, "{tasks:?}");
        // The two clients with a request in flight each name the task
        // that sent it — never one driving a connection — as exact
        // values.
        let (callers, pattern) = field_values(&session, "caller").unwrap();
        assert!(!pattern);
        assert_eq!(callers.len(), 2, "{callers:?}");
        assert!(callers.iter().all(|c| !tasks.contains(c)), "{callers:?}");
        // The one peer is the pool key of the client whose pool keeps a
        // reaper: the listener's loopback address.
        let (peers, pattern) = field_values(&session, "peer").unwrap();
        assert!(pattern);
        assert_eq!(peers.len(), 1, "{peers:?}");
        assert!(peers[0].starts_with("127.0.0.1:"), "{peers:?}");
        // The request reaches the prompt's offers as the URL and the
        // path the two parked handlers and the reqwest requester carry,
        // the method left to its own field.
        let (requests, pattern) = field_values(&session, "request").unwrap();
        assert!(pattern);
        assert_eq!(requests.len(), 2, "{requests:?}");
        assert!(requests.iter().any(|r| r == "/park"), "{requests:?}");
        assert!(
            requests
                .iter()
                .any(|r| r.starts_with("http://127.0.0.1:") && r.ends_with("/park")),
            "{requests:?}"
        );
        assert_eq!(
            field_values(&session, "method"),
            Some((vec!["GET".to_string()], true))
        );
        assert_eq!(field_values(&session, "buffered"), None);
        assert_eq!(field_values(&session, "colour"), None);
    }

    #[test]
    fn test_fields_offer_their_values() {
        let rows = [
            row(0x10, HttpRole::Client, Some(HttpPhase::Idle)),
            row(0x20, HttpRole::Server, Some(HttpPhase::Idle)),
        ];
        assert_eq!(Field::Proto.values(&rows).unwrap(), ["http1"]);
        assert_eq!(Field::Role.values(&rows).unwrap(), ["client", "server"]);
        assert_eq!(Field::Phase.values(&rows).unwrap(), ["idle"]);
        assert_eq!(Field::Buffered.values(&rows), None);
        assert!(Field::Peer.is_pattern());
        assert!(!Field::Task.is_pattern());
        assert!(!Field::Caller.is_pattern());
        let names: Vec<&str> = Field::names().collect();
        assert_eq!(names.len(), 11);
        for name in names {
            assert_eq!(Field::parse(name).unwrap().name(), name);
        }
    }
}
