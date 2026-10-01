// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! The `connection` command: one row of `connections` in full — the
//! protocol on top first, then the TLS connection its route crossed,
//! then the socket, each layer with its own words and its own role —
//! and the `whatis` claim an address inside any of those layers makes.

use crate::Session;
use crate::connections::{self, ConnRow};
use crate::tasks::{task_id, task_label};
use crate::typenames::TypeNames;
use crate::whatis::separate;

use anyhow::{Result, anyhow};
use hansei_bundle::{BundleView, HttpRole, IoSocket};
use hansei_runtime::tokio::bundle::{IoResourceInfo, IoSlot, TaskList, TlsReading};
use hansei_runtime::tokio::observe::{
    HttpConnObservation, HttpReading, HttpWriting, KeepAlive, ResourceObservation, ValueKey,
};

use std::io;

/// One object a connection is made of, as an address inside it names
/// the connection: the HTTP dispatcher, a stream on the route, the
/// socket's registration.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) struct Layer {
    /// What the object is to the connection, as the claim words it.
    pub(crate) what: &'static str,
    pub(crate) value: ValueKey,
}

impl Layer {
    /// How far into the object `addr` lies, where it lies in it. An
    /// object whose type the bundle does not size claims its first
    /// byte only.
    fn offset(&self, view: &BundleView<'_>, addr: u64) -> Option<u64> {
        let size = view.ty(self.value.ty).map_or(1, |ty| ty.size().max(1));
        let offset = addr.checked_sub(self.value.addr)?;
        (offset < size).then_some(offset)
    }
}

/// The objects the observation a row was read from reaches, outermost
/// first: the dispatcher or the wrapper, each stream the route crossed,
/// and the socket's registration.
pub(crate) fn layers(observation: &ResourceObservation) -> Vec<Layer> {
    let mut layers = Vec::new();
    let mut route = |streams: &[ValueKey], tls: Option<ValueKey>, registration: ValueKey| {
        for (i, &value) in streams.iter().enumerate() {
            let what = if Some(value) == tls {
                "the TLS stream"
            } else if i + 1 == streams.len() {
                "the socket's stream"
            } else {
                "a stream on the route"
            };
            layers.push(Layer { what, value });
        }
        layers.push(Layer {
            what: "the socket's registration",
            value: registration,
        });
    };
    match observation {
        ResourceObservation::HttpConn(http) => {
            let socket = http.stream.as_ref().and_then(|s| s.as_ref().ok());
            let dispatcher = Layer {
                what: "the HTTP/1 dispatcher",
                value: http.dispatcher,
            };
            match socket {
                Some(socket) => {
                    route(&socket.streams, socket.tls_stream, socket.scheduled_io);
                    layers.insert(0, dispatcher);
                }
                None => layers.push(dispatcher),
            }
        }
        ResourceObservation::HttpNegotiating(negotiating) => layers.push(Layer {
            what: "the version-choosing wrapper",
            value: negotiating.wrapper,
        }),
        ResourceObservation::Io(io) if io.socket.is_some() => {
            route(&io.route, io.tls_stream, io.scheduled_io)
        }
        _ => {}
    }
    layers
}

/// A row and the observation it was read from.
fn primary<'s, T: proc::Target>(
    session: &'s Session<'_, T>,
    row: &ConnRow,
) -> Option<&'s ResourceObservation> {
    row.sources.first()?.observation(session)
}

/// What `whatis` says of an address inside a connection's layer.
#[derive(Clone, PartialEq, Eq, Debug)]
pub(crate) struct Claim {
    /// The row's `ADDR`, which `connection` takes.
    pub(crate) at: u64,
    /// The connection in a few words: `http1 server, idle (18ms)`.
    pub(crate) summary: String,
    /// The tasks driving it, as `tasks` names them.
    pub(crate) tasks: String,
    pub(crate) layer: &'static str,
    pub(crate) offset: u64,
    /// The layer's type, named.
    pub(crate) ty: String,
}

/// Every connection with a layer containing `addr`, and where in it.
pub(crate) fn claims_at<T: proc::Target>(session: &Session<'_, T>, addr: u64) -> Vec<Claim> {
    let view = session.ctx.view;
    let names = TypeNames::of(session);
    let mut claims = Vec::new();
    for row in connections::rows(session) {
        let Some(observation) = primary(session, row) else {
            continue;
        };
        let found = layers(observation)
            .into_iter()
            .find_map(|layer| Some((layer, layer.offset(&view, addr)?)));
        if let Some((layer, offset)) = found {
            claims.push(Claim {
                at: row.at,
                summary: summary(row),
                tasks: tasks_of(&session.tasks, row),
                layer: layer.what,
                offset,
                ty: names.folded(layer.value.ty),
            });
        }
    }
    claims
}

/// `http1 server, idle (18ms)`: the protocol and the role, then the
/// phase.
fn summary(row: &ConnRow) -> String {
    let mut head = row.proto.word().to_string();
    if let Some(role) = row.role_word() {
        head = format!("{head} {role}");
    }
    match row.phase_cell() {
        Some(phase) => format!("{head}, {phase}"),
        None => head,
    }
}

/// The tasks driving the connection, as `tasks` names them, each once
/// and in the order the row met them: `task 7`, or `tasks 7, 9` where
/// two tasks drive a socket's two halves.
fn tasks_of(list: &TaskList, row: &ConnRow) -> String {
    let mut owners: Vec<usize> = Vec::new();
    for source in &row.sources {
        if !owners.contains(&source.owner) {
            owners.push(source.owner);
        }
    }
    match owners.as_slice() {
        [one] => task_label(list, *one),
        _ => {
            let ids: Vec<String> = owners.iter().map(|&i| task_id(list, i)).collect();
            format!("tasks {}", ids.join(", "))
        }
    }
}

/// `connection ADDR`: every connection with a layer containing the
/// address, in full.
pub(crate) fn exec_connection<T: proc::Target>(
    session: &Session<'_, T>,
    addr: u64,
    out: &mut dyn io::Write,
) -> Result<()> {
    let view = session.ctx.view;
    let found: Vec<&ConnRow> = connections::rows(session)
        .iter()
        .filter(|row| {
            row.at == addr
                || primary(session, row).is_some_and(|observation| {
                    layers(observation)
                        .iter()
                        .any(|layer| layer.offset(&view, addr).is_some())
                })
        })
        .collect();
    if found.is_empty() {
        return Err(anyhow!(
            "no connection `connections` lists has an object containing {addr:#x}"
        ));
    }
    let mut blocks = 0;
    for row in found {
        separate(&mut blocks, out)?;
        print_connection(session, row, out)?;
    }
    Ok(())
}

/// One connection's block: its head, then a section per layer from the
/// protocol on top down to the socket, then the route that joins them.
fn print_connection<T: proc::Target>(
    session: &Session<'_, T>,
    row: &ConnRow,
    out: &mut dyn io::Write,
) -> Result<()> {
    let names = TypeNames::of(session);
    let list = &session.tasks;
    writeln!(out, "connection {:#x}", row.at)?;
    writeln!(out, "    proto: {}", row.proto.word())?;
    writeln!(out, "    driven by: {}", tasks_of(list, row))?;
    let Some(observation) = primary(session, row) else {
        return Ok(());
    };
    // The peers, every source labelled by what it is: the accepted
    // socket's address a server's service keeps, the authority of the
    // pool key a client was made for, a name a stream on the route
    // keeps.
    let mut peers: Vec<String> = Vec::new();
    match observation {
        ResourceObservation::HttpNegotiating(negotiating) => {
            writeln!(out, "    http: server, negotiating")?;
            writeln!(
                out,
                "        wrapper: {:#x} {}",
                negotiating.wrapper.addr,
                names.folded(negotiating.wrapper.ty)
            )?;
        }
        ResourceObservation::HttpConn(http) => {
            print_http(row, http, &names, &mut peers, out)?;
            match &http.stream {
                Some(Ok(socket)) => {
                    if let Some(tls) = &socket.tls {
                        print_tls(tls, socket.tls_stream, &names, out)?;
                    }
                    if let (Some(Ok(peer)), Some(stream)) = (&socket.peer, socket.peer_stream) {
                        peers.push(format!("{peer} (named by {})", names.folded(stream.ty)));
                    }
                    print_socket(
                        session,
                        socket.socket,
                        socket.fd,
                        socket.streams.last().copied(),
                        socket.scheduled_io,
                        out,
                    )?;
                    print_peers(&peers, out)?;
                    print_route(&socket.streams, &names, out)?;
                }
                Some(Err(why)) => {
                    writeln!(out, "    socket: unread ({why})")?;
                    print_peers(&peers, out)?;
                }
                None => {
                    writeln!(
                        out,
                        "    socket: no route recorded for the connection's stream"
                    )?;
                    print_peers(&peers, out)?;
                }
            }
        }
        ResourceObservation::Io(io) => {
            if let Some(tls) = &io.tls {
                print_tls(tls, io.tls_stream, &names, out)?;
            }
            if let (Some(Ok(peer)), Some(stream)) = (&io.peer, io.peer_stream) {
                peers.push(format!("{peer} (named by {})", names.folded(stream.ty)));
            }
            if let Some(socket) = io.socket {
                print_socket(
                    session,
                    socket,
                    io.fd,
                    io.route.last().copied(),
                    io.scheduled_io,
                    out,
                )?;
            }
            print_peers(&peers, out)?;
            print_route(&io.route, &names, out)?;
        }
        _ => {}
    }
    Ok(())
}

/// The `http:` section: the role and the phase on its line, then the
/// connection's own words and the facts read beside them.
fn print_http(
    row: &ConnRow,
    http: &HttpConnObservation,
    names: &TypeNames<'_>,
    peers: &mut Vec<String>,
    out: &mut dyn io::Write,
) -> Result<()> {
    let role = match http.role {
        HttpRole::Client => "client",
        HttpRole::Server => "server",
    };
    let phase = row
        .phase_cell()
        .unwrap_or_else(|| "phase unknown".to_string());
    writeln!(out, "    http: {role}, {phase}")?;
    writeln!(
        out,
        "        dispatcher: {:#x} {}",
        http.dispatcher.addr,
        names.folded(http.dispatcher.ty)
    )?;
    writeln!(out, "        conn: {:#x}", http.conn)?;
    writeln!(
        out,
        "        keep-alive: {}",
        keep_alive_word(&http.keep_alive)
    )?;
    writeln!(out, "        reading: {}", reading_word(&http.reading))?;
    writeln!(out, "        writing: {}", writing_word(&http.writing))?;
    if let Some(method) = &http.method {
        writeln!(out, "        method: {method}")?;
    }
    if http.is_closing {
        writeln!(out, "        closing: yes")?;
    }
    if let Some(caller) = &row.caller {
        writeln!(out, "        caller: task {caller}")?;
    }
    if let Some(request) = &row.request {
        writeln!(out, "        request: {request}")?;
    }
    if let Some(server) = &http.server {
        let handler = match server.in_flight {
            true => "running",
            false => "none running",
        };
        writeln!(out, "        handler: {handler}")?;
        let mut timer = vec![match server.header_read_timer_running {
            true => "armed".to_string(),
            false => "not armed".to_string(),
        }];
        if let Some(timeout) = server.header_read_timeout {
            timer.push(format!("{}s timeout", timeout.as_secs_f64()));
        }
        if let Some(deadline) = &row.deadline {
            timer.push(deadline.clone());
        }
        writeln!(out, "        header-read timer: {}", timer.join(", "))?;
        if let Some(context) = &server.context {
            writeln!(out, "        server: {context}")?;
        }
        // The accepting server's own state, which every connection it
        // accepted shares.
        let scheme = server.tls.map(|tls| match tls {
            true => "https",
            false => "http",
        });
        match (&server.local_addr, scheme) {
            (Some(addr), Some(scheme)) => writeln!(out, "        listening: {addr} ({scheme})")?,
            (Some(addr), None) => writeln!(out, "        listening: {addr}")?,
            (None, Some(scheme)) => writeln!(out, "        listening: unread ({scheme})")?,
            (None, None) => {}
        }
        if let Some(peer) = &server.peer {
            peers.push(format!(
                "{peer} (the accepted socket's, kept by the server's service)"
            ));
        }
    }
    if http.role == HttpRole::Client
        && let Some(peer) = &row.peer
    {
        peers.push(format!(
            "{peer} (the authority of the pool key it was made for)"
        ));
    }
    Ok(())
}

/// The `tls:` section: the side, the version and the verdict on its
/// line, then the records, what is unsent, and how far each direction
/// has closed.
fn print_tls(
    tls: &Result<TlsReading, String>,
    stream: Option<ValueKey>,
    names: &TypeNames<'_>,
    out: &mut dyn io::Write,
) -> Result<()> {
    let reading = match tls {
        Ok(reading) => reading,
        Err(why) => {
            writeln!(out, "    tls: unread ({why})")?;
            if let Some(stream) = stream {
                writeln!(
                    out,
                    "        stream: {:#x} {}",
                    stream.addr,
                    names.folded(stream.ty)
                )?;
            }
            return Ok(());
        }
    };
    let mut head = vec![reading.side.to_ascii_lowercase()];
    head.extend(reading.version.clone());
    head.push(reading.verdict().word().to_string());
    writeln!(out, "    tls: {}", head.join(", "))?;
    if let Some(stream) = stream {
        writeln!(
            out,
            "        stream: {:#x} {}",
            stream.addr,
            names.folded(stream.ty)
        )?;
    }
    writeln!(
        out,
        "        records: {} read, {} written",
        reading.read_seq, reading.write_seq
    )?;
    let (records, bytes) = reading.unsent;
    writeln!(out, "        unsent: {records} records, {bytes} bytes")?;
    writeln!(out, "        stream state: {}", reading.stream_state)?;
    let mut closed = Vec::new();
    for (set, word) in [
        (reading.has_sent_close_notify, "close_notify sent"),
        (reading.has_received_close_notify, "close_notify received"),
        (reading.has_seen_eof, "eof seen"),
        (reading.sent_fatal_alert, "fatal alert sent"),
        (reading.failed, "failed"),
    ] {
        if set {
            closed.push(word);
        }
    }
    if closed.is_empty() {
        closed.push("none");
    }
    writeln!(out, "        closure: {}", closed.join(", "))?;
    Ok(())
}

/// The `tcp:` or `unix:` section: the descriptor on its line, then the
/// socket's stream and its registration, with what the io driver last
/// delivered and the wakers parked on it.
fn print_socket<T: proc::Target>(
    session: &Session<'_, T>,
    socket: IoSocket,
    fd: Option<i32>,
    stream: Option<ValueKey>,
    registration: ValueKey,
    out: &mut dyn io::Write,
) -> Result<()> {
    let kind = match socket {
        IoSocket::TcpStream => "tcp",
        IoSocket::UnixStream => "unix",
    };
    match fd {
        Some(fd) => writeln!(out, "    {kind}: fd {fd}")?,
        None => writeln!(out, "    {kind}: fd unread")?,
    }
    if let Some(stream) = stream {
        let names = TypeNames::of(session);
        writeln!(
            out,
            "        stream: {:#x} {}",
            stream.addr,
            names.folded(stream.ty)
        )?;
    }
    writeln!(out, "        registration: {:#x}", registration.addr)?;
    let resource = session
        .registries
        .io
        .iter()
        .find(|resource| resource.addr == registration.addr);
    match resource {
        Some(resource) => print_registration(&session.tasks, resource, out)?,
        None => writeln!(
            out,
            "        ready: not in the io driver's registration list"
        )?,
    }
    Ok(())
}

/// What the registration's words say: the readiness delivered, whether
/// the driver has shut it down, and each waker parked on it.
fn print_registration(
    list: &TaskList,
    resource: &IoResourceInfo,
    out: &mut dyn io::Write,
) -> Result<()> {
    match resource.ready() {
        Some(ready) => writeln!(out, "        ready: {ready}")?,
        None => writeln!(out, "        ready: unread")?,
    }
    if resource.readiness.is_some_and(shut_down) {
        writeln!(out, "        shut down: yes")?;
    }
    for waiter in &resource.waiters {
        let slot = match waiter.slot {
            IoSlot::Reader => "the reader slot".to_string(),
            IoSlot::Writer => "the writer slot".to_string(),
            IoSlot::Listed {
                interest: Some(interest),
            } => format!("the readiness list ({interest})"),
            IoSlot::Listed { interest: None } => "the readiness list".to_string(),
        };
        let task = waiter
            .task
            .and_then(|header| list.tasks.iter().position(|t| t.addr.0 == header))
            .map(|index| task_label(list, index));
        match task {
            Some(task) => writeln!(out, "        waker: {slot}, {task}")?,
            None => writeln!(out, "        waker: {slot}")?,
        }
    }
    Ok(())
}

/// The registration's shutdown flag, above the sixteen readiness bits
/// and the fifteen tick bits.
const SHUTDOWN: u64 = 1 << 31;

/// Whether a registration's readiness word says the driver has shut it
/// down.
fn shut_down(readiness: u64) -> bool {
    readiness & SHUTDOWN != 0
}

fn print_peers(peers: &[String], out: &mut dyn io::Write) -> Result<()> {
    for peer in peers {
        writeln!(out, "    peer: {peer}")?;
    }
    Ok(())
}

/// The `route:` section: every stream from the connection's own down to
/// the socket's, outermost first.
fn print_route(streams: &[ValueKey], names: &TypeNames<'_>, out: &mut dyn io::Write) -> Result<()> {
    if streams.is_empty() {
        return Ok(());
    }
    writeln!(out, "    route:")?;
    for stream in streams {
        writeln!(
            out,
            "        {:#x} {}",
            stream.addr,
            names.folded(stream.ty)
        )?;
    }
    Ok(())
}

fn keep_alive_word(keep_alive: &KeepAlive) -> String {
    match keep_alive {
        KeepAlive::Idle => "idle".to_string(),
        KeepAlive::Busy => "busy".to_string(),
        KeepAlive::Disabled => "disabled".to_string(),
        KeepAlive::Unknown(word) => format!("unknown ({word})"),
    }
}

fn reading_word(reading: &HttpReading) -> String {
    match reading {
        HttpReading::Init => "init".to_string(),
        HttpReading::Continue(framing) => framed("continue", framing),
        HttpReading::Body(framing) => framed("body", framing),
        HttpReading::KeepAlive => "keep-alive".to_string(),
        HttpReading::Closed => "closed".to_string(),
        HttpReading::Unknown(word) => format!("unknown ({word})"),
    }
}

fn writing_word(writing: &HttpWriting) -> String {
    match writing {
        HttpWriting::Init => "init".to_string(),
        HttpWriting::Body(framing) => framed("body", framing),
        HttpWriting::KeepAlive => "keep-alive".to_string(),
        HttpWriting::Closed => "closed".to_string(),
        HttpWriting::Unknown(word) => format!("unknown ({word})"),
    }
}

fn framed(word: &str, framing: &Option<hansei_runtime::tokio::bundle::BodyFraming>) -> String {
    match framing {
        Some(framing) => format!("{word} ({framing})"),
        None => word.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::offline::session_args;
    use hansei_bundle::{BundleTypeId, IoOperationKind};
    use hansei_runtime::testkit;
    use hansei_runtime::tokio::bundle::Interest;
    use hansei_runtime::tokio::observe::{
        HttpNegotiatingObservation, IoObservation, SocketReading,
    };

    fn key(addr: u64) -> ValueKey {
        ValueKey {
            addr,
            ty: BundleTypeId(3),
        }
    }

    fn io(socket: Option<IoSocket>) -> IoObservation {
        IoObservation {
            future: key(0x1),
            operation: IoOperationKind::Read,
            scheduled_io: key(0x6500),
            interest: Interest::READABLE,
            waiter_node: None,
            remaining: None,
            readiness_state: None,
            waiter_ready: None,
            route: vec![key(0x10), key(0x20), key(0x30)],
            fd: Some(9),
            tls: None,
            tls_stream: Some(key(0x20)),
            socket,
            peer: None,
            peer_stream: None,
        }
    }

    /// A connection's objects run from the protocol on top down to the
    /// registration, each named for what it is to the connection: the
    /// stream the TLS connection was read from, the socket's own, the
    /// ones between. A route that did not read leaves the dispatcher
    /// alone; a readiness await is no connection and has none.
    #[test]
    fn test_layers_run_from_the_protocol_to_the_registration() {
        let named = |layers: Vec<Layer>| -> Vec<(&'static str, u64)> {
            layers.iter().map(|l| (l.what, l.value.addr)).collect()
        };
        let route = [
            ("a stream on the route", 0x10),
            ("the TLS stream", 0x20),
            ("the socket's stream", 0x30),
            ("the socket's registration", 0x6500),
        ];
        let read = ResourceObservation::Io(io(Some(IoSocket::TcpStream)));
        assert_eq!(named(layers(&read)), route);
        let readiness = ResourceObservation::Io(io(None));
        assert_eq!(named(layers(&readiness)), []);

        let socket = SocketReading {
            streams: vec![key(0x10), key(0x20), key(0x30)],
            scheduled_io: key(0x6500),
            fd: Some(9),
            socket: IoSocket::TcpStream,
            tls: None,
            tls_stream: Some(key(0x20)),
            peer: None,
            peer_stream: None,
        };
        let http = |stream| {
            ResourceObservation::HttpConn(Box::new(HttpConnObservation {
                dispatcher: key(0x7b78948),
                conn: 0x7b78948,
                role: HttpRole::Server,
                keep_alive: KeepAlive::Idle,
                reading: HttpReading::Init,
                writing: HttpWriting::Init,
                method: None,
                is_closing: false,
                client: None,
                server: None,
                stream,
            }))
        };
        let mut over = vec![("the HTTP/1 dispatcher", 0x7b78948)];
        over.extend(route);
        assert_eq!(named(layers(&http(Some(Ok(socket))))), over);
        assert_eq!(
            named(layers(&http(Some(Err("unread".to_string()))))),
            [("the HTTP/1 dispatcher", 0x7b78948)]
        );
        let negotiating = ResourceObservation::HttpNegotiating(HttpNegotiatingObservation {
            wrapper: key(0x12345),
        });
        assert_eq!(
            named(layers(&negotiating)),
            [("the version-choosing wrapper", 0x12345)]
        );
    }

    /// Over the fixture holding TLS, TCP and HTTP-over-TLS connections:
    /// the first and last byte of every object of every row claim that
    /// row, in the outermost of its objects holding the byte — a stream
    /// held by value at offset zero shares its holder's address — and
    /// the byte past an object's end is not that object's.
    #[test]
    fn test_every_object_of_a_row_claims_it() {
        let (bundle, snapshot) = testkit::load("illumos", "tls-conns");
        let args = session_args("illumos", "tls-conns");
        let session = Session::attach(&snapshot, &bundle, &args).expect("the pair attaches");
        let view = session.ctx.view;
        let rows = connections::rows(&session);
        assert!(!rows.is_empty());
        for row in rows {
            let observation = primary(&session, row).expect("a row has its observation");
            let objects = layers(observation);
            for layer in &objects {
                let size = view.ty(layer.value.ty).map_or(1, |ty| ty.size().max(1));
                let start = layer.value.addr;
                for addr in [start, start + size - 1] {
                    let (outermost, offset) = objects
                        .iter()
                        .find_map(|l| Some((l, l.offset(&view, addr)?)))
                        .expect("the object itself holds the byte");
                    let claims = claims_at(&session, addr);
                    assert!(
                        claims.iter().any(|c| c.at == row.at
                            && c.layer == outermost.what
                            && c.offset == offset),
                        "{} of {:#x} at {addr:#x}: {claims:?}",
                        layer.what,
                        row.at
                    );
                }
                assert_eq!(layer.offset(&view, start + size), None);
            }
        }
    }

    /// `connection` takes any byte of any of a row's objects, not only
    /// the address the listing prints: over the fixture, every row's
    /// first block is its own, whichever object's last byte selected
    /// it, and no other row's block follows; an address no object
    /// holds selects nothing.
    #[test]
    fn test_any_byte_of_a_rows_objects_selects_it() {
        let (bundle, snapshot) = testkit::load("illumos", "tls-conns");
        let args = session_args("illumos", "tls-conns");
        let session = Session::attach(&snapshot, &bundle, &args).expect("the pair attaches");
        let view = session.ctx.view;
        let rows = connections::rows(&session);
        assert!(!rows.is_empty());
        for row in rows {
            let observation = primary(&session, row).expect("a row has its observation");
            for layer in layers(observation) {
                let size = view.ty(layer.value.ty).map_or(1, |ty| ty.size().max(1));
                let addr = layer.value.addr + size - 1;
                let mut out = Vec::new();
                exec_connection(&session, addr, &mut out).expect("the byte selects a row");
                let out = String::from_utf8(out).unwrap();
                assert!(
                    out.starts_with(&format!("connection {:#x}\n", row.at)),
                    "{} of {:#x} at {addr:#x}:\n{out}",
                    layer.what,
                    row.at
                );
                assert_eq!(
                    out.lines()
                        .filter(|line| line.starts_with("connection "))
                        .count(),
                    1,
                    "{out}"
                );
            }
        }
        let mut out = Vec::new();
        assert!(exec_connection(&session, 0x10, &mut out).is_err());
        assert!(out.is_empty());
    }

    /// The shutdown flag is the bit above the sixteen readiness bits and
    /// the fifteen tick bits, and no bit below it.
    #[test]
    fn test_the_shutdown_flag_is_bit_31() {
        assert!(shut_down(1 << 31));
        assert!(shut_down((1 << 31) | 0x7fff_ffff));
        assert!(!shut_down(0x7fff_ffff));
        assert!(!shut_down(0));
    }

    /// A body's state words carry its framing where hyper's decoder or
    /// encoder says it, and stand bare where it does not.
    #[test]
    fn test_body_words_carry_their_framing() {
        use hansei_runtime::tokio::bundle::BodyFraming;
        assert_eq!(
            reading_word(&HttpReading::Body(Some(BodyFraming::Length {
                remaining: 5
            }))),
            "body (5 bytes remaining)"
        );
        assert_eq!(
            reading_word(&HttpReading::Continue(Some(BodyFraming::Chunked))),
            "continue (chunked)"
        );
        assert_eq!(reading_word(&HttpReading::Body(None)), "body");
        assert_eq!(
            writing_word(&HttpWriting::Body(Some(BodyFraming::CloseDelimited))),
            "body (close-delimited)"
        );
        assert_eq!(writing_word(&HttpWriting::Body(None)), "body");
    }
}
