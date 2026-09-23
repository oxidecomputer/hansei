// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! hyper HTTP/1 connections parked in three steady states, for the
//! hyper formatters: a hyper-util `auto` server on a loopback listener
//! and two hyper-util legacy clients in one process. (a) One idle
//! client connection in its pool after two completed GETs on one
//! client — the server accepted exactly one connection for both, which
//! is what shows the pool reused it. (b) One in-flight GET whose
//! handler parks on a `Notify` nothing ever signals: the client
//! connection is busy awaiting the response, the server connection is
//! running the handler. (c) One raw `TcpStream` connected and never
//! written, so the server side is still reading the first bytes to
//! choose between HTTP/1 and HTTP/2. (d) The in-flight GET of (b) sent
//! once more through reqwest, whose `send()` future keeps the request's
//! method and URL the way a client on a real target does, so the
//! request behind a connection can be read from the requester's side.
//! `READY` on stdout means every connection has reached its parked
//! state; there are no timing sleeps — readiness is observed over
//! channels, including the moment a client connection returns to its
//! pool, which hyper-util does on a background task the client's
//! executor spawns.

use std::convert::Infallible;
use std::future::Future;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use bytes::Bytes;
use http_body_util::{BodyExt, Empty, Full};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper::{Request, Response};
use hyper_util::client::legacy::Client;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use hyper_util::server::conn::auto;
use test_programs::census_expect;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Notify, mpsc, oneshot};

/// What the server side reports to main.
enum Event {
    /// The accept loop took a connection.
    Accepted,
    /// The `/park` handler is about to park on its `Notify`.
    HandlerParked,
}

/// The legacy client's executor: tokio's, counting the futures handed
/// to it and reporting on `done` as each completes. A request's
/// completion says nothing about the pool: hyper-util hands the
/// connection back either inline, when the connection is already ready
/// for another request by the time the response head is delivered, or
/// from a task it spawns here once it becomes ready — which of the two
/// is a race the caller cannot see. What the caller can see is the
/// number of live background tasks: the connection task never
/// completes while the fixture parks, so once every other future the
/// client spawned has completed, the connection is in the pool.
#[derive(Clone)]
struct Reporting {
    spawned: Arc<AtomicUsize>,
    done: mpsc::UnboundedSender<()>,
}

impl<F> hyper::rt::Executor<F> for Reporting
where
    F: Future<Output = ()> + Send + 'static,
{
    fn execute(&self, fut: F) {
        self.spawned.fetch_add(1, Ordering::SeqCst);
        let done = self.done.clone();
        tokio::spawn(async move {
            fut.await;
            let _ = done.send(());
        });
    }
}

/// Wait until only `live` of the futures a [`Reporting`] executor was
/// handed are still running. Every spawn a request causes happens
/// before the request returns, so the count is final when this is
/// called, and each completion arrives on `done`.
async fn settled(
    executor: &Reporting,
    done: &mut mpsc::UnboundedReceiver<()>,
    completed: &mut usize,
    live: usize,
) {
    while executor.spawned.load(Ordering::SeqCst) - *completed > live {
        done.recv().await.expect("the executor reports completions");
        *completed += 1;
    }
}

/// The service: a small body naming the peer, for any path, except that
/// `/park` first says so on `events` and then waits on `park`, which
/// nothing ever signals, so that request stays in flight on both ends.
async fn handle(
    req: Request<Incoming>,
    peer: SocketAddr,
    events: mpsc::UnboundedSender<Event>,
    park: Arc<Notify>,
) -> Result<Response<Full<Bytes>>, Infallible> {
    if req.uri().path() == "/park" {
        events
            .send(Event::HandlerParked)
            .expect("main waits for the handler");
        park.notified().await;
    }
    Ok(Response::new(Full::new(Bytes::from(format!(
        "hello {peer}"
    )))))
}

/// Serve one accepted connection through hyper-util's version-choosing
/// server, with upgrades, the way a dropshot server does. The service
/// keeps the accepted socket's peer address, as dropshot's does, so a
/// server connection's dispatch holds a `SocketAddr`. hyper's timer is
/// installed, as dropshot installs it, with an hour's header-read
/// timeout — long enough never to fire before the core is taken — so an
/// idle connection holds its armed header-read timer.
async fn serve(
    stream: TcpStream,
    peer: SocketAddr,
    events: mpsc::UnboundedSender<Event>,
    park: Arc<Notify>,
) {
    let service = service_fn(move |req| handle(req, peer, events.clone(), park.clone()));
    let mut builder = auto::Builder::new(TokioExecutor::new());
    builder
        .http1()
        .timer(TokioTimer::new())
        .header_read_timeout(std::time::Duration::from_secs(3600));
    let _ = builder
        .serve_connection_with_upgrades(TokioIo::new(stream), service)
        .await;
}

/// Accept forever, reporting each connection on `events` before
/// handing it, with its peer's address, to its own task.
async fn accept_loop(
    listener: TcpListener,
    events: mpsc::UnboundedSender<Event>,
    park: Arc<Notify>,
) {
    census_expect::task("http_conns::accept_loop");
    loop {
        let (stream, peer) = listener.accept().await.expect("accept");
        events
            .send(Event::Accepted)
            .expect("main waits for accepts");
        tokio::spawn(serve(stream, peer, events.clone(), park.clone()));
    }
}

/// Send one GET and drain the response body, so the connection that
/// carried it can go idle.
async fn get(client: &Client<HttpConnector, Empty<Bytes>>, uri: &str) {
    let req = Request::builder()
        .uri(uri)
        .body(Empty::new())
        .expect("a well-formed request");
    let res = client.request(req).await.expect("a response");
    res.into_body().collect().await.expect("a whole body");
}

/// Park awaiting the response to `/park`, which never comes.
async fn requester(client: Client<HttpConnector, Empty<Bytes>>, uri: String) {
    census_expect::task("http_conns::requester");
    get(&client, &uri).await;
}

/// Park awaiting the response to `/park` through reqwest, which keeps
/// the request it sent — method and URL — in the future being awaited.
async fn reqwest_requester(client: reqwest::Client, url: String) {
    census_expect::task("http_conns::reqwest_requester");
    let _ = client.get(url).send().await;
}

/// Park forever holding a connected socket nothing writes to.
async fn raw_holder(_stream: TcpStream, park: oneshot::Receiver<()>) {
    census_expect::task("http_conns::raw_holder");
    let _ = park.await;
}

fn main() {
    test_programs::allow_any_tracer();

    let mut builder = test_programs::Builder::new_multi_thread();
    builder.worker_threads(2);
    test_programs::run_builder(&mut builder, async {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("a loopback listener");
        let addr = listener.local_addr().expect("a bound address");
        let (events_tx, mut events) = mpsc::unbounded_channel();
        let park = Arc::new(Notify::new());
        let _accept_loop = tokio::spawn(accept_loop(listener, events_tx, park.clone()));

        let (done_tx, mut done) = mpsc::unbounded_channel();
        let executor = Reporting {
            spawned: Arc::new(AtomicUsize::new(0)),
            done: done_tx,
        };
        let mut completed = 0;

        // (a) Two GETs on one client. The client asks a fresh
        // connection for the first, then reuses it for the second —
        // but only if the pool already holds it when asked, since a
        // checkout that is not ready at once races a fresh connect. So
        // main waits, before the second GET, until the client's one
        // connection is its only live background task.
        let pooled = Client::builder(executor.clone()).build_http::<Empty<Bytes>>();
        let uri = format!("http://{addr}/");
        get(&pooled, &uri).await;
        settled(&executor, &mut done, &mut completed, 1).await;
        get(&pooled, &uri).await;
        settled(&executor, &mut done, &mut completed, 1).await;
        assert!(
            matches!(events.try_recv(), Ok(Event::Accepted)),
            "the first GET opens a connection"
        );
        assert!(
            matches!(events.try_recv(), Err(mpsc::error::TryRecvError::Empty)),
            "the second GET reuses it"
        );

        // (b) A GET whose handler parks: the requester waits on the
        // response, the server connection on the handler.
        let busy = Client::builder(executor).build_http::<Empty<Bytes>>();
        let _requester = tokio::spawn(requester(busy, format!("http://{addr}/park")));
        assert!(
            matches!(events.recv().await, Some(Event::Accepted)),
            "the parked GET opens its own connection"
        );
        assert!(
            matches!(events.recv().await, Some(Event::HandlerParked)),
            "the handler parks"
        );

        // (d) The same parked GET through reqwest: its client keeps no
        // executor of the fixture's, so nothing here counts what it
        // spawns; the server side reports the connection and the
        // handler as for (b). No proxy discovery, so the request goes
        // to the listener whatever the environment says.
        let via_reqwest = reqwest::Client::builder()
            .no_proxy()
            .build()
            .expect("a reqwest client");
        let _reqwest_requester = tokio::spawn(reqwest_requester(
            via_reqwest,
            format!("http://{addr}/park"),
        ));
        assert!(
            matches!(events.recv().await, Some(Event::Accepted)),
            "the reqwest GET opens its own connection"
        );
        assert!(
            matches!(events.recv().await, Some(Event::HandlerParked)),
            "its handler parks"
        );

        // (c) A connection that never speaks, so the server side is
        // still choosing the protocol version.
        let raw = TcpStream::connect(addr).await.expect("a loopback connect");
        assert!(
            matches!(events.recv().await, Some(Event::Accepted)),
            "the raw connection is accepted"
        );
        let (park_tx, park_rx) = oneshot::channel();
        std::mem::forget(park_tx);
        let _raw_holder = tokio::spawn(raw_holder(raw, park_rx));

        // What the census finds inside hyper-util's own futures, which
        // the fixture can name only by the task holding it: under the
        // connection that never spoke, the version-choosing read the
        // wrapper is parked on. The HTTP/1 connection tasks register
        // nothing: on either side the dispatcher is a frame of the
        // task's own await chain, reached through hyper's and
        // hyper-util's connection wrappers, so it is no held find.
        census_expect::held_by_task("http_conns::serve", "auto::ReadVersion");
        // Under the idle server connection of (a): its header-read
        // timer, armed as it waits for the next request head. hyper
        // drops the timer once a head is parsed, so the servers
        // running a handler hold none.
        census_expect::held_by_task("http_conns::serve", "TokioSleep");
        // Under the reqwest requester: the request itself behind the
        // box reqwest's `send()` future keeps it in, and the two tower
        // layers under it the census descends through to the response
        // future — library values the fixture cannot address either.
        census_expect::held_by_task("http_conns::reqwest_requester", "PendingRequest");
        census_expect::held_by_task(
            "http_conns::reqwest_requester",
            "follow_redirect::ResponseFuture",
        );
        census_expect::held_by_task("http_conns::reqwest_requester", "either::Either");

        test_programs::quiesce();
        println!("READY");
        std::future::pending::<()>().await
    })
}
