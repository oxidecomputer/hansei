// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! TLS and plain TCP connections parked in the states a real target's
//! connection tasks park in, for the io routes and the TLS session
//! words: rustls through tokio-rustls, both ends in one process over
//! loopback. (a) An established pair after one exchange: the client
//! parks in a `read` on its `client::TlsStream`, the server in a
//! `read_exact` on its `server::TlsStream`, the shape an attestation
//! exchange waits in. (b) An established pair whose client stream is
//! tokio-rustls's `TlsStream` enum, split with `tokio::io::split`, and
//! parked in a `select!` over a read on one half and a disabled
//! `write_buf` on the other, as trust-quorum's connections park; its
//! server reads through a boxed `BufStream`, as sprockets' server does.
//! (c) The same `select!` over a plain TCP stream split into owned
//! halves, as bootstore's connections park, against a server reading
//! its bare `TcpStream`. (d) A client that sent its close_notify and
//! still reads, through a reference to its stream, against a server that
//! read to that end of stream and keeps its stream. (e) A client
//! mid-handshake, its ClientHello sent to a peer that never answers.
//! (f) A server mid-handshake, waiting for the ClientHello of a peer
//! that never sends one. (g) An HTTP/1 exchange over TLS, after which
//! both ends park between exchanges: the server through hyper-util's
//! version-choosing server, as dropshot serves HTTPS, the client
//! through hyper's own connection.
//!
//! The certificate authority and the `localhost` certificate it signed
//! are embedded below: generated once with openssl, ECDSA P-256, valid
//! for a hundred years, so the fixture needs no clock but the host's
//! and no certificate generator. `READY` on stdout means every
//! connection has reached its parked state; readiness is observed over
//! channels, with no timing sleeps.

use std::convert::Infallible;
use std::io::Cursor;
use std::sync::Arc;

use bytes::{Buf, Bytes};
use http_body_util::{BodyExt, Empty, Full};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper::{Request, Response};
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use test_programs::census_expect;
use tokio::io::{AsyncReadExt, AsyncWriteExt, BufStream, ReadHalf, WriteHalf};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, oneshot};
use tokio_rustls::{TlsAcceptor, TlsConnector, TlsStream, client, server};

/// The authority the client trusts.
const CA: &str = "\
-----BEGIN CERTIFICATE-----
MIIBozCCAUmgAwIBAgIUJ3F1Ok8McO4AiTaqeGC7mMOf37gwCgYIKoZIzj0EAwIw
HjEcMBoGA1UEAwwTaGFuc2VpIHRscy1jb25ucyBDQTAgFw0yNjA5MzAxMjQwNTFa
GA8yMTI2MDkwNjEyNDA1MVowHjEcMBoGA1UEAwwTaGFuc2VpIHRscy1jb25ucyBD
QTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABMDtz2017eZqlQmAeBZfCi7woS0w
UEZMj1sEyPSJrjdVtqAnCqxKx5rfvykyGkzhq5qlHpNiG5GvBxqXJMGh/P2jYzBh
MB0GA1UdDgQWBBQoBI0waSkqhS9/RFe1N81PNopFbjAfBgNVHSMEGDAWgBQoBI0w
aSkqhS9/RFe1N81PNopFbjAPBgNVHRMBAf8EBTADAQH/MA4GA1UdDwEB/wQEAwIB
BjAKBggqhkjOPQQDAgNIADBFAiEAyhxQy3wj98kExbhbUoMUfmkE3+NjX95tQn29
XSKBHiMCICOp0Z6EzlKjy1QChC2G5+LdrEbVEfraul5xU2+Syj24
-----END CERTIFICATE-----
";

/// The server's certificate, for `localhost`, signed by [`CA`].
const LEAF: &str = "\
-----BEGIN CERTIFICATE-----
MIIBzjCCAXOgAwIBAgIUVzx57UhLPQMZ0Al6p4pI0TfzipgwCgYIKoZIzj0EAwIw
HjEcMBoGA1UEAwwTaGFuc2VpIHRscy1jb25ucyBDQTAgFw0yNjA5MzAxMjQwNTFa
GA8yMTI2MDkwNjEyNDA1MVowFDESMBAGA1UEAwwJbG9jYWxob3N0MFkwEwYHKoZI
zj0CAQYIKoZIzj0DAQcDQgAEninU6ff/1uA9M95s1W+QYQQN/fybvIjLYgvkjmI6
aUScrBed/HUZDio/7vz5ZP2aGcn15uf1WvO4rzXkcM9UlKOBljCBkzAUBgNVHREE
DTALgglsb2NhbGhvc3QwDAYDVR0TAQH/BAIwADAOBgNVHQ8BAf8EBAMCB4AwHQYD
VR0lBBYwFAYIKwYBBQUHAwEGCCsGAQUFBwMCMB0GA1UdDgQWBBTyHwMrpr660cmC
y2gO8Zq9yvZblTAfBgNVHSMEGDAWgBQoBI0waSkqhS9/RFe1N81PNopFbjAKBggq
hkjOPQQDAgNJADBGAiEA5C1ym0a62g+PqPiMQQLk5/W5uNw3uqYcL7bhTuuvqKAC
IQDY+aJlOWmyiMUly8DSWg1W/NwMEpE6+iOdCkPZl/gJaQ==
-----END CERTIFICATE-----
";

/// The server certificate's key, PKCS#8.
const KEY: &str = "\
-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgO7XVzd765TBa2UFb
wxpK2vwCpgtaeB+lSEDGns3meuShRANCAASeKdTp9//W4D0z3mzVb5BhBA39/Ju8
iMtiC+SOYjppRJysF538dRkOKj/u/Plk/ZoZyfXm5/Va87ivNeRwz1SU
-----END PRIVATE KEY-----
";

/// The two configurations every TLS connection here is made with:
/// ring's provider, the default protocol versions, a client trusting
/// [`CA`] and a server presenting [`LEAF`].
fn tls_ends() -> (TlsConnector, TlsAcceptor) {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut roots = rustls::RootCertStore::empty();
    roots
        .add(CertificateDer::from_pem_slice(CA.as_bytes()).expect("the CA parses"))
        .expect("the CA is a trust anchor");
    let client = rustls::ClientConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()
        .expect("ring supports the default versions")
        .with_root_certificates(roots)
        .with_no_client_auth();
    let server = rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .expect("ring supports the default versions")
        .with_no_client_auth()
        .with_single_cert(
            vec![CertificateDer::from_pem_slice(LEAF.as_bytes()).expect("the leaf parses")],
            PrivateKeyDer::from_pem_slice(KEY.as_bytes()).expect("the key parses"),
        )
        .expect("the key matches the leaf");
    (
        TlsConnector::from(Arc::new(client)),
        TlsAcceptor::from(Arc::new(server)),
    )
}

/// The name the client asks for, which [`LEAF`] carries.
fn localhost() -> ServerName<'static> {
    ServerName::try_from("localhost").expect("a DNS name")
}

/// One loopback TCP connection: the client's end and the server's.
async fn tcp_pair() -> (TcpStream, TcpStream) {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("a loopback listener");
    let addr = listener.local_addr().expect("a bound address");
    let (client, accepted) = tokio::join!(TcpStream::connect(addr), listener.accept());
    (
        client.expect("a loopback connect"),
        accepted.expect("a loopback accept").0,
    )
}

/// One established TLS connection over [`tcp_pair`].
async fn tls_pair(
    connector: &TlsConnector,
    acceptor: &TlsAcceptor,
) -> (client::TlsStream<TcpStream>, server::TlsStream<TcpStream>) {
    let (client_tcp, server_tcp) = tcp_pair().await;
    let (client, server) = tokio::join!(
        connector.connect(localhost(), client_tcp),
        acceptor.accept(server_tcp)
    );
    (
        client.expect("the client handshake completes"),
        server.expect("the server handshake completes"),
    )
}

/// (a) The client end: after one exchange, park reading a reply that
/// never comes.
async fn plain_client(mut stream: client::TlsStream<TcpStream>, ready: oneshot::Sender<()>) {
    census_expect::task("tls_conns::plain_client");
    stream.write_all(b"ping").await.expect("the ping is sent");
    let mut pong = [0u8; 4];
    stream
        .read_exact(&mut pong)
        .await
        .expect("the pong arrives");
    assert_eq!(&pong, b"pong");
    ready.send(()).expect("main waits for readiness");
    let mut more = [0u8; 64];
    let _ = stream.read(&mut more).await;
}

/// (a) The server end: answer the ping, then wait for a length-prefixed
/// message's four length bytes that never come.
async fn exact_server(mut stream: server::TlsStream<TcpStream>, ready: oneshot::Sender<()>) {
    census_expect::task("tls_conns::exact_server");
    let mut ping = [0u8; 4];
    stream
        .read_exact(&mut ping)
        .await
        .expect("the ping arrives");
    stream.write_all(b"pong").await.expect("the pong is sent");
    ready.send(()).expect("main waits for readiness");
    let mut len = [0u8; 4];
    let _ = stream.read_exact(&mut len).await;
}

/// (b) The client end: a `select!` over a read on one half and a
/// `write_buf` on the other, disabled while there is nothing to write.
/// Both branch futures are pinned locals the select borrows, so the
/// census finds each at an address the fixture can name.
async fn split_client(
    mut reader: ReadHalf<TlsStream<TcpStream>>,
    mut writer: WriteHalf<TlsStream<TcpStream>>,
    ready: oneshot::Sender<()>,
) {
    census_expect::task("tls_conns::split_client");
    let mut buf = vec![0u8; 1024];
    let mut queued = Cursor::new(Vec::new());
    let writing = queued.has_remaining();
    let read = reader.read(&mut buf);
    let write = writer.write_buf(&mut queued);
    tokio::pin!(read, write);
    census_expect::held(&*read as *const _ as u64, "Read<");
    census_expect::held(&*write as *const _ as u64, "WriteBuf<");
    ready.send(()).expect("main waits for readiness");
    tokio::select! {
        _ = &mut read => {}
        _ = &mut write, if writing => {}
    }
}

/// (b) The server end, reading through a boxed `BufStream`.
async fn buffered_server(
    mut stream: Box<BufStream<server::TlsStream<TcpStream>>>,
    ready: oneshot::Sender<()>,
) {
    census_expect::task("tls_conns::buffered_server");
    ready.send(()).expect("main waits for readiness");
    let mut len = [0u8; 2];
    let _ = stream.read_exact(&mut len).await;
}

/// (c) The client end: (b)'s `select!` over a plain TCP stream's owned
/// halves.
async fn owned_split_client(
    mut reader: OwnedReadHalf,
    mut writer: OwnedWriteHalf,
    ready: oneshot::Sender<()>,
) {
    census_expect::task("tls_conns::owned_split_client");
    let mut buf = vec![0u8; 512];
    let mut queued = Cursor::new(Vec::new());
    let writing = queued.has_remaining();
    let read = reader.read(&mut buf);
    let write = writer.write_buf(&mut queued);
    tokio::pin!(read, write);
    census_expect::held(&*read as *const _ as u64, "Read<");
    census_expect::held(&*write as *const _ as u64, "WriteBuf<");
    ready.send(()).expect("main waits for readiness");
    tokio::select! {
        _ = &mut read => {}
        _ = &mut write, if writing => {}
    }
}

/// (c) The server end, reading its bare stream.
async fn tcp_server(mut stream: TcpStream, ready: oneshot::Sender<()>) {
    census_expect::task("tls_conns::tcp_server");
    ready.send(()).expect("main waits for readiness");
    let mut buf = [0u8; 256];
    let _ = stream.read(&mut buf).await;
}

/// (d) The client end: send close_notify, which also shuts the
/// socket's write side, then keep reading.
async fn closing_client(mut stream: client::TlsStream<TcpStream>, ready: oneshot::Sender<()>) {
    census_expect::task("tls_conns::closing_client");
    stream.shutdown().await.expect("the close_notify is sent");
    ready.send(()).expect("main waits for readiness");
    // Read through a reference, so the read's stream is the reference
    // itself and the route crosses it.
    let mut reader = &mut stream;
    let mut more = [0u8; 32];
    let _ = AsyncReadExt::read(&mut reader, &mut more).await;
}

/// (d) The server end: read to the end of stream the close_notify
/// marks, then keep the stream, reading nothing.
async fn drained_server(
    mut stream: server::TlsStream<TcpStream>,
    ready: oneshot::Sender<()>,
    park: oneshot::Receiver<()>,
) {
    census_expect::task("tls_conns::drained_server");
    let mut rest = Vec::new();
    stream
        .read_to_end(&mut rest)
        .await
        .expect("the stream ends cleanly");
    ready.send(()).expect("main waits for readiness");
    let _ = park.await;
    drop(stream);
}

/// (e) The client end: a handshake whose ClientHello goes unanswered.
async fn handshaking_client(
    connector: TlsConnector,
    tcp: TcpStream,
) -> Option<client::TlsStream<TcpStream>> {
    census_expect::task("tls_conns::handshaking_client");
    // tokio-rustls's `Connect` is a newtype over its own handshake
    // future, which the census finds inside it at an address the
    // fixture cannot name.
    census_expect::held_by_task("tls_conns::handshaking_client", "MidHandshake");
    connector.connect(localhost(), tcp).await.ok()
}

/// (e) The peer: read the ClientHello's first bytes, say so, and never
/// answer.
async fn silent_peer(
    mut stream: TcpStream,
    ready: oneshot::Sender<()>,
    park: oneshot::Receiver<()>,
) {
    census_expect::task("tls_conns::silent_peer");
    let mut hello = [0u8; 5];
    stream
        .read_exact(&mut hello)
        .await
        .expect("a ClientHello's record header arrives");
    ready.send(()).expect("main waits for readiness");
    let _ = park.await;
    drop(stream);
}

/// (f) The server end: a handshake waiting for a ClientHello.
async fn handshaking_server(
    acceptor: TlsAcceptor,
    tcp: TcpStream,
    ready: oneshot::Sender<()>,
) -> Option<server::TlsStream<TcpStream>> {
    census_expect::task("tls_conns::handshaking_server");
    // `Accept` holds the same handshake future `Connect` does.
    census_expect::held_by_task("tls_conns::handshaking_server", "MidHandshake");
    ready.send(()).expect("main waits for readiness");
    acceptor.accept(tcp).await.ok()
}

/// (f) The peer: connected, and never sending a byte.
async fn mute_peer(stream: TcpStream, park: oneshot::Receiver<()>) {
    census_expect::task("tls_conns::mute_peer");
    let _ = park.await;
    drop(stream);
}

/// (g) The server end: hyper-util's version-choosing server over the
/// TLS stream, answering every request, parked reading the next.
async fn https_server(stream: server::TlsStream<TcpStream>) {
    census_expect::task("tls_conns::https_server");
    let service = service_fn(|_: Request<Incoming>| async {
        Ok::<_, Infallible>(Response::new(Full::new(Bytes::from_static(b"hello"))))
    });
    let _ = auto::Builder::new(TokioExecutor::new())
        .serve_connection_with_upgrades(TokioIo::new(stream), service)
        .await;
}

/// (g) The client end: hyper's connection over the TLS stream, driven
/// by its own task, parked between exchanges.
async fn https_client(
    conn: hyper::client::conn::http1::Connection<
        TokioIo<client::TlsStream<TcpStream>>,
        Empty<Bytes>,
    >,
) {
    census_expect::task("tls_conns::https_client");
    let _ = conn.await;
}

/// A oneshot whose sender is gone for good without ever being dropped,
/// so its receiver parks forever.
fn never() -> oneshot::Receiver<()> {
    let (tx, rx) = oneshot::channel();
    std::mem::forget(tx);
    rx
}

fn main() {
    test_programs::allow_any_tracer();

    let mut builder = test_programs::Builder::new_multi_thread();
    builder.worker_threads(2);
    test_programs::run_builder(&mut builder, async {
        let (connector, acceptor) = tls_ends();
        let (ready_tx, mut ready) = mpsc::unbounded_channel::<oneshot::Receiver<()>>();
        let signal = || {
            let (tx, rx) = oneshot::channel();
            ready_tx.send(rx).expect("main holds the receiver");
            tx
        };

        // (a)
        let (client, server) = tls_pair(&connector, &acceptor).await;
        tokio::spawn(plain_client(client, signal()));
        tokio::spawn(exact_server(server, signal()));

        // (b)
        let (client, server) = tls_pair(&connector, &acceptor).await;
        let (reader, writer) = tokio::io::split(TlsStream::from(client));
        tokio::spawn(split_client(reader, writer, signal()));
        tokio::spawn(buffered_server(Box::new(BufStream::new(server)), signal()));

        // (c)
        let (client, server) = tcp_pair().await;
        let (reader, writer) = client.into_split();
        tokio::spawn(owned_split_client(reader, writer, signal()));
        tokio::spawn(tcp_server(server, signal()));

        // (d)
        let (client, server) = tls_pair(&connector, &acceptor).await;
        tokio::spawn(closing_client(client, signal()));
        tokio::spawn(drained_server(server, signal(), never()));

        // (e)
        let (client, server) = tcp_pair().await;
        tokio::spawn(silent_peer(server, signal(), never()));
        tokio::spawn(handshaking_client(connector.clone(), client));

        // (f)
        let (client, server) = tcp_pair().await;
        tokio::spawn(mute_peer(client, never()));
        tokio::spawn(handshaking_server(acceptor.clone(), server, signal()));

        drop(ready_tx);
        while let Some(rx) = ready.recv().await {
            rx.await.expect("every parked task reports");
        }

        // (g) One GET, answered and read whole, leaves both ends
        // between exchanges; the sender is kept, so the client's
        // connection stays open.
        let (client, server) = tls_pair(&connector, &acceptor).await;
        tokio::spawn(https_server(server));
        let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(client))
            .await
            .expect("the HTTP/1 handshake completes");
        tokio::spawn(https_client(conn));
        let request = Request::get("/")
            .header("host", "localhost")
            .body(Empty::<Bytes>::new())
            .expect("a request");
        let response = sender
            .send_request(request)
            .await
            .expect("the response arrives");
        response
            .into_body()
            .collect()
            .await
            .expect("the body arrives");

        test_programs::quiesce();
        println!("READY");
        std::future::pending::<()>().await
    })
}
