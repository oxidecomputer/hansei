// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! A small tokio program for hansei to look at.
//!
//! It stands up the tasks a real service has — a listener, a producer
//! feeding a bounded channel, a dispatcher, a pool of workers under a
//! `JoinSet`, a fan-out over a `FuturesUnordered`, a heartbeat — and
//! then wedges: the dispatcher waits for the config lock the reloader
//! holds, and the reloader waits for an acknowledgement only the
//! dispatcher sends. Everything else backs up behind the two of them,
//! so nothing ever completes and the process can be cored at leisure.
//!
//! Build it as the README's "Trying it out" describes, run it, and core
//! the pid it prints.

use std::collections::BTreeMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use futures_util::stream::{FuturesUnordered, StreamExt};
use tokio::net::TcpListener;
use tokio::sync::{Mutex, Notify, OwnedMutexGuard, mpsc, oneshot, watch};
use tokio::task::JoinSet;
use tokio::time::sleep;

/// What the producer hands the dispatcher.
#[derive(Debug)]
struct Job {
    id: u32,
    name: String,
    priority: Priority,
    tags: Vec<&'static str>,
}

#[derive(Debug, Clone, Copy)]
enum Priority {
    Low,
    Normal,
    High,
}

/// The settings the dispatcher reads and the reloader replaces.
#[derive(Debug)]
struct Config {
    upstream: SocketAddr,
    max_in_flight: usize,
    retries: BTreeMap<String, u32>,
}

/// What the workers wait for the dispatcher to announce.
#[derive(Debug, Clone, Copy, PartialEq)]
enum Phase {
    Starting,
    Serving,
    Draining,
}

fn main() {
    allow_any_tracer();
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .expect("build the runtime");
    rt.block_on(run());
}

async fn run() {
    let pid = std::process::id();
    println!("hansei-example running as pid {pid}");
    println!("core it with:  gcore {pid}");

    let config = Arc::new(Mutex::new(Config {
        upstream: SocketAddr::from((Ipv4Addr::new(10, 0, 0, 7), 8080)),
        max_in_flight: 4,
        retries: BTreeMap::from([("connect".to_string(), 3), ("read".to_string(), 1)]),
    }));
    let (jobs_tx, jobs_rx) = mpsc::channel::<Job>(4);
    let (ack_tx, ack_rx) = oneshot::channel::<()>();
    let (phase_tx, phase_rx) = watch::channel(Phase::Starting);
    let ready = Arc::new(Notify::new());

    // The reloader holds the config lock from the moment it is spawned,
    // so the dispatcher can never get it first.
    let guard = config.clone().lock_owned().await;

    tokio::spawn(listener(jobs_tx.clone()));
    tokio::spawn(producer(jobs_tx));
    tokio::spawn(dispatcher(jobs_rx, config, ack_tx, phase_tx, ready.clone()));
    tokio::spawn(reloader(guard, ack_rx));
    tokio::spawn(fanout(ready));
    tokio::spawn(heartbeat());
    let supervisor = tokio::spawn(supervisor(phase_rx));

    supervisor.await.expect("the supervisor never finishes");
}

/// Accepts connections and turns each into a job. Parked in `accept`
/// on the io driver; nothing ever connects.
async fn listener(jobs: mpsc::Sender<Job>) {
    let socket = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind");
    let addr = socket.local_addr().expect("local addr");
    let mut accepted: u32 = 0;
    loop {
        let (_stream, peer) = socket.accept().await.expect("accept");
        accepted += 1;
        let job = Job {
            id: 1000 + accepted,
            name: format!("connection from {peer} to {addr}"),
            priority: Priority::High,
            tags: vec!["network"],
        };
        jobs.send(job).await.expect("the dispatcher is gone");
    }
}

/// Fills the job channel. The dispatcher takes one job and stalls, so
/// the channel fills and the producer parks in `send` on its
/// semaphore, holding the job it could not deliver.
async fn producer(jobs: mpsc::Sender<Job>) {
    let names = ["compact", "index", "backup", "prune", "verify", "report"];
    let mut sent: usize = 0;
    for (i, name) in names.iter().cycle().enumerate() {
        let job = Job {
            id: i as u32 + 1,
            name: name.to_string(),
            priority: match i % 3 {
                0 => Priority::High,
                1 => Priority::Normal,
                _ => Priority::Low,
            },
            tags: vec!["batch", if i % 2 == 0 { "even" } else { "odd" }],
        };
        jobs.send(job).await.expect("the dispatcher is gone");
        sent += 1;
    }
    println!("producer: sent {sent} jobs");
}

/// Takes jobs off the channel and runs each under the config lock. It
/// gets the first job, then parks on the lock the reloader holds — with
/// the acknowledgement the reloader is waiting for still in its hands.
async fn dispatcher(
    mut jobs: mpsc::Receiver<Job>,
    config: Arc<Mutex<Config>>,
    ack: oneshot::Sender<()>,
    phase: watch::Sender<Phase>,
    ready: Arc<Notify>,
) {
    let mut ack = Some(ack);
    let mut processed: u64 = 0;
    while let Some(job) = jobs.recv().await {
        let cfg = config.lock().await;
        if let Some(ack) = ack.take() {
            let _ = ack.send(());
            let _ = phase.send(Phase::Serving);
            ready.notify_waiters();
        }
        println!(
            "dispatcher: job {} {} ({:?}, {:?}) via {}",
            job.id, job.name, job.priority, job.tags, cfg.upstream
        );
        processed += 1;
        if processed as usize >= cfg.max_in_flight {
            let _ = phase.send(Phase::Draining);
        }
    }
}

/// Rewrites the config and waits for the dispatcher to acknowledge it
/// before letting go of the lock. The dispatcher is waiting for the
/// lock, so this is the wedge.
async fn reloader(mut config: OwnedMutexGuard<Config>, ack: oneshot::Receiver<()>) {
    let previous = config.max_in_flight;
    config.max_in_flight = 8;
    config.retries.insert("write".to_string(), 2);
    let started = Instant::now();
    ack.await.expect("the dispatcher is gone");
    println!(
        "reloader: max_in_flight {previous} -> {} acknowledged after {:?}",
        config.max_in_flight,
        started.elapsed()
    );
}

/// Drives a pool of workers through a `JoinSet`, parked in `join_next`
/// until one of them finishes; none does.
async fn supervisor(phase: watch::Receiver<Phase>) {
    let mut workers = JoinSet::new();
    for id in 0..3 {
        workers.spawn(worker(id, phase.clone()));
    }
    let mut finished: Vec<usize> = Vec::new();
    while let Some(result) = workers.join_next().await {
        finished.push(result.expect("a worker panicked"));
    }
    println!("supervisor: workers {finished:?} finished");
}

/// Waits for the dispatcher to announce a phase change; it never does.
async fn worker(id: usize, mut phase: watch::Receiver<Phase>) -> usize {
    let label = format!("worker-{id}");
    let mut served: u32 = 0;
    while phase.changed().await.is_ok() {
        match *phase.borrow() {
            Phase::Starting => {}
            Phase::Serving => served += 1,
            Phase::Draining => break,
        }
    }
    println!("{label}: served {served}");
    id
}

/// Probes every upstream at once through a `FuturesUnordered`, parked
/// in `next` while each probe waits for the dispatcher's go-ahead.
async fn fanout(ready: Arc<Notify>) {
    let upstreams: Vec<SocketAddr> = (1..=3)
        .map(|n| SocketAddr::from((Ipv4Addr::new(10, 0, 0, n), 8080)))
        .collect();
    let mut probes: FuturesUnordered<_> = upstreams
        .iter()
        .map(|target| probe(*target, ready.clone()))
        .collect();
    let mut latencies: BTreeMap<SocketAddr, Duration> = BTreeMap::new();
    while let Some((target, latency)) = probes.next().await {
        latencies.insert(target, latency);
    }
    println!("fanout: {latencies:?}");
}

async fn probe(target: SocketAddr, ready: Arc<Notify>) -> (SocketAddr, Duration) {
    ready.notified().await;
    let started = Instant::now();
    sleep(Duration::from_millis(20)).await;
    (target, started.elapsed())
}

/// Wakes every few seconds and counts: a task parked on the timer, with a
/// local that changes while the program runs.
async fn heartbeat() {
    let period = Duration::from_secs(3);
    let mut beats: u64 = 0;
    loop {
        sleep(period).await;
        beats += 1;
        if beats % 20 == 0 {
            println!("heartbeat: {beats} beats, still wedged");
        }
    }
}

/// Let any process of this uid trace this one, so `gcore <pid>` works on
/// a Linux box whose Yama `ptrace_scope` permits tracing descendants
/// only. Other systems gate tracing elsewhere and need nothing here.
#[cfg(target_os = "linux")]
fn allow_any_tracer() {
    const PR_SET_PTRACER: libc::c_int = 0x59616d61;
    const PR_SET_PTRACER_ANY: libc::c_ulong = libc::c_ulong::MAX;
    // SAFETY: prctl with one unsigned-long argument, touching none of
    // our memory. A kernel without Yama fails it with EINVAL, which is
    // as good an answer as success.
    unsafe {
        libc::prctl(PR_SET_PTRACER, PR_SET_PTRACER_ANY);
    }
}

#[cfg(not(target_os = "linux"))]
fn allow_any_tracer() {}
