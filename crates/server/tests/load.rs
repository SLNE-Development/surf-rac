//! Load tests for the registration and session request limits.
//!
//! The tests are ignored by default; run them with `--ignored --nocapture` to see
//! the accepted and refused counts and the registration latency percentiles.

mod common;

use std::time::{Duration, Instant};

use common::ws::Ws;
use common::ws::send;
use futures_util::{StreamExt, stream};
use serde_json::{Value, json};
use sqlx::PgPool;
use tokio_tungstenite::tungstenite::Message;

/// Registrations allowed per client /64 per hour (the server default).
const REGISTER_PER_HOUR: usize = 5;

/// Session requests relayed to one target per minute (the server default).
const SESSION_REQUESTS_PER_MINUTE: usize = 10;

/// Number of registrations attempted by each registration scenario.
const REGISTRATIONS: usize = 1000;

/// Number of registration requests kept in flight at once.
const CONCURRENCY: usize = 16;

/// Latency budget for the 95th percentile registration, measured locally.
const P95_BUDGET: Duration = Duration::from_millis(200);

/// Outcome of a batch of registration attempts.
struct RegistrationRun {
    /// Number of attempts answered with HTTP 200.
    accepted: usize,
    /// Number of attempts answered with HTTP 429.
    refused: usize,
    /// Number of attempts answered with any other status.
    other: usize,
    /// Round-trip time of every attempt, sorted ascending.
    latencies: Vec<Duration>,
}

impl RegistrationRun {
    /// Returns the latency at percentile `p` (0.0 to 1.0) using the nearest-rank method.
    fn percentile(&self, p: f64) -> Duration {
        let rank = ((self.latencies.len() as f64) * p).ceil() as usize;
        self.latencies[rank.clamp(1, self.latencies.len()) - 1]
    }

    /// Prints the counts and latency percentiles of this run under `label`.
    fn report(&self, label: &str) {
        println!(
            "[{label}] attempts={} accepted={} refused={} other={} p50={:?} p95={:?} p99={:?} max={:?}",
            self.latencies.len(),
            self.accepted,
            self.refused,
            self.other,
            self.percentile(0.50),
            self.percentile(0.95),
            self.percentile(0.99),
            self.latencies.last().unwrap(),
        );
    }
}

/// Registers one fresh device per entry of `ips`, with `CONCURRENCY` requests in flight, and
/// returns the status counts and sorted latencies.
async fn register_from_addresses(app: &common::TestApp, ips: Vec<String>) -> RegistrationRun {
    let results: Vec<(u16, Duration)> = stream::iter(ips.into_iter().enumerate())
        .map(|(n, ip)| async move {
            let key = common::identity_key();
            let fingerprint = common::fingerprint(n as u32 + 1);
            let started = Instant::now();
            let res = app
                .register_device_from(&key, &fingerprint, "load", &ip)
                .await;
            (res.status().as_u16(), started.elapsed())
        })
        .buffer_unordered(CONCURRENCY)
        .collect()
        .await;
    let mut run = RegistrationRun {
        accepted: 0,
        refused: 0,
        other: 0,
        latencies: Vec::with_capacity(results.len()),
    };
    for (status, elapsed) in results {
        match status {
            200 => run.accepted += 1,
            429 => run.refused += 1,
            _ => run.other += 1,
        }
        run.latencies.push(elapsed);
    }
    run.latencies.sort();
    run
}

/// Counts the frames of each kind that arrive on `ws` until it stays quiet for `quiet`.
///
/// Returns the number of `session_request` frames and the number of `rate_limited` errors.
async fn drain_counts(ws: &mut Ws, quiet: Duration) -> (usize, usize) {
    let (mut requests, mut limited) = (0, 0);
    while let Ok(Some(Ok(msg))) = tokio::time::timeout(quiet, ws.next()).await {
        if let Message::Text(text) = msg {
            let v: Value = serde_json::from_str(text.as_str()).unwrap();
            match v["type"].as_str() {
                Some("session_request") => requests += 1,
                Some("error") if v["code"] == "rate_limited" => limited += 1,
                _ => {}
            }
        }
    }
    (requests, limited)
}

/// Returns a well-formed session request to `to` with session ID `session_id`.
fn session_request(to: &str, session_id: &str) -> Value {
    json!({"type":"session_request","to":to,"session_id":session_id,
           "session_key": common_b64(32), "signature": common_b64(64), "unattended": false})
}

/// Returns standard base64 of `len` bytes, a well-formed key or signature field.
fn common_b64(len: usize) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(vec![7u8; len])
}

/// A thousand registrations spread over 200 IPv6 /64 prefixes all succeed within the p95 latency
/// budget.
#[ignore = "load test"]
#[sqlx::test(migrations = "./migrations")]
async fn register_1000_devices_from_200_distinct_64s(pool: PgPool) {
    let app = common::spawn(pool).await;
    let ips = (0..REGISTRATIONS)
        .map(|i| format!("2001:db8:{:x}::{:x}", i % 200 + 1, i / 200 + 1))
        .collect();
    let run = register_from_addresses(&app, ips).await;
    run.report("1000 devices, 200 /64s");
    assert_eq!(run.other, 0);
    assert_eq!(run.accepted, REGISTRATIONS, "5 per /64 is within the limit");
    assert_eq!(run.refused, 0);
    assert!(
        run.percentile(0.95) < P95_BUDGET,
        "p95 {:?} over budget",
        run.percentile(0.95)
    );
}

/// A thousand registrations from one IPv6 /64 accept exactly the hourly limit, refuse the rest, and
/// stay within the p95 latency budget.
#[ignore = "load test"]
#[sqlx::test(migrations = "./migrations")]
async fn register_1000_devices_from_one_64(pool: PgPool) {
    let app = common::spawn(pool).await;
    let ips = (0..REGISTRATIONS)
        .map(|i| format!("2001:db8:ffff:1::{:x}", i + 1))
        .collect();
    let run = register_from_addresses(&app, ips).await;
    run.report("1000 devices, one /64");
    assert_eq!(run.other, 0);
    assert_eq!(
        run.accepted, REGISTER_PER_HOUR,
        "exactly the hourly limit succeeds"
    );
    assert_eq!(run.refused, REGISTRATIONS - REGISTER_PER_HOUR);
    assert_eq!(app.count("devices", "true").await, REGISTER_PER_HOUR as i64);
    assert!(
        run.percentile(0.95) < P95_BUDGET,
        "p95 {:?} over budget",
        run.percentile(0.95)
    );
}

/// A flood of a thousand session requests from fifty senders relays at most the per-minute limit to
/// the target and refuses the rest.
#[ignore = "load test"]
#[sqlx::test(migrations = "./migrations")]
async fn session_request_flood_relays_at_most_the_per_minute_limit(pool: PgPool) {
    /// Number of devices that send session requests to the target.
    const SENDERS: usize = 50;
    let app = common::spawn(pool).await;
    let mut target = app.online_device(1).await;
    let mut senders = Vec::with_capacity(SENDERS);
    for n in 0..SENDERS {
        senders.push(app.online_device(n as u32 + 2).await);
    }
    let per_sender = 1000 / SENDERS;
    let started = Instant::now();
    for (i, sender) in senders.iter_mut().enumerate() {
        for j in 0..per_sender {
            send(
                &mut sender.ws,
                session_request(&target.id, &format!("s{i}-{j}")),
            )
            .await;
        }
    }
    let (relayed, _) = drain_counts(&mut target.ws, Duration::from_secs(1)).await;
    let elapsed = started.elapsed();
    let mut refused = 0;
    for sender in senders.iter_mut() {
        refused += drain_counts(&mut sender.ws, Duration::from_millis(200))
            .await
            .1;
    }
    println!(
        "[flood 1000 requests, 50 senders] sent={} relayed={relayed} refused={refused} window={elapsed:?}",
        SENDERS * per_sender,
    );
    assert!(
        elapsed < Duration::from_secs(60),
        "flood must fit one minute"
    );
    assert!(
        relayed <= SESSION_REQUESTS_PER_MINUTE,
        "relayed {relayed} over the per-minute limit"
    );
    assert_eq!(relayed + refused, SENDERS * per_sender);
}
