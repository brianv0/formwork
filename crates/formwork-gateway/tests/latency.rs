//! The Gateway's time budgets, measured on loopback fixtures in release builds.
//!
//! - FW-E2E-096 (both): the latency budget (FEP-6 §9 f, `formwork.md` §8). What the Gateway adds
//!   to a request over the same client connecting directly: tunnel grade, a new connection, to the
//!   first response byte, under 2 ms; inspected grade, a reused connection, per request, under
//!   1 ms; inspected grade, the first connection to a host (its leaf minted), under 5 ms.
//! - FW-E2E-093 (both): streaming. Server-sent events through an inspected host with a brokered
//!   credential, so through the reflection guard, reach the client within 20 ms of the fixture
//!   writing them -- decided on the 99th percentile of the events' delays.
//!
//! A wall-clock bound on a shared runner is a flaky test unless the measurement is built for it
//! (constitution *Testing*), so these decide two ways:
//!
//! - **On a confidence interval, not a number.** FW-E2E-096's samples are pairs -- the request
//!   direct and through the Gateway, in alternating order -- and its statistic is the median of the
//!   pairs' differences; FW-E2E-093's is the 99th percentile of the events' delays. Each comes with
//!   a distribution-free 95% interval from its order statistics. A row passes when the whole
//!   interval is under the budget and fails when the whole interval is over it; an interval that
//!   straddles the budget takes 1,000 more samples, up to 4,000, and is then a failure: a
//!   statistic that close to its budget is a finding, not noise.
//! - **Against this node, within a cap.** Between batches the test times a fixed TLS workload --
//!   in-memory handshakes and records on the provider the Gateway uses -- and divides by the same
//!   workload's time on the reference node, a GitHub-hosted `ubuntu-24.04` runner. The budget is
//!   the target times that factor, clamped to [1, 3]: a node faster than the reference gets the
//!   targets as written, and no node gets more than three times them.
//!
//! They measure release builds only, one at a time, in their own CI step:
//! `cargo test --release -p formwork-gateway --test latency -- --ignored --nocapture
//! --test-threads=1`.

mod support;

use std::future::Future;
use std::io::{Read, Write};
use std::sync::Arc;
use std::time::{Duration, Instant};

use formwork_blueprint::{BrokerScheme, CanonicalHost};
use formwork_gateway::{Broker, EgressProxy, SessionCa};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use support::*;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// The calibration workload's median round on the reference node (GitHub-hosted `ubuntu-24.04`:
/// 8.18-8.25 ms across the three rows when this was set), re-measured whenever the workload
/// changes.
const REFERENCE_ROUND: Duration = Duration::from_micros(8_200);
/// The most the budget stretches on a slow node.
const FACTOR_CAP: f64 = 3.0;
const CALIBRATION_HANDSHAKES: usize = 20;
const CALIBRATION_RECORDS: usize = 20;

const WARMUP: usize = 50;
const BATCH: usize = 250;
const DECIDE_EVERY: usize = 1_000;
const MAX_PAIRS: usize = 4_000;
/// Hosts per Gateway session in the first-connection row: each is minted once per session.
const HOSTS_PER_SESSION: usize = 20;
/// FW-E2E-093: events per stream, and the fixture's gap between them.
const EVENTS_PER_STREAM: usize = 250;
const EVENT_GAP_MS: u64 = 20;
const EVENT_BUDGET_US: f64 = 20_000.0;
const PLACEHOLDER: &str = "fwcred-anthropic-perf";
const SECRET: &str = "sk-ant-PERF-SECRET-0001";

fn release_only(test: &str) {
    if cfg!(debug_assertions) {
        panic!(
            "{test} measures release builds: cargo test --release -p formwork-gateway \
             --test latency -- --ignored --nocapture --test-threads=1"
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "FW-E2E-096 measures time: run it in release, in its own CI step"]
async fn fw_e2e_096_latency_budget() {
    release_only("FW-E2E-096");
    let first_hosts: Vec<String> = (0..HOSTS_PER_SESSION)
        .map(|i| format!("h{i}.first.test"))
        .collect();
    let mut names = vec!["tunnel.test".to_string(), "api.test".to_string()];
    names.extend(first_hosts.iter().cloned());
    let name_refs: Vec<&str> = names.iter().map(String::as_str).collect();
    let tls = fixture_tls(&name_refs);
    let up = upstream(Some(tls.clone())).await;
    let fixture_client = latency_client(std::slice::from_ref(&tls.root));
    let mut calibration = Calibration::new();

    let mut report = Vec::new();

    // Tunnel grade: a new connection each time, to the first response byte.
    let (tunnel_proxy, _) = Session::new(
        &[format!("tunnel:tunnel.test:{}", up.port)],
        resolver(&[("tunnel.test", "127.0.0.1")]),
    )
    .start();
    let mut tunnel = TunnelNew {
        proxy: tunnel_proxy,
        port: up.port,
        client: fixture_client.clone(),
    };
    report.push(
        measure(
            "tunnel, new connection, to first byte",
            2_000.0,
            &mut tunnel,
            &mut calibration,
        )
        .await,
    );
    drop(tunnel);

    // Inspected grade: one client connection each way, reused for every request.
    let mut session = Session::new(
        &[format!("allow:api.test:{}", up.port)],
        resolver(&[("api.test", "127.0.0.1")]),
    );
    session.upstream_roots = Some(vec![tls.root.clone()]);
    let (proxy, ca) = session.start();
    let ca = ca.unwrap();
    let target = format!("api.test:{}", up.port);
    let through = connect_through(&proxy, &target).await;
    let through = handshake(through, &latency_client(&[ca.cert_der()]), "api.test").await;
    let direct = handshake(tcp(up.port).await, &fixture_client, "api.test").await;
    let mut reused = InspectedReused {
        _proxy: proxy,
        request: format!("GET /lat HTTP/1.1\r\nHost: {target}\r\n\r\n"),
        through,
        direct,
    };
    report.push(
        measure(
            "inspected, reused connection, per request",
            1_000.0,
            &mut reused,
            &mut calibration,
        )
        .await,
    );
    drop(reused);

    // Inspected grade: the first connection to a host, its leaf minted on the way.
    let mut first = InspectedFirst {
        hosts: first_hosts,
        port: up.port,
        upstream_root: tls.root.clone(),
        client: fixture_client,
        session: None,
        next: 0,
    };
    report.push(
        measure(
            "inspected, first connection to a host",
            5_000.0,
            &mut first,
            &mut calibration,
        )
        .await,
    );

    let lines: Vec<String> = report.iter().map(|r| r.line.clone()).collect();
    eprintln!(
        "FW-E2E-096 latency budget (reference round {}, factor cap {FACTOR_CAP:.0}):\n  {}",
        ms(REFERENCE_ROUND.as_secs_f64() * 1e6),
        lines.join("\n  ")
    );
    assert!(
        report.iter().all(|r| r.passed),
        "a row is over its budget:\n  {}",
        lines.join("\n  ")
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "FW-E2E-093 measures time: run it in release, in its own CI step"]
async fn fw_e2e_093_streamed_events_arrive_within_20_ms() {
    release_only("FW-E2E-093");
    let tls = fixture_tls(&["api.test"]);
    let up = upstream(Some(tls.clone())).await;
    let mut session = Session::new(
        &[format!("allow:api.test:{}", up.port)],
        resolver(&[("api.test", "127.0.0.1")]),
    );
    session.upstream_roots = Some(vec![tls.root.clone()]);
    // A brokered credential on the host, so every response runs through the reflection guard.
    session.brokers = vec![Broker {
        name: "anthropic".into(),
        placeholder: PLACEHOLDER.into(),
        secret: SECRET.into(),
        bindings: vec![(
            CanonicalHost::Name("api.test".into()),
            BrokerScheme::Header("x-api-key".into()),
        )],
    }];
    let (proxy, ca) = session.start();
    let client = latency_client(&[ca.unwrap().cert_der()]);
    let mut calibration = Calibration::new();
    let stream = |n: usize| stream_events(&proxy, &client, &up, n);

    stream(20).await;
    let (mut delays, mut rounds) = (Vec::new(), Vec::new());
    let line = loop {
        rounds.push(calibration.round());
        rounds.push(calibration.round());
        delays.extend(stream(EVENTS_PER_STREAM).await);
        if delays.len() % DECIDE_EVERY != 0 {
            continue;
        }
        let reference_us = REFERENCE_ROUND.as_secs_f64() * 1e6;
        let round = median(&mut rounds);
        let factor = (round / reference_us).clamp(1.0, FACTOR_CAP);
        let budget = EVENT_BUDGET_US * factor;
        let (lo, p99, hi) = quantile_interval(&mut delays, 0.99);
        let verdict = if hi < budget {
            Some("pass")
        } else if lo > budget {
            Some("over budget")
        } else if delays.len() >= MAX_PAIRS {
            Some("too close to call")
        } else {
            None
        };
        if let Some(verdict) = verdict {
            let max = delays.iter().cloned().fold(0.0, f64::max);
            break (
                format!(
                    "{:44} n={:<5} median {}  p99 {} [95% {} .. {}]  max {}  \
                     budget {} x {factor:.2} (round {}) = {}  {verdict}",
                    "streamed events through the guard",
                    delays.len(),
                    ms(quantile_interval(&mut delays, 0.5).1),
                    ms(p99),
                    ms(lo),
                    ms(hi),
                    ms(max),
                    ms(EVENT_BUDGET_US),
                    ms(round),
                    ms(budget),
                ),
                verdict == "pass",
            );
        }
    };
    eprintln!("FW-E2E-093 streaming budget:\n  {}", line.0);
    assert!(line.1, "{}", line.0);
}

/// One stream of `n` events through the Gateway: each event's delay, in microseconds, from the
/// fixture's write to the client's read.
async fn stream_events(
    proxy: &EgressProxy,
    client: &Arc<rustls::ClientConfig>,
    up: &Upstream,
    n: usize,
) -> Vec<f64> {
    up.events.lock().unwrap().clear();
    let target = format!("api.test:{}", up.port);
    let mut s = handshake(connect_through(proxy, &target).await, client, "api.test").await;
    s.write_all(
        format!(
            "GET /events?n={n}&gap_ms={EVENT_GAP_MS} HTTP/1.1\r\nHost: {target}\r\n\
             x-api-key: {PLACEHOLDER}\r\n\r\n"
        )
        .as_bytes(),
    )
    .await
    .unwrap();
    s.flush().await.unwrap();
    let mut raw = Vec::new();
    let mut chunk = [0u8; 16 * 1024];
    let mut body = Dechunk::default();
    let mut head_done = false;
    let mut arrivals = Vec::new();
    while !body.done {
        let read = s.read(&mut chunk).await.unwrap();
        assert!(read > 0, "the stream ended after {} events", arrivals.len());
        let at = Instant::now();
        if head_done {
            body.feed(&chunk[..read]);
        } else {
            raw.extend_from_slice(&chunk[..read]);
            if let Some(end) = raw.windows(4).position(|w| w == b"\r\n\r\n") {
                assert!(
                    raw.starts_with(b"HTTP/1.1 200"),
                    "{}",
                    String::from_utf8_lossy(&raw)
                );
                head_done = true;
                body.feed(&raw[end + 4..]);
            }
        }
        // Every event ends with a blank line; each one completed by this read arrived now.
        let complete = body.body.windows(2).filter(|w| w == b"\n\n").count();
        arrivals.resize(complete, at);
    }
    let written = up.events.lock().unwrap().clone();
    assert_eq!(arrivals.len(), n, "events read");
    assert_eq!(written.len(), n, "events written");
    written
        .iter()
        .zip(&arrivals)
        .map(|(w, a)| a.duration_since(*w).as_secs_f64() * 1e6)
        .collect()
}

/// A chunked body, reassembled however its chunks arrive.
#[derive(Default)]
struct Dechunk {
    raw: Vec<u8>,
    body: Vec<u8>,
    done: bool,
}

impl Dechunk {
    fn feed(&mut self, bytes: &[u8]) {
        self.raw.extend_from_slice(bytes);
        while let Some(line_end) = self.raw.windows(2).position(|w| w == b"\r\n") {
            let line = String::from_utf8_lossy(&self.raw[..line_end]).into_owned();
            let size = usize::from_str_radix(line.split(';').next().unwrap_or("").trim(), 16)
                .expect("a chunk size");
            if size == 0 {
                self.done = true;
                return;
            }
            if self.raw.len() < line_end + 2 + size + 2 {
                return;
            }
            self.body
                .extend_from_slice(&self.raw[line_end + 2..line_end + 2 + size]);
            self.raw.drain(..line_end + 2 + size + 2);
        }
    }
}

/// One row's measurements: one pair of timings per call, direct and through the Gateway.
trait Pair {
    fn sample(&mut self, direct_first: bool) -> impl Future<Output = (Duration, Duration)>;
}

struct Row {
    line: String,
    passed: bool,
}

async fn measure<P: Pair>(name: &str, target_us: f64, pair: &mut P, cal: &mut Calibration) -> Row {
    for i in 0..WARMUP {
        pair.sample(i % 2 == 0).await;
    }
    let mut rounds = Vec::new();
    let (mut direct, mut through, mut added) = (Vec::new(), Vec::new(), Vec::new());
    loop {
        rounds.push(cal.round());
        rounds.push(cal.round());
        for i in 0..BATCH {
            let (d, t) = pair.sample(i % 2 == 0).await;
            let (d, t) = (d.as_secs_f64() * 1e6, t.as_secs_f64() * 1e6);
            direct.push(d);
            through.push(t);
            added.push(t - d);
        }
        if added.len() % DECIDE_EVERY != 0 {
            continue;
        }
        let reference_us = REFERENCE_ROUND.as_secs_f64() * 1e6;
        let round = median(&mut rounds);
        let factor = (round / reference_us).clamp(1.0, FACTOR_CAP);
        let budget = target_us * factor;
        let (lo, mid, hi) = quantile_interval(&mut added, 0.5);
        let verdict = if hi < budget {
            Some("pass")
        } else if lo > budget {
            Some("over budget")
        } else if added.len() >= MAX_PAIRS {
            Some("too close to call")
        } else {
            None
        };
        if let Some(verdict) = verdict {
            return Row {
                line: format!(
                    "{name:44} n={:<5} direct {}  gateway {}  added {} [95% {} .. {}]  \
                     budget {} x {factor:.2} (round {}) = {}  {verdict}",
                    added.len(),
                    ms(median(&mut direct)),
                    ms(median(&mut through)),
                    ms(mid),
                    ms(lo),
                    ms(hi),
                    ms(target_us),
                    ms(round),
                    ms(budget),
                ),
                passed: verdict == "pass",
            };
        }
    }
}

/// The tunnel grade: a new connection to the first response byte, direct and through the Gateway.
struct TunnelNew {
    proxy: EgressProxy,
    port: u16,
    client: Arc<rustls::ClientConfig>,
}

impl Pair for TunnelNew {
    async fn sample(&mut self, direct_first: bool) -> (Duration, Duration) {
        let host = format!("tunnel.test:{}", self.port);
        let direct = async {
            let t = Instant::now();
            let mut s = handshake(tcp(self.port).await, &self.client, "tunnel.test").await;
            first_byte(&mut s, &host).await;
            t.elapsed()
        };
        let through = async {
            let t = Instant::now();
            let s = connect_through(&self.proxy, &host).await;
            let mut s = handshake(s, &self.client, "tunnel.test").await;
            first_byte(&mut s, &host).await;
            t.elapsed()
        };
        in_order(direct_first, direct, through).await
    }
}

/// The inspected grade on reused connections: one request and its whole response.
struct InspectedReused {
    _proxy: EgressProxy,
    request: String,
    through: Tls,
    direct: Tls,
}

impl Pair for InspectedReused {
    async fn sample(&mut self, direct_first: bool) -> (Duration, Duration) {
        let request = self.request.as_str();
        let (direct, through) = (&mut self.direct, &mut self.through);
        let direct = async {
            let t = Instant::now();
            assert!(request_ok(direct, request).await);
            t.elapsed()
        };
        let through = async {
            let t = Instant::now();
            assert!(request_ok(through, request).await);
            t.elapsed()
        };
        in_order(direct_first, direct, through).await
    }
}

/// The inspected grade's first connection to a host: a session serves each of its hosts once, so
/// every sample through the Gateway mints a leaf and opens its upstream connection.
struct InspectedFirst {
    hosts: Vec<String>,
    port: u16,
    upstream_root: CertificateDer<'static>,
    client: Arc<rustls::ClientConfig>,
    session: Option<(EgressProxy, Arc<rustls::ClientConfig>)>,
    next: usize,
}

impl Pair for InspectedFirst {
    async fn sample(&mut self, direct_first: bool) -> (Duration, Duration) {
        if self.session.is_none() || self.next == self.hosts.len() {
            // A new session, outside the timed region; the old one shuts down first.
            self.session = None;
            let rules: Vec<String> = self
                .hosts
                .iter()
                .map(|h| format!("allow:{h}:{}", self.port))
                .collect();
            let entries: Vec<(&str, &str)> = self
                .hosts
                .iter()
                .map(|h| (h.as_str(), "127.0.0.1"))
                .collect();
            let mut session = Session::new(&rules, resolver(&entries));
            session.upstream_roots = Some(vec![self.upstream_root.clone()]);
            let (proxy, ca) = session.start();
            let ca: Arc<SessionCa> = ca.unwrap();
            self.session = Some((proxy, latency_client(&[ca.cert_der()])));
            self.next = 0;
        }
        let name = self.hosts[self.next].clone();
        self.next += 1;
        let host = format!("{name}:{}", self.port);
        let (proxy, session_client) = self.session.as_ref().unwrap();
        let direct = async {
            let t = Instant::now();
            let mut s = handshake(tcp(self.port).await, &self.client, &name).await;
            first_byte(&mut s, &host).await;
            t.elapsed()
        };
        let through = async {
            let t = Instant::now();
            let s = connect_through(proxy, &host).await;
            let mut s = handshake(s, session_client, &name).await;
            first_byte(&mut s, &host).await;
            t.elapsed()
        };
        in_order(direct_first, direct, through).await
    }
}

/// Run the two arms one after the other, in the order given; returns (direct, through).
async fn in_order(
    direct_first: bool,
    direct: impl Future<Output = Duration>,
    through: impl Future<Output = Duration>,
) -> (Duration, Duration) {
    if direct_first {
        let d = direct.await;
        (d, through.await)
    } else {
        let t = through.await;
        (direct.await, t)
    }
}

/// A client as a fresh process is one: no session resumption, so every handshake is a full one.
fn latency_client(roots: &[CertificateDer<'static>]) -> Arc<rustls::ClientConfig> {
    let mut store = rustls::RootCertStore::empty();
    for r in roots {
        store.add(r.clone()).unwrap();
    }
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut config = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(store)
        .with_no_client_auth();
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    config.resumption = rustls::client::Resumption::disabled();
    Arc::new(config)
}

/// A loopback connection with Nagle off; closed with a reset, so thousands of samples leave no
/// client ports in TIME_WAIT.
async fn tcp(port: u16) -> TcpStream {
    let s = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    s.set_nodelay(true).unwrap();
    // Deprecated for a nonzero linger, which blocks on drop; a zero one resets at once.
    #[allow(deprecated)]
    s.set_linger(Some(Duration::ZERO)).unwrap();
    s
}

async fn connect_through(proxy: &EgressProxy, target: &str) -> TcpStream {
    let mut s = tcp(proxy.addr().port()).await;
    s.write_all(
        format!(
            "CONNECT {target} HTTP/1.1\r\nHost: {target}\r\nProxy-Authorization: {}\r\n\r\n",
            proxy_auth()
        )
        .as_bytes(),
    )
    .await
    .unwrap();
    let mut got = Vec::new();
    let mut chunk = [0u8; 512];
    while !got.windows(4).any(|w| w == b"\r\n\r\n") {
        let n = s.read(&mut chunk).await.unwrap();
        assert!(n > 0, "the Gateway closed the CONNECT");
        got.extend_from_slice(&chunk[..n]);
    }
    assert!(
        got.starts_with(b"HTTP/1.1 200"),
        "{}",
        String::from_utf8_lossy(&got)
    );
    s
}

async fn handshake(tcp: TcpStream, client: &Arc<rustls::ClientConfig>, sni: &str) -> Tls {
    tokio_rustls::TlsConnector::from(client.clone())
        .connect(ServerName::try_from(sni.to_string()).unwrap(), tcp)
        .await
        .unwrap()
}

async fn first_byte(s: &mut Tls, host: &str) {
    s.write_all(format!("GET /lat HTTP/1.1\r\nHost: {host}\r\n\r\n").as_bytes())
        .await
        .unwrap();
    s.flush().await.unwrap();
    let mut b = [0u8; 1];
    assert_eq!(s.read(&mut b).await.unwrap(), 1, "no response");
}

async fn request_ok(s: &mut Tls, raw: &str) -> bool {
    request(s, raw).await.starts_with("HTTP/1.1 200")
}

/// The calibration workload: TLS handshakes and records in memory, on the provider and key type
/// the Gateway uses (ring, ECDSA P-256) -- the work that dominates what it adds to a request.
struct Calibration {
    server: Arc<rustls::ServerConfig>,
    client: Arc<rustls::ClientConfig>,
}

impl Calibration {
    fn new() -> Calibration {
        let key = rcgen::KeyPair::generate().unwrap();
        let cert = rcgen::CertificateParams::new(vec!["calibration.test".to_string()])
            .unwrap()
            .self_signed(&key)
            .unwrap();
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let server = rustls::ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(
                vec![cert.der().clone()],
                PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der())),
            )
            .unwrap();
        Calibration {
            server: Arc::new(server),
            client: latency_client(&[cert.der().clone()]),
        }
    }

    /// One round, timed.
    fn round(&mut self) -> f64 {
        let started = Instant::now();
        for _ in 0..CALIBRATION_HANDSHAKES {
            let mut c = rustls::ClientConnection::new(
                self.client.clone(),
                ServerName::try_from("calibration.test").unwrap(),
            )
            .unwrap();
            let mut s = rustls::ServerConnection::new(self.server.clone()).unwrap();
            pump(&mut c, &mut s);
            let mut buf = [0u8; 512];
            for _ in 0..CALIBRATION_RECORDS {
                c.writer().write_all(&[7u8; 512]).unwrap();
                pump(&mut c, &mut s);
                s.reader().read_exact(&mut buf).unwrap();
                s.writer().write_all(&buf).unwrap();
                pump(&mut c, &mut s);
                c.reader().read_exact(&mut buf).unwrap();
            }
        }
        started.elapsed().as_secs_f64() * 1e6
    }
}

/// Move TLS bytes both ways until neither side has anything to send.
fn pump(c: &mut rustls::ClientConnection, s: &mut rustls::ServerConnection) {
    loop {
        let mut moved = false;
        while c.wants_write() {
            let mut wire = Vec::new();
            c.write_tls(&mut wire).unwrap();
            let mut rd = wire.as_slice();
            while !rd.is_empty() {
                s.read_tls(&mut rd).unwrap();
                s.process_new_packets().unwrap();
            }
            moved = true;
        }
        while s.wants_write() {
            let mut wire = Vec::new();
            s.write_tls(&mut wire).unwrap();
            let mut rd = wire.as_slice();
            while !rd.is_empty() {
                c.read_tls(&mut rd).unwrap();
                c.process_new_packets().unwrap();
            }
            moved = true;
        }
        if !moved {
            return;
        }
    }
}

fn median(xs: &mut [f64]) -> f64 {
    xs.sort_by(|a, b| a.total_cmp(b));
    xs[xs.len() / 2]
}

/// The `q` quantile and a distribution-free 95% interval for it: the order statistics
/// nq -/+ 1.96 sqrt(nq(1-q)) (the normal approximation to the binomial count of samples below the
/// quantile).
fn quantile_interval(xs: &mut [f64], q: f64) -> (f64, f64, f64) {
    xs.sort_by(|a, b| a.total_cmp(b));
    let n = xs.len() as f64;
    let last = xs.len() - 1;
    let half = 1.96 * (n * q * (1.0 - q)).sqrt();
    let lo = ((n * q - half).floor().max(0.0) as usize).min(last);
    let hi = ((n * q + half).ceil() as usize).min(last);
    (xs[lo], xs[((n * q) as usize).min(last)], xs[hi])
}

/// Microseconds, printed as milliseconds.
fn ms(us: f64) -> String {
    format!("{:.3} ms", us / 1_000.0)
}

#[test]
fn quantile_intervals_bracket_their_quantile() {
    let mut xs: Vec<f64> = (0..1_000).map(f64::from).collect();
    assert_eq!(quantile_interval(&mut xs, 0.5), (469.0, 500.0, 531.0));
    assert_eq!(quantile_interval(&mut xs, 0.99), (983.0, 990.0, 997.0));
}

#[test]
fn the_dechunker_reassembles_split_chunks() {
    let mut d = Dechunk::default();
    for piece in [
        &b"9\r\ndata"[..],
        b": 0\n\n\r",
        b"\n9\r\ndata: 1\n\n\r\n0\r\n\r\n",
    ] {
        d.feed(piece);
    }
    assert_eq!(d.body, b"data: 0\n\ndata: 1\n\n");
    assert!(d.done);
}
