//! Fault matrix for the egress engine (FEP-6 §4.4, §4.9): the real Gateway listener between a real
//! client and a scripted upstream that misbehaves at a chosen point -- at connect, in the TLS
//! handshake, in the response head or body, on a pooled connection, inside a tunnel -- and a client
//! that misbehaves the same ways. Every scenario holds the session to the same properties: no
//! panic, the listener still serves (FW-XR11), the client gets a refusal or a truncated stream and
//! never a fabricated success, a non-idempotent request is never sent twice, and an upstream
//! connection the exchange no longer needs is released. Each fault is named and deterministic, so a
//! failure reproduces from the test's name.
//!
//! Linux only: the error a reset surfaces as (reset, broken pipe, end of stream) differs by
//! platform, and the engine under test is the same on both.

#![cfg(target_os = "linux")]

mod support;

use std::collections::VecDeque;
use std::sync::atomic::{AtomicIsize, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, Once};
use std::time::Duration;

use formwork_gateway::{EgressProxy, SessionCa};
use support::*;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// How long a scenario waits for any one step; nothing in the matrix legitimately takes longer.
const STEP: Duration = Duration::from_secs(5);

static PANICS: AtomicUsize = AtomicUsize::new(0);

/// Count every panic outside the test files, including one inside a Gateway task, which tokio
/// would otherwise swallow with the connection; a failing assertion here is not counted.
fn count_panics() {
    static HOOK: Once = Once::new();
    HOOK.call_once(|| {
        let previous = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |info| {
            if !info
                .location()
                .is_some_and(|l| l.file().contains("/tests/"))
            {
                PANICS.fetch_add(1, Ordering::SeqCst);
            }
            previous(info);
        }));
    });
}

/// What the upstream does with one accepted connection.
#[derive(Clone, Copy, Debug)]
enum Fault {
    /// Answer every request `200 ok:<path>`, keep-alive.
    Serve,
    /// Reset the connection as soon as it is accepted.
    ResetOnAccept,
    /// Read the ClientHello, then close without answering it.
    CloseInHandshake,
    /// Read the request, send half a response head, reset.
    ResetMidHead,
    /// Read the request, send half a response head, close cleanly.
    EndMidHead,
    /// Read the request, answer with bytes that are not HTTP.
    Garbage,
    /// Read the request, answer with a head larger than any head the Gateway reads.
    HugeHead,
    /// Read the request, promise 100 bytes, send 10, close cleanly.
    ShortBody,
    /// Read the request, send one chunk, reset.
    ResetMidChunked,
    /// Read the request, send one chunk, close cleanly.
    EndMidChunked,
    /// Read the request, send a chunk whose size is not hexadecimal.
    BadChunk,
    /// Read the request and never answer; the connection is released when the Gateway drops it.
    StallBeforeHead,
    /// Read the request, send the head and 10 of 100 bytes, then wait for the Gateway to drop it.
    StallMidBody,
    /// Serve one request, then reset the idle connection.
    ServeOnceThenReset,
}

/// A TLS upstream whose connections take their behaviour from a script, in accept order; once the
/// script is spent, every connection is served.
#[derive(Clone)]
struct Upstream {
    port: u16,
    script: Arc<Mutex<VecDeque<Fault>>>,
    /// Connections accepted and not yet closed by either side.
    open: Arc<AtomicIsize>,
    /// The method and path of every request read in full.
    seen: Arc<Mutex<Vec<String>>>,
}

impl Upstream {
    async fn start(tls: &FixtureTls, script: &[Fault]) -> Upstream {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let up = Upstream {
            port: listener.local_addr().unwrap().port(),
            script: Arc::new(Mutex::new(script.iter().copied().collect())),
            open: Arc::new(AtomicIsize::new(0)),
            seen: Arc::new(Mutex::new(Vec::new())),
        };
        let acceptor = tokio_rustls::TlsAcceptor::from(tls.config.clone());
        let fixture = up.clone();
        tokio::spawn(async move {
            while let Ok((tcp, _)) = listener.accept().await {
                let fault = fixture
                    .script
                    .lock()
                    .unwrap()
                    .pop_front()
                    .unwrap_or(Fault::Serve);
                let fixture = fixture.clone();
                let acceptor = acceptor.clone();
                fixture.open.fetch_add(1, Ordering::SeqCst);
                tokio::spawn(async move {
                    fixture.connection(tcp, acceptor, fault).await;
                    fixture.open.fetch_sub(1, Ordering::SeqCst);
                });
            }
        });
        up
    }

    async fn connection(&self, tcp: TcpStream, acceptor: tokio_rustls::TlsAcceptor, fault: Fault) {
        match fault {
            Fault::ResetOnAccept => {
                let _ = tcp.set_zero_linger();
                return;
            }
            Fault::CloseInHandshake => {
                let mut tcp = tcp;
                let mut hello = [0u8; 512];
                let _ = tcp.read(&mut hello).await;
                return;
            }
            _ => {}
        }
        let Ok(mut tls) = acceptor.accept(tcp).await else {
            return;
        };
        let reset = |tls: &tokio_rustls::server::TlsStream<TcpStream>| {
            let _ = tls.get_ref().0.set_zero_linger();
        };
        let mut buf = Vec::new();
        let mut served = 0usize;
        loop {
            let Some(path) = self.read_request(&mut tls, &mut buf).await else {
                return;
            };
            let reply: Vec<u8> = match fault {
                Fault::Serve | Fault::ServeOnceThenReset => {
                    let body = format!("ok:{path}");
                    format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{body}",
                        body.len()
                    )
                    .into_bytes()
                }
                Fault::ResetMidHead | Fault::EndMidHead => {
                    b"HTTP/1.1 200 OK\r\nContent-Le".to_vec()
                }
                Fault::Garbage => b"SSH-2.0-OpenSSH_9.6\r\n\r\n".to_vec(),
                Fault::HugeHead => format!(
                    "HTTP/1.1 200 OK\r\nX-Pad: {}\r\n\r\n",
                    "a".repeat(80 * 1024)
                )
                .into_bytes(),
                Fault::ShortBody | Fault::StallMidBody => {
                    b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\n0123456789".to_vec()
                }
                Fault::ResetMidChunked | Fault::EndMidChunked => {
                    b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n".to_vec()
                }
                Fault::BadChunk => {
                    b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nzz\r\nhello\r\n".to_vec()
                }
                Fault::StallBeforeHead => Vec::new(),
                Fault::ResetOnAccept | Fault::CloseInHandshake => unreachable!(),
            };
            if tls.write_all(&reply).await.is_err() || tls.flush().await.is_err() {
                return;
            }
            served += 1;
            match fault {
                Fault::Serve => continue,
                Fault::ServeOnceThenReset if served == 1 => {
                    // Let the Gateway pool the connection, then end it under it.
                    tokio::time::sleep(Duration::from_millis(200)).await;
                    reset(&tls);
                    return;
                }
                Fault::ResetMidHead | Fault::ResetMidChunked => {
                    reset(&tls);
                    return;
                }
                Fault::StallBeforeHead | Fault::StallMidBody => {
                    // Held open until the Gateway lets go of it.
                    let mut rest = [0u8; 1024];
                    while matches!(tls.read(&mut rest).await, Ok(n) if n > 0) {}
                    return;
                }
                _ => {
                    let _ = tls.shutdown().await;
                    return;
                }
            }
        }
    }

    /// Read one request head (and its `Content-Length` body); `None` when the connection ends
    /// first. A request is recorded only once read in full.
    async fn read_request<S: AsyncRead + Unpin>(
        &self,
        s: &mut S,
        buf: &mut Vec<u8>,
    ) -> Option<String> {
        let end = loop {
            if let Some(end) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                break end;
            }
            let mut chunk = [0u8; 16 * 1024];
            match s.read(&mut chunk).await {
                Ok(0) | Err(_) => return None,
                Ok(n) => buf.extend_from_slice(&chunk[..n]),
            }
        };
        let head = String::from_utf8_lossy(&buf[..end]).into_owned();
        buf.drain(..end + 4);
        let length = head
            .lines()
            .skip(1)
            .find_map(|l| {
                let (n, v) = l.split_once(':')?;
                n.eq_ignore_ascii_case("content-length")
                    .then(|| v.trim().parse::<usize>().ok())?
            })
            .unwrap_or(0);
        while buf.len() < length {
            let mut chunk = [0u8; 16 * 1024];
            match s.read(&mut chunk).await {
                Ok(0) | Err(_) => return None,
                Ok(n) => buf.extend_from_slice(&chunk[..n]),
            }
        }
        buf.drain(..length);
        let mut line = head.lines().next().unwrap_or("").split(' ');
        let request = format!("{} {}", line.next()?, line.next()?);
        self.seen.lock().unwrap().push(request.clone());
        Some(request.split(' ').nth(1)?.to_string())
    }

    fn seen(&self) -> Vec<String> {
        self.seen.lock().unwrap().clone()
    }

    /// Whether at least `least` connections are open within `STEP`.
    async fn open_at_least(&self, least: isize) -> bool {
        let deadline = tokio::time::Instant::now() + STEP;
        while tokio::time::Instant::now() < deadline {
            if self.open.load(Ordering::SeqCst) >= least {
                return true;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        false
    }

    /// Whether the open connections fall to at most `most` within `STEP`.
    async fn open_at_most(&self, most: isize) -> bool {
        let deadline = tokio::time::Instant::now() + STEP;
        while tokio::time::Instant::now() < deadline {
            if self.open.load(Ordering::SeqCst) <= most {
                return true;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        false
    }
}

/// A session that inspects `api.test` on the upstream's port, the upstream scripted with `script`.
struct Rig {
    up: Upstream,
    proxy: EgressProxy,
    /// The session CA, for a rule the Gateway inspects.
    ca: Option<Arc<SessionCa>>,
    /// The root the fixture upstream's certificate chains to, for a tunnel client.
    root: rustls::pki_types::CertificateDer<'static>,
}

impl Rig {
    async fn new(script: &[Fault], rule: &str) -> Rig {
        count_panics();
        let tls = fixture_tls(&["api.test"]);
        let up = Upstream::start(&tls, script).await;
        let mut session = Session::new(
            &[format!("{rule}:api.test:{}", up.port)],
            resolver(&[("api.test", "127.0.0.1")]),
        );
        if rule != "tunnel" {
            session.upstream_roots = Some(vec![tls.root.clone()]);
        }
        let (proxy, ca) = session.start();
        Rig {
            up,
            proxy,
            ca,
            root: tls.root.clone(),
        }
    }

    fn target(&self) -> String {
        format!("api.test:{}", self.up.port)
    }

    fn get(&self, path: &str) -> String {
        format!("GET {path} HTTP/1.1\r\nHost: {}\r\n\r\n", self.target())
    }

    /// CONNECT and complete TLS with the session CA, as a client that trusts it.
    async fn inspected(&self) -> Tls {
        tokio::time::timeout(
            STEP,
            tunnel(
                &self.proxy,
                &[self.ca.as_ref().expect("an inspected rule").cert_der()],
                &self.target(),
                "api.test",
            ),
        )
        .await
        .expect("the tunnel within STEP")
        .expect("an inspected tunnel")
    }

    /// The properties every scenario ends on: no panic anywhere, the listener alive, and a fresh
    /// connection served end to end.
    async fn still_serves(&self) {
        assert_eq!(PANICS.load(Ordering::SeqCst), 0, "a panic in the process");
        assert!(self.proxy.is_alive(), "the listener died (FW-XR11)");
        let mut tls = self.inspected().await;
        let ok = tokio::time::timeout(STEP, request(&mut tls, &self.get("/after")))
            .await
            .expect("the follow-up within STEP");
        assert!(ok.starts_with("HTTP/1.1 200"), "the follow-up: {ok}");
        assert!(ok.ends_with("ok:/after"), "the follow-up: {ok}");
    }
}

/// Everything the client reads until the Gateway ends the stream, bounded by `STEP`.
async fn read_to_end<S: AsyncRead + Unpin>(s: &mut S) -> String {
    let mut out = Vec::new();
    let mut chunk = [0u8; 16 * 1024];
    loop {
        match tokio::time::timeout(STEP, s.read(&mut chunk)).await {
            Ok(Ok(n)) if n > 0 => out.extend_from_slice(&chunk[..n]),
            Ok(_) => break,
            Err(_) => panic!(
                "the Gateway neither answered nor ended the stream within {STEP:?}: {}",
                String::from_utf8_lossy(&out)
            ),
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Upstream faults before a usable response head: the client gets `502` and nothing the upstream
/// sent, the connection ends, and the session serves the next request.
#[tokio::test(flavor = "multi_thread")]
async fn an_upstream_that_fails_before_its_head_is_a_502() {
    for fault in [
        Fault::ResetOnAccept,
        Fault::CloseInHandshake,
        Fault::ResetMidHead,
        Fault::EndMidHead,
        Fault::Garbage,
        Fault::HugeHead,
    ] {
        let rig = Rig::new(&[fault], "allow").await;
        let mut tls = rig.inspected().await;
        tls.write_all(rig.get("/x").as_bytes()).await.unwrap();
        let got = read_to_end(&mut tls).await;
        assert!(got.starts_with("HTTP/1.1 502"), "{fault:?}: {got}");
        assert!(
            !got.contains("200 OK") && !got.contains("SSH-") && !got.contains("X-Pad"),
            "{fault:?}: upstream bytes reached the client: {got}"
        );
        rig.still_serves().await;
    }
}

/// A refused upstream port is a `502` too, and the session keeps serving the next host.
#[tokio::test(flavor = "multi_thread")]
async fn an_upstream_that_refuses_the_connection_is_a_502() {
    count_panics();
    let closed = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = closed.local_addr().unwrap().port();
    drop(closed);
    let tls = fixture_tls(&["api.test"]);
    let mut session = Session::new(
        &[format!("allow:api.test:{port}")],
        resolver(&[("api.test", "127.0.0.1")]),
    );
    session.upstream_roots = Some(vec![tls.root.clone()]);
    let (proxy, ca) = session.start();
    let ca = ca.unwrap();
    let target = format!("api.test:{port}");
    let mut client = tunnel(&proxy, &[ca.cert_der()], &target, "api.test")
        .await
        .expect("an inspected tunnel");
    client
        .write_all(format!("GET /x HTTP/1.1\r\nHost: {target}\r\n\r\n").as_bytes())
        .await
        .unwrap();
    let got = read_to_end(&mut client).await;
    assert!(got.starts_with("HTTP/1.1 502"), "{got}");
    assert_eq!(PANICS.load(Ordering::SeqCst), 0);
    assert!(proxy.is_alive());
}

/// Upstream faults inside the body: the client gets the head and the bytes that came, then the
/// stream ends short of what the head promised -- never a completed response -- and no grant
/// records it as served.
#[tokio::test(flavor = "multi_thread")]
async fn an_upstream_that_fails_inside_its_body_ends_the_response_short() {
    for fault in [Fault::ShortBody, Fault::EndMidChunked, Fault::BadChunk] {
        let rig = Rig::new(&[fault], "allow").await;
        let mut tls = rig.inspected().await;
        tls.write_all(rig.get("/x").as_bytes()).await.unwrap();
        let got = read_to_end(&mut tls).await;
        assert!(got.starts_with("HTTP/1.1 200"), "{fault:?}: {got}");
        let body = got.split_once("\r\n\r\n").map(|(_, b)| b).unwrap_or("");
        match fault {
            Fault::ShortBody => assert!(body.len() < 100, "{fault:?}: {body:?}"),
            _ => assert!(
                !body.ends_with("0\r\n\r\n"),
                "{fault:?}: a terminated body {body:?}"
            ),
        }
        assert!(
            rig.proxy
                .grants()
                .iter()
                .all(|g| g.path.as_deref() != Some("/x")),
            "{fault:?}: a short response recorded as served: {:?}",
            rig.proxy.grants()
        );
        rig.still_serves().await;
    }
}

/// How a client leaves an exchange.
#[derive(Clone, Copy, Debug)]
enum Exit {
    /// Closes the socket: TCP FIN, no `close_notify`.
    Close,
    /// Resets the connection.
    Reset,
    /// Shuts down its sending side and keeps reading, which Envoy's connection manager also treats
    /// as leaving.
    HalfClose,
}

/// An upstream that never answers is waited for -- a response has no timeout (FEP-6 §4.9) -- but
/// once the client leaves, however it leaves, the Gateway drops the upstream connection instead of
/// holding it for as long as the upstream does, before the response head and in the middle of the
/// body alike.
#[tokio::test(flavor = "multi_thread")]
async fn a_client_that_leaves_a_stalled_upstream_releases_it() {
    for fault in [Fault::StallBeforeHead, Fault::StallMidBody] {
        for exit in [Exit::Close, Exit::Reset, Exit::HalfClose] {
            let rig = Rig::new(&[fault], "allow").await;
            let mut tls = rig.inspected().await;
            tls.write_all(rig.get("/x").as_bytes()).await.unwrap();
            if matches!(fault, Fault::StallMidBody) {
                let mut first = [0u8; 1];
                let _ = tokio::time::timeout(STEP, tls.read(&mut first)).await;
            }
            assert!(
                rig.up.open_at_least(1).await,
                "{fault:?} {exit:?}: the stalled exchange never reached the upstream"
            );
            let kept = match exit {
                Exit::Close => {
                    drop(tls);
                    None
                }
                Exit::Reset => {
                    tls.get_ref().0.set_zero_linger().unwrap();
                    drop(tls);
                    None
                }
                Exit::HalfClose => {
                    tls.get_mut().0.shutdown().await.unwrap();
                    Some(tls)
                }
            };
            assert!(
                rig.up.open_at_most(0).await,
                "{fault:?} {exit:?}: the upstream connection outlived the client by more than {STEP:?}"
            );
            if let Some(mut tls) = kept {
                let rest = read_to_end(&mut tls).await;
                assert!(!rest.contains("ok:"), "{fault:?} {exit:?}: {rest}");
            }
            rig.still_serves().await;
        }
    }
}

/// A pooled connection the upstream reset while idle: a bodiless request is retried once on a
/// fresh connection; a request with a body is never sent a second time.
#[tokio::test(flavor = "multi_thread")]
async fn a_pooled_connection_reset_while_idle() {
    let rig = Rig::new(&[Fault::ServeOnceThenReset], "allow").await;
    let mut tls = rig.inspected().await;
    let first = request(&mut tls, &rig.get("/first")).await;
    assert!(first.ends_with("ok:/first"), "{first}");
    assert!(rig.up.open_at_most(0).await, "the upstream did not reset");
    let again = tokio::time::timeout(STEP, request(&mut tls, &rig.get("/again")))
        .await
        .expect("the retry within STEP");
    assert!(
        again.ends_with("ok:/again"),
        "a bodiless request is retried: {again}"
    );

    let rig = Rig::new(&[Fault::ServeOnceThenReset], "get,post").await;
    let mut tls = rig.inspected().await;
    let post = |path: &str| {
        format!(
            "POST {path} HTTP/1.1\r\nHost: {}\r\nContent-Length: 4\r\n\r\nbody",
            rig.target()
        )
    };
    let first = request(&mut tls, &post("/first")).await;
    assert!(first.ends_with("ok:/first"), "{first}");
    assert!(rig.up.open_at_most(0).await, "the upstream did not reset");
    tls.write_all(post("/once").as_bytes()).await.unwrap();
    let got = tokio::time::timeout(STEP, read_response(&mut tls))
        .await
        .expect("an answer within STEP");
    assert!(
        got.starts_with("HTTP/1.1 502") || got.ends_with("ok:/once"),
        "{got}"
    );
    let sent = rig.up.seen().iter().filter(|r| *r == "POST /once").count();
    assert!(
        sent <= 1,
        "a request with a body went upstream {sent} times"
    );
}

/// A tunnel whose upstream resets mid-stream ends for the client too, and the session serves on.
#[tokio::test(flavor = "multi_thread")]
async fn a_tunnel_whose_upstream_resets_ends_for_the_client() {
    let rig = Rig::new(&[Fault::ResetMidChunked], "tunnel").await;
    let client = tunnel(
        &rig.proxy,
        std::slice::from_ref(&rig.root),
        &rig.target(),
        "api.test",
    )
    .await;
    let mut client = client.expect("a tunnel to the fixture");
    client.write_all(rig.get("/x").as_bytes()).await.unwrap();
    let got = read_to_end(&mut client).await;
    assert!(!got.ends_with("0\r\n\r\n"), "{got}");
    assert!(rig.up.open_at_most(0).await);
    assert_eq!(PANICS.load(Ordering::SeqCst), 0);
    assert!(rig.proxy.is_alive());
    let mut again = tunnel(
        &rig.proxy,
        std::slice::from_ref(&rig.root),
        &rig.target(),
        "api.test",
    )
    .await
    .expect("a second tunnel");
    let ok = request(&mut again, &rig.get("/after")).await;
    assert!(ok.ends_with("ok:/after"), "{ok}");
}

/// Client faults mid-request and mid-response: a request whose body the client abandoned never
/// reaches the upstream as a request, and an upstream connection left mid-response is not reused.
#[tokio::test(flavor = "multi_thread")]
async fn a_client_that_vanishes_mid_exchange() {
    let rig = Rig::new(&[], "get,post").await;
    let mut tls = rig.inspected().await;
    tls.write_all(
        format!(
            "POST /partial HTTP/1.1\r\nHost: {}\r\nContent-Length: 1000\r\n\r\n{}",
            rig.target(),
            "a".repeat(100)
        )
        .as_bytes(),
    )
    .await
    .unwrap();
    tls.flush().await.unwrap();
    tokio::time::sleep(Duration::from_millis(200)).await;
    tls.get_ref().0.set_zero_linger().unwrap();
    drop(tls);
    assert!(
        rig.up.open_at_most(0).await,
        "the upstream connection outlived the abandoned request"
    );
    assert!(
        !rig.up.seen().iter().any(|r| r.ends_with("/partial")),
        "a request the client abandoned reached the upstream whole"
    );
    rig.still_serves().await;

    let rig = Rig::new(&[Fault::StallMidBody], "allow").await;
    let mut tls = rig.inspected().await;
    tls.write_all(rig.get("/x").as_bytes()).await.unwrap();
    let mut first = [0u8; 1];
    let _ = tokio::time::timeout(STEP, tls.read(&mut first)).await;
    tls.get_ref().0.set_zero_linger().unwrap();
    drop(tls);
    assert!(
        rig.up.open_at_most(0).await,
        "the upstream connection left mid-response was kept"
    );
    rig.still_serves().await;
}

/// Two requests a client pipelines in one write get two responses, in order: the bytes the
/// Gateway reads from the client while it watches it during the first exchange are kept for the
/// second.
#[tokio::test(flavor = "multi_thread")]
async fn pipelined_requests_are_answered_in_order() {
    let rig = Rig::new(&[], "allow").await;
    let mut tls = rig.inspected().await;
    let both = format!("{}{}", rig.get("/one"), rig.get("/two"));
    tls.write_all(both.as_bytes()).await.unwrap();
    let one = tokio::time::timeout(STEP, read_response(&mut tls))
        .await
        .expect("the first response");
    let two = tokio::time::timeout(STEP, read_response(&mut tls))
        .await
        .expect("the second response");
    assert!(one.ends_with("ok:/one"), "{one}");
    assert!(two.ends_with("ok:/two"), "{two}");
    rig.still_serves().await;
}
