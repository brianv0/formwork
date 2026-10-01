//! The inspected grade (FW-EGR10, FW-EGR20-25, FW-CRED16-19, FEP-6 §4.4, §4.7) through the real
//! Gateway listener: a rustls client that trusts only the session CA CONNECTs through the listener
//! and speaks HTTP/1.1 to a TLS fixture upstream whose certificate the Gateway trusts through the
//! fixture-roots input. The upstream records every handshake and request, so each test sees
//! exactly what crossed.

mod support;

use std::sync::atomic::Ordering;
use std::sync::Arc;

use formwork_blueprint::{BrokerScheme, CanonicalHost, HostPattern, RefusalReason};
use formwork_gateway::{Broker, EgressProxy, SessionCa};
use rustls::pki_types::ServerName;
use support::*;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const SECRET: &str = "sk-ant-REAL-SECRET-0001";
const PLACEHOLDER: &str = "fwcred-anthropic-abc123";

struct Inspected {
    up: Upstream,
    proxy: EgressProxy,
    ca: Arc<SessionCa>,
}

impl Inspected {
    fn target(&self, host: &str) -> String {
        format!("{host}:{}", self.up.port)
    }

    fn host_header(&self, host: &str) -> String {
        format!("Host: {host}:{}\r\n", self.up.port)
    }

    async fn tunnel(&self, host: &str) -> Tls {
        tunnel(&self.proxy, &[self.ca.cert_der()], &self.target(host), host)
            .await
            .expect("an inspected tunnel")
    }
}

/// A session inspecting `api.test` (and `other.test`) on the fixture's port with `rules` written
/// against `{port}`.
async fn inspected(rules: &[&str], brokers: Vec<Broker>) -> Inspected {
    let tls = fixture_tls(&["api.test", "other.test"]);
    let up = upstream(Some(tls.clone())).await;
    let rules: Vec<String> = rules
        .iter()
        .map(|r| r.replace("{port}", &up.port.to_string()))
        .collect();
    let mut session = Session::new(
        &rules,
        resolver(&[("api.test", "127.0.0.1"), ("other.test", "127.0.0.1")]),
    );
    session.upstream_roots = Some(vec![tls.root.clone()]);
    session.brokers = brokers;
    let (proxy, ca) = session.start();
    Inspected {
        up,
        proxy,
        ca: ca.unwrap(),
    }
}

fn anthropic_broker() -> Vec<Broker> {
    vec![Broker {
        name: "anthropic".into(),
        placeholder: PLACEHOLDER.into(),
        secret: SECRET.into(),
        bindings: vec![(
            CanonicalHost::Name("api.test".into()),
            BrokerScheme::Header("x-api-key".into()),
        )],
    }]
}

/// Does any run of 8 or more bytes of the credential appear in `out`?
fn leaks(out: &str) -> bool {
    SECRET
        .as_bytes()
        .windows(8)
        .any(|w| out.as_bytes().windows(8).any(|o| o == w))
}

/// FW-E2E-077: under `post:api.test/repos/acme/**` a POST inside the scope passes; a POST outside
/// it and a GET inside it are refused with a generic 403 on a connection that stays usable, the
/// record naming the reason.
#[tokio::test(flavor = "multi_thread")]
async fn fw_e2e_077_inspected_path_scope() {
    let s = inspected(&["post:api.test:{port}/repos/acme/**"], vec![]).await;
    let host = s.host_header("api.test");
    let mut tls = s.tunnel("api.test").await;
    let ok = request(
        &mut tls,
        &format!("POST /repos/acme/x HTTP/1.1\r\n{host}Content-Length: 2\r\n\r\nhi"),
    )
    .await;
    assert!(ok.starts_with("HTTP/1.1 200"), "{ok}");
    let refused = request(
        &mut tls,
        &format!("POST /repos/other/x HTTP/1.1\r\n{host}Content-Length: 3\r\n\r\nabc"),
    )
    .await;
    assert!(refused.starts_with("HTTP/1.1 403"), "{refused}");
    assert!(!refused.contains("repos"), "the 403 body names no rule");
    let get = request(
        &mut tls,
        &format!("GET /repos/acme/x HTTP/1.1\r\n{host}\r\n"),
    )
    .await;
    assert!(
        get.starts_with("HTTP/1.1 403"),
        "the connection stayed usable: {get}"
    );
    assert_eq!(s.up.seen().len(), 1, "only the admitted request crossed");
    let v = s.proxy.violations();
    assert_eq!(
        v.iter().map(|v| v.reason).collect::<Vec<_>>(),
        vec![RefusalReason::Path, RefusalReason::Method]
    );
    assert_eq!(v[0].path.as_deref(), Some("/repos/other/x"));
}

/// FW-ADV-017 (TLS path): traversal and smuggling against an inspected rule never reach
/// `/repos/other`.
#[tokio::test(flavor = "multi_thread")]
async fn fw_adv_017_traversal_against_an_inspected_rule() {
    let s = inspected(&["post:api.test:{port}/repos/acme/**"], vec![]).await;
    let host = s.host_header("api.test");
    for path in [
        "/repos/acme/../other/x",
        "/repos/acme/%2e%2e/other/x",
        "/repos/acme%2F..%2Fother/x",
    ] {
        let mut tls = s.tunnel("api.test").await;
        let out = request(
            &mut tls,
            &format!("POST {path} HTTP/1.1\r\n{host}Content-Length: 0\r\n\r\n"),
        )
        .await;
        assert!(
            out.starts_with("HTTP/1.1 403") || out.starts_with("HTTP/1.1 400"),
            "{path}: {out}"
        );
    }
    let mut tls = s.tunnel("api.test").await;
    let smuggle = request(
        &mut tls,
        &format!("POST /repos/acme/x HTTP/1.1\r\n{host}Content-Length: 4\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n"),
    )
    .await;
    assert!(smuggle.starts_with("HTTP/1.1 400"), "{smuggle}");
    assert!(s.up.seen().is_empty(), "{:?}", s.up.seen());
}

/// FW-EGR10: the Host header and the server name must match the CONNECT target; a mismatched
/// server name is refused before any certificate is presented.
#[tokio::test(flavor = "multi_thread")]
async fn fw_egr10_host_and_sni_must_agree_with_the_target() {
    let s = inspected(&["allow:api.test:{port}"], vec![]).await;
    let mut tls = s.tunnel("api.test").await;
    let wrong_host = request(&mut tls, "GET / HTTP/1.1\r\nHost: other.test\r\n\r\n").await;
    assert!(wrong_host.starts_with("HTTP/1.1 403"), "{wrong_host}");
    assert!(tunnel(
        &s.proxy,
        &[s.ca.cert_der()],
        &s.target("api.test"),
        "other.test"
    )
    .await
    .is_none());
    assert!(s.up.seen().is_empty());
    assert_eq!(
        reasons(&s.proxy),
        vec![RefusalReason::HostMismatch, RefusalReason::SniMismatch]
    );
}

/// FW-EGR20: an inspected host offers only `http/1.1`; a ClientHello whose ALPN list excludes it
/// is refused, and one that offers both negotiates HTTP/1.1.
#[tokio::test(flavor = "multi_thread")]
async fn fw_egr20_inspected_hosts_speak_http_1_1_only() {
    let s = inspected(&["allow:api.test:{port}"], vec![]).await;
    let connector =
        |alpn: &[&[u8]]| tokio_rustls::TlsConnector::from(client_config(&[s.ca.cert_der()], alpn));
    let name = || ServerName::try_from("api.test").unwrap();
    let tcp = connect(&s.proxy, &s.target("api.test")).await.unwrap();
    assert!(connector(&[b"h2"]).connect(name(), tcp).await.is_err());
    let tcp = connect(&s.proxy, &s.target("api.test")).await.unwrap();
    let mut both = connector(&[b"h2", b"http/1.1"])
        .connect(name(), tcp)
        .await
        .expect("HTTP/1.1 is negotiated");
    assert_eq!(both.get_ref().1.alpn_protocol(), Some(&b"http/1.1"[..]));
    let host = s.host_header("api.test");
    assert!(
        request(&mut both, &format!("GET /x HTTP/1.1\r\n{host}\r\n"))
            .await
            .ends_with("ok:/x")
    );
    assert_eq!(reasons(&s.proxy), vec![RefusalReason::Alpn]);
}

/// FW-EGR23: TRACE and CONNECT are refused on an inspected host even under `allow:`, which admits
/// every other method, including ones outside the rule atoms.
#[tokio::test(flavor = "multi_thread")]
async fn fw_egr23_reflective_methods_are_refused_under_every_rule() {
    let s = inspected(&["allow:api.test:{port}"], vec![]).await;
    let host = s.host_header("api.test");
    let mut tls = s.tunnel("api.test").await;
    let trace = request(&mut tls, &format!("TRACE / HTTP/1.1\r\n{host}\r\n")).await;
    assert!(trace.starts_with("HTTP/1.1 403"), "{trace}");
    let connect_inner = request(
        &mut tls,
        &format!("CONNECT other.test:443 HTTP/1.1\r\n{host}\r\n"),
    )
    .await;
    assert!(
        connect_inner.starts_with("HTTP/1.1 400") || connect_inner.starts_with("HTTP/1.1 403"),
        "{connect_inner}"
    );
    let mut tls = s.tunnel("api.test").await;
    let propfind = request(&mut tls, &format!("PROPFIND /dav HTTP/1.1\r\n{host}\r\n")).await;
    assert!(propfind.ends_with("ok:/dav"), "{propfind}");
    assert_eq!(s.up.seen().len(), 1);
}

/// FW-EGR22: the upstream receives a request line built from the canonical path that matched, and
/// no hop-by-hop field -- `Proxy-Authorization`, `Keep-Alive`, `TE`, or a field `Connection` names.
#[tokio::test(flavor = "multi_thread")]
async fn fw_egr22_the_upstream_receives_what_matched() {
    let s = inspected(&["get:api.test:{port}/a/**"], vec![]).await;
    let host = s.host_header("api.test");
    let mut tls = s.tunnel("api.test").await;
    let out = request(
        &mut tls,
        &format!(
            "GET /a/./b/../c/%7Ed?q=1 HTTP/1.1\r\n{host}Connection: keep-alive, X-Private\r\n\
             X-Private: 1\r\nKeep-Alive: timeout=5\r\nTE: trailers\r\n\
             Proxy-Authorization: Basic eDp5\r\nAccept: */*\r\n\r\n"
        ),
    )
    .await;
    assert!(out.ends_with("ok:/a/c/~d"), "{out}");
    let seen = &s.up.seen()[0];
    assert!(
        seen.head.starts_with("GET /a/c/~d?q=1 HTTP/1.1"),
        "{}",
        seen.head
    );
    for hop in [
        "x-private",
        "keep-alive",
        "te",
        "proxy-authorization",
        "connection",
    ] {
        assert!(seen.header(hop).is_none(), "{hop}: {}", seen.head);
    }
    assert_eq!(seen.header("accept").as_deref(), Some("*/*"));
}

/// FW-E2E-078 (the Gateway half), FW-CRED11/18: the upstream receives the real credential in
/// `x-api-key`, substituted for the placeholder and added when absent, never on OPTIONS; the
/// placeholder toward another host, or outside its scheme's header, is refused.
#[tokio::test(flavor = "multi_thread")]
async fn fw_e2e_078_brokered_header_is_presented_where_bound() {
    let s = inspected(
        &["allow:api.test:{port}", "allow:other.test:{port}"],
        anthropic_broker(),
    )
    .await;
    let host = s.host_header("api.test");
    let mut tls = s.tunnel("api.test").await;
    let with = request(
        &mut tls,
        &format!("GET /v1 HTTP/1.1\r\n{host}x-api-key: {PLACEHOLDER}\r\n\r\n"),
    )
    .await;
    assert!(with.ends_with("ok:/v1"), "{with}");
    let without = request(&mut tls, &format!("GET /v2 HTTP/1.1\r\n{host}\r\n")).await;
    assert!(without.ends_with("ok:/v2"), "{without}");
    let options = request(
        &mut tls,
        &format!("OPTIONS /v3 HTTP/1.1\r\n{host}x-api-key: {PLACEHOLDER}\r\n\r\n"),
    )
    .await;
    assert!(options.ends_with("ok:/v3"), "{options}");
    let query = request(
        &mut tls,
        &format!("GET /v4?k={PLACEHOLDER} HTTP/1.1\r\n{host}\r\n"),
    )
    .await;
    assert!(query.starts_with("HTTP/1.1 403"), "{query}");
    let seen = s.up.seen();
    assert_eq!(seen.len(), 3, "{seen:?}");
    assert_eq!(seen[0].header("x-api-key").as_deref(), Some(SECRET));
    assert_eq!(seen[1].header("x-api-key").as_deref(), Some(SECRET));
    assert_eq!(
        seen[0].header("accept-encoding").as_deref(),
        Some("identity")
    );
    assert!(
        seen[2].header("x-api-key").is_none(),
        "FW-CRED18: {}",
        seen[2].head
    );
    assert!(seen.iter().all(|h| !h.head.contains(PLACEHOLDER)));

    let mut other = s.tunnel("other.test").await;
    let leak = request(
        &mut other,
        &format!(
            "GET / HTTP/1.1\r\n{}x-api-key: {PLACEHOLDER}\r\n\r\n",
            s.host_header("other.test")
        ),
    )
    .await;
    assert!(leak.starts_with("HTTP/1.1 403"), "{leak}");
    assert_eq!(
        s.up.seen().len(),
        3,
        "the placeholder never reached other.test"
    );
    assert_eq!(
        reasons(&s.proxy),
        vec![RefusalReason::Placeholder, RefusalReason::Placeholder]
    );
}

/// FW-ADV-021 / FW-CRED17: an upstream that echoes the presented credential -- in the body, split
/// across two writes 50 ms apart, in a response header, or compressed -- has its response ended;
/// no 8-byte run of the credential reaches the client, and TRACE is refused outright.
#[tokio::test(flavor = "multi_thread")]
async fn fw_adv_021_credential_reflection() {
    let s = inspected(&["allow:api.test:{port}"], anthropic_broker()).await;
    let host = s.host_header("api.test");
    for query in ["", "?split=1", "?in=header", "?gzip=1"] {
        let mut tls = s.tunnel("api.test").await;
        let out = request(
            &mut tls,
            &format!("GET /reflect{query} HTTP/1.1\r\n{host}x-api-key: {PLACEHOLDER}\r\n\r\n"),
        )
        .await;
        assert!(
            !leaks(&out),
            "{query}: the credential reached the client: {out}"
        );
    }
    let mut tls = s.tunnel("api.test").await;
    let trace = request(
        &mut tls,
        &format!("TRACE / HTTP/1.1\r\n{host}x-api-key: {PLACEHOLDER}\r\n\r\n"),
    )
    .await;
    assert!(trace.starts_with("HTTP/1.1 403"), "{trace}");
    assert!(!leaks(&trace));
    assert_eq!(
        reasons(&s.proxy),
        vec![
            RefusalReason::Reflection,
            RefusalReason::Reflection,
            RefusalReason::Reflection,
            RefusalReason::Reflection,
            RefusalReason::Method
        ]
    );
    // A response to a request that presented nothing is not guarded: it cannot hold the secret.
    let unbrokered = inspected(&["allow:api.test:{port}"], vec![]).await;
    let mut tls = unbrokered.tunnel("api.test").await;
    let echo = request(
        &mut tls,
        &format!(
            "GET /reflect HTTP/1.1\r\n{}\r\n",
            unbrokered.host_header("api.test")
        ),
    )
    .await;
    assert!(echo.contains("echo:"), "{echo}");
}

/// FW-E2E-093 / FW-CRED17: a server-sent-event stream through the reflection guard reaches the
/// client event by event -- the guard holds back only a prefix of the credential, which `\n\n`
/// never begins.
#[tokio::test(flavor = "multi_thread")]
async fn fw_e2e_093_streamed_events_pass_the_guard_as_they_arrive() {
    let s = inspected(&["allow:api.test:{port}"], anthropic_broker()).await;
    let mut tls = s.tunnel("api.test").await;
    tls.write_all(
        format!(
            "GET /sse HTTP/1.1\r\n{}x-api-key: {PLACEHOLDER}\r\n\r\n",
            s.host_header("api.test")
        )
        .as_bytes(),
    )
    .await
    .unwrap();
    let mut got = Vec::new();
    let mut chunk = [0u8; 4096];
    while !String::from_utf8_lossy(&got).contains("data: 1\n\n") {
        let n = tokio::time::timeout(std::time::Duration::from_secs(4), tls.read(&mut chunk))
            .await
            .expect("the first event arrives while the stream is open")
            .unwrap();
        assert!(n > 0, "{}", String::from_utf8_lossy(&got));
        got.extend_from_slice(&chunk[..n]);
    }
    s.up.ack();
    while !got.windows(5).any(|w| w == b"0\r\n\r\n") {
        let n = tokio::time::timeout(std::time::Duration::from_secs(4), tls.read(&mut chunk))
            .await
            .expect("the stream ends")
            .unwrap();
        assert!(n > 0, "{}", String::from_utf8_lossy(&got));
        got.extend_from_slice(&chunk[..n]);
    }
    assert!(String::from_utf8_lossy(&got).contains("data: 2"));
    assert!(
        s.up.acked(),
        "the second event followed the client's receipt of the first"
    );
}

/// FW-EGR21 / FW-E2E-092: request bodies stream through in their framing -- a chunked upload
/// larger than any buffer and a length-framed one arrive byte-identical.
#[tokio::test(flavor = "multi_thread")]
async fn fw_egr21_bodies_stream_byte_identical() {
    let _ = tracing_subscriber::fmt()
        .with_test_writer()
        .with_env_filter("formwork_gateway=debug")
        .try_init();
    let s = inspected(&["post:api.test:{port}/sum"], vec![]).await;
    let host = s.host_header("api.test");
    let body: Vec<u8> = (0..3 * 1024 * 1024u32)
        .map(|i| (i * 7 % 251) as u8)
        .collect();
    let sum: u64 = body.iter().map(|b| *b as u64).sum();
    let mut tls = s.tunnel("api.test").await;
    let mut chunked =
        format!("POST /sum HTTP/1.1\r\n{host}Transfer-Encoding: chunked\r\n\r\n").into_bytes();
    for piece in body.chunks(1024 * 1024) {
        chunked.extend_from_slice(format!("{:x}\r\n", piece.len()).as_bytes());
        chunked.extend_from_slice(piece);
        chunked.extend_from_slice(b"\r\n");
    }
    chunked.extend_from_slice(b"0\r\n\r\n");
    let started = std::time::Instant::now();
    // tokio-rustls returns from a write once the session holds the bytes, even while the socket
    // would block; without a flush the tail of a large upload can stay in the client's TLS buffer
    // (macOS's loopback buffers are small enough for that).
    tls.write_all(&chunked).await.unwrap();
    tls.flush().await.unwrap();
    let written = started.elapsed();
    let out = read_response(&mut tls).await;
    assert!(
        out.ends_with(&format!("{} {sum}", body.len())),
        "written in {written:?}, answered after {:?}: {out:?}; the fixture saw {} request(s); \
         refusals: {:?}",
        started.elapsed(),
        s.up.seen().len(),
        s.proxy.violations()
    );
    let mut sized = format!(
        "POST /sum HTTP/1.1\r\n{host}Content-Length: {}\r\n\r\n",
        body.len()
    )
    .into_bytes();
    sized.extend_from_slice(&body);
    tls.write_all(&sized).await.unwrap();
    tls.flush().await.unwrap();
    let out = read_response(&mut tls).await;
    assert!(out.ends_with(&format!("{} {sum}", body.len())), "{out}");
}

/// FW-E2E-095: twenty sequential requests, each on its own client connection, reuse one upstream
/// connection: the fixture observes one TLS handshake.
#[tokio::test(flavor = "multi_thread")]
async fn fw_e2e_095_upstream_connections_are_pooled() {
    let s = inspected(&["allow:api.test:{port}"], vec![]).await;
    let host = s.host_header("api.test");
    for i in 0..20 {
        let mut tls = s.tunnel("api.test").await;
        let out = request(&mut tls, &format!("GET /{i} HTTP/1.1\r\n{host}\r\n")).await;
        assert!(out.ends_with(&format!("ok:/{i}")), "{out}");
    }
    assert_eq!(s.up.handshakes.load(Ordering::SeqCst), 1);
    assert_eq!(s.up.seen().len(), 20);
    // The last grant is recorded once its response is written, just after the client reads it.
    let mut grants = s.proxy.grants();
    for _ in 0..100 {
        if grants.len() == 20 {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        grants = s.proxy.grants();
    }
    assert_eq!(grants.len(), 20, "FW-FID13: one grant per request");
    assert!(grants
        .iter()
        .all(|g| g.grade == "inspected" && g.status == Some(200)));
}

/// FW-EGR24: an upstream whose certificate does not chain to the host trust store is refused
/// (`upstream-tls`); the session CA never counts as upstream trust.
#[tokio::test(flavor = "multi_thread")]
async fn fw_egr24_upstreams_verify_against_the_host_trust_store() {
    let impostor = upstream(Some(fixture_tls(&["api.test"]))).await;
    let mut session = Session::new(
        &[format!("allow:api.test:{}", impostor.port)],
        resolver(&[("api.test", "127.0.0.1")]),
    );
    session.upstream_roots = Some(vec![fixture_tls(&["api.test"]).root]);
    let (proxy, ca) = session.start();
    let ca = ca.unwrap();
    let mut tls = tunnel(
        &proxy,
        &[ca.cert_der()],
        &format!("api.test:{}", impostor.port),
        "api.test",
    )
    .await
    .unwrap();
    let out = request(
        &mut tls,
        &format!("GET / HTTP/1.1\r\nHost: api.test:{}\r\n\r\n", impostor.port),
    )
    .await;
    assert!(out.starts_with("HTTP/1.1 502"), "{out}");
    assert!(impostor.seen().is_empty());
    assert_eq!(reasons(&proxy), vec![RefusalReason::UpstreamTls]);
}

/// FW-EGR25 / FW-E2E-097: the session CA is constrained to the inspected hosts. A leaf it mints
/// for any other name fails verification in a client that enforces name constraints.
#[tokio::test(flavor = "multi_thread")]
async fn fw_egr25_the_session_ca_is_name_constrained() {
    let api = HostPattern::Exact("api.test".into());
    let ca = SessionCa::generate(&[&api]).unwrap();
    for (name, verifies) in [("api.test", true), ("other.test", false)] {
        let host = CanonicalHost::Name(name.into());
        let acceptor = tokio_rustls::TlsAcceptor::from(ca.server_config(&host).unwrap());
        let connector =
            tokio_rustls::TlsConnector::from(client_config(&[ca.cert_der()], &[b"http/1.1"]));
        let (a, b) = tokio::io::duplex(64 * 1024);
        let (_, client) = tokio::join!(
            acceptor.accept(a),
            connector.connect(ServerName::try_from(name).unwrap(), b)
        );
        assert_eq!(client.is_ok(), verifies, "{name}: {:?}", client.err());
    }
    assert!(!ca.cert_pem().contains("PRIVATE KEY"));
}

/// FEP-6 §4.8: a WebSocket upgrade is matched like any request, and the two sides are spliced only
/// after the upstream answers `101`.
#[tokio::test(flavor = "multi_thread")]
async fn a_websocket_upgrade_is_spliced_after_101() {
    let s = inspected(&["get:api.test:{port}/ws"], vec![]).await;
    let mut tls = s.tunnel("api.test").await;
    let head = request(
        &mut tls,
        &format!(
            "GET /ws HTTP/1.1\r\n{}Connection: Upgrade\r\nUpgrade: websocket\r\n\r\n",
            s.host_header("api.test")
        ),
    )
    .await;
    assert!(head.starts_with("HTTP/1.1 101"), "{head}");
    tls.write_all(b"frame-bytes").await.unwrap();
    let mut echoed = [0u8; 11];
    tls.read_exact(&mut echoed).await.unwrap();
    assert_eq!(&echoed, b"frame-bytes");
    let seen = &s.up.seen()[0];
    assert_eq!(seen.header("upgrade").as_deref(), Some("websocket"));
}
