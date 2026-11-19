//! The inspected grade (FW-EGR10, FW-EGR20-25, FW-CRED16-19, FEP-6 §4.4, §4.7) through the real
//! Gateway listener: a rustls client that trusts only the session CA CONNECTs through the listener
//! and speaks HTTP/1.1 to a TLS fixture upstream whose certificate the Gateway trusts through the
//! fixture-roots input. The upstream records every handshake and request, so each test sees
//! exactly what crossed.

mod support;

use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

use formwork_blueprint::{BrokerScheme, CanonicalHost, HostPattern, RefusalReason};
use formwork_gateway::{Broker, EgressProxy, Grant, SessionCa};
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
/// server name is refused before any certificate is presented (FW-ADV-022's name disagreements).
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
/// is refused, and one that offers both negotiates HTTP/1.1 (FW-ADV-022's `h2`-only case).
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

/// The grant records once there are `n`: a grant is recorded just after its response is written.
async fn grants_after(proxy: &EgressProxy, n: usize) -> Vec<Grant> {
    for _ in 0..100 {
        if proxy.grants().len() >= n {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    proxy.grants()
}

/// A request head a lenient upstream would serve if the Gateway left it unframed behind an
/// admitted request: another method, path and host than any rule admits.
const SMUGGLED: &str = "GET /smuggled HTTP/1.1\r\nHost: other.test\r\n\r\n";

/// Under `post:api.test/allowed`, send an admitted POST whose `Connection` header names its own
/// framing field and whose body is [`SMUGGLED`], then an ordinary POST on the same connection.
/// The upstream must have received those two requests and nothing else, the first with its body,
/// each with one grant record. Returns the first request as the upstream saw it.
async fn post_with_named_framing(named: &str, framing: &str, wire_body: &str) -> Seen {
    let s = inspected(&["post:api.test:{port}/allowed"], vec![]).await;
    let host = s.host_header("api.test");
    let mut tls = s.tunnel("api.test").await;
    let out = request(
        &mut tls,
        &format!(
            "POST /allowed HTTP/1.1\r\n{host}Connection: {named}\r\n{framing}\r\n\r\n{wire_body}"
        ),
    )
    .await;
    assert!(
        out.starts_with("HTTP/1.1 200") && out.ends_with("ok:/allowed"),
        "{out}"
    );
    let seen = s.up.seen();
    assert_eq!(seen.len(), 1, "one request crossed: {seen:?}");
    assert_eq!(seen[0].body, SMUGGLED.as_bytes(), "{}", seen[0].head);
    assert_eq!(grants_after(&s.proxy, 1).await.len(), 1);

    // The upstream reads its connection in order, so anything it took for a second request is
    // recorded before this one.
    let again = request(
        &mut tls,
        &format!("POST /allowed HTTP/1.1\r\n{host}Content-Length: 2\r\n\r\nhi"),
    )
    .await;
    assert!(again.ends_with("ok:/allowed"), "{again}");
    let seen = s.up.seen();
    assert_eq!(seen.len(), 2, "{seen:?}");
    assert!(
        seen.iter().all(|r| r.head.starts_with("POST /allowed ")),
        "{seen:?}"
    );
    let grants = grants_after(&s.proxy, 2).await;
    assert_eq!(grants.len(), 2, "{grants:?}");
    assert!(
        grants.iter().all(|g| g.method.as_deref() == Some("POST")
            && g.path.as_deref() == Some("/allowed")
            && g.status == Some(200)),
        "{grants:?}"
    );
    assert!(s.proxy.violations().is_empty());
    seen[0].clone()
}

/// FW-E2E-212 / FW-EGR38: a request whose `Connection` header names `content-length` reaches the
/// upstream as one request with its `Content-Length` and its whole body. Forwarded without the
/// field, the body would be read as a second request that no rule decided and no record shows.
#[tokio::test(flavor = "multi_thread")]
async fn fw_egr38_connection_cannot_remove_a_requests_content_length() {
    let first = post_with_named_framing(
        "content-length",
        &format!("Content-Length: {}", SMUGGLED.len()),
        SMUGGLED,
    )
    .await;
    assert_eq!(
        first.header("content-length"),
        Some(SMUGGLED.len().to_string()),
        "{}",
        first.head
    );
    assert!(first.header("transfer-encoding").is_none());
}

/// FW-E2E-212 / FW-EGR38: the same for `Connection: transfer-encoding` and a chunked body.
#[tokio::test(flavor = "multi_thread")]
async fn fw_egr38_connection_cannot_remove_a_requests_transfer_encoding() {
    let first = post_with_named_framing(
        "Transfer-Encoding",
        "Transfer-Encoding: chunked",
        &format!("{:x}\r\n{SMUGGLED}\r\n0\r\n\r\n", SMUGGLED.len()),
    )
    .await;
    assert_eq!(
        first.header("transfer-encoding").as_deref(),
        Some("chunked"),
        "{}",
        first.head
    );
    assert!(first.header("content-length").is_none());
}

/// FW-E2E-212 / FW-EGR38: a response whose `Connection` header names its own framing field
/// reaches the client framed as the Gateway read it, and the client connection stays usable.
#[tokio::test(flavor = "multi_thread")]
async fn fw_egr38_connection_cannot_remove_a_responses_framing() {
    let s = inspected(&["get:api.test:{port}/**"], vec![]).await;
    let host = s.host_header("api.test");
    let mut tls = s.tunnel("api.test").await;
    let sized = request(&mut tls, &format!("GET /hop HTTP/1.1\r\n{host}\r\n")).await;
    assert_eq!(sized, "HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nhop");
    let chunked = request(
        &mut tls,
        &format!("GET /hop?chunked=1 HTTP/1.1\r\n{host}\r\n"),
    )
    .await;
    assert_eq!(
        chunked,
        "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nhop\r\n0\r\n\r\n"
    );
    let after = request(&mut tls, &format!("GET /after HTTP/1.1\r\n{host}\r\n")).await;
    assert_eq!(
        after,
        "HTTP/1.1 200 OK\r\nContent-Length: 9\r\n\r\nok:/after"
    );
    assert_eq!(grants_after(&s.proxy, 3).await.len(), 3);
}

/// FW-EGR10 / FW-EGR22: `Connection` cannot name away `Host`; the upstream receives the one `Host`
/// field the Gateway checked.
#[tokio::test(flavor = "multi_thread")]
async fn fw_egr22_connection_cannot_remove_host() {
    let s = inspected(&["get:api.test:{port}/**"], vec![]).await;
    let host = s.host_header("api.test");
    let mut tls = s.tunnel("api.test").await;
    let out = request(
        &mut tls,
        &format!("GET /x HTTP/1.1\r\n{host}Connection: host\r\n\r\n"),
    )
    .await;
    assert!(out.ends_with("ok:/x"), "{out}");
    let seen = &s.up.seen()[0];
    assert_eq!(seen.head, format!("GET /x HTTP/1.1\r\n{}", host.trim_end()));
}

/// FW-E2E-212 / FW-EGR36: a request that repeats `Host`, `Content-Length`, `Transfer-Encoding` or
/// a brokered header name is refused as `malformed` and nothing reaches the upstream, whichever
/// copy would have passed the check and whether or not the copies agree. A repeated field the
/// Gateway does not decide on passes.
#[tokio::test(flavor = "multi_thread")]
async fn fw_egr36_repeated_singleton_fields_are_refused() {
    let mut brokers = anthropic_broker();
    brokers.push(Broker {
        name: "github".into(),
        placeholder: "fwcred-github-def456".into(),
        secret: "ghp_REAL-SECRET-0002".into(),
        bindings: vec![(CanonicalHost::Name("api.test".into()), BrokerScheme::Bearer)],
    });
    let s = inspected(&["allow:api.test:{port}"], brokers).await;
    let host = s.host_header("api.test");
    let other = s.host_header("other.test");
    let repeated = [
        format!("GET / HTTP/1.1\r\n{host}{other}\r\n"),
        format!("GET / HTTP/1.1\r\n{other}{host}\r\n"),
        format!("GET / HTTP/1.1\r\n{host}{host}\r\n"),
        format!("POST / HTTP/1.1\r\n{host}Content-Length: 2\r\ncontent-length: 2\r\n\r\nhi"),
        format!("POST / HTTP/1.1\r\n{host}Content-Length: 2\r\nContent-Length: 3\r\n\r\nhi"),
        format!(
            "POST / HTTP/1.1\r\n{host}Transfer-Encoding: chunked\r\n\
             transfer-encoding: chunked\r\n\r\n2\r\nhi\r\n0\r\n\r\n"
        ),
        format!("GET / HTTP/1.1\r\n{host}x-api-key: {PLACEHOLDER}\r\nX-Api-Key: mine\r\n\r\n"),
        format!("GET / HTTP/1.1\r\n{host}x-api-key: mine\r\nx-api-key: {PLACEHOLDER}\r\n\r\n"),
        format!(
            "GET / HTTP/1.1\r\n{host}Authorization: Bearer a\r\nauthorization: Bearer b\r\n\r\n"
        ),
    ];
    for raw in &repeated {
        let mut tls = s.tunnel("api.test").await;
        let out = request(&mut tls, raw).await;
        assert!(out.starts_with("HTTP/1.1 400"), "{raw:?}: {out}");
    }
    assert!(s.up.seen().is_empty(), "{:?}", s.up.seen());
    let v = s.proxy.violations();
    assert_eq!(
        v.iter().map(|v| v.reason).collect::<Vec<_>>(),
        vec![RefusalReason::Malformed; repeated.len()],
        "{v:?}"
    );
    assert!(v.iter().all(|v| v.host.as_deref() == Some("api.test")));
    assert!(v.iter().all(|v| !v.detail.contains(PLACEHOLDER)), "{v:?}");

    let mut tls = s.tunnel("api.test").await;
    let out = request(
        &mut tls,
        &format!("GET /twice HTTP/1.1\r\n{host}Accept: text/a\r\nAccept: text/b\r\n\r\n"),
    )
    .await;
    assert!(out.ends_with("ok:/twice"), "{out}");
    assert_eq!(s.up.seen().len(), 1);
}

/// Read one response head and nothing after it.
async fn read_head(tls: &mut Tls) -> String {
    let mut got = Vec::new();
    let mut byte = [0u8; 1];
    while !got.ends_with(b"\r\n\r\n") {
        let n = tokio::time::timeout(Duration::from_secs(5), tls.read(&mut byte))
            .await
            .expect("a response head")
            .unwrap();
        assert!(n > 0, "{}", String::from_utf8_lossy(&got));
        got.push(byte[0]);
    }
    String::from_utf8(got).unwrap()
}

/// FW-EGR38's controls: ordinary messages cross byte for byte. A length-framed and a chunked POST
/// and a bodiless GET reach the upstream with the head the client sent; their responses, a
/// response to HEAD and a 204 reach the client with the head the upstream sent.
#[tokio::test(flavor = "multi_thread")]
async fn fw_egr38_ordinary_messages_cross_unchanged() {
    let s = inspected(&["allow:api.test:{port}"], vec![]).await;
    let host = s.host_header("api.test");
    let mut tls = s.tunnel("api.test").await;
    let sized = format!("POST /a HTTP/1.1\r\n{host}Content-Length: 5\r\nAccept: */*");
    let chunked = format!("POST /b HTTP/1.1\r\n{host}Transfer-Encoding: chunked\r\nAccept: */*");
    let empty = format!("POST /c HTTP/1.1\r\n{host}Content-Length: 0");
    let get = format!("GET /d HTTP/1.1\r\n{host}Accept: */*");
    for (head, body, answer) in [
        (&sized, "hello", "ok:/a"),
        (&chunked, "5\r\nhello\r\n0\r\n\r\n", "ok:/b"),
        (&empty, "", "ok:/c"),
        (&get, "", "ok:/d"),
    ] {
        let out = request(&mut tls, &format!("{head}\r\n\r\n{body}")).await;
        assert_eq!(
            out,
            format!("HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\n{answer}")
        );
    }
    let seen = s.up.seen();
    let heads: Vec<&str> = seen.iter().map(|r| r.head.as_str()).collect();
    assert_eq!(heads, [&sized, &chunked, &empty, &get]);
    assert_eq!(seen[0].body, b"hello");
    assert_eq!(seen[1].body, b"hello");

    tls.write_all(format!("HEAD /e HTTP/1.1\r\n{host}\r\n").as_bytes())
        .await
        .unwrap();
    assert_eq!(
        read_head(&mut tls).await,
        "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\n"
    );
    tls.write_all(format!("GET /none HTTP/1.1\r\n{host}\r\n").as_bytes())
        .await
        .unwrap();
    assert_eq!(read_head(&mut tls).await, "HTTP/1.1 204 No Content\r\n\r\n");
    let after = request(&mut tls, &format!("GET /f HTTP/1.1\r\n{host}\r\n")).await;
    assert_eq!(after, "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nok:/f");
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

/// FEP-6 §4.4: a pooled upstream connection the upstream closed while it sat idle is not reused --
/// checked with a request whose body the Gateway cannot replay on a fresh connection, so a stale
/// connection would answer `502`.
#[tokio::test(flavor = "multi_thread")]
async fn a_pooled_connection_the_upstream_closed_is_not_reused() {
    let s = inspected(&["allow:api.test:{port}"], vec![]).await;
    let host = s.host_header("api.test");
    let mut tls = s.tunnel("api.test").await;
    let out = request(&mut tls, &format!("GET /bye HTTP/1.1\r\n{host}\r\n")).await;
    assert!(out.ends_with("bye"), "{out}");
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    let out = request(
        &mut tls,
        &format!("POST /sum HTTP/1.1\r\n{host}Content-Length: 3\r\n\r\nabc"),
    )
    .await;
    assert!(out.ends_with("3 294"), "{out}");
    assert_eq!(s.up.handshakes.load(Ordering::SeqCst), 2);
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

/// The inspected hosts a client was recorded rejecting the session CA for, once the connection's
/// handler has had `wait` to run.
async fn ca_rejections_after(s: &Inspected, wait: Duration) -> Vec<(CanonicalHost, u16)> {
    let deadline = tokio::time::Instant::now() + wait;
    loop {
        let got = s.proxy.ca_rejections();
        if !got.is_empty() || tokio::time::Instant::now() >= deadline {
            return got;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

/// FW-FID9: a client that rejects the session CA is named, whichever way it rejects. One that
/// verifies in the handshake sends `unknown_ca`; one that verifies after it (curl 8.x on OpenSSL)
/// completes the handshake and aborts -- a reset, or an end without `close_notify` -- before
/// sending a byte. A client that closes with `close_notify`, or sends a request, is not counted.
#[tokio::test(flavor = "multi_thread")]
async fn fw_fid9_a_client_rejecting_the_session_ca_is_named() {
    let host = |s: &Inspected| vec![(CanonicalHost::Name("api.test".into()), s.up.port)];

    let s = inspected(&["get:api.test:{port}/**"], vec![]).await;
    let other = fixture_tls(&["api.test"]);
    let refused = tunnel(&s.proxy, &[other.root], &s.target("api.test"), "api.test").await;
    assert!(refused.is_none(), "the client trusts another root");
    assert_eq!(
        ca_rejections_after(&s, Duration::from_secs(5)).await,
        host(&s),
        "an unknown_ca alert in the handshake"
    );

    let s = inspected(&["get:api.test:{port}/**"], vec![]).await;
    let tls = s.tunnel("api.test").await;
    tls.get_ref().0.set_zero_linger().unwrap();
    drop(tls);
    assert_eq!(
        ca_rejections_after(&s, Duration::from_secs(5)).await,
        host(&s),
        "a reset after the handshake"
    );

    let s = inspected(&["get:api.test:{port}/**"], vec![]).await;
    let mut tls = s.tunnel("api.test").await;
    tls.get_mut().0.shutdown().await.unwrap();
    assert_eq!(
        ca_rejections_after(&s, Duration::from_secs(5)).await,
        host(&s),
        "an end without close_notify after the handshake"
    );

    let s = inspected(&["get:api.test:{port}/**"], vec![]).await;
    let mut tls = s.tunnel("api.test").await;
    tls.shutdown().await.unwrap();
    let mut rest = Vec::new();
    let _ = tls.read_to_end(&mut rest).await;
    let mut tls = s.tunnel("api.test").await;
    let ok = request(
        &mut tls,
        &format!("GET /x HTTP/1.1\r\n{}\r\n", s.host_header("api.test")),
    )
    .await;
    assert!(ok.starts_with("HTTP/1.1 200"), "{ok}");
    drop(tls);
    assert!(
        ca_rejections_after(&s, Duration::from_millis(500))
            .await
            .is_empty(),
        "a close_notify or a served request is not a rejection"
    );
}
