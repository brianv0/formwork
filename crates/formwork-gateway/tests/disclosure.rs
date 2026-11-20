//! Egress disclosure, FEP-12 phase A, through the real Gateway listener: the head search for the
//! derived markers (FW-EGR34), the bytes no search reads (FW-FID28) and the per-host account
//! (FW-FID29). Fixture upstreams record every request, so each test sees what crossed. Every test
//! here also searches the Gateway's log lines, at every level, and its records for the marker and
//! for each of its encodings: the marker's name may appear, its bytes may not (FEP-12 §5, its
//! draft invariant on markers).

mod support;

use std::io::Write;
use std::sync::{Arc, Mutex, Once};
use std::time::Duration;

use base64::Engine as _;
use formwork_blueprint::{BrokerScheme, CanonicalHost, RefusalReason};
use formwork_compile::Capability;
use formwork_gateway::{Broker, EgressProxy, Marker, SessionCa};
use support::*;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// What a stripped `GITHUB_TOKEN` held on the launching host.
const TOKEN: &str = "ghp_R3alT0kenValue/7c41+e9";
/// A stripped `NPM_TOKEN`: every byte a token byte, so it can be a header name or a host label.
const NPM: &str = "npm_tokenbytes0123";
const SECRET: &str = "sk-ant-BROKERED-9f2e1d";
const PLACEHOLDER: &str = "fwcred-anthropic-5e6f";

static LOG: Mutex<Vec<u8>> = Mutex::new(Vec::new());

struct Capture;

impl Write for Capture {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        LOG.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Every log line of this test binary, at every level and from every crate, into [`LOG`].
fn capture_logs() {
    static INIT: Once = Once::new();
    INIT.call_once(|| {
        tracing_subscriber::fmt()
            .with_env_filter("trace")
            .with_ansi(false)
            .with_writer(|| Capture)
            .init();
    });
}

/// The marker-encodings of `value` (FEP-12 §3.2) and every run of 8 of its raw bytes.
fn encodings(value: &str) -> Vec<Vec<u8>> {
    let v = value.as_bytes();
    let pct = |upper: bool| -> Vec<u8> {
        v.iter()
            .flat_map(|&b| {
                if b.is_ascii_alphanumeric() || b"-._~".contains(&b) {
                    vec![b]
                } else if upper {
                    format!("%{b:02X}").into_bytes()
                } else {
                    format!("%{b:02x}").into_bytes()
                }
            })
            .collect()
    };
    let hex: String = v.iter().map(|b| format!("{b:02x}")).collect();
    let json = serde_json::to_string(value).unwrap();
    let mut out = vec![
        pct(true),
        pct(false),
        hex.clone().into_bytes(),
        hex.to_ascii_uppercase().into_bytes(),
        json.as_bytes()[1..json.len() - 1].to_vec(),
    ];
    for engine in [
        base64::engine::general_purpose::STANDARD_NO_PAD,
        base64::engine::general_purpose::URL_SAFE_NO_PAD,
    ] {
        for lead in 0..3usize {
            let mut aligned = vec![0u8; lead];
            aligned.extend_from_slice(v);
            let text = engine.encode(&aligned).into_bytes();
            out.push(text[(lead * 8).div_ceil(6)..aligned.len() * 8 / 6].to_vec());
        }
    }
    out.extend(v.windows(8).map(<[u8]>::to_vec));
    out
}

/// The draft marker invariant over this binary's log and `proxy`'s records: no encoding of any of
/// `values` in either.
fn assert_withheld(proxy: &EgressProxy, values: &[&str]) {
    let mut surfaces = LOG.lock().unwrap().clone();
    for v in proxy.violations() {
        surfaces.extend(format!("{v:?}").bytes());
        surfaces.extend(serde_json::to_vec(&v).unwrap());
    }
    for g in proxy.grants() {
        surfaces.extend(format!("{g:?}").bytes());
    }
    for a in proxy.account(Duration::from_secs(2)) {
        surfaces.extend(serde_json::to_vec(&a).unwrap());
    }
    for value in values {
        for e in encodings(value) {
            assert!(
                !surfaces.windows(e.len()).any(|w| w == e.as_slice()),
                "{:?} (an encoding of a marker) is in a log line or record",
                String::from_utf8_lossy(&e)
            );
        }
    }
}

fn markers() -> Vec<Marker> {
    vec![
        Marker::stripped("GITHUB_TOKEN", TOKEN).unwrap(),
        Marker::stripped("NPM_TOKEN", NPM).unwrap(),
    ]
}

fn broker() -> Broker {
    Broker {
        name: "anthropic".into(),
        placeholder: PLACEHOLDER.into(),
        secret: SECRET.into(),
        bindings: vec![(
            CanonicalHost::Name("api.test".into()),
            BrokerScheme::Header("x-api-key".into()),
        )],
    }
}

struct Fixture {
    tls_up: Upstream,
    plain_up: Upstream,
    proxy: EgressProxy,
    ca: Arc<SessionCa>,
    /// The fixture's certificate, which a tunnelled client verifies.
    root: rustls::pki_types::CertificateDer<'static>,
}

impl Fixture {
    async fn start(markers: Vec<Marker>, brokers: Vec<Broker>) -> Fixture {
        capture_logs();
        let tls = fixture_tls(&["api.test", "other.test", "tunnel.test"]);
        let tls_up = upstream(Some(tls.clone())).await;
        let plain_up = upstream(None).await;
        let (t, p) = (tls_up.port, plain_up.port);
        let rules = [
            format!("allow:api.test:{t}"),
            format!("get:other.test:{t}/**"),
            format!("tunnel:tunnel.test:{t}"),
            format!("allow:plain.test:{p}"),
        ];
        let mut session = Session::new(
            &rules,
            resolver(&[
                ("api.test", "127.0.0.1"),
                ("other.test", "127.0.0.1"),
                ("tunnel.test", "127.0.0.1"),
                ("plain.test", "127.0.0.1"),
                ("blocked.test", "127.0.0.1"),
            ]),
        );
        session.upstream_roots = Some(vec![tls.root.clone()]);
        session.brokers = brokers;
        session.markers = markers;
        let (proxy, ca) = session.start();
        Fixture {
            tls_up,
            plain_up,
            proxy,
            ca: ca.unwrap(),
            root: tls.root,
        }
    }

    async fn inspected(&self, host: &str) -> Tls {
        let target = format!("{host}:{}", self.tls_up.port);
        tunnel(&self.proxy, &[self.ca.cert_der()], &target, host)
            .await
            .expect("an inspected tunnel")
    }

    /// One request over a fresh inspected connection to `host`; `head` is written against
    /// `{host}`, the Host field's value.
    async fn send(&self, host: &str, head: &str) -> String {
        let mut tls = self.inspected(host).await;
        let authority = format!("{host}:{}", self.tls_up.port);
        request(&mut tls, &head.replace("{host}", &authority)).await
    }

    /// One plain-HTTP request to `plain.test` straight to the listener; `head` names the request
    /// target and fields, without the proxy credential.
    async fn send_plain(&self, head: &str) -> String {
        let mut s = TcpStream::connect(self.proxy.addr()).await.unwrap();
        let head = head
            .replace("{host}", &format!("plain.test:{}", self.plain_up.port))
            .replacen(
                "\r\n",
                &format!("\r\nProxy-Authorization: {}\r\n", proxy_auth()),
                1,
            );
        let _ = s.write_all(head.as_bytes()).await;
        read_response(&mut s).await
    }
}

fn b64(text: &str) -> String {
    base64::engine::general_purpose::STANDARD.encode(text)
}

/// FW-E2E-172 (both): a stripped credential's value, and a brokered secret, sent by the session to
/// a granted host in any part of a request head and in any marker-encoding, is refused: the
/// upstream receives nothing, and the violation record carries `marker` and names the marker but
/// neither the request's method nor its path. Each request is paired with the same request
/// without the value, which is admitted. Plain HTTP and a CONNECT authority are searched too.
#[tokio::test(flavor = "multi_thread")]
async fn fw_e2e_172_a_derived_marker_in_a_request_head_is_refused() {
    // The Launcher registers a brokered secret as a marker beside the stripped values (FW-EGR33).
    let mut derived = markers();
    derived.extend(Marker::brokered(&broker()));
    let f = Fixture::start(derived, vec![broker()]).await;
    let hex: String = TOKEN.bytes().map(|b| format!("{b:02x}")).collect();
    let cases: Vec<(&str, String, String)> = vec![
        (
            "target",
            format!("GET /search?q={TOKEN} HTTP/1.1\r\nHost: {{host}}\r\n\r\n"),
            "GET /search?q=public HTTP/1.1\r\nHost: {host}\r\n\r\n".to_string(),
        ),
        (
            "target, one escape",
            format!(
                "GET /x?t=%67{} HTTP/1.1\r\nHost: {{host}}\r\n\r\n",
                TOKEN[1..].replace('/', "%2F").replace('+', "%2B")
            ),
            "GET /x?t=%67hp HTTP/1.1\r\nHost: {host}\r\n\r\n".to_string(),
        ),
        (
            "user-agent",
            format!("GET /a HTTP/1.1\r\nHost: {{host}}\r\nUser-Agent: agent/1.0 ({TOKEN})\r\n\r\n"),
            "GET /a HTTP/1.1\r\nHost: {host}\r\nUser-Agent: agent/1.0\r\n\r\n".to_string(),
        ),
        (
            "basic credentials",
            format!(
                "GET /b HTTP/1.1\r\nHost: {{host}}\r\nAuthorization: Basic {}\r\n\r\n",
                b64(&format!("x:{TOKEN}"))
            ),
            format!(
                "GET /b HTTP/1.1\r\nHost: {{host}}\r\nAuthorization: Basic {}\r\n\r\n",
                b64("x:public")
            ),
        ),
        (
            "hex",
            format!("GET /c HTTP/1.1\r\nHost: {{host}}\r\nX-Trace: {hex}\r\n\r\n"),
            "GET /c HTTP/1.1\r\nHost: {host}\r\nX-Trace: 00ff\r\n\r\n".to_string(),
        ),
        (
            "header name",
            format!("GET /d HTTP/1.1\r\nHost: {{host}}\r\nX-{NPM}: 1\r\n\r\n"),
            "GET /d HTTP/1.1\r\nHost: {host}\r\nX-Public: 1\r\n\r\n".to_string(),
        ),
        (
            "dot-segments",
            "GET /a/ghp_R3alT0kenValue/x/../7c41+e9 HTTP/1.1\r\nHost: {host}\r\n\r\n".to_string(),
            "GET /x/../public HTTP/1.1\r\nHost: {host}\r\n\r\n".to_string(),
        ),
        (
            "brokered secret",
            format!("GET /e HTTP/1.1\r\nHost: {{host}}\r\nX-Api-Key: {SECRET}\r\n\r\n"),
            format!("GET /e HTTP/1.1\r\nHost: {{host}}\r\nX-Api-Key: {PLACEHOLDER}\r\n\r\n"),
        ),
    ];
    for (i, (label, carrying, clean)) in cases.iter().enumerate() {
        let before = f.tls_up.seen().len();
        let refused = f.send("api.test", carrying).await;
        assert!(refused.starts_with("HTTP/1.1 403"), "{label}: {refused}");
        assert_eq!(
            f.tls_up.seen().len(),
            before,
            "{label}: the upstream got a head"
        );
        let v = f.proxy.violations();
        assert_eq!(v.len(), i + 1, "{label}: {v:?}");
        let last = v.last().unwrap();
        assert_eq!(last.reason, RefusalReason::Marker, "{label}");
        assert_eq!(last.capability, Capability::NetInspection, "{label}");
        assert_eq!(last.host.as_deref(), Some("api.test"), "{label}");
        assert!(
            last.method.is_none() && last.path.is_none(),
            "{label}: {last:?}"
        );
        assert!(
            last.rule
                .as_deref()
                .is_some_and(|r| r.starts_with("marker ")),
            "{label}: {last:?}"
        );

        let admitted = f.send("api.test", clean).await;
        assert!(admitted.starts_with("HTTP/1.1 200"), "{label}: {admitted}");
        assert_eq!(f.tls_up.seen().len(), before + 1, "{label}");
    }
    let names: Vec<String> = f
        .proxy
        .violations()
        .iter()
        .map(|v| v.detail.clone())
        .collect();
    for name in [
        "stripped:GITHUB_TOKEN",
        "stripped:NPM_TOKEN",
        "brokered:anthropic",
    ] {
        assert!(names.iter().any(|d| d.contains(name)), "{name}: {names:?}");
    }
    assert!(names[5].contains("a header name"), "{}", names[5]);

    // Plain HTTP: in the target the host may be the marker, so the record names none; in a
    // header it names the host.
    let n = f.proxy.violations().len();
    let refused = f
        .send_plain(&format!(
            "GET http://{{host}}/q?{TOKEN} HTTP/1.1\r\nHost: {{host}}\r\n\r\n"
        ))
        .await;
    assert!(refused.starts_with("HTTP/1.1 403"), "{refused}");
    let refused = f
        .send_plain(&format!(
            "GET http://{{host}}/q HTTP/1.1\r\nHost: {{host}}\r\nCookie: t={TOKEN}\r\n\r\n"
        ))
        .await;
    assert!(refused.starts_with("HTTP/1.1 403"), "{refused}");
    let admitted = f
        .send_plain("GET http://{host}/q HTTP/1.1\r\nHost: {host}\r\nCookie: t=1\r\n\r\n")
        .await;
    assert!(admitted.starts_with("HTTP/1.1 200"), "{admitted}");
    assert_eq!(f.plain_up.seen().len(), 1, "only the clean request crossed");
    let v = f.proxy.violations();
    assert_eq!(v.len(), n + 2);
    assert_eq!(v[n].reason, RefusalReason::Marker);
    assert_eq!(v[n].host, None, "{:?}", v[n]);
    assert_eq!(v[n + 1].host.as_deref(), Some("plain.test"));

    // A CONNECT authority is resolved and sent as the server name; one carrying the marker is
    // refused before either.
    let refused = connect(&f.proxy, &format!("{NPM}.tunnel.test:443")).await;
    assert!(refused.is_err_and(|r| r.starts_with("HTTP/1.1 403")));
    let v = f.proxy.violations();
    assert_eq!(v.last().unwrap().reason, RefusalReason::Marker);
    assert_eq!(v.last().unwrap().host, None);

    let log = String::from_utf8_lossy(&LOG.lock().unwrap()).into_owned();
    for line in [
        "egress refused (marker)",
        "stripped:GITHUB_TOKEN",
        "egress granted",
    ] {
        assert!(log.contains(line), "the capture holds no {line:?}");
    }
    assert_withheld(&f.proxy, &[TOKEN, NPM, SECRET]);
}

/// FW-E2E-174 (both): bytes the Gateway forwards without searching them -- a `tunnel:` host's, a
/// gzip-coded body, a stream after a WebSocket upgrade, and in phase A every request body, a body
/// cut short included -- are counted as **unscanned** for their host, and none of them produces a
/// record. The search reads heads only.
#[tokio::test(flavor = "multi_thread")]
async fn fw_e2e_174_unsearched_bytes_are_counted_per_host() {
    let f = Fixture::start(markers(), vec![]).await;
    let port = f.tls_up.port;

    // A tunnel: everything after the CONNECT, the ClientHello included, carrying the marker.
    let mut tls = tunnel(
        &f.proxy,
        std::slice::from_ref(&f.root),
        &format!("tunnel.test:{port}"),
        "tunnel.test",
    )
    .await
    .expect("a tunnel");
    let answer = request(
        &mut tls,
        &format!("GET /t?{TOKEN} HTTP/1.1\r\nHost: tunnel.test\r\nConnection: close\r\n\r\n"),
    )
    .await;
    assert!(answer.starts_with("HTTP/1.1 200"), "{answer}");
    drop(tls);

    // Bodies: gzip-coded, identity-coded, and one cut short after 100 of its 1,000 bytes.
    let gz = format!("{TOKEN}-pretend-this-is-gzip");
    let gzip = f
        .send(
            "api.test",
            &format!(
                "POST /sum HTTP/1.1\r\nHost: {{host}}\r\nContent-Encoding: gzip\r\nContent-Length: {}\r\n\r\n{gz}",
                gz.len()
            ),
        )
        .await;
    assert!(gzip.starts_with("HTTP/1.1 200"), "{gzip}");
    let plain_body = format!("body={TOKEN}");
    let identity = f
        .send(
            "api.test",
            &format!(
                "POST /sum HTTP/1.1\r\nHost: {{host}}\r\nContent-Length: {}\r\n\r\n{plain_body}",
                plain_body.len()
            ),
        )
        .await;
    assert!(identity.starts_with("HTTP/1.1 200"), "{identity}");
    let mut cut = f.inspected("api.test").await;
    cut.write_all(
        format!("POST /sum HTTP/1.1\r\nHost: api.test:{port}\r\nContent-Length: 1000\r\n\r\n")
            .as_bytes(),
    )
    .await
    .unwrap();
    cut.write_all(&[b'x'; 100]).await.unwrap();
    cut.flush().await.unwrap();
    tokio::time::sleep(Duration::from_millis(200)).await;
    drop(cut);

    // An upgrade: the frames after `101`.
    let mut ws = f.inspected("other.test").await;
    let head = request(
        &mut ws,
        &format!(
            "GET /ws HTTP/1.1\r\nHost: other.test:{port}\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n"
        ),
    )
    .await;
    assert!(head.starts_with("HTTP/1.1 101"), "{head}");
    let frame = format!("frame:{TOKEN}");
    ws.write_all(frame.as_bytes()).await.unwrap();
    let mut echoed = vec![0u8; frame.len()];
    ws.read_exact(&mut echoed).await.unwrap();
    drop(ws);

    let account = f.proxy.account(Duration::from_secs(2));
    let grants = f.proxy.grants();
    let up = |host: &str| -> u64 {
        grants
            .iter()
            .filter(|g| g.host == host)
            .map(|g| g.bytes_up)
            .sum()
    };
    let of = |host: &str| account.iter().find(|a| a.host == host).unwrap().clone();
    let tunnelled = of("tunnel.test");
    assert!(tunnelled.unscanned > (TOKEN.len() as u64), "{tunnelled:?}");
    assert_eq!(tunnelled.unscanned, up("tunnel.test"));
    assert_eq!(tunnelled.unscanned, tunnelled.bytes_up);
    let api = of("api.test");
    assert_eq!(
        api.unscanned,
        (gz.len() + plain_body.len() + 100) as u64,
        "{api:?}"
    );
    assert_eq!(api.bytes_up, api.unscanned);
    assert_eq!(api.requests, 3, "the cut request's head was forwarded");
    assert_eq!(of("other.test").unscanned, frame.len() as u64);
    assert!(
        reasons(&f.proxy)
            .iter()
            .all(|r| *r == RefusalReason::Malformed),
        "only the cut body may be refused: {:?}",
        f.proxy.violations()
    );
    assert!(account.iter().all(|a| a.disclosures == 0), "{account:?}");
    assert_withheld(&f.proxy, &[TOKEN, NPM]);
}

/// FW-E2E-175 (both): after a run that reached three hosts -- two inspected, one tunnelled -- and
/// was refused at a fourth, the account lists exactly the three with their request counts, bytes
/// both ways as the grant records sum them, grades, the header names the session sent, and the
/// one marker refusal among their requests; nothing for the refused host, and no header value.
#[tokio::test(flavor = "multi_thread")]
async fn fw_e2e_175_the_egress_account_lists_each_contacted_host() {
    let f = Fixture::start(markers(), vec![]).await;
    let port = f.tls_up.port;
    let ok = |r: &str| assert!(r.starts_with("HTTP/1.1 200"), "{r}");
    let mut api = f.inspected("api.test").await;
    let host = format!("api.test:{port}");
    ok(&request(
        &mut api,
        &format!("GET /one HTTP/1.1\r\nHost: {host}\r\nAccept: */*\r\nUser-Agent: probe/1\r\n\r\n"),
    )
    .await);
    ok(&request(
        &mut api,
        &format!("POST /sum HTTP/1.1\r\nHost: {host}\r\nContent-Length: 5\r\nX-Request-Id: hidden-value\r\n\r\nhello"),
    )
    .await);
    drop(api);
    let refused = f
        .send(
            "api.test",
            &format!("GET /x HTTP/1.1\r\nHost: {{host}}\r\nUser-Agent: {TOKEN}\r\n\r\n"),
        )
        .await;
    assert!(refused.starts_with("HTTP/1.1 403"), "{refused}");
    ok(&f
        .send("other.test", "GET /two HTTP/1.1\r\nHost: {host}\r\n\r\n")
        .await);
    let refused_path = f
        .send(
            "other.test",
            "POST /no HTTP/1.1\r\nHost: {host}\r\nX-Refused: 1\r\n\r\n",
        )
        .await;
    assert!(refused_path.starts_with("HTTP/1.1 403"), "{refused_path}");
    let mut t = tunnel(
        &f.proxy,
        std::slice::from_ref(&f.root),
        &format!("tunnel.test:{port}"),
        "tunnel.test",
    )
    .await
    .expect("a tunnel");
    ok(&request(
        &mut t,
        "GET /three HTTP/1.1\r\nHost: tunnel.test\r\nConnection: close\r\n\r\n",
    )
    .await);
    drop(t);
    assert!(connect(&f.proxy, &format!("blocked.test:{port}"))
        .await
        .is_err());
    // A host whose one request carried a marker received nothing, so it has no entry either.
    let refused_plain = f
        .send_plain(&format!(
            "GET http://{{host}}/p HTTP/1.1\r\nHost: {{host}}\r\nCookie: {TOKEN}\r\n\r\n"
        ))
        .await;
    assert!(refused_plain.starts_with("HTTP/1.1 403"), "{refused_plain}");

    let account = f.proxy.account(Duration::from_secs(2));
    let hosts: Vec<&str> = account.iter().map(|a| a.host.as_str()).collect();
    assert_eq!(
        hosts,
        vec!["api.test", "other.test", "tunnel.test"],
        "{account:?}"
    );
    let grants = f.proxy.grants();
    for a in &account {
        let mine = grants.iter().filter(|g| g.host == a.host);
        assert_eq!(
            a.bytes_up,
            mine.clone().map(|g| g.bytes_up).sum::<u64>(),
            "{a:?}"
        );
        assert_eq!(
            a.bytes_down,
            mine.map(|g| g.bytes_down).sum::<u64>(),
            "{a:?}"
        );
        assert!(a.bytes_down > 0, "{a:?}");
        assert_eq!(a.port, port);
    }
    let (api, other, tunnelled) = (&account[0], &account[1], &account[2]);
    assert_eq!(api.requests, 2, "the refused request is not one");
    assert_eq!(api.grades, vec!["inspected"]);
    assert_eq!(api.disclosures, 1);
    assert_eq!(
        api.header_names,
        vec![
            "accept",
            "content-length",
            "host",
            "user-agent",
            "x-request-id"
        ]
    );
    assert_eq!(other.requests, 1);
    assert_eq!(other.header_names, vec!["host"]);
    assert_eq!(other.disclosures, 0);
    assert_eq!(tunnelled.grades, vec!["tunnel"]);
    assert_eq!(tunnelled.requests, 1);
    assert!(tunnelled.header_names.is_empty());
    let json = serde_json::to_string(&account).unwrap();
    for hidden in [
        "hidden-value",
        "probe/1",
        "/one",
        "x-refused",
        "blocked.test",
        "plain.test",
        "cookie",
    ] {
        assert!(!json.contains(hidden), "{hidden} is in the account: {json}");
    }
    assert_withheld(&f.proxy, &[TOKEN, NPM]);
}
