//! Inspected egress (FW-EGR10/EGR11, FW-CRED11, FW-INV13) through the real Gateway listener: a
//! rustls client that trusts only the session CA, CONNECTs through the listener, and speaks HTTP/1.1
//! to a real TLS fixture upstream whose certificate the Gateway trusts through the fixture-roots
//! input. The upstream records every request it receives, so the tests see exactly what crossed.

use std::collections::{BTreeMap, HashSet};
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use formwork_blueprint::{BrokerScheme, CanonicalHost, HostRule, HostTable};
use formwork_gateway::{
    Admission, Broker, EgressConfig, EgressProxy, Inspection, Resolver, SessionCa,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

const CREDENTIAL: &str = "inspect-nonce";
const SECRET: &str = "sk-ant-REAL-SECRET-0001";
const PLACEHOLDER: &str = "fwcred-anthropic-abc123";

/// A TLS upstream for `api.test` that records each request head and answers with a body that
/// echoes the request's headers (so a leaked credential would come back to the client).
struct Upstream {
    port: u16,
    cert: CertificateDer<'static>,
    seen: Arc<Mutex<Vec<String>>>,
}

async fn upstream() -> Upstream {
    let key = rcgen::KeyPair::generate().unwrap();
    let params = rcgen::CertificateParams::new(vec!["api.test".to_string()]).unwrap();
    let cert = params.self_signed(&key).unwrap();
    let der = cert.der().clone();
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let config = rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![der.clone()],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der())),
        )
        .unwrap();
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let log = seen.clone();
    tokio::spawn(async move {
        loop {
            let Ok((tcp, _)) = listener.accept().await else {
                return;
            };
            let acceptor = acceptor.clone();
            let log = log.clone();
            tokio::spawn(async move {
                let Ok(mut tls) = acceptor.accept(tcp).await else {
                    return;
                };
                let mut buf = Vec::new();
                loop {
                    let mut chunk = [0u8; 4096];
                    let n = match tls.read(&mut chunk).await {
                        Ok(0) | Err(_) => return,
                        Ok(n) => n,
                    };
                    buf.extend_from_slice(&chunk[..n]);
                    while let Some(end) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                        let head = String::from_utf8_lossy(&buf[..end]).into_owned();
                        let len: usize = head
                            .lines()
                            .find_map(|l| {
                                l.to_ascii_lowercase()
                                    .strip_prefix("content-length:")
                                    .map(|v| v.trim().parse().unwrap_or(0))
                            })
                            .unwrap_or(0);
                        while buf.len() < end + 4 + len {
                            let n = tls.read(&mut chunk).await.unwrap_or(0);
                            if n == 0 {
                                return;
                            }
                            buf.extend_from_slice(&chunk[..n]);
                        }
                        buf.drain(..end + 4 + len);
                        log.lock().unwrap().push(head.clone());
                        let body = format!("echo:\n{head}\n");
                        let resp = format!(
                            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nX-Echo-Auth: {}\r\n\r\n{body}",
                            body.len(),
                            head.lines().find(|l| l.to_ascii_lowercase().starts_with("x-api-key")).unwrap_or("none")
                        );
                        if tls.write_all(resp.as_bytes()).await.is_err() {
                            return;
                        }
                    }
                }
            });
        }
    });
    Upstream {
        port,
        cert: der,
        seen,
    }
}

fn rule(s: &str) -> HostRule {
    serde_json::from_value(serde_json::Value::String(s.to_string())).unwrap()
}

fn start(rules: &[String], up: &Upstream, ca: Arc<SessionCa>, brokers: Vec<Broker>) -> EgressProxy {
    let mut map: BTreeMap<String, Vec<IpAddr>> = BTreeMap::new();
    map.insert("api.test".into(), vec!["127.0.0.1".parse().unwrap()]);
    map.insert("other.test".into(), vec!["127.0.0.1".parse().unwrap()]);
    EgressProxy::start(EgressConfig {
        table: HostTable::new(rules.iter().map(|r| rule(r)).collect()),
        resolver: Resolver::Fixture {
            map,
            loopback_upstreams: true,
        },
        admission: Admission {
            credential: CREDENTIAL.into(),
            registry: None::<Arc<Mutex<HashSet<u16>>>>,
        },
        inspection: Some(Inspection::new(ca, std::slice::from_ref(&up.cert))),
        brokers,
    })
    .unwrap()
}

fn proxy_auth() -> String {
    use base64::Engine as _;
    let raw = format!("fw:{CREDENTIAL}");
    format!(
        "Basic {}",
        base64::engine::general_purpose::STANDARD.encode(raw)
    )
}

/// CONNECT through the proxy and complete TLS as `sni`, trusting only the session CA.
async fn tunnel(
    proxy: &EgressProxy,
    ca: &SessionCa,
    target: &str,
    sni: &str,
) -> Option<tokio_rustls::client::TlsStream<TcpStream>> {
    let mut tcp = TcpStream::connect(proxy.addr()).await.unwrap();
    tcp.write_all(
        format!(
            "CONNECT {target} HTTP/1.1\r\nHost: {target}\r\nProxy-Authorization: {}\r\n\r\n",
            proxy_auth()
        )
        .as_bytes(),
    )
    .await
    .unwrap();
    let mut buf = [0u8; 256];
    let mut got = Vec::new();
    while !got.windows(4).any(|w| w == b"\r\n\r\n") {
        let n = tcp.read(&mut buf).await.unwrap();
        if n == 0 {
            return None;
        }
        got.extend_from_slice(&buf[..n]);
    }
    if !got.starts_with(b"HTTP/1.1 200") {
        return None;
    }
    let mut roots = rustls::RootCertStore::empty();
    roots.add(ca.cert_der()).unwrap();
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let config = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let connector = tokio_rustls::TlsConnector::from(Arc::new(config));
    connector
        .connect(ServerName::try_from(sni.to_string()).unwrap(), tcp)
        .await
        .ok()
}

/// Send one request and read one response (by Content-Length), or the connection's end.
async fn request(tls: &mut tokio_rustls::client::TlsStream<TcpStream>, raw: &str) -> String {
    tls.write_all(raw.as_bytes()).await.unwrap();
    let mut out = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        let n = tokio::time::timeout(Duration::from_secs(5), tls.read(&mut chunk))
            .await
            .map(|r| r.unwrap_or(0))
            .unwrap_or(0);
        if n == 0 {
            break;
        }
        out.extend_from_slice(&chunk[..n]);
        if let Some(end) = out.windows(4).position(|w| w == b"\r\n\r\n") {
            let head = String::from_utf8_lossy(&out[..end]).to_ascii_lowercase();
            if let Some(len) = head.lines().find_map(|l| {
                l.strip_prefix("content-length:")
                    .map(|v| v.trim().parse::<usize>().unwrap_or(0))
            }) {
                if out.len() >= end + 4 + len {
                    break;
                }
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// FW-E2E-077: under `post:api.test/repos/acme/**` a POST inside the scope passes; a POST outside
/// it and a GET inside it are refused with a generic 403, the operator record naming the rule.
#[tokio::test(flavor = "multi_thread")]
async fn fw_e2e_077_inspected_path_scope() {
    let up = upstream().await;
    let ca = Arc::new(SessionCa::generate().unwrap());
    let proxy = start(
        &[format!("post:api.test:{}/repos/acme/**", up.port)],
        &up,
        ca.clone(),
        vec![],
    );
    let target = format!("api.test:{}", up.port);
    let host = format!("Host: api.test:{}\r\n", up.port);

    let mut tls = tunnel(&proxy, &ca, &target, "api.test")
        .await
        .expect("tunnel");
    let ok = request(
        &mut tls,
        &format!("POST /repos/acme/x HTTP/1.1\r\n{host}Content-Length: 2\r\n\r\nhi"),
    )
    .await;
    assert!(ok.starts_with("HTTP/1.1 200"), "{ok}");
    // Keep-alive: a second request on the same connection is decided on its own.
    let refused = request(
        &mut tls,
        &format!("POST /repos/other/x HTTP/1.1\r\n{host}Content-Length: 0\r\n\r\n"),
    )
    .await;
    assert!(refused.starts_with("HTTP/1.1 403"), "{refused}");
    assert!(
        !refused.contains("repos/acme"),
        "the 403 body names no rule"
    );

    let mut tls = tunnel(&proxy, &ca, &target, "api.test")
        .await
        .expect("tunnel");
    let get = request(
        &mut tls,
        &format!("GET /repos/acme/x HTTP/1.1\r\n{host}\r\n"),
    )
    .await;
    assert!(get.starts_with("HTTP/1.1 403"), "{get}");
    let seen = up.seen.lock().unwrap().clone();
    assert_eq!(
        seen.len(),
        1,
        "only the admitted request reached the upstream: {seen:?}"
    );
    let v = proxy.violations();
    assert!(
        v.iter().any(|v| v.target.contains("/repos/other/x")),
        "{v:?}"
    );
}

/// FW-ADV-017 (TLS path): traversal and smuggling against an inspected rule never reach
/// `/repos/other`.
#[tokio::test(flavor = "multi_thread")]
async fn fw_adv_017_traversal_against_an_inspected_rule() {
    let up = upstream().await;
    let ca = Arc::new(SessionCa::generate().unwrap());
    let proxy = start(
        &[format!("post:api.test:{}/repos/acme/**", up.port)],
        &up,
        ca.clone(),
        vec![],
    );
    let target = format!("api.test:{}", up.port);
    let host = format!("Host: api.test:{}\r\n", up.port);
    for path in [
        "/repos/acme/../other/x",
        "/repos/acme/%2e%2e/other/x",
        "/repos/acme%2F..%2Fother/x",
    ] {
        let mut tls = tunnel(&proxy, &ca, &target, "api.test")
            .await
            .expect("tunnel");
        let out = request(
            &mut tls,
            &format!("POST {path} HTTP/1.1\r\n{host}Content-Length: 0\r\n\r\n"),
        )
        .await;
        assert!(out.starts_with("HTTP/1.1 403"), "{path}: {out}");
    }
    let mut tls = tunnel(&proxy, &ca, &target, "api.test")
        .await
        .expect("tunnel");
    let smuggle = request(
        &mut tls,
        &format!("POST /repos/acme/x HTTP/1.1\r\n{host}Content-Length: 4\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n"),
    )
    .await;
    assert!(smuggle.starts_with("HTTP/1.1 403"), "{smuggle}");
    assert!(
        up.seen
            .lock()
            .unwrap()
            .iter()
            .all(|h| !h.contains("/repos/other")),
        "nothing reached /repos/other"
    );
}

/// FW-EGR10: the Host header and the SNI must match the CONNECT target.
#[tokio::test(flavor = "multi_thread")]
async fn fw_egr10_host_and_sni_must_agree_with_the_target() {
    let up = upstream().await;
    let ca = Arc::new(SessionCa::generate().unwrap());
    let proxy = start(
        &[format!("any:api.test:{}", up.port)],
        &up,
        ca.clone(),
        vec![],
    );
    let target = format!("api.test:{}", up.port);
    let mut tls = tunnel(&proxy, &ca, &target, "api.test")
        .await
        .expect("tunnel");
    let wrong_host = request(&mut tls, "GET / HTTP/1.1\r\nHost: other.test\r\n\r\n").await;
    assert!(wrong_host.starts_with("HTTP/1.1 403"), "{wrong_host}");
    // A client that names another host in its SNI is refused (it gets a leaf for api.test, and does
    // not verify it for other.test, so the handshake itself fails).
    assert!(tunnel(&proxy, &ca, &target, "other.test").await.is_none());
    assert!(up.seen.lock().unwrap().is_empty());
}

/// FW-E2E-078: a brokered credential. The upstream receives the real credential in `x-api-key`
/// (substituted for the placeholder, and added when absent); the client never sees its bytes, even
/// where the upstream echoes the header back (FW-INV13); the placeholder sent to another host is
/// refused.
#[tokio::test(flavor = "multi_thread")]
async fn fw_e2e_078_brokered_header_is_presented_and_never_disclosed() {
    let up = upstream().await;
    let ca = Arc::new(SessionCa::generate().unwrap());
    let api = CanonicalHost::Name("api.test".into());
    let brokers = vec![Broker {
        name: "anthropic".into(),
        placeholder: PLACEHOLDER.into(),
        secret: SECRET.into(),
        bindings: vec![(api, BrokerScheme::Header("x-api-key".into()))],
    }];
    let proxy = start(
        &[
            format!("any:api.test:{}", up.port),
            format!("any:other.test:{}", up.port),
        ],
        &up,
        ca.clone(),
        brokers,
    );
    let host = format!("Host: api.test:{}\r\n", up.port);
    let mut tls = tunnel(&proxy, &ca, &format!("api.test:{}", up.port), "api.test")
        .await
        .expect("tunnel");
    let with_placeholder = request(
        &mut tls,
        &format!("GET /v1 HTTP/1.1\r\n{host}x-api-key: {PLACEHOLDER}\r\n\r\n"),
    )
    .await;
    assert!(
        with_placeholder.starts_with("HTTP/1.1 200"),
        "{with_placeholder}"
    );
    let without = request(&mut tls, &format!("GET /v2 HTTP/1.1\r\n{host}\r\n")).await;
    assert!(without.starts_with("HTTP/1.1 200"), "{without}");
    for out in [&with_placeholder, &without] {
        assert!(
            !out.contains(SECRET),
            "the credential leaked back to the client: {out}"
        );
        assert!(
            out.contains(&"*".repeat(SECRET.len())),
            "the echo is masked: {out}"
        );
    }
    let seen = up.seen.lock().unwrap().clone();
    assert_eq!(seen.len(), 2);
    for head in &seen {
        assert!(head.contains(&format!("x-api-key: {SECRET}")), "{head}");
        assert!(!head.contains(PLACEHOLDER));
    }

    let mut other = tunnel(
        &proxy,
        &ca,
        &format!("other.test:{}", up.port),
        "other.test",
    )
    .await
    .expect("tunnel");
    let leak = request(
        &mut other,
        &format!(
            "GET / HTTP/1.1\r\nHost: other.test:{}\r\nx-api-key: {PLACEHOLDER}\r\n\r\n",
            up.port
        ),
    )
    .await;
    assert!(leak.starts_with("HTTP/1.1 403"), "{leak}");
    assert_eq!(
        up.seen.lock().unwrap().len(),
        2,
        "the placeholder never reached other.test"
    );
    assert!(proxy
        .violations()
        .iter()
        .any(|v| v.reason.contains("placeholder")));
}
