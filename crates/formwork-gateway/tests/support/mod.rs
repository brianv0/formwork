//! The egress test harness (FEP-1 test harness, FEP-6 §7.1): the real egress listener, driven over
//! real sockets against loopback fixture upstreams, with the fixture resolver as the only name
//! service (no DNS, no external network). Fixture upstreams record every handshake and request,
//! so each test asserts what crossed, and denials are asserted on violation records.

#![allow(dead_code)]

use std::collections::{BTreeMap, HashSet};
use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use formwork_blueprint::{HostRule, HostTable, RefusalReason};
use formwork_gateway::{
    Admission, Broker, EgressConfig, EgressProxy, Inspection, PeerCheck, Resolver, SessionCa,
    UpstreamProxy, Violation,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

pub const CREDENTIAL: &str = "test-nonce-0123456789";

pub fn rule(s: &str) -> HostRule {
    s.parse().unwrap()
}

pub fn resolver(entries: &[(&str, &str)]) -> Resolver {
    let mut map: BTreeMap<String, Vec<IpAddr>> = BTreeMap::new();
    for (name, ip) in entries {
        map.entry(name.to_string())
            .or_default()
            .push(ip.parse().unwrap());
    }
    Resolver::Fixture(map)
}

/// Everything a test varies about a session's egress.
pub struct Session {
    pub rules: Vec<String>,
    pub resolver: Resolver,
    pub registry: Option<Arc<Mutex<HashSet<u16>>>>,
    pub peer_check: Option<PeerCheck>,
    /// Roots the Gateway verifies upstreams against; inspection is on when this is set.
    pub upstream_roots: Option<Vec<CertificateDer<'static>>>,
    pub brokers: Vec<Broker>,
    pub host_addresses: Vec<IpAddr>,
    pub upstream_proxy: Option<UpstreamProxy>,
}

impl Session {
    pub fn new(rules: &[String], resolver: Resolver) -> Session {
        Session {
            rules: rules.to_vec(),
            resolver,
            registry: None,
            peer_check: None,
            upstream_roots: None,
            brokers: Vec::new(),
            host_addresses: Vec::new(),
            upstream_proxy: None,
        }
    }

    /// Start the listener; with upstream roots, also the session CA it inspects with.
    pub fn start(self) -> (EgressProxy, Option<Arc<SessionCa>>) {
        let table = HostTable::new(self.rules.iter().map(|r| rule(r)).collect());
        let ca = self.upstream_roots.as_ref().map(|_| {
            Arc::new(SessionCa::generate(&table.inspected_hosts()).expect("an inspected host"))
        });
        let inspection = match (&ca, &self.upstream_roots) {
            (Some(ca), Some(roots)) => Some(Inspection::new(ca.clone(), roots)),
            _ => None,
        };
        let proxy = EgressProxy::start(EgressConfig {
            table,
            resolver: self.resolver,
            admission: Admission {
                credential: CREDENTIAL.to_string(),
                registry: self.registry,
                peer_check: self.peer_check,
            },
            inspection,
            brokers: self.brokers,
            host_addresses: self.host_addresses,
            upstream_proxy: self.upstream_proxy,
        })
        .unwrap();
        (proxy, ca)
    }
}

pub fn proxy_auth() -> String {
    use base64::Engine as _;
    format!(
        "Basic {}",
        base64::engine::general_purpose::STANDARD.encode(format!("fw:{CREDENTIAL}"))
    )
}

pub fn reasons(proxy: &EgressProxy) -> Vec<RefusalReason> {
    proxy.violations().iter().map(|v| v.reason).collect()
}

pub fn violation_for<'a>(v: &'a [Violation], host: &str) -> Option<&'a Violation> {
    v.iter().find(|v| v.host.as_deref() == Some(host))
}

/// A fixture certificate authority: a self-signed certificate for `names`, which is its own root.
#[derive(Clone)]
pub struct FixtureTls {
    pub root: CertificateDer<'static>,
    config: Arc<rustls::ServerConfig>,
}

pub fn fixture_tls(names: &[&str]) -> FixtureTls {
    let key = rcgen::KeyPair::generate().unwrap();
    let params =
        rcgen::CertificateParams::new(names.iter().map(|n| n.to_string()).collect::<Vec<_>>())
            .unwrap();
    let cert = params.self_signed(&key).unwrap();
    let root = cert.der().clone();
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut config = rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![root.clone()],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der())),
        )
        .unwrap();
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    FixtureTls {
        root,
        config: Arc::new(config),
    }
}

/// One request an upstream fixture received: its head (request line and headers) and its body,
/// de-chunked.
#[derive(Clone, Debug)]
pub struct Seen {
    pub head: String,
    pub body: Vec<u8>,
}

impl Seen {
    pub fn header(&self, name: &str) -> Option<String> {
        self.head.lines().skip(1).find_map(|l| {
            let (n, v) = l.split_once(':')?;
            n.eq_ignore_ascii_case(name).then(|| v.trim().to_string())
        })
    }
}

/// An HTTP/1.1 upstream on loopback, over TLS or plain, that records every handshake and request
/// and answers by path:
///
/// - `/reflect`: echoes the request head in the body (`?in=header` also in a response header,
///   `?gzip=1` marks the body gzip-coded, `?split=1` writes it in two halves 50 ms apart);
/// - `/sse`: a server-sent-event stream of two events, the second sent only once the test calls
///   [`Upstream::ack`] (or after five seconds, which [`Upstream::acked`] then reports);
/// - `/ws`: `101 Switching Protocols` to an upgrade, then echoes every byte;
/// - `/sum`: answers with the body's length and checksum;
/// - `/bye`: answers as keep-alive, then closes the connection;
/// - anything else: `ok:<path>`.
#[derive(Clone)]
pub struct Upstream {
    pub port: u16,
    pub handshakes: Arc<AtomicUsize>,
    pub seen: Arc<Mutex<Vec<Seen>>>,
    ack: Arc<AtomicBool>,
    acked: Arc<AtomicBool>,
}

impl Upstream {
    pub fn seen(&self) -> Vec<Seen> {
        self.seen.lock().unwrap().clone()
    }

    pub fn ack(&self) {
        self.ack.store(true, Ordering::SeqCst);
    }

    /// Whether the SSE fixture's second event followed the test's ack, not the timeout.
    pub fn acked(&self) -> bool {
        self.acked.load(Ordering::SeqCst)
    }
}

pub async fn upstream(tls: Option<FixtureTls>) -> Upstream {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let up = Upstream {
        port: listener.local_addr().unwrap().port(),
        handshakes: Arc::new(AtomicUsize::new(0)),
        seen: Arc::new(Mutex::new(Vec::new())),
        ack: Arc::new(AtomicBool::new(false)),
        acked: Arc::new(AtomicBool::new(false)),
    };
    let fixture = up.clone();
    tokio::spawn(async move {
        loop {
            let Ok((tcp, _)) = listener.accept().await else {
                return;
            };
            let _ = tcp.set_nodelay(true);
            let fixture = fixture.clone();
            let tls = tls.clone();
            tokio::spawn(async move {
                match tls {
                    Some(t) => {
                        let acceptor = tokio_rustls::TlsAcceptor::from(t.config.clone());
                        if let Ok(stream) = acceptor.accept(tcp).await {
                            fixture.handshakes.fetch_add(1, Ordering::SeqCst);
                            serve_fixture(stream, fixture).await;
                        }
                    }
                    None => {
                        fixture.handshakes.fetch_add(1, Ordering::SeqCst);
                        serve_fixture(tcp, fixture).await;
                    }
                }
            });
        }
    });
    up
}

async fn read_more<S: AsyncRead + Unpin>(s: &mut S, buf: &mut Vec<u8>) -> bool {
    let mut chunk = [0u8; 16 * 1024];
    match s.read(&mut chunk).await {
        Ok(0) | Err(_) => false,
        Ok(n) => {
            buf.extend_from_slice(&chunk[..n]);
            true
        }
    }
}

async fn serve_fixture<S: AsyncRead + AsyncWrite + Unpin>(mut s: S, fixture: Upstream) {
    let mut buf = Vec::new();
    loop {
        let end = loop {
            if let Some(end) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                break end;
            }
            if !read_more(&mut s, &mut buf).await {
                return;
            }
        };
        let head = String::from_utf8_lossy(&buf[..end]).into_owned();
        buf.drain(..end + 4);
        let header = |name: &str| {
            head.lines().skip(1).find_map(|l| {
                let (n, v) = l.split_once(':')?;
                n.eq_ignore_ascii_case(name).then(|| v.trim().to_string())
            })
        };
        let mut body = Vec::new();
        if header("transfer-encoding").is_some() {
            loop {
                let line_end = loop {
                    if let Some(i) = buf.windows(2).position(|w| w == b"\r\n") {
                        break i;
                    }
                    if !read_more(&mut s, &mut buf).await {
                        return;
                    }
                };
                let size = usize::from_str_radix(
                    String::from_utf8_lossy(&buf[..line_end])
                        .split(';')
                        .next()
                        .unwrap_or("")
                        .trim(),
                    16,
                )
                .unwrap_or(0);
                buf.drain(..line_end + 2);
                while buf.len() < size + 2 {
                    if !read_more(&mut s, &mut buf).await {
                        return;
                    }
                }
                body.extend_from_slice(&buf[..size]);
                buf.drain(..size + 2);
                if size == 0 {
                    break;
                }
            }
        } else if let Some(len) = header("content-length").and_then(|v| v.parse::<usize>().ok()) {
            while buf.len() < len {
                if !read_more(&mut s, &mut buf).await {
                    return;
                }
            }
            body = buf.drain(..len).collect();
        }
        fixture.seen.lock().unwrap().push(Seen {
            head: head.clone(),
            body: body.clone(),
        });
        let target = head.split(' ').nth(1).unwrap_or("/").to_string();
        let (path, query) = target.split_once('?').unwrap_or((&target, ""));
        let respond = |extra: &str, body: &str| {
            format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n{extra}\r\n{body}",
                body.len()
            )
        };
        let ok = match path {
            "/reflect" => {
                let echoed = format!("echo:\n{head}\n");
                let mut extra = String::new();
                if query.contains("in=header") {
                    let key = header("x-api-key").unwrap_or_default();
                    extra.push_str(&format!("X-Echo: {key}\r\n"));
                }
                if query.contains("gzip=1") {
                    extra.push_str("Content-Encoding: gzip\r\n");
                }
                if query.contains("split=1") {
                    let whole = respond(&extra, &echoed);
                    let mid = whole
                        .find("x-api-key")
                        .map(|i| i + 14)
                        .unwrap_or(whole.len() / 2);
                    let (a, b) = whole.split_at(mid);
                    let first = s.write_all(a.as_bytes()).await.is_ok();
                    let _ = s.flush().await;
                    tokio::time::sleep(Duration::from_millis(50)).await;
                    first && s.write_all(b.as_bytes()).await.is_ok()
                } else {
                    s.write_all(respond(&extra, &echoed).as_bytes())
                        .await
                        .is_ok()
                }
            }
            "/sse" => {
                let _ = s
                    .write_all(
                        b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\n\
                          Transfer-Encoding: chunked\r\n\r\n",
                    )
                    .await;
                let event = |n: u8| format!("{:x}\r\ndata: {n}\n\n\r\n", 9);
                let _ = s.write_all(event(1).as_bytes()).await;
                let _ = s.flush().await;
                let deadline = std::time::Instant::now() + Duration::from_secs(5);
                while !fixture.ack.load(Ordering::SeqCst) && std::time::Instant::now() < deadline {
                    tokio::time::sleep(Duration::from_millis(5)).await;
                }
                fixture
                    .acked
                    .store(fixture.ack.load(Ordering::SeqCst), Ordering::SeqCst);
                let _ = s.write_all(event(2).as_bytes()).await;
                s.write_all(b"0\r\n\r\n").await.is_ok()
            }
            "/ws" if header("upgrade").is_some() => {
                let _ = s
                    .write_all(
                        b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n\
                          Connection: Upgrade\r\n\r\n",
                    )
                    .await;
                let _ = s.flush().await;
                if !buf.is_empty() {
                    let _ = s.write_all(&buf).await;
                }
                let mut chunk = [0u8; 4096];
                loop {
                    match s.read(&mut chunk).await {
                        Ok(0) | Err(_) => return,
                        Ok(n) => {
                            if s.write_all(&chunk[..n]).await.is_err() {
                                return;
                            }
                            let _ = s.flush().await;
                        }
                    }
                }
            }
            "/sum" => {
                let sum: u64 = body.iter().map(|b| *b as u64).sum();
                s.write_all(respond("", &format!("{} {sum}", body.len())).as_bytes())
                    .await
                    .is_ok()
            }
            "/bye" => {
                // Answered as keep-alive, then closed: the Gateway pools a connection the
                // upstream has already left.
                let _ = s.write_all(respond("", "bye").as_bytes()).await;
                let _ = s.flush().await;
                return;
            }
            _ => s
                .write_all(respond("", &format!("ok:{path}")).as_bytes())
                .await
                .is_ok(),
        };
        let _ = s.flush().await;
        if !ok {
            return;
        }
    }
}

/// Send `CONNECT target` through the proxy; the stream after `200`, or the whole refusal.
pub async fn connect(proxy: &EgressProxy, target: &str) -> Result<TcpStream, String> {
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
    let mut got = Vec::new();
    while !got.windows(4).any(|w| w == b"\r\n\r\n") {
        if !read_more(&mut tcp, &mut got).await {
            return Err(String::from_utf8_lossy(&got).into_owned());
        }
    }
    if got.starts_with(b"HTTP/1.1 200") {
        Ok(tcp)
    } else {
        let _ = tokio::time::timeout(Duration::from_secs(2), read_more(&mut tcp, &mut got)).await;
        Err(String::from_utf8_lossy(&got).into_owned())
    }
}

pub fn client_config(
    roots: &[CertificateDer<'static>],
    alpn: &[&[u8]],
) -> Arc<rustls::ClientConfig> {
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
    config.alpn_protocols = alpn.iter().map(|p| p.to_vec()).collect();
    Arc::new(config)
}

pub type Tls = tokio_rustls::client::TlsStream<TcpStream>;

/// CONNECT through the proxy and complete TLS as `sni`, trusting `roots`.
pub async fn tunnel(
    proxy: &EgressProxy,
    roots: &[CertificateDer<'static>],
    target: &str,
    sni: &str,
) -> Option<Tls> {
    let tcp = connect(proxy, target).await.ok()?;
    let connector = tokio_rustls::TlsConnector::from(client_config(roots, &[b"http/1.1"]));
    connector
        .connect(ServerName::try_from(sni.to_string()).unwrap(), tcp)
        .await
        .ok()
}

/// Send one request and read one response: by Content-Length, chunked to its last chunk, or to the
/// connection's end. An empty string means the connection ended with nothing.
pub async fn request<S: AsyncRead + AsyncWrite + Unpin>(s: &mut S, raw: &str) -> String {
    s.write_all(raw.as_bytes()).await.unwrap();
    s.flush().await.unwrap();
    read_response(s).await
}

pub async fn read_response<S: AsyncRead + Unpin>(s: &mut S) -> String {
    let mut out = Vec::new();
    loop {
        if let Some(end) = out.windows(4).position(|w| w == b"\r\n\r\n") {
            let head = String::from_utf8_lossy(&out[..end]).to_ascii_lowercase();
            if head.starts_with("http/1.1 1") && !head.starts_with("http/1.1 101") {
                // An interim response; the final one follows.
            } else if let Some(len) = head.lines().find_map(|l| {
                l.strip_prefix("content-length:")
                    .map(|v| v.trim().parse::<usize>().unwrap_or(0))
            }) {
                if out.len() >= end + 4 + len {
                    break;
                }
            } else if head.contains("transfer-encoding: chunked") {
                if out[end..].windows(5).any(|w| w == b"0\r\n\r\n") {
                    break;
                }
            } else if head.starts_with("http/1.1 101") {
                break;
            }
        }
        let more = tokio::time::timeout(Duration::from_secs(5), read_more(s, &mut out))
            .await
            .unwrap_or(false);
        if !more {
            break;
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// A CONNECT proxy fixture standing in for an operator's corporate proxy: it records each CONNECT
/// line and absolute-form request line, and forwards to the loopback address the name maps to.
pub struct CorporateProxy {
    pub port: u16,
    pub lines: Arc<Mutex<Vec<String>>>,
}

pub async fn corporate_proxy(ports: BTreeMap<String, u16>) -> CorporateProxy {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let lines = Arc::new(Mutex::new(Vec::new()));
    let log = lines.clone();
    tokio::spawn(async move {
        loop {
            let Ok((mut client, _)) = listener.accept().await else {
                return;
            };
            let log = log.clone();
            let ports = ports.clone();
            tokio::spawn(async move {
                let mut buf = Vec::new();
                while !buf.windows(4).any(|w| w == b"\r\n\r\n") {
                    if !read_more(&mut client, &mut buf).await {
                        return;
                    }
                }
                let end = buf.windows(4).position(|w| w == b"\r\n\r\n").unwrap();
                let head = String::from_utf8_lossy(&buf[..end]).into_owned();
                let line = head.lines().next().unwrap_or("").to_string();
                log.lock().unwrap().push(line.clone());
                let target = line.split(' ').nth(1).unwrap_or("");
                let authority = target
                    .strip_prefix("http://")
                    .map(|r| r.split('/').next().unwrap_or(""))
                    .unwrap_or(target);
                let host = authority
                    .rsplit_once(':')
                    .map(|(h, _)| h)
                    .unwrap_or(authority);
                let Some(port) = ports.get(host) else {
                    let _ = client.write_all(b"HTTP/1.1 502 Bad Gateway\r\n\r\n").await;
                    return;
                };
                let Ok(mut upstream) = TcpStream::connect(("127.0.0.1", *port)).await else {
                    return;
                };
                if line.starts_with("CONNECT ") {
                    buf.drain(..end + 4);
                    let _ = client
                        .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                        .await;
                } else {
                    let path = target
                        .strip_prefix("http://")
                        .and_then(|r| r.find('/').map(|i| r[i..].to_string()))
                        .unwrap_or_else(|| "/".into());
                    let rewritten = String::from_utf8_lossy(&buf)
                        .replacen(target, &path, 1)
                        .into_bytes();
                    buf = rewritten;
                }
                let _ = upstream.write_all(&buf).await;
                let _ = tokio::io::copy_bidirectional(&mut client, &mut upstream).await;
            });
        }
    });
    CorporateProxy { port, lines }
}
