//! Gateway egress E2E (FEP-1 Part A, FEP-5 §3.1): the real egress listener, driven over real
//! sockets against loopback fixture upstreams, with the fixture resolver as the only name service
//! (no DNS, no external network). Denials are asserted as violation records and refusals, never
//! by waiting on a timeout.

use std::collections::{BTreeMap, HashSet};
use std::io::{Read, Write};
use std::net::{IpAddr, SocketAddr, TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use formwork_blueprint::{HostRule, HostTable};
use formwork_gateway::{Admission, EgressConfig, EgressProxy, Resolver};

const CREDENTIAL: &str = "test-nonce-0123456789";

/// A loopback upstream that answers every connection with its name, as a plain HTTP response.
struct Fixture {
    port: u16,
}

impl Fixture {
    fn start(name: &'static str) -> Fixture {
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        std::thread::spawn(move || {
            for stream in listener.incoming().flatten() {
                std::thread::spawn(move || {
                    let mut stream = stream;
                    let _ = stream.set_read_timeout(Some(Duration::from_millis(500)));
                    let mut buf = [0u8; 4096];
                    let n = stream.read(&mut buf).unwrap_or(0);
                    let request = String::from_utf8_lossy(&buf[..n]).into_owned();
                    let first = request.lines().next().unwrap_or("").to_string();
                    let body = format!("fixture:{name} {first}");
                    let _ = write!(
                        stream,
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                        body.len()
                    );
                });
            }
        });
        Fixture { port }
    }
}

fn rule(s: &str) -> HostRule {
    serde_json::from_value(serde_json::Value::String(s.to_string())).unwrap()
}

fn fixture_resolver(entries: &[(&str, &str)]) -> Resolver {
    let mut map: BTreeMap<String, Vec<IpAddr>> = BTreeMap::new();
    for (name, ip) in entries {
        map.entry(name.to_string())
            .or_default()
            .push(ip.parse().unwrap());
    }
    Resolver::Fixture {
        map,
        loopback_upstreams: true,
    }
}

fn start(
    rules: &[String],
    resolver: Resolver,
    registry: Option<Arc<Mutex<HashSet<u16>>>>,
) -> EgressProxy {
    EgressProxy::start(EgressConfig {
        table: HostTable::new(rules.iter().map(|r| rule(r)).collect()),
        resolver,
        admission: Admission {
            credential: CREDENTIAL.to_string(),
            registry,
        },
    })
    .unwrap()
}

fn auth() -> String {
    // base64("fw:test-nonce-0123456789")
    let raw = format!("fw:{CREDENTIAL}");
    let table = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in raw.as_bytes().chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        out.push(table[(n >> 18) as usize & 63] as char);
        out.push(table[(n >> 12) as usize & 63] as char);
        out.push(if chunk.len() > 1 {
            table[(n >> 6) as usize & 63] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            table[n as usize & 63] as char
        } else {
            '='
        });
    }
    format!("Basic {out}")
}

/// Send one raw request head to the proxy and read everything it returns.
fn exchange(proxy: &EgressProxy, request: &str) -> String {
    let mut s = TcpStream::connect(proxy.addr()).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    s.write_all(request.as_bytes()).unwrap();
    let mut out = Vec::new();
    let _ = s.read_to_end(&mut out);
    String::from_utf8_lossy(&out).into_owned()
}

/// CONNECT, then (if admitted) send a request through the tunnel and read the fixture's answer.
fn connect_through(proxy: &EgressProxy, target: &str) -> String {
    exchange(
        proxy,
        &format!(
            "CONNECT {target} HTTP/1.1\r\nHost: {target}\r\nProxy-Authorization: {}\r\n\r\nGET / HTTP/1.1\r\nHost: x\r\n\r\n",
            auth()
        ),
    )
}

/// FW-E2E-029: the host allowlist admits one and refuses the rest, with a violation and no upstream
/// socket for the refused host.
#[test]
fn fw_e2e_029_host_allowlist_admits_one_denies_the_rest() {
    let allowed = Fixture::start("allowed");
    let blocked = Fixture::start("blocked");
    let proxy = start(
        &[format!("https:allowed.test:{}", allowed.port)],
        fixture_resolver(&[("allowed.test", "127.0.0.1"), ("blocked.test", "127.0.0.1")]),
        None,
    );
    let ok = connect_through(&proxy, &format!("allowed.test:{}", allowed.port));
    assert!(
        ok.starts_with("HTTP/1.1 200 Connection Established"),
        "{ok}"
    );
    assert!(ok.contains("fixture:allowed"), "{ok}");

    let refused = connect_through(&proxy, &format!("blocked.test:{}", blocked.port));
    assert!(refused.starts_with("HTTP/1.1 403"), "{refused}");
    assert!(
        !refused.contains("fixture:"),
        "no upstream bytes: {refused}"
    );
    assert!(
        !refused.contains("blocked.test") && refused.contains("denied by formwork policy"),
        "the client sees a generic refusal (FW-CRED7): {refused}"
    );
    let v = proxy.violations();
    assert_eq!(v.len(), 1, "{v:?}");
    assert!(v[0].target.contains("blocked.test"));
    assert!(
        v[0].explain
            .starts_with("formwork explain https://blocked.test"),
        "{v:?}"
    );
}

/// FW-E2E-030: an empty allowlist is full deny (the CVE-2025-66479 regression).
#[test]
fn fw_e2e_030_empty_allowlist_is_full_deny() {
    let fixture = Fixture::start("allowed");
    let proxy = start(
        &[],
        fixture_resolver(&[("allowed.test", "127.0.0.1")]),
        None,
    );
    let out = connect_through(&proxy, &format!("allowed.test:{}", fixture.port));
    assert!(out.starts_with("HTTP/1.1 403"), "{out}");
    assert_eq!(proxy.violations().len(), 1);
}

/// FW-E2E-031: metadata and private literals are refused under a broad wildcard that names neither.
#[test]
fn fw_e2e_031_metadata_and_private_addresses_blocked() {
    let proxy = start(
        &["https:*.test:80".into(), "https:169.254.169.254:81".into()],
        fixture_resolver(&[]),
        None,
    );
    for target in ["169.254.169.254:80", "10.0.0.1:80", "[fd00:ec2::254]:80"] {
        let out = connect_through(&proxy, target);
        assert!(out.starts_with("HTTP/1.1 403"), "{target}: {out}");
    }
    // Named explicitly by an IP-literal rule, a restricted address is admitted past policy (the
    // connect then fails, since nothing listens there -- a 502, not a 403).
    let named = connect_through(&proxy, "169.254.169.254:81");
    assert!(!named.starts_with("HTTP/1.1 403"), "{named}");
}

/// FW-ADV-007: the hostname bypass battery -- every variant is refused or canonicalizes to the
/// genuine name; none reaches the blocked fixture.
#[test]
fn fw_adv_007_hostname_bypass_battery() {
    let allowed = Fixture::start("allowed");
    let blocked = Fixture::start("blocked");
    let p = allowed.port;
    let proxy = start(
        &[format!("https:allowed.test:{p}")],
        fixture_resolver(&[("allowed.test", "127.0.0.1"), ("blocked.test", "127.0.0.2")]),
        None,
    );
    let _ = blocked;
    for target in [
        format!("allowed.test\\x00.blocked.test:{p}"),
        format!("allowed%2etest.blocked.test:{p}"),
        format!("blocked.test#.allowed.test:{p}"),
        format!("[::ffff:127.0.0.1%25allowed.test]:{p}"),
        format!("аllowed.test:{p}"),
    ] {
        let out = connect_through(&proxy, &target);
        assert!(!out.contains("fixture:blocked"), "{target}: {out}");
        assert!(
            out.starts_with("HTTP/1.1 403") || out.starts_with("HTTP/1.1 400"),
            "{target}: {out}"
        );
    }
    let trailing = connect_through(&proxy, &format!("allowed.test.:{p}"));
    assert!(
        trailing.contains("fixture:allowed"),
        "a trailing dot canonicalizes: {trailing}"
    );
}

/// FW-ADV-008: DNS rebinding -- an allowlisted name that resolves to a restricted address is
/// refused at the resolved IP, never connected.
#[test]
fn fw_adv_008_rebinding_to_a_blocked_ip_is_refused() {
    let proxy = start(
        &["https:allowed.test".into(), "https:private.test".into()],
        fixture_resolver(&[
            ("allowed.test", "169.254.169.254"),
            ("private.test", "10.0.0.5"),
        ]),
        None,
    );
    for target in ["allowed.test:443", "private.test:443"] {
        let out = connect_through(&proxy, target);
        assert!(out.starts_with("HTTP/1.1 403"), "{target}: {out}");
    }
    let v = proxy.violations();
    assert!(v.iter().all(|v| v.reason.contains("restricted")), "{v:?}");
}

/// FW-ADV-009 / FW-EGR9: no unauthenticated door. Without the credential the listener answers 407;
/// with a registry, a connection the supervisor did not register is dropped before any byte, and a
/// registered one is served.
#[test]
fn fw_adv_009_no_unauthenticated_door() {
    let fixture = Fixture::start("allowed");
    let rules = [format!("https:allowed.test:{}", fixture.port)];
    let resolver = || fixture_resolver(&[("allowed.test", "127.0.0.1")]);

    let open = start(&rules, resolver(), None);
    let no_cred = exchange(
        &open,
        &format!(
            "CONNECT allowed.test:{0} HTTP/1.1\r\nHost: allowed.test:{0}\r\n\r\n",
            fixture.port
        ),
    );
    assert!(no_cred.starts_with("HTTP/1.1 407"), "{no_cred}");

    let registry = Arc::new(Mutex::new(HashSet::new()));
    let gated = start(&rules, resolver(), Some(registry.clone()));
    let unregistered = connect_through(&gated, &format!("allowed.test:{}", fixture.port));
    assert!(
        unregistered.is_empty(),
        "an unregistered peer gets nothing: {unregistered:?}"
    );

    // Register a source port first, the way the supervisor does, then connect from it.
    let socket = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let port = socket.local_addr().unwrap().port();
    drop(socket);
    registry.lock().unwrap().insert(port);
    let stream = bind_and_connect(port, gated.addr());
    let mut stream = stream;
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    write!(
        stream,
        "CONNECT allowed.test:{0} HTTP/1.1\r\nHost: allowed.test:{0}\r\nProxy-Authorization: {1}\r\n\r\nGET / HTTP/1.1\r\n\r\n",
        fixture.port,
        auth()
    )
    .unwrap();
    let mut out = Vec::new();
    let _ = stream.read_to_end(&mut out);
    assert!(String::from_utf8_lossy(&out).contains("fixture:allowed"));
    assert!(
        !registry.lock().unwrap().contains(&port),
        "a registration is single-use"
    );
}

fn bind_and_connect(local_port: u16, to: SocketAddr) -> TcpStream {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(async {
        let socket = tokio::net::TcpSocket::new_v4().unwrap();
        socket.set_reuseaddr(true).unwrap();
        socket
            .bind(SocketAddr::from(([127, 0, 0, 1], local_port)))
            .unwrap();
        socket.connect(to).await.unwrap().into_std().unwrap()
    })
    .tap_blocking()
}

trait TapBlocking {
    fn tap_blocking(self) -> Self;
}
impl TapBlocking for TcpStream {
    fn tap_blocking(self) -> Self {
        self.set_nonblocking(false).unwrap();
        self
    }
}

/// Plain HTTP to an inspected host is decided by method and canonical path (FW-EGR10/EGR11), with
/// dot-segment traversal and request smuggling refused (FW-ADV-017's plain-HTTP half).
#[test]
fn plain_http_inspected_rules_decide_method_and_canonical_path() {
    let fixture = Fixture::start("api");
    let p = fixture.port;
    let proxy = start(
        &[format!("get:api.test:{p}/ok/**")],
        fixture_resolver(&[("api.test", "127.0.0.1")]),
        None,
    );
    let req = |method: &str, path: &str, extra: &str| {
        exchange(
            &proxy,
            &format!(
                "{method} http://api.test:{p}{path} HTTP/1.1\r\nHost: api.test:{p}\r\nProxy-Authorization: {}\r\n{extra}\r\n",
                auth()
            ),
        )
    };
    let ok = req("GET", "/ok/x", "");
    assert!(ok.contains("fixture:api GET /ok/x"), "{ok}");
    assert!(
        !ok.contains("Proxy-Authorization"),
        "the credential is not forwarded"
    );
    assert!(req("POST", "/ok/x", "").starts_with("HTTP/1.1 403"));
    assert!(req("GET", "/ok/../secret", "").starts_with("HTTP/1.1 403"));
    assert!(req("GET", "/ok/%2e%2e/secret", "").starts_with("HTTP/1.1 403"));
    assert!(req("GET", "/ok%2F..%2Fsecret", "").starts_with("HTTP/1.1 403"));
    let smuggle = req(
        "GET",
        "/ok/x",
        "Content-Length: 5\r\nTransfer-Encoding: chunked\r\n",
    );
    assert!(smuggle.starts_with("HTTP/1.1 403"), "{smuggle}");
}
