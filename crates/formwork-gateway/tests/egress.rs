//! Gateway egress E2E (FEP-1 Part A, FEP-5 §3.1, FEP-6): the front door, the tunnel grade, the
//! destination classes and the parser, through the real egress listener against loopback fixture
//! upstreams. Denials are asserted on violation records, never by waiting on a timeout.

mod support;

use std::collections::{BTreeMap, HashSet};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use formwork_blueprint::RefusalReason;
use formwork_gateway::UpstreamProxy;
use rustls::pki_types::ServerName;
use support::*;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// Send raw bytes to the listener and read one response, or nothing if it closes first.
async fn raw(proxy: &formwork_gateway::EgressProxy, bytes: &[u8]) -> String {
    let mut s = TcpStream::connect(proxy.addr()).await.unwrap();
    // A refusal can close the socket before an oversized head is all written.
    let _ = s.write_all(bytes).await;
    read_response(&mut s).await
}

fn with_auth(head: &str) -> String {
    head.replacen(
        "\r\n",
        &format!("\r\nProxy-Authorization: {}\r\n", proxy_auth()),
        1,
    )
}

/// FW-E2E-029: the host allowlist admits one host and refuses the rest, with a violation and no
/// upstream socket for the refused host.
#[tokio::test(flavor = "multi_thread")]
async fn fw_e2e_029_host_allowlist_admits_one_denies_the_rest() {
    let tls = fixture_tls(&["allowed.test"]);
    let allowed = upstream(Some(tls.clone())).await;
    let blocked = upstream(Some(fixture_tls(&["blocked.test"]))).await;
    let (proxy, _) = Session::new(
        &[format!("tunnel:allowed.test:{}", allowed.port)],
        resolver(&[("allowed.test", "127.0.0.1"), ("blocked.test", "127.0.0.1")]),
    )
    .start();
    let mut t = tunnel(
        &proxy,
        std::slice::from_ref(&tls.root),
        &format!("allowed.test:{}", allowed.port),
        "allowed.test",
    )
    .await
    .expect("the tunnel carries the client's own TLS");
    let ok = request(&mut t, "GET /ok HTTP/1.1\r\nHost: allowed.test\r\n\r\n").await;
    assert!(ok.ends_with("ok:/ok"), "{ok}");

    let refused = connect(&proxy, &format!("blocked.test:{}", blocked.port))
        .await
        .unwrap_err();
    assert!(refused.starts_with("HTTP/1.1 403"), "{refused}");
    assert!(
        !refused.contains("blocked.test") && refused.contains("denied by formwork policy"),
        "the client sees a generic refusal (FW-CRED7): {refused}"
    );
    assert_eq!(
        blocked.handshakes.load(std::sync::atomic::Ordering::SeqCst),
        0
    );
    let v = proxy.violations();
    assert_eq!(v.len(), 1, "{v:?}");
    assert_eq!(v[0].reason, RefusalReason::HostNotListed);
    assert_eq!(v[0].host.as_deref(), Some("blocked.test"));
    assert!(
        v[0].explain
            .starts_with("formwork explain https://blocked.test"),
        "{v:?}"
    );
    // FW-FID13: the admitted tunnel is a grant record with its byte counts.
    tokio::time::sleep(Duration::from_millis(50)).await;
    drop(t);
    tokio::time::sleep(Duration::from_millis(100)).await;
    let grants = proxy.grants();
    assert!(
        grants
            .iter()
            .any(|g| g.grade == "tunnel" && g.host == "allowed.test" && g.bytes_up > 0),
        "{grants:?}"
    );
}

/// FW-E2E-030: an empty allowlist is full deny (the CVE-2025-66479 regression).
#[tokio::test(flavor = "multi_thread")]
async fn fw_e2e_030_empty_allowlist_is_full_deny() {
    let (proxy, _) = Session::new(&[], resolver(&[("allowed.test", "127.0.0.1")])).start();
    let out = connect(&proxy, "allowed.test:443").await.unwrap_err();
    assert!(out.starts_with("HTTP/1.1 403"), "{out}");
    assert_eq!(reasons(&proxy), vec![RefusalReason::HostNotListed]);
}

/// FW-EGR16 / FW-ADV-022: a tunnel forwards only a ClientHello whose server name is the CONNECT
/// host, and only TLS. The tests named for FW-EGR10 and FW-EGR20 in `inspect.rs` carry the rest
/// of FW-ADV-022.
#[tokio::test(flavor = "multi_thread")]
async fn fw_egr16_a_tunnel_checks_the_server_name_and_carries_tls_only() {
    let tls = fixture_tls(&["allowed.test", "blocked.test"]);
    let up = upstream(Some(tls.clone())).await;
    let target = format!("allowed.test:{}", up.port);
    let (proxy, _) = Session::new(
        &[format!("tunnel:{target}")],
        resolver(&[("allowed.test", "127.0.0.1")]),
    )
    .start();
    assert!(
        tunnel(
            &proxy,
            std::slice::from_ref(&tls.root),
            &target,
            "blocked.test"
        )
        .await
        .is_none(),
        "a ClientHello for another name is refused"
    );
    let mut plain = connect(&proxy, &target).await.unwrap();
    let out = request(&mut plain, "GET / HTTP/1.1\r\nHost: allowed.test\r\n\r\n").await;
    assert!(out.is_empty(), "nothing but TLS crosses a tunnel: {out}");
    let mut truncated = connect(&proxy, &target).await.unwrap();
    truncated.write_all(&[0x16, 3, 1, 0, 200, 1]).await.unwrap();
    truncated.shutdown().await.unwrap();
    let mut rest = Vec::new();
    let _ = truncated.read_to_end(&mut rest).await;
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(
        reasons(&proxy),
        vec![
            RefusalReason::SniMismatch,
            RefusalReason::NotTls,
            RefusalReason::Malformed
        ]
    );
    assert_eq!(up.handshakes.load(std::sync::atomic::Ordering::SeqCst), 0);
    assert!(up.seen().is_empty());
}

/// FW-ADV-023 / FW-EGR17-19: under a wildcard, no answer outside the global class is reached --
/// metadata, private, loopback, special-purpose, IPv4 embedded in IPv6, a public address mixed
/// with a private one, or an address of the host's own interfaces. An exact name may reach a
/// loopback fixture, never a metadata address.
#[tokio::test(flavor = "multi_thread")]
async fn fw_adv_023_address_classes() {
    let cases = [
        ("loopback.test", "127.0.0.1"),
        ("private.test", "10.0.0.1"),
        ("alibaba.test", "100.100.100.200"),
        ("wireserver.test", "168.63.129.16"),
        ("mapped.test", "::ffff:169.254.169.254"),
        ("nat64.test", "64:ff9b::a9fe:a9fe"),
        ("sixtofour.test", "2002:a9fe:a9fe::1"),
        ("linklocal.test", "fe80::1"),
        ("documentation.test", "198.51.100.7"),
        ("self.test", "203.0.113.50"),
    ];
    let mut entries: Vec<(&str, &str)> = cases.to_vec();
    entries.push(("mixed.test", "93.184.216.34"));
    entries.push(("mixed.test", "10.0.0.1"));
    let mut session = Session::new(&["allow:*.test".to_string()], resolver(&entries));
    session.host_addresses = vec!["203.0.113.50".parse().unwrap()];
    session.upstream_roots = Some(Vec::new());
    let (proxy, _) = session.start();
    for (name, _) in cases.iter().chain([("mixed.test", "")].iter()) {
        let out = connect(&proxy, &format!("{name}:443")).await.unwrap_err();
        assert!(out.starts_with("HTTP/1.1 403"), "{name}: {out}");
    }
    let v = proxy.violations();
    assert_eq!(v.len(), cases.len() + 1, "{v:?}");
    assert!(
        v.iter().all(|v| v.reason == RefusalReason::AddressClass),
        "{v:?}"
    );

    let up = upstream(Some(fixture_tls(&["allowed.test"]))).await;
    let (exact, _) = Session::new(
        &[
            format!("tunnel:allowed.test:{}", up.port),
            format!("tunnel:meta.test:{}", up.port),
        ],
        resolver(&[
            ("allowed.test", "127.0.0.1"),
            ("meta.test", "169.254.169.254"),
        ]),
    )
    .start();
    let _held = connect(&exact, &format!("allowed.test:{}", up.port))
        .await
        .expect("an exact name reaches a loopback fixture (FW-EGR19)");
    let meta = connect(&exact, &format!("meta.test:{}", up.port))
        .await
        .unwrap_err();
    assert!(meta.starts_with("HTTP/1.1 403"), "{meta}");
    assert_eq!(reasons(&exact), vec![RefusalReason::AddressClass]);
}

/// FW-E2E-031: metadata and private literals are refused under a broad wildcard that names neither,
/// and reached past policy only when an IP-literal rule names them.
#[tokio::test(flavor = "multi_thread")]
async fn fw_e2e_031_metadata_and_private_addresses_blocked() {
    let (proxy, _) = Session::new(
        &[
            "tunnel:*.test:80".into(),
            "tunnel:169.254.169.254:81".into(),
        ],
        resolver(&[]),
    )
    .start();
    for target in ["169.254.169.254:80", "10.0.0.1:80", "[fd00:ec2::254]:80"] {
        let out = connect(&proxy, target).await.unwrap_err();
        assert!(out.starts_with("HTTP/1.1 403"), "{target}: {out}");
    }
    assert!(
        connect(&proxy, "169.254.169.254:81").await.is_ok(),
        "named by an IP-literal rule, the metadata address passes policy"
    );
}

/// FW-ADV-007: the hostname bypass battery -- every variant is refused or canonicalizes to the
/// genuine name; none reaches the blocked fixture.
#[tokio::test(flavor = "multi_thread")]
async fn fw_adv_007_hostname_bypass_battery() {
    let tls = fixture_tls(&["allowed.test"]);
    let allowed = upstream(Some(tls.clone())).await;
    let blocked = upstream(Some(fixture_tls(&["blocked.test"]))).await;
    let p = allowed.port;
    let (proxy, _) = Session::new(
        &[format!("tunnel:allowed.test:{p}")],
        resolver(&[("allowed.test", "127.0.0.1"), ("blocked.test", "127.0.0.2")]),
    )
    .start();
    for target in [
        format!("allowed.test\\x00.blocked.test:{p}"),
        format!("allowed%2etest.blocked.test:{p}"),
        format!("blocked.test#.allowed.test:{p}"),
        format!("[::ffff:127.0.0.1%25allowed.test]:{p}"),
        format!("аllowed.test:{p}"),
    ] {
        let out = connect(&proxy, &target).await.unwrap_err();
        assert!(
            out.starts_with("HTTP/1.1 403") || out.starts_with("HTTP/1.1 400"),
            "{target}: {out}"
        );
    }
    assert!(
        tunnel(
            &proxy,
            std::slice::from_ref(&tls.root),
            &format!("allowed.test.:{p}"),
            "allowed.test"
        )
        .await
        .is_some(),
        "a trailing dot canonicalizes"
    );
    assert_eq!(
        blocked.handshakes.load(std::sync::atomic::Ordering::SeqCst),
        0
    );
}

/// FW-ADV-008 / FW-EGR17: DNS rebinding -- a name that resolves to a restricted address under a
/// wildcard, or to a public address mixed with a private one, is refused at the resolved answer,
/// never connected.
#[tokio::test(flavor = "multi_thread")]
async fn fw_adv_008_rebinding_to_a_blocked_ip_is_refused() {
    let (proxy, _) = Session::new(
        &["tunnel:*.test".into()],
        resolver(&[
            ("allowed.test", "169.254.169.254"),
            ("private.test", "10.0.0.5"),
            ("mixed.test", "93.184.216.34"),
            ("mixed.test", "192.168.0.9"),
        ]),
    )
    .start();
    for target in ["allowed.test:443", "private.test:443", "mixed.test:443"] {
        let out = connect(&proxy, target).await.unwrap_err();
        assert!(out.starts_with("HTTP/1.1 403"), "{target}: {out}");
    }
    assert_eq!(
        reasons(&proxy),
        vec![RefusalReason::AddressClass; 3],
        "{:?}",
        proxy.violations()
    );
}

/// FW-ADV-009 / FW-EGR9: no unauthenticated door. Without the credential the listener answers 407;
/// with a registry (Linux), a connection the supervisor did not register is closed before any
/// byte, and a registered one is served; with a peer check (macOS), likewise for a connection no
/// session process holds.
#[tokio::test(flavor = "multi_thread")]
async fn fw_adv_009_no_unauthenticated_door() {
    let up = upstream(None).await;
    let rules = [format!("allow:allowed.test:{}", up.port)];
    let request_line = format!(
        "GET http://allowed.test:{0}/door HTTP/1.1\r\nHost: allowed.test:{0}\r\n\r\n",
        up.port
    );

    let (open, _) = Session::new(&rules, resolver(&[("allowed.test", "127.0.0.1")])).start();
    let no_cred = raw(&open, request_line.as_bytes()).await;
    assert!(no_cred.starts_with("HTTP/1.1 407"), "{no_cred}");

    let registry = Arc::new(Mutex::new(HashSet::new()));
    let mut session = Session::new(&rules, resolver(&[("allowed.test", "127.0.0.1")]));
    session.registry = Some(registry.clone());
    let (gated, _) = session.start();
    let unregistered = raw(&gated, with_auth(&request_line).as_bytes()).await;
    assert!(
        unregistered.is_empty(),
        "an unregistered peer gets nothing: {unregistered:?}"
    );

    // Register a source port first, the way the supervisor does, then connect from it.
    let socket = tokio::net::TcpSocket::new_v4().unwrap();
    socket.set_reuseaddr(true).unwrap();
    socket.bind("127.0.0.1:0".parse().unwrap()).unwrap();
    let port = socket.local_addr().unwrap().port();
    registry.lock().unwrap().insert(port);
    let mut stream = socket.connect(gated.addr()).await.unwrap();
    let out = request(&mut stream, &with_auth(&request_line)).await;
    assert!(out.ends_with("ok:/door"), "{out}");
    assert!(
        !registry.lock().unwrap().contains(&port),
        "a registration is single-use"
    );
    assert!(up
        .seen()
        .iter()
        .all(|s| s.header("proxy-authorization").is_none()));

    // macOS's second gate: a connection whose client end no session process holds is closed
    // before any byte, and the check sees the connection's own addresses.
    let asked = Arc::new(Mutex::new(Vec::new()));
    let admit_from = Arc::new(Mutex::new(None::<u16>));
    let mut session = Session::new(&rules, resolver(&[("allowed.test", "127.0.0.1")]));
    let (log, admit) = (asked.clone(), admit_from.clone());
    session.peer_check = Some(formwork_gateway::PeerCheck(Arc::new(move |peer, local| {
        log.lock().unwrap().push((peer, local));
        *admit.lock().unwrap() == Some(peer.port())
    })));
    let (checked, _) = session.start();
    let refused = raw(&checked, with_auth(&request_line).as_bytes()).await;
    assert!(
        refused.is_empty(),
        "a peer outside the session gets nothing: {refused:?}"
    );
    let socket = tokio::net::TcpSocket::new_v4().unwrap();
    socket.bind("127.0.0.1:0".parse().unwrap()).unwrap();
    let port = socket.local_addr().unwrap().port();
    *admit_from.lock().unwrap() = Some(port);
    let mut stream = socket.connect(checked.addr()).await.unwrap();
    let out = request(&mut stream, &with_auth(&request_line)).await;
    assert!(out.ends_with("ok:/door"), "{out}");
    let asked = asked.lock().unwrap();
    assert_eq!(asked.len(), 2, "{asked:?}");
    assert_eq!(asked[1].0.port(), port);
    assert_eq!(asked[1].1, checked.addr());
}

/// Plain HTTP runs the inspected request pipeline without TLS (FEP-6 §4.8): decided by method and
/// canonical path, forwarded from what matched (FW-EGR22), with traversal, smuggling and a
/// tunnel-grade host refused.
#[tokio::test(flavor = "multi_thread")]
async fn plain_http_is_the_inspected_pipeline_without_tls() {
    let up = upstream(None).await;
    let p = up.port;
    let (proxy, _) = Session::new(
        &[
            format!("get:api.test:{p}/ok/**"),
            format!("tunnel:tls.test:{p}"),
        ],
        resolver(&[("api.test", "127.0.0.1"), ("tls.test", "127.0.0.1")]),
    )
    .start();
    let req = |method: &str, host: &str, path: &str, extra: &str| {
        let proxy = &proxy;
        let head = format!(
            "{method} http://{host}:{p}{path} HTTP/1.1\r\nHost: {host}:{p}\r\nProxy-Authorization: {}\r\n{extra}\r\n",
            proxy_auth()
        );
        async move { raw(proxy, head.as_bytes()).await }
    };
    let ok = req(
        "GET",
        "api.test",
        "/ok/./x?q=1",
        "Connection: close, X-Hop\r\nX-Hop: 1\r\n",
    )
    .await;
    assert!(ok.contains("ok:/ok/x"), "{ok}");
    let seen = up.seen();
    assert_eq!(seen.len(), 1);
    assert!(
        seen[0].head.starts_with("GET /ok/x?q=1 HTTP/1.1"),
        "the request line is written from the canonical path: {}",
        seen[0].head
    );
    assert!(seen[0].header("proxy-authorization").is_none());
    assert!(seen[0].header("x-hop").is_none(), "{}", seen[0].head);
    assert!(req("POST", "api.test", "/ok/x", "Content-Length: 0\r\n")
        .await
        .starts_with("HTTP/1.1 403"));
    assert!(req("GET", "api.test", "/ok/../secret", "")
        .await
        .starts_with("HTTP/1.1 403"));
    assert!(req("GET", "api.test", "/ok/%2e%2e/secret", "")
        .await
        .starts_with("HTTP/1.1 403"));
    assert!(req("GET", "api.test", "/ok%2F..%2Fsecret", "")
        .await
        .starts_with("HTTP/1.1 400"));
    let smuggle = req(
        "GET",
        "api.test",
        "/ok/x",
        "Content-Length: 5\r\nTransfer-Encoding: chunked\r\n",
    )
    .await;
    assert!(smuggle.starts_with("HTTP/1.1 400"), "{smuggle}");
    assert!(req("GET", "tls.test", "/ok/x", "")
        .await
        .starts_with("HTTP/1.1 403"));
    assert_eq!(up.seen().len(), 1, "nothing else reached the upstream");
    assert_eq!(
        reasons(&proxy),
        vec![
            RefusalReason::Method,
            RefusalReason::Path,
            RefusalReason::Path,
            RefusalReason::Malformed,
            RefusalReason::Malformed,
            RefusalReason::NotTls
        ]
    );
}

/// FW-ADV-024 (`FW-INV15`): heads, authorities and ClientHellos the engine cannot parse are
/// refused, and the fixture upstream receives no byte from any of them.
#[tokio::test(flavor = "multi_thread")]
async fn fw_adv_024_parser_battery() {
    let up = upstream(None).await;
    let p = up.port;
    let (proxy, _) = Session::new(
        &[
            format!("allow:api.test:{p}"),
            format!("tunnel:api.test:{}", p + 1),
        ],
        resolver(&[("api.test", "127.0.0.1")]),
    )
    .start();
    let auth = proxy_auth();
    let get = |extra: &str| {
        format!(
            "GET http://api.test:{p}/ HTTP/1.1\r\nHost: api.test:{p}\r\nProxy-Authorization: {auth}\r\n{extra}\r\n"
        )
    };
    let oversized = format!("X-Big: {}\r\n", "a".repeat(70 * 1024));
    let many: String = (0..120).map(|i| format!("X-{i}: v\r\n")).collect();
    let heads = [
        get("Content-Length: 1\r\nTransfer-Encoding: chunked\r\n"),
        get("Content-Length: 1\r\nContent-Length: 2\r\n"),
        get("X-Folded: a\r\n b\r\n"),
        format!("GET http://api.test:{p}/ HTTP/1.1\nHost: api.test\r\nProxy-Authorization: {auth}\r\n\r\n"),
        get("X-Nul: a\0b\r\n"),
        format!("G@T http://api.test:{p}/ HTTP/1.1\r\nProxy-Authorization: {auth}\r\n\r\n"),
        get(&oversized),
        get(&many),
    ];
    for head in &heads {
        let out = raw(&proxy, head.as_bytes()).await;
        assert!(
            out.starts_with("HTTP/1.1 400"),
            "{:?}: {out}",
            &head[..head.len().min(120)]
        );
    }
    for authority in [
        format!("user@api.test:{p}"),
        format!("api.test:{p}/x"),
        format!("[fe80::1%25eth0]:{p}"),
        format!("api%2etest:{p}"),
        format!("2130706433:{p}"),
        format!("0x7f.1:{p}"),
        format!("127.1:{p}"),
        "api.test".to_string(),
    ] {
        let out = connect(&proxy, &authority).await.unwrap_err();
        assert!(out.starts_with("HTTP/1.1 400"), "{authority}: {out}");
    }
    assert!(up.seen().is_empty(), "{:?}", up.seen());
    assert_eq!(up.handshakes.load(std::sync::atomic::Ordering::SeqCst), 0);
    let r = reasons(&proxy);
    assert!(
        r.iter()
            .all(|r| matches!(r, RefusalReason::Malformed | RefusalReason::Limit)),
        "{r:?}"
    );
    assert!(r.contains(&RefusalReason::Limit), "{r:?}");
}

/// FW-EGR26: with an upstream proxy in the operator's environment, admitted egress goes through it
/// -- `CONNECT` for TLS, absolute form for plain HTTP -- except to hosts `NO_PROXY` exempts, and a
/// name the proxy carries is not resolved by the Gateway.
#[tokio::test(flavor = "multi_thread")]
async fn fw_egr26_egress_leaves_through_the_upstream_proxy() {
    let tls = fixture_tls(&["model.test"]);
    let model = upstream(Some(tls.clone())).await;
    let corp = upstream(None).await;
    let plain = upstream(None).await;
    let mut ports = BTreeMap::new();
    ports.insert("model.test".to_string(), model.port);
    ports.insert("plain.test".to_string(), plain.port);
    let corporate = corporate_proxy(ports).await;
    let url = format!("http://127.0.0.1:{}", corporate.port);
    let mut session = Session::new(
        &[
            format!("tunnel:model.test:{}", model.port),
            format!("allow:git.corp.test:{}", corp.port),
            format!("allow:plain.test:{}", plain.port),
        ],
        // model.test and plain.test have no answer: only the proxy can reach them.
        resolver(&[("git.corp.test", "127.0.0.1")]),
    );
    session.upstream_proxy =
        UpstreamProxy::from_values(Some(&url), Some(&url), Some(".corp.test")).unwrap();
    let (proxy, _) = session.start();

    let mut t = tunnel(
        &proxy,
        std::slice::from_ref(&tls.root),
        &format!("model.test:{}", model.port),
        "model.test",
    )
    .await
    .expect("tunneled through the corporate proxy");
    assert!(
        request(&mut t, "GET /m HTTP/1.1\r\nHost: model.test\r\n\r\n")
            .await
            .ends_with("ok:/m")
    );
    let direct = raw(
        &proxy,
        format!(
            "GET http://git.corp.test:{0}/g HTTP/1.1\r\nHost: git.corp.test:{0}\r\nProxy-Authorization: {1}\r\nConnection: close\r\n\r\n",
            corp.port,
            proxy_auth()
        )
        .as_bytes(),
    )
    .await;
    assert!(direct.contains("ok:/g"), "{direct}");
    let proxied = raw(
        &proxy,
        format!(
            "GET http://plain.test:{0}/p HTTP/1.1\r\nHost: plain.test:{0}\r\nProxy-Authorization: {1}\r\nConnection: close\r\n\r\n",
            plain.port,
            proxy_auth()
        )
        .as_bytes(),
    )
    .await;
    assert!(proxied.contains("ok:/p"), "{proxied}");
    let lines = corporate.lines.lock().unwrap().clone();
    assert!(
        lines.contains(&format!("CONNECT model.test:{} HTTP/1.1", model.port)),
        "{lines:?}"
    );
    assert!(
        lines
            .iter()
            .any(|l| l.starts_with(&format!("GET http://plain.test:{}/p ", plain.port))),
        "{lines:?}"
    );
    assert!(
        !lines.iter().any(|l| l.contains("corp.test")),
        "NO_PROXY exempts the intranet: {lines:?}"
    );
}

/// FW-EGR22 at the tunnel boundary: the confined client's proxy credential never crosses a tunnel,
/// and a TLS client that names an IP literal (no server name) is admitted under an IP-literal rule.
#[tokio::test(flavor = "multi_thread")]
async fn an_ip_literal_tunnel_admits_a_client_hello_without_a_server_name() {
    let tls = fixture_tls(&["127.0.0.1"]);
    let up = upstream(Some(tls.clone())).await;
    let target = format!("127.0.0.1:{}", up.port);
    let (proxy, _) = Session::new(&[format!("tunnel:{target}")], resolver(&[])).start();
    let tcp = connect(&proxy, &target).await.unwrap();
    let connector =
        tokio_rustls::TlsConnector::from(client_config(std::slice::from_ref(&tls.root), &[]));
    let ip: std::net::IpAddr = "127.0.0.1".parse().unwrap();
    let mut t = connector
        .connect(ServerName::IpAddress(ip.into()), tcp)
        .await
        .expect("no SNI for an IP literal");
    assert!(
        request(&mut t, "GET /ip HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n")
            .await
            .ends_with("ok:/ip")
    );
    assert!(proxy.violations().is_empty());
}
