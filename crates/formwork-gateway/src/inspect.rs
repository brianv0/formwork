//! The inspected grade (FW-EGR10, FEP-6 §4.4): the Gateway terminates TLS with a leaf minted by
//! the session CA after the ClientHello's server name matches the CONNECT host and its ALPN admits
//! HTTP/1.1 (FW-EGR20), then decides every request by `Host`, method and canonical path before
//! writing it upstream from what matched (FW-EGR22). Plain HTTP to an inspected rule runs the same
//! request pipeline without TLS. Brokered credentials are presented here, over TLS only
//! (FW-CRED11, FW-CRED18, FW-CRED19), and a response that would echo one is ended (FW-CRED17).
//! Upstream connections come from a per-session keep-alive pool, each reused only for the host it
//! was opened for.

use std::collections::HashMap;
use std::io;
use std::sync::Arc;
use std::time::Instant;

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use rustls::pki_types::{CertificateDer, ServerName};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use formwork_blueprint::{
    canonicalize_host, split_host_port, BrokerScheme, CanonicalHost, CanonicalPath,
    ConnectDecision, HttpMethod, RefusalReason, RequestDecision, DEFAULT_HTTPS_PORT,
    DEFAULT_HTTP_PORT,
};
use formwork_compile::Capability;

use crate::egress::{
    check_server_name, destination, dial, read_client_hello, Destination, Grant, Prefixed, Refusal,
    Shared,
};
use crate::http::{
    connection_tokens, end_to_end, parse_head, parse_response_head, render_request,
    render_response, request_framing, respond, response_framing, BodyError, BoxIo, Buffered,
    Framing, Guard, Head, HeadError, HEAD_TIMEOUT, IDLE_TIMEOUT, READ_CHUNK,
};

/// The prefix of every session placeholder (FW-CRED14); the placeholder scan looks for it.
pub const PLACEHOLDER_PREFIX: &str = "fwcred-";
/// Idle upstream connections kept per host and port.
const MAX_IDLE_PER_HOST: usize = 8;

/// A brokered credential as the Gateway holds it (FW-CRED15): the secret never leaves this process
/// except in the scheme's header toward a bound host, over TLS.
#[derive(Clone)]
pub struct Broker {
    pub name: String,
    /// What the confined environment carries instead of the secret (FW-CRED14).
    pub placeholder: String,
    pub secret: String,
    pub bindings: Vec<(CanonicalHost, BrokerScheme)>,
}

impl std::fmt::Debug for Broker {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Broker")
            .field("name", &self.name)
            .field("placeholder", &self.placeholder)
            .field("bindings", &self.bindings.len())
            .finish_non_exhaustive()
    }
}

/// Inspection's session state: the CA, and the upstream TLS config -- built once, so every upstream
/// connection shares its roots and resumption state.
#[derive(Clone, Debug)]
pub struct Inspection {
    pub ca: Arc<crate::ca::SessionCa>,
    upstream: Arc<rustls::ClientConfig>,
}

impl Inspection {
    /// `roots` are what upstream certificates must chain to (FW-EGR24): the host trust store
    /// ([`crate::native_roots`]) in a session, a fixture root in the Gateway's own tests. The
    /// session CA is never among them.
    pub fn new(ca: Arc<crate::ca::SessionCa>, roots: &[CertificateDer<'static>]) -> Inspection {
        let mut store = rustls::RootCertStore::empty();
        let session_ca = ca.cert_der();
        let (added, ignored) =
            store.add_parsable_certificates(roots.iter().filter(|r| **r != session_ca).cloned());
        tracing::debug!(added, ignored, "upstream trust store loaded");
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let mut config = rustls::ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .expect("ring supports the default protocol versions")
            .with_root_certificates(store)
            .with_no_client_auth();
        config.alpn_protocols = vec![b"http/1.1".to_vec()];
        Inspection {
            ca,
            upstream: Arc::new(config),
        }
    }
}

/// `Basic base64(<user>:<password>)` (RFC 7617).
pub(crate) fn basic_value(user: &str, password: &str) -> String {
    format!("Basic {}", BASE64.encode(format!("{user}:{password}")))
}

/// The decoded `user:password` of a `Basic` authorization value.
fn basic_decoded(value: &str) -> Option<String> {
    value
        .strip_prefix("Basic ")
        .and_then(|b64| BASE64.decode(b64.trim()).ok())
        .map(|raw| String::from_utf8_lossy(&raw).into_owned())
}

/// Is this TLS failure a client rejecting the session CA? (FW-FID9's `unknown_ca` line.) A client
/// that verifies in the handshake sends `unknown_ca` or a sibling alert. One that verifies after
/// its side of the handshake (curl 8.x on OpenSSL) sends no alert: having seen the leaf, it aborts
/// before a byte of request -- a reset, or an end without `close_notify` -- which the Gateway sees
/// while reading the client's last flight or the first request. A client that closes with
/// `close_notify` ended the session on purpose and is not counted.
fn rejected_our_ca(e: &io::Error) -> bool {
    use rustls::AlertDescription as A;
    matches!(
        e.kind(),
        io::ErrorKind::ConnectionReset | io::ErrorKind::UnexpectedEof
    ) || matches!(
        e.get_ref()
            .and_then(|inner| inner.downcast_ref::<rustls::Error>()),
        Some(rustls::Error::AlertReceived(
            A::UnknownCA | A::BadCertificate | A::CertificateUnknown
        ))
    )
}

/// The inspected grade after `200 Connection Established` (FEP-6 §4.4).
pub(crate) async fn serve_inspected(
    mut client: Buffered<TcpStream>,
    dest: Destination,
    shared: Arc<Shared>,
) -> io::Result<()> {
    let (host, port) = (dest.host.clone(), dest.port);
    let tunnel_rule = if port == DEFAULT_HTTPS_PORT {
        format!("tunnel:{host}")
    } else {
        format!("tunnel:{host}:{port}")
    };
    let hello = match read_client_hello(&mut client).await {
        Ok(h) => h,
        Err(r) => {
            shared.refuse(r.at(&host, port));
            return Ok(());
        }
    };
    if let Err(r) = check_server_name(&hello, &host) {
        shared.refuse(r.at(&host, port));
        return Ok(());
    }
    if let Some(offered) = &hello.alpn {
        if !offered.iter().any(|p| p == b"http/1.1") {
            let shown: Vec<String> = offered
                .iter()
                .map(|p| String::from_utf8_lossy(p).into_owned())
                .collect();
            shared.refuse(
                Refusal::new(
                    RefusalReason::Alpn,
                    format!(
                        "the client offers only {shown:?}; an inspected host is served over \
                         HTTP/1.1 (FW-EGR20). If the client cannot fall back, make the host a \
                         tunnel (`{tunnel_rule}`)"
                    ),
                )
                .at(&host, port),
            );
            return Ok(());
        }
    }
    let Some(inspection) = shared.config.inspection.clone() else {
        tracing::error!(host = %host, "formwork: an inspected host in a session without a CA");
        return Ok(());
    };
    let server = match inspection.ca.server_config(&host) {
        Ok(c) => c,
        Err(e) => {
            tracing::error!(error = %e, host = %host, "formwork: minting an inspection leaf failed");
            return Ok(());
        }
    };
    let replay = Prefixed {
        prefix: hello.raw,
        inner: client.s,
    };
    let accepted = tokio::time::timeout(
        HEAD_TIMEOUT,
        tokio_rustls::TlsAcceptor::from(server).accept(replay),
    )
    .await;
    let ca_rejected = |shared: &Shared| {
        // FW-FID9: the one line that turns an opaque x509 error into a diagnosis.
        shared.note_ca_rejection(&host, port);
        tracing::warn!(
            host = %host,
            "formwork: a client rejected the session CA for inspected host {host}: it does not \
             read SSL_CERT_FILE (on macOS, Security.framework clients such as Go and Swift never \
             do), or it was given its own CA file. Options: make the host a tunnel \
             (`{tunnel_rule}`), or use a client that honors the variable; reproduce: formwork \
             explain https://{host}:{port}/"
        );
    };
    let tls = match accepted {
        Ok(Ok(t)) => t,
        Ok(Err(e)) if rejected_our_ca(&e) => {
            ca_rejected(&shared);
            return Ok(());
        }
        Ok(Err(e)) => {
            tracing::debug!(error = %e, host = %host, "inspection handshake failed");
            return Ok(());
        }
        Err(_) => return Ok(()),
    };
    let mut client = Buffered::new(Box::new(tls) as BoxIo, Vec::new());
    match tokio::time::timeout(HEAD_TIMEOUT, client.fill()).await {
        Ok(Ok(0)) | Err(_) => return Ok(()),
        Ok(Ok(_)) => {}
        Ok(Err(e)) if rejected_our_ca(&e) => {
            ca_rejected(&shared);
            return Ok(());
        }
        Ok(Err(e)) => return Err(e),
    }
    relay(client, Scope::Tls(dest), None, &shared).await
}

/// A plain-HTTP proxy connection (FEP-6 §4.8): the inspected request pipeline without TLS, each
/// absolute-form request decided on its own.
pub(crate) async fn serve_plain(
    client: Buffered<TcpStream>,
    first: Head,
    shared: Arc<Shared>,
) -> io::Result<()> {
    let client = Buffered::new(Box::new(client.s) as BoxIo, client.buf);
    relay(client, Scope::Plain, Some(first), &shared).await
}

/// What a client connection is for: one inspected host over TLS, or plain-HTTP requests that each
/// name their own host.
enum Scope {
    Tls(Destination),
    Plain,
}

enum Next {
    KeepAlive,
    Close,
}

async fn relay(
    mut client: Buffered<BoxIo>,
    scope: Scope,
    mut first: Option<Head>,
    shared: &Arc<Shared>,
) -> io::Result<()> {
    let at = |r: Refusal| match &scope {
        Scope::Tls(d) => r.at(&d.host, d.port),
        Scope::Plain => r.plain(true),
    };
    let mut idle = HEAD_TIMEOUT;
    loop {
        let head = match first.take() {
            Some(h) => h,
            None => match client
                .raw_head(Some(idle))
                .await
                .and_then(|raw| parse_head(&raw))
            {
                Ok(h) => h,
                Err(HeadError::Closed | HeadError::Idle) => return Ok(()),
                Err(HeadError::Io(e)) => return Err(e),
                Err(HeadError::Limit(why)) => {
                    let r = Refusal::new(RefusalReason::Limit, why);
                    shared.refuse(at(r).capability(Capability::NetInspection));
                    return respond(&mut client.s, "400 Bad Request", "", true).await;
                }
                Err(HeadError::Malformed(why)) => {
                    let r = Refusal::new(RefusalReason::Malformed, why);
                    shared.refuse(at(r).capability(Capability::NetInspection));
                    return respond(&mut client.s, "400 Bad Request", "", true).await;
                }
            },
        };
        idle = IDLE_TIMEOUT;
        match exchange(&mut client, head, &scope, shared).await? {
            Next::KeepAlive => {}
            Next::Close => return Ok(()),
        }
    }
}

/// How a refused request ends: a policy refusal keeps the connection once the body is drained; a
/// request the engine cannot frame, or one naming another host, closes it.
async fn refused(
    client: &mut Buffered<BoxIo>,
    shared: &Shared,
    refusal: Refusal,
    framing: Option<Framing>,
) -> io::Result<Next> {
    let reason = refusal.reason();
    shared.refuse(refusal);
    let status = match reason {
        RefusalReason::Malformed | RefusalReason::Limit => "400 Bad Request",
        _ => "403 Forbidden",
    };
    match framing {
        Some(framing) if reason != RefusalReason::HostMismatch => {
            if client
                .copy_body(framing, &mut tokio::io::sink(), None)
                .await
                .is_err()
            {
                return Ok(Next::Close);
            }
            respond(&mut client.s, status, "", false).await?;
            Ok(Next::KeepAlive)
        }
        _ => {
            respond(&mut client.s, status, "", true).await?;
            Ok(Next::Close)
        }
    }
}

/// Split an absolute-form `http://authority/path?query` target; the path and query are kept as
/// sent for canonicalization.
fn split_absolute(target: &str) -> Option<(&str, String)> {
    let rest = target.strip_prefix("http://")?;
    let end = rest.find(['/', '?']).unwrap_or(rest.len());
    let (authority, tail) = rest.split_at(end);
    let tail = if tail.starts_with('/') {
        tail.to_string()
    } else {
        format!("/{tail}")
    };
    Some((authority, tail))
}

fn host_header_matches(value: &str, host: &CanonicalHost, port: u16, default_port: u16) -> bool {
    let Ok((h, p)) = split_host_port(value.trim()) else {
        return false;
    };
    p.unwrap_or(default_port) == port && canonicalize_host(h).is_ok_and(|c| &c == host)
}

/// The authority as a request names it: the port only when it is not the scheme's default.
fn authority(host: &CanonicalHost, port: u16, default_port: u16) -> String {
    if port == default_port {
        host.to_string()
    } else {
        format!("{host}:{port}")
    }
}

/// One request and its response (FEP-6 §4.4 step 3).
async fn exchange(
    client: &mut Buffered<BoxIo>,
    head: Head,
    scope: &Scope,
    shared: &Arc<Shared>,
) -> io::Result<Next> {
    let started = Instant::now();
    let plain = matches!(scope, Scope::Plain);
    let default_port = if plain {
        DEFAULT_HTTP_PORT
    } else {
        DEFAULT_HTTPS_PORT
    };
    let malformed = |why: &str| {
        Refusal::new(RefusalReason::Malformed, why)
            .capability(Capability::NetInspection)
            .plain(plain)
    };

    // Where the request goes.
    let (host, port, path_and_query) = match scope {
        Scope::Tls(dest) => {
            if !head.target.starts_with('/') {
                let r = malformed("an inner request target that is not origin-form");
                return refused(client, shared, r.at(&dest.host, dest.port), None).await;
            }
            (dest.host.clone(), dest.port, head.target.clone())
        }
        Scope::Plain => {
            let parsed = split_absolute(&head.target).and_then(|(authority, tail)| {
                let (h, p) = split_host_port(authority).ok()?;
                Some((
                    canonicalize_host(h).ok()?,
                    p.unwrap_or(DEFAULT_HTTP_PORT),
                    tail,
                ))
            });
            match parsed {
                Some(p) => p,
                None => {
                    let r = malformed(
                        "only CONNECT and absolute-form http:// requests with a valid authority \
                         reach the Gateway",
                    );
                    return refused(client, shared, r, None).await;
                }
            }
        }
    };
    let (raw_path, query) = match path_and_query.split_once('?') {
        Some((p, q)) => (p.to_string(), Some(q.to_string())),
        None => (path_and_query.clone(), None),
    };
    if path_and_query.contains('#') {
        let r = malformed("a fragment in the request target");
        return refused(client, shared, r.at(&host, port), None).await;
    }
    let path = match CanonicalPath::parse(&raw_path) {
        Ok(p) => p,
        Err(why) => return refused(client, shared, malformed(&why).at(&host, port), None).await,
    };
    let at = |r: Refusal| {
        r.at(&host, port)
            .request(&head.method, path.as_str())
            .plain(plain)
    };
    let framing = match request_framing(&head) {
        Ok(f) => f,
        Err(why) => {
            let r = malformed(&format!("request smuggling shape: {why} (FW-EGR11)"));
            return refused(client, shared, at(r), None).await;
        }
    };

    // FW-EGR10: the Host header names the host the request was admitted for.
    let host_ok = match head.header("host") {
        Some(v) => host_header_matches(v, &host, port, default_port),
        None => plain,
    };
    if !host_ok {
        let r = Refusal::new(
            RefusalReason::HostMismatch,
            "the Host header does not name the host the connection was admitted for (FW-EGR10)",
        );
        return refused(client, shared, at(r), Some(framing)).await;
    }

    // FW-EGR23: TRACE reflects the request, credentials included; CONNECT inside an inspected
    // host would open a tunnel no rule decided.
    if head.method == "TRACE" || head.method == "CONNECT" {
        let r = Refusal::new(
            RefusalReason::Method,
            format!(
                "{} is refused on inspected hosts under every rule (FW-EGR23)",
                head.method
            ),
        );
        return refused(client, shared, at(r), Some(framing)).await;
    }

    let table = &shared.config.table;
    if plain {
        match table.decide_connect(&host, port) {
            ConnectDecision::Inspect => {}
            ConnectDecision::Deny(d) => {
                let r = Refusal::new(d.reason, d.detail).rule(d.rule);
                return refused(client, shared, at(r), Some(framing)).await;
            }
            ConnectDecision::Tunnel(rule) => {
                let r = Refusal::new(
                    RefusalReason::NotTls,
                    format!(
                        "`{rule}` is a tunnel, which carries TLS only; plain HTTP needs an \
                         inspected rule for the host"
                    ),
                )
                .rule(Some(rule));
                return refused(client, shared, at(r), Some(framing)).await;
            }
        }
    }
    let method = HttpMethod::from_token(&head.method);
    if let RequestDecision::Deny(d) = table.decide_request(&host, port, method, &path) {
        let r = Refusal::new(d.reason, d.detail).rule(d.rule);
        return refused(client, shared, at(r), Some(framing)).await;
    }
    if let Err(why) =
        scan_placeholders(&head, &path_and_query, &host, &shared.config.brokers, plain)
    {
        let r = Refusal::new(RefusalReason::Placeholder, why);
        return refused(client, shared, at(r), Some(framing)).await;
    }
    let dest = match scope {
        Scope::Tls(dest) => dest.clone(),
        Scope::Plain => match destination(shared, &host, port, false).await {
            Ok(d) => d,
            Err(r) => return refused(client, shared, at(r), Some(framing)).await,
        },
    };

    // FW-EGR22: what goes upstream is built from what matched.
    let upgrade = connection_tokens(&head.headers).contains(&"upgrade".to_string())
        && head.header("upgrade").is_some();
    let expect_continue = head
        .header("expect")
        .is_some_and(|v| v.eq_ignore_ascii_case("100-continue"))
        && framing != Framing::None;
    let mut headers: Vec<(String, String)> = end_to_end(&head.headers)
        .into_iter()
        .filter(|(n, _)| !(expect_continue && n.eq_ignore_ascii_case("expect")))
        .collect();
    if plain {
        headers.retain(|(n, _)| !n.eq_ignore_ascii_case("host"));
        headers.insert(0, ("Host".into(), authority(&host, port, default_port)));
    }
    let brokered: Vec<&Broker> = shared
        .config
        .brokers
        .iter()
        .filter(|b| b.bindings.iter().any(|(h, _)| h == &host))
        .collect();
    let encodings = if plain || brokered.is_empty() {
        Vec::new()
    } else if head.method == "OPTIONS" {
        // FW-CRED18: no credential on OPTIONS; its placeholder goes nowhere either.
        headers.retain(|(_, v)| !carries_any(v, &brokered));
        Vec::new()
    } else {
        present(&mut headers, &host, &brokered)
    };
    if !encodings.is_empty() {
        // FW-CRED17: identity coding keeps a reflected credential scannable; a compressed
        // WebSocket would hide it the same way.
        headers.retain(|(n, _)| {
            !n.eq_ignore_ascii_case("accept-encoding")
                && !n.eq_ignore_ascii_case("sec-websocket-extensions")
        });
        headers.push(("Accept-Encoding".into(), "identity".into()));
    }
    if upgrade {
        if let Some(protocol) = head.header("upgrade") {
            headers.push(("Connection".into(), "Upgrade".into()));
            headers.push(("Upgrade".into(), protocol.to_string()));
        }
    }
    let mut line_target = match &query {
        Some(q) => format!("{path}?{q}"),
        None => path.to_string(),
    };
    if let (true, Some(proxy)) = (plain, dest.proxy()) {
        line_target = format!(
            "http://{}{line_target}",
            authority(&host, port, default_port)
        );
        if let Some(auth) = &proxy.authorization {
            headers.push(("Proxy-Authorization".into(), auth.clone()));
        }
    }
    let request_bytes = render_request(&head.method, &line_target, &headers);

    // Upstream: a pooled connection for this host, else a new one; a bodiless request whose reused
    // connection turns out closed is retried once on a fresh one.
    let key = PoolKey {
        host: host.clone(),
        port,
        tls: !plain,
    };
    let mut pooled = shared.pool.take(&key).await;
    let mut bytes_up: u64;
    let (mut up, response) = loop {
        let reused = pooled.is_some();
        let mut conn = match pooled.take() {
            Some(c) => c,
            None => match connect_upstream(shared, &dest, !plain).await {
                Ok(c) => c,
                Err(Some(r)) => {
                    shared.refuse(at(r));
                    respond(&mut client.s, "502 Bad Gateway", "", true).await?;
                    return Ok(Next::Close);
                }
                Err(None) => {
                    respond(&mut client.s, "502 Bad Gateway", "", true).await?;
                    return Ok(Next::Close);
                }
            },
        };
        let retryable = reused && framing == Framing::None;
        if conn.s.write_all(&request_bytes).await.is_err() {
            if retryable {
                continue;
            }
            respond(&mut client.s, "502 Bad Gateway", "", true).await?;
            return Ok(Next::Close);
        }
        if expect_continue {
            client.s.write_all(b"HTTP/1.1 100 Continue\r\n\r\n").await?;
            client.s.flush().await?;
        }
        match client.copy_body(framing, &mut conn.s, None).await {
            Ok(n) => bytes_up = n,
            Err(BodyError::Malformed(why)) => {
                shared.refuse(at(malformed(why)));
                return Ok(Next::Close);
            }
            Err(BodyError::Io(e)) => {
                tracing::info!(host = %host, error = %e, "egress request body did not pass through");
                return Ok(Next::Close);
            }
            Err(BodyError::Reflected) => return Ok(Next::Close),
        }
        if conn.s.flush().await.is_err() {
            if retryable {
                continue;
            }
            respond(&mut client.s, "502 Bad Gateway", "", true).await?;
            return Ok(Next::Close);
        }
        match conn
            .raw_head(None)
            .await
            .and_then(|raw| parse_response_head(&raw))
        {
            Ok(response) => break (conn, response),
            Err(HeadError::Closed) if retryable => continue,
            Err(e) => {
                tracing::info!(host = %host, error = ?e, "egress upstream response unreadable");
                respond(&mut client.s, "502 Bad Gateway", "", true).await?;
                return Ok(Next::Close);
            }
        }
    };

    let mut guard = (!encodings.is_empty()).then(|| Guard::new(encodings));
    let reflection = |why: String| Refusal::new(RefusalReason::Reflection, why);
    let mut response = response;
    loop {
        if let Some(g) = &guard {
            let coding = response
                .header("content-encoding")
                .map(|v| v.trim().to_ascii_lowercase())
                .filter(|v| !v.is_empty() && v != "identity");
            if let Some(coding) = coding {
                // FW-CRED17: a compressed echo cannot be scanned without decompressing it.
                shared.refuse(at(reflection(format!(
                    "the response to a brokered request came with content coding {coding:?}; \
                     the reflection guard admits identity-coded responses only"
                ))));
                return Ok(Next::Close);
            }
            if response
                .headers
                .iter()
                .any(|(n, v)| g.scan(n.as_bytes()) || g.scan(v.as_bytes()))
            {
                shared.refuse(at(reflection(
                    "a response header carries the brokered credential".into(),
                )));
                return Ok(Next::Close);
            }
        }
        if response.status == 101 {
            if !upgrade {
                respond(&mut client.s, "502 Bad Gateway", "", true).await?;
                return Ok(Next::Close);
            }
            // The two sides are spliced only after the upstream agreed to switch (FEP-6 §4.8).
            let mut out = end_to_end(&response.headers);
            out.push(("Connection".into(), "Upgrade".into()));
            if let Some(protocol) = response.header("upgrade") {
                out.push(("Upgrade".into(), protocol.to_string()));
            }
            client
                .s
                .write_all(&render_response(&response, &out))
                .await?;
            client.s.flush().await?;
            let spliced = splice(client, &mut up, guard.as_mut()).await;
            if spliced.reflected {
                shared.refuse(at(reflection(
                    "the upgraded stream carried the brokered credential".into(),
                )));
            }
            shared.grant(grant(
                &host,
                port,
                &head.method,
                &path,
                101,
                bytes_up + spliced.up,
                spliced.down,
                started,
            ));
            return Ok(Next::Close);
        }
        if (100..200).contains(&response.status) {
            let interim = render_response(&response, &end_to_end(&response.headers));
            client.s.write_all(&interim).await?;
            client.s.flush().await?;
            response = match up
                .raw_head(None)
                .await
                .and_then(|raw| parse_response_head(&raw))
            {
                Ok(r) => r,
                Err(_) => return Ok(Next::Close),
            };
            continue;
        }
        break;
    }

    let framing_down = match response_framing(&response, &head.method) {
        Ok(f) => f,
        Err(why) => {
            tracing::info!(host = %host, why, "egress upstream response framing refused");
            respond(&mut client.s, "502 Bad Gateway", "", true).await?;
            return Ok(Next::Close);
        }
    };
    let server_close = connection_tokens(&response.headers).contains(&"close".to_string())
        || (response.version == "HTTP/1.0"
            && !connection_tokens(&response.headers).contains(&"keep-alive".to_string()));
    let client_close = connection_tokens(&head.headers).contains(&"close".to_string());
    let close_after = client_close || framing_down == Framing::UntilClose;
    let mut out = end_to_end(&response.headers);
    if framing_down == Framing::Chunked {
        // A response framed by both is read as chunked here; the client must read it the same way.
        out.retain(|(n, _)| !n.eq_ignore_ascii_case("content-length"));
    }
    if close_after {
        out.push(("Connection".into(), "close".into()));
    }
    client
        .s
        .write_all(&render_response(&response, &out))
        .await?;
    if guard.is_some() && matches!(response.status, 401 | 403) {
        let names: Vec<&str> = brokered.iter().map(|b| b.name.as_str()).collect();
        tracing::warn!(
            host = %host,
            status = response.status,
            "formwork: {host} answered {} to a request carrying the brokered {} credential; it \
             may be expired or scoped too narrowly",
            response.status,
            names.join(", ")
        );
    }
    let bytes_down = match up
        .copy_body(framing_down, &mut client.s, guard.as_mut())
        .await
    {
        Ok(n) => n,
        Err(BodyError::Reflected) => {
            shared.refuse(at(reflection(
                "the response body carries the brokered credential; the response is ended".into(),
            )));
            return Ok(Next::Close);
        }
        Err(BodyError::Malformed(why)) => {
            tracing::info!(host = %host, why, "egress upstream response body refused");
            return Ok(Next::Close);
        }
        Err(BodyError::Io(e)) => {
            tracing::debug!(host = %host, error = %e, "egress response ended early");
            return Ok(Next::Close);
        }
    };
    shared.grant(grant(
        &host,
        port,
        &head.method,
        &path,
        response.status,
        bytes_up,
        bytes_down,
        started,
    ));
    if !server_close && framing_down != Framing::UntilClose {
        shared.pool.put(key, up);
    }
    if close_after {
        let _ = client.s.shutdown().await;
        return Ok(Next::Close);
    }
    Ok(Next::KeepAlive)
}

#[allow(clippy::too_many_arguments)]
fn grant(
    host: &CanonicalHost,
    port: u16,
    method: &str,
    path: &CanonicalPath,
    status: u16,
    bytes_up: u64,
    bytes_down: u64,
    started: Instant,
) -> Grant {
    Grant {
        host: host.to_string(),
        port,
        grade: "inspected",
        method: Some(method.to_string()),
        path: Some(path.to_string()),
        status: Some(status),
        bytes_up,
        bytes_down,
        duration_ms: started.elapsed().as_millis() as u64,
    }
}

/// What an upgraded connection carried before either side ended it.
struct Spliced {
    up: u64,
    down: u64,
    /// The guard ended the upstream's bytes: they carried the presented credential.
    reflected: bool,
}

/// Copy an upgraded connection both ways until either side ends; the upstream's bytes pass through
/// the guard when a credential was presented on the upgrade (FW-CRED17).
async fn splice(
    client: &mut Buffered<BoxIo>,
    up: &mut Buffered<BoxIo>,
    mut guard: Option<&mut Guard>,
) -> Spliced {
    let early_up = std::mem::take(&mut client.buf);
    let early_down = std::mem::take(&mut up.buf);
    let (mut client_r, mut client_w) = tokio::io::split(&mut client.s);
    let (mut up_r, mut up_w) = tokio::io::split(&mut up.s);
    let sent = std::sync::atomic::AtomicU64::new(0);
    let received = std::sync::atomic::AtomicU64::new(0);
    let to_upstream = async {
        if up_w.write_all(&early_up).await.is_err() {
            return;
        }
        sent.fetch_add(early_up.len() as u64, std::sync::atomic::Ordering::Relaxed);
        let mut chunk = vec![0u8; READ_CHUNK];
        loop {
            match client_r.read(&mut chunk).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if up_w.write_all(&chunk[..n]).await.is_err() {
                        break;
                    }
                    sent.fetch_add(n as u64, std::sync::atomic::Ordering::Relaxed);
                }
            }
        }
        let _ = up_w.shutdown().await;
    };
    let to_client = async {
        let mut pending = early_down;
        loop {
            if !pending.is_empty() {
                received.fetch_add(pending.len() as u64, std::sync::atomic::Ordering::Relaxed);
                let released = match guard.as_deref_mut() {
                    Some(g) => match g.push(&pending) {
                        Ok(r) => r,
                        Err(_) => return true,
                    },
                    None => std::mem::take(&mut pending),
                };
                pending.clear();
                if client_w.write_all(&released).await.is_err() || client_w.flush().await.is_err() {
                    return false;
                }
            }
            let mut chunk = vec![0u8; READ_CHUNK];
            match up_r.read(&mut chunk).await {
                Ok(0) | Err(_) => {
                    if let Some(g) = guard.as_deref_mut() {
                        let _ = client_w.write_all(&g.finish()).await;
                    }
                    let _ = client_w.shutdown().await;
                    return false;
                }
                Ok(n) => {
                    chunk.truncate(n);
                    pending = chunk;
                }
            }
        }
    };
    let reflected = tokio::select! {
        _ = to_upstream => false,
        reflected = to_client => reflected,
    };
    Spliced {
        up: sent.into_inner(),
        down: received.into_inner(),
        reflected,
    }
}

/// An idle upstream connection is reused only for the host, port and transport it was opened for.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
struct PoolKey {
    host: CanonicalHost,
    port: u16,
    tls: bool,
}

/// The session's keep-alive upstream connections (FEP-6 §4.4), each idle for at most
/// **idle-timeout**.
#[derive(Default)]
pub(crate) struct Pool {
    idle: std::sync::Mutex<HashMap<PoolKey, Vec<Idle>>>,
}

/// An upstream connection and when it went idle.
type Idle = (Instant, Buffered<BoxIo>);

impl Pool {
    async fn take(&self, key: &PoolKey) -> Option<Buffered<BoxIo>> {
        loop {
            let (since, mut conn) = self.idle.lock().ok()?.get_mut(key)?.pop()?;
            if since.elapsed() >= IDLE_TIMEOUT || !conn.buf.is_empty() {
                continue;
            }
            // A connection the upstream closed while idle reads EOF at once; a live one blocks.
            // One poll, not `timeout(Duration::ZERO, ..)`: a zero timeout still waits for the
            // timer's next 1 ms tick, which every reused request paid (found by FW-E2E-096).
            let pending = {
                let mut fill = std::pin::pin!(conn.fill());
                std::future::poll_fn(|cx| {
                    std::task::Poll::Ready(
                        std::future::Future::poll(fill.as_mut(), cx).is_pending(),
                    )
                })
                .await
            };
            if pending {
                return Some(conn);
            }
        }
    }

    fn put(&self, key: PoolKey, conn: Buffered<BoxIo>) {
        if let Ok(mut idle) = self.idle.lock() {
            let list = idle.entry(key).or_default();
            list.retain(|(since, _)| since.elapsed() < IDLE_TIMEOUT);
            if list.len() < MAX_IDLE_PER_HOST {
                list.push((Instant::now(), conn));
            }
        }
    }
}

/// A new upstream connection for a destination: TLS verified against the host trust store for the
/// requested name (FW-EGR24), or plain TCP. `Err(Some)` is a refusal (`upstream-tls`); `Err(None)`
/// an upstream that was unreachable, which is not a policy decision.
async fn connect_upstream(
    shared: &Shared,
    dest: &Destination,
    tls: bool,
) -> Result<Buffered<BoxIo>, Option<Refusal>> {
    let host = &dest.host;
    let tcp = match dial(dest, tls).await {
        Ok(t) => t,
        Err(why) => {
            tracing::info!(host = %host, port = dest.port, %why, "egress upstream unavailable");
            return Err(None);
        }
    };
    if !tls {
        return Ok(Buffered::new(tcp, Vec::new()));
    }
    let Some(inspection) = &shared.config.inspection else {
        return Err(None);
    };
    let name = match host {
        CanonicalHost::Name(n) => ServerName::try_from(n.clone()).map_err(|_| None)?,
        CanonicalHost::Ip(ip) => ServerName::IpAddress((*ip).into()),
    };
    let connector = tokio_rustls::TlsConnector::from(inspection.upstream.clone());
    match tokio::time::timeout(HEAD_TIMEOUT, connector.connect(name, tcp)).await {
        Ok(Ok(tls)) => Ok(Buffered::new(Box::new(tls), Vec::new())),
        Ok(Err(e))
            if e.get_ref()
                .is_some_and(|inner| inner.downcast_ref::<rustls::Error>().is_some()) =>
        {
            Err(Some(Refusal::new(
                RefusalReason::UpstreamTls,
                format!(
                    "the upstream certificate for {host} did not verify against the host trust \
                     store: {e} (FW-EGR24)"
                ),
            )))
        }
        Ok(Err(e)) => {
            tracing::info!(host = %host, error = %e, "egress upstream TLS failed");
            Err(None)
        }
        Err(_) => Err(None),
    }
}

fn carries(value: &str, placeholder: &str) -> bool {
    value.contains(placeholder) || basic_decoded(value).is_some_and(|d| d.contains(placeholder))
}

fn carries_any(value: &str, brokers: &[&Broker]) -> bool {
    brokers.iter().any(|b| carries(value, &b.placeholder))
}

/// The placeholder scan (FEP-6 §4.7): every occurrence of the placeholder prefix in the request
/// target or a header value (a `Basic` value decoded) must be a known placeholder, bound to this
/// host, in its scheme's header, on a request forwarded over TLS.
fn scan_placeholders(
    head: &Head,
    target: &str,
    host: &CanonicalHost,
    brokers: &[Broker],
    plain: bool,
) -> Result<(), String> {
    let mut sites: Vec<(Option<&str>, bool, String)> = vec![(None, false, target.to_string())];
    for (name, value) in &head.headers {
        sites.push((Some(name.as_str()), false, value.clone()));
        if name.eq_ignore_ascii_case("authorization") {
            if let Some(decoded) = basic_decoded(value) {
                sites.push((Some(name.as_str()), true, decoded));
            }
        }
    }
    for (site, basic, text) in &sites {
        for (i, _) in text.match_indices(PLACEHOLDER_PREFIX) {
            let where_ = site
                .map(|n| format!("the {n} header"))
                .unwrap_or_else(|| "the request target".to_string());
            let Some(b) = brokers
                .iter()
                .find(|b| text[i..].starts_with(&b.placeholder))
            else {
                return Err(format!("an unknown placeholder in {where_}"));
            };
            if plain {
                return Err(format!(
                    "the {} placeholder was sent over plain HTTP, where no credential is ever \
                     presented (FW-CRED19)",
                    b.name
                ));
            }
            let Some((_, scheme)) = b.bindings.iter().find(|(h, _)| h == host) else {
                return Err(format!(
                    "the {} placeholder was sent to {host}, which it is not bound to",
                    b.name
                ));
            };
            let (header, as_basic) = match scheme {
                BrokerScheme::Bearer => ("authorization", false),
                BrokerScheme::Basic { .. } => ("authorization", true),
                BrokerScheme::Header(name) => (name.as_str(), false),
            };
            let in_place =
                site.is_some_and(|n| n.eq_ignore_ascii_case(header)) && *basic == as_basic;
            if !in_place {
                return Err(format!(
                    "the {} placeholder appears in {where_}, outside its scheme's header ({scheme})",
                    b.name
                ));
            }
        }
    }
    Ok(())
}

/// Present each brokered credential bound to this host (FW-CRED11): substitute its placeholder in
/// the scheme's header, or add the header when the request carries none; a request that already
/// carries another credential there is forwarded unchanged. Returns the wire encodings presented
/// -- the secret and the full scheme value -- for the reflection guard.
fn present(
    headers: &mut Vec<(String, String)>,
    host: &CanonicalHost,
    brokered: &[&Broker],
) -> Vec<Vec<u8>> {
    let mut encodings = Vec::new();
    for b in brokered {
        let Some((_, scheme)) = b.bindings.iter().find(|(h, _)| h == host) else {
            continue;
        };
        let (name, value) = match scheme {
            BrokerScheme::Bearer => ("Authorization", format!("Bearer {}", b.secret)),
            BrokerScheme::Header(name) => (name.as_str(), b.secret.clone()),
            BrokerScheme::Basic { user } => ("Authorization", basic_value(user, &b.secret)),
        };
        let position = headers
            .iter()
            .position(|(n, _)| n.eq_ignore_ascii_case(name));
        let presented = match position {
            None => {
                headers.push((name.to_string(), value.clone()));
                true
            }
            Some(i) if carries(&headers[i].1, &b.placeholder) => {
                headers[i].1 = match scheme {
                    BrokerScheme::Header(_) => headers[i].1.replace(&b.placeholder, &b.secret),
                    _ => value.clone(),
                };
                true
            }
            Some(_) => false,
        };
        if presented {
            encodings.push(b.secret.as_bytes().to_vec());
            encodings.push(value.into_bytes());
        }
    }
    encodings
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn a_client_rejecting_the_session_ca_is_recognized() {
        // FW-FID9: a client that does not trust the session CA fails the handshake with an alert
        // the Gateway must recognize to emit its diagnosis line.
        let pattern = formwork_blueprint::HostPattern::Exact("api.test".into());
        let ca = crate::ca::SessionCa::generate(&[&pattern]).unwrap();
        let host = CanonicalHost::Name("api.test".into());
        let acceptor = tokio_rustls::TlsAcceptor::from(ca.server_config(&host).unwrap());
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let client = rustls::ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(rustls::RootCertStore::empty())
            .with_no_client_auth();
        let connector = tokio_rustls::TlsConnector::from(Arc::new(client));
        let (a, b) = tokio::io::duplex(64 * 1024);
        let name = ServerName::try_from("api.test").unwrap();
        let (server, _client) = tokio::join!(acceptor.accept(a), connector.connect(name, b));
        let err = server.expect_err("the handshake fails");
        assert!(rejected_our_ca(&err), "{err:?}");
    }

    fn broker(scheme: BrokerScheme) -> Broker {
        Broker {
            name: "github".into(),
            placeholder: "fwcred-github-abc".into(),
            secret: "ghp_REAL".into(),
            bindings: vec![(CanonicalHost::Name("api.github.com".into()), scheme)],
        }
    }

    fn head(headers: &[(&str, &str)]) -> Head {
        Head {
            method: "GET".into(),
            target: "/".into(),
            headers: headers
                .iter()
                .map(|(n, v)| (n.to_string(), v.to_string()))
                .collect(),
        }
    }

    #[test]
    fn presentation_substitutes_adds_and_leaves_other_credentials() {
        let bearer = broker(BrokerScheme::Bearer);
        let mut h = vec![(
            "Authorization".to_string(),
            "Bearer fwcred-github-abc".to_string(),
        )];
        let gh = CanonicalHost::Name("api.github.com".into());
        let presented = present(&mut h, &gh, &[&bearer]);
        assert_eq!(h[0].1, "Bearer ghp_REAL");
        assert!(presented.contains(&b"ghp_REAL".to_vec()));
        let mut none = vec![];
        present(&mut none, &gh, &[&bearer]);
        assert_eq!(none[0].1, "Bearer ghp_REAL", "added when absent");
        let mut own = vec![("authorization".to_string(), "Bearer mine".to_string())];
        assert!(present(&mut own, &gh, &[&bearer]).is_empty());
        assert_eq!(
            own[0].1, "Bearer mine",
            "a non-placeholder credential passes unchanged"
        );
        let basic = broker(BrokerScheme::Basic {
            user: "x-access-token".into(),
        });
        let mut git = vec![];
        let presented = present(&mut git, &gh, &[&basic]);
        let value = format!("Basic {}", BASE64.encode(b"x-access-token:ghp_REAL"));
        assert_eq!(git[0].1, value);
        assert!(
            presented.contains(&value.into_bytes()),
            "the full scheme value is guarded"
        );
    }

    #[test]
    fn the_placeholder_scan_refuses_every_misplaced_placeholder() {
        let gh = CanonicalHost::Name("api.github.com".into());
        let other = CanonicalHost::Name("evil.test".into());
        let brokers = vec![broker(BrokerScheme::Bearer)];
        let ok = head(&[("Authorization", "Bearer fwcred-github-abc")]);
        assert!(scan_placeholders(&ok, "/", &gh, &brokers, false).is_ok());
        assert!(scan_placeholders(&ok, "/", &other, &brokers, false).is_err());
        assert!(scan_placeholders(&ok, "/", &gh, &brokers, true).is_err());
        let in_query = head(&[]);
        assert!(
            scan_placeholders(&in_query, "/?k=fwcred-github-abc", &gh, &brokers, false).is_err()
        );
        let elsewhere = head(&[("X-Debug", "fwcred-github-abc")]);
        assert!(scan_placeholders(&elsewhere, "/", &gh, &brokers, false).is_err());
        let unknown = head(&[("Authorization", "Bearer fwcred-other-zzz")]);
        assert!(scan_placeholders(&unknown, "/", &gh, &brokers, false).is_err());
        let basic_brokers = vec![broker(BrokerScheme::Basic { user: "x".into() })];
        let basic = head(&[(
            "Authorization",
            &format!("Basic {}", BASE64.encode("x:fwcred-github-abc")),
        )]);
        assert!(scan_placeholders(&basic, "/", &gh, &basic_brokers, false).is_ok());
    }

    #[test]
    fn absolute_targets_split_with_their_query() {
        assert_eq!(
            split_absolute("http://a.test:8080/x?q=1"),
            Some(("a.test:8080", "/x?q=1".to_string()))
        );
        assert_eq!(
            split_absolute("http://a.test?q=1"),
            Some(("a.test", "/?q=1".to_string()))
        );
        assert_eq!(
            split_absolute("http://a.test"),
            Some(("a.test", "/".to_string()))
        );
        assert_eq!(split_absolute("https://a.test/"), None);
    }
}
