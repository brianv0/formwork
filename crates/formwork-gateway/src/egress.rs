//! The Gateway's egress listener (FW-EGR1, FEP-5 §3.1): the one network door of a host-scoped
//! session. An HTTP proxy on a loopback port that admits only registered connections (the Linux
//! supervisor registers each one it performs, FW-EGR9) carrying the per-session credential, and
//! forwards only what the host table admits:
//!
//! - `CONNECT host:port` to a tunnel-grade host splices bytes to the upstream (FW-EGR5: the request
//!   stays opaque);
//! - an absolute-form plain-HTTP request is checked by method and canonical path when its host is
//!   inspected, or by host when it is tunnel-grade, then forwarded once with `Connection: close`;
//! - an inspected host over TLS is terminated by the inspection layer (FW-EGR10).
//!
//! Names resolve once, here, and the address connected to is the address checked: a name that
//! resolves into a restricted range is refused however it is allowlisted (FW-EGR4, FW-ADV-008).
//! Every refusal is a structured violation record on the operator channel naming the rule and the
//! `explain` invocation that reproduces it (FW-FID5, FW-FID9), while the client gets a generic 403
//! (FW-CRED7).

use std::collections::{BTreeMap, HashSet, VecDeque};
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::io::{AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use formwork_blueprint::{
    canonicalize_host, canonicalize_request_path, is_restricted_ip, split_host_port, split_url,
    CanonicalHost, ConnectDecision, Denial, HostTable, HttpMethod, DEFAULT_HTTPS_PORT,
};

use crate::inspect::{
    basic_value, render_request, request_framing, Broker, Buffered, Inspection, Scrubber,
};
use crate::GatewayError;

/// Bound on a message head, so a peer that never ends its headers cannot make the Gateway buffer
/// without limit (a stability bound, like `MAX_FRAME_BYTES`).
pub(crate) const MAX_HEAD_BYTES: usize = 64 * 1024;
/// The reproduction for a refusal that names no destination.
const EXPLAIN_HOSTS: &str = "formwork explain --hosts";
const UPSTREAM_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// Violation records kept for an embedder or test to read back; older ones are dropped.
const MAX_KEPT_VIOLATIONS: usize = 1024;

/// How the Gateway resolves names. `System` is the host resolver. `Fixture` maps names to
/// addresses with no DNS at all -- the controlled input the egress tests drive the real Gateway
/// with (FEP-1 test harness); it is reachable only through this library API, never the CLI.
#[derive(Clone, Debug)]
pub enum Resolver {
    System,
    Fixture {
        map: BTreeMap<String, Vec<IpAddr>>,
        /// Fixture upstreams listen on loopback; a fixture's loopback answers are therefore not a
        /// rebinding. Private, link-local and metadata answers are still refused.
        loopback_upstreams: bool,
    },
}

/// Who may use the listener (FW-EGR9).
#[derive(Clone, Debug)]
pub struct Admission {
    /// The per-session credential every request carries (`Proxy-Authorization: Basic`).
    pub credential: String,
    /// Linux: source ports the supervisor registered for connections it performed. A connection
    /// from an unregistered port is refused before a byte is read. `None` on macOS, where the
    /// credential is the admission (FW-EGR9's residual, reported `Partial`).
    pub registry: Option<Arc<Mutex<HashSet<u16>>>>,
}

#[derive(Clone, Debug)]
pub struct EgressConfig {
    pub table: HostTable,
    pub resolver: Resolver,
    pub admission: Admission,
    /// The session CA and upstream trust, when any host is inspected (FW-EGR10/EGR13).
    pub inspection: Option<Inspection>,
    /// Brokered credentials (FW-CRED11).
    pub brokers: Vec<Broker>,
}

/// One refusal (FW-FID5): what was refused, why, the deciding rule, and the reproduction.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize)]
pub struct Violation {
    pub kind: &'static str,
    pub target: String,
    pub reason: String,
    pub rule: Option<String>,
    pub explain: String,
    /// What the session needed, when the refusal was a policy decision `learn` can propose a rule
    /// for (FW-DISC12). Absent for protocol refusals (malformed, smuggling-shaped, mismatched).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub need: Option<formwork_blueprint::EgressObservation>,
}

/// A refused destination, as `learn` sees it.
pub(crate) fn need(
    host: &CanonicalHost,
    port: u16,
    request: Option<(&str, &str)>,
) -> Option<formwork_blueprint::EgressObservation> {
    Some(formwork_blueprint::EgressObservation {
        host: host.to_string(),
        port,
        method: request.map(|(m, _)| m.to_string()),
        path: request.map(|(_, p)| p.to_string()),
    })
}

/// A running egress listener. Dropping it stops the listener and joins its thread.
pub struct EgressProxy {
    addr: SocketAddr,
    credential: String,
    violations: Arc<Mutex<VecDeque<Violation>>>,
    shutdown: Option<tokio::sync::oneshot::Sender<()>>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl EgressProxy {
    /// Bind `127.0.0.1:0` and serve on a dedicated thread with its own runtime, so the caller (the
    /// synchronous CLI) stays free of tokio (constitution Layers).
    pub fn start(config: EgressConfig) -> Result<EgressProxy, GatewayError> {
        let std_listener = std::net::TcpListener::bind(("127.0.0.1", 0))?;
        std_listener.set_nonblocking(true)?;
        let addr = std_listener.local_addr()?;
        let violations = Arc::new(Mutex::new(VecDeque::new()));
        let (tx, rx) = tokio::sync::oneshot::channel::<()>();
        let credential = config.admission.credential.clone();
        let shared = Arc::new(Shared {
            expected_auth: basic_value("fw", &credential),
            secrets: Scrubber::secrets_of(&config.brokers),
            config,
            violations: violations.clone(),
        });
        let thread = std::thread::Builder::new()
            .name("formwork-egress".into())
            .spawn(move || {
                let runtime = match tokio::runtime::Builder::new_multi_thread()
                    .worker_threads(2)
                    .enable_all()
                    .build()
                {
                    Ok(rt) => rt,
                    Err(e) => {
                        tracing::error!(error = %e, "formwork: egress listener runtime failed to start");
                        return;
                    }
                };
                runtime.block_on(async move {
                    let listener = match TcpListener::from_std(std_listener) {
                        Ok(l) => l,
                        Err(e) => {
                            tracing::error!(error = %e, "formwork: egress listener failed");
                            return;
                        }
                    };
                    tokio::select! {
                        _ = rx => {}
                        _ = accept_loop(listener, shared) => {}
                    }
                });
            })?;
        tracing::info!(listener = %addr, "gateway egress listener started (FW-EGR14)");
        Ok(EgressProxy {
            addr,
            credential,
            violations,
            shutdown: Some(tx),
            thread: Some(thread),
        })
    }

    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    /// The value for `HTTP(S)_PROXY` in the confined child.
    pub fn proxy_url(&self) -> String {
        format!("http://fw:{}@{}", self.credential, self.addr)
    }

    /// The refusals recorded so far, oldest first.
    pub fn violations(&self) -> Vec<Violation> {
        self.violations
            .lock()
            .map(|v| v.iter().cloned().collect())
            .unwrap_or_default()
    }

    /// Whether the listener thread is still serving; a dead listener is a Formwork failure after
    /// spawn (FW-XR11).
    pub fn is_alive(&self) -> bool {
        self.thread
            .as_ref()
            .map(|t| !t.is_finished())
            .unwrap_or(false)
    }
}

impl Drop for EgressProxy {
    fn drop(&mut self) {
        if let Some(tx) = self.shutdown.take() {
            let _ = tx.send(());
        }
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}

pub(crate) struct Shared {
    pub(crate) config: EgressConfig,
    /// The `Proxy-Authorization` value every admitted request carries (FW-EGR9).
    expected_auth: String,
    /// The brokered secrets response scrubbers mask (FW-INV13).
    pub(crate) secrets: Arc<[Vec<u8>]>,
    violations: Arc<Mutex<VecDeque<Violation>>>,
}

impl Shared {
    pub(crate) fn refuse(
        &self,
        kind: &'static str,
        target: &str,
        reason: &str,
        rule: Option<String>,
        explain: String,
    ) {
        self.refuse_needing(kind, target, reason, rule, explain, None)
    }

    /// As [`Shared::refuse`], recording what the session needed (FW-DISC12).
    pub(crate) fn refuse_needing(
        &self,
        kind: &'static str,
        target: &str,
        reason: &str,
        rule: Option<String>,
        explain: String,
        need: Option<formwork_blueprint::EgressObservation>,
    ) {
        let v = Violation {
            kind,
            target: target.to_string(),
            reason: reason.to_string(),
            rule,
            explain,
            need,
        };
        // FW-FID9: one operator-channel line naming what was refused, the deciding rule, and the
        // reproduction; the confined client sees only a generic refusal.
        tracing::warn!(
            violation = kind,
            target = %v.target,
            rule = v.rule.as_deref().unwrap_or("(no rule admits it)"),
            reproduce = %v.explain,
            "formwork: refused {kind} {} -- {}",
            v.target,
            v.reason
        );
        if let Ok(mut all) = self.violations.lock() {
            if all.len() >= MAX_KEPT_VIOLATIONS {
                all.pop_front();
            }
            all.push_back(v);
        }
    }
}

async fn accept_loop(listener: TcpListener, shared: Arc<Shared>) {
    loop {
        let (stream, peer) = match listener.accept().await {
            Ok(x) => x,
            Err(e) => {
                tracing::warn!(error = %e, "egress accept failed");
                continue;
            }
        };
        if let Some(registry) = &shared.config.admission.registry {
            // FW-EGR9: only connections the supervisor performed (and registered) are admitted;
            // a co-resident process that found the port is dropped before a byte is read.
            let registered = registry
                .lock()
                .map(|mut r| r.remove(&peer.port()))
                .unwrap_or(false);
            if !registered {
                shared.refuse(
                    "unregistered-connection",
                    &peer.to_string(),
                    "the connection was not made through the session's supervisor",
                    None,
                    EXPLAIN_HOSTS.into(),
                );
                continue;
            }
        }
        let shared = shared.clone();
        tokio::spawn(async move {
            if let Err(e) = serve(stream, shared).await {
                tracing::debug!(error = %e, "egress connection ended");
            }
        });
    }
}

/// A parsed request head.
pub(crate) struct Head {
    pub(crate) method: String,
    pub(crate) target: String,
    pub(crate) headers: Vec<(String, String)>,
}

/// A parsed response head.
pub(crate) struct ResponseHead {
    pub(crate) version: String,
    pub(crate) status: u16,
    pub(crate) reason: String,
    pub(crate) headers: Vec<(String, String)>,
}

fn find_header<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|(n, _)| n.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.as_str())
}

impl Head {
    pub(crate) fn header(&self, name: &str) -> Option<&str> {
        find_header(&self.headers, name)
    }
}

impl ResponseHead {
    pub(crate) fn header(&self, name: &str) -> Option<&str> {
        find_header(&self.headers, name)
    }
}

/// Split a head into its start line and strictly parsed headers: CRLF line endings, no obsolete
/// line folding, no NUL, one `name: value` per line with a token name. Anything else is refused
/// rather than guessed at (FW-EGR11's spirit at the head).
fn parse_lines(raw: &[u8]) -> Option<(&str, Vec<(String, String)>)> {
    let text = std::str::from_utf8(raw).ok()?;
    if text.contains('\0') {
        return None;
    }
    let mut lines = text.split("\r\n");
    let start = lines.next()?;
    let mut headers = Vec::new();
    for line in lines {
        if line.is_empty() {
            continue;
        }
        if line.starts_with(' ')
            || line.starts_with('\t')
            || line.contains('\n')
            || line.contains('\r')
        {
            return None;
        }
        let (name, value) = line.split_once(':')?;
        if name.is_empty() || name.contains(' ') {
            return None;
        }
        headers.push((name.to_string(), value.trim().to_string()));
    }
    Some((start, headers))
}

fn http_version(v: &str) -> bool {
    v == "HTTP/1.1" || v == "HTTP/1.0"
}

/// A request head: `METHOD target HTTP/1.x`, then headers.
pub(crate) fn parse_head(raw: &[u8]) -> Option<Head> {
    let (start, headers) = parse_lines(raw)?;
    let mut parts = start.split(' ');
    let method = parts.next()?.to_string();
    let target = parts.next()?.to_string();
    let version = parts.next()?;
    if parts.next().is_some() || !http_version(version) {
        return None;
    }
    Some(Head {
        method,
        target,
        headers,
    })
}

/// A response head: `HTTP/1.x <3-digit status> [reason]`, then headers.
pub(crate) fn parse_response_head(raw: &[u8]) -> Option<ResponseHead> {
    let (start, headers) = parse_lines(raw)?;
    let mut parts = start.splitn(3, ' ');
    let version = parts.next()?;
    let status = parts.next()?;
    let reason = parts.next().unwrap_or("").to_string();
    if !http_version(version) || status.len() != 3 || !status.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    Some(ResponseHead {
        version: version.to_string(),
        status: status.parse().ok()?,
        reason,
        headers,
    })
}

/// A Gateway-originated response, then close. A 403 carries the one generic refusal body the
/// confined client ever sees (FW-CRED7).
pub(crate) async fn respond<W: AsyncWrite + Unpin>(
    stream: &mut W,
    status: &str,
    extra: &str,
) -> std::io::Result<()> {
    let body = if status.starts_with("403") {
        "denied by formwork policy\n"
    } else {
        ""
    };
    let msg = format!(
        "HTTP/1.1 {status}\r\n{extra}Content-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    stream.write_all(msg.as_bytes()).await?;
    stream.shutdown().await
}

/// Compare without an early exit on the first differing byte.
fn same_secret(a: &str, b: &str) -> bool {
    a.len() == b.len()
        && a.bytes()
            .zip(b.bytes())
            .fold(0u8, |acc, (x, y)| acc | (x ^ y))
            == 0
}

pub(crate) fn explain_hint(scheme: &str, host: &CanonicalHost, port: u16, path: &str) -> String {
    let default = if scheme == "https" {
        DEFAULT_HTTPS_PORT
    } else {
        formwork_blueprint::DEFAULT_HTTP_PORT
    };
    if port == default {
        format!("formwork explain {scheme}://{host}{path}")
    } else {
        format!("formwork explain {scheme}://{host}:{port}{path}")
    }
}

async fn serve(stream: TcpStream, shared: Arc<Shared>) -> std::io::Result<()> {
    let mut client = Buffered::new(stream, Vec::new());
    let Some(head) = client.head().await? else {
        return Ok(());
    };
    let (mut stream, leftover) = (client.s, client.buf);
    let presented = head.header("Proxy-Authorization").unwrap_or("");
    if !same_secret(presented, &shared.expected_auth) {
        return respond(
            &mut stream,
            "407 Proxy Authentication Required",
            "Proxy-Authenticate: Basic realm=\"formwork\"\r\n",
        )
        .await;
    }
    if head.method == "CONNECT" {
        serve_connect(stream, head, leftover, shared).await
    } else {
        serve_plain(stream, head, leftover, shared).await
    }
}

/// Resolve and pin (FW-EGR4, FW-ADV-008): the first address that is not restricted -- unless the
/// host is an IP literal a rule names, which is the explicit naming EGR4 requires.
pub(crate) async fn resolve(
    shared: &Shared,
    host: &CanonicalHost,
    port: u16,
) -> Result<SocketAddr, String> {
    if host.is_restricted() && !shared.config.table.names_explicitly(host) {
        return Err(match host {
            CanonicalHost::Ip(ip) => format!(
                "{ip} is a restricted address (metadata, private, loopback or link-local) and no \
                 rule names it (FW-EGR4)"
            ),
            CanonicalHost::Name(name) => {
                format!("{name} is a metadata service and no rule names it (FW-EGR4)")
            }
        });
    }
    match host {
        CanonicalHost::Ip(ip) => Ok(SocketAddr::new(*ip, port)),
        CanonicalHost::Name(name) => {
            let (candidates, loopback_ok): (Vec<IpAddr>, bool) = match &shared.config.resolver {
                Resolver::Fixture {
                    map,
                    loopback_upstreams,
                } => (
                    map.get(name).cloned().unwrap_or_default(),
                    *loopback_upstreams,
                ),
                Resolver::System => (
                    tokio::net::lookup_host((name.as_str(), port))
                        .await
                        .map_err(|e| format!("{name} did not resolve: {e}"))?
                        .map(|a| a.ip())
                        .collect(),
                    false,
                ),
            };
            if candidates.is_empty() {
                return Err(format!("{name} did not resolve"));
            }
            candidates
                .into_iter()
                .map(formwork_blueprint::canonical_ip)
                .find(|ip| !is_restricted_ip(*ip) || (loopback_ok && ip.is_loopback()))
                .map(|ip| SocketAddr::new(ip, port))
                .ok_or_else(|| {
                    format!(
                        "{name} resolves only to restricted addresses; a name never admits a \
                         restricted address (FW-EGR4, DNS rebinding)"
                    )
                })
        }
    }
}

pub(crate) async fn connect_upstream(addr: SocketAddr) -> Result<TcpStream, String> {
    match tokio::time::timeout(UPSTREAM_CONNECT_TIMEOUT, TcpStream::connect(addr)).await {
        Ok(Ok(s)) => Ok(s),
        Ok(Err(e)) => Err(format!("upstream {addr} refused: {e}")),
        Err(_) => Err(format!("upstream {addr} timed out")),
    }
}

async fn serve_connect(
    mut stream: TcpStream,
    head: Head,
    leftover: Vec<u8>,
    shared: Arc<Shared>,
) -> std::io::Result<()> {
    let target = head.target.as_str();
    let Ok((raw_host, port)) = split_host_port(target) else {
        shared.refuse(
            "connect",
            target,
            "malformed CONNECT target",
            None,
            EXPLAIN_HOSTS.into(),
        );
        return respond(&mut stream, "400 Bad Request", "").await;
    };
    let port = port.unwrap_or(DEFAULT_HTTPS_PORT);
    let host = match canonicalize_host(raw_host) {
        Ok(h) => h,
        Err(e) => {
            shared.refuse(
                "connect",
                target,
                &e.to_string(),
                None,
                EXPLAIN_HOSTS.into(),
            );
            return respond(&mut stream, "403 Forbidden", "").await;
        }
    };
    let hint = explain_hint("https", &host, port, "");
    match shared.config.table.decide_connect(&host, port) {
        ConnectDecision::Tunnel(_) => {}
        ConnectDecision::Inspect => {
            return crate::inspect::serve_inspected(stream, host, port, leftover, shared.clone())
                .await;
        }
        ConnectDecision::Deny(Denial { reason, rule }) => {
            shared.refuse_needing(
                "connect",
                &format!("{host}:{port}"),
                &reason,
                rule.map(|r| r.to_string()),
                hint,
                need(&host, port, None),
            );
            return respond(&mut stream, "403 Forbidden", "").await;
        }
    }
    let addr = match resolve(&shared, &host, port).await {
        Ok(a) => a,
        Err(reason) => {
            shared.refuse_needing(
                "connect",
                &format!("{host}:{port}"),
                &reason,
                None,
                hint,
                need(&host, port, None),
            );
            return respond(&mut stream, "403 Forbidden", "").await;
        }
    };
    let mut upstream = match connect_upstream(addr).await {
        Ok(u) => u,
        Err(reason) => {
            tracing::info!(target = %format!("{host}:{port}"), %reason, "egress upstream unavailable");
            return respond(&mut stream, "502 Bad Gateway", "").await;
        }
    };
    tracing::info!(host = %host, port, upstream = %addr, "egress tunnel opened");
    stream
        .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        .await?;
    if !leftover.is_empty() {
        upstream.write_all(&leftover).await?;
    }
    let _ = tokio::io::copy_bidirectional(&mut stream, &mut upstream).await;
    Ok(())
}

/// A plain-HTTP request in absolute form (`GET http://host/path HTTP/1.1`): decided by host, and by
/// method and canonical path when the host is inspected, then forwarded once.
async fn serve_plain(
    mut stream: TcpStream,
    head: Head,
    leftover: Vec<u8>,
    shared: Arc<Shared>,
) -> std::io::Result<()> {
    let parsed = head
        .target
        .starts_with("http://")
        .then(|| split_url(&head.target).ok())
        .flatten();
    let Some((raw_host, port, raw_path)) = parsed else {
        shared.refuse(
            "request",
            &head.target,
            "only CONNECT and absolute-form http:// requests reach the Gateway",
            None,
            EXPLAIN_HOSTS.into(),
        );
        return respond(&mut stream, "400 Bad Request", "").await;
    };
    let host = match canonicalize_host(raw_host) {
        Ok(h) => h,
        Err(e) => {
            shared.refuse(
                "request",
                raw_host,
                &e.to_string(),
                None,
                EXPLAIN_HOSTS.into(),
            );
            return respond(&mut stream, "403 Forbidden", "").await;
        }
    };
    let path = match canonicalize_request_path(raw_path) {
        Ok(p) => p,
        Err(reason) => {
            shared.refuse(
                "request",
                &format!("{host}{raw_path}"),
                &reason,
                None,
                EXPLAIN_HOSTS.into(),
            );
            return respond(&mut stream, "403 Forbidden", "").await;
        }
    };
    if let Err(reason) = request_framing(&head) {
        shared.refuse(
            "request",
            &format!("{host}{path}"),
            &format!("request smuggling shape: {reason} (FW-EGR11)"),
            None,
            EXPLAIN_HOSTS.into(),
        );
        return respond(&mut stream, "403 Forbidden", "").await;
    }
    let hint = explain_hint("http", &host, port, &path);
    // A brokered credential is never presented over plain HTTP, and its placeholder never leaves
    // unencrypted (FW-CRED11).
    if let Some(b) = shared
        .config
        .brokers
        .iter()
        .find(|b| head.headers.iter().any(|(_, v)| v.contains(&b.placeholder)))
    {
        shared.refuse(
            "request",
            &format!("{} {host}:{port}{path}", head.method),
            &format!("the {} placeholder was sent over plain HTTP", b.name),
            None,
            hint,
        );
        return respond(&mut stream, "403 Forbidden", "").await;
    }
    let method = HttpMethod::from_token(&head.method);
    if let Err(Denial { reason, rule }) = shared.config.table.decide(&host, port, method, &path) {
        shared.refuse_needing(
            "request",
            &format!("{} {host}:{port}{path}", head.method),
            &reason,
            rule.map(|r| r.to_string()),
            hint,
            need(&host, port, Some((&head.method, &path))),
        );
        return respond(&mut stream, "403 Forbidden", "").await;
    }
    let addr = match resolve(&shared, &host, port).await {
        Ok(a) => a,
        Err(reason) => {
            shared.refuse_needing(
                "request",
                &format!("{host}:{port}"),
                &reason,
                None,
                hint,
                need(&host, port, None),
            );
            return respond(&mut stream, "403 Forbidden", "").await;
        }
    };
    let mut upstream = match connect_upstream(addr).await {
        Ok(u) => u,
        Err(_) => return respond(&mut stream, "502 Bad Gateway", "").await,
    };
    // Origin-form request line; the proxy credential and hop-by-hop headers stay here.
    let hop = [
        "proxy-authorization",
        "proxy-connection",
        "connection",
        "keep-alive",
    ];
    let mut headers: Vec<(String, String)> = head
        .headers
        .iter()
        .filter(|(name, _)| !hop.contains(&name.to_ascii_lowercase().as_str()))
        .cloned()
        .collect();
    headers.push(("Connection".into(), "close".into()));
    upstream
        .write_all(&render_request(&head, raw_path, &headers))
        .await?;
    if !leftover.is_empty() {
        upstream.write_all(&leftover).await?;
    }
    let _ = tokio::io::copy_bidirectional(&mut stream, &mut upstream).await;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn heads_parse_strictly() {
        let h = parse_head(b"CONNECT a.test:443 HTTP/1.1\r\nHost: a.test\r\n\r\n").unwrap();
        assert_eq!(h.method, "CONNECT");
        assert_eq!(h.header("host"), Some("a.test"));
        assert!(parse_head(b"GET / HTTP/1.1\r\n folded\r\n\r\n").is_none());
        assert!(parse_head(b"GET / HTTP/2\r\n\r\n").is_none());
        assert!(parse_head(b"GET  / HTTP/1.1\r\n\r\n").is_none());
        let r = parse_response_head(b"HTTP/1.1 404 Not Found\r\nA: b\r\n\r\n").unwrap();
        assert_eq!((r.status, r.reason.as_str()), (404, "Not Found"));
        assert!(parse_response_head(b"HTTP/1.1 20 X\r\n\r\n").is_none());
    }
}
