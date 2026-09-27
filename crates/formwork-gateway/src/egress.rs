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

use std::collections::{BTreeMap, HashSet};
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use formwork_blueprint::{
    canonicalize_host, canonicalize_request_path, is_restricted_ip, CanonicalHost, EgressDecision,
    HostTable, HttpMethod, METADATA_HOSTNAMES,
};

use crate::GatewayError;

/// Bound on a request head, so a client that never ends its headers cannot make the Gateway buffer
/// without limit (a stability bound, like `MAX_FRAME_BYTES`).
const MAX_HEAD_BYTES: usize = 64 * 1024;
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
}

/// One refusal (FW-FID5): what was refused, why, the deciding rule, and the reproduction.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize)]
pub struct Violation {
    pub kind: &'static str,
    pub target: String,
    pub reason: String,
    pub rule: Option<String>,
    pub explain: String,
}

/// A running egress listener. Dropping it stops the listener and joins its thread.
pub struct EgressProxy {
    addr: SocketAddr,
    credential: String,
    violations: Arc<Mutex<Vec<Violation>>>,
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
        let violations = Arc::new(Mutex::new(Vec::new()));
        let (tx, rx) = tokio::sync::oneshot::channel::<()>();
        let credential = config.admission.credential.clone();
        let shared = Arc::new(Shared {
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
            .map(|v| v.clone())
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

struct Shared {
    config: EgressConfig,
    violations: Arc<Mutex<Vec<Violation>>>,
}

impl Shared {
    fn refuse(
        &self,
        kind: &'static str,
        target: &str,
        reason: &str,
        rule: Option<String>,
        explain: String,
    ) {
        let v = Violation {
            kind,
            target: target.to_string(),
            reason: reason.to_string(),
            rule,
            explain,
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
                all.remove(0);
            }
            all.push(v);
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
                    "formwork explain --hosts".to_string(),
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
struct Head {
    method: String,
    target: String,
    headers: Vec<(String, String)>,
}

impl Head {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
}

/// Read one request head (through the blank line), returning it and any bytes read past it.
async fn read_head(stream: &mut TcpStream) -> std::io::Result<Option<(Head, Vec<u8>)>> {
    let mut buf = Vec::with_capacity(4096);
    let mut chunk = [0u8; 4096];
    loop {
        if let Some(end) = find_head_end(&buf) {
            let rest = buf.split_off(end);
            let head = parse_head(&buf).ok_or_else(|| {
                std::io::Error::new(std::io::ErrorKind::InvalidData, "malformed request head")
            })?;
            return Ok(Some((head, rest)));
        }
        if buf.len() > MAX_HEAD_BYTES {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "request head exceeded the maximum size",
            ));
        }
        let n = stream.read(&mut chunk).await?;
        if n == 0 {
            return Ok(None);
        }
        buf.extend_from_slice(&chunk[..n]);
    }
}

fn find_head_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n").map(|i| i + 4)
}

/// Strict head parsing: CRLF line endings, no obsolete line folding, no NUL, one `name: value` per
/// line. Anything else is refused rather than guessed at (FW-EGR11's spirit at the head).
fn parse_head(raw: &[u8]) -> Option<Head> {
    let text = std::str::from_utf8(raw).ok()?;
    if text.contains('\0') {
        return None;
    }
    let mut lines = text.split("\r\n");
    let request_line = lines.next()?;
    let mut parts = request_line.split(' ');
    let method = parts.next()?.to_string();
    let target = parts.next()?.to_string();
    let version = parts.next()?;
    if parts.next().is_some() || !(version == "HTTP/1.1" || version == "HTTP/1.0") {
        return None;
    }
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
    Some(Head {
        method,
        target,
        headers,
    })
}

async fn respond(stream: &mut TcpStream, status: &str, extra: &str) -> std::io::Result<()> {
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

fn basic_credential(credential: &str) -> String {
    format!("Basic {}", base64(format!("fw:{credential}").as_bytes()))
}

/// Standard base64 with padding (RFC 4648 §4), for the one header value the listener compares.
fn base64(input: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        out.push(TABLE[(n >> 18) as usize & 63] as char);
        out.push(TABLE[(n >> 12) as usize & 63] as char);
        out.push(if chunk.len() > 1 {
            TABLE[(n >> 6) as usize & 63] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            TABLE[n as usize & 63] as char
        } else {
            '='
        });
    }
    out
}

/// Compare without an early exit on the first differing byte.
fn same_secret(a: &str, b: &str) -> bool {
    a.len() == b.len()
        && a.bytes()
            .zip(b.bytes())
            .fold(0u8, |acc, (x, y)| acc | (x ^ y))
            == 0
}

fn explain_hint(scheme: &str, host: &str, port: u16, path: &str) -> String {
    let default = if scheme == "https" { 443 } else { 80 };
    if port == default {
        format!("formwork explain {scheme}://{host}{path}")
    } else {
        format!("formwork explain {scheme}://{host}:{port}{path}")
    }
}

async fn serve(mut stream: TcpStream, shared: Arc<Shared>) -> std::io::Result<()> {
    let Some((head, leftover)) = read_head(&mut stream).await? else {
        return Ok(());
    };
    let expected = basic_credential(&shared.config.admission.credential);
    let presented = head.header("Proxy-Authorization").unwrap_or("");
    if !same_secret(presented, &expected) {
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

/// Split `host:port` (or `[v6]:port`), with a default port.
fn split_authority(authority: &str, default_port: u16) -> Option<(String, u16)> {
    if let Some(rest) = authority.strip_prefix('[') {
        let end = rest.find(']')?;
        let host = &authority[..end + 2];
        let port = match &rest[end + 1..] {
            "" => default_port,
            p => p.strip_prefix(':')?.parse().ok()?,
        };
        return Some((host.to_string(), port));
    }
    match authority.rsplit_once(':') {
        Some((h, p)) => Some((h.to_string(), p.parse().ok()?)),
        None => Some((authority.to_string(), default_port)),
    }
}

/// Resolve and pin (FW-EGR4, FW-ADV-008): the first address that is not restricted -- unless the
/// host is an IP literal a rule names, which is the explicit naming EGR4 requires.
async fn resolve(shared: &Shared, host: &CanonicalHost, port: u16) -> Result<SocketAddr, String> {
    let table = &shared.config.table;
    match host {
        CanonicalHost::Ip(ip) => {
            if is_restricted_ip(*ip) && !table.names_explicitly(host) {
                return Err(format!(
                    "{ip} is a restricted address (metadata, private, loopback or link-local) and \
                     no rule names it (FW-EGR4)"
                ));
            }
            Ok(SocketAddr::new(*ip, port))
        }
        CanonicalHost::Name(name) => {
            if METADATA_HOSTNAMES.contains(&name.as_str()) && !table.names_explicitly(host) {
                return Err(format!(
                    "{name} is a metadata service and no rule names it (FW-EGR4)"
                ));
            }
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

async fn connect_upstream(addr: SocketAddr) -> Result<TcpStream, String> {
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
    let target = head.target.clone();
    let Some((raw_host, port)) = split_authority(&target, 443) else {
        shared.refuse(
            "connect",
            &target,
            "malformed CONNECT target",
            None,
            "formwork explain --hosts".into(),
        );
        return respond(&mut stream, "400 Bad Request", "").await;
    };
    let host = match canonicalize_host(&raw_host) {
        Ok(h) => h,
        Err(e) => {
            shared.refuse(
                "connect",
                &target,
                &e.to_string(),
                None,
                "formwork explain --hosts".into(),
            );
            return respond(&mut stream, "403 Forbidden", "").await;
        }
    };
    let hint = explain_hint("https", &host.to_string(), port, "");
    match shared.config.table.decide_connect(&host, port) {
        EgressDecision::Tunnel { .. } => {}
        EgressDecision::Inspect => {
            return crate::inspect::serve_inspected(
                stream,
                host,
                port,
                leftover,
                shared_inspect(&shared),
            )
            .await;
        }
        EgressDecision::Deny { reason, rule } => {
            shared.refuse(
                "connect",
                &format!("{host}:{port}"),
                &reason,
                rule.map(|r| r.to_string()),
                hint,
            );
            return respond(&mut stream, "403 Forbidden", "").await;
        }
        EgressDecision::Allow { .. } => unreachable_allow(),
    }
    let addr = match resolve(&shared, &host, port).await {
        Ok(a) => a,
        Err(reason) => {
            shared.refuse("connect", &format!("{host}:{port}"), &reason, None, hint);
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

/// `decide_connect` never returns `Allow`; kept as a named unreachable so the match is exhaustive
/// without a wildcard that would swallow a future variant.
fn unreachable_allow() -> ! {
    unreachable!("decide_connect returns Tunnel, Inspect or Deny")
}

fn shared_inspect(shared: &Arc<Shared>) -> crate::inspect::InspectContext {
    crate::inspect::InspectContext {
        table: shared.config.table.clone(),
        refuse: {
            let shared = shared.clone();
            Arc::new(
                move |target: &str, reason: &str, rule: Option<String>, explain: String| {
                    shared.refuse("request", target, reason, rule, explain)
                },
            )
        },
        resolve: {
            let shared = shared.clone();
            Arc::new(move |host: CanonicalHost, port: u16| {
                let shared = shared.clone();
                Box::pin(async move { resolve(&shared, &host, port).await })
            })
        },
    }
}

/// A plain-HTTP request in absolute form (`GET http://host/path HTTP/1.1`): decided by host, and by
/// method and canonical path when the host is inspected, then forwarded once.
async fn serve_plain(
    mut stream: TcpStream,
    head: Head,
    leftover: Vec<u8>,
    shared: Arc<Shared>,
) -> std::io::Result<()> {
    let Some(rest) = head.target.strip_prefix("http://") else {
        shared.refuse(
            "request",
            &head.target,
            "only CONNECT and absolute-form http:// requests reach the Gateway",
            None,
            "formwork explain --hosts".into(),
        );
        return respond(&mut stream, "400 Bad Request", "").await;
    };
    let (authority, raw_path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };
    let Some((raw_host, port)) = split_authority(authority, 80) else {
        return respond(&mut stream, "400 Bad Request", "").await;
    };
    let host = match canonicalize_host(&raw_host) {
        Ok(h) => h,
        Err(e) => {
            shared.refuse(
                "request",
                authority,
                &e.to_string(),
                None,
                "formwork explain --hosts".into(),
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
                "formwork explain --hosts".into(),
            );
            return respond(&mut stream, "403 Forbidden", "").await;
        }
    };
    if head.header("Content-Length").is_some() && head.header("Transfer-Encoding").is_some() {
        shared.refuse(
            "request",
            &format!("{host}{path}"),
            "a request carrying both Content-Length and Transfer-Encoding (FW-EGR11)",
            None,
            "formwork explain --hosts".into(),
        );
        return respond(&mut stream, "403 Forbidden", "").await;
    }
    let hint = explain_hint("http", &host.to_string(), port, &path);
    let method = HttpMethod::from_token(&head.method);
    let decision = match shared.config.table.decide_connect(&host, port) {
        EgressDecision::Inspect => shared
            .config
            .table
            .decide_request(&host, port, method, &path),
        other => other,
    };
    if let EgressDecision::Deny { reason, rule } = decision {
        shared.refuse(
            "request",
            &format!("{} {host}:{port}{path}", head.method),
            &reason,
            rule.map(|r| r.to_string()),
            hint,
        );
        return respond(&mut stream, "403 Forbidden", "").await;
    }
    let addr = match resolve(&shared, &host, port).await {
        Ok(a) => a,
        Err(reason) => {
            shared.refuse("request", &format!("{host}:{port}"), &reason, None, hint);
            return respond(&mut stream, "403 Forbidden", "").await;
        }
    };
    let mut upstream = match connect_upstream(addr).await {
        Ok(u) => u,
        Err(_) => return respond(&mut stream, "502 Bad Gateway", "").await,
    };
    // Origin-form request line; the proxy credential and hop-by-hop headers stay here.
    let mut out = format!("{} {} HTTP/1.1\r\n", head.method, raw_path);
    let hop = [
        "proxy-authorization",
        "proxy-connection",
        "connection",
        "keep-alive",
    ];
    for (name, value) in &head.headers {
        if !hop.contains(&name.to_ascii_lowercase().as_str()) {
            out.push_str(&format!("{name}: {value}\r\n"));
        }
    }
    out.push_str("Connection: close\r\n\r\n");
    upstream.write_all(out.as_bytes()).await?;
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
    fn base64_matches_rfc4648_vectors() {
        assert_eq!(base64(b""), "");
        assert_eq!(base64(b"f"), "Zg==");
        assert_eq!(base64(b"fo"), "Zm8=");
        assert_eq!(base64(b"foo"), "Zm9v");
        assert_eq!(base64(b"foobar"), "Zm9vYmFy");
    }

    #[test]
    fn heads_parse_strictly() {
        let h = parse_head(b"CONNECT a.test:443 HTTP/1.1\r\nHost: a.test\r\n\r\n").unwrap();
        assert_eq!(h.method, "CONNECT");
        assert_eq!(h.header("host"), Some("a.test"));
        assert!(parse_head(b"GET / HTTP/1.1\r\n folded\r\n\r\n").is_none());
        assert!(parse_head(b"GET / HTTP/2\r\n\r\n").is_none());
        assert!(parse_head(b"GET  / HTTP/1.1\r\n\r\n").is_none());
    }

    #[test]
    fn authorities_split_with_defaults() {
        assert_eq!(
            split_authority("a.test:8443", 443),
            Some(("a.test".into(), 8443))
        );
        assert_eq!(split_authority("a.test", 80), Some(("a.test".into(), 80)));
        assert_eq!(split_authority("[::1]:9", 443), Some(("[::1]".into(), 9)));
        assert_eq!(split_authority("a.test:x", 443), None);
    }
}
