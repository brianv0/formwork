//! The egress engine (FW-EGR1, FEP-5 §3.1, FEP-6): the one network door of a host-scoped
//! session, an HTTP proxy on a loopback port inside the Gateway. It admits only registered
//! connections (the Linux supervisor registers each one it performs, FW-EGR9) carrying the
//! per-session credential, and serves each through one pipeline (FEP-6 §4.2):
//!
//! 1. the proxy request head, read within **head-timeout** and **head-limit**: `CONNECT host:port`,
//!    or an absolute-form `http://` request for a plain-HTTP rule;
//! 2. the authority, parsed into the one host type rules parse into (FW-EGR3);
//! 3. the host decision -- not listed, denied, tunnel or inspected;
//! 4. the destination: one resolution, every address classified, only admitted addresses dialed
//!    (FW-EGR17-19);
//! 5. the grade: a tunnel forwards TLS after its ClientHello's server name matches the CONNECT host
//!    (FW-EGR16); an inspected host is terminated and each request decided (`inspect`).
//!
//! Every refusal is one violation record with a reason from a closed set (FW-FID12) and one
//! operator line naming the rule and the `explain` invocation that reproduces it (FW-FID9), while
//! the client gets a generic refusal (FW-CRED7). Every admitted tunnel and request is a grant
//! record (FW-FID13).

use std::collections::{BTreeMap, HashSet, VecDeque};
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use formwork_blueprint::{
    admit_addresses, canonicalize_host, split_host_port, CanonicalHost, ConnectDecision,
    EgressObservation, HostRule, HostTable, LocalAddresses, Naming, RefusalReason,
    DEFAULT_HTTPS_PORT, DEFAULT_HTTP_PORT,
};
use formwork_compile::Capability;

use crate::http::{parse_head, parse_response_head, respond, BoxIo, Buffered, HeadError};
use crate::inspect::{basic_value, Broker, Inspection, Pool};
use crate::upstream::{ProxyEndpoint, UpstreamProxy};
use crate::GatewayError;

/// **hello-limit** (FEP-6 §4.9): the buffered ClientHello.
const HELLO_LIMIT: usize = 16 * 1024;
/// **hello-timeout**: from the `200` reply to a complete ClientHello.
const HELLO_TIMEOUT: Duration = Duration::from_secs(10);
const UPSTREAM_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const RESOLVE_TIMEOUT: Duration = Duration::from_secs(10);
/// Records kept for an embedder or test to read back; older ones are dropped.
const MAX_KEPT_RECORDS: usize = 1024;
/// The reproduction for a refusal that names no destination.
const EXPLAIN_HOSTS: &str = "formwork explain --hosts";

/// How the Gateway resolves names. `System` is the host resolver (`getaddrinfo`, so `/etc/hosts`,
/// NSS and split-horizon DNS behave as they do for the operator). `Fixture` maps names to addresses
/// with no DNS at all -- the controlled input the egress tests drive the real Gateway with (FEP-1
/// test harness); it is reachable only through this library API, never the CLI.
#[derive(Clone, Debug)]
pub enum Resolver {
    System,
    Fixture(BTreeMap<String, Vec<IpAddr>>),
}

/// Who may use the listener (FW-EGR9).
#[derive(Clone, Debug)]
pub struct Admission {
    /// The per-session credential every proxy request carries (`Proxy-Authorization: Basic`).
    pub credential: String,
    /// Linux: source ports the supervisor registered for connections it performed. A connection
    /// from an unregistered port is closed before a byte is read. `None` on macOS, where the
    /// credential is the admission (FW-EGR9's residual, reported `Partial`).
    pub registry: Option<Arc<Mutex<HashSet<u16>>>>,
}

#[derive(Clone, Debug)]
pub struct EgressConfig {
    pub table: HostTable,
    pub resolver: Resolver,
    pub admission: Admission,
    /// The session CA and upstream trust; present whenever a host is inspected (FW-EGR13).
    pub inspection: Option<Inspection>,
    /// Brokered credentials (FW-CRED11).
    pub brokers: Vec<Broker>,
    /// Every address on the host's interfaces, enumerated at session start (FW-EGR19).
    pub host_addresses: Vec<IpAddr>,
    /// The operator's upstream proxy, from `formwork run`'s own environment (FW-EGR26).
    pub upstream_proxy: Option<UpstreamProxy>,
}

/// One refusal (FW-FID5, FW-FID12): the capability refused, one reason from the closed set, what
/// the request was when known, and the deciding rule. It never carries a header value, a body or a
/// query string, which can hold secrets.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct Violation {
    pub capability: Capability,
    pub reason: RefusalReason,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub method: Option<String>,
    /// The canonical path, without its query (FW-EGR11).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rule: Option<String>,
    /// Operator-channel prose.
    pub detail: String,
    pub explain: String,
    /// Milliseconds since the Unix epoch.
    pub timestamp: u64,
    /// What the session needed, when `learn` can propose a rule for it or must itemize why not
    /// (FW-DISC12).
    #[serde(skip)]
    pub need: Option<EgressObservation>,
}

/// One admitted tunnel or inspected request (FW-FID13), under the same exclusions as a violation.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct Grant {
    pub host: String,
    pub port: u16,
    /// `tunnel` or `inspected`.
    pub grade: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub method: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<u16>,
    pub bytes_up: u64,
    pub bytes_down: u64,
    pub duration_ms: u64,
}

/// A refusal on its way to a record: the engine's typed error for a connection or request it will
/// not forward. Boxed, since it travels in every `Result` of the pipeline.
#[derive(Clone, Debug)]
pub(crate) struct Refusal(Box<RefusalParts>);

#[derive(Clone, Debug)]
struct RefusalParts {
    reason: RefusalReason,
    capability: Capability,
    detail: String,
    host: Option<(CanonicalHost, u16)>,
    request: Option<(String, String)>,
    rule: Option<String>,
    plain: bool,
}

impl Refusal {
    pub(crate) fn new(reason: RefusalReason, detail: impl Into<String>) -> Refusal {
        use RefusalReason as R;
        let capability = match reason {
            R::HostNotListed
            | R::HostDenied
            | R::Resolution
            | R::AddressClass
            | R::NotTls
            | R::SniMismatch
            | R::Malformed
            | R::Limit => Capability::NetHostScope,
            R::Alpn | R::HostMismatch | R::Method | R::Path | R::UpstreamTls => {
                Capability::NetInspection
            }
            R::Placeholder | R::Reflection => Capability::CredentialBroker,
        };
        Refusal(Box::new(RefusalParts {
            reason,
            capability,
            detail: detail.into(),
            host: None,
            request: None,
            rule: None,
            plain: false,
        }))
    }

    pub(crate) fn at(mut self, host: &CanonicalHost, port: u16) -> Refusal {
        self.0.host = Some((host.clone(), port));
        self
    }

    pub(crate) fn request(mut self, method: &str, path: &str) -> Refusal {
        self.0.request = Some((method.to_string(), path.to_string()));
        self
    }

    pub(crate) fn rule(mut self, rule: Option<&HostRule>) -> Refusal {
        self.0.rule = rule.map(|r| r.to_string());
        self
    }

    pub(crate) fn plain(mut self, plain: bool) -> Refusal {
        self.0.plain = plain;
        self
    }

    pub(crate) fn capability(mut self, capability: Capability) -> Refusal {
        self.0.capability = capability;
        self
    }

    pub(crate) fn reason(&self) -> RefusalReason {
        self.0.reason
    }
}

/// A running egress listener. Dropping it stops the listener and joins its thread.
pub struct EgressProxy {
    addr: SocketAddr,
    credential: String,
    shared: Arc<Shared>,
    shutdown: Option<tokio::sync::oneshot::Sender<()>>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl EgressProxy {
    /// Bind `127.0.0.1:0` and serve on a dedicated thread with its own runtime, so the caller (the
    /// synchronous CLI) stays free of tokio (constitution Layers). A listener that cannot bind is
    /// an error, never a session without its door.
    pub fn start(config: EgressConfig) -> Result<EgressProxy, GatewayError> {
        let std_listener = std::net::TcpListener::bind(("127.0.0.1", 0))?;
        std_listener.set_nonblocking(true)?;
        let addr = std_listener.local_addr()?;
        let (tx, rx) = tokio::sync::oneshot::channel::<()>();
        let credential = config.admission.credential.clone();
        let shared = Arc::new(Shared {
            expected_auth: basic_value("fw", &credential),
            local: LocalAddresses {
                gateway: vec![addr],
                host: config.host_addresses.clone(),
            },
            config,
            pool: Pool::default(),
            records: Mutex::new(Records::default()),
        });
        let serving = shared.clone();
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
                        _ = accept_loop(listener, serving) => {}
                    }
                });
            })?;
        tracing::info!(listener = %addr, "gateway egress listener started (FW-EGR14)");
        if let Some(proxy) = &shared.config.upstream_proxy {
            tracing::info!(
                upstream = %proxy.describe(),
                "egress leaves through the operator's upstream proxy, which resolves the names it \
                 carries: address classification for those hosts is Partial (FW-EGR26)"
            );
        }
        Ok(EgressProxy {
            addr,
            credential,
            shared,
            shutdown: Some(tx),
            thread: Some(thread),
        })
    }

    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    /// The value for the proxy variables in the confined child.
    pub fn proxy_url(&self) -> String {
        format!("http://fw:{}@{}", self.credential, self.addr)
    }

    /// The refusals recorded so far, oldest first.
    pub fn violations(&self) -> Vec<Violation> {
        self.shared
            .records
            .lock()
            .map(|r| r.violations.iter().cloned().collect())
            .unwrap_or_default()
    }

    /// The admitted tunnels and requests recorded so far, oldest first (FW-FID13).
    pub fn grants(&self) -> Vec<Grant> {
        self.shared
            .records
            .lock()
            .map(|r| r.grants.iter().cloned().collect())
            .unwrap_or_default()
    }

    /// Inspected hosts whose clients rejected the session CA, which only a `tunnel:` rule serves.
    pub fn ca_rejections(&self) -> Vec<(CanonicalHost, u16)> {
        self.shared
            .records
            .lock()
            .map(|r| r.ca_rejections.clone())
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

#[derive(Default)]
struct Records {
    violations: VecDeque<Violation>,
    grants: VecDeque<Grant>,
    ca_rejections: Vec<(CanonicalHost, u16)>,
}

fn keep<T>(list: &mut VecDeque<T>, item: T) {
    if list.len() >= MAX_KEPT_RECORDS {
        list.pop_front();
    }
    list.push_back(item);
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

pub(crate) struct Shared {
    pub(crate) config: EgressConfig,
    /// The `Proxy-Authorization` value every admitted proxy request carries (FW-EGR9).
    expected_auth: String,
    /// The listener endpoint and the host's addresses, for classification (FW-EGR18/EGR19).
    pub(crate) local: LocalAddresses,
    pub(crate) pool: Pool,
    records: Mutex<Records>,
}

impl Shared {
    /// Record a refusal and emit its operator line (FW-FID9); the confined client sees only a
    /// generic refusal.
    pub(crate) fn refuse(&self, r: Refusal) {
        use RefusalReason as R;
        let r = *r.0;
        let scheme = if r.plain { "http" } else { "https" };
        let explain = match &r.host {
            Some((host, port)) => explain_hint(
                scheme,
                host,
                *port,
                r.request.as_ref().map(|(_, p)| p.as_str()).unwrap_or(""),
            ),
            None => EXPLAIN_HOSTS.to_string(),
        };
        let need = match (&r.host, r.reason) {
            (
                Some((host, port)),
                R::HostNotListed | R::HostDenied | R::AddressClass | R::Method | R::Path,
            ) => Some(EgressObservation {
                host: host.to_string(),
                port: *port,
                reason: r.reason,
                method: r.request.as_ref().map(|(m, _)| m.clone()),
                path: r.request.as_ref().map(|(_, p)| p.clone()),
            }),
            _ => None,
        };
        let target = match (&r.host, &r.request) {
            (Some((h, p)), Some((m, path))) => format!("{m} {h}:{p}{path}"),
            (Some((h, p)), None) => format!("{h}:{p}"),
            (None, _) => "(no destination)".to_string(),
        };
        tracing::warn!(
            reason = r.reason.as_str(),
            capability = r.capability.as_key(),
            rule = r.rule.as_deref().unwrap_or("(no rule admits it)"),
            explain = %explain,
            "formwork: egress refused ({}) {target}: {}",
            r.reason,
            r.detail
        );
        let v = Violation {
            capability: r.capability,
            reason: r.reason,
            host: r.host.as_ref().map(|(h, _)| h.to_string()),
            port: r.host.as_ref().map(|(_, p)| *p),
            method: r.request.as_ref().map(|(m, _)| m.clone()),
            path: r.request.map(|(_, p)| p),
            rule: r.rule,
            detail: r.detail,
            explain,
            timestamp: now_ms(),
            need,
        };
        if let Ok(mut records) = self.records.lock() {
            keep(&mut records.violations, v);
        }
    }

    pub(crate) fn grant(&self, g: Grant) {
        tracing::debug!(
            host = %g.host,
            port = g.port,
            grade = g.grade,
            method = g.method.as_deref().unwrap_or("-"),
            path = g.path.as_deref().unwrap_or("-"),
            status = g.status.unwrap_or(0),
            bytes_up = g.bytes_up,
            bytes_down = g.bytes_down,
            duration_ms = g.duration_ms,
            "egress granted (FW-FID13)"
        );
        if let Ok(mut records) = self.records.lock() {
            keep(&mut records.grants, g);
        }
    }

    pub(crate) fn note_ca_rejection(&self, host: &CanonicalHost, port: u16) {
        if let Ok(mut records) = self.records.lock() {
            if !records.ca_rejections.contains(&(host.clone(), port)) {
                records.ca_rejections.push((host.clone(), port));
            }
        }
    }
}

pub(crate) fn explain_hint(scheme: &str, host: &CanonicalHost, port: u16, path: &str) -> String {
    let default = if scheme == "https" {
        DEFAULT_HTTPS_PORT
    } else {
        DEFAULT_HTTP_PORT
    };
    let path = if path.is_empty() { "/" } else { path };
    if port == default {
        format!("formwork explain {scheme}://{host}{path}")
    } else {
        format!("formwork explain {scheme}://{host}:{port}{path}")
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
            // FW-EGR9: only connections the supervisor performed (and registered) are admitted; a
            // co-resident process that found the port is dropped before a byte is read.
            let registered = registry
                .lock()
                .map(|mut r| r.remove(&peer.port()))
                .unwrap_or(false);
            if !registered {
                tracing::warn!(
                    peer = %peer,
                    "formwork: the egress listener closed a connection the session's supervisor \
                     did not make (FW-EGR9)"
                );
                continue;
            }
        }
        let _ = stream.set_nodelay(true);
        let shared = shared.clone();
        tokio::spawn(async move {
            if let Err(e) = serve(stream, shared).await {
                tracing::debug!(error = %e, "egress connection ended");
            }
        });
    }
}

/// Compare without an early exit on the first differing byte.
fn same_secret(a: &str, b: &str) -> bool {
    a.len() == b.len()
        && a.bytes()
            .zip(b.bytes())
            .fold(0u8, |acc, (x, y)| acc | (x ^ y))
            == 0
}

/// The front door (FEP-6 §4.2 stages 1-2): the only stage that knows how the connection arrived.
async fn serve(stream: TcpStream, shared: Arc<Shared>) -> io::Result<()> {
    let mut client = Buffered::new(stream, Vec::new());
    let head = match client
        .raw_head(Some(crate::http::HEAD_TIMEOUT))
        .await
        .and_then(|raw| parse_head(&raw))
    {
        Ok(head) => head,
        Err(HeadError::Closed | HeadError::Idle) => return Ok(()),
        Err(HeadError::Io(e)) => return Err(e),
        Err(HeadError::Limit(why)) => {
            shared.refuse(Refusal::new(RefusalReason::Limit, why));
            return respond(&mut client.s, "400 Bad Request", "", true).await;
        }
        Err(HeadError::Malformed(why)) => {
            shared.refuse(Refusal::new(RefusalReason::Malformed, why));
            return respond(&mut client.s, "400 Bad Request", "", true).await;
        }
    };
    let presented = head.header("Proxy-Authorization").unwrap_or("");
    if !same_secret(presented, &shared.expected_auth) {
        return respond(
            &mut client.s,
            "407 Proxy Authentication Required",
            "Proxy-Authenticate: Basic realm=\"formwork\"\r\n",
            true,
        )
        .await;
    }
    if head.method == "CONNECT" {
        serve_connect(client, head.target, shared).await
    } else {
        crate::inspect::serve_plain(client, head, shared).await
    }
}

/// Stages 2-6 for `CONNECT host:port`.
async fn serve_connect(
    mut client: Buffered<TcpStream>,
    target: String,
    shared: Arc<Shared>,
) -> io::Result<()> {
    let authority = split_host_port(&target)
        .map_err(|e| e.to_string())
        .and_then(|(h, p)| {
            let port = p.ok_or("a CONNECT authority without a port")?;
            let host = canonicalize_host(h).map_err(|e| e.to_string())?;
            Ok((host, port))
        });
    let (host, port) = match authority {
        Ok(a) => a,
        Err(why) => {
            shared.refuse(Refusal::new(
                RefusalReason::Malformed,
                format!("the CONNECT authority {target:?}: {why}"),
            ));
            return respond(&mut client.s, "400 Bad Request", "", true).await;
        }
    };
    let inspect = match shared.config.table.decide_connect(&host, port) {
        ConnectDecision::Tunnel(_) => false,
        ConnectDecision::Inspect => true,
        ConnectDecision::Deny(d) => {
            shared.refuse(
                Refusal::new(d.reason, d.detail)
                    .at(&host, port)
                    .rule(d.rule),
            );
            return respond(&mut client.s, "403 Forbidden", "", true).await;
        }
    };
    let dest = match destination(&shared, &host, port, true).await {
        Ok(d) => d,
        Err(r) => {
            shared.refuse(r.at(&host, port));
            return respond(&mut client.s, "403 Forbidden", "", true).await;
        }
    };
    client
        .s
        .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        .await?;
    if inspect {
        crate::inspect::serve_inspected(client, dest, shared).await
    } else {
        tunnel(client, dest, shared).await
    }
}

/// The tunnel grade (FW-EGR16): the ClientHello's server name must be the CONNECT host before a
/// byte goes upstream; then bytes are copied until either side closes.
async fn tunnel(
    mut client: Buffered<TcpStream>,
    dest: Destination,
    shared: Arc<Shared>,
) -> io::Result<()> {
    let started = Instant::now();
    let (host, port) = (dest.host.clone(), dest.port);
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
    let mut upstream = match dial(&dest, true).await {
        Ok(u) => u,
        Err(why) => {
            tracing::info!(host = %host, port, %why, "egress upstream unavailable");
            return Ok(());
        }
    };
    upstream.write_all(&hello.raw).await?;
    let (up, down) = tokio::io::copy_bidirectional(&mut client.s, &mut upstream)
        .await
        .unwrap_or((0, 0));
    shared.grant(Grant {
        host: host.to_string(),
        port,
        grade: "tunnel",
        method: None,
        path: None,
        status: None,
        bytes_up: up + hello.raw.len() as u64,
        bytes_down: down,
        duration_ms: started.elapsed().as_millis() as u64,
    });
    Ok(())
}

/// A complete ClientHello, parsed, and every byte read to get it, which is replayed to whichever
/// side terminates the TLS session.
pub(crate) struct Hello {
    pub(crate) sni: Option<String>,
    pub(crate) alpn: Option<Vec<Vec<u8>>>,
    pub(crate) raw: Vec<u8>,
}

/// Buffer one complete TLS ClientHello within **hello-limit** and **hello-timeout** and parse it
/// with rustls's own acceptor, which is then dropped (FEP-6 §4.3). A first byte other than a TLS
/// handshake record is `not-tls`.
pub(crate) async fn read_client_hello<S: AsyncRead + Unpin>(
    client: &mut Buffered<S>,
) -> Result<Hello, Refusal> {
    let deadline = tokio::time::Instant::now() + HELLO_TIMEOUT;
    loop {
        if let Some(&first) = client.buf.first() {
            if first != 0x16 {
                return Err(Refusal::new(
                    RefusalReason::NotTls,
                    "the first byte after CONNECT is not a TLS handshake record",
                ));
            }
            let mut acceptor = rustls::server::Acceptor::default();
            let mut rd: &[u8] = &client.buf;
            while !rd.is_empty() {
                match acceptor.read_tls(&mut rd) {
                    Ok(0) | Err(_) => break,
                    Ok(_) => {}
                }
            }
            match acceptor.accept() {
                Ok(Some(accepted)) => {
                    let ch = accepted.client_hello();
                    let sni = ch.server_name().map(str::to_string);
                    let alpn = ch
                        .alpn()
                        .map(|protocols| protocols.map(<[u8]>::to_vec).collect());
                    return Ok(Hello {
                        sni,
                        alpn,
                        raw: std::mem::take(&mut client.buf),
                    });
                }
                Ok(None) => {}
                Err((e, _)) => {
                    return Err(Refusal::new(
                        RefusalReason::Malformed,
                        format!("the ClientHello does not parse: {e}"),
                    ))
                }
            }
        }
        if client.buf.len() > HELLO_LIMIT {
            return Err(Refusal::new(
                RefusalReason::Limit,
                "a ClientHello larger than hello-limit",
            ));
        }
        match tokio::time::timeout_at(deadline, client.fill()).await {
            Err(_) => {
                return Err(Refusal::new(
                    RefusalReason::Limit,
                    "no complete ClientHello within hello-timeout",
                ))
            }
            Ok(Ok(0)) | Ok(Err(_)) => {
                return Err(Refusal::new(
                    RefusalReason::Malformed,
                    "the client closed before a complete ClientHello",
                ))
            }
            Ok(Ok(_)) => {}
        }
    }
}

/// The server name must be the CONNECT host after the same canonicalization; only a connection to
/// an IP literal may omit it (FW-EGR10, FW-EGR16).
pub(crate) fn check_server_name(hello: &Hello, host: &CanonicalHost) -> Result<(), Refusal> {
    match &hello.sni {
        None if matches!(host, CanonicalHost::Ip(_)) => Ok(()),
        None => Err(Refusal::new(
            RefusalReason::SniMismatch,
            "the ClientHello names no server, which only a connection to an IP literal may omit",
        )),
        Some(sni) if canonicalize_host(sni).is_ok_and(|n| &n == host) => Ok(()),
        Some(sni) => Err(Refusal::new(
            RefusalReason::SniMismatch,
            format!(
                "the ClientHello names {sni:?}, not the CONNECT host {host}; a client using \
                 Encrypted Client Hello sends its provider's outer name, the likely cause if it \
                 enables ECH"
            ),
        )),
    }
}

/// Where an admitted connection may go: the admitted addresses of one resolution, in answer order
/// (FW-EGR17), or the operator's upstream proxy, which resolves the name itself (FW-EGR26).
#[derive(Clone, Debug)]
pub(crate) struct Destination {
    pub(crate) host: CanonicalHost,
    pub(crate) port: u16,
    route: Route,
}

#[derive(Clone, Debug)]
enum Route {
    Direct(Vec<SocketAddr>),
    Proxied(ProxyEndpoint),
}

impl Destination {
    pub(crate) fn proxy(&self) -> Option<&ProxyEndpoint> {
        match &self.route {
            Route::Proxied(p) => Some(p),
            Route::Direct(_) => None,
        }
    }
}

/// Resolve once and classify every address (FW-EGR17-19). A name the upstream proxy carries is not
/// resolved here; an IP literal is classified either way.
pub(crate) async fn destination(
    shared: &Shared,
    host: &CanonicalHost,
    port: u16,
    tls: bool,
) -> Result<Destination, Refusal> {
    let naming = shared
        .config
        .table
        .naming(host, port)
        .unwrap_or(Naming::Wildcard);
    let proxy = shared
        .config
        .upstream_proxy
        .as_ref()
        .and_then(|p| p.endpoint_for(host, tls))
        .cloned();
    let answer = match (host, &proxy) {
        (CanonicalHost::Ip(ip), _) => vec![*ip],
        (CanonicalHost::Name(_), Some(p)) => {
            return Ok(Destination {
                host: host.clone(),
                port,
                route: Route::Proxied(p.clone()),
            })
        }
        (CanonicalHost::Name(name), None) => resolve(shared, name, port).await?,
    };
    let admitted =
        admit_addresses(&answer, port, naming, &shared.local).map_err(|(ip, class)| {
            let by = match naming {
                Naming::Wildcard => "a wildcard rule",
                Naming::Exact => "an exact-name rule",
                Naming::IpLiteral => "an IP-literal rule",
            };
            let detail = match class {
                formwork_blueprint::AddressClass::GatewayEndpoint => format!(
                    "{host} reaches {ip}:{port}, the Gateway's own listener, which no rule admits \
                 (FW-EGR18)"
                ),
                _ => format!(
                    "{host} resolves to {ip}, a {class} address, which {by} does not admit \
                 (FW-EGR19); a mixed or rebound answer is refused whole (FW-EGR17)"
                ),
            };
            Refusal::new(RefusalReason::AddressClass, detail)
        })?;
    Ok(Destination {
        host: host.clone(),
        port,
        route: match proxy {
            Some(p) => Route::Proxied(p),
            None => Route::Direct(admitted),
        },
    })
}

async fn resolve(shared: &Shared, name: &str, port: u16) -> Result<Vec<IpAddr>, Refusal> {
    let answer: Vec<IpAddr> = match &shared.config.resolver {
        Resolver::Fixture(map) => map.get(name).cloned().unwrap_or_default(),
        Resolver::System => {
            match tokio::time::timeout(RESOLVE_TIMEOUT, tokio::net::lookup_host((name, port))).await
            {
                Ok(Ok(addrs)) => addrs.map(|a| a.ip()).collect(),
                Ok(Err(e)) => {
                    return Err(Refusal::new(
                        RefusalReason::Resolution,
                        format!("{name} did not resolve: {e}"),
                    ))
                }
                Err(_) => {
                    return Err(Refusal::new(
                        RefusalReason::Resolution,
                        format!("{name} did not resolve within {RESOLVE_TIMEOUT:?}"),
                    ))
                }
            }
        }
    };
    if answer.is_empty() {
        return Err(Refusal::new(
            RefusalReason::Resolution,
            format!("{name} did not resolve"),
        ));
    }
    Ok(answer)
}

/// Open a connection to a destination: the first reachable admitted address, or the upstream
/// proxy. `tls` asks the proxy for a tunnel (`CONNECT`); a plain-HTTP request instead goes to the
/// proxy in absolute form.
pub(crate) async fn dial(dest: &Destination, tls: bool) -> Result<BoxIo, String> {
    match &dest.route {
        Route::Direct(addrs) => {
            let mut last = String::from("no admitted address");
            for addr in addrs {
                match tokio::time::timeout(UPSTREAM_CONNECT_TIMEOUT, TcpStream::connect(addr)).await
                {
                    Ok(Ok(s)) => {
                        let _ = s.set_nodelay(true);
                        return Ok(Box::new(s));
                    }
                    Ok(Err(e)) => last = format!("{addr}: {e}"),
                    Err(_) => last = format!("{addr}: timed out"),
                }
            }
            Err(last)
        }
        Route::Proxied(proxy) => {
            let tcp = match tokio::time::timeout(
                UPSTREAM_CONNECT_TIMEOUT,
                TcpStream::connect((proxy.host.as_str(), proxy.port)),
            )
            .await
            {
                Ok(Ok(s)) => s,
                Ok(Err(e)) => return Err(format!("upstream proxy {}: {e}", proxy.describe())),
                Err(_) => return Err(format!("upstream proxy {}: timed out", proxy.describe())),
            };
            let _ = tcp.set_nodelay(true);
            if !tls {
                return Ok(Box::new(tcp));
            }
            let authority = format!("{}:{}", dest.host, dest.port);
            let mut request = format!("CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n");
            if let Some(auth) = &proxy.authorization {
                request.push_str(&format!("Proxy-Authorization: {auth}\r\n"));
            }
            request.push_str("\r\n");
            let mut conn = Buffered::new(tcp, Vec::new());
            conn.s
                .write_all(request.as_bytes())
                .await
                .map_err(|e| e.to_string())?;
            let head = conn
                .raw_head(Some(UPSTREAM_CONNECT_TIMEOUT))
                .await
                .and_then(|raw| parse_response_head(&raw))
                .map_err(|e| format!("upstream proxy {}: {e:?}", proxy.describe()))?;
            if !(200..300).contains(&head.status) {
                return Err(format!(
                    "upstream proxy {} answered CONNECT {authority} with {}",
                    proxy.describe(),
                    head.status
                ));
            }
            Ok(Box::new(Prefixed {
                prefix: conn.buf,
                inner: conn.s,
            }))
        }
    }
}

/// Bytes already read from a stream, replayed ahead of it: a ClientHello the engine buffered, or
/// what an upstream proxy sent past its `200`.
pub(crate) struct Prefixed<S> {
    pub(crate) prefix: Vec<u8>,
    pub(crate) inner: S,
}

impl<S: AsyncRead + Unpin> AsyncRead for Prefixed<S> {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        if !self.prefix.is_empty() {
            let n = self.prefix.len().min(buf.remaining());
            let rest = self.prefix.split_off(n);
            let head = std::mem::replace(&mut self.prefix, rest);
            buf.put_slice(&head);
            return std::task::Poll::Ready(Ok(()));
        }
        std::pin::Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Prefixed<S> {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        data: &[u8],
    ) -> std::task::Poll<io::Result<usize>> {
        std::pin::Pin::new(&mut self.inner).poll_write(cx, data)
    }
    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn a_client_hello_is_read_whole_and_refused_when_it_is_not_tls() {
        let mut plain = Buffered::new(&b"GET / HTTP/1.1\r\n\r\n"[..], Vec::new());
        let err = read_client_hello(&mut plain).await.err().unwrap();
        assert_eq!(err.reason(), RefusalReason::NotTls);
        let mut truncated = Buffered::new(&[0x16u8, 3, 1, 0, 200, 1][..], Vec::new());
        let err = read_client_hello(&mut truncated).await.err().unwrap();
        assert_eq!(err.reason(), RefusalReason::Malformed);
    }

    #[test]
    fn server_names_are_compared_canonically() {
        let hello = |sni: Option<&str>| Hello {
            sni: sni.map(str::to_string),
            alpn: None,
            raw: Vec::new(),
        };
        let api = CanonicalHost::Name("api.test".into());
        assert!(check_server_name(&hello(Some("API.test")), &api).is_ok());
        assert!(check_server_name(&hello(Some("other.test")), &api).is_err());
        assert!(check_server_name(&hello(None), &api).is_err());
        let ip = CanonicalHost::Ip("127.0.0.1".parse().unwrap());
        assert!(check_server_name(&hello(None), &ip).is_ok());
    }
}
