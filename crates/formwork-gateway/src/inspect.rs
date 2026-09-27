//! Inspected hosts (FW-EGR10): the Gateway terminates TLS with a leaf minted by the session CA,
//! checks that the SNI, every request's `Host` header and the CONNECT target agree, and decides each
//! request by method and canonical path (FW-EGR11) before forwarding it upstream over a TLS
//! connection verified against the host trust store. Brokered credentials are presented here
//! (FW-CRED11), and any echo of a credential's bytes in a response is masked (FW-INV13).
//!
//! HTTP/1.1 only: the Gateway advertises `http/1.1` by ALPN, and frames bodies strictly --
//! `Content-Length` or `Transfer-Encoding: chunked`, never both (FW-EGR11).

use std::io;
use std::sync::Arc;

use rustls::pki_types::ServerName;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;

use formwork_blueprint::{
    canonicalize_request_path, BrokerScheme, CanonicalHost, EgressDecision, HttpMethod,
};

use crate::egress::{base64, parse_head, Head, Shared};

/// Bound on a chunk-size or trailer line.
const MAX_LINE: usize = 8 * 1024;

/// A brokered credential as the Gateway holds it (FW-CRED15): the secret never leaves this process
/// except in the scheme's header toward a bound host.
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

/// Where upstream certificates are verified: the host trust store, or -- for the Gateway's own
/// tests -- a fixture root (a controlled input, reachable only through the library API).
#[derive(Clone, Debug)]
pub enum UpstreamRoots {
    System,
    Fixture(Vec<rustls::pki_types::CertificateDer<'static>>),
}

/// Inspection's session state: the CA and the upstream trust.
#[derive(Clone, Debug)]
pub struct Inspection {
    pub ca: Arc<crate::ca::SessionCa>,
    pub upstream_roots: UpstreamRoots,
}

pub(crate) fn upstream_config(roots: &UpstreamRoots) -> Arc<rustls::ClientConfig> {
    let mut store = rustls::RootCertStore::empty();
    match roots {
        UpstreamRoots::System => {
            let loaded = rustls_native_certs::load_native_certs();
            for e in &loaded.errors {
                tracing::warn!(error = %e, "loading a host trust-store certificate failed");
            }
            let (added, ignored) = store.add_parsable_certificates(loaded.certs);
            tracing::debug!(added, ignored, "upstream trust store loaded");
        }
        UpstreamRoots::Fixture(certs) => {
            for c in certs {
                let _ = store.add(c.clone());
            }
        }
    }
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut config = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .expect("ring supports the default protocol versions")
        .with_root_certificates(store)
        .with_no_client_auth();
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Arc::new(config)
}

/// A read side with a buffer, so a request head and whatever follows it can be taken apart.
struct Buffered<S> {
    s: S,
    buf: Vec<u8>,
}

impl<S: AsyncRead + Unpin> Buffered<S> {
    fn new(s: S, initial: Vec<u8>) -> Self {
        Buffered { s, buf: initial }
    }

    async fn fill(&mut self) -> io::Result<usize> {
        let mut chunk = [0u8; 16 * 1024];
        let n = self.s.read(&mut chunk).await?;
        self.buf.extend_from_slice(&chunk[..n]);
        Ok(n)
    }

    /// One head through the blank line, or `None` at a clean EOF between messages.
    async fn head(&mut self, max: usize) -> io::Result<Option<Head>> {
        self.head_as(max, false).await
    }

    async fn response_head(&mut self, max: usize) -> io::Result<Option<Head>> {
        self.head_as(max, true).await
    }

    async fn head_as(&mut self, max: usize, response: bool) -> io::Result<Option<Head>> {
        loop {
            if let Some(end) = self.buf.windows(4).position(|w| w == b"\r\n\r\n") {
                let rest = self.buf.split_off(end + 4);
                let raw = std::mem::replace(&mut self.buf, rest);
                let parsed = if response {
                    crate::egress::parse_response_head(&raw)
                } else {
                    parse_head(&raw)
                };
                return parsed
                    .map(Some)
                    .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "malformed head"));
            }
            if self.buf.len() > max {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "head too large"));
            }
            if self.fill().await? == 0 {
                return if self.buf.is_empty() {
                    Ok(None)
                } else {
                    Err(io::ErrorKind::UnexpectedEof.into())
                };
            }
        }
    }

    async fn line(&mut self) -> io::Result<Vec<u8>> {
        loop {
            if let Some(i) = self.buf.windows(2).position(|w| w == b"\r\n") {
                let rest = self.buf.split_off(i + 2);
                let mut line = std::mem::replace(&mut self.buf, rest);
                line.truncate(i);
                return Ok(line);
            }
            if self.buf.len() > MAX_LINE {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "line too long"));
            }
            if self.fill().await? == 0 {
                return Err(io::ErrorKind::UnexpectedEof.into());
            }
        }
    }

    async fn take(&mut self, n: usize) -> io::Result<Vec<u8>> {
        while self.buf.len() < n {
            if self.fill().await? == 0 {
                return Err(io::ErrorKind::UnexpectedEof.into());
            }
        }
        let rest = self.buf.split_off(n);
        Ok(std::mem::replace(&mut self.buf, rest))
    }

    /// Copy exactly `n` body bytes to `out`, through the scrubber.
    async fn copy_exact<W: AsyncWrite + Unpin>(
        &mut self,
        mut n: u64,
        out: &mut W,
        scrub: &mut Scrubber,
    ) -> io::Result<()> {
        while n > 0 {
            if self.buf.is_empty() && self.fill().await? == 0 {
                return Err(io::ErrorKind::UnexpectedEof.into());
            }
            let take = (self.buf.len() as u64).min(n) as usize;
            let rest = self.buf.split_off(take);
            let data = std::mem::replace(&mut self.buf, rest);
            out.write_all(&scrub.push(&data)).await?;
            n -= take as u64;
        }
        out.write_all(&scrub.finish()).await
    }

    /// Relay a chunked body, re-framed (the scrubber may hold bytes back across chunk edges).
    async fn copy_chunked<W: AsyncWrite + Unpin>(
        &mut self,
        out: &mut W,
        scrub: &mut Scrubber,
    ) -> io::Result<()> {
        loop {
            let line = self.line().await?;
            let text = std::str::from_utf8(&line)
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "chunk size"))?;
            let size_hex = text.split(';').next().unwrap_or("").trim();
            let size = u64::from_str_radix(size_hex, 16)
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "chunk size"))?;
            if size == 0 {
                // Trailers, through the blank line; relayed verbatim after any held-back bytes.
                let tail = scrub.finish();
                if !tail.is_empty() {
                    out.write_all(format!("{:x}\r\n", tail.len()).as_bytes())
                        .await?;
                    out.write_all(&tail).await?;
                    out.write_all(b"\r\n").await?;
                }
                out.write_all(b"0\r\n").await?;
                loop {
                    let t = self.line().await?;
                    out.write_all(&scrub.mask_whole(&t)).await?;
                    out.write_all(b"\r\n").await?;
                    if t.is_empty() {
                        return Ok(());
                    }
                }
            }
            let data = self.take(size as usize).await?;
            if self.take(2).await? != b"\r\n" {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "chunk framing"));
            }
            let emit = scrub.push(&data);
            if !emit.is_empty() {
                out.write_all(format!("{:x}\r\n", emit.len()).as_bytes())
                    .await?;
                out.write_all(&emit).await?;
                out.write_all(b"\r\n").await?;
            }
        }
    }

    async fn copy_to_end<W: AsyncWrite + Unpin>(
        &mut self,
        out: &mut W,
        scrub: &mut Scrubber,
    ) -> io::Result<()> {
        loop {
            if !self.buf.is_empty() {
                let data = std::mem::take(&mut self.buf);
                out.write_all(&scrub.push(&data)).await?;
            }
            if self.fill().await? == 0 {
                return out.write_all(&scrub.finish()).await;
            }
        }
    }
}

/// Masks every occurrence of a brokered secret in a byte stream with same-length `*`s, holding back
/// the last `longest - 1` bytes so an occurrence split across reads is still caught (FW-INV13).
pub(crate) struct Scrubber {
    secrets: Vec<Vec<u8>>,
    pending: Vec<u8>,
    hold: usize,
}

impl Scrubber {
    pub(crate) fn new(secrets: Vec<Vec<u8>>) -> Scrubber {
        let secrets: Vec<Vec<u8>> = secrets.into_iter().filter(|s| !s.is_empty()).collect();
        let hold = secrets.iter().map(|s| s.len()).max().unwrap_or(1) - 1;
        Scrubber {
            secrets,
            pending: Vec::new(),
            hold,
        }
    }

    fn mask(&self, data: &mut [u8]) {
        for s in &self.secrets {
            let mut i = 0;
            while i + s.len() <= data.len() {
                if &data[i..i + s.len()] == s.as_slice() {
                    data[i..i + s.len()].fill(b'*');
                    i += s.len();
                } else {
                    i += 1;
                }
            }
        }
    }

    pub(crate) fn mask_whole(&self, data: &[u8]) -> Vec<u8> {
        let mut v = data.to_vec();
        self.mask(&mut v);
        v
    }

    pub(crate) fn push(&mut self, data: &[u8]) -> Vec<u8> {
        if self.secrets.is_empty() {
            return data.to_vec();
        }
        self.pending.extend_from_slice(data);
        let mut pending = std::mem::take(&mut self.pending);
        self.mask(&mut pending);
        let keep = self.hold.min(pending.len());
        self.pending = pending.split_off(pending.len() - keep);
        pending
    }

    pub(crate) fn finish(&mut self) -> Vec<u8> {
        let mut rest = std::mem::take(&mut self.pending);
        self.mask(&mut rest);
        rest
    }
}

fn host_header_matches(value: &str, host: &CanonicalHost, port: u16) -> bool {
    let value = value.trim();
    let (h, p) = match value.rsplit_once(':') {
        Some((h, p)) if !value.ends_with(']') => (h, p.parse::<u16>().ok()),
        _ => (value, None),
    };
    let port_ok = p.map(|p| p == port).unwrap_or(port == 443);
    port_ok
        && formwork_blueprint::canonicalize_host(h)
            .map(|c| &c == host)
            .unwrap_or(false)
}

/// Present brokered credentials for a request to `host` (FW-CRED11): substitute the placeholder in
/// the scheme's header, add the header when the request carries no credential, and refuse a request
/// that carries a placeholder toward a host it is not bound to.
fn present(
    headers: &mut Vec<(String, String)>,
    host: &CanonicalHost,
    brokers: &[Broker],
) -> Result<(), String> {
    for b in brokers {
        let binding = b.bindings.iter().find(|(h, _)| h == host);
        let carries = headers.iter().any(|(_, v)| v.contains(&b.placeholder))
            || headers
                .iter()
                .filter(|(n, _)| n.eq_ignore_ascii_case("authorization"))
                .any(|(_, v)| basic_carries(v, &b.placeholder));
        let Some((_, scheme)) = binding else {
            if carries {
                return Err(format!(
                    "the {} placeholder was sent to {host}, which it is not bound to",
                    b.name
                ));
            }
            continue;
        };
        match scheme {
            BrokerScheme::Bearer => set_auth(
                headers,
                "authorization",
                &b.placeholder,
                &format!("Bearer {}", b.secret),
            ),
            BrokerScheme::Header(name) => set_auth(headers, name, &b.placeholder, &b.secret),
            BrokerScheme::Basic { user } => {
                let value = format!(
                    "Basic {}",
                    base64(format!("{user}:{}", b.secret).as_bytes())
                );
                let pos = headers
                    .iter()
                    .position(|(n, _)| n.eq_ignore_ascii_case("authorization"));
                match pos {
                    None => headers.push(("Authorization".into(), value)),
                    Some(i) if basic_carries(&headers[i].1, &b.placeholder) => headers[i].1 = value,
                    Some(_) => {}
                }
            }
        }
    }
    Ok(())
}

/// Substitute the placeholder in the scheme's header, or add the header when absent.
fn set_auth(headers: &mut Vec<(String, String)>, name: &str, placeholder: &str, value: &str) {
    match headers
        .iter()
        .position(|(n, _)| n.eq_ignore_ascii_case(name))
    {
        None => headers.push((name.to_string(), value.to_string())),
        Some(i) => {
            if headers[i].1.contains(placeholder) {
                headers[i].1 = if name.eq_ignore_ascii_case("authorization") {
                    value.to_string()
                } else {
                    headers[i].1.replace(placeholder, value)
                };
            }
        }
    }
}

/// Does a `Basic` authorization value carry the placeholder in its decoded password?
fn basic_carries(value: &str, placeholder: &str) -> bool {
    value
        .strip_prefix("Basic ")
        .and_then(|b64| crate::egress::base64_decode(b64.trim()))
        .map(|raw| String::from_utf8_lossy(&raw).contains(placeholder))
        .unwrap_or(false)
}

/// Body framing of a message (FW-EGR11): exactly one of these, or refused.
enum Framing {
    None,
    Length(u64),
    Chunked,
    UntilClose,
}

fn request_framing(head: &Head) -> Result<Framing, String> {
    let te: Vec<&str> = head
        .headers
        .iter()
        .filter(|(n, _)| n.eq_ignore_ascii_case("transfer-encoding"))
        .map(|(_, v)| v.as_str())
        .collect();
    let cl: Vec<&str> = head
        .headers
        .iter()
        .filter(|(n, _)| n.eq_ignore_ascii_case("content-length"))
        .map(|(_, v)| v.as_str())
        .collect();
    if !te.is_empty() && !cl.is_empty() {
        return Err("both Content-Length and Transfer-Encoding".into());
    }
    if !te.is_empty() {
        return if te.len() == 1 && te[0].eq_ignore_ascii_case("chunked") {
            Ok(Framing::Chunked)
        } else {
            Err(format!("Transfer-Encoding {te:?}"))
        };
    }
    match cl.as_slice() {
        [] => Ok(Framing::None),
        [one] => one
            .trim()
            .parse::<u64>()
            .map(Framing::Length)
            .map_err(|_| format!("Content-Length {one:?}")),
        _ => Err("more than one Content-Length".into()),
    }
}

fn response_framing(head: &Head, status: u16, request_method: &str) -> Framing {
    if request_method.eq_ignore_ascii_case("HEAD") || status == 204 || status == 304 || status < 200
    {
        return Framing::None;
    }
    if head
        .header("transfer-encoding")
        .map(|v| v.to_ascii_lowercase().contains("chunked"))
        .unwrap_or(false)
    {
        return Framing::Chunked;
    }
    match head
        .header("content-length")
        .and_then(|v| v.trim().parse().ok())
    {
        Some(n) => Framing::Length(n),
        None => Framing::UntilClose,
    }
}

fn render_request(head: &Head, target: &str, headers: &[(String, String)]) -> Vec<u8> {
    let mut out = format!("{} {} HTTP/1.1\r\n", head.method, target);
    for (n, v) in headers {
        out.push_str(&format!("{n}: {v}\r\n"));
    }
    out.push_str("\r\n");
    out.into_bytes()
}

async fn deny<W: AsyncWrite + Unpin>(w: &mut W) -> io::Result<()> {
    w.write_all(
        b"HTTP/1.1 403 Forbidden\r\nContent-Type: text/plain\r\nContent-Length: 26\r\nConnection: close\r\n\r\ndenied by formwork policy\n",
    )
    .await?;
    w.flush().await
}

/// Is this TLS failure a client rejecting the session CA? (FW-FID9's `unknown_ca` line.)
fn rejected_our_ca(e: &io::Error) -> bool {
    let text = format!("{e:?}");
    text.contains("UnknownCA")
        || text.contains("BadCertificate")
        || text.contains("CertificateUnknown")
}

/// One upstream TLS connection, split: the buffered read side and the write side.
type Upstream = (
    Buffered<tokio::io::ReadHalf<tokio_rustls::client::TlsStream<TcpStream>>>,
    tokio::io::WriteHalf<tokio_rustls::client::TlsStream<TcpStream>>,
);

pub(crate) async fn serve_inspected(
    mut stream: TcpStream,
    host: CanonicalHost,
    port: u16,
    leftover: Vec<u8>,
    shared: Arc<Shared>,
) -> io::Result<()> {
    let target = format!("{host}:{port}");
    let Some(inspection) = shared.config.inspection.clone() else {
        shared.refuse(
            "connect",
            &target,
            "the host is inspected, and this session has no inspection CA",
            None,
            format!("formwork explain https://{host}"),
        );
        return deny(&mut stream).await;
    };
    let leaf = match inspection.ca.leaf_for(&host) {
        Ok(l) => l,
        Err(e) => {
            tracing::warn!(error = %e, host = %host, "minting an inspection leaf failed");
            return deny(&mut stream).await;
        }
    };
    stream
        .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        .await?;
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut server = rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .expect("ring supports the default protocol versions")
        .with_no_client_auth()
        .with_cert_resolver(Arc::new(FixedCert(leaf.clone())));
    // The leaf is the CONNECT target's whatever SNI the client sends; the SNI is checked against
    // the target below, after the handshake.
    server.alpn_protocols = vec![b"http/1.1".to_vec()];
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server));
    let prefixed = Prefixed {
        prefix: leftover,
        inner: stream,
    };
    let tls = match acceptor.accept(prefixed).await {
        Ok(t) => t,
        Err(e) => {
            if rejected_our_ca(&e) {
                // FW-FID9: the one line that turns an opaque x509 error into a diagnosis.
                tracing::warn!(
                    host = %host,
                    "formwork: a client rejected the session CA for inspected host {host}: it does \
                     not read SSL_CERT_FILE (on macOS, Security.framework clients such as Go and \
                     Swift never do). Options: make the host tunnel-grade (`https:{host}`), or use \
                     a client that honors the variable; reproduce: formwork explain https://{host}"
                );
            } else {
                tracing::debug!(error = %e, host = %host, "inspection handshake failed");
            }
            return Ok(());
        }
    };
    let sni_ok = match tls.get_ref().1.server_name() {
        Some(sni) => formwork_blueprint::canonicalize_host(sni)
            .map(|c| c == host)
            .unwrap_or(false),
        None => true,
    };
    let (read, mut write) = tokio::io::split(tls);
    if !sni_ok {
        shared.refuse(
            "request",
            &target,
            "the TLS SNI does not match the CONNECT target (FW-EGR10)",
            None,
            format!("formwork explain https://{host}"),
        );
        return deny(&mut write).await;
    }
    relay(
        Buffered::new(read, Vec::new()),
        write,
        host,
        port,
        inspection,
        shared,
    )
    .await
}

async fn relay<R, W>(
    mut client: Buffered<R>,
    mut client_w: W,
    host: CanonicalHost,
    port: u16,
    inspection: Inspection,
    shared: Arc<Shared>,
) -> io::Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let secrets: Vec<Vec<u8>> = shared
        .config
        .brokers
        .iter()
        .map(|b| b.secret.clone().into_bytes())
        .collect();
    let mut upstream: Option<Upstream> = None;
    loop {
        let Some(head) = client.head(64 * 1024).await? else {
            return Ok(());
        };
        let hint = |path: &str| format!("formwork explain https://{host}{path}");
        let target = head.target.clone();
        if !head
            .header("host")
            .map(|h| host_header_matches(h, &host, port))
            .unwrap_or(false)
        {
            shared.refuse(
                "request",
                &format!("{host}{target}"),
                "the Host header does not match the CONNECT target (FW-EGR10)",
                None,
                hint(""),
            );
            return deny(&mut client_w).await;
        }
        let (raw_path, query) = match target.split_once('?') {
            Some((p, q)) => (p, Some(q)),
            None => (target.as_str(), None),
        };
        let path = match canonicalize_request_path(raw_path) {
            Ok(p) => p,
            Err(reason) => {
                shared.refuse(
                    "request",
                    &format!("{host}{target}"),
                    &reason,
                    None,
                    hint(""),
                );
                return deny(&mut client_w).await;
            }
        };
        let framing = match request_framing(&head) {
            Ok(f) => f,
            Err(reason) => {
                shared.refuse(
                    "request",
                    &format!("{host}{path}"),
                    &format!("request smuggling shape: {reason} (FW-EGR11)"),
                    None,
                    hint(&path),
                );
                return deny(&mut client_w).await;
            }
        };
        let method = HttpMethod::from_token(&head.method);
        match shared
            .config
            .table
            .decide_request(&host, port, method, &path)
        {
            EgressDecision::Allow { .. } => {}
            EgressDecision::Deny { reason, rule } => {
                shared.refuse(
                    "request",
                    &format!("{} {host}{path}", head.method),
                    &reason,
                    rule.map(|r| r.to_string()),
                    hint(&path),
                );
                return deny(&mut client_w).await;
            }
            _ => return deny(&mut client_w).await,
        }
        let mut headers: Vec<(String, String)> = head
            .headers
            .iter()
            .filter(|(n, _)| {
                !n.eq_ignore_ascii_case("proxy-authorization")
                    && !n.eq_ignore_ascii_case("proxy-connection")
            })
            .cloned()
            .collect();
        if let Err(reason) = present(&mut headers, &host, &shared.config.brokers) {
            shared.refuse(
                "request",
                &format!("{} {host}{path}", head.method),
                &reason,
                None,
                hint(&path),
            );
            return deny(&mut client_w).await;
        }
        if upstream.is_none() {
            let addr = match crate::egress::resolve(&shared, &host, port).await {
                Ok(a) => a,
                Err(reason) => {
                    shared.refuse(
                        "connect",
                        &format!("{host}:{port}"),
                        &reason,
                        None,
                        hint(""),
                    );
                    return deny(&mut client_w).await;
                }
            };
            let tcp = TcpStream::connect(addr).await?;
            let connector =
                tokio_rustls::TlsConnector::from(upstream_config(&inspection.upstream_roots));
            let name = match &host {
                CanonicalHost::Name(n) => ServerName::try_from(n.clone())
                    .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?,
                CanonicalHost::Ip(ip) => ServerName::IpAddress((*ip).into()),
            };
            let tls = match connector.connect(name, tcp).await {
                Ok(t) => t,
                Err(e) => {
                    tracing::warn!(host = %host, error = %e, "formwork: the upstream certificate for {host} did not verify against the host trust store");
                    client_w
                        .write_all(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                        .await?;
                    return Ok(());
                }
            };
            let (r, w) = tokio::io::split(tls);
            upstream = Some((Buffered::new(r, Vec::new()), w));
        }
        let (up_r, up_w) = upstream.as_mut().expect("connected above");
        let forwarded_target = match query {
            Some(q) => format!("{path}?{q}"),
            None => path.clone(),
        };
        up_w.write_all(&render_request(&head, &forwarded_target, &headers))
            .await?;
        let mut none = Scrubber::new(Vec::new());
        match framing {
            Framing::Length(n) => client.copy_exact(n, up_w, &mut none).await?,
            Framing::Chunked => client.copy_chunked(up_w, &mut none).await?,
            Framing::None | Framing::UntilClose => {}
        }
        up_w.flush().await?;
        let client_close = head
            .header("connection")
            .map(|v| v.eq_ignore_ascii_case("close"))
            .unwrap_or(false);
        // Response(s): 1xx interim responses are relayed until the final one.
        loop {
            let Some(resp) = up_r.response_head(64 * 1024).await? else {
                return Ok(());
            };
            let status: u16 = resp.target.parse().unwrap_or(502);
            let scrub_head = Scrubber::new(secrets.clone());
            let mut raw = format!("{} {} {}\r\n", resp.method, resp.target, resp.reason);
            for (n, v) in &resp.headers {
                let v = String::from_utf8_lossy(&scrub_head.mask_whole(v.as_bytes())).into_owned();
                raw.push_str(&format!("{n}: {v}\r\n"));
            }
            raw.push_str("\r\n");
            client_w.write_all(raw.as_bytes()).await?;
            if status == 101 {
                // An admitted upgrade (WebSocket): the connection is no longer HTTP.
                client_w.flush().await?;
                let mut scrub = Scrubber::new(secrets.clone());
                let up_to_client = up_r.copy_to_end(&mut client_w, &mut scrub);
                let client_to_up = async {
                    if !client.buf.is_empty() {
                        up_w.write_all(&std::mem::take(&mut client.buf)).await?;
                    }
                    tokio::io::copy(&mut client.s, up_w).await.map(|_| ())
                };
                let _ = tokio::join!(up_to_client, client_to_up);
                return Ok(());
            }
            if (100..200).contains(&status) {
                continue;
            }
            let mut scrub = Scrubber::new(secrets.clone());
            let framing = response_framing(&resp, status, &head.method);
            let server_close = resp
                .header("connection")
                .map(|v| v.eq_ignore_ascii_case("close"))
                .unwrap_or(false);
            match framing {
                Framing::Length(n) => up_r.copy_exact(n, &mut client_w, &mut scrub).await?,
                Framing::Chunked => up_r.copy_chunked(&mut client_w, &mut scrub).await?,
                Framing::UntilClose => {
                    up_r.copy_to_end(&mut client_w, &mut scrub).await?;
                    client_w.flush().await?;
                    return Ok(());
                }
                Framing::None => {}
            }
            client_w.flush().await?;
            if client_close || server_close {
                return Ok(());
            }
            break;
        }
    }
}

/// Answers every handshake with the CONNECT target's leaf.
#[derive(Debug)]
struct FixedCert(Arc<rustls::sign::CertifiedKey>);

impl rustls::server::ResolvesServerCert for FixedCert {
    fn resolve(
        &self,
        _hello: rustls::server::ClientHello<'_>,
    ) -> Option<Arc<rustls::sign::CertifiedKey>> {
        Some(self.0.clone())
    }
}

/// The leftover bytes read past a CONNECT head (a client that sends its ClientHello without waiting
/// for the 200) are replayed ahead of the socket.
struct Prefixed {
    prefix: Vec<u8>,
    inner: TcpStream,
}

impl AsyncRead for Prefixed {
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

impl AsyncWrite for Prefixed {
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

    #[test]
    fn scrubber_masks_across_split_reads() {
        let mut s = Scrubber::new(vec![b"sk-secret".to_vec()]);
        let mut out = s.push(b"before sk-se");
        out.extend(s.push(b"cret after"));
        out.extend(s.finish());
        assert_eq!(out, b"before ********* after");
    }

    #[test]
    fn presentation_substitutes_adds_and_refuses_unbound() {
        let gh = CanonicalHost::Name("api.github.com".into());
        let other = CanonicalHost::Name("evil.test".into());
        let brokers = vec![Broker {
            name: "github".into(),
            placeholder: "fwcred-github-abc".into(),
            secret: "ghp_REAL".into(),
            bindings: vec![(gh.clone(), BrokerScheme::Bearer)],
        }];
        let mut h = vec![(
            "Authorization".to_string(),
            "Bearer fwcred-github-abc".to_string(),
        )];
        present(&mut h, &gh, &brokers).unwrap();
        assert_eq!(h[0].1, "Bearer ghp_REAL");
        let mut none = vec![];
        present(&mut none, &gh, &brokers).unwrap();
        assert_eq!(none[0].1, "Bearer ghp_REAL", "added when absent");
        let mut leak = vec![("X-Token".to_string(), "fwcred-github-abc".to_string())];
        assert!(present(&mut leak, &other, &brokers).is_err());
        let basic = vec![Broker {
            bindings: vec![(
                gh.clone(),
                BrokerScheme::Basic {
                    user: "x-access-token".into(),
                },
            )],
            ..brokers[0].clone()
        }];
        let mut git = vec![];
        present(&mut git, &gh, &basic).unwrap();
        assert_eq!(
            git[0].1,
            format!("Basic {}", base64(b"x-access-token:ghp_REAL"))
        );
    }

    #[test]
    fn framing_refuses_smuggling_shapes() {
        let head = |h: &[(&str, &str)]| Head {
            method: "POST".into(),
            target: "/".into(),
            reason: String::new(),
            headers: h
                .iter()
                .map(|(a, b)| (a.to_string(), b.to_string()))
                .collect(),
        };
        assert!(request_framing(&head(&[
            ("Content-Length", "3"),
            ("Transfer-Encoding", "chunked")
        ]))
        .is_err());
        assert!(request_framing(&head(&[("Transfer-Encoding", "gzip, chunked")])).is_err());
        assert!(
            request_framing(&head(&[("Content-Length", "3"), ("Content-Length", "4")])).is_err()
        );
        assert!(matches!(
            request_framing(&head(&[("Content-Length", "3")])),
            Ok(Framing::Length(3))
        ));
    }
}
