//! HTTP/1.1 on the egress engine's sockets (FEP-6 §4.4, §4.9): strict message heads, body framing
//! (`Content-Length` or chunked, never both -- FW-EGR11), bodies streamed with a bounded buffer
//! (FW-EGR21), and the reflection guard that ends a response before it releases a byte that begins
//! a brokered credential (FW-CRED17). Anything the parser cannot read is refused, never forwarded
//! (FW-INV15).

use std::io;
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// **head-limit** (FEP-6 §4.9): bytes and header fields of one message head.
pub(crate) const HEAD_LIMIT: usize = 64 * 1024;
pub(crate) const HEAD_FIELDS: usize = 100;
/// **head-timeout**: from accept, or from the first byte of a later request, to a complete head.
pub(crate) const HEAD_TIMEOUT: Duration = Duration::from_secs(10);
/// **idle-timeout**: an idle keep-alive connection, client side or pooled upstream.
pub(crate) const IDLE_TIMEOUT: Duration = Duration::from_secs(90);
/// One read. With the reflection guard's hold-back, what a body holds in memory stays under
/// **body-buffer** (64 KiB per direction).
pub(crate) const READ_CHUNK: usize = 16 * 1024;
/// Bound on a chunk-size or trailer line.
const MAX_LINE: usize = 8 * 1024;

/// Any byte stream the engine relays: a client or upstream socket, with or without TLS.
pub(crate) trait Io: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Io for T {}
pub(crate) type BoxIo = Box<dyn Io>;

/// Header fields in the order received.
pub(crate) type Headers = Vec<(String, String)>;

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

pub(crate) fn find_header<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
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

/// The comma-separated tokens of every `Connection` header, lowercased.
pub(crate) fn connection_tokens(headers: &[(String, String)]) -> Vec<String> {
    headers
        .iter()
        .filter(|(n, _)| n.eq_ignore_ascii_case("connection"))
        .flat_map(|(_, v)| v.split(','))
        .map(|t| t.trim().to_ascii_lowercase())
        .filter(|t| !t.is_empty())
        .collect()
}

/// Headers meaningful to one hop only (RFC 9110 §7.6.1), never forwarded as received.
pub(crate) const HOP_BY_HOP: &[&str] = &[
    "connection",
    "keep-alive",
    "proxy-connection",
    "proxy-authorization",
    "proxy-authenticate",
    "te",
    "trailer",
    "upgrade",
];

/// `headers` without hop-by-hop fields, including every field the `Connection` header names.
pub(crate) fn end_to_end(headers: &[(String, String)]) -> Vec<(String, String)> {
    let named = connection_tokens(headers);
    headers
        .iter()
        .filter(|(n, _)| {
            let lower = n.to_ascii_lowercase();
            !HOP_BY_HOP.contains(&lower.as_str()) && !named.contains(&lower)
        })
        .cloned()
        .collect()
}

/// RFC 9110 `tchar`, the bytes of a method or header name.
fn is_token(s: &str) -> bool {
    !s.is_empty()
        && s.bytes().all(|b| {
            b.is_ascii_alphanumeric()
                || matches!(
                    b,
                    b'!' | b'#'
                        | b'$'
                        | b'%'
                        | b'&'
                        | b'\''
                        | b'*'
                        | b'+'
                        | b'-'
                        | b'.'
                        | b'^'
                        | b'_'
                        | b'`'
                        | b'|'
                        | b'~'
                )
        })
}

/// Why a head was not read.
#[derive(Debug)]
pub(crate) enum HeadError {
    /// The peer closed cleanly before a byte of a new message.
    Closed,
    /// No byte of a new message within the idle limit.
    Idle,
    /// Over **head-limit**, or not complete within **head-timeout**.
    Limit(&'static str),
    Malformed(&'static str),
    Io(io::Error),
}

impl From<io::Error> for HeadError {
    fn from(e: io::Error) -> Self {
        HeadError::Io(e)
    }
}

/// Split a head into its start line and strictly parsed headers: CRLF line endings, no obsolete
/// line folding, no NUL or bare CR, one `name: value` per line with a token name, at most
/// **head-limit** fields. Anything else is refused rather than guessed at (FW-EGR11, FW-INV15).
fn parse_lines(raw: &[u8]) -> Result<(&str, Headers), HeadError> {
    let text = std::str::from_utf8(raw).map_err(|_| HeadError::Malformed("a non-UTF-8 head"))?;
    if text.contains('\0') {
        return Err(HeadError::Malformed("a NUL in the head"));
    }
    let mut lines = text.split("\r\n");
    let start = lines.next().unwrap_or("");
    let mut headers = Vec::new();
    for line in lines {
        if line.is_empty() {
            continue;
        }
        if line.starts_with(' ') || line.starts_with('\t') {
            return Err(HeadError::Malformed("obsolete line folding"));
        }
        if line.contains('\r') || line.contains('\n') {
            return Err(HeadError::Malformed("a bare CR or LF"));
        }
        let (name, value) = line
            .split_once(':')
            .ok_or(HeadError::Malformed("a header line without a colon"))?;
        if !is_token(name) {
            return Err(HeadError::Malformed("a header name that is not a token"));
        }
        if value.bytes().any(|b| (b < 0x20 && b != b'\t') || b == 0x7f) {
            return Err(HeadError::Malformed("a control byte in a header value"));
        }
        headers.push((name.to_string(), value.trim().to_string()));
        if headers.len() > HEAD_FIELDS {
            return Err(HeadError::Limit("more header fields than head-limit"));
        }
    }
    Ok((start, headers))
}

fn http_version(v: &str) -> bool {
    v == "HTTP/1.1" || v == "HTTP/1.0"
}

/// A request head: `METHOD target HTTP/1.x`, then headers. The target is visible ASCII.
pub(crate) fn parse_head(raw: &[u8]) -> Result<Head, HeadError> {
    let (start, headers) = parse_lines(raw)?;
    let mut parts = start.split(' ');
    let (Some(method), Some(target), Some(version), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err(HeadError::Malformed(
            "a request line that is not three fields",
        ));
    };
    if !is_token(method) {
        return Err(HeadError::Malformed("an invalid method token"));
    }
    if target.is_empty() || target.bytes().any(|b| !(0x21..0x7f).contains(&b)) {
        return Err(HeadError::Malformed(
            "a request target outside visible ASCII",
        ));
    }
    if !http_version(version) {
        return Err(HeadError::Malformed(
            "an HTTP version other than 1.0 or 1.1",
        ));
    }
    Ok(Head {
        method: method.to_string(),
        target: target.to_string(),
        headers,
    })
}

/// A response head: `HTTP/1.x <3-digit status> [reason]`, then headers.
pub(crate) fn parse_response_head(raw: &[u8]) -> Result<ResponseHead, HeadError> {
    let (start, headers) = parse_lines(raw)?;
    let mut parts = start.splitn(3, ' ');
    let version = parts.next().unwrap_or("");
    let status = parts.next().unwrap_or("");
    let reason = parts.next().unwrap_or("").to_string();
    if !http_version(version) || status.len() != 3 || !status.bytes().all(|b| b.is_ascii_digit()) {
        return Err(HeadError::Malformed("a malformed status line"));
    }
    Ok(ResponseHead {
        version: version.to_string(),
        status: status
            .parse()
            .map_err(|_| HeadError::Malformed("a malformed status"))?,
        reason,
        headers,
    })
}

/// Body framing of a message (FW-EGR11): exactly one of these, or refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Framing {
    None,
    Length(u64),
    Chunked,
    UntilClose,
}

pub(crate) fn request_framing(head: &Head) -> Result<Framing, &'static str> {
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
        return Err("both Content-Length and Transfer-Encoding");
    }
    if !te.is_empty() {
        return if te.len() == 1 && te[0].eq_ignore_ascii_case("chunked") {
            Ok(Framing::Chunked)
        } else {
            Err("a Transfer-Encoding other than chunked")
        };
    }
    match cl.as_slice() {
        [] => Ok(Framing::None),
        [one] if !one.is_empty() && one.bytes().all(|b| b.is_ascii_digit()) => one
            .parse::<u64>()
            .map(Framing::Length)
            .map_err(|_| "an oversized Content-Length"),
        [_] => Err("a Content-Length that is not a number"),
        _ => Err("more than one Content-Length"),
    }
}

pub(crate) fn response_framing(
    head: &ResponseHead,
    request_method: &str,
) -> Result<Framing, &'static str> {
    let status = head.status;
    if request_method.eq_ignore_ascii_case("HEAD") || status == 204 || status == 304 || status < 200
    {
        return Ok(Framing::None);
    }
    let te: Vec<&str> = head
        .headers
        .iter()
        .filter(|(n, _)| n.eq_ignore_ascii_case("transfer-encoding"))
        .map(|(_, v)| v.as_str())
        .collect();
    if !te.is_empty() {
        let last = te
            .last()
            .and_then(|v| v.split(',').next_back())
            .map(|v| v.trim());
        return if last.is_some_and(|v| v.eq_ignore_ascii_case("chunked")) {
            Ok(Framing::Chunked)
        } else {
            Ok(Framing::UntilClose)
        };
    }
    let cl: Vec<&str> = head
        .headers
        .iter()
        .filter(|(n, _)| n.eq_ignore_ascii_case("content-length"))
        .map(|(_, v)| v.trim())
        .collect();
    match cl.as_slice() {
        [] => Ok(Framing::UntilClose),
        [first, rest @ ..] if rest.iter().all(|v| v == first) => first
            .parse::<u64>()
            .map(Framing::Length)
            .map_err(|_| "a Content-Length that is not a number"),
        _ => Err("conflicting Content-Length values"),
    }
}

/// Why a body stopped.
#[derive(Debug)]
pub(crate) enum BodyError {
    Io(io::Error),
    Malformed(&'static str),
    /// The reflection guard found a brokered credential (FW-CRED17).
    Reflected,
}

impl From<io::Error> for BodyError {
    fn from(e: io::Error) -> Self {
        BodyError::Io(e)
    }
}

/// The reflection guard (FW-CRED17): scans a response to a request that carried a presented
/// credential for every wire encoding of it, holding back only the longest suffix of the stream
/// that is a proper prefix of an encoding, so no released byte begins a match.
pub(crate) struct Guard {
    encodings: Vec<Vec<u8>>,
    held: Vec<u8>,
}

impl Guard {
    pub(crate) fn new(mut encodings: Vec<Vec<u8>>) -> Guard {
        encodings.retain(|e| !e.is_empty());
        encodings.sort();
        encodings.dedup();
        Guard {
            encodings,
            held: Vec::new(),
        }
    }

    pub(crate) fn scan(&self, data: &[u8]) -> bool {
        self.encodings
            .iter()
            .any(|e| data.windows(e.len()).any(|w| w == e.as_slice()))
    }

    pub(crate) fn push(&mut self, data: &[u8]) -> Result<Vec<u8>, BodyError> {
        let mut joined = std::mem::take(&mut self.held);
        joined.extend_from_slice(data);
        if self.scan(&joined) {
            return Err(BodyError::Reflected);
        }
        let keep = self
            .encodings
            .iter()
            .filter_map(|e| (1..e.len()).rev().find(|&l| joined.ends_with(&e[..l])))
            .max()
            .unwrap_or(0);
        self.held = joined.split_off(joined.len() - keep);
        Ok(joined)
    }

    pub(crate) fn finish(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.held)
    }
}

/// A read side with a buffer, so a head and whatever follows it can be taken apart.
pub(crate) struct Buffered<S> {
    pub(crate) s: S,
    pub(crate) buf: Vec<u8>,
}

impl<S: AsyncRead + Unpin> Buffered<S> {
    pub(crate) fn new(s: S, initial: Vec<u8>) -> Self {
        Buffered { s, buf: initial }
    }

    pub(crate) async fn fill(&mut self) -> io::Result<usize> {
        let mut chunk = [0u8; READ_CHUNK];
        let n = self.s.read(&mut chunk).await?;
        self.buf.extend_from_slice(&chunk[..n]);
        Ok(n)
    }

    /// The raw bytes of one head through its blank line. `idle` bounds the wait for the first
    /// byte, and **head-timeout** the rest; `None` waits for the first byte without limit.
    pub(crate) async fn raw_head(&mut self, idle: Option<Duration>) -> Result<Vec<u8>, HeadError> {
        if self.buf.is_empty() {
            let first = match idle {
                Some(limit) => tokio::time::timeout(limit, self.fill())
                    .await
                    .map_err(|_| HeadError::Idle)??,
                None => self.fill().await?,
            };
            if first == 0 {
                return Err(HeadError::Closed);
            }
        }
        let deadline = tokio::time::Instant::now() + HEAD_TIMEOUT;
        loop {
            if let Some(end) = self.buf.windows(4).position(|w| w == b"\r\n\r\n") {
                if end + 4 > HEAD_LIMIT {
                    return Err(HeadError::Limit("a head larger than head-limit"));
                }
                check_line_endings(&self.buf[..end + 4])?;
                let rest = self.buf.split_off(end + 4);
                return Ok(std::mem::replace(&mut self.buf, rest));
            }
            check_line_endings(&self.buf)?;
            if self.buf.len() > HEAD_LIMIT {
                return Err(HeadError::Limit("a head larger than head-limit"));
            }
            match tokio::time::timeout_at(deadline, self.fill()).await {
                Err(_) => return Err(HeadError::Limit("a head not complete within head-timeout")),
                Ok(Ok(0)) => return Err(HeadError::Malformed("the peer closed mid-head")),
                Ok(r) => r?,
            };
        }
    }

    async fn line(&mut self) -> Result<Vec<u8>, BodyError> {
        loop {
            if let Some(i) = self.buf.windows(2).position(|w| w == b"\r\n") {
                let rest = self.buf.split_off(i + 2);
                let mut line = std::mem::replace(&mut self.buf, rest);
                line.truncate(i);
                return Ok(line);
            }
            if self.buf.len() > MAX_LINE {
                return Err(BodyError::Malformed(
                    "a chunk line longer than the line bound",
                ));
            }
            if self.fill().await? == 0 {
                return Err(BodyError::Malformed("the peer closed mid-chunk"));
            }
        }
    }

    /// Up to `max` bytes, reading once if nothing is buffered; empty at EOF.
    async fn piece(&mut self, max: usize) -> io::Result<Vec<u8>> {
        if self.buf.is_empty() && self.fill().await? == 0 {
            return Ok(Vec::new());
        }
        let take = self.buf.len().min(max);
        let rest = self.buf.split_off(take);
        Ok(std::mem::replace(&mut self.buf, rest))
    }

    /// Relay a body in its framing, streaming (FW-EGR21), through the guard when one is given.
    /// Returns the body bytes read.
    pub(crate) async fn copy_body<W: AsyncWrite + Unpin>(
        &mut self,
        framing: Framing,
        out: &mut W,
        mut guard: Option<&mut Guard>,
    ) -> Result<u64, BodyError> {
        match framing {
            Framing::None => Ok(0),
            Framing::Length(n) => {
                let mut left = n;
                while left > 0 {
                    let data = self.piece(left.min(READ_CHUNK as u64) as usize).await?;
                    if data.is_empty() {
                        return Err(BodyError::Malformed("the peer closed mid-body"));
                    }
                    left -= data.len() as u64;
                    emit(out, &data, guard.as_deref_mut(), false).await?;
                }
                if let Some(g) = guard {
                    out.write_all(&g.finish()).await?;
                }
                out.flush().await?;
                Ok(n)
            }
            Framing::UntilClose => {
                let mut total = 0u64;
                loop {
                    let data = self.piece(READ_CHUNK).await?;
                    if data.is_empty() {
                        break;
                    }
                    total += data.len() as u64;
                    emit(out, &data, guard.as_deref_mut(), false).await?;
                }
                if let Some(g) = guard {
                    out.write_all(&g.finish()).await?;
                }
                out.flush().await?;
                Ok(total)
            }
            Framing::Chunked => self.copy_chunked(out, guard).await,
        }
    }

    /// A chunked body, one chunk at a time and each chunk in pieces. Without a guard the chunk
    /// sizes pass through; with one, released bytes are re-chunked, since the guard may hold bytes
    /// across a chunk edge. Chunk extensions are dropped.
    async fn copy_chunked<W: AsyncWrite + Unpin>(
        &mut self,
        out: &mut W,
        mut guard: Option<&mut Guard>,
    ) -> Result<u64, BodyError> {
        let mut total = 0u64;
        loop {
            let line = self.line().await?;
            let size_hex = std::str::from_utf8(&line)
                .ok()
                .and_then(|l| l.split(';').next())
                .map(str::trim)
                .unwrap_or("");
            if size_hex.is_empty()
                || size_hex.len() > 15
                || !size_hex.bytes().all(|b| b.is_ascii_hexdigit())
            {
                return Err(BodyError::Malformed("a malformed chunk size"));
            }
            let size = u64::from_str_radix(size_hex, 16)
                .map_err(|_| BodyError::Malformed("a malformed chunk size"))?;
            if size == 0 {
                if let Some(g) = guard.as_deref_mut() {
                    let tail = g.finish();
                    if !tail.is_empty() {
                        out.write_all(format!("{:x}\r\n", tail.len()).as_bytes())
                            .await?;
                        out.write_all(&tail).await?;
                        out.write_all(b"\r\n").await?;
                    }
                }
                out.write_all(b"0\r\n").await?;
                loop {
                    let trailer = self.line().await?;
                    if guard.as_deref().is_some_and(|g| g.scan(&trailer)) {
                        return Err(BodyError::Reflected);
                    }
                    out.write_all(&trailer).await?;
                    out.write_all(b"\r\n").await?;
                    if trailer.is_empty() {
                        out.flush().await?;
                        return Ok(total);
                    }
                }
            }
            if guard.is_none() {
                out.write_all(format!("{size:x}\r\n").as_bytes()).await?;
            }
            let mut left = size;
            while left > 0 {
                let data = self.piece(left.min(READ_CHUNK as u64) as usize).await?;
                if data.is_empty() {
                    return Err(BodyError::Malformed("the peer closed mid-chunk"));
                }
                left -= data.len() as u64;
                total += data.len() as u64;
                emit(out, &data, guard.as_deref_mut(), true).await?;
            }
            if guard.is_none() {
                out.write_all(b"\r\n").await?;
                out.flush().await?;
            }
            if self.line().await?.is_empty() {
                continue;
            }
            return Err(BodyError::Malformed("chunk data longer than its size"));
        }
    }
}

/// Write one piece of a body, through the guard when there is one; `chunked` frames what the
/// guard releases as its own chunk.
async fn emit<W: AsyncWrite + Unpin>(
    out: &mut W,
    data: &[u8],
    guard: Option<&mut Guard>,
    chunked: bool,
) -> Result<(), BodyError> {
    match guard {
        None => out.write_all(data).await?,
        Some(g) => {
            let released = g.push(data)?;
            if released.is_empty() {
                return Ok(());
            }
            if chunked {
                out.write_all(format!("{:x}\r\n", released.len()).as_bytes())
                    .await?;
                out.write_all(&released).await?;
                out.write_all(b"\r\n").await?;
            } else {
                out.write_all(&released).await?;
            }
            out.flush().await?;
        }
    }
    Ok(())
}

/// A head ends lines with CRLF; a bare LF is refused where a lenient parser would split a line,
/// the start of a smuggling disagreement (FW-ADV-024).
fn check_line_endings(bytes: &[u8]) -> Result<(), HeadError> {
    for (i, b) in bytes.iter().enumerate() {
        if *b == b'\n' && (i == 0 || bytes[i - 1] != b'\r') {
            return Err(HeadError::Malformed("a bare LF in the head"));
        }
    }
    Ok(())
}

/// Serialize a request line and headers.
pub(crate) fn render_request(method: &str, target: &str, headers: &[(String, String)]) -> Vec<u8> {
    let mut out = format!("{method} {target} HTTP/1.1\r\n");
    for (n, v) in headers {
        out.push_str(&format!("{n}: {v}\r\n"));
    }
    out.push_str("\r\n");
    out.into_bytes()
}

pub(crate) fn render_response(head: &ResponseHead, headers: &[(String, String)]) -> Vec<u8> {
    let mut out = format!("{} {} {}\r\n", head.version, head.status, head.reason);
    for (n, v) in headers {
        out.push_str(&format!("{n}: {v}\r\n"));
    }
    out.push_str("\r\n");
    out.into_bytes()
}

/// A Gateway-originated response. A 403 carries the one generic refusal body the confined client
/// ever sees (FW-CRED7).
pub(crate) async fn respond<W: AsyncWrite + Unpin>(
    stream: &mut W,
    status: &str,
    extra: &str,
    close: bool,
) -> io::Result<()> {
    let body = if status.starts_with("403") {
        "denied by formwork policy\n"
    } else {
        ""
    };
    let connection = if close { "Connection: close\r\n" } else { "" };
    let msg = format!(
        "HTTP/1.1 {status}\r\n{extra}Content-Type: text/plain\r\nContent-Length: {}\r\n{connection}\r\n{body}",
        body.len()
    );
    stream.write_all(msg.as_bytes()).await?;
    if close {
        stream.shutdown().await
    } else {
        stream.flush().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn head(h: &[(&str, &str)]) -> Head {
        Head {
            method: "POST".into(),
            target: "/".into(),
            headers: h
                .iter()
                .map(|(a, b)| (a.to_string(), b.to_string()))
                .collect(),
        }
    }

    #[test]
    fn heads_parse_strictly() {
        let h = parse_head(b"CONNECT a.test:443 HTTP/1.1\r\nHost: a.test\r\n\r\n").unwrap();
        assert_eq!(h.method, "CONNECT");
        assert_eq!(h.header("host"), Some("a.test"));
        for bad in [
            &b"GET / HTTP/1.1\r\n folded\r\n\r\n"[..],
            b"GET / HTTP/2\r\n\r\n",
            b"GET  / HTTP/1.1\r\n\r\n",
            b"G(T / HTTP/1.1\r\n\r\n",
            b"GET / HTTP/1.1\r\nA\0: b\r\n\r\n",
            b"GET / HTTP/1.1\r\nA: b\0c\r\n\r\n",
            b"GET /\xc3\xa9 HTTP/1.1\r\n\r\n",
        ] {
            assert!(parse_head(bad).is_err(), "{}", String::from_utf8_lossy(bad));
        }
        let many: String = (0..=HEAD_FIELDS).map(|i| format!("X-{i}: v\r\n")).collect();
        assert!(matches!(
            parse_head(format!("GET / HTTP/1.1\r\n{many}\r\n").as_bytes()),
            Err(HeadError::Limit(_))
        ));
        let r = parse_response_head(b"HTTP/1.1 404 Not Found\r\nA: b\r\n\r\n").unwrap();
        assert_eq!((r.status, r.reason.as_str()), (404, "Not Found"));
        assert!(parse_response_head(b"HTTP/1.1 20 X\r\n\r\n").is_err());
        assert!(check_line_endings(b"GET / HTTP/1.1\nHost: a\r\n").is_err());
    }

    #[test]
    fn framing_refuses_smuggling_shapes() {
        assert!(request_framing(&head(&[
            ("Content-Length", "3"),
            ("Transfer-Encoding", "chunked")
        ]))
        .is_err());
        assert!(request_framing(&head(&[("Transfer-Encoding", "gzip, chunked")])).is_err());
        assert!(
            request_framing(&head(&[("Content-Length", "3"), ("Content-Length", "4")])).is_err()
        );
        assert!(request_framing(&head(&[("Content-Length", "+3")])).is_err());
        assert_eq!(
            request_framing(&head(&[("Content-Length", "3")])),
            Ok(Framing::Length(3))
        );
    }

    #[test]
    fn hop_by_hop_fields_and_the_fields_connection_names_are_dropped() {
        let kept = end_to_end(&[
            ("Connection".into(), "keep-alive, X-Secret".into()),
            ("X-Secret".into(), "1".into()),
            ("Keep-Alive".into(), "timeout=5".into()),
            ("Proxy-Authorization".into(), "Basic x".into()),
            ("Accept".into(), "*/*".into()),
        ]);
        assert_eq!(kept, vec![("Accept".to_string(), "*/*".to_string())]);
    }

    #[test]
    fn the_guard_holds_back_only_a_matching_prefix() {
        let mut g = Guard::new(vec![b"sk-secret".to_vec()]);
        assert_eq!(g.push(b"data: one\n\n").unwrap(), b"data: one\n\n");
        assert_eq!(g.push(b"before sk-se").unwrap(), b"before ");
        assert!(matches!(g.push(b"cret after"), Err(BodyError::Reflected)));
        let mut g = Guard::new(vec![b"sk-secret".to_vec()]);
        assert_eq!(g.push(b"x sk").unwrap(), b"x ");
        assert_eq!(g.push(b"y").unwrap(), b"sky");
        assert_eq!(g.finish(), b"");
    }

    #[tokio::test]
    async fn chunked_bodies_stream_and_the_guard_rechunks() {
        let body = b"4\r\nabcd\r\n3;ext=1\r\nefg\r\n0\r\nX-T: 1\r\n\r\n".to_vec();
        let mut src = Buffered::new(&body[..], Vec::new());
        let mut out = Vec::new();
        let n = src
            .copy_body(Framing::Chunked, &mut out, None)
            .await
            .unwrap();
        assert_eq!(n, 7);
        assert_eq!(out, b"4\r\nabcd\r\n3\r\nefg\r\n0\r\nX-T: 1\r\n\r\n");
        let body = b"3\r\nabs\r\n2\r\nk-\r\n0\r\n\r\n".to_vec();
        let mut src = Buffered::new(&body[..], Vec::new());
        let mut guard = Guard::new(vec![b"sk-secret".to_vec()]);
        let mut out = Vec::new();
        src.copy_body(Framing::Chunked, &mut out, Some(&mut guard))
            .await
            .unwrap();
        assert_eq!(out, b"2\r\nab\r\n3\r\nsk-\r\n0\r\n\r\n");
    }
}
