//! Host-scoped egress (FW-EGR1, FEP-5 §4, FEP-6): host rules in the verb grammar and their
//! one-grade-per-host-and-port validation (FW-BP14, FW-BP16), the parse of foreign host and path
//! text into the types rules and requests share (FW-EGR3, FW-EGR11), the destination class table
//! (FW-EGR17-19), the closed set of refusal reasons (FW-FID12), and the pure decision the Gateway
//! and `explain` share. A host and port resolve to exactly one grade: *inspected* (`allow:` and
//! method verbs, the default: TLS terminated, every request decided, FW-EGR10) or *tunnel*
//! (`tunnel:`, forwarded after the server-name check, FW-EGR16). `deny:` is terminal.

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// The default port for a host rule without one.
pub const DEFAULT_HTTPS_PORT: u16 = 443;
/// The default port of an `http://` URL; an inspected rule on it is served without TLS.
pub const DEFAULT_HTTP_PORT: u16 = 80;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum HttpMethod {
    Get,
    Post,
    Put,
    Patch,
    Delete,
    Head,
    Options,
}

impl HttpMethod {
    pub const ALL: [HttpMethod; 7] = [
        HttpMethod::Get,
        HttpMethod::Post,
        HttpMethod::Put,
        HttpMethod::Patch,
        HttpMethod::Delete,
        HttpMethod::Head,
        HttpMethod::Options,
    ];

    pub fn atom(self) -> &'static str {
        match self {
            HttpMethod::Get => "get",
            HttpMethod::Post => "post",
            HttpMethod::Put => "put",
            HttpMethod::Patch => "patch",
            HttpMethod::Delete => "delete",
            HttpMethod::Head => "head",
            HttpMethod::Options => "options",
        }
    }

    /// The request-line token (`GET`), case-sensitive per RFC 9110.
    pub fn from_token(token: &str) -> Option<HttpMethod> {
        HttpMethod::ALL.into_iter().find(|m| {
            m.atom().eq_ignore_ascii_case(token) && token.bytes().all(|b| b.is_ascii_uppercase())
        })
    }

    fn from_atom(atom: &str) -> Option<HttpMethod> {
        HttpMethod::ALL.into_iter().find(|m| m.atom() == atom)
    }

    /// A rule's method list as written: `allow` for every method, else the atoms comma-joined.
    pub fn atoms(methods: &[HttpMethod]) -> String {
        if methods.is_empty() {
            return "allow".to_string();
        }
        methods
            .iter()
            .map(|m| m.atom())
            .collect::<Vec<_>>()
            .join(",")
    }
}

/// How specifically a rule names its host, which decides the address classes it may reach
/// (FW-EGR19). Ordered weakest first.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Naming {
    Wildcard,
    Exact,
    IpLiteral,
}

/// A host pattern (FEP-5 §4): an exact DNS name, `*.example.com` for one or more labels under the
/// suffix (the apex excluded), or an IP literal.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum HostPattern {
    Exact(String),
    Wildcard(String),
    Ip(IpAddr),
}

impl HostPattern {
    /// Does a canonical requested host match this pattern?
    pub fn matches(&self, host: &CanonicalHost) -> bool {
        match (self, host) {
            (HostPattern::Exact(e), CanonicalHost::Name(h)) => e == h,
            (HostPattern::Wildcard(suffix), CanonicalHost::Name(h)) => under(h, suffix),
            (HostPattern::Ip(a), CanonicalHost::Ip(b)) => a == b,
            _ => false,
        }
    }

    /// Could one host match both patterns (FW-BP14)?
    pub fn overlaps(&self, other: &HostPattern) -> bool {
        match (self, other) {
            (HostPattern::Exact(a), HostPattern::Exact(b)) => a == b,
            (HostPattern::Exact(e), HostPattern::Wildcard(s))
            | (HostPattern::Wildcard(s), HostPattern::Exact(e)) => under(e, s),
            (HostPattern::Wildcard(a), HostPattern::Wildcard(b)) => {
                a == b || under(a, b) || under(b, a)
            }
            (HostPattern::Ip(a), HostPattern::Ip(b)) => a == b,
            _ => false,
        }
    }

    pub fn naming(&self) -> Naming {
        match self {
            HostPattern::Exact(_) => Naming::Exact,
            HostPattern::Wildcard(_) => Naming::Wildcard,
            HostPattern::Ip(_) => Naming::IpLiteral,
        }
    }
}

/// Is `name` one or more labels under `suffix` (the apex excluded)?
fn under(name: &str, suffix: &str) -> bool {
    name.len() > suffix.len() + 1
        && name.ends_with(suffix)
        && name.as_bytes()[name.len() - suffix.len() - 1] == b'.'
}

impl fmt::Display for HostPattern {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HostPattern::Exact(h) => f.write_str(h),
            HostPattern::Wildcard(s) => write!(f, "*.{s}"),
            HostPattern::Ip(IpAddr::V6(ip)) => write!(f, "[{ip}]"),
            HostPattern::Ip(ip) => write!(f, "{ip}"),
        }
    }
}

/// A requested host after canonicalization (FW-EGR3): parse, don't validate -- a request host that
/// cannot be canonicalized is refused at the Gateway edge, never matched loosely. One value serves
/// the policy decision, the leaf certificate, the credential binding and the upstream server name.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum CanonicalHost {
    Name(String),
    Ip(IpAddr),
}

impl CanonicalHost {
    /// A metadata hostname, or an IP literal outside the global class: `learn` never proposes one
    /// (FW-DISC12), because only a rule an operator writes by hand may name it (FW-EGR19).
    pub fn is_restricted(&self) -> bool {
        match self {
            CanonicalHost::Ip(ip) => is_restricted_ip(*ip),
            CanonicalHost::Name(n) => METADATA_HOSTNAMES.contains(&n.as_str()),
        }
    }
}

impl fmt::Display for CanonicalHost {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CanonicalHost::Name(h) => f.write_str(h),
            CanonicalHost::Ip(IpAddr::V6(ip)) => write!(f, "[{ip}]"),
            CanonicalHost::Ip(ip) => write!(f, "{ip}"),
        }
    }
}

/// Why a host string was refused (FW-EGR3).
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum HostError {
    #[error("empty host")]
    Empty,
    #[error("host {0:?} contains a byte outside the DNS grammar [A-Za-z0-9.-]")]
    ForbiddenByte(String),
    #[error("host {0:?} is not ASCII; write an internationalized name in its xn-- form")]
    NotAscii(String),
    #[error("host {0:?} is not a valid DNS name")]
    Invalid(String),
    #[error(
        "host {0:?} ends in a numeric label, which resolvers read as an IPv4 address; an IPv4 \
         address is accepted only in dotted-decimal form"
    )]
    Numeric(String),
}

/// Canonicalize a requested host (FW-EGR3, FEP-6 §4.2): bytes limited to `[A-Za-z0-9.-]`,
/// lowercased, one trailing dot removed, no empty label, labels of at most 63 bytes and names of at
/// most 253; IPv6 literals in brackets without a zone identifier. A name whose last label is
/// numeric or starts with `0x` is read as an IPv4 address, as the WHATWG URL parser and
/// `getaddrinfo` read it, and accepted only in dotted-decimal form (`127.1`, `2130706433` and
/// `0x7f.1` are refused). IPv4-mapped IPv6 canonicalizes to IPv4.
pub fn canonicalize_host(raw: &str) -> Result<CanonicalHost, HostError> {
    if raw.is_empty() {
        return Err(HostError::Empty);
    }
    if !raw.is_ascii() {
        return Err(HostError::NotAscii(raw.to_string()));
    }
    if let Some(inner) = raw.strip_prefix('[') {
        return inner
            .strip_suffix(']')
            .and_then(|v6| v6.parse::<Ipv6Addr>().ok())
            .map(|v6| CanonicalHost::Ip(canonical_ip(IpAddr::V6(v6))))
            .ok_or_else(|| HostError::Invalid(raw.to_string()));
    }
    if raw
        .bytes()
        .any(|b| !(b.is_ascii_alphanumeric() || b == b'.' || b == b'-'))
    {
        return Err(HostError::ForbiddenByte(raw.to_string()));
    }
    let lower = raw.to_ascii_lowercase();
    let name = lower.strip_suffix('.').unwrap_or(&lower);
    if name.is_empty() || name.len() > 253 {
        return Err(HostError::Invalid(raw.to_string()));
    }
    let labels: Vec<&str> = name.split('.').collect();
    for label in &labels {
        if label.is_empty() || label.len() > 63 || label.starts_with('-') || label.ends_with('-') {
            return Err(HostError::Invalid(raw.to_string()));
        }
    }
    let last = labels.last().copied().unwrap_or("");
    if last.bytes().all(|b| b.is_ascii_digit()) || last.starts_with("0x") {
        return name
            .parse::<Ipv4Addr>()
            .map(|v4| CanonicalHost::Ip(IpAddr::V4(v4)))
            .map_err(|_| HostError::Numeric(raw.to_string()));
    }
    Ok(CanonicalHost::Name(name.to_string()))
}

/// IPv4-mapped IPv6 addresses canonicalize to IPv4, so `::ffff:10.0.0.1` cannot dodge an IPv4 rule
/// or class.
pub fn canonical_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => v6
            .to_ipv4_mapped()
            .map(IpAddr::V4)
            .unwrap_or(IpAddr::V6(v6)),
        v4 => v4,
    }
}

/// Hostnames of metadata services; `learn` never proposes them (FW-DISC12). The address they
/// resolve to is in the metadata class, which only an IP-literal rule admits (FW-EGR19).
pub const METADATA_HOSTNAMES: &[&str] = &["metadata.google.internal", "metadata"];

/// Cloud metadata services, reachable only through an IP-literal rule naming the address.
const METADATA_ADDRESSES: [IpAddr; 4] = [
    IpAddr::V4(Ipv4Addr::new(169, 254, 169, 254)),
    IpAddr::V6(Ipv6Addr::new(0xfd00, 0xec2, 0, 0, 0, 0, 0, 0x254)),
    // Alibaba Cloud.
    IpAddr::V4(Ipv4Addr::new(100, 100, 100, 200)),
    // Azure WireServer.
    IpAddr::V4(Ipv4Addr::new(168, 63, 129, 16)),
];

/// The destination classes of FEP-6 §4.5, in table order: the first that matches an address
/// decides it. Each class admits a narrower or wider set of rules (FW-EGR17-19).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum AddressClass {
    Metadata,
    GatewayEndpoint,
    HostAddress,
    LocalPrivate,
    SpecialPurpose,
    Global,
}

impl AddressClass {
    pub fn as_str(self) -> &'static str {
        match self {
            AddressClass::Metadata => "metadata",
            AddressClass::GatewayEndpoint => "gateway endpoint",
            AddressClass::HostAddress => "host address",
            AddressClass::LocalPrivate => "local or private",
            AddressClass::SpecialPurpose => "special-purpose",
            AddressClass::Global => "global",
        }
    }

    /// Whether a rule that names its host this way may reach an address of this class.
    pub fn admits(self, naming: Naming) -> bool {
        match self {
            AddressClass::Metadata | AddressClass::SpecialPurpose => naming == Naming::IpLiteral,
            AddressClass::GatewayEndpoint => false,
            AddressClass::HostAddress | AddressClass::LocalPrivate => naming >= Naming::Exact,
            AddressClass::Global => true,
        }
    }

    /// How few rules admit this class, so an IPv6 address and the IPv4 address it embeds are
    /// judged by the stricter of the two.
    fn strictness(self) -> u8 {
        match self {
            AddressClass::GatewayEndpoint => 4,
            AddressClass::Metadata | AddressClass::SpecialPurpose => 3,
            AddressClass::HostAddress | AddressClass::LocalPrivate => 2,
            AddressClass::Global => 0,
        }
    }
}

impl fmt::Display for AddressClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The session facts classification needs beyond an address itself: the Gateway's own listener
/// endpoints (FW-EGR18) and every address on the host's interfaces, enumerated at session start.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct LocalAddresses {
    pub gateway: Vec<SocketAddr>,
    pub host: Vec<IpAddr>,
}

/// Classify one destination (FEP-6 §4.5). An IPv6 address that embeds an IPv4 address
/// (IPv4-mapped, IPv4-compatible, NAT64, 6to4, Teredo) is judged by the stricter of its own class
/// and the embedded address's: `64:ff9b::a9fe:a9fe` reaches `169.254.169.254` on a NAT64 network.
pub fn classify(dest: SocketAddr, local: &LocalAddresses) -> AddressClass {
    let ip = canonical_ip(dest.ip());
    let port = dest.port();
    let mut class = classify_one(ip, port, local);
    if let IpAddr::V6(v6) = ip {
        for v4 in embedded_v4(v6) {
            let embedded = classify_one(IpAddr::V4(v4), port, local);
            if embedded.strictness() > class.strictness() {
                class = embedded;
            }
        }
    }
    class
}

fn classify_one(ip: IpAddr, port: u16, local: &LocalAddresses) -> AddressClass {
    if METADATA_ADDRESSES.contains(&ip) {
        return AddressClass::Metadata;
    }
    let local_ip = |a: IpAddr| canonical_ip(a) == ip;
    if local.gateway.iter().any(|g| {
        g.port() == port
            && (local_ip(g.ip())
                || ip.is_loopback()
                || ip.is_unspecified()
                || local.host.iter().any(|h| local_ip(*h)))
    }) {
        return AddressClass::GatewayEndpoint;
    }
    if local.host.iter().any(|h| local_ip(*h)) {
        return AddressClass::HostAddress;
    }
    let (local_private, special) = match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            (
                o[0] == 0
                    || o[0] == 127
                    || o[0] == 10
                    || (o[0] == 172 && (16..32).contains(&o[1]))
                    || (o[0] == 192 && o[1] == 168)
                    || (o[0] == 100 && (64..128).contains(&o[1]))
                    || (o[0] == 169 && o[1] == 254),
                (o[0] == 192 && o[1] == 0 && (o[2] == 0 || o[2] == 2))
                    || (o[0] == 198 && (o[1] == 18 || o[1] == 19))
                    || (o[0] == 198 && o[1] == 51 && o[2] == 100)
                    || (o[0] == 203 && o[1] == 0 && o[2] == 113)
                    // 240.0.0.0/4 (255.255.255.255 included) and multicast 224.0.0.0/4.
                    || o[0] >= 224,
            )
        }
        IpAddr::V6(v6) => {
            let s = v6.segments();
            (
                v6.is_loopback()
                    || v6.is_unspecified()
                    || (s[0] & 0xffc0) == 0xfe80
                    || (s[0] & 0xfe00) == 0xfc00,
                (s[0] & 0xff00) == 0xff00
                    || (s[0] == 0x100 && s[1] == 0 && s[2] == 0 && s[3] == 0)
                    || (s[0] == 0x2001 && s[1] == 0xdb8),
            )
        }
    };
    if local_private {
        AddressClass::LocalPrivate
    } else if special {
        AddressClass::SpecialPurpose
    } else {
        AddressClass::Global
    }
}

/// The IPv4 addresses an IPv6 address carries: IPv4-compatible (`::/96`), NAT64 (`64:ff9b::/96`,
/// and every RFC 6052 layout of the local-use `64:ff9b:1::/48`), 6to4 (`2002::/16`), and Teredo
/// (`2001::/32`: the server address, and the client address, which is XOR-obfuscated).
fn embedded_v4(v6: Ipv6Addr) -> Vec<Ipv4Addr> {
    let o = v6.octets();
    let s = v6.segments();
    let v4 = |a: u8, b: u8, c: u8, d: u8| Ipv4Addr::new(a, b, c, d);
    let tail = v4(o[12], o[13], o[14], o[15]);
    let mut out = Vec::new();
    if s[..6].iter().all(|&x| x == 0) && !v6.is_loopback() && !v6.is_unspecified() {
        out.push(tail);
    }
    if s[0] == 0x64 && s[1] == 0xff9b && s[2..6].iter().all(|&x| x == 0) {
        out.push(tail);
    }
    if s[0] == 0x64 && s[1] == 0xff9b && s[2] == 1 {
        out.push(v4(o[6], o[7], o[9], o[10]));
        out.push(v4(o[7], o[9], o[10], o[11]));
        out.push(v4(o[9], o[10], o[11], o[12]));
        out.push(tail);
    }
    if s[0] == 0x2002 {
        out.push(v4(o[2], o[3], o[4], o[5]));
    }
    if s[0] == 0x2001 && s[1] == 0 {
        out.push(v4(o[4], o[5], o[6], o[7]));
        out.push(v4(!o[12], !o[13], !o[14], !o[15]));
    }
    out
}

/// An address that no wildcard rule may reach and `learn` never proposes: anything outside the
/// global class, judged without session facts.
pub fn is_restricted_ip(ip: IpAddr) -> bool {
    classify(SocketAddr::new(ip, 0), &LocalAddresses::default()) != AddressClass::Global
}

/// FW-EGR17: one resolution, every address classified; a single refused address refuses the
/// connection, because a mixed public and private answer is the rebinding pattern. `Ok` carries the
/// admitted addresses in answer order, the only ones the Gateway may connect to.
pub fn admit_addresses(
    answer: &[IpAddr],
    port: u16,
    naming: Naming,
    local: &LocalAddresses,
) -> Result<Vec<SocketAddr>, (IpAddr, AddressClass)> {
    let mut admitted = Vec::with_capacity(answer.len());
    for ip in answer {
        let dest = SocketAddr::new(canonical_ip(*ip), port);
        let class = classify(dest, local);
        if !class.admits(naming) {
            return Err((dest.ip(), class));
        }
        if !admitted.contains(&dest) {
            admitted.push(dest);
        }
    }
    Ok(admitted)
}

/// Why the Gateway refused egress (FW-FID12): exactly one per violation record, a stable string in
/// the record schema. The set is closed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RefusalReason {
    HostNotListed,
    HostDenied,
    Resolution,
    AddressClass,
    NotTls,
    SniMismatch,
    Alpn,
    Malformed,
    Limit,
    HostMismatch,
    Method,
    Path,
    Placeholder,
    Reflection,
    UpstreamTls,
}

impl RefusalReason {
    pub fn as_str(self) -> &'static str {
        match self {
            RefusalReason::HostNotListed => "host-not-listed",
            RefusalReason::HostDenied => "host-denied",
            RefusalReason::Resolution => "resolution",
            RefusalReason::AddressClass => "address-class",
            RefusalReason::NotTls => "not-tls",
            RefusalReason::SniMismatch => "sni-mismatch",
            RefusalReason::Alpn => "alpn",
            RefusalReason::Malformed => "malformed",
            RefusalReason::Limit => "limit",
            RefusalReason::HostMismatch => "host-mismatch",
            RefusalReason::Method => "method",
            RefusalReason::Path => "path",
            RefusalReason::Placeholder => "placeholder",
            RefusalReason::Reflection => "reflection",
            RefusalReason::UpstreamTls => "upstream-tls",
        }
    }
}

impl fmt::Display for RefusalReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A request path after canonicalization (FW-EGR11), without its query: the only form a rule's
/// path glob is matched against and the Gateway forwards (FW-EGR22).
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CanonicalPath(String);

impl CanonicalPath {
    /// Canonicalize a request target's path (FW-EGR11): strip the query, decode percent-encoded
    /// unreserved characters, remove dot-segments, and refuse an encoded `/`, a NUL, a backslash
    /// or a byte outside visible ASCII rather than guess how the upstream would read them.
    pub fn parse(raw: &str) -> Result<CanonicalPath, String> {
        let path = raw.split(['?', '#']).next().unwrap_or("");
        if !path.starts_with('/') {
            return Err(format!("request target {raw:?} is not origin-form"));
        }
        if path.contains('\\') {
            return Err("a backslash in the request path".to_string());
        }
        if path.bytes().any(|b| !(0x21..0x7f).contains(&b)) {
            return Err("a control, space or non-ASCII byte in the request path".to_string());
        }
        let bytes = path.as_bytes();
        let mut decoded = Vec::with_capacity(bytes.len());
        let mut i = 0;
        while i < bytes.len() {
            if bytes[i] == b'%' {
                let hex = bytes
                    .get(i + 1..i + 3)
                    .and_then(|h| std::str::from_utf8(h).ok())
                    .and_then(|h| u8::from_str_radix(h, 16).ok())
                    .ok_or_else(|| "a malformed percent-escape in the request path".to_string())?;
                match hex {
                    0 => return Err("an encoded NUL in the request path".to_string()),
                    b'/' => return Err("an encoded `/` in the request path".to_string()),
                    b'\\' => return Err("an encoded backslash in the request path".to_string()),
                    b if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~') => {
                        decoded.push(b)
                    }
                    // Reserved and non-ASCII escapes stay encoded (uppercase hex, RFC 3986 §6.2.2.1).
                    b => decoded.extend_from_slice(format!("%{b:02X}").as_bytes()),
                }
                i += 3;
            } else {
                decoded.push(bytes[i]);
                i += 1;
            }
        }
        let decoded = String::from_utf8(decoded).map_err(|_| "a non-ASCII request path")?;
        // RFC 3986 §5.2.4 remove_dot_segments, over whole segments.
        let mut out: Vec<&str> = Vec::new();
        let trailing =
            decoded.ends_with('/') || decoded.ends_with("/.") || decoded.ends_with("/..");
        for seg in decoded.split('/').skip(1) {
            match seg {
                "." => {}
                ".." => {
                    out.pop();
                }
                s => out.push(s),
            }
        }
        let mut canonical = String::from("/");
        canonical.push_str(&out.join("/"));
        if trailing && !canonical.ends_with('/') {
            canonical.push('/');
        }
        Ok(CanonicalPath(canonical))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for CanonicalPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// A path glob over a canonical request path (FEP-5 §4): `*` matches one segment, `**` any depth
/// (zero or more segments), `?` one character; within a segment `*` matches any run of
/// characters. Absent in a rule means `/**`.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PathGlob(String);

impl PathGlob {
    pub fn any() -> PathGlob {
        PathGlob("/**".to_string())
    }

    fn parse(raw: &str) -> Result<PathGlob, String> {
        if !raw.starts_with('/') {
            return Err(format!("path glob {raw:?} must start with '/'"));
        }
        if raw.contains('#') {
            return Err(format!("path glob {raw:?} must not carry a fragment"));
        }
        for seg in raw.split('/').skip(1) {
            if seg == "." || seg == ".." {
                return Err(format!("path glob {raw:?} must not contain dot-segments"));
            }
            if seg.contains("**") && seg != "**" {
                return Err(format!("`**` must be a whole segment in {raw:?}"));
            }
        }
        let collapsed = raw.trim_end_matches('/');
        Ok(PathGlob(if collapsed.is_empty() {
            "/".to_string()
        } else {
            collapsed.to_string()
        }))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn matches(&self, path: &CanonicalPath) -> bool {
        let pat: Vec<&str> = self
            .0
            .split('/')
            .skip(1)
            .filter(|s| !s.is_empty())
            .collect();
        let segs: Vec<&str> = path
            .as_str()
            .split('/')
            .skip(1)
            .filter(|s| !s.is_empty())
            .collect();
        match_segments(&pat, &segs)
    }
}

fn match_segments(pat: &[&str], segs: &[&str]) -> bool {
    match pat.split_first() {
        None => segs.is_empty(),
        Some((&"**", rest)) => (0..=segs.len()).any(|i| match_segments(rest, &segs[i..])),
        Some((p, rest)) => match segs.split_first() {
            Some((s, srest)) => {
                match_segment(p.as_bytes(), s.as_bytes()) && match_segments(rest, srest)
            }
            None => false,
        },
    }
}

fn match_segment(p: &[u8], s: &[u8]) -> bool {
    match p.split_first() {
        None => s.is_empty(),
        Some((b'*', rest)) => (0..=s.len()).any(|i| match_segment(rest, &s[i..])),
        Some((b'?', rest)) => !s.is_empty() && match_segment(rest, &s[1..]),
        Some((c, rest)) => s.first() == Some(c) && match_segment(rest, &s[1..]),
    }
}

/// What a host rule grants.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum HostAccess {
    /// `tunnel:host`: TLS forwarded after the server-name check (FW-EGR16); the request is opaque
    /// (FW-EGR5).
    Tunnel,
    /// `allow:` or method verbs: TLS is terminated and each request's method and canonical path
    /// must match (FW-EGR10). An empty method list is `allow:`, every method.
    Inspected {
        methods: Vec<HttpMethod>,
        path: PathGlob,
    },
    /// `deny:host` (terminal for the host) or `deny:host/path` (terminal for matching requests;
    /// needs the inspected grade, FW-BP14).
    Deny { path: Option<PathGlob> },
}

/// One host rule, as authored in `rules` (FW-BP13). Serialized as its canonical rule string.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct HostRule {
    pub host: HostPattern,
    /// `None` means every port (a `deny` without a port), else the port the rule admits.
    pub port: Option<u16>,
    pub access: HostAccess,
}

/// The verb atoms that belong to the egress axis alone (FW-BP13): every [`HttpMethod::atom`], then
/// `tunnel`. `allow` and `deny` belong to both axes, and the target's shape decides (FW-BP16).
pub const HTTP_ATOMS: &[&str] = &[
    "get", "post", "put", "patch", "delete", "head", "options", "tunnel",
];

/// FW-BP16: a rule target is a path pattern when it begins with `/`, `~`, `$` (a sigil) or `**` (an
/// any-depth pattern, which no host can start with), and a host target otherwise.
pub fn target_is_host(target: &str) -> bool {
    !(target.starts_with('/')
        || target.starts_with('~')
        || target.starts_with('$')
        || target.starts_with("**"))
}

/// The host grammar, stated once for every refusal that needs it.
const HOST_GRAMMAR: &str = "a host target is an exact DNS name containing a dot, `localhost`, \
                            `*.<suffix>` for the names under a suffix, or an IP literal (IPv6 in \
                            brackets), optionally followed by `:port` and, except for `tunnel:`, a \
                            path glob";

impl HostRule {
    /// Parse `<atoms>:<target>` where the atoms are HTTP method atoms, `allow`, `tunnel` or `deny`
    /// and the target is `host[:port][/glob]` (FW-BP13). `atoms` is the part before the first `:`.
    pub fn parse(atoms: &str, target: &str) -> Result<HostRule, String> {
        let atoms: Vec<&str> = atoms.split(',').map(str::trim).collect();
        let (host, port, path) = parse_target(target)?;
        let single = |verb: &str| -> Result<(), String> {
            if atoms.len() > 1 {
                return Err(format!("`{verb}` cannot be combined with other atoms"));
            }
            Ok(())
        };
        if atoms.contains(&"deny") {
            single("deny")?;
            return Ok(HostRule {
                host,
                port,
                access: HostAccess::Deny { path },
            });
        }
        if atoms.contains(&"tunnel") {
            single("tunnel")?;
            if path.is_some() {
                return Err(format!(
                    "`tunnel:{target}` names a path, which a tunnel cannot see; `allow:{target}` \
                     inspects the host and admits that path"
                ));
            }
            return Ok(HostRule {
                host,
                port: Some(port.unwrap_or(DEFAULT_HTTPS_PORT)),
                access: HostAccess::Tunnel,
            });
        }
        let mut methods = Vec::new();
        if atoms.contains(&"allow") {
            single("allow")?;
        } else {
            for atom in &atoms {
                match HttpMethod::from_atom(atom) {
                    Some(m) => methods.push(m),
                    None => {
                        return Err(format!(
                            "unknown egress atom {atom:?} (known: {}, allow, deny)",
                            HTTP_ATOMS.join(", ")
                        ))
                    }
                }
            }
        }
        methods.sort();
        methods.dedup();
        Ok(HostRule {
            host,
            port: Some(port.unwrap_or(DEFAULT_HTTPS_PORT)),
            access: HostAccess::Inspected {
                methods,
                path: path.unwrap_or_else(PathGlob::any),
            },
        })
    }

    pub fn is_inspected(&self) -> bool {
        matches!(self.access, HostAccess::Inspected { .. })
    }

    pub fn port_matches(&self, port: u16) -> bool {
        self.port.map(|p| p == port).unwrap_or(true)
    }

    fn same_port(&self, other: &HostRule) -> bool {
        match (self.port, other.port) {
            (Some(a), Some(b)) => a == b,
            _ => true,
        }
    }
}

impl fmt::Display for HostRule {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let target = |path: Option<&PathGlob>| {
            let mut t = self.host.to_string();
            if let Some(p) = self.port {
                if p != DEFAULT_HTTPS_PORT || matches!(self.access, HostAccess::Deny { .. }) {
                    t.push_str(&format!(":{p}"));
                }
            }
            if let Some(path) = path {
                t.push_str(path.as_str());
            }
            t
        };
        match &self.access {
            HostAccess::Tunnel => write!(f, "tunnel:{}", target(None)),
            HostAccess::Deny { path } => write!(f, "deny:{}", target(path.as_ref())),
            HostAccess::Inspected { methods, path } => {
                let shown = (path.as_str() != "/**").then_some(path);
                write!(f, "{}:{}", HttpMethod::atoms(methods), target(shown))
            }
        }
    }
}

impl Serialize for HostRule {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_string())
    }
}

impl std::str::FromStr for HostRule {
    type Err = String;

    /// A whole `<atoms>:<target>` rule string.
    fn from_str(raw: &str) -> Result<HostRule, String> {
        let (atoms, target) = raw
            .split_once(':')
            .ok_or_else(|| format!("host rule {raw:?} has no verb"))?;
        HostRule::parse(atoms, target)
    }
}

impl<'de> Deserialize<'de> for HostRule {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        String::deserialize(deserializer)?
            .parse()
            .map_err(serde::de::Error::custom)
    }
}

/// Split `host[:port]` or `[v6][:port]` -- the one authority parser rules, the Gateway and
/// `explain` share. The host keeps its brackets for [`canonicalize_host`].
pub fn split_host_port(hostport: &str) -> Result<(&str, Option<u16>), String> {
    if let Some(rest) = hostport.strip_prefix('[') {
        let end = rest
            .find(']')
            .ok_or_else(|| format!("unclosed IPv6 literal in {hostport:?}"))?;
        let port = match &rest[end + 1..] {
            "" => None,
            p => Some(parse_port(p.strip_prefix(':').unwrap_or("x"), hostport)?),
        };
        return Ok((&hostport[..end + 2], port));
    }
    match hostport.rsplit_once(':') {
        Some((h, p)) => Ok((h, Some(parse_port(p, hostport)?))),
        None => Ok((hostport, None)),
    }
}

/// Split an absolute `http://` or `https://` URL into its host, port (the scheme's default when
/// absent) and raw path -- shared by the Gateway's plain-HTTP path and `explain` (FW-FID9).
pub fn split_url(url: &str) -> Result<(&str, u16, &str), String> {
    let (scheme, rest) = url
        .split_once("://")
        .ok_or_else(|| format!("{url:?} is not an absolute URL"))?;
    let default_port = match scheme {
        "https" => DEFAULT_HTTPS_PORT,
        "http" => DEFAULT_HTTP_PORT,
        other => return Err(format!("only http:// and https:// URLs, not {other}://")),
    };
    let (authority, path) = match rest.find(['/', '?']) {
        Some(i) if rest.as_bytes()[i] == b'/' => (&rest[..i], &rest[i..]),
        Some(i) => (&rest[..i], "/"),
        None => (rest, "/"),
    };
    let (host, port) = split_host_port(authority)?;
    Ok((host, port.unwrap_or(default_port), path))
}

fn parse_target(target: &str) -> Result<(HostPattern, Option<u16>, Option<PathGlob>), String> {
    let (hostport, path) = match target.find('/') {
        Some(i) => (&target[..i], Some(PathGlob::parse(&target[i..])?)),
        None => (target, None),
    };
    let (host_raw, port) = split_host_port(hostport).map_err(|e| format!("{e} in {target:?}"))?;
    let refuse = |e: String| format!("{e} in {target:?}; {HOST_GRAMMAR}");
    let host = if let Some(suffix) = host_raw.strip_prefix("*.") {
        match canonicalize_host(suffix).map_err(|e| refuse(e.to_string()))? {
            CanonicalHost::Name(n) => HostPattern::Wildcard(n),
            CanonicalHost::Ip(_) => return Err(refuse("a wildcard cannot cover an IP".into())),
        }
    } else {
        match canonicalize_host(host_raw).map_err(|e| refuse(e.to_string()))? {
            // FW-BP16: a dotless name is a relative path typed by mistake far more often than a
            // host, so it is refused rather than read as one.
            CanonicalHost::Name(n) if !n.contains('.') && n != "localhost" => {
                return Err(refuse(format!(
                    "{n:?} has no dot; a path target starts with /, ~ or $CWD"
                )))
            }
            CanonicalHost::Name(n) => HostPattern::Exact(n),
            CanonicalHost::Ip(ip) => HostPattern::Ip(ip),
        }
    };
    Ok((host, port, path))
}

fn parse_port(p: &str, hostport: &str) -> Result<u16, String> {
    match p.parse::<u16>() {
        Ok(0) | Err(_) => Err(format!("invalid port {p:?} in {hostport:?}")),
        Ok(port) => Ok(port),
    }
}

/// The one-grade-per-host-and-port rule (FW-BP14): a tunnel rule and an inspected rule that could
/// match one host on one port (directly or through a wildcard) are a compile error naming both, as
/// is a path-scoped deny on a host no inspected rule covers. Returns every conflict.
pub fn validate_host_rules(rules: &[HostRule]) -> Result<(), Vec<String>> {
    let mut errors = Vec::new();
    for (i, a) in rules.iter().enumerate() {
        for b in &rules[i + 1..] {
            let (tunnel, inspected) = match (&a.access, &b.access) {
                (HostAccess::Tunnel, HostAccess::Inspected { .. }) => (a, b),
                (HostAccess::Inspected { .. }, HostAccess::Tunnel) => (b, a),
                _ => continue,
            };
            if tunnel.host.overlaps(&inspected.host) && tunnel.same_port(inspected) {
                errors.push(format!(
                    "`{tunnel}` and `{inspected}` give one host and port two grades; the tunnel \
                     would admit every request and the inspected rule would be decoration -- keep \
                     one (`allow:{}` inspects the whole host)",
                    tunnel.host
                ));
            }
        }
        if let HostAccess::Deny { path: Some(_) } = &a.access {
            let covered = rules
                .iter()
                .any(|r| r.is_inspected() && r.host.overlaps(&a.host) && r.same_port(a));
            if !covered {
                errors.push(format!(
                    "`{a}` denies a path on a host that is not inspected, so the Gateway cannot see \
                     the path; add an inspected rule for the host (e.g. `allow:{}`) or deny the \
                     host",
                    a.host
                ));
            }
        }
    }
    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors)
    }
}

/// The Gateway's verdict on a CONNECT, or on the host half of a plain-HTTP request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ConnectDecision<'a> {
    /// Tunnel grade: check the server name, then splice bytes (FW-EGR16).
    Tunnel(&'a HostRule),
    /// Terminate TLS and decide per request.
    Inspect,
    Deny(Denial<'a>),
}

/// The verdict on one request to an inspected host.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RequestDecision<'a> {
    Allow(&'a HostRule),
    Deny(Denial<'a>),
}

/// Why a destination or request was refused, and the `deny:` rule that refused it, if one did.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Denial<'a> {
    pub reason: RefusalReason,
    /// Operator-channel prose; never shown to the confined process (FW-CRED7).
    pub detail: String,
    pub rule: Option<&'a HostRule>,
}

/// The merged, validated host table (FW-EGR1). Empty means deny everything (FW-EGR2).
#[derive(Clone, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct HostTable {
    pub rules: Vec<HostRule>,
}

impl HostTable {
    pub fn new(mut rules: Vec<HostRule>) -> HostTable {
        rules.sort();
        rules.dedup();
        HostTable { rules }
    }

    /// Decide a CONNECT (or the host half of a plain-HTTP request): a host-level deny is terminal;
    /// otherwise the host and port's single grade decides.
    pub fn decide_connect(&self, host: &CanonicalHost, port: u16) -> ConnectDecision<'_> {
        if let Some(rule) = self.rules.iter().find(|r| {
            matches!(r.access, HostAccess::Deny { path: None })
                && r.port_matches(port)
                && r.host.matches(host)
        }) {
            return ConnectDecision::Deny(Denial {
                reason: RefusalReason::HostDenied,
                detail: format!("{host} is denied"),
                rule: Some(rule),
            });
        }
        let matching: Vec<&HostRule> = self
            .rules
            .iter()
            .filter(|r| r.port_matches(port) && r.host.matches(host))
            .collect();
        if matching.iter().any(|r| r.is_inspected()) {
            return ConnectDecision::Inspect;
        }
        if let Some(rule) = matching
            .into_iter()
            .find(|r| matches!(r.access, HostAccess::Tunnel))
        {
            return ConnectDecision::Tunnel(rule);
        }
        ConnectDecision::Deny(Denial {
            reason: RefusalReason::HostNotListed,
            detail: format!("no host rule admits {host}:{port}"),
            rule: None,
        })
    }

    /// How specifically the admitting rules name this host and port: the strongest naming among
    /// them decides the address classes the connection may reach (FW-EGR19).
    pub fn naming(&self, host: &CanonicalHost, port: u16) -> Option<Naming> {
        self.rules
            .iter()
            .filter(|r| !matches!(r.access, HostAccess::Deny { .. }))
            .filter(|r| r.port_matches(port) && r.host.matches(host))
            .map(|r| r.host.naming())
            .max()
    }

    /// Decide one request on an inspected host: a path deny is terminal, then any inspected rule
    /// whose methods and path match admits it (FW-EGR10). `method` is `None` for a method outside
    /// the rule atoms, which only `allow:` admits.
    pub fn decide_request(
        &self,
        host: &CanonicalHost,
        port: u16,
        method: Option<HttpMethod>,
        path: &CanonicalPath,
    ) -> RequestDecision<'_> {
        let for_host = || {
            self.rules
                .iter()
                .filter(move |r| r.port_matches(port) && r.host.matches(host))
        };
        for r in for_host() {
            if let HostAccess::Deny { path: deny } = &r.access {
                if deny.as_ref().map(|g| g.matches(path)).unwrap_or(true) {
                    return RequestDecision::Deny(Denial {
                        reason: RefusalReason::Path,
                        detail: format!("{host}{path} is denied"),
                        rule: Some(r),
                    });
                }
            }
        }
        let mut path_matched = false;
        for r in for_host() {
            if let HostAccess::Inspected {
                methods,
                path: glob,
            } = &r.access
            {
                if !glob.matches(path) {
                    continue;
                }
                path_matched = true;
                if methods.is_empty() || method.map(|m| methods.contains(&m)).unwrap_or(false) {
                    return RequestDecision::Allow(r);
                }
            }
        }
        let shown = method
            .map(|m| m.atom().to_ascii_uppercase())
            .unwrap_or_else(|| "this method".into());
        RequestDecision::Deny(if path_matched {
            Denial {
                reason: RefusalReason::Method,
                detail: format!("no rule admits {shown} on {host}{path}"),
                rule: None,
            }
        } else {
            Denial {
                reason: RefusalReason::Path,
                detail: format!("no rule admits the path {host}{path}"),
                rule: None,
            }
        })
    }

    /// Decide a plain-HTTP request (and `explain`'s question about one): the host decides, then
    /// the method and canonical path when the host is inspected. `Ok` carries the admitting rule.
    pub fn decide(
        &self,
        host: &CanonicalHost,
        port: u16,
        method: Option<HttpMethod>,
        path: &CanonicalPath,
    ) -> Result<&HostRule, Denial<'_>> {
        match self.decide_connect(host, port) {
            ConnectDecision::Tunnel(rule) => Ok(rule),
            ConnectDecision::Deny(d) => Err(d),
            ConnectDecision::Inspect => match self.decide_request(host, port, method, path) {
                RequestDecision::Allow(rule) => Ok(rule),
                RequestDecision::Deny(d) => Err(d),
            },
        }
    }

    /// The patterns the session CA may certify (FW-EGR25): every inspected rule's host, once.
    pub fn inspected_hosts(&self) -> Vec<&HostPattern> {
        let mut hosts: Vec<&HostPattern> = self
            .rules
            .iter()
            .filter(|r| r.is_inspected())
            .map(|r| &r.host)
            .collect();
        hosts.sort();
        hosts.dedup();
        hosts
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rule(s: &str) -> HostRule {
        s.parse().unwrap()
    }

    fn host(s: &str) -> CanonicalHost {
        canonicalize_host(s).unwrap()
    }

    fn path(s: &str) -> CanonicalPath {
        CanonicalPath::parse(s).unwrap()
    }

    trait Denied {
        fn denial(&self) -> Option<RefusalReason>;
    }

    impl Denied for ConnectDecision<'_> {
        fn denial(&self) -> Option<RefusalReason> {
            match self {
                ConnectDecision::Deny(d) => Some(d.reason),
                _ => None,
            }
        }
    }

    impl Denied for RequestDecision<'_> {
        fn denial(&self) -> Option<RefusalReason> {
            match self {
                RequestDecision::Deny(d) => Some(d.reason),
                _ => None,
            }
        }
    }

    #[test]
    fn authorities_and_urls_split_one_way() {
        assert_eq!(split_host_port("a.test:8443"), Ok(("a.test", Some(8443))));
        assert_eq!(split_host_port("a.test"), Ok(("a.test", None)));
        assert_eq!(split_host_port("[::1]:9"), Ok(("[::1]", Some(9))));
        assert!(split_host_port("a.test:x").is_err());
        assert!(split_host_port("a.test:0").is_err());
        assert_eq!(split_url("http://a.test/x"), Ok(("a.test", 80, "/x")));
        assert_eq!(split_url("https://[::1]"), Ok(("[::1]", 443, "/")));
        assert_eq!(split_url("http://a.test?q=1"), Ok(("a.test", 80, "/")));
        assert!(split_url("ftp://a.test/").is_err());
    }

    #[test]
    fn egress_atoms_list_every_method_then_tunnel() {
        let methods: Vec<&str> = HttpMethod::ALL.iter().map(|m| m.atom()).collect();
        assert_eq!(HTTP_ATOMS, [methods, vec!["tunnel"]].concat());
    }

    #[test]
    fn rules_parse_and_round_trip_through_their_canonical_text() {
        for s in [
            "tunnel:api.anthropic.com",
            "get,patch,post:api.github.com/repos/acme/**",
            "get:*.npmjs.org",
            "tunnel:internal.corp:8443",
            "deny:telemetry.example.com",
            "allow:api.github.com",
            "allow:status.corp.internal:80/health",
            "tunnel:127.0.0.1:8080",
            "tunnel:[::1]:9000",
            "allow:localhost:3000",
        ] {
            let r = rule(s);
            let text = r.to_string();
            assert_eq!(rule(&text), r, "{s} -> {text}");
        }
        assert_eq!(
            rule("get,post:api.github.com").to_string(),
            "get,post:api.github.com"
        );
        assert_eq!(
            rule("allow:api.github.com/**").to_string(),
            "allow:api.github.com"
        );
    }

    #[test]
    fn fw_bp16_and_the_verb_grammar_refuse_what_they_cannot_read() {
        // A tunnel has no path; a dotless name is a path typed by mistake; `*` alone is no host.
        assert!(HostRule::parse("tunnel", "api.github.com/repos").is_err());
        let dotless = HostRule::parse("allow", "build/**").unwrap_err();
        assert!(dotless.contains("no dot"), "{dotless}");
        let bare = HostRule::parse("allow", "*").unwrap_err();
        assert!(bare.contains("a host target is"), "{bare}");
        assert!(HostRule::parse("fetch", "api.github.com").is_err());
        assert!(HostRule::parse("tunnel", "api.github.com:0").is_err());
        // The FEP-5 spellings are gone, not aliased.
        assert!(HostRule::parse("any", "api.github.com").is_err());
        assert!(HostRule::parse("https", "api.github.com").is_err());
        assert!(HostRule::parse("allow,get", "api.github.com").is_err());
        assert!(HostRule::parse("tunnel,get", "api.github.com").is_err());
        for path in ["/etc/x", "~/.ssh", "$CWD/**", "**/.env"] {
            assert!(!target_is_host(path), "{path}");
        }
        for h in [
            "api.test",
            "*.test",
            "localhost:3000",
            "127.0.0.1",
            "build/**",
        ] {
            assert!(target_is_host(h), "{h}");
        }
    }

    #[test]
    fn wildcards_cover_labels_below_the_suffix_but_not_the_apex() {
        let r = rule("tunnel:*.example.com");
        assert!(r.host.matches(&host("a.example.com")));
        assert!(r.host.matches(&host("a.b.example.com")));
        assert!(!r.host.matches(&host("example.com")));
        assert!(!r.host.matches(&host("badexample.com")));
    }

    #[test]
    fn one_grade_per_host_and_port() {
        assert!(
            validate_host_rules(&[rule("tunnel:api.github.com"), rule("get:api.github.com")])
                .is_err()
        );
        let err =
            validate_host_rules(&[rule("tunnel:*.github.com"), rule("post:api.github.com/x")])
                .unwrap_err();
        assert!(err[0].contains("tunnel:*.github.com") && err[0].contains("post:api.github.com/x"));
        assert!(validate_host_rules(&[rule("deny:api.github.com/admin/**")]).is_err());
        assert!(validate_host_rules(&[
            rule("allow:api.github.com"),
            rule("deny:api.github.com/admin/**")
        ])
        .is_ok());
        assert!(validate_host_rules(&[rule("tunnel:a.test"), rule("get:b.test")]).is_ok());
        // FEP-6 S8 row 7b: one host on two ports is two endpoints.
        assert!(validate_host_rules(&[
            rule("tunnel:internal.corp.example:8443"),
            rule("allow:internal.corp.example")
        ])
        .is_ok());
    }

    #[test]
    fn decisions_follow_grade_terminal_deny_and_the_reason_set() {
        let t = HostTable::new(vec![
            rule("tunnel:api.anthropic.com"),
            rule("post:api.github.com/repos/acme/**"),
            rule("deny:api.github.com/repos/acme/secret/**"),
            rule("deny:telemetry.example.com"),
            rule("tunnel:*.example.com"),
        ]);
        assert!(matches!(
            t.decide_connect(&host("api.anthropic.com"), 443),
            ConnectDecision::Tunnel(_)
        ));
        assert_eq!(
            t.decide_connect(&host("api.github.com"), 443),
            ConnectDecision::Inspect
        );
        assert_eq!(
            t.decide_connect(&host("telemetry.example.com"), 443)
                .denial(),
            Some(RefusalReason::HostDenied)
        );
        assert_eq!(
            t.decide_connect(&host("blocked.test"), 443).denial(),
            Some(RefusalReason::HostNotListed)
        );
        assert_eq!(
            t.decide_connect(&host("api.anthropic.com"), 8443).denial(),
            Some(RefusalReason::HostNotListed)
        );
        let gh = host("api.github.com");
        let post = Some(HttpMethod::Post);
        assert!(matches!(
            t.decide_request(&gh, 443, post, &path("/repos/acme/x")),
            RequestDecision::Allow(_)
        ));
        assert_eq!(
            t.decide_request(&gh, 443, post, &path("/repos/other/x"))
                .denial(),
            Some(RefusalReason::Path)
        );
        assert_eq!(
            t.decide_request(&gh, 443, Some(HttpMethod::Get), &path("/repos/acme/x"))
                .denial(),
            Some(RefusalReason::Method)
        );
        match t.decide_request(&gh, 443, post, &path("/repos/acme/secret/k")) {
            RequestDecision::Deny(d) => {
                assert_eq!(d.reason, RefusalReason::Path);
                assert!(d.rule.is_some(), "the deny line decides");
            }
            other => panic!("{other:?}"),
        }
        // Only `allow:` admits a method outside the rule atoms.
        let all = HostTable::new(vec![rule("allow:api.test")]);
        assert!(matches!(
            all.decide_request(&host("api.test"), 443, None, &path("/x")),
            RequestDecision::Allow(_)
        ));
        // FW-EGR2: an empty table admits nothing.
        assert!(HostTable::default()
            .decide_connect(&gh, 443)
            .denial()
            .is_some());
    }

    #[test]
    fn naming_is_the_strongest_admitting_rule() {
        let t = HostTable::new(vec![
            rule("allow:*.corp.test"),
            rule("allow:git.corp.test"),
            rule("allow:10.0.0.1"),
            rule("deny:bad.corp.test:443"),
        ]);
        assert_eq!(t.naming(&host("git.corp.test"), 443), Some(Naming::Exact));
        assert_eq!(t.naming(&host("x.corp.test"), 443), Some(Naming::Wildcard));
        assert_eq!(t.naming(&host("10.0.0.1"), 443), Some(Naming::IpLiteral));
        assert_eq!(t.naming(&host("other.test"), 443), None);
    }

    #[test]
    fn hostname_bypass_battery_is_refused_or_canonical() {
        // FW-ADV-007 and FEP-6 §4.2: each variant canonicalizes to the genuine name or is refused.
        assert!(canonicalize_host("allowed.test\0.blocked.test").is_err());
        assert!(canonicalize_host("allowed%2etest.blocked.test").is_err());
        assert!(canonicalize_host("blocked.test#.allowed.test").is_err());
        assert!(canonicalize_host("under_score.test").is_err());
        assert_eq!(
            host("allowed.test."),
            CanonicalHost::Name("allowed.test".into())
        );
        assert_eq!(
            host("ALLOWED.test"),
            CanonicalHost::Name("allowed.test".into())
        );
        assert!(canonicalize_host("[::ffff:127.0.0.1%25allowed.test]").is_err());
        assert!(canonicalize_host("::1").is_err(), "IPv6 needs brackets");
        assert!(
            canonicalize_host("аllowed.test").is_err(),
            "a Cyrillic confusable"
        );
        for numeric in [
            "127.1",
            "2130706433",
            "0x7f.1",
            "0x7f000001",
            "a.b.1",
            "010.0.0.1",
        ] {
            assert!(
                matches!(canonicalize_host(numeric), Err(HostError::Numeric(_))),
                "{numeric}"
            );
        }
        assert_eq!(
            host("127.0.0.1"),
            CanonicalHost::Ip("127.0.0.1".parse().unwrap())
        );
        assert!(canonicalize_host("user@allowed.test").is_err());
        assert_eq!(
            host("[::ffff:10.0.0.1]"),
            CanonicalHost::Ip("10.0.0.1".parse().unwrap())
        );
    }

    fn class(ip: &str) -> AddressClass {
        classify(
            SocketAddr::new(ip.parse().unwrap(), 443),
            &LocalAddresses::default(),
        )
    }

    #[test]
    fn the_class_table_decides_in_order_with_embedded_ipv4() {
        for ip in [
            "169.254.169.254",
            "fd00:ec2::254",
            "100.100.100.200",
            "168.63.129.16",
            "::ffff:169.254.169.254",
            "64:ff9b::a9fe:a9fe",
            "2002:a9fe:a9fe::1",
        ] {
            assert_eq!(class(ip), AddressClass::Metadata, "{ip}");
        }
        for ip in [
            "127.0.0.1",
            "10.0.0.1",
            "172.16.0.1",
            "192.168.1.1",
            "100.64.0.1",
            "169.254.1.1",
            "0.0.0.0",
            "::1",
            "::",
            "fe80::1",
            "fc00::1",
            "::127.0.0.1",
            "64:ff9b::a00:1",
        ] {
            assert_eq!(class(ip), AddressClass::LocalPrivate, "{ip}");
        }
        for ip in [
            "192.0.2.1",
            "198.51.100.7",
            "203.0.113.9",
            "198.18.0.1",
            "240.0.0.1",
            "255.255.255.255",
            "224.0.0.1",
            "ff02::1",
            "2001:db8::1",
            "100::1",
        ] {
            assert_eq!(class(ip), AddressClass::SpecialPurpose, "{ip}");
        }
        // Teredo: the client address is XOR-obfuscated (here 10.0.0.1).
        assert_eq!(
            class("2001:0:4136:e378:8000:63bf:f5ff:fffe"),
            AddressClass::LocalPrivate
        );
        for ip in ["93.184.216.34", "2606:4700::1111", "64:ff9b::5db8:d822"] {
            assert_eq!(class(ip), AddressClass::Global, "{ip}");
        }
    }

    #[test]
    fn gateway_endpoints_and_host_addresses_are_classes() {
        let local = LocalAddresses {
            gateway: vec!["127.0.0.1:4100".parse().unwrap()],
            host: vec![
                "203.0.113.50".parse().unwrap(),
                "127.0.0.1".parse().unwrap(),
            ],
        };
        let at = |s: &str| classify(s.parse().unwrap(), &local);
        assert_eq!(at("127.0.0.1:4100"), AddressClass::GatewayEndpoint);
        assert_eq!(at("0.0.0.0:4100"), AddressClass::GatewayEndpoint);
        assert_eq!(at("203.0.113.50:4100"), AddressClass::GatewayEndpoint);
        assert_eq!(at("203.0.113.50:22"), AddressClass::HostAddress);
        assert_eq!(at("127.0.0.1:22"), AddressClass::HostAddress);
        assert!(!AddressClass::GatewayEndpoint.admits(Naming::IpLiteral));
    }

    #[test]
    fn fw_egr17_a_single_refused_address_refuses_the_answer() {
        let local = LocalAddresses::default();
        let answer: Vec<IpAddr> = vec![
            "93.184.216.34".parse().unwrap(),
            "10.0.0.1".parse().unwrap(),
        ];
        assert_eq!(
            admit_addresses(&answer, 443, Naming::Wildcard, &local),
            Err(("10.0.0.1".parse().unwrap(), AddressClass::LocalPrivate))
        );
        // FW-EGR19: an exact name may reach a private address; a wildcard never.
        let admitted = admit_addresses(&answer, 443, Naming::Exact, &local).unwrap();
        assert_eq!(admitted.len(), 2);
        let meta: Vec<IpAddr> = vec!["169.254.169.254".parse().unwrap()];
        assert!(admit_addresses(&meta, 80, Naming::Exact, &local).is_err());
        assert!(admit_addresses(&meta, 80, Naming::IpLiteral, &local).is_ok());
    }

    #[test]
    fn request_paths_canonicalize_before_matching() {
        // FW-ADV-017's cases.
        assert_eq!(path("/repos/acme/../other/x").as_str(), "/repos/other/x");
        assert_eq!(
            path("/repos/acme/%2e%2e/other/x").as_str(),
            "/repos/other/x"
        );
        assert!(CanonicalPath::parse("/repos/acme%2F..%2Fother/x").is_err());
        assert!(CanonicalPath::parse("/a\\b").is_err());
        assert!(CanonicalPath::parse("/a%00b").is_err());
        assert!(CanonicalPath::parse("/a b").is_err());
        assert!(CanonicalPath::parse("/a\u{e9}").is_err());
        assert_eq!(path("/a/b?x=../../y").as_str(), "/a/b");
        assert_eq!(path("/%7Euser/%41").as_str(), "/~user/A");
        let glob = PathGlob::parse("/repos/acme/**").unwrap();
        assert!(glob.matches(&path("/repos/acme/x")));
        assert!(glob.matches(&path("/repos/acme")));
        assert!(!glob.matches(&path("/repos/acmex/y")));
        assert!(PathGlob::parse("/repos/*/pulls")
            .unwrap()
            .matches(&path("/repos/acme/pulls")));
        assert!(!PathGlob::parse("/repos/*/pulls")
            .unwrap()
            .matches(&path("/repos/a/b/pulls")));
    }

    #[test]
    fn refusal_reasons_serialize_as_their_stable_strings() {
        for r in [
            RefusalReason::HostNotListed,
            RefusalReason::AddressClass,
            RefusalReason::SniMismatch,
            RefusalReason::UpstreamTls,
        ] {
            assert_eq!(
                serde_json::to_value(r).unwrap(),
                serde_json::Value::String(r.as_str().to_string())
            );
        }
    }
}
