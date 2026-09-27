//! Host-scoped egress (FW-EGR1, FEP-5 §4): host rules in the verb grammar, their one-host-one-grade
//! validation (FW-BP14), hostname canonicalization (FW-EGR3), and the pure decision the Gateway
//! and `explain` share. A host resolves to exactly one grade: *tunnel* (`https:host`, admitted at
//! CONNECT, request opaque) or *inspected* (method verbs, admitted per request after TLS
//! termination, FW-EGR10). `deny:host` is terminal.

use std::fmt;
use std::net::IpAddr;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// The default port for a host rule without one.
pub const DEFAULT_HTTPS_PORT: u16 = 443;

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
}

/// A host pattern (FEP-5 §4): an exact DNS name, `*.example.com` for one or more labels under the
/// suffix (the apex excluded), or an IP literal. IP literals are the explicit naming FW-EGR4
/// requires for private and metadata addresses.
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
            (HostPattern::Wildcard(suffix), CanonicalHost::Name(h)) => {
                h.len() > suffix.len() + 1
                    && h.ends_with(suffix.as_str())
                    && h.as_bytes()[h.len() - suffix.len() - 1] == b'.'
            }
            (HostPattern::Ip(a), CanonicalHost::Ip(b)) => a == b,
            _ => false,
        }
    }

    /// Could one host match both patterns (FW-BP14)?
    pub fn overlaps(&self, other: &HostPattern) -> bool {
        let under = |name: &str, suffix: &str| {
            name.len() > suffix.len() + 1
                && name.ends_with(suffix)
                && name.as_bytes()[name.len() - suffix.len() - 1] == b'.'
        };
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

    pub fn is_ip(&self) -> bool {
        matches!(self, HostPattern::Ip(_))
    }
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
/// cannot be canonicalized is refused at the Gateway edge, never matched loosely.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum CanonicalHost {
    Name(String),
    Ip(IpAddr),
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
    #[error("host {0:?} contains a byte that is never part of a hostname (NUL, CR, LF, space, `%`, `#`, `@`, `\\`)")]
    ForbiddenByte(String),
    #[error("host {0:?} is not ASCII; write an internationalized name in its xn-- form")]
    NotAscii(String),
    #[error("host {0:?} is not a valid DNS name")]
    Invalid(String),
}

/// Canonicalize a requested host (FW-EGR3): lowercase ASCII, one trailing dot removed, and every
/// byte that has carried a bypass elsewhere refused outright -- NUL (`allowed\0.blocked`),
/// percent-encoding, CR/LF, fragment and userinfo separators, IPv6 zone IDs. IP literals, bare or
/// bracketed, become [`CanonicalHost::Ip`] (so `127.1` is not an IP and is refused as a name with a
/// numeric final label).
pub fn canonicalize_host(raw: &str) -> Result<CanonicalHost, HostError> {
    if raw.is_empty() {
        return Err(HostError::Empty);
    }
    if raw.bytes().any(|b| {
        matches!(
            b,
            0 | b'\r' | b'\n' | b' ' | b'\t' | b'%' | b'#' | b'@' | b'\\' | b'/'
        )
    }) {
        return Err(HostError::ForbiddenByte(raw.to_string()));
    }
    if !raw.is_ascii() {
        return Err(HostError::NotAscii(raw.to_string()));
    }
    let inner = raw
        .strip_prefix('[')
        .and_then(|r| r.strip_suffix(']'))
        .unwrap_or(raw);
    if let Ok(ip) = inner.parse::<IpAddr>() {
        return Ok(CanonicalHost::Ip(canonical_ip(ip)));
    }
    if inner != raw {
        return Err(HostError::Invalid(raw.to_string()));
    }
    let lower = raw.to_ascii_lowercase();
    let name = lower.strip_suffix('.').unwrap_or(&lower);
    if name.is_empty() || name.len() > 253 {
        return Err(HostError::Invalid(raw.to_string()));
    }
    let labels: Vec<&str> = name.split('.').collect();
    for label in &labels {
        let ok = !label.is_empty()
            && label.len() <= 63
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_');
        if !ok {
            return Err(HostError::Invalid(raw.to_string()));
        }
    }
    // A numeric final label is an IP-ish shorthand (`127.1`, `0x7f.1`) some resolvers expand; it is
    // never a DNS name, so it cannot be matched as one.
    if labels
        .last()
        .map(|l| l.bytes().all(|b| b.is_ascii_digit()) || l.starts_with("0x"))
        .unwrap_or(false)
    {
        return Err(HostError::Invalid(raw.to_string()));
    }
    Ok(CanonicalHost::Name(name.to_string()))
}

/// IPv4-mapped IPv6 addresses canonicalize to IPv4, so `::ffff:10.0.0.1` cannot dodge an IPv4 rule
/// or block.
pub fn canonical_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => v6
            .to_ipv4_mapped()
            .map(IpAddr::V4)
            .unwrap_or(IpAddr::V6(v6)),
        v4 => v4,
    }
}

/// Addresses that host rules reach only when an IP-literal rule names them (FW-EGR4): cloud
/// metadata, private and link-local ranges, unique-local IPv6, loopback, and the unspecified,
/// broadcast and multicast addresses. A name that resolves into one of these is refused at
/// connect even when the name is allowlisted -- the DNS-rebinding case (FW-ADV-008).
pub fn is_restricted_ip(ip: IpAddr) -> bool {
    match canonical_ip(ip) {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            v4.is_private()
                || v4.is_loopback()
                || v4.is_link_local()
                || v4.is_unspecified()
                || v4.is_broadcast()
                || v4.is_multicast()
                || o[0] == 0
                // Carrier-grade NAT (100.64/10) hosts internal services on some clouds.
                || (o[0] == 100 && (64..128).contains(&o[1]))
        }
        IpAddr::V6(v6) => {
            let s = v6.segments();
            v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_multicast()
                || (s[0] & 0xfe00) == 0xfc00 // unique local, fd00:ec2::254 included
                || (s[0] & 0xffc0) == 0xfe80 // link local
        }
    }
}

/// Hostnames of metadata services, refused unless a rule names them exactly (FW-EGR4).
pub const METADATA_HOSTNAMES: &[&str] = &["metadata.google.internal", "metadata"];

/// A path glob over a canonicalized request path (FEP-5 §4): `*` matches one segment, `**` any
/// depth (zero or more segments), `?` one character; within a segment `*` matches any run of
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

    /// Match a canonical request path (FW-EGR11 canonicalization happens before this).
    pub fn matches(&self, path: &str) -> bool {
        let pat: Vec<&str> = self
            .0
            .split('/')
            .skip(1)
            .filter(|s| !s.is_empty())
            .collect();
        let segs: Vec<&str> = path.split('/').skip(1).filter(|s| !s.is_empty()).collect();
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
    /// `https:host`: the CONNECT target is checked; the request is opaque (FW-EGR5).
    Tunnel,
    /// Method verbs: TLS is terminated and each request's method and canonical path must match
    /// (FW-EGR10). An empty method list is `any`.
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

/// The HTTP-axis verb atoms (FW-BP15).
pub const HTTP_ATOMS: &[&str] = &[
    "get", "post", "put", "patch", "delete", "head", "options", "any", "https",
];

/// Whether a rule target reads as a host rather than a path: paths start with `/`, `~`, `$CWD` or
/// `**` (FW-BP5 sigils included).
pub fn target_is_host(target: &str) -> bool {
    !(target.starts_with('/')
        || target.starts_with('~')
        || target.starts_with("$CWD")
        || target.starts_with("**"))
}

impl HostRule {
    /// Parse `<atoms>:<target>` where the atoms are HTTP atoms or `deny` and the target is
    /// `host[:port][/glob]` (FW-BP13). `atoms` is the part before the first `:`.
    pub fn parse(atoms: &str, target: &str) -> Result<HostRule, String> {
        let atoms: Vec<&str> = atoms.split(',').map(str::trim).collect();
        let (host, port, path) = parse_target(target)?;
        if atoms == ["deny"] {
            return Ok(HostRule {
                host,
                port,
                access: HostAccess::Deny { path },
            });
        }
        if atoms == ["https"] {
            if path.is_some() {
                return Err(format!(
                    "`https:{target}` names a path, which the tunnel grade cannot see; name the \
                     methods instead (e.g. `any:{target}`) to inspect the host"
                ));
            }
            return Ok(HostRule {
                host,
                port: Some(port.unwrap_or(DEFAULT_HTTPS_PORT)),
                access: HostAccess::Tunnel,
            });
        }
        let mut methods = Vec::new();
        let mut any = false;
        for atom in &atoms {
            if *atom == "any" {
                any = true;
            } else if let Some(m) = HttpMethod::from_atom(atom) {
                methods.push(m);
            } else if *atom == "https" || *atom == "deny" {
                return Err(format!("`{atom}` cannot be combined with other atoms"));
            } else {
                return Err(format!(
                    "unknown HTTP atom {atom:?} (known: {})",
                    HTTP_ATOMS.join(", ")
                ));
            }
        }
        if any {
            methods.clear();
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

    fn port_matches(&self, port: u16) -> bool {
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
            HostAccess::Tunnel => write!(f, "https:{}", target(None)),
            HostAccess::Deny { path } => write!(f, "deny:{}", target(path.as_ref())),
            HostAccess::Inspected { methods, path } => {
                let atoms = if methods.is_empty() {
                    "any".to_string()
                } else {
                    methods
                        .iter()
                        .map(|m| m.atom())
                        .collect::<Vec<_>>()
                        .join(",")
                };
                let shown = (path.as_str() != "/**").then_some(path);
                write!(f, "{atoms}:{}", target(shown))
            }
        }
    }
}

impl Serialize for HostRule {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for HostRule {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let raw = String::deserialize(deserializer)?;
        let (atoms, target) = raw
            .split_once(':')
            .ok_or_else(|| serde::de::Error::custom(format!("host rule {raw:?} has no verb")))?;
        HostRule::parse(atoms, target).map_err(serde::de::Error::custom)
    }
}

fn parse_target(target: &str) -> Result<(HostPattern, Option<u16>, Option<PathGlob>), String> {
    let (hostport, path) = match target.find('/') {
        Some(i) => (&target[..i], Some(PathGlob::parse(&target[i..])?)),
        None => (target, None),
    };
    let (host_raw, port) = if let Some(rest) = hostport.strip_prefix('[') {
        let end = rest
            .find(']')
            .ok_or_else(|| format!("unclosed IPv6 literal in {target:?}"))?;
        let port = match &rest[end + 1..] {
            "" => None,
            p => Some(parse_port(p.strip_prefix(':').unwrap_or("x"), target)?),
        };
        (&hostport[..end + 2], port)
    } else {
        match hostport.rsplit_once(':') {
            Some((h, p)) => (h, Some(parse_port(p, target)?)),
            None => (hostport, None),
        }
    };
    let host = if let Some(suffix) = host_raw.strip_prefix("*.") {
        match canonicalize_host(suffix).map_err(|e| format!("{e} in {target:?}"))? {
            CanonicalHost::Name(n) => HostPattern::Wildcard(n),
            CanonicalHost::Ip(_) => {
                return Err(format!("a wildcard cannot cover an IP ({target:?})"))
            }
        }
    } else {
        match canonicalize_host(host_raw).map_err(|e| format!("{e} in {target:?}"))? {
            CanonicalHost::Name(n) => HostPattern::Exact(n),
            CanonicalHost::Ip(ip) => HostPattern::Ip(ip),
        }
    };
    Ok((host, port, path))
}

fn parse_port(p: &str, target: &str) -> Result<u16, String> {
    match p.parse::<u16>() {
        Ok(0) | Err(_) => Err(format!("invalid port {p:?} in {target:?}")),
        Ok(port) => Ok(port),
    }
}

/// The one-host-one-grade rule (FW-BP14): a tunnel rule and an inspected rule that could match one
/// host (directly or through a wildcard) are a compile error naming both, as is a path-scoped deny
/// on a host no inspected rule covers. Returns every conflict, not just the first.
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
                    "`{tunnel}` and `{inspected}` give one host two grades; the tunnel rule would \
                     admit every request and the method rule would be decoration -- keep one \
                     (use `any:` to inspect the whole host)"
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
                     the path; add an inspected rule for the host (e.g. `any:{}`) or deny the host",
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

/// The Gateway's verdict for a CONNECT or a proxied request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EgressDecision {
    /// Tunnel: splice bytes to the upstream, request opaque.
    Tunnel { rule: HostRule },
    /// Terminate TLS and decide per request.
    Inspect,
    /// Admitted request on an inspected host.
    Allow { rule: HostRule },
    Deny {
        reason: String,
        rule: Option<HostRule>,
    },
}

impl EgressDecision {
    pub fn is_denied(&self) -> bool {
        matches!(self, EgressDecision::Deny { .. })
    }
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
    /// otherwise the host's single grade decides.
    pub fn decide_connect(&self, host: &CanonicalHost, port: u16) -> EgressDecision {
        if let Some(rule) = self.rules.iter().find(|r| {
            matches!(r.access, HostAccess::Deny { path: None })
                && r.port_matches(port)
                && r.host.matches(host)
        }) {
            return EgressDecision::Deny {
                reason: format!("{host} is denied"),
                rule: Some(rule.clone()),
            };
        }
        let matching: Vec<&HostRule> = self
            .rules
            .iter()
            .filter(|r| r.port_matches(port) && r.host.matches(host))
            .collect();
        if matching.iter().any(|r| r.is_inspected()) {
            return EgressDecision::Inspect;
        }
        if let Some(rule) = matching
            .iter()
            .find(|r| matches!(r.access, HostAccess::Tunnel))
        {
            return EgressDecision::Tunnel {
                rule: (*rule).clone(),
            };
        }
        EgressDecision::Deny {
            reason: format!("no host rule admits {host}:{port}"),
            rule: None,
        }
    }

    /// Decide one request on an inspected host: a path deny is terminal, then any inspected rule
    /// whose methods and path match admits it (FW-EGR10). `path` is already canonical (FW-EGR11).
    pub fn decide_request(
        &self,
        host: &CanonicalHost,
        port: u16,
        method: Option<HttpMethod>,
        path: &str,
    ) -> EgressDecision {
        let for_host = || {
            self.rules
                .iter()
                .filter(move |r| r.port_matches(port) && r.host.matches(host))
        };
        for r in for_host() {
            if let HostAccess::Deny { path: deny } = &r.access {
                if deny.as_ref().map(|g| g.matches(path)).unwrap_or(true) {
                    return EgressDecision::Deny {
                        reason: format!("{host}{path} is denied"),
                        rule: Some(r.clone()),
                    };
                }
            }
        }
        for r in for_host() {
            if let HostAccess::Inspected {
                methods,
                path: glob,
            } = &r.access
            {
                let method_ok =
                    methods.is_empty() || method.map(|m| methods.contains(&m)).unwrap_or(false);
                if method_ok && glob.matches(path) {
                    return EgressDecision::Allow { rule: r.clone() };
                }
            }
        }
        let shown = method
            .map(|m| m.atom().to_ascii_uppercase())
            .unwrap_or_else(|| "request".into());
        EgressDecision::Deny {
            reason: format!("no rule admits {shown} {host}{path}"),
            rule: None,
        }
    }

    /// Whether a rule names this exact host -- the explicit naming FW-EGR4 requires before a
    /// metadata hostname or a restricted IP literal is reachable.
    pub fn names_explicitly(&self, host: &CanonicalHost) -> bool {
        self.rules.iter().any(|r| {
            !matches!(r.access, HostAccess::Deny { .. })
                && match (&r.host, host) {
                    (HostPattern::Exact(e), CanonicalHost::Name(h)) => e == h,
                    (HostPattern::Ip(a), CanonicalHost::Ip(b)) => a == b,
                    _ => false,
                }
        })
    }
}

/// Canonicalize a request target path for matching (FW-EGR11): strip the query, decode
/// percent-encoded unreserved characters, remove dot-segments, and refuse an encoded `/`, a NUL,
/// or a backslash rather than guess how the upstream would read them.
pub fn canonicalize_request_path(raw: &str) -> Result<String, String> {
    let path = raw.split(['?', '#']).next().unwrap_or("");
    if !path.starts_with('/') {
        return Err(format!("request target {raw:?} is not origin-form"));
    }
    if path.contains('\\') {
        return Err("a backslash in the request path".to_string());
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
        } else if bytes[i] == 0 {
            return Err("a NUL in the request path".to_string());
        } else {
            decoded.push(bytes[i]);
            i += 1;
        }
    }
    let decoded = String::from_utf8(decoded).map_err(|_| "a non-UTF-8 request path".to_string())?;
    // RFC 3986 §5.2.4 remove_dot_segments, over whole segments.
    let mut out: Vec<&str> = Vec::new();
    let trailing = decoded.ends_with('/') || decoded.ends_with("/.") || decoded.ends_with("/..");
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
    Ok(canonical)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rule(s: &str) -> HostRule {
        let (a, t) = s.split_once(':').unwrap();
        HostRule::parse(a, t).unwrap()
    }

    fn host(s: &str) -> CanonicalHost {
        canonicalize_host(s).unwrap()
    }

    #[test]
    fn rules_parse_and_round_trip_through_their_canonical_text() {
        for s in [
            "https:api.anthropic.com",
            "get,patch,post:api.github.com/repos/acme/**",
            "get:*.npmjs.org",
            "https:internal.corp:8443",
            "deny:telemetry.example.com",
            "any:api.github.com",
            "https:127.0.0.1:8080",
            "https:[::1]:9000",
        ] {
            let r = rule(s);
            let text = r.to_string();
            assert_eq!(rule(&text), r, "{s} -> {text}");
        }
        assert_eq!(
            rule("get,post:api.github.com").to_string(),
            "get,post:api.github.com"
        );
        assert!(HostRule::parse("https", "api.github.com/repos").is_err());
        assert!(HostRule::parse("fetch", "api.github.com").is_err());
        assert!(HostRule::parse("https", "api.github.com:0").is_err());
    }

    #[test]
    fn wildcards_cover_labels_below_the_suffix_but_not_the_apex() {
        let r = rule("https:*.example.com");
        assert!(r.host.matches(&host("a.example.com")));
        assert!(r.host.matches(&host("a.b.example.com")));
        assert!(!r.host.matches(&host("example.com")));
        assert!(!r.host.matches(&host("badexample.com")));
    }

    #[test]
    fn one_host_one_grade() {
        assert!(
            validate_host_rules(&[rule("https:api.github.com"), rule("get:api.github.com")])
                .is_err()
        );
        let err = validate_host_rules(&[rule("https:*.github.com"), rule("post:api.github.com/x")])
            .unwrap_err();
        assert!(err[0].contains("https:*.github.com") && err[0].contains("post:api.github.com/x"));
        assert!(validate_host_rules(&[rule("deny:api.github.com/admin/**")]).is_err());
        assert!(validate_host_rules(&[
            rule("any:api.github.com"),
            rule("deny:api.github.com/admin/**")
        ])
        .is_ok());
        assert!(validate_host_rules(&[rule("https:a.test"), rule("get:b.test")]).is_ok());
        // Same host on different ports are different endpoints.
        assert!(validate_host_rules(&[rule("https:a.test"), rule("get:a.test:8443")]).is_ok());
    }

    #[test]
    fn decisions_follow_grade_and_terminal_deny() {
        let t = HostTable::new(vec![
            rule("https:api.anthropic.com"),
            rule("post:api.github.com/repos/acme/**"),
            rule("deny:telemetry.example.com"),
            rule("https:*.example.com"),
        ]);
        assert!(matches!(
            t.decide_connect(&host("api.anthropic.com"), 443),
            EgressDecision::Tunnel { .. }
        ));
        assert_eq!(
            t.decide_connect(&host("api.github.com"), 443),
            EgressDecision::Inspect
        );
        assert!(t
            .decide_connect(&host("telemetry.example.com"), 443)
            .is_denied());
        assert!(t.decide_connect(&host("blocked.test"), 443).is_denied());
        assert!(t
            .decide_connect(&host("api.anthropic.com"), 8443)
            .is_denied());
        let gh = host("api.github.com");
        assert!(matches!(
            t.decide_request(&gh, 443, Some(HttpMethod::Post), "/repos/acme/x"),
            EgressDecision::Allow { .. }
        ));
        assert!(t
            .decide_request(&gh, 443, Some(HttpMethod::Post), "/repos/other/x")
            .is_denied());
        assert!(t
            .decide_request(&gh, 443, Some(HttpMethod::Get), "/repos/acme/x")
            .is_denied());
        // FW-EGR2: an empty table admits nothing.
        assert!(HostTable::default().decide_connect(&gh, 443).is_denied());
    }

    #[test]
    fn hostname_bypass_battery_is_refused_or_canonical() {
        // FW-ADV-007: each variant canonicalizes to the genuine name or is refused.
        assert!(canonicalize_host("allowed.test\0.blocked.test").is_err());
        assert!(canonicalize_host("allowed%2etest.blocked.test").is_err());
        assert!(canonicalize_host("blocked.test#.allowed.test").is_err());
        assert_eq!(
            host("allowed.test."),
            CanonicalHost::Name("allowed.test".into())
        );
        assert_eq!(
            host("ALLOWED.test"),
            CanonicalHost::Name("allowed.test".into())
        );
        assert!(canonicalize_host("::ffff:127.0.0.1%allowed.test").is_err());
        assert!(
            canonicalize_host("аllowed.test").is_err(),
            "a Cyrillic confusable"
        );
        assert!(canonicalize_host("127.1").is_err());
        assert!(canonicalize_host("user@allowed.test").is_err());
        assert_eq!(
            host("[::ffff:10.0.0.1]"),
            CanonicalHost::Ip("10.0.0.1".parse().unwrap())
        );
    }

    #[test]
    fn restricted_addresses_include_metadata_private_and_loopback() {
        for ip in [
            "169.254.169.254",
            "10.0.0.1",
            "192.168.1.1",
            "172.16.0.1",
            "127.0.0.1",
            "fd00:ec2::254",
            "::1",
            "0.0.0.0",
            "100.100.100.200",
        ] {
            assert!(is_restricted_ip(ip.parse().unwrap()), "{ip}");
        }
        for ip in ["93.184.216.34", "2606:4700::1111"] {
            assert!(!is_restricted_ip(ip.parse().unwrap()), "{ip}");
        }
    }

    #[test]
    fn request_paths_canonicalize_before_matching() {
        // FW-ADV-017's cases.
        assert_eq!(
            canonicalize_request_path("/repos/acme/../other/x").unwrap(),
            "/repos/other/x"
        );
        assert_eq!(
            canonicalize_request_path("/repos/acme/%2e%2e/other/x").unwrap(),
            "/repos/other/x"
        );
        assert!(canonicalize_request_path("/repos/acme%2F..%2Fother/x").is_err());
        assert!(canonicalize_request_path("/a\\b").is_err());
        assert!(canonicalize_request_path("/a%00b").is_err());
        assert_eq!(canonicalize_request_path("/a/b?x=../../y").unwrap(), "/a/b");
        assert_eq!(
            canonicalize_request_path("/%7Euser/%41").unwrap(),
            "/~user/A"
        );
        let glob = PathGlob::parse("/repos/acme/**").unwrap();
        assert!(glob.matches("/repos/acme/x"));
        assert!(glob.matches("/repos/acme"));
        assert!(!glob.matches("/repos/acmex/y"));
        assert!(PathGlob::parse("/repos/*/pulls")
            .unwrap()
            .matches("/repos/acme/pulls"));
        assert!(!PathGlob::parse("/repos/*/pulls")
            .unwrap()
            .matches("/repos/a/b/pulls"));
    }
}
