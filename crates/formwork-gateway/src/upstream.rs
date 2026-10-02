//! The operator's upstream proxy (FW-EGR26, FEP-6 §4.8): when `formwork run`'s own environment
//! names one, admitted egress leaves through it -- `CONNECT` for TLS, absolute form for plain
//! HTTP -- except to hosts its `NO_PROXY` exempts. The proxy resolves the names it carries, so the
//! engine cannot classify their addresses (reported `Partial`); the proxy's own address comes from
//! the operator and is not classified. Loopback destinations are always exempt, as in Go's
//! `net/http`: a remote proxy's loopback is not this host's.

use std::net::IpAddr;

use formwork_blueprint::{canonicalize_host, split_host_port, CanonicalHost};

/// One proxy: where it listens and the `Proxy-Authorization` value its URL's userinfo gives. NTLM
/// and Kerberos proxies are not supported.
#[derive(Clone, PartialEq, Eq)]
pub struct ProxyEndpoint {
    pub host: String,
    pub port: u16,
    pub authorization: Option<String>,
}

impl std::fmt::Debug for ProxyEndpoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.describe())
    }
}

impl ProxyEndpoint {
    /// `http://[user:password@]host[:port][/]`, or the same without a scheme.
    pub fn parse(url: &str) -> Result<ProxyEndpoint, String> {
        let rest = match url.split_once("://") {
            Some(("http" | "HTTP", rest)) => rest,
            Some((scheme, _)) => {
                return Err(format!(
                    "the upstream proxy {url:?} uses {scheme}://; only http:// proxies are \
                     supported (FW-EGR26)"
                ))
            }
            None => url,
        };
        let rest = rest.trim_end_matches('/');
        let (userinfo, hostport) = match rest.rsplit_once('@') {
            Some((u, h)) => (Some(u), h),
            None => (None, rest),
        };
        let (host, port) =
            split_host_port(hostport).map_err(|e| format!("the upstream proxy {url:?}: {e}"))?;
        if host.is_empty() {
            return Err(format!("the upstream proxy {url:?} names no host"));
        }
        let host = host
            .trim_start_matches('[')
            .trim_end_matches(']')
            .to_string();
        let authorization = userinfo.map(|u| {
            let (user, password) = u.split_once(':').unwrap_or((u, ""));
            crate::inspect::basic_value(&percent_decode(user), &percent_decode(password))
        });
        Ok(ProxyEndpoint {
            host,
            port: port.unwrap_or(80),
            authorization,
        })
    }

    /// The proxy without its credentials, for operator lines.
    pub fn describe(&self) -> String {
        if self.host.contains(':') {
            format!("[{}]:{}", self.host, self.port)
        } else {
            format!("{}:{}", self.host, self.port)
        }
    }
}

fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        let hex = bytes
            .get(i + 1..i + 3)
            .filter(|_| bytes[i] == b'%')
            .and_then(|h| std::str::from_utf8(h).ok())
            .and_then(|h| u8::from_str_radix(h, 16).ok());
        match hex {
            Some(b) => {
                out.push(b);
                i += 3;
            }
            None => {
                out.push(bytes[i]);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum Exempt {
    All,
    Suffix(String),
    Net(IpAddr, u8),
}

/// The upstream proxies `formwork run`'s environment names, and the hosts it exempts.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UpstreamProxy {
    /// For TLS: `HTTPS_PROXY` / `https_proxy`.
    pub https: Option<ProxyEndpoint>,
    /// For plain HTTP: `HTTP_PROXY` / `http_proxy`.
    pub http: Option<ProxyEndpoint>,
    exempt: Vec<Exempt>,
}

impl UpstreamProxy {
    /// From the values of the proxy variables; `None` when neither proxy is named.
    pub fn from_values(
        https: Option<&str>,
        http: Option<&str>,
        no_proxy: Option<&str>,
    ) -> Result<Option<UpstreamProxy>, String> {
        let parse = |v: Option<&str>| {
            v.map(str::trim)
                .filter(|v| !v.is_empty())
                .map(ProxyEndpoint::parse)
                .transpose()
        };
        let (https, http) = (parse(https)?, parse(http)?);
        if https.is_none() && http.is_none() {
            return Ok(None);
        }
        let exempt = no_proxy
            .unwrap_or("")
            .split(',')
            .map(|e| e.trim().to_ascii_lowercase())
            .filter(|e| !e.is_empty())
            .filter_map(|e| parse_exempt(&e))
            .collect();
        Ok(Some(UpstreamProxy {
            https,
            http,
            exempt,
        }))
    }

    /// The proxy a connection to `host` goes through, or `None` when it goes direct.
    pub fn endpoint_for(&self, host: &CanonicalHost, tls: bool) -> Option<&ProxyEndpoint> {
        if self.exempts(host) {
            return None;
        }
        if tls {
            self.https.as_ref()
        } else {
            self.http.as_ref()
        }
    }

    pub fn exempts(&self, host: &CanonicalHost) -> bool {
        match host {
            CanonicalHost::Ip(ip) if ip.is_loopback() => return true,
            CanonicalHost::Name(n) if n == "localhost" => return true,
            _ => {}
        }
        self.exempt.iter().any(|e| match (e, host) {
            (Exempt::All, _) => true,
            (Exempt::Suffix(s), CanonicalHost::Name(n)) => {
                n == s
                    || (n.len() > s.len()
                        && n.ends_with(s)
                        && n[..n.len() - s.len()].ends_with('.'))
            }
            (Exempt::Net(net, bits), CanonicalHost::Ip(ip)) => in_net(*ip, *net, *bits),
            _ => false,
        })
    }

    pub fn describe(&self) -> String {
        let mut parts = Vec::new();
        if let Some(p) = &self.https {
            parts.push(format!("https via {}", p.describe()));
        }
        if let Some(p) = &self.http {
            parts.push(format!("http via {}", p.describe()));
        }
        parts.join(", ")
    }
}

/// One `NO_PROXY` entry: `*`, a name or `.suffix` (with an optional `*.`), an IP, or a CIDR block.
/// A `:port` suffix is ignored.
fn parse_exempt(entry: &str) -> Option<Exempt> {
    if entry == "*" {
        return Some(Exempt::All);
    }
    if let Some((net, bits)) = entry.split_once('/') {
        let ip = net.trim_matches(['[', ']']).parse::<IpAddr>().ok()?;
        return Some(Exempt::Net(ip, bits.parse().ok()?));
    }
    if let Ok(ip) = entry.trim_matches(['[', ']']).parse::<IpAddr>() {
        let bits = if ip.is_ipv4() { 32 } else { 128 };
        return Some(Exempt::Net(ip, bits));
    }
    let name = entry.trim_start_matches('*').trim_start_matches('.');
    let name = split_host_port(name).map(|(h, _)| h).unwrap_or(name);
    match canonicalize_host(name) {
        Ok(CanonicalHost::Name(n)) => Some(Exempt::Suffix(n)),
        Ok(CanonicalHost::Ip(ip)) => Some(Exempt::Net(ip, if ip.is_ipv4() { 32 } else { 128 })),
        Err(_) => None,
    }
}

fn in_net(ip: IpAddr, net: IpAddr, bits: u8) -> bool {
    match (ip, net) {
        (IpAddr::V4(a), IpAddr::V4(n)) => {
            let bits = bits.min(32) as u32;
            let mask = u32::MAX.checked_shl(32 - bits).unwrap_or(0);
            u32::from(a) & mask == u32::from(n) & mask
        }
        (IpAddr::V6(a), IpAddr::V6(n)) => {
            let bits = bits.min(128) as u32;
            let mask = u128::MAX.checked_shl(128 - bits).unwrap_or(0);
            u128::from(a) & mask == u128::from(n) & mask
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn host(s: &str) -> CanonicalHost {
        canonicalize_host(s).unwrap()
    }

    #[test]
    fn proxy_urls_parse_with_credentials_and_defaults() {
        let p = ProxyEndpoint::parse("http://u%40x:p%3Aw@proxy.corp.internal:3128/").unwrap();
        assert_eq!((p.host.as_str(), p.port), ("proxy.corp.internal", 3128));
        assert_eq!(
            p.authorization.as_deref(),
            Some(crate::inspect::basic_value("u@x", "p:w").as_str())
        );
        assert_eq!(ProxyEndpoint::parse("proxy.test").unwrap().port, 80);
        assert!(ProxyEndpoint::parse("socks5://proxy.test:1080").is_err());
        assert!(!format!("{p:?}").contains("p:w"), "credentials never print");
    }

    #[test]
    fn no_proxy_exempts_suffixes_addresses_blocks_and_loopback() {
        let p = UpstreamProxy::from_values(
            Some("http://proxy.test:3128"),
            None,
            Some(".corp.internal, 10.0.0.0/8, 192.0.2.7, other.test:8080"),
        )
        .unwrap()
        .unwrap();
        assert!(p.endpoint_for(&host("git.corp.internal"), true).is_none());
        assert!(p.endpoint_for(&host("corp.internal"), true).is_none());
        assert!(p.endpoint_for(&host("xcorp.internal"), true).is_some());
        assert!(p.endpoint_for(&host("10.2.3.4"), true).is_none());
        assert!(p.endpoint_for(&host("192.0.2.7"), true).is_none());
        assert!(p.endpoint_for(&host("other.test"), true).is_none());
        assert!(p.endpoint_for(&host("127.0.0.1"), true).is_none());
        assert!(p.endpoint_for(&host("localhost"), true).is_none());
        assert!(p.endpoint_for(&host("api.test"), true).is_some());
        assert!(
            p.endpoint_for(&host("api.test"), false).is_none(),
            "no HTTP_PROXY, so plain HTTP goes direct"
        );
        assert!(UpstreamProxy::from_values(None, Some(""), Some("*"))
            .unwrap()
            .is_none());
    }
}
