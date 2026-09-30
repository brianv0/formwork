//! The per-session inspection CA (FW-EGR13, FEP-6 §4.6): generated in memory at session start, its
//! private key never written to a file nor handed to a confined process. Only the certificate is
//! exported, as the PEM bundle confined clients trust. The CA is name-constrained to the hosts the
//! blueprint inspects (FW-EGR25), so a leaked key or a minting defect can impersonate nothing else
//! to a client that enforces constraints on a trust anchor. Leaves share one session key, distinct
//! from the CA's, and are minted per host on first use.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use rcgen::{
    BasicConstraints, CertificateParams, CidrSubnet, DnType, GeneralSubtree, IsCa, KeyPair,
    KeyUsagePurpose, NameConstraints, SanType, SerialNumber,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::sign::{CertifiedKey, SigningKey};
use rustls::ServerConfig;

use formwork_blueprint::{CanonicalHost, HostPattern};

/// **ca-lifetime** (FEP-6 §4.9): the CA's validity; its key dies with the process.
const CA_LIFETIME: Duration = Duration::from_secs(400 * 86_400);
/// **leaf-lifetime**: a leaf's validity; it is re-minted once half has elapsed.
const LEAF_LIFETIME: Duration = Duration::from_secs(30 * 86_400);
/// **leaf-cache**: distinct leaves kept; the least recently used is dropped.
const LEAF_CACHE: usize = 1024;
/// Validity starts this long before issue, so a client clock that runs behind still accepts it.
const BACKDATE: Duration = Duration::from_secs(3600);

pub struct SessionCa {
    cert: rcgen::Certificate,
    key: KeyPair,
    /// The one key every leaf certifies (FEP-6 §10: a key per host buys nothing when every key
    /// lives in this process, and serving the CA's own key would put it in every handshake).
    leaf_key: KeyPair,
    leaf_signer: Arc<dyn SigningKey>,
    leaves: Mutex<LeafCache>,
}

impl std::fmt::Debug for SessionCa {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SessionCa { .. }")
    }
}

#[derive(Debug, thiserror::Error)]
#[error("session CA: {0}")]
pub struct CaError(String);

fn err(e: impl std::fmt::Display) -> CaError {
    CaError(e.to_string())
}

struct Leaf {
    config: Arc<ServerConfig>,
    minted: SystemTime,
    used: u64,
}

#[derive(Default)]
struct LeafCache {
    by_host: HashMap<CanonicalHost, Leaf>,
    tick: u64,
}

/// Set a validity window from `BACKDATE` before `from` to `lifetime` after it, in rcgen's time
/// type reached from the epoch both share.
fn window(params: &mut CertificateParams, from: SystemTime, lifetime: Duration) {
    let epoch = rcgen::date_time_ymd(1970, 1, 1);
    let since = |t: SystemTime| t.duration_since(UNIX_EPOCH).unwrap_or_default();
    params.not_before = epoch + since(from - BACKDATE);
    params.not_after = epoch + since(from + lifetime);
}

/// 16 random bytes with the high bit clear, so the serial encodes as a positive integer.
fn serial() -> Result<SerialNumber, CaError> {
    let mut bytes = [0u8; 16];
    rustls::crypto::ring::default_provider()
        .secure_random
        .fill(&mut bytes)
        .map_err(|_| err("the system random source failed"))?;
    bytes[0] &= 0x7f;
    Ok(SerialNumber::from_slice(&bytes))
}

/// The permitted subtree for one inspected host pattern (FW-EGR25): a DNS name constraint covers
/// the name and every name under it, so a wildcard's suffix is written as itself.
fn subtree(pattern: &HostPattern) -> GeneralSubtree {
    match pattern {
        HostPattern::Exact(n) | HostPattern::Wildcard(n) => GeneralSubtree::DnsName(n.clone()),
        HostPattern::Ip(ip @ IpAddr::V4(_)) => {
            GeneralSubtree::IpAddress(CidrSubnet::from_addr_prefix(*ip, 32))
        }
        HostPattern::Ip(ip @ IpAddr::V6(_)) => {
            GeneralSubtree::IpAddress(CidrSubnet::from_addr_prefix(*ip, 128))
        }
    }
}

impl SessionCa {
    /// A CA for exactly the `inspected` host patterns. It exists only when the blueprint inspects a
    /// host, so an empty list is refused: without constraints the CA could certify any name.
    pub fn generate(inspected: &[&HostPattern]) -> Result<SessionCa, CaError> {
        if inspected.is_empty() {
            return Err(err("no inspected host to constrain the CA to"));
        }
        let key = KeyPair::generate().map_err(err)?;
        let mut params = CertificateParams::default();
        params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
        params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        params.distinguished_name = rcgen::DistinguishedName::new();
        params
            .distinguished_name
            .push(DnType::CommonName, "Formwork session CA");
        params
            .distinguished_name
            .push(DnType::OrganizationName, "Formwork (this session only)");
        params.name_constraints = Some(NameConstraints {
            permitted_subtrees: inspected.iter().map(|p| subtree(p)).collect(),
            excluded_subtrees: Vec::new(),
        });
        params.serial_number = Some(serial()?);
        window(&mut params, SystemTime::now(), CA_LIFETIME);
        let cert = params.self_signed(&key).map_err(err)?;
        let leaf_key = KeyPair::generate().map_err(err)?;
        let leaf_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(leaf_key.serialize_der()));
        let leaf_signer = rustls::crypto::ring::sign::any_supported_type(&leaf_der).map_err(err)?;
        Ok(SessionCa {
            cert,
            key,
            leaf_key,
            leaf_signer,
            leaves: Mutex::new(LeafCache::default()),
        })
    }

    /// The CA certificate, PEM. The only part of the CA that leaves memory.
    pub fn cert_pem(&self) -> String {
        self.cert.pem()
    }

    /// The bundle confined clients trust: this CA first, then `roots` (the host's, from
    /// [`native_roots`]), so a tunnel-grade host still verifies for a client that reads only the
    /// bundle.
    pub fn trust_bundle(&self, roots: &[CertificateDer<'_>]) -> String {
        let mut out = self.cert_pem();
        out.push_str(&pem_bundle(roots));
        out
    }

    pub fn cert_der(&self) -> CertificateDer<'static> {
        self.cert.der().clone()
    }

    /// The TLS server config for one inspected host, around a leaf minted on first use and again
    /// once half its lifetime has elapsed. ALPN offers `http/1.1` only (FW-EGR20).
    pub fn server_config(&self, host: &CanonicalHost) -> Result<Arc<ServerConfig>, CaError> {
        let now = SystemTime::now();
        let mut cache = self.leaves.lock().map_err(err)?;
        cache.tick += 1;
        let tick = cache.tick;
        if let Some(leaf) = cache.by_host.get_mut(host) {
            let age = now.duration_since(leaf.minted).unwrap_or_default();
            if age < LEAF_LIFETIME / 2 {
                leaf.used = tick;
                return Ok(leaf.config.clone());
            }
        }
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let mut config = ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .map_err(err)?
            .with_no_client_auth()
            .with_cert_resolver(Arc::new(FixedCert(self.mint_leaf(host, now)?)));
        config.alpn_protocols = vec![b"http/1.1".to_vec()];
        let config = Arc::new(config);
        if cache.by_host.len() >= LEAF_CACHE && !cache.by_host.contains_key(host) {
            if let Some(oldest) = cache
                .by_host
                .iter()
                .min_by_key(|(_, l)| l.used)
                .map(|(h, _)| h.clone())
            {
                cache.by_host.remove(&oldest);
            }
        }
        cache.by_host.insert(
            host.clone(),
            Leaf {
                config: config.clone(),
                minted: now,
                used: tick,
            },
        );
        Ok(config)
    }

    fn mint_leaf(
        &self,
        host: &CanonicalHost,
        now: SystemTime,
    ) -> Result<Arc<CertifiedKey>, CaError> {
        let mut params = CertificateParams::default();
        params.subject_alt_names = vec![match host {
            CanonicalHost::Name(n) => SanType::DnsName(n.clone().try_into().map_err(err)?),
            CanonicalHost::Ip(ip) => SanType::IpAddress(*ip),
        }];
        params.distinguished_name = rcgen::DistinguishedName::new();
        // A name leaf carries its name; an IP leaf carries no name-shaped subject, which OpenSSL
        // would otherwise check against the CA's DNS constraints.
        params.distinguished_name.push(
            DnType::CommonName,
            match host {
                CanonicalHost::Name(n) => n.clone(),
                CanonicalHost::Ip(_) => "Formwork session leaf".to_string(),
            },
        );
        params.is_ca = IsCa::ExplicitNoCa;
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ServerAuth];
        // Python 3.13's VERIFY_X509_STRICT rejects a leaf without an authority key identifier.
        params.use_authority_key_identifier_extension = true;
        params.serial_number = Some(serial()?);
        window(&mut params, now, LEAF_LIFETIME);
        let leaf = params
            .signed_by(&self.leaf_key, &self.cert, &self.key)
            .map_err(err)?;
        Ok(Arc::new(CertifiedKey::new(
            vec![leaf.der().clone(), self.cert.der().clone()],
            self.leaf_signer.clone(),
        )))
    }
}

/// Answers every handshake with the CONNECT target's leaf; the Gateway has already checked the
/// ClientHello's server name against the target (FW-EGR10).
#[derive(Debug)]
struct FixedCert(Arc<CertifiedKey>);

impl rustls::server::ResolvesServerCert for FixedCert {
    fn resolve(&self, _hello: rustls::server::ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        Some(self.0.clone())
    }
}

/// The host trust store, loaded once per session from `formwork run`'s own environment
/// (`SSL_CERT_FILE`/`SSL_CERT_DIR` when set, else the platform store): the roots upstreams are
/// verified against (FW-EGR24) and the second half of the confined clients' bundle.
pub fn native_roots() -> Vec<CertificateDer<'static>> {
    let loaded = rustls_native_certs::load_native_certs();
    for e in &loaded.errors {
        tracing::warn!(error = %e, "loading a host trust-store certificate failed");
    }
    loaded.certs
}

/// Where [`native_roots`] reads from, for the resolved-input disclosure (FW-FID7).
pub fn native_roots_source() -> String {
    let named: Vec<String> = ["SSL_CERT_FILE", "SSL_CERT_DIR"]
        .iter()
        .filter_map(|v| std::env::var(v).ok().map(|p| format!("{v}={p}")))
        .collect();
    if named.is_empty() {
        "the platform trust store".to_string()
    } else {
        named.join(", ")
    }
}

/// PEM-encode DER certificates, for the bundle confined clients read.
fn pem_bundle(certs: &[CertificateDer<'_>]) -> String {
    use base64::Engine as _;
    let mut out = String::new();
    for c in certs {
        out.push_str("-----BEGIN CERTIFICATE-----\n");
        let b64 = base64::engine::general_purpose::STANDARD.encode(c.as_ref());
        for line in b64.as_bytes().chunks(64) {
            out.push_str(std::str::from_utf8(line).unwrap_or(""));
            out.push('\n');
        }
        out.push_str("-----END CERTIFICATE-----\n");
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn exact(n: &str) -> HostPattern {
        HostPattern::Exact(n.to_string())
    }

    #[test]
    fn a_ca_needs_an_inspected_host() {
        assert!(SessionCa::generate(&[]).is_err());
    }

    #[test]
    fn a_leaf_chains_to_the_session_ca_and_its_config_is_cached() {
        let api = exact("api.test");
        let ca = SessionCa::generate(&[&api]).unwrap();
        let host = CanonicalHost::Name("api.test".into());
        let leaf = ca.mint_leaf(&host, SystemTime::now()).unwrap();
        assert_eq!(leaf.cert.len(), 2);
        let a = ca.server_config(&host).unwrap();
        let b = ca.server_config(&host).unwrap();
        assert!(Arc::ptr_eq(&a, &b));
        assert!(ca.cert_pem().starts_with("-----BEGIN CERTIFICATE-----"));
    }

    #[test]
    fn leaves_share_one_key_distinct_from_the_ca_key() {
        let a = exact("a.test");
        let ca = SessionCa::generate(&[&a]).unwrap();
        assert_ne!(ca.key.public_key_der(), ca.leaf_key.public_key_der());
    }

    #[test]
    fn the_leaf_cache_is_bounded() {
        let wild = HostPattern::Wildcard("test".into());
        let ca = SessionCa::generate(&[&wild]).unwrap();
        for i in 0..LEAF_CACHE + 5 {
            ca.server_config(&CanonicalHost::Name(format!("h{i}.test")))
                .unwrap();
        }
        assert_eq!(ca.leaves.lock().unwrap().by_host.len(), LEAF_CACHE);
    }
}
