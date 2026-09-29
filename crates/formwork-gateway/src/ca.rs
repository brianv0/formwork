//! The per-session inspection CA (FW-EGR13): generated in memory at session start, its private key
//! never written to a file nor handed to a confined process. Only the certificate is exported, as
//! the PEM bundle confined clients trust. Leaves are minted per inspected host and cached.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, KeyPair, KeyUsagePurpose, SanType};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::sign::CertifiedKey;
use rustls::ServerConfig;

use formwork_blueprint::CanonicalHost;

/// Leaves are valid from a day before minting to thirty days after, so a skewed client clock does
/// not reject them and nothing outlives a plausible session by much.
const LEAF_DAYS_BEFORE: i64 = 1;
const LEAF_DAYS_AFTER: i64 = 30;

pub struct SessionCa {
    cert: rcgen::Certificate,
    key: KeyPair,
    /// One TLS server config per inspected host, around the leaf minted for it.
    servers: Mutex<HashMap<String, Arc<ServerConfig>>>,
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

/// Civil date (y, m, d) for a day offset from the Unix epoch (Howard Hinnant's algorithm), so the
/// validity window follows the clock without a date-time dependency.
fn civil_from_days(days: i64) -> (i32, u8, u8) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    ((if m <= 2 { y + 1 } else { y }) as i32, m as u8, d as u8)
}

fn today() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| (d.as_secs() / 86_400) as i64)
}

fn window(params: &mut CertificateParams, before: i64, after: i64) {
    let (y, m, d) = civil_from_days(today() - before);
    params.not_before = rcgen::date_time_ymd(y, m, d);
    let (y, m, d) = civil_from_days(today() + after);
    params.not_after = rcgen::date_time_ymd(y, m, d);
}

impl SessionCa {
    pub fn generate() -> Result<SessionCa, CaError> {
        let key = KeyPair::generate().map_err(err)?;
        let mut params = CertificateParams::default();
        params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
        params.key_usages = vec![
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::CrlSign,
            KeyUsagePurpose::DigitalSignature,
        ];
        params
            .distinguished_name
            .push(DnType::CommonName, "Formwork session CA");
        params
            .distinguished_name
            .push(DnType::OrganizationName, "Formwork (this session only)");
        window(&mut params, LEAF_DAYS_BEFORE, LEAF_DAYS_AFTER);
        let cert = params.self_signed(&key).map_err(err)?;
        Ok(SessionCa {
            cert,
            key,
            servers: Mutex::new(HashMap::new()),
        })
    }

    /// The CA certificate, PEM. The only part of the CA that leaves memory.
    fn cert_pem(&self) -> String {
        self.cert.pem()
    }

    /// The bundle confined clients trust: this CA first, then `roots` (the host's, from
    /// [`native_roots`]), so a tunneled (uninspected) host still verifies for a client that reads
    /// only the bundle.
    pub fn trust_bundle(&self, roots: &[CertificateDer<'_>]) -> String {
        let mut out = self.cert_pem();
        out.push_str(&pem_bundle(roots));
        out
    }

    pub fn cert_der(&self) -> CertificateDer<'static> {
        self.cert.der().clone()
    }

    /// The TLS server config for one inspected host, around a leaf minted on first use. It
    /// answers every handshake with that leaf whatever SNI the client sends; the Gateway checks
    /// the SNI against the CONNECT target after the handshake.
    pub fn server_config(&self, host: &CanonicalHost) -> Result<Arc<ServerConfig>, CaError> {
        let name = host.to_string();
        if let Some(c) = self.servers.lock().map_err(err)?.get(&name) {
            return Ok(c.clone());
        }
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let mut config = ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .map_err(err)?
            .with_no_client_auth()
            .with_cert_resolver(Arc::new(FixedCert(self.mint_leaf(host)?)));
        config.alpn_protocols = vec![b"http/1.1".to_vec()];
        let config = Arc::new(config);
        self.servers
            .lock()
            .map_err(err)?
            .insert(name, config.clone());
        Ok(config)
    }

    fn mint_leaf(&self, host: &CanonicalHost) -> Result<Arc<CertifiedKey>, CaError> {
        let name = host.to_string();
        let mut params = CertificateParams::default();
        params.subject_alt_names = vec![match host {
            CanonicalHost::Name(n) => SanType::DnsName(n.clone().try_into().map_err(err)?),
            CanonicalHost::Ip(ip) => SanType::IpAddress(*ip),
        }];
        params
            .distinguished_name
            .push(DnType::CommonName, name.clone());
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ServerAuth];
        params.use_authority_key_identifier_extension = true;
        window(&mut params, LEAF_DAYS_BEFORE, LEAF_DAYS_AFTER);
        let leaf_key = KeyPair::generate().map_err(err)?;
        let leaf = params
            .signed_by(&leaf_key, &self.cert, &self.key)
            .map_err(err)?;
        let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(leaf_key.serialize_der()));
        let signing = rustls::crypto::ring::sign::any_supported_type(&key_der).map_err(err)?;
        Ok(Arc::new(CertifiedKey::new(
            vec![leaf.der().clone(), self.cert.der().clone()],
            signing,
        )))
    }
}

/// Answers every handshake with the CONNECT target's leaf.
#[derive(Debug)]
struct FixedCert(Arc<CertifiedKey>);

impl rustls::server::ResolvesServerCert for FixedCert {
    fn resolve(&self, _hello: rustls::server::ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        Some(self.0.clone())
    }
}

/// The host trust store, loaded once per session: the roots upstreams are verified against and
/// the second half of the confined clients' bundle.
pub fn native_roots() -> Vec<CertificateDer<'static>> {
    let loaded = rustls_native_certs::load_native_certs();
    for e in &loaded.errors {
        tracing::warn!(error = %e, "loading a host trust-store certificate failed");
    }
    loaded.certs
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

    #[test]
    fn civil_dates_match_known_days() {
        assert_eq!(civil_from_days(0), (1970, 1, 1));
        assert_eq!(civil_from_days(19_723), (2024, 1, 1));
        assert_eq!(civil_from_days(20_723), (2026, 9, 27));
    }

    #[test]
    fn a_leaf_chains_to_the_session_ca_and_its_config_is_cached() {
        let ca = SessionCa::generate().unwrap();
        let host = CanonicalHost::Name("api.test".into());
        assert_eq!(ca.mint_leaf(&host).unwrap().cert.len(), 2);
        let a = ca.server_config(&host).unwrap();
        let b = ca.server_config(&host).unwrap();
        assert!(Arc::ptr_eq(&a, &b));
        assert!(ca.cert_pem().starts_with("-----BEGIN CERTIFICATE-----"));
    }
}
