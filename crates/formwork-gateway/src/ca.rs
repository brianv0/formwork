//! The per-session inspection CA (FW-EGR13): generated in memory at session start, its private key
//! never written to a file nor handed to a confined process. Only the certificate is exported, as
//! the PEM bundle confined clients trust. Leaves are minted per inspected host and cached.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, KeyPair, KeyUsagePurpose, SanType};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::sign::CertifiedKey;

use formwork_blueprint::CanonicalHost;

/// Leaves are valid from a day before minting to thirty days after, so a skewed client clock does
/// not reject them and nothing outlives a plausible session by much.
const LEAF_DAYS_BEFORE: i64 = 1;
const LEAF_DAYS_AFTER: i64 = 30;

pub struct SessionCa {
    cert: rcgen::Certificate,
    key: KeyPair,
    leaves: Mutex<HashMap<String, Arc<CertifiedKey>>>,
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
        .map(|d| (d.as_secs() / 86_400) as i64)
        .unwrap_or(0)
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
            leaves: Mutex::new(HashMap::new()),
        })
    }

    /// The CA certificate, PEM. The only part of the CA that leaves memory.
    pub fn cert_pem(&self) -> String {
        self.cert.pem()
    }

    /// The bundle confined clients trust: this CA first, then the host's roots, so a tunneled
    /// (uninspected) host still verifies for a client that reads only the bundle.
    pub fn trust_bundle(&self) -> String {
        let mut out = self.cert_pem();
        let native = rustls_native_certs::load_native_certs();
        for e in &native.errors {
            tracing::warn!(error = %e, "loading a host trust-store certificate failed");
        }
        out.push_str(&pem_bundle(&native.certs));
        out
    }

    pub fn cert_der(&self) -> CertificateDer<'static> {
        self.cert.der().clone()
    }

    /// The leaf for one inspected host, minted on first use.
    pub fn leaf_for(&self, host: &CanonicalHost) -> Result<Arc<CertifiedKey>, CaError> {
        let name = host.to_string();
        if let Some(k) = self.leaves.lock().map_err(err)?.get(&name) {
            return Ok(k.clone());
        }
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
        let certified = Arc::new(CertifiedKey::new(
            vec![leaf.der().clone(), self.cert.der().clone()],
            signing,
        ));
        self.leaves
            .lock()
            .map_err(err)?
            .insert(name, certified.clone());
        Ok(certified)
    }
}

/// PEM-encode DER certificates, for the bundle confined clients read.
pub fn pem_bundle(certs: &[CertificateDer<'_>]) -> String {
    let mut out = String::new();
    for c in certs {
        out.push_str("-----BEGIN CERTIFICATE-----\n");
        let b64 = crate::egress::base64(c.as_ref());
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
    fn a_leaf_chains_to_the_session_ca_and_is_cached() {
        let ca = SessionCa::generate().unwrap();
        let host = CanonicalHost::Name("api.test".into());
        let a = ca.leaf_for(&host).unwrap();
        let b = ca.leaf_for(&host).unwrap();
        assert!(Arc::ptr_eq(&a, &b));
        assert_eq!(a.cert.len(), 2);
        assert!(ca.cert_pem().starts_with("-----BEGIN CERTIFICATE-----"));
    }
}
