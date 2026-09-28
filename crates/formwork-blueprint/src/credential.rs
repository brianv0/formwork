//! `allow-credentials` entries (FW-BP12): a bare Catalog type (expose -- the landed FW-CRED5 lift),
//! `broker:<type>` (the Gateway presents the credential; the floor holds, FW-CRED10), or an inline
//! binding for a credential the Catalog does not know. One list governs the Catalog; a type named
//! in both forms resolves to `broker`.

use std::fmt;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// How a brokered credential is presented on a bound host (FEP-5 §3.2).
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum BrokerScheme {
    /// `Authorization: Bearer <credential>`.
    Bearer,
    /// `Authorization: Basic base64(<user>:<credential>)`; `user` is the Catalog's (GitHub's
    /// `x-access-token`) or empty.
    Basic { user: String },
    /// `<name>: <credential>` (Anthropic's `x-api-key`).
    Header(String),
}

impl BrokerScheme {
    pub fn parse(raw: &str) -> Result<BrokerScheme, String> {
        match raw {
            "bearer" => Ok(BrokerScheme::Bearer),
            "basic" => Ok(BrokerScheme::Basic {
                user: String::new(),
            }),
            s => {
                if let Some(user) = s.strip_prefix("basic:") {
                    return Ok(BrokerScheme::Basic {
                        user: user.to_string(),
                    });
                }
                match s.strip_prefix("header:") {
                    Some(name)
                        if !name.is_empty()
                            && name
                                .bytes()
                                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_') =>
                    {
                        Ok(BrokerScheme::Header(name.to_ascii_lowercase()))
                    }
                    _ => Err(format!(
                        "unknown broker scheme {raw:?} (known: bearer, basic, basic:<user>, header:<name>)"
                    )),
                }
            }
        }
    }
}

impl fmt::Display for BrokerScheme {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BrokerScheme::Bearer => f.write_str("bearer"),
            BrokerScheme::Basic { user } if user.is_empty() => f.write_str("basic"),
            BrokerScheme::Basic { user } => write!(f, "basic:{user}"),
            BrokerScheme::Header(name) => write!(f, "header:{name}"),
        }
    }
}

/// An inline binding: a credential the Catalog does not know, named by the environment variable
/// that holds it on the launching host.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InlineBinding {
    pub name: String,
    pub env: String,
    pub hosts: Vec<String>,
    #[serde(with = "scheme_serde")]
    pub scheme: BrokerScheme,
}

mod scheme_serde {
    use super::BrokerScheme;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(s: &BrokerScheme, ser: S) -> Result<S::Ok, S::Error> {
        ser.serialize_str(&s.to_string())
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(de: D) -> Result<BrokerScheme, D::Error> {
        let raw = String::deserialize(de)?;
        BrokerScheme::parse(&raw).map_err(serde::de::Error::custom)
    }
}

/// One `allow-credentials` entry.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum CredentialEntry {
    /// Lift the floor for this type: the agent holds the credential (FW-CRED5).
    Expose(String),
    /// Keep the floor; the Gateway presents the credential (FW-CRED10/11).
    Broker(String),
    /// Broker a credential the Catalog does not know.
    Inline(InlineBinding),
}

impl CredentialEntry {
    pub fn parse(raw: &str) -> CredentialEntry {
        match raw.strip_prefix("broker:") {
            Some(t) => CredentialEntry::Broker(t.to_string()),
            None => CredentialEntry::Expose(raw.to_string()),
        }
    }

    /// The Catalog type or binding name.
    pub fn name(&self) -> &str {
        match self {
            CredentialEntry::Expose(t) | CredentialEntry::Broker(t) => t,
            CredentialEntry::Inline(b) => &b.name,
        }
    }
}

impl From<&str> for CredentialEntry {
    fn from(s: &str) -> Self {
        CredentialEntry::parse(s)
    }
}

impl Serialize for CredentialEntry {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            CredentialEntry::Expose(t) => serializer.serialize_str(t),
            CredentialEntry::Broker(t) => serializer.serialize_str(&format!("broker:{t}")),
            CredentialEntry::Inline(b) => b.serialize(serializer),
        }
    }
}

impl<'de> Deserialize<'de> for CredentialEntry {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Repr {
            Name(String),
            Inline(InlineBinding),
        }
        Ok(match Repr::deserialize(deserializer)? {
            Repr::Name(s) => CredentialEntry::parse(&s),
            Repr::Inline(b) => CredentialEntry::Inline(b),
        })
    }
}

/// The exposed type names: bare entries whose type is not also brokered (broker wins, FW-BP12).
/// This is the list every floor computation lifts (FW-CRED5).
pub fn exposed_types(entries: &[CredentialEntry]) -> Vec<String> {
    let brokered: Vec<&str> = entries
        .iter()
        .filter_map(|e| match e {
            CredentialEntry::Broker(t) => Some(t.as_str()),
            _ => None,
        })
        .collect();
    let mut out: Vec<String> = entries
        .iter()
        .filter_map(|e| match e {
            CredentialEntry::Expose(t) if !brokered.contains(&t.as_str()) => Some(t.clone()),
            _ => None,
        })
        .collect();
    out.sort();
    out.dedup();
    out
}

/// Types named both bare and `broker:` -- resolved to `broker`, with an operator line (FW-BP12).
pub fn doubly_named(entries: &[CredentialEntry]) -> Vec<String> {
    let mut out: Vec<String> = entries
        .iter()
        .filter_map(|e| match e {
            CredentialEntry::Expose(t) if entries.contains(&CredentialEntry::Broker(t.clone())) => {
                Some(t.clone())
            }
            _ => None,
        })
        .collect();
    out.sort();
    out.dedup();
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entries_parse_in_all_three_forms_and_broker_wins() {
        #[derive(Deserialize)]
        struct W {
            #[serde(rename = "allow-credentials")]
            c: Vec<CredentialEntry>,
        }
        let w: W = toml::from_str(
            r#"allow-credentials = ["claude", "broker:anthropic", "anthropic",
                { name = "ghe", env = "GHE_TOKEN", hosts = ["ghe.corp.internal"], scheme = "bearer" }]"#,
        )
        .unwrap();
        assert_eq!(exposed_types(&w.c), vec!["claude"]);
        assert_eq!(doubly_named(&w.c), vec!["anthropic"]);
        assert!(matches!(&w.c[3], CredentialEntry::Inline(b) if b.scheme == BrokerScheme::Bearer));
        let json = serde_json::to_string(&w.c).unwrap();
        let back: Vec<CredentialEntry> = serde_json::from_str(&json).unwrap();
        assert_eq!(back, w.c);
    }

    #[test]
    fn schemes_parse() {
        assert_eq!(
            BrokerScheme::parse("header:X-Api-Key").unwrap(),
            BrokerScheme::Header("x-api-key".into())
        );
        assert_eq!(
            BrokerScheme::parse("basic:x-access-token").unwrap(),
            BrokerScheme::Basic {
                user: "x-access-token".into()
            }
        );
        assert!(BrokerScheme::parse("digest").is_err());
        assert!(BrokerScheme::parse("header:").is_err());
    }
}

/// A brokered credential resolved against the Catalog (FW-CRED11/12): where its value comes from on
/// the launching host, and the scheme per bound host.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct BrokerPlan {
    pub name: String,
    /// Candidate env vars on the launching host, first set wins; the placeholder is set on the same
    /// variable in the confined environment (FW-CRED14).
    pub env_sources: Vec<String>,
    /// `(exact host, scheme)`.
    #[serde(serialize_with = "ser_bindings")]
    pub bindings: Vec<(crate::CanonicalHost, BrokerScheme)>,
}

fn ser_bindings<S: Serializer>(
    b: &[(crate::CanonicalHost, BrokerScheme)],
    ser: S,
) -> Result<S::Ok, S::Error> {
    use serde::ser::SerializeMap;
    let mut m = ser.serialize_map(Some(b.len()))?;
    for (h, s) in b {
        m.serialize_entry(&h.to_string(), &s.to_string())?;
    }
    m.end()
}

/// Resolve every brokered entry, checking FW-CRED12: each bound host must have an inspected rule,
/// or the Gateway could not see the request to present the credential. Every problem is returned,
/// each naming what to write.
pub fn resolve_brokers(
    entries: &[CredentialEntry],
    catalog: &crate::ResolvedCatalog,
    table: Option<&crate::HostTable>,
) -> Result<Vec<BrokerPlan>, Vec<String>> {
    let mut plans = Vec::new();
    let mut errors = Vec::new();
    for entry in entries {
        type RawBinding = (String, Result<BrokerScheme, String>);
        let (name, env_sources, raw_bindings): (String, Vec<String>, Vec<RawBinding>) = match entry
        {
            CredentialEntry::Expose(_) => continue,
            CredentialEntry::Broker(t) => match catalog.types.get(t) {
                None => {
                    errors.push(format!("broker:{t}: no such Catalog type"));
                    continue;
                }
                Some(e) if e.broker.is_empty() => {
                    errors.push(format!(
                        "broker:{t}: the Catalog has no broker binding for {t}; write an inline \
                             binding {{ name, env, hosts, scheme }} instead"
                    ));
                    continue;
                }
                Some(e) => (
                    t.clone(),
                    e.envs.clone(),
                    e.broker
                        .iter()
                        .flat_map(|b| {
                            let scheme = BrokerScheme::parse(&b.scheme);
                            b.hosts.iter().map(move |h| (h.clone(), scheme.clone()))
                        })
                        .collect(),
                ),
            },
            CredentialEntry::Inline(b) => {
                if catalog.types.contains_key(&b.name) {
                    errors.push(format!(
                        "inline binding {:?} shadows a Catalog type; use `broker:{}`",
                        b.name, b.name
                    ));
                    continue;
                }
                (
                    b.name.clone(),
                    vec![b.env.clone()],
                    b.hosts
                        .iter()
                        .map(|h| (h.clone(), Ok(b.scheme.clone())))
                        .collect(),
                )
            }
        };
        let mut bindings = Vec::new();
        for (raw_host, raw_scheme) in raw_bindings {
            let host = match crate::canonicalize_host(&raw_host) {
                Ok(h) => h,
                Err(e) => {
                    errors.push(format!("{name}: bound host {raw_host:?}: {e}"));
                    continue;
                }
            };
            let scheme = match raw_scheme {
                Ok(s) => s,
                Err(e) => {
                    errors.push(format!("{name}: {e}"));
                    continue;
                }
            };
            let inspected = table
                .map(|t| {
                    t.rules.iter().any(|r| {
                        r.is_inspected()
                            && r.port_matches(crate::DEFAULT_HTTPS_PORT)
                            && r.host.matches(&host)
                    })
                })
                .unwrap_or(false);
            if !inspected {
                errors.push(format!(
                    "{name} is brokered to {host}, which no inspected rule covers, so the Gateway \
                     could not see its requests; add `any:{host}/**` (or narrower methods and \
                     paths) to `rules`"
                ));
            }
            bindings.push((host, scheme));
        }
        plans.push(BrokerPlan {
            name,
            env_sources,
            bindings,
        });
    }
    if errors.is_empty() {
        Ok(plans)
    } else {
        Err(errors)
    }
}

#[cfg(test)]
mod broker_tests {
    use super::*;

    #[test]
    fn brokering_requires_an_inspected_rule_per_bound_host() {
        let catalog = crate::ResolvedCatalog::builtin_for_home("/home/x").unwrap();
        let entries = vec![CredentialEntry::parse("broker:github")];
        let rule =
            |s: &str| -> crate::HostRule { serde_json::from_str(&format!("\"{s}\"")).unwrap() };
        let partial = crate::HostTable::new(vec![rule("any:api.github.com")]);
        let err = resolve_brokers(&entries, &catalog, Some(&partial)).unwrap_err();
        assert_eq!(err.len(), 1);
        assert!(err[0].contains("any:github.com/**"), "{err:?}");
        let tunnel =
            crate::HostTable::new(vec![rule("https:github.com"), rule("any:api.github.com")]);
        assert!(resolve_brokers(&entries, &catalog, Some(&tunnel)).is_err());
        let full = crate::HostTable::new(vec![rule("any:github.com"), rule("any:api.github.com")]);
        let plans = resolve_brokers(&entries, &catalog, Some(&full)).unwrap();
        assert_eq!(plans[0].bindings.len(), 2);
        assert_eq!(plans[0].env_sources, vec!["GITHUB_TOKEN", "GH_TOKEN"]);
        assert!(resolve_brokers(
            &[CredentialEntry::parse("broker:ssh")],
            &catalog,
            Some(&full)
        )
        .is_err());
    }
}
