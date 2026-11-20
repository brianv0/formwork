//! Derived markers and the head search (FEP-12 phase A; FW-EGR33, FW-EGR34). A marker is a value
//! the session is never given: the value of a variable the Launcher stripped under the credential
//! floor, or the secret of a brokered credential. One in a request crossed the floor by a route
//! Formwork did not close, and forwarding it would complete the disclosure, so the Gateway
//! searches every request head for each marker in each **marker-encoding** and refuses a head that
//! carries one. The search reads the head as the session wrote it, before a brokered credential is
//! presented, so the Gateway never matches its own substitution.
//!
//! A marker's bytes stay in this module: a record names the marker and the encoding, never the
//! value, an encoding of it, or the bytes around it.

use std::collections::HashSet;

use base64::engine::general_purpose::{STANDARD_NO_PAD, URL_SAFE_NO_PAD};
use base64::Engine as _;
use formwork_blueprint::RefusalReason;
use formwork_compile::Capability;

use crate::egress::Refusal;
use crate::http::{percent_decoded, Head};
use crate::inspect::Broker;

/// **marker-min**: a shorter value matches unrelated content.
pub const MARKER_MIN: usize = 8;

/// A value the Gateway searches requests for, by name. `Debug` prints the name alone.
#[derive(Clone)]
pub struct Marker {
    name: String,
    value: Vec<u8>,
}

impl std::fmt::Debug for Marker {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Marker")
            .field("name", &self.name)
            .finish_non_exhaustive()
    }
}

impl Marker {
    /// The value of a variable the Launcher stripped (FW-CRED4), named `stripped:<variable>`;
    /// `None` below **marker-min**.
    pub fn stripped(variable: &str, value: &str) -> Option<Marker> {
        Marker::new(format!("stripped:{variable}"), value.as_bytes())
    }

    /// A brokered credential's secret (FW-CRED11), named `brokered:<credential>`; `None` below
    /// **marker-min**.
    pub fn brokered(broker: &Broker) -> Option<Marker> {
        Marker::new(
            format!("brokered:{}", broker.name),
            broker.secret.as_bytes(),
        )
    }

    fn new(name: String, value: &[u8]) -> Option<Marker> {
        (value.len() >= MARKER_MIN).then(|| Marker {
            name,
            value: value.to_vec(),
        })
    }

    pub fn name(&self) -> &str {
        &self.name
    }
}

/// The **marker-encodings** (FEP-12 §3.2): a closed set, so a record can name one and a reader
/// knows what was not searched for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Encoding {
    Raw,
    PercentUpper,
    PercentLower,
    HexLower,
    HexUpper,
    Json,
    /// Standard base64 of the value starting at this byte offset within a 3-byte group.
    Base64(usize),
    Base64Url(usize),
}

impl Encoding {
    pub(crate) const ALL: [Encoding; 12] = [
        Encoding::Raw,
        Encoding::PercentUpper,
        Encoding::PercentLower,
        Encoding::HexLower,
        Encoding::HexUpper,
        Encoding::Json,
        Encoding::Base64(0),
        Encoding::Base64(1),
        Encoding::Base64(2),
        Encoding::Base64Url(0),
        Encoding::Base64Url(1),
        Encoding::Base64Url(2),
    ];

    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Encoding::Raw => "raw",
            Encoding::PercentUpper => "percent-upper",
            Encoding::PercentLower => "percent-lower",
            Encoding::HexLower => "hex-lower",
            Encoding::HexUpper => "hex-upper",
            Encoding::Json => "json",
            Encoding::Base64(0) => "base64-0",
            Encoding::Base64(1) => "base64-1",
            Encoding::Base64(_) => "base64-2",
            Encoding::Base64Url(0) => "base64url-0",
            Encoding::Base64Url(1) => "base64url-1",
            Encoding::Base64Url(_) => "base64url-2",
        }
    }

    /// `value` as this encoding writes it inside a longer text. A base64 form keeps only the
    /// characters the value alone decides at its alignment: the ones that also carry bits of the
    /// neighbouring bytes differ with them.
    pub(crate) fn apply(self, value: &[u8]) -> Vec<u8> {
        let percent = |upper: bool| {
            let mut out = Vec::with_capacity(value.len() * 3);
            for &b in value {
                if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~') {
                    out.push(b);
                } else if upper {
                    out.extend_from_slice(format!("%{b:02X}").as_bytes());
                } else {
                    out.extend_from_slice(format!("%{b:02x}").as_bytes());
                }
            }
            out
        };
        let base64 = |engine: &base64::engine::GeneralPurpose, offset: usize| {
            let mut aligned = vec![0u8; offset];
            aligned.extend_from_slice(value);
            let text = engine.encode(&aligned).into_bytes();
            let first = (offset * 8).div_ceil(6);
            let end = aligned.len() * 8 / 6;
            text[first..end].to_vec()
        };
        match self {
            Encoding::Raw => value.to_vec(),
            Encoding::PercentUpper => percent(true),
            Encoding::PercentLower => percent(false),
            Encoding::HexLower => value
                .iter()
                .flat_map(|b| format!("{b:02x}").into_bytes())
                .collect(),
            Encoding::HexUpper => value
                .iter()
                .flat_map(|b| format!("{b:02X}").into_bytes())
                .collect(),
            Encoding::Json => std::str::from_utf8(value)
                .ok()
                .and_then(|s| serde_json::to_string(s).ok())
                .map(|quoted| quoted.as_bytes()[1..quoted.len() - 1].to_vec())
                .unwrap_or_else(|| value.to_vec()),
            Encoding::Base64(offset) => base64(&STANDARD_NO_PAD, offset),
            Encoding::Base64Url(offset) => base64(&URL_SAFE_NO_PAD, offset),
        }
    }
}

struct Pattern {
    bytes: Vec<u8>,
    marker: usize,
    encoding: Encoding,
}

/// What the search found: the marker's name and the encoding it was in.
#[derive(Clone, Debug)]
pub(crate) struct Found {
    pub(crate) marker: String,
    pub(crate) encoding: Encoding,
}

/// Every encoding of every marker, indexed by first byte: a position is compared only against
/// the patterns that begin with its byte. An encoding that spells the same bytes as an earlier
/// one is searched once, under the earlier name.
pub(crate) struct Search {
    names: Vec<String>,
    patterns: Vec<Pattern>,
    by_first: Vec<Vec<usize>>,
}

impl Search {
    pub(crate) fn new(markers: &[Marker]) -> Search {
        let mut seen: HashSet<Vec<u8>> = HashSet::new();
        let mut patterns = Vec::new();
        let mut by_first = vec![Vec::new(); 256];
        for (i, m) in markers.iter().enumerate() {
            for encoding in Encoding::ALL {
                let bytes = encoding.apply(&m.value);
                if bytes.is_empty() || !seen.insert(bytes.clone()) {
                    continue;
                }
                by_first[bytes[0] as usize].push(patterns.len());
                patterns.push(Pattern {
                    bytes,
                    marker: i,
                    encoding,
                });
            }
        }
        Search {
            names: markers.iter().map(|m| m.name.clone()).collect(),
            patterns,
            by_first,
        }
    }

    pub(crate) fn names(&self) -> &[String] {
        &self.names
    }

    pub(crate) fn find(&self, data: &[u8]) -> Option<Found> {
        if self.patterns.is_empty() {
            return None;
        }
        for (i, &b) in data.iter().enumerate() {
            for &p in &self.by_first[b as usize] {
                let pattern = &self.patterns[p];
                if data[i..].starts_with(&pattern.bytes) {
                    return Some(Found {
                        marker: self.names[pattern.marker].clone(),
                        encoding: pattern.encoding,
                    });
                }
            }
        }
        None
    }

    /// FW-EGR34: search the request line: the method, and the target as sent and with its
    /// percent-escapes decoded once, as an origin reads it (FW-CRED37). A CONNECT's other fields
    /// go nowhere, so its line is all that is searched.
    pub(crate) fn request_line(&self, head: &Head) -> Option<HeadMatch> {
        if self.patterns.is_empty() {
            return None;
        }
        let line = |found: Found, site: &str| HeadMatch {
            found,
            site: site.to_string(),
            in_request_line: true,
        };
        if let Some(f) = self.find(head.method.as_bytes()) {
            return Some(line(f, "the request method"));
        }
        if let Some(f) = self.find(head.target.as_bytes()) {
            return Some(line(f, "the request target"));
        }
        let decoded = percent_decoded(&head.target);
        if decoded != head.target {
            if let Some(f) = self.find(decoded.as_bytes()) {
                return Some(line(f, "the request target once its escapes are decoded"));
            }
        }
        None
    }

    /// FW-EGR34: search a request head where the session can write: its request line, then each
    /// header's name and value in order. A header is named in the result only once its name has
    /// been searched.
    pub(crate) fn head(&self, head: &Head) -> Option<HeadMatch> {
        if let Some(found) = self.request_line(head) {
            return Some(found);
        }
        for (name, value) in &head.headers {
            if let Some(found) = self.find(name.as_bytes()) {
                return Some(HeadMatch {
                    found,
                    site: "a header name".to_string(),
                    in_request_line: false,
                });
            }
            if let Some(found) = self.find(value.as_bytes()) {
                return Some(HeadMatch {
                    found,
                    site: format!("the {} header", name.to_ascii_lowercase()),
                    in_request_line: false,
                });
            }
        }
        None
    }
}

/// Where a head carried a marker. `in_request_line` says the method or target did, so neither
/// may enter a record.
pub(crate) struct HeadMatch {
    pub(crate) found: Found,
    pub(crate) site: String,
    pub(crate) in_request_line: bool,
}

impl HeadMatch {
    /// The `marker` refusal (FW-FID12): the marker by name, the encoding and the site, and never
    /// the request's method or path, which may be where the marker is.
    pub(crate) fn refusal(&self) -> Refusal {
        Refusal::new(
            RefusalReason::Marker,
            format!(
                "{} carries {} ({}), a value the session is never given (FW-EGR34)",
                self.site,
                self.found.marker,
                self.found.encoding.as_str()
            ),
        )
        .capability(Capability::NetInspection)
        .decided_by(format!("marker {}", self.found.marker))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn marker(value: &str) -> Marker {
        Marker::stripped("TEST_TOKEN", value).unwrap()
    }

    #[test]
    fn fw_egr33_a_value_below_marker_min_is_not_a_marker() {
        assert!(Marker::stripped("SHORT", "1234567").is_none());
        assert_eq!(marker("12345678").name(), "stripped:TEST_TOKEN");
        assert!(!format!("{:?}", marker("secret-value-1")).contains("secret-value-1"));
    }

    #[test]
    fn fw_egr34_every_encoding_is_found_at_every_alignment() {
        let value = b"ghp_Secret/Value+0123";
        let search = Search::new(&[marker(std::str::from_utf8(value).unwrap())]);
        let std = base64::engine::general_purpose::STANDARD;
        let url = base64::engine::general_purpose::URL_SAFE;
        for lead in 0..3 {
            let mut framed = b"pre:".to_vec();
            framed.extend(std::iter::repeat_n(b'x', lead));
            framed.extend_from_slice(value);
            framed.extend_from_slice(b":post");
            for engine in [&std, &url] {
                let text = engine.encode(&framed);
                assert!(
                    search.find(text.as_bytes()).is_some(),
                    "lead {lead}: {text}"
                );
            }
        }
        let hex: String = value.iter().map(|b| format!("{b:02x}")).collect();
        for text in [
            hex.clone(),
            hex.to_ascii_uppercase(),
            "ghp_Secret%2FValue%2B0123".to_string(),
            "ghp_Secret%2fValue%2b0123".to_string(),
        ] {
            assert!(
                search.find(format!("a={text};").as_bytes()).is_some(),
                "{text}"
            );
        }
        assert!(search.find(b"ghp_Secret/Value+012").is_none());
    }

    #[test]
    fn fw_egr34_json_escapes_are_found() {
        let search = Search::new(&[marker("quote\"back\\slash")]);
        assert!(search.find(br#"{"ua":"x quote\"back\\slash y"}"#).is_some());
    }
}
