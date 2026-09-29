//! Host-service channels (FW-ISO13, FW-BP9/BP10) and the isolation tier (FW-ISO10): the two FEP-5
//! blueprint fields whose values are portable names of what is granted, never of how a platform
//! implements it (FW-XR6). A channel is a host service that can act outside the sandbox on the
//! confined process's behalf; the baseline denies every one of them, and `channels` lifts by name.
//! Groups are exact enumerations expanded at the parse edge like a sigil (FW-BP5), so the merged
//! Blueprint carries only channel names.

use std::collections::BTreeSet;
use std::fmt;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// The closed channel enum. `os-keyring` is deliberately absent: it is a credential, lifted through
/// `allow-credentials` (FW-CRED13), never here.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Channel {
    /// A service that runs code outside the session: launchd job submission, AppleEvents, the
    /// session bus and `systemd --user`.
    RunOutside,
    /// Opening a web page in the user's browser -- brokered by the Gateway (FW-ISO17/ISO18), never
    /// a host-service lift.
    OpenUrl,
    /// Programmatic clipboard access (pasteboard services; X11/Wayland sockets).
    Clipboard,
    /// Screen capture services.
    Screen,
    Camera,
    Microphone,
}

impl Channel {
    pub const ALL: [Channel; 6] = [
        Channel::RunOutside,
        Channel::OpenUrl,
        Channel::Clipboard,
        Channel::Screen,
        Channel::Camera,
        Channel::Microphone,
    ];

    pub fn name(self) -> &'static str {
        match self {
            Channel::RunOutside => "run-outside",
            Channel::OpenUrl => "open-url",
            Channel::Clipboard => "clipboard",
            Channel::Screen => "screen",
            Channel::Camera => "camera",
            Channel::Microphone => "microphone",
        }
    }

    pub fn from_name(name: &str) -> Option<Channel> {
        Channel::ALL.into_iter().find(|c| c.name() == name)
    }

    /// The environment variables by which this channel's platform clients locate it (FW-BP11);
    /// stripped while the channel is denied, re-admitted when it is lifted.
    pub fn locator_vars(self) -> &'static [&'static str] {
        match self {
            Channel::RunOutside => &["DBUS_SESSION_BUS_ADDRESS"],
            Channel::Clipboard | Channel::Screen => &["DISPLAY", "WAYLAND_DISPLAY"],
            Channel::OpenUrl | Channel::Camera | Channel::Microphone => &[],
        }
    }
}

impl fmt::Display for Channel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// The fixed groups (FW-BP9): exact schema lists, never patterns (FW-CAP2). `run-outside` belongs
/// to no group and is lifted only by its own name.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChannelGroup {
    /// What an interactive login uses by hand; neither member runs code outside the sandbox.
    Desktop,
    /// The TCC-tier privacy set.
    Media,
}

impl ChannelGroup {
    pub fn name(self) -> &'static str {
        match self {
            ChannelGroup::Desktop => "desktop",
            ChannelGroup::Media => "media",
        }
    }

    pub fn from_name(name: &str) -> Option<ChannelGroup> {
        match name {
            "desktop" => Some(ChannelGroup::Desktop),
            "media" => Some(ChannelGroup::Media),
            _ => None,
        }
    }

    pub fn members(self) -> &'static [Channel] {
        match self {
            ChannelGroup::Desktop => &[Channel::Clipboard, Channel::OpenUrl],
            ChannelGroup::Media => &[Channel::Screen, Channel::Camera, Channel::Microphone],
        }
    }
}

/// Every name the `channels` field accepts, for the parse error that lists them.
pub fn valid_channel_names() -> Vec<&'static str> {
    Channel::ALL
        .iter()
        .map(|c| c.name())
        .chain([ChannelGroup::Desktop.name(), ChannelGroup::Media.name()])
        .collect()
}

/// A channel or group name that is not in the schema. Fail-loud at parse (FW-INV6), listing the
/// valid names (the `deny_unknown_fields` discipline applied to a value).
#[derive(Debug, thiserror::Error)]
#[error("unknown channel {name:?} (valid: {valid})")]
pub struct ChannelError {
    pub name: String,
    pub valid: String,
}

fn expand_names(names: &[String]) -> Result<BTreeSet<Channel>, ChannelError> {
    let mut out = BTreeSet::new();
    for name in names {
        if let Some(c) = Channel::from_name(name) {
            out.insert(c);
        } else if let Some(g) = ChannelGroup::from_name(name) {
            out.extend(g.members().iter().copied());
        } else {
            return Err(ChannelError {
                name: name.clone(),
                valid: valid_channel_names().join(", "),
            });
        }
    }
    Ok(out)
}

/// The channel policy (FW-BP9): an `allow` scope and a terminal `deny` list, the shape of the MCP
/// policy tables (FW-GW9). `"deny"` is the default posture -- an empty allow scope -- not a
/// terminal list (FW-BP10). Authoring forms: `"deny"`, `["clipboard"]` (sugar for `{ allow }`),
/// `{ allow = [...] }`, `{ allow = [...], deny = [...] }`, `{ deny = [...] }`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ChannelPolicy {
    allow: BTreeSet<Channel>,
    deny: BTreeSet<Channel>,
}

impl ChannelPolicy {
    pub fn allow<I: IntoIterator<Item = Channel>>(channels: I) -> ChannelPolicy {
        ChannelPolicy {
            allow: channels.into_iter().collect(),
            deny: BTreeSet::new(),
        }
    }

    pub fn with_deny<I: IntoIterator<Item = Channel>>(mut self, channels: I) -> ChannelPolicy {
        self.deny.extend(channels);
        self
    }

    /// Parse authoring names (channels and groups) into a policy; groups expand here.
    pub fn parse(allow: &[String], deny: &[String]) -> Result<ChannelPolicy, ChannelError> {
        Ok(ChannelPolicy {
            allow: expand_names(allow)?,
            deny: expand_names(deny)?,
        })
    }

    /// A channel is lifted iff the allow scope names it and no deny names it -- deny is terminal
    /// from any layer (FW-BP10).
    pub fn lifted(&self, channel: Channel) -> bool {
        self.allow.contains(&channel) && !self.deny.contains(&channel)
    }

    pub fn lifted_channels(&self) -> Vec<Channel> {
        Channel::ALL
            .into_iter()
            .filter(|c| self.lifted(*c))
            .collect()
    }

    pub fn allowed(&self) -> &BTreeSet<Channel> {
        &self.allow
    }

    pub fn denied(&self) -> &BTreeSet<Channel> {
        &self.deny
    }

    /// Layer fold (FW-BP10): allow scopes union, deny entries accumulate (terminal).
    pub fn merge_from(&mut self, other: &ChannelPolicy) {
        self.allow.extend(other.allow.iter().copied());
        self.deny.extend(other.deny.iter().copied());
    }

    /// The locator variables every lifted channel's clients need (FW-BP11), and the ones stripped
    /// because their channel stays denied.
    pub fn locator_vars(&self) -> (Vec<&'static str>, Vec<&'static str>) {
        let mut admitted = BTreeSet::new();
        let mut stripped = BTreeSet::new();
        for c in Channel::ALL {
            for var in c.locator_vars() {
                if self.lifted(c) {
                    admitted.insert(*var);
                } else {
                    stripped.insert(*var);
                }
            }
        }
        // A variable shared by a lifted and a denied channel is admitted: the lifted channel's
        // client needs it, and the socket behind it stays closed for the denied channel by the
        // channel mechanism, not by hiding the variable (D5).
        let stripped: Vec<_> = stripped.difference(&admitted).copied().collect();
        (admitted.into_iter().collect(), stripped)
    }
}

/// The serde surface: a keyword, a bare list (sugar for `allow`), or an `{ allow, deny }` table.
#[derive(Serialize)]
#[serde(untagged)]
enum ChannelRepr {
    Keyword(ChannelKeyword),
    List(Vec<String>),
    Table(ChannelTable),
}

#[derive(Serialize)]
#[serde(rename_all = "kebab-case")]
enum ChannelKeyword {
    Deny,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ChannelTable {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    allow: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    deny: Vec<String>,
}

impl Serialize for ChannelPolicy {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let names = |set: &BTreeSet<Channel>| -> Vec<String> {
            set.iter().map(|c| c.name().to_string()).collect()
        };
        let repr = if self.allow.is_empty() && self.deny.is_empty() {
            ChannelRepr::Keyword(ChannelKeyword::Deny)
        } else if self.deny.is_empty() {
            ChannelRepr::List(names(&self.allow))
        } else {
            ChannelRepr::Table(ChannelTable {
                allow: names(&self.allow),
                deny: names(&self.deny),
            })
        };
        repr.serialize(serializer)
    }
}

// A hand-written visitor rather than an untagged enum, so a wrong shape or an unknown table key
// keeps its own message instead of serde's "did not match any variant".
impl<'de> Deserialize<'de> for ChannelPolicy {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct Visitor;
        impl<'de> serde::de::Visitor<'de> for Visitor {
            type Value = ChannelPolicy;

            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str(
                    r#""deny", a list of channel names, or { allow = [...], deny = [...] }"#,
                )
            }

            fn visit_str<E: serde::de::Error>(self, v: &str) -> Result<ChannelPolicy, E> {
                if v == "deny" {
                    return Ok(ChannelPolicy::default());
                }
                Err(E::custom(format!(
                    r#"channels = "{v}": the only keyword is "deny"; to lift a channel, list it: ["{v}"]"#
                )))
            }

            fn visit_seq<A: serde::de::SeqAccess<'de>>(
                self,
                seq: A,
            ) -> Result<ChannelPolicy, A::Error> {
                let names =
                    Vec::<String>::deserialize(serde::de::value::SeqAccessDeserializer::new(seq))?;
                ChannelPolicy::parse(&names, &[]).map_err(serde::de::Error::custom)
            }

            fn visit_map<A: serde::de::MapAccess<'de>>(
                self,
                map: A,
            ) -> Result<ChannelPolicy, A::Error> {
                let t =
                    ChannelTable::deserialize(serde::de::value::MapAccessDeserializer::new(map))?;
                ChannelPolicy::parse(&t.allow, &t.deny).map_err(serde::de::Error::custom)
            }
        }
        deserializer.deserialize_any(Visitor)
    }
}

/// The opt-in isolation tier's members (FW-ISO10): portable names, mapped per backend.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum IsolateMember {
    /// Other processes are not visible, signalable or inspectable, including their arguments.
    Processes,
    /// SysV and POSIX IPC confined to the session.
    Ipc,
}

impl IsolateMember {
    pub fn name(self) -> &'static str {
        match self {
            IsolateMember::Processes => "processes",
            IsolateMember::Ipc => "ipc",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(toml_value: &str) -> Result<ChannelPolicy, toml::de::Error> {
        #[derive(Deserialize)]
        struct Wrap {
            channels: ChannelPolicy,
        }
        toml::from_str::<Wrap>(&format!("channels = {toml_value}\n")).map(|w| w.channels)
    }

    #[test]
    fn keyword_list_and_table_forms_parse() {
        assert_eq!(parse(r#""deny""#).unwrap(), ChannelPolicy::default());
        assert_eq!(
            parse(r#"["clipboard"]"#).unwrap(),
            ChannelPolicy::allow([Channel::Clipboard])
        );
        assert_eq!(
            parse(r#"{ allow = ["desktop"] }"#).unwrap(),
            ChannelPolicy::allow([Channel::Clipboard, Channel::OpenUrl])
        );
        let p = parse(r#"{ allow = ["desktop"], deny = ["screen"] }"#).unwrap();
        assert!(p.lifted(Channel::Clipboard));
        assert!(!p.lifted(Channel::Screen));
    }

    #[test]
    fn wrong_shapes_keep_their_own_message() {
        let bare = parse(r#""clipboard""#).unwrap_err().to_string();
        assert!(bare.contains(r#"["clipboard"]"#), "{bare}");
        let typo = parse(r#"{ alow = ["clipboard"] }"#)
            .unwrap_err()
            .to_string();
        assert!(typo.contains("alow"), "{typo}");
    }

    #[test]
    fn groups_expand_at_the_parse_edge_and_run_outside_is_in_none() {
        let media = parse(r#"["media"]"#).unwrap();
        assert!(media.lifted(Channel::Screen));
        assert!(media.lifted(Channel::Camera));
        assert!(media.lifted(Channel::Microphone));
        assert!(!media.lifted(Channel::RunOutside));
        let desktop = parse(r#"["desktop"]"#).unwrap();
        assert!(!desktop.lifted(Channel::RunOutside));
        assert!(!desktop.lifted(Channel::Screen));
    }

    #[test]
    fn unknown_name_fails_loud_listing_valid_names() {
        let err = parse(r#"{ allow = ["desk"] }"#).unwrap_err().to_string();
        assert!(err.contains("desk"), "{err}");
        assert!(
            err.contains("clipboard") && err.contains("desktop"),
            "{err}"
        );
    }

    #[test]
    fn deny_is_terminal_across_layers_and_the_keyword_is_a_posture() {
        // A base "deny" is an empty allow scope: a downstream allow still lifts (FW-BP10)...
        let mut base = parse(r#""deny""#).unwrap();
        base.merge_from(&parse(r#"["clipboard"]"#).unwrap());
        assert!(base.lifted(Channel::Clipboard));
        // ...while a deny entry from any layer is terminal.
        let mut team = parse(r#"["desktop"]"#).unwrap();
        team.merge_from(&parse(r#"{ deny = ["desktop"] }"#).unwrap());
        assert!(!team.lifted(Channel::Clipboard));
        assert!(!team.lifted(Channel::OpenUrl));
    }

    #[test]
    fn locator_vars_follow_the_lift() {
        let (admitted, stripped) = ChannelPolicy::default().locator_vars();
        assert!(admitted.is_empty());
        assert!(stripped.contains(&"DISPLAY") && stripped.contains(&"DBUS_SESSION_BUS_ADDRESS"));
        let (admitted, stripped) = parse(r#"["desktop"]"#).unwrap().locator_vars();
        assert!(admitted.contains(&"DISPLAY") && admitted.contains(&"WAYLAND_DISPLAY"));
        assert!(stripped.contains(&"DBUS_SESSION_BUS_ADDRESS"));
        assert!(!stripped.contains(&"DISPLAY"));
    }

    #[test]
    fn round_trips_through_serde() {
        for src in [
            r#""deny""#,
            r#"["clipboard", "open-url"]"#,
            r#"{ allow = ["clipboard"], deny = ["screen"] }"#,
        ] {
            let p = parse(src).unwrap();
            let json = serde_json::to_string(&p).unwrap();
            let back: ChannelPolicy = serde_json::from_str(&json).unwrap();
            assert_eq!(p, back, "{src}");
        }
    }
}
