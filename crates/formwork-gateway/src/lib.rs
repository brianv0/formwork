//! The gateway: an MCP-aware policy proxy between a confined agent and one backend. Its shading is
//! binding only because the confiner beneath leaves the agent no other door to the backend -- no
//! network, no filesystem past the injected fd (FW-GW4). Refusals are oracle-free by construction
//! (FW-ADV-004): a hidden-but-real name and a nonexistent one take the same local path and yield the
//! same error, so nothing tells "blocked" from "absent". A backend frame is filtered by its shape --
//! a `result` carrying a list array -- and never by matching it to a request (FW-GW15), so a runtime
//! `list_changed` re-filters for free. Frames parse once, at this edge, into typed structures that
//! refuse a repeated key (FW-GW17). Granted traffic forwards as the exact bytes received (FW-GW8);
//! any `AsyncRead`/`AsyncWrite` pair works, so an http/sse backend needs only a framing adapter.

use std::collections::HashSet;
use std::fmt;
use std::io;
use std::marker::PhantomData;
use std::sync::Arc;

use serde::de::value::MapAccessDeserializer;
use serde::de::{Deserializer, IgnoredAny, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::sync::Mutex;

use formwork_blueprint::{Gate, McpPolicy, Visibility};
use formwork_compile::CompiledPolicy;

pub mod ca;
pub mod egress;
mod http;
mod inspect;
pub mod opener;
mod upstream;

pub use ca::{native_roots, native_roots_source, SessionCa};
pub use egress::{Admission, EgressConfig, EgressProxy, Grant, PeerCheck, Resolver, Violation};
pub use inspect::{Broker, Inspection, PLACEHOLDER_PREFIX};
pub use opener::{OpenRecord, OpenerService};
pub use upstream::{ProxyEndpoint, UpstreamProxy};

// Bounds a single frame so a peer that never sends a newline can't make the gateway buffer without
// limit; overflow closes the connection. A stability bound (design §3), not a DoS-resistance claim.
const MAX_FRAME_BYTES: usize = 16 * 1024 * 1024;

// Bounds the ids FW-GW16 remembers, so a backend that never answers can't make the set grow without
// limit; a request beyond it is refused. A stability bound like the one above.
const MAX_IN_FLIGHT_REQUESTS: usize = 1 << 16;

#[derive(Debug, thiserror::Error)]
pub enum GatewayError {
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error("confining a backend failed: {0}")]
    Confine(#[from] formwork_confine::ConfineError),
}

/// A JSON-RPC request id: a string, or a number spelled as an integer. Two ids are the same id iff
/// they are equal here, which is equality by JSON value (FW-GW16).
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize)]
#[serde(untagged)]
enum RequestId {
    Str(String),
    /// Wide enough for both the `i64` and the `u64` range, which is all the parser yields.
    Int(i128),
}

/// What a frame's `id` key held.
#[derive(Debug, PartialEq)]
enum Id {
    /// Missing or `null`: the frame is a notification.
    Absent,
    Valid(RequestId),
    /// Any other JSON value. serde_json reports a number with a fraction or an exponent, `-0`, and
    /// an integer outside the 64-bit range all as a float, so each lands here: `1`, `1.0` and `1e0`
    /// can never be held as distinct ids (FW-GW16).
    Invalid,
}

impl Id {
    fn valid(&self) -> Option<&RequestId> {
        match self {
            Id::Valid(id) => Some(id),
            Id::Absent | Id::Invalid => None,
        }
    }
}

impl From<Leaf> for Id {
    fn from(leaf: Leaf) -> Id {
        match leaf {
            Shape::Null => Id::Absent,
            Shape::Str(s) => Id::Valid(RequestId::Str(s)),
            Shape::Int(n) => Id::Valid(RequestId::Int(n)),
            Shape::Object(_) | Shape::Array | Shape::Other => Id::Invalid,
        }
    }
}

/// A JSON value at a position the gateway reads, kept only as far as it is read. An object goes
/// through `T`'s derived `Deserialize`, which refuses a repeated field (FW-GW17). An array is never
/// offered to `T`: a derived struct would read it positionally, and decide on a field the peer
/// never named.
#[derive(Default)]
enum Shape<T> {
    #[default]
    Null,
    Str(String),
    Int(i128),
    Object(T),
    Array,
    Other,
}

/// A position where the gateway reads a string or an id, and nothing inside an object.
type Leaf = Shape<IgnoredAny>;

impl<T> Shape<T> {
    fn into_string(self) -> String {
        match self {
            Shape::Str(s) => s,
            _ => String::new(),
        }
    }

    fn into_object(self) -> Option<T> {
        match self {
            Shape::Object(object) => Some(object),
            _ => None,
        }
    }
}

impl<'de, T: Deserialize<'de>> Deserialize<'de> for Shape<T> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct ShapeVisitor<T>(PhantomData<T>);

        impl<'de, T: Deserialize<'de>> Visitor<'de> for ShapeVisitor<T> {
            type Value = Shape<T>;

            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("any JSON value")
            }
            fn visit_unit<E>(self) -> Result<Self::Value, E> {
                Ok(Shape::Null)
            }
            fn visit_bool<E>(self, _: bool) -> Result<Self::Value, E> {
                Ok(Shape::Other)
            }
            fn visit_f64<E>(self, _: f64) -> Result<Self::Value, E> {
                Ok(Shape::Other)
            }
            fn visit_i64<E>(self, n: i64) -> Result<Self::Value, E> {
                Ok(Shape::Int(n.into()))
            }
            fn visit_u64<E>(self, n: u64) -> Result<Self::Value, E> {
                Ok(Shape::Int(n.into()))
            }
            fn visit_str<E>(self, s: &str) -> Result<Self::Value, E> {
                Ok(Shape::Str(s.to_owned()))
            }
            fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
                while seq.next_element::<IgnoredAny>()?.is_some() {}
                Ok(Shape::Array)
            }
            fn visit_map<A: MapAccess<'de>>(self, map: A) -> Result<Self::Value, A::Error> {
                T::deserialize(MapAccessDeserializer::new(map)).map(Shape::Object)
            }
        }

        deserializer.deserialize_any(ShapeVisitor(PhantomData))
    }
}

/// The JSON-RPC envelope. Unknown keys are accepted and forwarded; a repeat of a key named here is
/// a parse error (FW-GW17), since a peer that keeps the first occurrence would act on a frame the
/// gateway did not decide on.
#[derive(Deserialize)]
struct Envelope {
    // Named only so that a repeat is refused.
    #[serde(rename = "jsonrpc")]
    _jsonrpc: Option<IgnoredAny>,
    #[serde(rename = "error")]
    _error: Option<IgnoredAny>,
    #[serde(default)]
    id: Leaf,
    #[serde(default)]
    method: Leaf,
    #[serde(default)]
    params: Shape<Params>,
    #[serde(default)]
    result: Shape<Lists>,
}

/// The parameters the gateway decides on, whichever method carries them.
#[derive(Default, Deserialize)]
struct Params {
    #[serde(default)]
    name: Leaf,
    #[serde(default)]
    uri: Leaf,
    #[serde(default, rename = "ref")]
    reference: Shape<Reference>,
}

/// A `completion/complete` reference.
#[derive(Deserialize)]
struct Reference {
    #[serde(default, rename = "type")]
    kind: Leaf,
    #[serde(default)]
    name: Leaf,
    #[serde(default)]
    uri: Leaf,
}

/// The keys of a `result` that make it a list (FW-GW15).
#[derive(Deserialize)]
struct Lists {
    #[serde(default)]
    tools: Leaf,
    #[serde(default)]
    resources: Leaf,
    #[serde(default, rename = "resourceTemplates")]
    resource_templates: Leaf,
    #[serde(default)]
    prompts: Leaf,
}

impl Lists {
    fn any(&self) -> bool {
        [
            &self.tools,
            &self.resources,
            &self.resource_templates,
            &self.prompts,
        ]
        .iter()
        .any(|list| matches!(list, Shape::Array))
    }
}

/// The `id` of a frame the typed parse refused, read without the repeat check so that the refusal
/// has an addressee. A repeated `id` names no one.
struct IdProbe(Id);

impl<'de> Deserialize<'de> for IdProbe {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct ProbeVisitor;

        impl<'de> Visitor<'de> for ProbeVisitor {
            type Value = IdProbe;

            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("a JSON object")
            }
            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
                let mut found = None;
                while let Some(key) = map.next_key::<String>()? {
                    if key == "id" {
                        let id = Id::from(map.next_value::<Leaf>()?);
                        found = Some(if found.is_some() { Id::Invalid } else { id });
                    } else {
                        map.next_value::<IgnoredAny>()?;
                    }
                }
                Ok(IdProbe(found.unwrap_or(Id::Absent)))
            }
        }

        deserializer.deserialize_map(ProbeVisitor)
    }
}

/// One JSON-RPC frame reduced to what the gateway routes on. `raw` is the exact received bytes, kept
/// so granted traffic forwards byte-for-byte (FW-GW8) with no re-serialization. [`Frame::parse`]
/// classifies each frame so the pumps route on the variant, never on `Value`; the one other place raw
/// JSON is parsed is `filter_lists`, which prunes ungranted items from list responses.
enum Frame {
    /// A JSON object. With a `method` it is a request (it carries an id) or a notification;
    /// without one it is a response. `listing` holds when its `result` carries a list array.
    Message {
        id: Id,
        method: Option<Method>,
        listing: bool,
        raw: Vec<u8>,
    },
    /// A JSON-RPC batch array. MCP 2025-06-18 removed batching, and a batch would carry gated
    /// calls past per-frame policy, so it is refused whole (D6).
    Batch,
    /// A frame that repeats a key the gateway reads (FW-GW17). It is never forwarded.
    Ambiguous { id: Id },
    /// Not JSON at all. From the agent it closes the connection (D6); from a backend it forwards,
    /// since backend output is not a door into anything.
    NotJson(Vec<u8>),
    /// JSON that is neither an object nor an array.
    Passthrough(Vec<u8>),
}

enum Method {
    /// Names an item on a shaded axis (FW-GW2, FW-GW3). Policy applies with or without an `id`: a
    /// refused notification has no one to answer, so it is dropped (D6, FW-ADV-016).
    Gated {
        axis: Axis,
        target: String,
    },
    Sampling,
    Elicitation,
    Other,
}

#[derive(Clone, Copy)]
enum Axis {
    Tool,
    Resource,
    Prompt,
    /// A reference no grant can name (a malformed `completion/complete` ref): always refused.
    Unknown,
}

impl Axis {
    fn permits(self, policy: &McpPolicy, target: &str) -> bool {
        match self {
            Axis::Tool => policy.tools.permits(target),
            Axis::Resource => policy.resources.permits(target),
            Axis::Prompt => policy.prompts.permits(target),
            Axis::Unknown => false,
        }
    }

    /// The error code, audit label and message of a refusal on this axis. Each is what a genuine
    /// absence yields (-32002 is MCP's "resource not found"), so a refusal is not an oracle
    /// (FW-ADV-004).
    fn refusal(self, target: &str) -> (i64, &'static str, String) {
        match self {
            Axis::Tool => (-32602, "tool", format!("Unknown tool: {target}")),
            Axis::Resource => (-32002, "resource", format!("Resource not found: {target}")),
            Axis::Prompt => (-32602, "prompt", format!("Unknown prompt: {target}")),
            Axis::Unknown => (
                -32602,
                "completion",
                "Invalid completion reference".to_string(),
            ),
        }
    }
}

impl Method {
    fn classify(method: &str, params: Shape<Params>) -> Method {
        let params = params.into_object().unwrap_or_default();
        let gated = |axis, target: Leaf| Method::Gated {
            axis,
            target: target.into_string(),
        };
        match method {
            "tools/call" => gated(Axis::Tool, params.name),
            "prompts/get" => gated(Axis::Prompt, params.name),
            // Subscribing is gated by `uri` exactly like reading, so an ungranted uri cannot be
            // subscribed (FW-GW3/FW-INV4).
            "resources/read" | "resources/subscribe" | "resources/unsubscribe" => {
                gated(Axis::Resource, params.uri)
            }
            // Gated on the referenced item: a `ref/prompt` on the prompt axis by `name`, a
            // `ref/resource` on the resource axis by `uri`.
            "completion/complete" => match params.reference.into_object() {
                Some(reference) => match reference.kind.into_string().as_str() {
                    "ref/prompt" => gated(Axis::Prompt, reference.name),
                    "ref/resource" => gated(Axis::Resource, reference.uri),
                    _ => gated(Axis::Unknown, Shape::Null),
                },
                None => gated(Axis::Unknown, Shape::Null),
            },
            "sampling/createMessage" => Method::Sampling,
            "elicitation/create" => Method::Elicitation,
            _ => Method::Other,
        }
    }
}

impl Frame {
    fn parse(raw: Vec<u8>) -> Frame {
        // serde_json does not check the encoding of a value it skips, and a peer that repairs bad
        // UTF-8 could read a different structure out of the same bytes.
        let Ok(text) = std::str::from_utf8(&raw) else {
            return Frame::NotJson(raw);
        };
        match serde_json::from_str::<Shape<Envelope>>(text) {
            Ok(Shape::Object(envelope)) => {
                let method = match envelope.method {
                    Shape::Str(method) => Some(Method::classify(&method, envelope.params)),
                    _ => None,
                };
                Frame::Message {
                    id: envelope.id.into(),
                    method,
                    listing: envelope.result.into_object().is_some_and(|l| l.any()),
                    raw,
                }
            }
            Ok(Shape::Array) => Frame::Batch,
            Ok(_) => Frame::Passthrough(raw),
            // The typed structures refuse nothing but a repeated key, so a data error from
            // well-formed JSON is one (FW-GW17). The probe re-reads the frame to its end, which
            // separates that from a frame that is also malformed further on.
            Err(e) if e.is_data() => match serde_json::from_str::<IdProbe>(text) {
                Ok(IdProbe(id)) => Frame::Ambiguous { id },
                Err(_) => Frame::NotJson(raw),
            },
            Err(_) => Frame::NotJson(raw),
        }
    }
}

/// The gateway for a single agent<->backend connection, applying one server's [`McpPolicy`].
pub struct Gateway {
    policy: McpPolicy,
}

/// The ids of agent requests forwarded to the backend and not yet answered (FW-GW16).
type InFlight = Arc<Mutex<HashSet<RequestId>>>;

impl Gateway {
    pub fn new(policy: McpPolicy) -> Self {
        Gateway { policy }
    }

    #[tracing::instrument(name = "gateway.run", skip_all)]
    pub async fn run<AR, AW, BR, BW>(
        &self,
        agent_read: AR,
        agent_write: AW,
        backend_read: BR,
        backend_write: BW,
    ) -> Result<(), GatewayError>
    where
        AR: AsyncRead + Unpin,
        AW: AsyncWrite + Unpin,
        BR: AsyncRead + Unpin,
        BW: AsyncWrite + Unpin,
    {
        let agent_w = Arc::new(Mutex::new(agent_write));
        let backend_w = Arc::new(Mutex::new(backend_write));
        let in_flight: InFlight = Arc::new(Mutex::new(HashSet::new()));

        let a2b = pump_agent_to_backend(
            agent_read,
            agent_w.clone(),
            backend_w.clone(),
            in_flight.clone(),
            &self.policy,
        );
        let b2a = pump_backend_to_agent(
            backend_read,
            agent_w.clone(),
            backend_w.clone(),
            in_flight.clone(),
            &self.policy,
        );

        // Whichever direction closes first cancels the other, so a one-sided hangup tears the
        // connection down instead of leaving the opposite pump blocked forever (fail-closed).
        tokio::select! {
            r = a2b => r?,
            r = b2a => r?,
        }
        Ok(())
    }
}

/// What the gateway does with an agent request that carries a usable id.
enum Decision {
    Forward,
    IdInFlight,
    Ungranted(Axis, String),
    TooManyInFlight,
}

async fn pump_agent_to_backend<AR, AW, BW>(
    reader: AR,
    agent_w: Arc<Mutex<AW>>,
    backend_w: Arc<Mutex<BW>>,
    in_flight: InFlight,
    policy: &McpPolicy,
) -> io::Result<()>
where
    AR: AsyncRead + Unpin,
    AW: AsyncWrite + Unpin,
    BW: AsyncWrite + Unpin,
{
    let mut reader = BufReader::new(reader);
    while let Some(raw) = read_frame(&mut reader, MAX_FRAME_BYTES).await? {
        match Frame::parse(raw) {
            Frame::Message {
                id: Id::Invalid,
                method: Some(_),
                ..
            } => {
                invalid_request(&agent_w, None, "the id is neither a string nor an integer")
                    .await?;
            }
            Frame::Message {
                id: Id::Valid(id),
                method: Some(method),
                raw,
                ..
            } => {
                let decision = {
                    let mut in_flight = in_flight.lock().await;
                    // The id is checked before policy, so this refusal says nothing about the
                    // target. The id is recorded before the frame is written: a reply could
                    // otherwise arrive first and leave the id held for good.
                    if in_flight.contains(&id) {
                        Decision::IdInFlight
                    } else {
                        match method {
                            Method::Gated { axis, target } if !axis.permits(policy, &target) => {
                                Decision::Ungranted(axis, target)
                            }
                            _ if in_flight.len() >= MAX_IN_FLIGHT_REQUESTS => {
                                Decision::TooManyInFlight
                            }
                            _ => {
                                in_flight.insert(id.clone());
                                Decision::Forward
                            }
                        }
                    }
                };
                match decision {
                    Decision::Forward => write_frame(&backend_w, &raw).await?,
                    Decision::IdInFlight => {
                        invalid_request(
                            &agent_w,
                            Some(&id),
                            "the id belongs to a request not yet answered",
                        )
                        .await?;
                    }
                    Decision::Ungranted(axis, target) => {
                        refuse(&agent_w, &id, axis, &target).await?;
                    }
                    Decision::TooManyInFlight => {
                        invalid_request(&agent_w, Some(&id), "too many requests not yet answered")
                            .await?;
                    }
                }
            }
            Frame::Message {
                id: Id::Absent,
                method: Some(Method::Gated { axis, target }),
                raw,
                ..
            } => {
                if axis.permits(policy, &target) {
                    write_frame(&backend_w, &raw).await?;
                } else {
                    tracing::info!(target = %target, "gateway dropped an id-less call to an ungranted item");
                }
            }
            Frame::Message { raw, .. } | Frame::Passthrough(raw) => {
                write_frame(&backend_w, &raw).await?;
            }
            Frame::Batch => {
                tracing::info!("gateway refused a JSON-RPC batch array");
                write_frame(&agent_w, error(None, -32600, "Invalid Request").as_bytes()).await?;
            }
            Frame::Ambiguous { id: Id::Absent } => {
                tracing::info!("gateway dropped an id-less frame that repeats a key");
            }
            Frame::Ambiguous { id } => {
                invalid_request(&agent_w, id.valid(), "the frame repeats a key").await?;
            }
            Frame::NotJson(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "agent sent a frame that is not JSON; closing the connection (fail-closed)",
                ));
            }
        }
    }
    Ok(())
}

async fn pump_backend_to_agent<BR, AW, BW>(
    reader: BR,
    agent_w: Arc<Mutex<AW>>,
    backend_w: Arc<Mutex<BW>>,
    in_flight: InFlight,
    policy: &McpPolicy,
) -> io::Result<()>
where
    BR: AsyncRead + Unpin,
    AW: AsyncWrite + Unpin,
    BW: AsyncWrite + Unpin,
{
    let mut reader = BufReader::new(reader);
    while let Some(raw) = read_frame(&mut reader, MAX_FRAME_BYTES).await? {
        match Frame::parse(raw) {
            Frame::Message {
                id: id @ (Id::Valid(_) | Id::Invalid),
                method: Some(Method::Sampling),
                ..
            } if policy.sampling != Gate::Allow => {
                police(&backend_w, id.valid(), "sampling/createMessage").await?;
            }
            Frame::Message {
                id: id @ (Id::Valid(_) | Id::Invalid),
                method: Some(Method::Elicitation),
                ..
            } if policy.elicitation != Gate::Allow => {
                police(&backend_w, id.valid(), "elicitation/create").await?;
            }
            Frame::Message {
                id,
                method,
                listing,
                raw,
            } => {
                // FW-GW15: decided by what the frame is, never by which request it answers.
                let frame = if listing {
                    match filter_lists(&raw, policy) {
                        Ok(filtered) => filtered.into_bytes(),
                        Err(error) => {
                            tracing::warn!(%error, "gateway dropped a list response it could not filter");
                            continue;
                        }
                    }
                } else {
                    raw
                };
                // Released before the write, so an agent that reuses the id on reading the
                // answer is never refused.
                if let (None, Some(id)) = (&method, id.valid()) {
                    in_flight.lock().await.remove(id);
                }
                write_frame(&agent_w, &frame).await?;
            }
            Frame::Batch => {
                tracing::warn!("gateway dropped a JSON-RPC batch array from the backend");
            }
            Frame::Ambiguous { .. } => {
                tracing::warn!("gateway dropped a backend frame that repeats a key");
            }
            Frame::NotJson(raw) | Frame::Passthrough(raw) => write_frame(&agent_w, &raw).await?,
        }
    }
    Ok(())
}

/// Read one newline-delimited frame (newline consumed, not returned), bounded to `max` bytes.
/// `Ok(None)` is a clean EOF; exceeding `max` before a newline is a fail-closed `InvalidData` error.
async fn read_frame<R: AsyncBufRead + Unpin>(
    reader: &mut R,
    max: usize,
) -> io::Result<Option<Vec<u8>>> {
    let mut buf: Vec<u8> = Vec::new();
    loop {
        let (consumed, done) = {
            let chunk = reader.fill_buf().await?;
            if chunk.is_empty() {
                return Ok(if buf.is_empty() { None } else { Some(buf) });
            }
            match chunk.iter().position(|&b| b == b'\n') {
                Some(nl) => {
                    buf.extend_from_slice(&chunk[..nl]);
                    (nl + 1, true)
                }
                None => {
                    buf.extend_from_slice(chunk);
                    (chunk.len(), false)
                }
            }
        };
        reader.consume(consumed);
        if done {
            return Ok(Some(buf));
        }
        if buf.len() > max {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "MCP frame exceeded the maximum size; closing connection (fail-closed)",
            ));
        }
    }
}

/// Drop ungranted items from every list a `result` carries, re-serializing (FW-GW15). Each list is
/// filtered by its own axis; every other field, `nextCursor` included, is kept. An item missing its
/// identifier is dropped (fail-closed). Item identity per design §4: tools/prompts by `name`,
/// resources by `uri`, resource templates by `uriTemplate`.
fn filter_lists(raw: &[u8], policy: &McpPolicy) -> serde_json::Result<String> {
    let mut value: Value = serde_json::from_slice(raw)?;
    let lists: [(&str, &str, &Visibility); 4] = [
        ("tools", "name", &policy.tools),
        ("resources", "uri", &policy.resources),
        ("resourceTemplates", "uriTemplate", &policy.resources),
        ("prompts", "name", &policy.prompts),
    ];
    for (field, id_field, vis) in lists {
        let Some(items) = value
            .get_mut("result")
            .and_then(|result| result.get_mut(field))
            .and_then(Value::as_array_mut)
        else {
            continue;
        };
        let before = items.len();
        items.retain(|item| {
            item.get(id_field)
                .and_then(Value::as_str)
                .map(|n| vis.permits(n))
                .unwrap_or(false)
        });
        let hidden = before - items.len();
        if hidden > 0 {
            tracing::debug!(field, hidden, "gateway shaded list response");
        }
    }
    Ok(value.to_string())
}

/// Refuse an ungranted client request. Records the target for the operator's audit trail (FW-FID3),
/// but the bytes returned to the agent carry only the message -- which is identical for a hidden-real
/// and a nonexistent item, so the log is not an oracle the agent can observe (FW-ADV-004).
async fn refuse<W: AsyncWrite + Unpin>(
    agent_w: &Arc<Mutex<W>>,
    id: &RequestId,
    axis: Axis,
    target: &str,
) -> io::Result<()> {
    let (code, item, message) = axis.refusal(target);
    tracing::info!(item, target, "gateway refused ungranted MCP item");
    write_frame(agent_w, error(Some(id), code, &message).as_bytes()).await
}

/// Refuse an agent frame for its envelope alone (FW-GW16, FW-GW17). `reason` depends on the frame
/// and on the agent's own unanswered requests, never on policy or on the backend, so the agent
/// learns nothing from it about what is hidden (FW-ADV-004).
async fn invalid_request<W: AsyncWrite + Unpin>(
    agent_w: &Arc<Mutex<W>>,
    id: Option<&RequestId>,
    reason: &str,
) -> io::Result<()> {
    tracing::info!(reason, "gateway refused an agent frame for its envelope");
    let message = format!("Invalid Request: {reason}");
    write_frame(agent_w, error(id, -32600, &message).as_bytes()).await
}

/// Refuse a server->client request the policy gates off, answering the backend locally so the request
/// never reaches the agent or model (FW-GW3).
async fn police<W: AsyncWrite + Unpin>(
    backend_w: &Arc<Mutex<W>>,
    id: Option<&RequestId>,
    method: &str,
) -> io::Result<()> {
    tracing::info!(method, "gateway policed server->client request");
    write_frame(
        backend_w,
        error(id, -32601, &format!("{method} not supported by client")).as_bytes(),
    )
    .await
}

fn error(id: Option<&RequestId>, code: i64, message: &str) -> String {
    json!({"jsonrpc": "2.0", "id": id, "error": {"code": code, "message": message}}).to_string()
}

/// Locks the shared writer for the whole frame so the two pumps never interleave a line.
async fn write_frame<W: AsyncWrite + Unpin>(
    writer: &Arc<Mutex<W>>,
    bytes: &[u8],
) -> io::Result<()> {
    let mut guard = writer.lock().await;
    guard.write_all(bytes).await?;
    guard.write_all(b"\n").await?;
    guard.flush().await
}

/// Build a `std::process::Command` for a stdio MCP backend confined to its own grant (FW-GW5), so a
/// spawned server is no more privileged than its policy (FW-E2E-019). [`serve_stdio`] converts to a
/// `tokio::process::Command` and spawns; the `pre_exec` confinement hook survives the conversion.
pub fn confined_command(
    program: &str,
    args: &[String],
    backend_policy: &CompiledPolicy,
) -> Result<std::process::Command, GatewayError> {
    let mut command = std::process::Command::new(program);
    command.args(args);
    formwork_confine::spawn_confined(&mut command, backend_policy)?;
    Ok(command)
}

/// Drive the stdio MCP proxy to completion: spawn the confined `backend`, wire this process's
/// stdin/stdout to it through the [`Gateway`], and run until either side hangs up. Owns the async
/// runtime so tokio stays inside this crate (constitution Layers: the one runtime lives only here) --
/// the CLI hands over a plain `std::process::Command` and stays synchronous.
pub fn serve_stdio(backend: std::process::Command, policy: McpPolicy) -> Result<(), GatewayError> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    runtime.block_on(proxy_stdio(backend, policy))
}

async fn proxy_stdio(
    backend: std::process::Command,
    policy: McpPolicy,
) -> Result<(), GatewayError> {
    use std::process::Stdio;

    let mut backend = tokio::process::Command::from(backend);
    backend.stdin(Stdio::piped()).stdout(Stdio::piped());
    let mut child = backend.spawn()?;
    let backend_read = child.stdout.take().expect("stdout is piped");
    let backend_write = child.stdin.take().expect("stdin is piped");

    Gateway::new(policy)
        .run(
            tokio::io::stdin(),
            tokio::io::stdout(),
            backend_read,
            backend_write,
        )
        .await?;
    let status = child.wait().await?;
    tracing::info!(exit_code = ?status.code(), "confined MCP backend exited");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn frames(input: &'static [u8], max: usize) -> io::Result<Vec<Vec<u8>>> {
        let mut reader = BufReader::new(input);
        let mut out = Vec::new();
        while let Some(f) = read_frame(&mut reader, max).await? {
            out.push(f);
        }
        Ok(out)
    }

    #[tokio::test]
    async fn read_frame_splits_on_newlines_and_returns_trailing_partial() {
        assert_eq!(
            frames(b"hi\nthere\n", 1024).await.unwrap(),
            vec![b"hi".to_vec(), b"there".to_vec()]
        );
        assert_eq!(
            frames(b"a\nb", 1024).await.unwrap(),
            vec![b"a".to_vec(), b"b".to_vec()]
        );
        assert!(frames(b"", 1024).await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn read_frame_fails_closed_on_oversize() {
        let err = frames(b"aaaaaaaaaaaa", 8).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    fn allow(tools: &[&str]) -> McpPolicy {
        McpPolicy {
            tools: Visibility::allow_exact(tools.iter().copied()),
            ..Default::default()
        }
    }

    fn parse(frame: &str) -> Frame {
        Frame::parse(frame.as_bytes().to_vec())
    }

    /// The id a frame parses to, whatever the frame is.
    fn id_of(frame: &str) -> Id {
        match parse(frame) {
            Frame::Message { id, .. } | Frame::Ambiguous { id } => id,
            _ => panic!("{frame} did not parse as a JSON object"),
        }
    }

    fn int(n: i128) -> Id {
        Id::Valid(RequestId::Int(n))
    }

    /// Run the agent->backend pump over `agent` to its end, against a backend that never
    /// answers. Returns what reached the backend and what was written back to the agent.
    async fn from_agent(policy: McpPolicy, agent: &[u8]) -> (Vec<String>, Vec<Value>) {
        let (_silent_backend, backend_read) = tokio::io::duplex(64);
        let (mut to_agent, mut to_backend) = (Vec::new(), Vec::new());
        Gateway::new(policy)
            .run(agent, &mut to_agent, backend_read, &mut to_backend)
            .await
            .unwrap();
        (lines(&to_backend), json_lines(&to_agent))
    }

    /// Run the backend->agent pump over `backend` to its end, with a silent agent.
    async fn from_backend(policy: McpPolicy, backend: &[u8]) -> (Vec<String>, Vec<Value>) {
        let (_silent_agent, agent_read) = tokio::io::duplex(64);
        let (mut to_agent, mut to_backend) = (Vec::new(), Vec::new());
        Gateway::new(policy)
            .run(agent_read, &mut to_agent, backend, &mut to_backend)
            .await
            .unwrap();
        (lines(&to_agent), json_lines(&to_backend))
    }

    fn lines(bytes: &[u8]) -> Vec<String> {
        std::str::from_utf8(bytes)
            .unwrap()
            .lines()
            .map(str::to_owned)
            .collect()
    }

    fn json_lines(bytes: &[u8]) -> Vec<Value> {
        lines(bytes)
            .iter()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect()
    }

    #[test]
    fn fw_gw15_filter_lists_hides_ungranted_and_keeps_granted() {
        let resp = json!({
            "jsonrpc": "2.0", "id": 1,
            "result": {"tools": [{"name": "keep"}, {"name": "drop"}, {"no_id": true}, {"name": 7}]}
        });
        let out = filter_lists(resp.to_string().as_bytes(), &allow(&["keep"])).unwrap();
        let parsed: Value = serde_json::from_str(&out).unwrap();
        assert_eq!(parsed["result"]["tools"], json!([{"name": "keep"}]));
    }

    /// FW-GW15: each list a result carries is filtered by its own axis, and every other field
    /// -- the pagination cursor, `_meta`, the id -- is kept as it was.
    #[test]
    fn fw_gw15_filter_lists_filters_each_list_and_keeps_other_fields() {
        let policy = McpPolicy {
            tools: Visibility::allow_exact(["keep"]),
            resources: Visibility::allow_exact(["file:///pub", "file:///logs/{name}"]),
            prompts: Visibility::allow_exact(["greeting"]),
            ..Default::default()
        };
        let resp = json!({
            "jsonrpc": "2.0", "id": "page-2",
            "result": {
                "tools": [{"name": "keep"}, {"name": "drop"}],
                "resources": [{"uri": "file:///pub"}, {"uri": "file:///secret"}],
                "resourceTemplates": [
                    {"uriTemplate": "file:///logs/{name}"},
                    {"uriTemplate": "file:///secret/{name}"}
                ],
                "prompts": [{"name": "greeting"}, {"name": "secret_prompt"}],
                "nextCursor": "c-3",
                "_meta": {"tools": [{"name": "drop-nested"}]}
            }
        });
        let out = filter_lists(resp.to_string().as_bytes(), &policy).unwrap();
        let parsed: Value = serde_json::from_str(&out).unwrap();
        assert_eq!(
            parsed,
            json!({
                "jsonrpc": "2.0", "id": "page-2",
                "result": {
                    "tools": [{"name": "keep"}],
                    "resources": [{"uri": "file:///pub"}],
                    "resourceTemplates": [{"uriTemplate": "file:///logs/{name}"}],
                    "prompts": [{"name": "greeting"}],
                    "nextCursor": "c-3",
                    "_meta": {"tools": [{"name": "drop-nested"}]}
                }
            })
        );
    }

    /// FW-GW15: a frame is a listing by the shape of its `result` alone -- with an id nobody
    /// asked under, with no id, even with a method -- and only a top-level array makes it one.
    #[test]
    fn fw_gw15_listing_is_decided_by_result_shape() {
        let listing = |frame: &str| match parse(frame) {
            Frame::Message { listing, .. } => listing,
            _ => panic!("{frame} did not parse as a JSON object"),
        };
        for key in ["tools", "resources", "resourceTemplates", "prompts"] {
            assert!(listing(&format!(r#"{{"id":1,"result":{{"{key}":[]}}}}"#)));
            assert!(listing(&format!(r#"{{"result":{{"{key}":[]}}}}"#)));
            assert!(listing(&format!(
                r#"{{"id":1,"method":"x","result":{{"{key}":[]}}}}"#
            )));
            assert!(!listing(&format!(
                r#"{{"id":1,"result":{{"{key}":{{}}}}}}"#
            )));
            assert!(!listing(&format!(
                r#"{{"id":1,"result":{{"{key}":null}}}}"#
            )));
            assert!(!listing(&format!(
                r#"{{"id":1,"result":{{"nested":{{"{key}":[]}}}}}}"#
            )));
        }
        assert!(!listing(r#"{"id":1,"result":{"content":[]}}"#));
        assert!(!listing(r#"{"id":1,"result":[{"tools":[]}]}"#));
        assert!(!listing(r#"{"id":1,"error":{"code":1,"message":"tools"}}"#));
    }

    /// FW-GW15: the backend pump filters every listing it forwards, with no request on record,
    /// and drops one it cannot filter rather than forwarding it as received.
    #[tokio::test]
    async fn fw_gw15_backend_listings_are_filtered_without_a_pending_request() {
        // 200 levels of nesting is JSON the typed parse skips over and `filter_lists` cannot read.
        let deep = format!(
            r#"{{"id":4,"result":{{"tools":[{{"name":"drop","inputSchema":{}{}}}]}}}}"#,
            "[".repeat(200),
            "]".repeat(200)
        );
        let backend = [
            r#"{"jsonrpc":"2.0","id":7,"result":{"tools":[{"name":"keep"},{"name":"drop"}]}}"#,
            r#"{"jsonrpc":"2.0","result":{"tools":[{"name":"drop"}],"nextCursor":"c"}}"#,
            r#"{"id":1.0,"result":{"content":[],"tools":[{"name":"drop"},{"name":"keep"}]}}"#,
            &deep,
            r#"{"id":5,"result":{"tools":[{"name":"drop"}]},"result":{"tools":[]}}"#,
            r#"{"id":6,"result":{"tools":[{"name":"drop"}],"tools":[]}}"#,
            r#"[{"id":8,"result":{"tools":[{"name":"drop"}]}}]"#,
            r#"{"jsonrpc":"2.0","id":9,"result":{"content":[{"type":"text","text":"ok"}]}}"#,
        ]
        .join("\n");
        let (to_agent, to_backend) = from_backend(allow(&["keep"]), backend.as_bytes()).await;
        assert!(to_backend.is_empty());
        assert_eq!(to_agent.len(), 4, "{to_agent:?}");
        assert!(
            to_agent.iter().all(|frame| !frame.contains("drop")),
            "a hidden name reached the agent: {to_agent:?}"
        );
        let parsed: Vec<Value> = to_agent
            .iter()
            .map(|frame| serde_json::from_str(frame).unwrap())
            .collect();
        assert_eq!(parsed[0]["result"]["tools"], json!([{"name": "keep"}]));
        assert_eq!(parsed[1]["result"], json!({"tools": [], "nextCursor": "c"}));
        assert_eq!(
            parsed[2]["result"],
            json!({"content": [], "tools": [{"name": "keep"}]})
        );
        // FW-GW8: a response that is no listing is the backend's own bytes.
        assert_eq!(
            to_agent[3],
            r#"{"jsonrpc":"2.0","id":9,"result":{"content":[{"type":"text","text":"ok"}]}}"#
        );
    }

    /// FW-GW16: an id is a string or a number spelled as an integer; equal JSON values are one
    /// id, and no spelling of a number gives a second id for the same value.
    #[test]
    fn fw_gw16_ids_parse_to_a_string_or_an_integer() {
        let with_id = |id: &str| id_of(&format!(r#"{{"id":{id},"method":"ping"}}"#));
        assert_eq!(with_id("1"), int(1));
        assert_eq!(with_id("0"), int(0));
        assert_eq!(with_id("-7"), int(-7));
        assert_eq!(with_id("18446744073709551615"), int(u64::MAX.into()));
        assert_eq!(with_id("-9223372036854775808"), int(i64::MIN.into()));
        assert_eq!(with_id(r#""1""#), Id::Valid(RequestId::Str("1".into())));
        assert_ne!(with_id("1"), with_id(r#""1""#));
        assert_eq!(with_id(r#""a""#), with_id(r#""a""#));
        assert_eq!(with_id("null"), Id::Absent);
        assert_eq!(id_of(r#"{"method":"ping"}"#), Id::Absent);
        for spelling in [
            "1.0",
            "1e0",
            "1E0",
            "10e-1",
            "1.5",
            "-0",
            "-0.0",
            "18446744073709551616",
            "-9223372036854775809",
            "99999999999999999999",
            "true",
            "false",
            "{}",
            r#"{"id":1}"#,
            "[]",
            "[1]",
        ] {
            assert_eq!(with_id(spelling), Id::Invalid, "id spelled {spelling}");
        }
    }

    /// FW-GW16: an id the gateway echoes in a refusal is spelled as it was received.
    #[test]
    fn fw_gw16_ids_serialize_as_received() {
        for id in [
            RequestId::Int(0),
            RequestId::Int(-7),
            RequestId::Int(u64::MAX.into()),
            RequestId::Int(i64::MIN.into()),
            RequestId::Str("1".into()),
        ] {
            let frame = error(Some(&id), -32600, "Invalid Request");
            assert_eq!(id_of(&frame), Id::Valid(id));
        }
        assert_eq!(
            error(None, -32600, "Invalid Request"),
            r#"{"error":{"code":-32600,"message":"Invalid Request"},"id":null,"jsonrpc":"2.0"}"#
        );
    }

    /// FW-GW16: a request whose id is unusable, or belongs to an unanswered request, is refused
    /// and not forwarded -- before policy, so the refusal is the same for any target.
    #[tokio::test]
    async fn fw_gw16_unusable_and_in_flight_ids_are_refused() {
        let agent = [
            r#"{"jsonrpc":"2.0","id":1,"method":"tools/list"}"#,
            r#"{"jsonrpc":"2.0","id":1,"method":"resources/list"}"#,
            r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"hidden"}}"#,
            r#"{"jsonrpc":"2.0","id":"1","method":"tools/list"}"#,
            r#"{"jsonrpc":"2.0","id":"1","method":"tools/list"}"#,
            r#"{"jsonrpc":"2.0","id":1.0,"method":"tools/list"}"#,
            r#"{"jsonrpc":"2.0","id":1e0,"method":"tools/list"}"#,
            r#"{"jsonrpc":"2.0","id":true,"method":"ping"}"#,
            // A refused request holds no id: `2` is free for the request after it.
            r#"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"hidden"}}"#,
            r#"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"keep"}}"#,
        ]
        .join("\n");
        let (to_backend, to_agent) = from_agent(allow(&["keep"]), agent.as_bytes()).await;
        assert_eq!(
            to_backend,
            [
                r#"{"jsonrpc":"2.0","id":1,"method":"tools/list"}"#,
                r#"{"jsonrpc":"2.0","id":"1","method":"tools/list"}"#,
                r#"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"keep"}}"#,
            ]
        );
        let refusals: Vec<(Value, i64)> = to_agent
            .iter()
            .map(|r| (r["id"].clone(), r["error"]["code"].as_i64().unwrap()))
            .collect();
        assert_eq!(
            refusals,
            [
                (json!(1), -32600),
                (json!(1), -32600),
                (json!("1"), -32600),
                (Value::Null, -32600),
                (Value::Null, -32600),
                (Value::Null, -32600),
                (json!(2), -32602),
            ]
        );
        assert_eq!(
            to_agent[0]["error"], to_agent[1]["error"],
            "an in-flight id is refused alike for a granted and an ungranted target"
        );
    }

    /// FW-GW16: the set of unanswered ids is bounded; the request past the bound is refused, and
    /// one the gateway refuses locally takes no place in it.
    #[tokio::test]
    async fn fw_gw16_in_flight_ids_are_bounded() {
        let mut agent = String::new();
        for id in 0..=MAX_IN_FLIGHT_REQUESTS {
            agent.push_str(&format!("{{\"id\":{id},\"method\":\"ping\"}}\n"));
        }
        let (to_backend, to_agent) = from_agent(allow(&[]), agent.as_bytes()).await;
        assert_eq!(to_backend.len(), MAX_IN_FLIGHT_REQUESTS);
        assert_eq!(to_agent.len(), 1);
        assert_eq!(to_agent[0]["id"], json!(MAX_IN_FLIGHT_REQUESTS));
        assert_eq!(to_agent[0]["error"]["code"], -32600);
    }

    /// FW-GW17: a repeat of any key the gateway reads refuses the frame, also where the value is
    /// skipped unread, where the key is spelled with an escape, and where the repeats agree.
    #[test]
    fn fw_gw17_a_repeated_key_is_ambiguous() {
        let call = |params: &str| format!(r#"{{"id":1,"method":"tools/call","params":{params}}}"#);
        let complete = |reference: &str| {
            format!(r#"{{"id":1,"method":"completion/complete","params":{{"ref":{reference}}}}}"#)
        };
        for frame in [
            r#"{"jsonrpc":"2.0","jsonrpc":"2.0","id":1,"method":"ping"}"#.to_string(),
            r#"{"id":1,"id":1,"method":"ping"}"#.to_string(),
            r#"{"id":1,"method":"ping","method":"ping"}"#.to_string(),
            r#"{"id":1,"method":"tools/call","method":"ping","params":{"name":"a"}}"#.to_string(),
            r#"{"id":1,"method":"tools/call","params":{"name":"a"},"params":{"name":"b"}}"#
                .to_string(),
            r#"{"id":1,"method":"tools/call","params":{"name":"a"},"params":null}"#.to_string(),
            r#"{"id":1,"method":"tools/call","params":{"name":"a"},"params":{"name":"b"}}"#
                .to_string(),
            r#"{"id":1,"result":{},"result":{}}"#.to_string(),
            r#"{"id":1,"error":{},"error":{}}"#.to_string(),
            call(r#"{"name":"a","name":"b"}"#),
            call(r#"{"name":"a","arguments":{},"name":"a"}"#),
            call(r#"{"name":"a","name":"b"}"#),
            call(r#"{"name":"a","uri":"x","uri":"y"}"#),
            call(r#"{"name":"a","ref":{},"ref":{}}"#),
            r#"{"id":1,"method":"resources/read","params":{"uri":"a","uri":"b"}}"#.to_string(),
            r#"{"id":1,"method":"initialize","params":{"name":"a","name":"b"}}"#.to_string(),
            complete(r#"{"type":"ref/prompt","type":"ref/resource","name":"a"}"#),
            complete(r#"{"type":"ref/prompt","name":"a","name":"b"}"#),
            complete(r#"{"type":"ref/resource","uri":"a","uri":"b"}"#),
            r#"{"id":1,"result":{"tools":[],"tools":[]}}"#.to_string(),
            r#"{"id":1,"result":{"resources":[],"resources":null}}"#.to_string(),
            r#"{"id":1,"result":{"resourceTemplates":[],"resourceTemplates":[]}}"#.to_string(),
            r#"{"id":1,"result":{"prompts":[],"prompts":[]}}"#.to_string(),
        ] {
            assert!(
                matches!(parse(&frame), Frame::Ambiguous { .. }),
                "{frame} must be refused"
            );
        }
    }

    /// FW-GW17: the refusal is addressed by the frame's id when it has exactly one usable id.
    #[test]
    fn fw_gw17_an_ambiguous_frame_keeps_its_addressee() {
        let dup = r#""method":"tools/call","method":"ping""#;
        assert_eq!(id_of(&format!(r#"{{"id":3,{dup}}}"#)), int(3));
        assert_eq!(
            id_of(&format!(r#"{{{dup},"id":"x"}}"#)),
            id_of(r#"{"id":"x"}"#)
        );
        assert_eq!(id_of(&format!(r#"{{{dup}}}"#)), Id::Absent);
        assert_eq!(id_of(&format!(r#"{{"id":null,{dup}}}"#)), Id::Absent);
        assert_eq!(id_of(&format!(r#"{{"id":1.0,{dup}}}"#)), Id::Invalid);
        assert_eq!(id_of(r#"{"id":1,"id":2,"method":"ping"}"#), Id::Invalid);
        assert_eq!(id_of(r#"{"id":1,"id":1,"method":"ping"}"#), Id::Invalid);
        // A repeated key ahead of a syntax error is still not JSON (D6).
        assert!(matches!(
            parse(r#"{"id":1,"id":2,"method":"ping""#),
            Frame::NotJson(_)
        ));
    }

    /// FW-GW17 / FW-GW8: keys the gateway does not read may repeat and are forwarded, and
    /// `params` given as an array is never read by position.
    #[test]
    fn fw_gw17_unread_keys_and_positional_params_are_not_decided_on() {
        let target = |frame: &str| match parse(frame) {
            Frame::Message {
                method: Some(Method::Gated { target, .. }),
                ..
            } => target,
            _ => panic!("{frame} did not parse as a gated call"),
        };
        assert_eq!(
            target(
                r#"{"id":1,"extra":1,"extra":2,"method":"tools/call","params":{"name":"a","arguments":{"name":"b","name":"c"},"_meta":1,"_meta":2}}"#
            ),
            "a"
        );
        assert_eq!(
            target(r#"{"id":1,"method":"tools/call","params":["keep"]}"#),
            ""
        );
        assert_eq!(
            target(r#"{"id":1,"method":"tools/call","params":{"name":["keep"]}}"#),
            ""
        );
        assert!(matches!(
            parse(r#"["2.0",null,1,"tools/call",{"name":"keep"}]"#),
            Frame::Batch
        ));
    }

    /// FW-GW17: an ambiguous agent frame is answered when it has an addressee, dropped when it is
    /// a notification, and reaches the backend in neither case.
    #[tokio::test]
    async fn fw_gw17_ambiguous_agent_frames_never_reach_the_backend() {
        let agent = [
            r#"{"id":1,"method":"tools/call","params":{"name":"drop"},"params":{"name":"keep"}}"#,
            r#"{"id":2,"method":"tools/call","params":{"name":"keep"},"params":{"name":"drop"}}"#,
            r#"{"id":3,"method":"tools/call","params":{"name":"drop","name":"keep"}}"#,
            r#"{"method":"tools/call","params":{"name":"drop","name":"keep"}}"#,
            r#"{"id":4,"id":5,"method":"tools/call","params":{"name":"keep"}}"#,
            r#"{"id":6,"method":"ping","method":"tools/call","params":{"name":"drop"}}"#,
            r#"{"id":7,"result":{},"result":{}}"#,
        ]
        .join("\n");
        let (to_backend, to_agent) = from_agent(allow(&["keep"]), agent.as_bytes()).await;
        assert!(to_backend.is_empty(), "{to_backend:?}");
        let refusals: Vec<(Value, i64)> = to_agent
            .iter()
            .map(|r| (r["id"].clone(), r["error"]["code"].as_i64().unwrap()))
            .collect();
        assert_eq!(
            refusals,
            [
                (json!(1), -32600),
                (json!(2), -32600),
                (json!(3), -32600),
                (Value::Null, -32600),
                (json!(6), -32600),
                (json!(7), -32600),
            ]
        );
        assert!(
            to_agent.windows(2).all(|w| w[0]["error"] == w[1]["error"]),
            "the refusal does not depend on which occurrence names a granted item"
        );
    }

    /// FW-GW17: a backend frame that repeats a key the gateway reads is not forwarded, in
    /// particular a server->client request the gate would otherwise have to decide on.
    #[tokio::test]
    async fn fw_gw17_ambiguous_backend_frames_are_dropped() {
        let policy = McpPolicy {
            sampling: Gate::Deny,
            ..Default::default()
        };
        let backend = [
            r#"{"id":"s1","method":"sampling/createMessage","method":"notifications/x"}"#,
            r#"{"id":"s2","method":"notifications/x","method":"sampling/createMessage"}"#,
            r#"{"id":"s3","id":null,"method":"sampling/createMessage"}"#,
            r#"{"jsonrpc":"2.0","method":"notifications/x"}"#,
        ]
        .join("\n");
        let (to_agent, to_backend) = from_backend(policy, backend.as_bytes()).await;
        assert_eq!(
            to_agent,
            [r#"{"jsonrpc":"2.0","method":"notifications/x"}"#]
        );
        assert!(to_backend.is_empty());
    }

    /// FW-GW8: a frame the gateway admits is forwarded as the bytes received -- spacing, key
    /// order, number spelling and unknown fields untouched.
    #[tokio::test]
    async fn fw_gw8_admitted_frames_forward_the_original_bytes() {
        let agent = [
            r#"{ "params" : {"arguments":{"n":1.50,"big":1E+2,"k":1,"k":2},"name":"keep"}, "method":"tools/call","x-unknown":[1 ,2], "id" : 10 , "jsonrpc":"2.0"}"#,
            r#"{"method":"notifications/progress","params":{"progress":0.50}}"#,
            r#"{"id":"s1","result":{"tools":[{"name":"anything"}]}}"#,
            r#""a bare string""#,
        ];
        let (to_backend, to_agent) =
            from_agent(allow(&["keep"]), agent.join("\n").as_bytes()).await;
        assert_eq!(to_backend, agent);
        assert!(to_agent.is_empty());
    }

    /// FW-GW3: a server->client sampling or elicitation request is answered to the backend when
    /// its gate is off and forwarded as received when it is on; the typed ids change neither.
    #[tokio::test]
    async fn fw_gw3_server_requests_are_gated_on_typed_ids() {
        let backend = [
            r#"{"jsonrpc":"2.0","id":"s1","method":"sampling/createMessage","params":{}}"#,
            r#"{"jsonrpc":"2.0","id":7,"method":"elicitation/create","params":{}}"#,
            r#"{"jsonrpc":"2.0","id":1.5,"method":"sampling/createMessage","params":{}}"#,
        ];
        let input = backend.join("\n");

        let (to_agent, to_backend) = from_backend(McpPolicy::default(), input.as_bytes()).await;
        assert!(to_agent.is_empty(), "{to_agent:?}");
        let refusals: Vec<(Value, i64)> = to_backend
            .iter()
            .map(|r| (r["id"].clone(), r["error"]["code"].as_i64().unwrap()))
            .collect();
        assert_eq!(
            refusals,
            [
                (json!("s1"), -32601),
                (json!(7), -32601),
                (Value::Null, -32601)
            ]
        );

        let open = McpPolicy {
            sampling: Gate::Allow,
            elicitation: Gate::Allow,
            ..Default::default()
        };
        let (to_agent, to_backend) = from_backend(open, input.as_bytes()).await;
        assert_eq!(to_agent, backend);
        assert!(to_backend.is_empty());
    }

    #[test]
    fn frame_parse_classifies_by_method_and_id() {
        let gated = |frame: &str| match parse(frame) {
            Frame::Message {
                id,
                method: Some(Method::Gated { axis, target }),
                ..
            } => (id, axis, target),
            _ => panic!("{frame} did not parse as a gated call"),
        };
        let (id, axis, target) = gated(r#"{"id":1,"method":"tools/call","params":{"name":"x"}}"#);
        assert!(id == int(1) && matches!(axis, Axis::Tool) && target == "x");
        let (id, axis, target) = gated(r#"{"method":"resources/subscribe","params":{"uri":"u"}}"#);
        assert!(id == Id::Absent && matches!(axis, Axis::Resource) && target == "u");
        let (_, axis, target) = gated(
            r#"{"id":1,"method":"completion/complete","params":{"ref":{"type":"ref/prompt","name":"p","uri":"u"}}}"#,
        );
        assert!(matches!(axis, Axis::Prompt) && target == "p");
        let (_, axis, target) = gated(
            r#"{"id":1,"method":"completion/complete","params":{"ref":{"type":"ref/resource","name":"p","uri":"u"}}}"#,
        );
        assert!(matches!(axis, Axis::Resource) && target == "u");
        let (_, axis, _) =
            gated(r#"{"id":1,"method":"completion/complete","params":{"ref":["ref/prompt"]}}"#);
        assert!(matches!(axis, Axis::Unknown));

        assert!(matches!(
            parse(r#"{"id":2,"method":"resources/templates/list"}"#),
            Frame::Message {
                method: Some(Method::Other),
                listing: false,
                ..
            }
        ));
        assert!(matches!(
            parse(r#"{"id":"s","method":"sampling/createMessage"}"#),
            Frame::Message {
                method: Some(Method::Sampling),
                ..
            }
        ));
        assert!(matches!(
            parse(r#"{"id":"e","method":"elicitation/create"}"#),
            Frame::Message {
                method: Some(Method::Elicitation),
                ..
            }
        ));
        assert!(matches!(
            parse(r#"{"id":3,"result":{}}"#),
            Frame::Message { method: None, .. }
        ));
        // A method that is not a string is no method the gateway gates.
        assert!(matches!(
            parse(r#"{"id":3,"method":5}"#),
            Frame::Message { method: None, .. }
        ));
        assert!(matches!(
            parse(r#"{"method":"notifications/x"}"#),
            Frame::Message {
                id: Id::Absent,
                method: Some(Method::Other),
                ..
            }
        ));
        assert!(matches!(parse("not json"), Frame::NotJson(_)));
        assert!(matches!(parse(""), Frame::NotJson(_)));
        assert!(matches!(
            Frame::parse(b"{\"id\":1,\"method\":\"ping\",\"x\":\"\xff\"}".to_vec()),
            Frame::NotJson(_)
        ));
        assert!(matches!(parse("17"), Frame::Passthrough(_)));
        assert!(matches!(
            parse(r#"[{"id":1,"method":"tools/call"}]"#),
            Frame::Batch
        ));
    }
}
