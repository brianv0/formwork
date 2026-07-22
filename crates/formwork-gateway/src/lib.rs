//! The gateway: an MCP-aware policy proxy between a confined agent and one backend. Its shading is
//! binding only because the confiner beneath leaves the agent no other door to the backend -- no
//! network, no filesystem past the injected fd (FW-GW4). Refusals are oracle-free by construction
//! (FW-ADV-004): a hidden-but-real name and a nonexistent one take the same local path and yield the
//! same error, so nothing tells "blocked" from "absent". `*/list` responses are filtered statelessly,
//! so a runtime `list_changed` re-filters for free. Granted traffic forwards as the exact bytes
//! received (FW-GW8); any `AsyncRead`/`AsyncWrite` pair works, so an http/sse backend needs only a
//! framing adapter.

use std::collections::HashMap;
use std::io;
use std::sync::Arc;

use serde_json::{json, Value};
use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::sync::Mutex;

use formwork_blueprint::{Gate, McpPolicy};
use formwork_compile::CompiledPolicy;

// Bounds a single frame so a peer that never sends a newline can't make the gateway buffer without
// limit; overflow closes the connection. A stability bound (design §3), not a DoS-resistance claim --
// the seam bounds its control channel the same way (`MAX_CONTROL_LINE`).
const MAX_FRAME_BYTES: usize = 16 * 1024 * 1024;

#[derive(Debug, thiserror::Error)]
pub enum GatewayError {
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error("confining a backend failed: {0}")]
    Confine(#[from] formwork_confine::ConfineError),
}

#[derive(Clone, Copy)]
enum ListKind {
    Tools,
    Resources,
    ResourceTemplates,
    Prompts,
}

/// One JSON-RPC frame reduced to what the gateway routes on. `raw` is the exact received bytes, kept
/// so granted traffic forwards byte-for-byte (FW-GW8) with no re-serialization. [`Frame::parse`]
/// classifies each frame so the pumps route on the variant, never on `Value`; the one other place raw
/// JSON is parsed is `filter_list`, which prunes ungranted items from `*/list` responses.
enum Frame {
    ToolCall {
        id: Value,
        target: String,
        raw: Vec<u8>,
    },
    ResourceRead {
        id: Value,
        target: String,
        raw: Vec<u8>,
    },
    PromptGet {
        id: Value,
        target: String,
        raw: Vec<u8>,
    },
    ListRequest {
        id: Value,
        kind: ListKind,
        raw: Vec<u8>,
    },
    Sampling {
        id: Value,
        raw: Vec<u8>,
    },
    Elicitation {
        id: Value,
        raw: Vec<u8>,
    },
    Response {
        id: Value,
        raw: Vec<u8>,
    },
    Passthrough(Vec<u8>),
}

impl Frame {
    fn parse(raw: Vec<u8>) -> Frame {
        let value: Value = match serde_json::from_slice(&raw) {
            Ok(v) => v,
            Err(_) => return Frame::Passthrough(raw),
        };
        let method = value
            .get("method")
            .and_then(Value::as_str)
            .map(str::to_owned);
        let id = value.get("id").filter(|v| !v.is_null()).cloned();
        let pointer_str = |ptr: &str| {
            value
                .pointer(ptr)
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_owned()
        };
        match (method.as_deref(), id) {
            (Some("tools/call"), Some(id)) => Frame::ToolCall {
                id,
                target: pointer_str("/params/name"),
                raw,
            },
            (Some("resources/read"), Some(id)) => Frame::ResourceRead {
                id,
                target: pointer_str("/params/uri"),
                raw,
            },
            (Some("prompts/get"), Some(id)) => Frame::PromptGet {
                id,
                target: pointer_str("/params/name"),
                raw,
            },
            (Some("tools/list"), Some(id)) => Frame::ListRequest {
                id,
                kind: ListKind::Tools,
                raw,
            },
            (Some("resources/list"), Some(id)) => Frame::ListRequest {
                id,
                kind: ListKind::Resources,
                raw,
            },
            (Some("resources/templates/list"), Some(id)) => Frame::ListRequest {
                id,
                kind: ListKind::ResourceTemplates,
                raw,
            },
            (Some("prompts/list"), Some(id)) => Frame::ListRequest {
                id,
                kind: ListKind::Prompts,
                raw,
            },
            (Some("sampling/createMessage"), Some(id)) => Frame::Sampling { id, raw },
            (Some("elicitation/create"), Some(id)) => Frame::Elicitation { id, raw },
            (None, Some(id)) => Frame::Response { id, raw },
            _ => Frame::Passthrough(raw),
        }
    }

    fn into_raw(self) -> Vec<u8> {
        match self {
            Frame::ToolCall { raw, .. }
            | Frame::ResourceRead { raw, .. }
            | Frame::PromptGet { raw, .. }
            | Frame::ListRequest { raw, .. }
            | Frame::Sampling { raw, .. }
            | Frame::Elicitation { raw, .. }
            | Frame::Response { raw, .. }
            | Frame::Passthrough(raw) => raw,
        }
    }
}

/// The gateway for a single agent<->backend connection, applying one server's [`McpPolicy`].
pub struct Gateway {
    policy: McpPolicy,
}

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
        let pending: Arc<Mutex<HashMap<String, ListKind>>> = Arc::new(Mutex::new(HashMap::new()));

        let a2b = pump_agent_to_backend(
            agent_read,
            agent_w.clone(),
            backend_w.clone(),
            pending.clone(),
            &self.policy,
        );
        let b2a = pump_backend_to_agent(
            backend_read,
            agent_w.clone(),
            backend_w.clone(),
            pending.clone(),
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

async fn pump_agent_to_backend<AR, AW, BW>(
    reader: AR,
    agent_w: Arc<Mutex<AW>>,
    backend_w: Arc<Mutex<BW>>,
    pending: Arc<Mutex<HashMap<String, ListKind>>>,
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
            Frame::ToolCall { id, target, raw } => {
                if policy.tools.permits(&target) {
                    write_frame(&backend_w, &raw).await?;
                } else {
                    refuse(
                        &agent_w,
                        &id,
                        -32602,
                        "tool",
                        &target,
                        format!("Unknown tool: {target}"),
                    )
                    .await?;
                }
            }
            Frame::ResourceRead { id, target, raw } => {
                if policy.resources.permits(&target) {
                    write_frame(&backend_w, &raw).await?;
                } else {
                    // -32002 is MCP's "resource not found" -- identical to a genuine absence.
                    refuse(
                        &agent_w,
                        &id,
                        -32002,
                        "resource",
                        &target,
                        format!("Resource not found: {target}"),
                    )
                    .await?;
                }
            }
            Frame::PromptGet { id, target, raw } => {
                if policy.prompts.permits(&target) {
                    write_frame(&backend_w, &raw).await?;
                } else {
                    refuse(
                        &agent_w,
                        &id,
                        -32602,
                        "prompt",
                        &target,
                        format!("Unknown prompt: {target}"),
                    )
                    .await?;
                }
            }
            Frame::ListRequest { id, kind, raw } => {
                pending.lock().await.insert(id_key(&id), kind);
                write_frame(&backend_w, &raw).await?;
            }
            other => write_frame(&backend_w, &other.into_raw()).await?,
        }
    }
    Ok(())
}

async fn pump_backend_to_agent<BR, AW, BW>(
    reader: BR,
    agent_w: Arc<Mutex<AW>>,
    backend_w: Arc<Mutex<BW>>,
    pending: Arc<Mutex<HashMap<String, ListKind>>>,
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
            Frame::Sampling { id, raw } => {
                if policy.sampling == Gate::Allow {
                    write_frame(&agent_w, &raw).await?;
                } else {
                    police(&backend_w, &id, "sampling/createMessage").await?;
                }
            }
            Frame::Elicitation { id, raw } => {
                if policy.elicitation == Gate::Allow {
                    write_frame(&agent_w, &raw).await?;
                } else {
                    police(&backend_w, &id, "elicitation/create").await?;
                }
            }
            Frame::Response { id, raw } => {
                let kind = pending.lock().await.remove(&id_key(&id));
                match kind.and_then(|k| filter_list(&raw, k, policy)) {
                    Some(filtered) => write_frame(&agent_w, filtered.as_bytes()).await?,
                    None => write_frame(&agent_w, &raw).await?,
                }
            }
            other => write_frame(&agent_w, &other.into_raw()).await?,
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

/// Drop ungranted items from a `*/list` response, re-serializing. `None` means the response wasn't a
/// filterable list shape, so the caller forwards the original bytes. An item missing its identifier
/// is dropped (fail-closed). Item identity per design §4: tools/prompts by `name`, resources by
/// `uri`, resource templates by `uriTemplate`.
fn filter_list(raw: &[u8], kind: ListKind, policy: &McpPolicy) -> Option<String> {
    let mut value: Value = serde_json::from_slice(raw).ok()?;
    let (field, id_field, vis) = match kind {
        ListKind::Tools => ("tools", "name", &policy.tools),
        ListKind::Resources => ("resources", "uri", &policy.resources),
        ListKind::ResourceTemplates => ("resourceTemplates", "uriTemplate", &policy.resources),
        ListKind::Prompts => ("prompts", "name", &policy.prompts),
    };
    let items = value.get_mut("result")?.get_mut(field)?.as_array_mut()?;
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
    Some(value.to_string())
}

/// Refuse an ungranted client request. Records the target for the operator's audit trail (FW-FID3),
/// but the bytes returned to the agent carry only `message` -- which is identical for a hidden-real
/// and a nonexistent item, so the log is not an oracle the agent can observe (FW-ADV-004).
async fn refuse<W: AsyncWrite + Unpin>(
    agent_w: &Arc<Mutex<W>>,
    id: &Value,
    code: i64,
    item: &str,
    target: &str,
    message: String,
) -> io::Result<()> {
    tracing::info!(item, target, "gateway refused ungranted MCP item");
    write_frame(agent_w, error(id, code, &message).as_bytes()).await
}

/// Refuse a server->client request the policy gates off, answering the backend locally so the request
/// never reaches the agent or model (FW-GW3).
async fn police<W: AsyncWrite + Unpin>(
    backend_w: &Arc<Mutex<W>>,
    id: &Value,
    method: &str,
) -> io::Result<()> {
    tracing::info!(method, "gateway policed server->client request");
    write_frame(
        backend_w,
        error(id, -32601, &format!("{method} not supported by client")).as_bytes(),
    )
    .await
}

fn error(id: &Value, code: i64, message: &str) -> String {
    json!({"jsonrpc": "2.0", "id": id, "error": {"code": code, "message": message}}).to_string()
}

fn id_key(id: &Value) -> String {
    id.to_string()
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
/// spawned server is no more privileged than its policy (FW-E2E-019). The caller converts to a
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

    #[test]
    fn filter_list_hides_ungranted_and_keeps_granted() {
        let policy = McpPolicy {
            tools: formwork_blueprint::Visibility::allow_exact(["keep"]),
            ..Default::default()
        };
        let resp = json!({
            "jsonrpc": "2.0", "id": 1,
            "result": {"tools": [{"name": "keep"}, {"name": "drop"}, {"no_id": true}]}
        });
        let out = filter_list(resp.to_string().as_bytes(), ListKind::Tools, &policy).unwrap();
        let parsed: Value = serde_json::from_str(&out).unwrap();
        let kept: Vec<&str> = parsed["result"]["tools"]
            .as_array()
            .unwrap()
            .iter()
            .map(|t| t["name"].as_str().unwrap_or(""))
            .collect();
        assert_eq!(kept, vec!["keep"]);
    }

    #[test]
    fn frame_parse_classifies_by_method_and_id() {
        let call =
            Frame::parse(br#"{"id":1,"method":"tools/call","params":{"name":"x"}}"#.to_vec());
        assert!(matches!(call, Frame::ToolCall { target, .. } if target == "x"));

        let list = Frame::parse(br#"{"id":2,"method":"resources/templates/list"}"#.to_vec());
        assert!(matches!(
            list,
            Frame::ListRequest {
                kind: ListKind::ResourceTemplates,
                ..
            }
        ));

        let resp = Frame::parse(br#"{"id":3,"result":{}}"#.to_vec());
        assert!(matches!(resp, Frame::Response { .. }));

        // A notification (no id) and non-JSON both forward verbatim.
        assert!(matches!(
            Frame::parse(br#"{"method":"notifications/x"}"#.to_vec()),
            Frame::Passthrough(_)
        ));
        assert!(matches!(
            Frame::parse(b"not json".to_vec()),
            Frame::Passthrough(_)
        ));
    }
}
