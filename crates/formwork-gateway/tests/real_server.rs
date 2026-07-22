//! FW-E2E-068: regex tool shading (FW-GW9) against a real, published MCP server --
//! `@modelcontextprotocol/server-everything`, the reference server the MCP project ships to
//! exercise clients. It is driven through the production shading path (`Gateway::run`, the exact
//! code the `formwork gateway` CLI wraps), so this proves the pattern policy holds against a
//! backend Formwork did not write.
//!
//! Ignored by default: it needs `npx` and network to fetch the pinned server. The CI
//! `mcp-integration` job runs it with `--ignored`; locally, `just test-integration-mcp`. If `npx`
//! is absent the test skips (returns) rather than failing, so it never breaks a node-less host.
//!
//! Scope: this isolates the *shading* so it runs in any Linux container with node. The orthogonal
//! backend-confinement arm (FW-GW5) needs a host confiner (Landlock/Seatbelt) and is covered by the
//! host-gated FW-E2E-019.

use std::process::Stdio;
use std::time::Duration;

use formwork_blueprint::{McpPolicy, Visibility};
use formwork_gateway::Gateway;
use serde_json::{json, Value};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader, DuplexStream, Lines};
use tokio::process::Command;
use tokio::time::timeout;

/// Pinned so the asserted tool set stays stable; bump deliberately alongside the assertions below.
const SERVER_SPEC: &str = "@modelcontextprotocol/server-everything@2025.8.18";

/// The client end of the gateway; replies are shaded by policy.
struct Agent {
    writer: DuplexStream,
    reader: Lines<BufReader<DuplexStream>>,
}

impl Agent {
    async fn send(&mut self, message: Value) {
        self.writer
            .write_all(format!("{message}\n").as_bytes())
            .await
            .unwrap();
        self.writer.flush().await.unwrap();
    }

    async fn request(&mut self, id: i64, method: &str, params: Value) {
        self.send(json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params}))
            .await;
    }

    async fn notify(&mut self, method: &str, params: Value) {
        self.send(json!({"jsonrpc": "2.0", "method": method, "params": params}))
            .await;
    }

    /// Read frames until one with the given id arrives (skipping notifications), or time out.
    async fn recv_id(&mut self, want: i64) -> Value {
        loop {
            let line = timeout(Duration::from_secs(90), self.reader.next_line())
                .await
                .expect("gateway reply timed out (server download or hang?)")
                .expect("stream error")
                .expect("stream closed before the awaited reply");
            let v: Value = match serde_json::from_str(&line) {
                Ok(v) => v,
                Err(_) => continue,
            };
            if v.get("id").and_then(Value::as_i64) == Some(want) {
                return v;
            }
        }
    }
}

fn tool_names(list: &Value) -> Vec<String> {
    let mut names: Vec<String> = list["result"]["tools"]
        .as_array()
        .expect("tools/list result")
        .iter()
        .map(|t| t["name"].as_str().unwrap_or("").to_string())
        .collect();
    names.sort();
    names
}

#[tokio::test]
#[ignore = "needs npx + network; run in the mcp-integration CI job or `just test-integration-mcp`"]
async fn fw_e2e_068_regex_shading_against_real_server() {
    // Allow echo/add plus every `get*` tool; deny the `getResource*` subset. Against the pinned
    // server this partitions its real catalog into: visible {add, echo, getTinyImage}, hidden by
    // deny {getResourceReference, getResourceLinks}, hidden by allow-miss {longRunningOperation,
    // printEnv, sampleLLM, annotatedMessage, startElicitation, structuredContent}.
    let allow = ["echo".to_string(), "add".to_string(), "/get.*/".to_string()];
    let deny = ["/getResource.*/".to_string()];
    let policy = McpPolicy {
        tools: Visibility::parse(&allow, &deny).expect("valid patterns"),
        ..Default::default()
    };

    // Spawn the real server as the backend. `npx -y` fetches the pinned package on first run.
    let child = Command::new("npx")
        .arg("-y")
        .arg(SERVER_SPEC)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn();
    let mut child = match child {
        Ok(c) => c,
        Err(e) => {
            eprintln!("skip fw_e2e_068: cannot launch npx ({e}); node toolchain absent");
            return;
        }
    };
    let backend_out = child.stdout.take().unwrap();
    let backend_in = child.stdin.take().unwrap();

    // Wrap the backend in the production shading path.
    let (agent_side, gw_agent_read) = tokio::io::duplex(1 << 16);
    let (gw_agent_write, agent_read) = tokio::io::duplex(1 << 16);
    tokio::spawn(async move {
        let _ = Gateway::new(policy)
            .run(gw_agent_read, gw_agent_write, backend_out, backend_in)
            .await;
        let _ = child.wait().await;
    });
    let mut agent = Agent {
        writer: agent_side,
        reader: BufReader::new(agent_read).lines(),
    };

    // MCP handshake, exactly as a host would.
    agent
        .request(
            1,
            "initialize",
            json!({
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {"name": "formwork-e2e", "version": "0"}
            }),
        )
        .await;
    let init = agent.recv_id(1).await;
    assert!(
        init["result"]["serverInfo"].is_object(),
        "real server must complete initialize: {init}"
    );
    agent.notify("notifications/initialized", json!({})).await;

    // 1) tools/list is shaded to exactly the allowed-minus-denied set.
    agent.request(2, "tools/list", json!({})).await;
    let listed = tool_names(&agent.recv_id(2).await);
    assert_eq!(
        listed,
        vec![
            "add".to_string(),
            "echo".to_string(),
            "getTinyImage".to_string()
        ],
        "only allow-matched, non-denied real tools are visible"
    );

    // 2) an allowed tool round-trips against the real backend.
    agent
        .request(
            3,
            "tools/call",
            json!({"name": "echo", "arguments": {"message": "formwork"}}),
        )
        .await;
    let echoed = agent.recv_id(3).await;
    assert!(
        echoed.get("error").is_none(),
        "allowed real tool must execute: {echoed}"
    );
    let text = echoed["result"]["content"][0]["text"]
        .as_str()
        .unwrap_or_default();
    assert!(
        text.contains("formwork"),
        "echo should reflect input: {text}"
    );

    // 3) a real tool the allow does not cover is hidden and refused oracle-free.
    agent
        .request(
            4,
            "tools/call",
            json!({"name": "sampleLLM", "arguments": {}}),
        )
        .await;
    let allow_miss = agent.recv_id(4).await;
    // 4) a real tool the *deny* removes (even though allow `/get.*/` would cover it) is refused too.
    agent
        .request(
            5,
            "tools/call",
            json!({"name": "getResourceReference", "arguments": {}}),
        )
        .await;
    let deny_hit = agent.recv_id(5).await;

    for (label, resp) in [("allow-miss", &allow_miss), ("deny-terminal", &deny_hit)] {
        assert!(
            resp["error"].is_object(),
            "{label} call must be refused, not executed: {resp}"
        );
        assert!(
            !resp["error"]["message"]
                .as_str()
                .unwrap_or_default()
                .to_lowercase()
                .contains("denied"),
            "{label} refusal must not reveal the tool is blocked (oracle-free): {resp}"
        );
    }
    // The two refusals are indistinguishable in code, so deny is not an oracle for existence.
    assert_eq!(
        allow_miss["error"]["code"], deny_hit["error"]["code"],
        "allow-miss and deny-terminal must refuse identically"
    );
}
