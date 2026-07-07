//! Gateway shading / policing E2E (design §7.4, §7.7), against the stdio fixture backend.

use std::time::Duration;

use formwork_blueprint::{Gate, McpPolicy, Visibility};
use formwork_gateway::Gateway;
use serde_json::{json, Value};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader, DuplexStream, Lines};
use tokio::process::Command;
use tokio::time::timeout;

/// The client end of the gateway; its replies may be shaded by policy.
struct Agent {
    writer: DuplexStream,
    reader: Lines<BufReader<DuplexStream>>,
}

impl Agent {
    async fn send(&mut self, message: Value) {
        let line = message.to_string();
        self.writer.write_all(line.as_bytes()).await.unwrap();
        self.writer.write_all(b"\n").await.unwrap();
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

    async fn recv(&mut self) -> Value {
        let line = timeout(Duration::from_secs(5), self.reader.next_line())
            .await
            .expect("recv timed out")
            .expect("stream error")
            .expect("stream closed unexpectedly");
        serde_json::from_str(&line).unwrap()
    }
}

/// The fixture child and gateway task are detached; they exit when the streams drop at test end.
fn start(policy: McpPolicy) -> Agent {
    let mut child = Command::new(env!("CARGO_BIN_EXE_fw-mcp-fixture"))
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()
        .expect("spawn fixture");
    let backend_out = child.stdout.take().unwrap();
    let backend_in = child.stdin.take().unwrap();

    let (agent_side, gw_agent_read) = tokio::io::duplex(1 << 16);
    let (gw_agent_write, agent_read) = tokio::io::duplex(1 << 16);

    tokio::spawn(async move {
        let gateway = Gateway::new(policy);
        let _ = gateway
            .run(gw_agent_read, gw_agent_write, backend_out, backend_in)
            .await;
        let _ = child.wait().await;
    });

    Agent {
        writer: agent_side,
        reader: BufReader::new(agent_read).lines(),
    }
}

fn names(list: &Value, field: &str, id_field: &str) -> Vec<String> {
    list["result"][field]
        .as_array()
        .unwrap()
        .iter()
        .map(|item| item[id_field].as_str().unwrap().to_string())
        .collect()
}

fn tools_only(allow: &[&str]) -> McpPolicy {
    McpPolicy {
        tools: Visibility::Allow(allow.iter().map(|s| s.to_string()).collect()),
        ..Default::default()
    }
}

/// FW-E2E-013: only granted tools appear in tools/list; the rest are absent, not flagged.
#[tokio::test]
async fn fw_e2e_013_tool_invisibility() {
    let mut agent = start(tools_only(&["read_file"]));
    agent.request(1, "tools/list", json!({})).await;
    let listed = names(&agent.recv().await, "tools", "name");
    assert_eq!(
        listed,
        vec!["read_file"],
        "only the granted tool is visible"
    );
}

/// FW-E2E-014 + FW-ADV-004: an ungranted call is refused as a genuine absence; a hidden-real tool is
/// indistinguishable from a nonexistent one -- no oracle.
#[tokio::test]
async fn fw_e2e_014_adv_004_ungranted_call_refused_no_oracle() {
    let mut agent = start(tools_only(&["read_file"]));

    agent
        .request(
            1,
            "tools/call",
            json!({"name": "http_fetch", "arguments": {}}),
        )
        .await;
    let hidden_real = agent.recv().await;

    agent
        .request(
            2,
            "tools/call",
            json!({"name": "does_not_exist", "arguments": {}}),
        )
        .await;
    let nonexistent = agent.recv().await;

    // Identical but for id and the echoed name, so nothing reveals that http_fetch exists-but-blocked.
    assert!(
        hidden_real["error"].is_object(),
        "hidden-real call must error, not execute"
    );
    assert_eq!(hidden_real["error"]["code"], nonexistent["error"]["code"]);
    let strip = |v: &Value| {
        v["error"]["message"]
            .as_str()
            .unwrap()
            .replace("http_fetch", "X")
            .replace("does_not_exist", "X")
    };
    assert_eq!(
        strip(&hidden_real),
        strip(&nonexistent),
        "refusals must be indistinguishable"
    );
    assert!(!hidden_real["error"]["message"]
        .as_str()
        .unwrap()
        .to_lowercase()
        .contains("denied"));
}

/// FW-E2E-015: resources and prompts are shaded like tools, on both list and fetch.
#[tokio::test]
async fn fw_e2e_015_resource_and_prompt_shading() {
    let policy = McpPolicy {
        resources: Visibility::Allow(vec!["file:///pub".into()]),
        prompts: Visibility::Allow(vec!["greeting".into()]),
        ..Default::default()
    };
    let mut agent = start(policy);

    agent.request(1, "resources/list", json!({})).await;
    assert_eq!(
        names(&agent.recv().await, "resources", "uri"),
        vec!["file:///pub"]
    );

    agent.request(2, "prompts/list", json!({})).await;
    assert_eq!(
        names(&agent.recv().await, "prompts", "name"),
        vec!["greeting"]
    );

    // Ungranted resource read and prompt get are refused.
    agent
        .request(3, "resources/read", json!({"uri": "file:///secret"}))
        .await;
    assert!(agent.recv().await["error"].is_object());

    agent
        .request(
            4,
            "prompts/get",
            json!({"name": "secret_prompt", "arguments": {}}),
        )
        .await;
    assert!(agent.recv().await["error"].is_object());

    // Granted resource read passes through.
    agent
        .request(5, "resources/read", json!({"uri": "file:///pub"}))
        .await;
    let ok = agent.recv().await;
    assert_eq!(ok["result"]["contents"][0]["uri"], "file:///pub");
}

/// FW-E2E-015 (resource templates): templates are shaded by `uriTemplate`, not by `name` (design §4
/// item identity), so a URI-shaped grant governs templates on the same axis as concrete resources.
#[tokio::test]
async fn fw_e2e_015_resource_templates_shaded_by_uri_template() {
    let policy = McpPolicy {
        resources: Visibility::Allow(vec!["file:///logs/{name}".into()]),
        ..Default::default()
    };
    let mut agent = start(policy);

    agent
        .request(1, "resources/templates/list", json!({}))
        .await;
    assert_eq!(
        names(&agent.recv().await, "resourceTemplates", "uriTemplate"),
        vec!["file:///logs/{name}"],
        "only the granted template (matched by uriTemplate) is visible"
    );
}

/// FW-E2E-016: a tool added at runtime (with a list_changed notification) stays shaded.
#[tokio::test]
async fn fw_e2e_016_list_changed_refiltering() {
    let mut agent = start(tools_only(&["read_file"]));

    agent.notify("trigger/list_changed", json!({})).await;
    let changed = agent.recv().await;
    assert_eq!(changed["method"], "notifications/tools/list_changed");

    agent.request(1, "tools/list", json!({})).await;
    let listed = names(&agent.recv().await, "tools", "name");
    assert_eq!(listed, vec!["read_file"], "runtime-added tool stays hidden");

    agent
        .request(
            2,
            "tools/call",
            json!({"name": "new_tool", "arguments": {}}),
        )
        .await;
    assert!(agent.recv().await["error"].is_object());
}

/// FW-E2E-017: a denied server->client sampling request is refused at the gateway and never reaches
/// the agent. The backend observes the refusal (proving it was policed, not dropped).
#[tokio::test]
async fn fw_e2e_017_sampling_policing() {
    let policy = McpPolicy {
        sampling: Gate::Deny,
        ..Default::default()
    };
    let mut agent = start(policy);

    agent.notify("trigger/sampling", json!({})).await;

    // The next thing the agent sees must be the backend's post-refusal note, NOT the sampling request.
    let msg = agent.recv().await;
    assert_eq!(
        msg["method"], "note/sampling_refused",
        "agent must never see the sampling request; backend must see the refusal: got {msg}"
    );
}

/// FW-E2E-018 / FW-GW8: a granted tool call round-trips with no semantic mangling.
#[tokio::test]
async fn fw_e2e_018_transparent_passthrough() {
    let mut agent = start(tools_only(&["read_file"]));
    agent
        .request(
            1,
            "tools/call",
            json!({"name": "read_file", "arguments": {"path": "/x"}}),
        )
        .await;
    let result = agent.recv().await;
    assert_eq!(result["id"], 1);
    assert_eq!(result["result"]["content"][0]["text"], "ok:read_file");
    assert_eq!(result["result"]["isError"], false);
}

/// FW-E2E-017 (allow path): when sampling is permitted, the request passes through to the agent.
#[tokio::test]
async fn fw_e2e_017_sampling_allowed_passes_through() {
    let policy = McpPolicy {
        sampling: Gate::Allow,
        ..Default::default()
    };
    let mut agent = start(policy);
    agent.notify("trigger/sampling", json!({})).await;
    let msg = agent.recv().await;
    assert_eq!(
        msg["method"], "sampling/createMessage",
        "allowed sampling reaches the agent"
    );
}

/// FW-E2E-019 / FW-GW5: a stdio backend the gateway spawns is itself confined to its own grant --
/// here the repo tree, net denied. Its out-of-scope read and direct connect both fail. macOS-only
/// (the confiner is Seatbelt here).
#[cfg(target_os = "macos")]
#[tokio::test]
async fn fw_e2e_019_backend_confinement_recursion() {
    use std::path::Path;
    use std::process::Stdio;

    use formwork_blueprint::{Blueprint, FsBlueprint, NetPosture, PathPattern, ReadMode};
    use formwork_compile::compile;
    use formwork_detect::detect;

    // Grant read of the repo tree (so the fixture binary + cwd load), net denied. /etc/hosts is out.
    let repo_root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap();
    let repo_glob = PathPattern::parse(&format!("{}/**", repo_root.display())).unwrap();
    let backend_blueprint = Blueprint {
        fs: FsBlueprint {
            read_mode: ReadMode::Closed,
            reads: vec![repo_glob],
            writes: vec![],
            subtract: vec![],
        },
        net: NetPosture::Deny,
        ..Blueprint::empty()
    };
    let backend_policy = compile(&backend_blueprint, &detect());

    let std_cmd = formwork_gateway::confined_command(
        env!("CARGO_BIN_EXE_fw-mcp-fixture"),
        &[],
        &backend_policy,
    )
    .expect("build confined backend command");
    let mut cmd = Command::from(std_cmd);
    cmd.stdin(Stdio::piped()).stdout(Stdio::piped());
    let mut child = cmd.spawn().expect("spawn confined fixture");
    let backend_out = child.stdout.take().unwrap();
    let backend_in = child.stdin.take().unwrap();

    let (agent_side, gw_agent_read) = tokio::io::duplex(1 << 16);
    let (gw_agent_write, agent_read) = tokio::io::duplex(1 << 16);
    tokio::spawn(async move {
        let gateway = Gateway::new(McpPolicy::default());
        let _ = gateway
            .run(gw_agent_read, gw_agent_write, backend_out, backend_in)
            .await;
        let _ = child.wait().await;
    });
    let mut agent = Agent {
        writer: agent_side,
        reader: BufReader::new(agent_read).lines(),
    };

    // The confined backend loaded and serves (proving Seatbelt let the ambient toolchain run).
    agent.request(1, "tools/list", json!({})).await;
    assert!(agent.recv().await["result"]["tools"]
        .as_array()
        .unwrap()
        .is_empty());

    // Its out-of-scope read and direct connect are both denied by its own confinement.
    agent
        .notify("trigger/probe", json!({"path": "/etc/hosts"}))
        .await;
    let note = agent.recv().await;
    assert_eq!(note["method"], "note/probe");
    assert_eq!(
        note["params"]["read_ok"], false,
        "backend read outside its grant must be denied"
    );
    assert_eq!(
        note["params"]["net_ok"], false,
        "backend direct egress must be denied"
    );
}
