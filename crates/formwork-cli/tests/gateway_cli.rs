//! End-to-end through the real `formwork gateway` binary: CLI -> blueprint load -> compile ->
//! confine the spawned backend -> shade its MCP surface with a regex allow/deny policy (FW-GW9),
//! driven as an MCP host would. This is the binary-plumbing counterpart to FW-E2E-065..067, which
//! exercise the same shading only at the `Gateway::run` library level.
//!
//! Runs where a real confiner exists -- macOS (Seatbelt) always, Linux (Landlock) when the kernel
//! carries it -- and skips otherwise, never a silent pass. The backend is the repo's stdio fixture,
//! located as a sibling of the `formwork` binary (both land in the same target dir); if it was not
//! built (e.g. `cargo test -p formwork-cli` alone rather than `--workspace`), the test skips.

use std::path::PathBuf;
use std::process::Stdio;
use std::time::Duration;

use serde_json::{json, Value};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader, Lines};
use tokio::process::{ChildStdin, ChildStdout, Command};
use tokio::time::timeout;

async fn send(stdin: &mut ChildStdin, v: Value) {
    stdin.write_all(format!("{v}\n").as_bytes()).await.unwrap();
}

/// Read frames until the one bearing `want` arrives; `None` on EOF or a 30s stall (gateway silent).
async fn recv(lines: &mut Lines<BufReader<ChildStdout>>, want: i64) -> Option<Value> {
    loop {
        match timeout(Duration::from_secs(30), lines.next_line()).await {
            Ok(Ok(Some(l))) => {
                if let Ok(v) = serde_json::from_str::<Value>(&l) {
                    if v.get("id").and_then(Value::as_i64) == Some(want) {
                        return Some(v);
                    }
                }
            }
            _ => return None,
        }
    }
}

fn fixture_path() -> Option<PathBuf> {
    let sib = PathBuf::from(env!("CARGO_BIN_EXE_formwork"))
        .parent()?
        .join("fw-mcp-fixture");
    sib.exists().then_some(sib)
}

fn confiner_available() -> bool {
    let host = formwork_detect::detect();
    if cfg!(target_os = "macos") {
        host.seatbelt
    } else if cfg!(target_os = "linux") {
        host.landlock_abi.is_some()
    } else {
        false
    }
}

/// A confiner-unavailability signal on stderr means "this host can't enforce", a skip -- distinct
/// from a broken gateway, which must fail loudly.
fn is_confiner_gap(stderr: &str) -> bool {
    let s = stderr.to_lowercase();
    [
        "no usable confiner",
        "mechanism promised",
        "not yet implemented",
        "landlock",
    ]
    .iter()
    .any(|needle| s.contains(needle))
}

const BLUEPRINT: &str = r#"
net = "deny"
[fs]
read-mode = "ambient-minus-subtract"
reads = ["/**"]
writes = []
[mcp.patterns]
tools = { allow = ["/.*_file/", "list_dir"], deny = ["/delete_.*/"] }
resources = "deny"
prompts = "deny"
"#;

#[test]
fn fw_e2e_066_gateway_binary_shades_by_pattern() {
    if !confiner_available() {
        eprintln!("skip: no real confiner on this host (needs Seatbelt or Landlock)");
        return;
    }
    let Some(fixture) = fixture_path() else {
        eprintln!("skip: fw-mcp-fixture not built (run via `cargo test --workspace`)");
        return;
    };

    let dir = std::env::temp_dir().join(format!("formwork-gw-cli-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let blueprint = dir.join("patterns.toml");
    std::fs::write(&blueprint, BLUEPRINT).unwrap();

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(drive(&blueprint, &fixture));
    let _ = std::fs::remove_dir_all(&dir);
}

async fn drive(blueprint: &std::path::Path, fixture: &std::path::Path) {
    let mut child = Command::new(env!("CARGO_BIN_EXE_formwork"))
        .args(["gateway", "--blueprint"])
        .arg(blueprint)
        .args(["--server", "patterns", "--"])
        .arg(fixture)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn `formwork gateway`");

    let mut stdin = child.stdin.take().unwrap();
    let mut lines = BufReader::new(child.stdout.take().unwrap()).lines();

    send(&mut stdin, json!({"jsonrpc":"2.0","id":1,"method":"initialize",
        "params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"fw-e2e","version":"0"}}}))
        .await;

    // If initialize never lands, the gateway failed to start. On a confiner-capable host that is a
    // real bug; on one whose mechanism could not install (a partial Linux tier), it is a skip.
    let Some(_init) = recv(&mut lines, 1).await else {
        let mut err = String::new();
        if let Some(mut e) = child.stderr.take() {
            use tokio::io::AsyncReadExt;
            let _ = e.read_to_string(&mut err).await;
        }
        let _ = child.kill().await;
        if is_confiner_gap(&err) {
            eprintln!("skip: gateway could not confine the backend here: {err}");
            return;
        }
        panic!("gateway did not complete initialize; stderr=\n{err}");
    };
    send(
        &mut stdin,
        json!({"jsonrpc":"2.0","method":"notifications/initialized","params":{}}),
    )
    .await;

    // tools/list is shaded to allow-minus-deny: read_file/write_file/list_dir; delete_file (deny) and
    // http_fetch (allow-miss) absent.
    send(
        &mut stdin,
        json!({"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}),
    )
    .await;
    let listed = recv(&mut lines, 2).await.expect("tools/list reply");
    let mut names: Vec<String> = listed["result"]["tools"]
        .as_array()
        .expect("tools array")
        .iter()
        .map(|t| t["name"].as_str().unwrap_or("").to_string())
        .collect();
    names.sort();
    assert_eq!(
        names,
        vec![
            "list_dir".to_string(),
            "read_file".to_string(),
            "write_file".to_string()
        ],
        "binary gateway must shade tools/list by the pattern policy"
    );

    // delete_file matches allow (/.*_file/) but the deny (/delete_.*/) removes it: refused.
    send(
        &mut stdin,
        json!({"jsonrpc":"2.0","id":3,"method":"tools/call",
        "params":{"name":"delete_file","arguments":{}}}),
    )
    .await;
    let denied = recv(&mut lines, 3).await.expect("delete_file reply");
    assert!(
        denied["error"].is_object(),
        "deny must beat the overlapping allow through the binary too: {denied}"
    );

    // A tool the deny does not touch round-trips.
    send(
        &mut stdin,
        json!({"jsonrpc":"2.0","id":4,"method":"tools/call",
        "params":{"name":"read_file","arguments":{}}}),
    )
    .await;
    let ok = recv(&mut lines, 4).await.expect("read_file reply");
    assert_eq!(ok["result"]["content"][0]["text"], "ok:read_file");

    drop(stdin);
    let _ = child.kill().await;
}
