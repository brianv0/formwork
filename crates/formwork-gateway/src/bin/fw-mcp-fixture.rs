//! A minimal stdio MCP backend for gateway tests: newline-delimited JSON-RPC by hand (no SDK). It
//! exposes three tools, two resources, two prompts, and one resource template, and reacts to a few
//! `trigger/*` notifications the tests use to drive runtime behavior:
//!
//! - `trigger/list_changed` -> add `new_tool`, emit `notifications/tools/list_changed` (FW-E2E-016).
//! - `trigger/sampling`     -> issue a server->client `sampling/createMessage`; on the response emit
//!   `note/sampling_refused` or `note/sampling_ok` (FW-E2E-017).
//! - `trigger/probe`        -> attempt an out-of-scope read and a direct TCP connect, reporting both
//!   in a `note/probe` (FW-E2E-019 backend confinement).

use std::io::{self, BufRead, Write};
use std::net::TcpStream;
use std::time::Duration;

use serde_json::{json, Value};

fn emit(value: &Value) {
    let mut out = io::stdout().lock();
    // Explicit flush: stdout is block-buffered when piped, and the gateway reads line-by-line.
    writeln!(out, "{value}").unwrap();
    out.flush().unwrap();
}

fn reply(id: &Option<Value>, result: Value) {
    if let Some(id) = id {
        if !id.is_null() {
            emit(&json!({"jsonrpc": "2.0", "id": id, "result": result}));
        }
    }
}

fn main() {
    let mut tools: Vec<&str> = vec!["read_file", "write_file", "http_fetch"];
    let stdin = io::stdin();

    for line in stdin.lock().lines() {
        let line = match line {
            Ok(l) => l,
            Err(_) => break,
        };
        if line.trim().is_empty() {
            continue;
        }
        let v: Value = match serde_json::from_str(&line) {
            Ok(v) => v,
            Err(_) => continue,
        };
        let method = v.get("method").and_then(Value::as_str);
        let id = v.get("id").cloned();

        match method {
            Some("initialize") => reply(
                &id,
                json!({
                    "protocolVersion": "2024-11-05",
                    "capabilities": {"tools": {"listChanged": true}, "resources": {}, "prompts": {}},
                    "serverInfo": {"name": "fw-mcp-fixture", "version": "0.0.0"}
                }),
            ),
            Some("notifications/initialized") => {}
            Some("ping") => reply(&id, json!({})),
            Some("tools/list") => {
                let arr: Vec<Value> = tools
                    .iter()
                    .map(|t| json!({"name": t, "description": format!("the {t} tool"), "inputSchema": {"type": "object"}}))
                    .collect();
                reply(&id, json!({"tools": arr}));
            }
            Some("tools/call") => {
                let name = v
                    .pointer("/params/name")
                    .and_then(Value::as_str)
                    .unwrap_or("");
                reply(
                    &id,
                    json!({"content": [{"type": "text", "text": format!("ok:{name}")}], "isError": false}),
                );
            }
            Some("resources/list") => reply(
                &id,
                json!({"resources": [
                    {"uri": "file:///pub", "name": "pub"},
                    {"uri": "file:///secret", "name": "secret"}
                ]}),
            ),
            Some("resources/templates/list") => reply(
                &id,
                // Templates carry `uriTemplate` (+ `name`); the gateway shades them by uriTemplate.
                json!({"resourceTemplates": [
                    {"uriTemplate": "file:///logs/{name}", "name": "logs"},
                    {"uriTemplate": "file:///secret/{name}", "name": "secret_tmpl"}
                ]}),
            ),
            Some("resources/read") => {
                let uri = v
                    .pointer("/params/uri")
                    .and_then(Value::as_str)
                    .unwrap_or("");
                reply(
                    &id,
                    json!({"contents": [{"uri": uri, "text": format!("contents of {uri}")}]}),
                );
            }
            Some("prompts/list") => reply(
                &id,
                json!({"prompts": [{"name": "greeting"}, {"name": "secret_prompt"}]}),
            ),
            Some("prompts/get") => {
                let name = v
                    .pointer("/params/name")
                    .and_then(Value::as_str)
                    .unwrap_or("");
                reply(
                    &id,
                    json!({"messages": [{"role": "user", "content": {"type": "text", "text": format!("prompt {name}")}}]}),
                );
            }
            Some("trigger/list_changed") => {
                if !tools.contains(&"new_tool") {
                    tools.push("new_tool");
                }
                emit(&json!({"jsonrpc": "2.0", "method": "notifications/tools/list_changed"}));
            }
            Some("trigger/sampling") => {
                emit(&json!({
                    "jsonrpc": "2.0", "id": "s1", "method": "sampling/createMessage",
                    "params": {"messages": [], "maxTokens": 10}
                }));
            }
            Some("trigger/probe") => {
                let path = v
                    .pointer("/params/path")
                    .and_then(Value::as_str)
                    .unwrap_or("/etc/hosts");
                let read_ok = std::fs::read(path).is_ok();
                let net_ok = "93.184.216.34:80"
                    .parse()
                    .ok()
                    .and_then(|addr| TcpStream::connect_timeout(&addr, Duration::from_secs(3)).ok())
                    .is_some();
                emit(
                    &json!({"jsonrpc": "2.0", "method": "note/probe", "params": {"read_ok": read_ok, "net_ok": net_ok}}),
                );
            }
            // A response to our own sampling request (has an id, no method).
            None if id.as_ref() == Some(&json!("s1")) => {
                let note = if v.get("error").is_some() {
                    "note/sampling_refused"
                } else {
                    "note/sampling_ok"
                };
                emit(&json!({"jsonrpc": "2.0", "method": note}));
            }
            _ => {}
        }
    }
}
