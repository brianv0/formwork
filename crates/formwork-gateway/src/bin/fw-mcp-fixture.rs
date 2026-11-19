//! A minimal stdio MCP backend for gateway tests: newline-delimited JSON-RPC by hand (no SDK). It
//! exposes three tools, two resources, two prompts, and two resource templates, and reacts to a few
//! `trigger/*` notifications the tests use to drive runtime behavior:
//!
//! - `trigger/list_changed` -> add `new_tool`, emit `notifications/tools/list_changed` (FW-E2E-016).
//! - `trigger/sampling`     -> issue a server->client `sampling/createMessage`; on the response emit
//!   `note/sampling_refused` or `note/sampling_ok` (FW-E2E-017).
//! - `trigger/probe`        -> attempt an out-of-scope read and a direct TCP connect, reporting both
//!   in a `note/probe` (FW-E2E-019 backend confinement).
//! - `trigger/hold`         -> queue every line instead of writing it, until `trigger/release`
//!   writes the queue (in reverse when `params.reverse`): a test decides when, and in which order,
//!   answers arrive (FW-E2E-203, FW-ADV-056).
//! - `trigger/emit`         -> write `params.line` verbatim: a frame no request asked for.
//! - `trigger/paginate`     -> answer `tools/list` two tools to a page, with a `nextCursor`.
//!
//! An id is echoed as a backend whose numbers are all doubles would echo it (`1.0` comes back as
//! `1`), and a `tools/call` copies `arguments.result_extra` into the top level of its result.

use std::io::{self, BufRead, Write};
use std::net::TcpStream;
use std::sync::Mutex;
use std::time::Duration;

use serde_json::{json, Value};

/// The lines queued since `trigger/hold`; `None` when the fixture writes as it goes.
static HELD: Mutex<Option<Vec<String>>> = Mutex::new(None);

fn write_line(line: &str) {
    let mut out = io::stdout().lock();
    // Explicit flush: stdout is block-buffered when piped, and the gateway reads line-by-line.
    writeln!(out, "{line}").unwrap();
    out.flush().unwrap();
}

fn emit_line(line: String) {
    let mut held = HELD.lock().unwrap();
    match held.as_mut() {
        Some(queue) => queue.push(line),
        None => write_line(&line),
    }
}

fn emit(value: &Value) {
    emit_line(value.to_string());
}

/// The id as a backend that reads every number as a double echoes it: `1.0` and `-0` come back
/// as `1` and `0`, the respelling FW-E2E-203 is about.
fn echoed(id: &Value) -> Value {
    match id.as_f64() {
        Some(f) if id.is_f64() && f.fract() == 0.0 && f.abs() < 9e15 => json!(f as i64),
        _ => id.clone(),
    }
}

fn reply(id: &Option<Value>, result: Value) {
    match id {
        Some(id) if !id.is_null() => {
            emit(&json!({"jsonrpc": "2.0", "id": echoed(id), "result": result}));
        }
        // An id-less call has no reply, so announce that it arrived: a gated call the gateway
        // should have dropped then shows up at the agent (FW-ADV-016).
        _ => emit(&json!({
            "jsonrpc": "2.0",
            "method": "notifications/message",
            "params": {"level": "info", "data": "fixture received an id-less call"}
        })),
    }
}

fn main() {
    // A spread of prefixes so pattern shading (FW-GW9) has distinct families to allow/deny across.
    let mut tools: Vec<&str> = vec![
        "read_file",
        "list_dir",
        "write_file",
        "delete_file",
        "http_fetch",
    ];
    let mut paginate = false;
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
                if paginate {
                    // The cursor is the index of the page's first tool.
                    let start = v
                        .pointer("/params/cursor")
                        .and_then(Value::as_str)
                        .and_then(|c| c.parse::<usize>().ok())
                        .unwrap_or(0)
                        .min(arr.len());
                    let end = (start + 2).min(arr.len());
                    let mut page = json!({"tools": arr[start..end]});
                    if end < arr.len() {
                        page["nextCursor"] = json!(end.to_string());
                    }
                    reply(&id, page);
                } else {
                    reply(&id, json!({"tools": arr}));
                }
            }
            Some("tools/call") => {
                let name = v
                    .pointer("/params/name")
                    .and_then(Value::as_str)
                    .unwrap_or("");
                let mut result = json!({"content": [{"type": "text", "text": format!("ok:{name}")}], "isError": false});
                if let Some(extra) = v
                    .pointer("/params/arguments/result_extra")
                    .and_then(Value::as_object)
                {
                    for (key, value) in extra {
                        result[key.as_str()] = value.clone();
                    }
                }
                reply(&id, result);
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
            Some("resources/subscribe") | Some("resources/unsubscribe") => reply(&id, json!({})),
            Some("completion/complete") => {
                let values = v
                    .pointer("/params/ref/name")
                    .or_else(|| v.pointer("/params/ref/uri"))
                    .and_then(Value::as_str)
                    .unwrap_or("");
                reply(
                    &id,
                    json!({"completion": {"values": [format!("completed:{values}")], "total": 1}}),
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
            Some("trigger/hold") => {
                HELD.lock().unwrap().get_or_insert_with(Vec::new);
            }
            Some("trigger/release") => {
                let mut queue = HELD.lock().unwrap().take().unwrap_or_default();
                if v.pointer("/params/reverse") == Some(&json!(true)) {
                    queue.reverse();
                }
                for line in queue {
                    write_line(&line);
                }
            }
            Some("trigger/emit") => {
                if let Some(line) = v.pointer("/params/line").and_then(Value::as_str) {
                    emit_line(line.to_owned());
                }
            }
            Some("trigger/paginate") => paginate = true,
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
