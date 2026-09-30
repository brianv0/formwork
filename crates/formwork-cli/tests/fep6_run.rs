//! FEP-6 black-box tests of `formwork run`: the egress engine at the real boundary -- the connect
//! supervisor routes a confined client's connection to the Gateway, the Launcher's variables steer
//! real clients (curl, Python, Node, git, pip, npm) through it, and the engine inspects, brokers,
//! resolves with the host's own resolver, and leaves through the operator's upstream proxy. Each
//! drives the built binary with `$HOME` and the launch directory pinned inside a scratch directory;
//! upstreams are loopback fixtures whose root the operator's `SSL_CERT_FILE` names (FEP-6 §7.1).

mod support;

#[cfg(target_os = "linux")]
use std::collections::BTreeMap;
#[cfg(target_os = "linux")]
use std::path::Path;

use support::*;

#[cfg(target_os = "linux")]
fn blueprint(dir: &Path, rules: &[String], extra: &str) {
    let rules: Vec<String> = std::iter::once("\"readwrite:$CWD/**\"".to_string())
        .chain(rules.iter().map(|r| format!("{r:?}")))
        .collect();
    std::fs::write(
        dir.join("FORMWORK.toml"),
        format!(
            "extends = [\"builtin:default\"]\nrules = [{}]\n{extra}",
            rules.join(", ")
        ),
    )
    .unwrap();
}

/// A session with the connect supervisor and the named tools, or a stated reason why not.
#[cfg(target_os = "linux")]
fn session_host(dir: &Path, tools: &[&str]) -> bool {
    if !supervision_host(dir) {
        not_exercised("connect supervision unavailable");
        return false;
    }
    if let Some(missing) = tools.iter().find(|t| !on_path(t)) {
        not_exercised(&format!("{missing} unavailable"));
        return false;
    }
    true
}

/// FW-E2E-098 (Linux; FEP-6 S1 rows 1, 8 and 9, and `FW-EGR24`): under `allow:` a client that
/// trusts the session bundle reaches the upstream through inspection -- the leaf is minted for an
/// IP literal and name-constrained to it (FW-EGR25), and the Gateway verifies the upstream against
/// the operator's `SSL_CERT_FILE`. Without that root the Gateway refuses the upstream: it never
/// trusts its own session bundle. A client that ignores the bundle fails its handshake and the
/// operator line names the `tunnel:` rule; under that rule the same client gets through.
#[cfg(target_os = "linux")]
#[test]
fn fw_e2e_098_inspected_https_through_run() {
    let dir = Scratch::new("fep6-inspect");
    if !session_host(dir.path(), &["curl"]) {
        return;
    }
    let cert = fixture_cert(dir.path(), &["127.0.0.1"]);
    let up = TlsFixture::start(&cert);
    let root = cert.root.to_str().unwrap();
    let url = format!("https://127.0.0.1:{}/ok", up.port);
    blueprint(dir.path(), &[format!("allow:127.0.0.1:{}", up.port)], "");
    let inspected = formwork(
        dir.path(),
        &["run", "--", "curl", "-sS", "-m", "10", &url],
        &[("SSL_CERT_FILE", root)],
    );
    assert_eq!(inspected.code, 0, "{}", inspected.stderr);
    assert_eq!(inspected.stdout, "ok:/ok\n");
    assert_eq!(up.seen().len(), 1);

    let untrusted = formwork(
        dir.path(),
        &["run", "--", "curl", "-sS", "-m", "10", &url],
        &[],
    );
    assert!(!untrusted.stdout.contains("ok:"), "{}", untrusted.stdout);
    assert!(
        untrusted.stderr.contains("reason=\"upstream-tls\""),
        "{}",
        untrusted.stderr
    );
    assert_eq!(
        up.seen().len(),
        1,
        "no request reached an unverified upstream"
    );

    let rejecting = formwork(
        dir.path(),
        &[
            "run", "--", "curl", "-sS", "-m", "10", "--cacert", root, &url,
        ],
        &[("SSL_CERT_FILE", root)],
    );
    assert_eq!(rejecting.code, 60, "{}", rejecting.stderr);
    assert!(
        rejecting
            .stderr
            .contains(&format!("tunnel:127.0.0.1:{}", up.port)),
        "the operator line names the tunnel rule (FW-FID9): {}",
        rejecting.stderr
    );
    assert_eq!(up.seen().len(), 1);

    blueprint(dir.path(), &[format!("tunnel:127.0.0.1:{}", up.port)], "");
    let tunneled = formwork(
        dir.path(),
        &[
            "run", "--", "curl", "-sS", "-m", "10", "--cacert", root, &url,
        ],
        &[],
    );
    assert_eq!(tunneled.code, 0, "{}", tunneled.stderr);
    assert_eq!(tunneled.stdout, "ok:/ok\n");
}

/// Node reads the proxy variables only with `NODE_USE_ENV_PROXY`, from 22.21 on the 22 line and
/// 24.5 on the 24 line (FEP-6 §4.11); older Node connects directly and is refused.
#[cfg(target_os = "linux")]
fn node_uses_env_proxy() -> bool {
    let out = std::process::Command::new("node")
        .arg("--version")
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).into_owned())
        .unwrap_or_default();
    let v: Vec<u32> = out
        .trim()
        .trim_start_matches('v')
        .split('.')
        .filter_map(|p| p.parse().ok())
        .collect();
    match v.as_slice() {
        [major, minor, ..] => {
            (*major == 22 && *minor >= 21) || (*major == 24 && *minor >= 5) || *major >= 25
        }
        _ => false,
    }
}

/// FW-E2E-094 (Linux): the client matrix. Each client on the runner fetches from an inspected host
/// and a tunnel host with nothing but the variables the Launcher sets (FEP-6 §4.11): the proxy
/// variables in both spellings, `NODE_USE_ENV_PROXY`, and the trust variables. The hosts are names
/// the operator's proxy fixture carries (FW-EGR26), not loopback addresses, which several clients
/// (npm among them) never send through a proxy. The matrix below is the recorded expectation; a
/// client absent from the runner is listed as absent, and curl and Python are required.
#[cfg(target_os = "linux")]
#[test]
fn fw_e2e_094_client_matrix() {
    let dir = Scratch::new("fep6-matrix");
    if !session_host(dir.path(), &["curl", "python3"]) {
        return;
    }
    let cert = fixture_cert(dir.path(), &["inspected.test", "tunnel.test"]);
    let inspected = TlsFixture::start(&cert);
    let tunneled = TlsFixture::start(&cert);
    let proxy = ConnectProxy::start(BTreeMap::from([
        ("inspected.test".to_string(), inspected.port),
        ("tunnel.test".to_string(), tunneled.port),
    ]));
    blueprint(
        dir.path(),
        &[
            format!("allow:inspected.test:{}", inspected.port),
            format!("tunnel:tunnel.test:{}", tunneled.port),
        ],
        "",
    );
    // Whether the session's Python has `requests`: a user-site install under the operator's
    // `$HOME` is not the session's.
    let requests_present = std::process::Command::new("python3")
        .args(["-c", "import requests"])
        .env("HOME", dir.path())
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    let node_proxy = node_uses_env_proxy();
    let proxy_url = format!("http://127.0.0.1:{}", proxy.port);
    let root = cert.root.to_str().unwrap().to_string();
    // (client, the tool it needs, whether it is expected to reach the fixture, command for a URL)
    type Invocation = fn(&str) -> String;
    // Go builds outside the session, once: a cold build inside would compile the standard
    // library into the session's cache.
    let go_client = dir.path().join("go-get");
    if on_path("go") {
        std::fs::write(
            dir.path().join("go-get.go"),
            "package main\n\nimport (\n\t\"fmt\"\n\t\"io\"\n\t\"net/http\"\n\t\"os\"\n)\n\n\
             func main() {\n\tr, err := http.Get(os.Args[1])\n\tif err != nil {\n\t\t\
             fmt.Println(err)\n\t\tos.Exit(1)\n\t}\n\tb, _ := io.ReadAll(r.Body)\n\t\
             fmt.Print(string(b))\n}\n",
        )
        .unwrap();
        let built = std::process::Command::new("go")
            .args(["build", "-o"])
            .arg(&go_client)
            .arg(dir.path().join("go-get.go"))
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        assert!(built, "building the Go client failed");
    }
    let clients: [(&str, &str, bool, Invocation); 10] = [
        ("curl", "curl", true, |u| format!("curl -sS -m 10 {u}")),
        ("python-urllib", "python3", true, |u| {
            format!(
                "python3 -c 'import sys, urllib.request; \
                 print(urllib.request.urlopen(sys.argv[1], timeout=10).read().decode())' {u}"
            )
        }),
        ("python-requests", "python3", true, |u| {
            format!(
                "python3 -c 'import sys, requests; print(requests.get(sys.argv[1], timeout=10).text)' {u}"
            )
        }),
        ("node-fetch", "node", node_proxy, |u| {
            format!(
                "node -e 'fetch(process.argv[1]).then(r => r.text()).then(t => console.log(t))' {u}"
            )
        }),
        ("node-https", "node", node_proxy, |u| {
            format!(
                "node -e 'require(\"https\").get(process.argv[1], r => {{ let d = \"\"; \
                 r.on(\"data\", c => d += c); r.on(\"end\", () => console.log(d)); }})' {u}"
            )
        }),
        ("git", "git", true, |u| {
            format!("git ls-remote {u}/repo.git")
        }),
        ("pip", "pip", true, |u| {
            format!(
                "pip download --no-deps --no-cache-dir --disable-pip-version-check --retries 0 \
                 --timeout 10 -d \"$TMPDIR/dl\" --index-url {u}/simple/ fixture-pkg"
            )
        }),
        ("npm", "npm", true, |u| {
            format!("npm view --no-update-notifier --fetch-retries=0 --registry {u}/ fixture-pkg")
        }),
        ("go", "go", true, |u| format!("./go-get {u}")),
        ("uv", "uv", true, |u| {
            format!("echo fixture-pkg | uv pip compile --no-cache --index-url {u}/simple/ -")
        }),
    ];
    let mut matrix = Vec::new();
    let mut mismatches = Vec::new();
    for (grade, host, fixture) in [
        ("inspected", "inspected.test", &inspected),
        ("tunnel", "tunnel.test", &tunneled),
    ] {
        for (client, tool, expected, command) in clients {
            if !on_path(tool) || (client == "python-requests" && !requests_present) {
                matrix.push(format!("{client:16} {grade:9} absent"));
                continue;
            }
            let path = format!("/{grade}/{client}");
            let url = format!("https://{host}:{}{path}", fixture.port);
            let out = formwork_env(
                dir.path(),
                &[
                    "run",
                    "--",
                    "/bin/sh",
                    "-c",
                    &format!("{} 2>&1", command(&url)),
                ],
                // An operator's npm proxy setting, which npm prefers to `https_proxy`; the
                // Launcher must override it too (FEP-6 §4.11).
                &[
                    ("SSL_CERT_FILE", &root),
                    ("https_proxy", &proxy_url),
                    ("npm_config_https_proxy", "http://127.0.0.1:1"),
                ],
                // The operator's environment may configure git through GIT_CONFIG_COUNT and
                // GIT_CONFIG_KEY_n/VALUE_n; the FW-ENV2 scrub strips the KEY_n names alone, which
                // leaves git unable to start. That is the Launcher's defect, not a client result.
                &["GIT_CONFIG_COUNT"],
            );
            let reached = fixture.seen().iter().any(|s| s.path().starts_with(&path));
            matrix.push(format!(
                "{client:16} {grade:9} {}",
                if reached { "reached" } else { "refused" }
            ));
            if reached != expected {
                mismatches.push(format!(
                    "{client} ({grade}): expected {}, got {}\n{}\n{}",
                    if expected { "reached" } else { "refused" },
                    if reached { "reached" } else { "refused" },
                    out.stdout,
                    out.stderr
                ));
            }
        }
    }
    eprintln!("FW-E2E-094 client matrix:\n  {}", matrix.join("\n  "));
    assert!(mismatches.is_empty(), "{}", mismatches.join("\n---\n"));
}

/// FW-E2E-099 (Linux; FEP-6 S2 through `run`): a brokered credential end to end. The session holds
/// a placeholder; the Gateway puts the real key in its header on the bound host -- substituted, or
/// added when absent, never on OPTIONS (FW-CRED18) -- refuses the placeholder toward another host,
/// and ends a response that echoes the key (FW-CRED17). The key appears nowhere the session can
/// see. The other host is `localhost`, reached through the host's own resolver (FW-EGR19).
#[cfg(target_os = "linux")]
#[test]
fn fw_e2e_099_a_brokered_request_through_run() {
    let dir = Scratch::new("fep6-broker");
    if !session_host(dir.path(), &["curl"]) {
        return;
    }
    let cert = fixture_cert(dir.path(), &["127.0.0.1", "localhost"]);
    let model = TlsFixture::start(&cert);
    let other = TlsFixture::start(&cert);
    blueprint(
        dir.path(),
        &[
            format!("allow:127.0.0.1:{}", model.port),
            format!("allow:localhost:{}", other.port),
        ],
        "allow-credentials = [{ name = \"model-fixture\", env = \"FIXTURE_MODEL_KEY\", \
         hosts = [\"127.0.0.1\"], scheme = \"header:x-api-key\" }]\n",
    );
    let secret = "fixture-secret-7d4c1e9a0b3f5a2c";
    let (m, o) = (model.port, other.port);
    let script = format!(
        r#"printf 'env=%s\n' "$FIXTURE_MODEL_KEY"
curl -sS -m 10 -H "x-api-key: $FIXTURE_MODEL_KEY" https://127.0.0.1:{m}/v1
curl -sS -m 10 https://127.0.0.1:{m}/v2
curl -sS -m 10 -X OPTIONS -H "x-api-key: $FIXTURE_MODEL_KEY" https://127.0.0.1:{m}/v3
curl -sS -m 10 -H "x-api-key: $FIXTURE_MODEL_KEY" https://localhost:{o}/leak
curl -sS -m 10 https://localhost:{o}/plain
curl -sS -m 10 -H "x-api-key: $FIXTURE_MODEL_KEY" https://127.0.0.1:{m}/reflect; echo "reflect=$?"
"#
    );
    let out = formwork(
        dir.path(),
        &["run", "--", "/bin/sh", "-c", &script],
        &[
            ("SSL_CERT_FILE", cert.root.to_str().unwrap()),
            ("FIXTURE_MODEL_KEY", secret),
        ],
    );
    assert_eq!(out.code, 0, "{}", out.stderr);
    assert!(
        out.stdout.contains("env=fwcred-model-fixture-"),
        "{}",
        out.stdout
    );
    for body in [
        "ok:/v1",
        "ok:/v2",
        "ok:/v3",
        "ok:/plain",
        "denied by formwork policy",
    ] {
        assert!(out.stdout.contains(body), "{body}: {}", out.stdout);
    }
    assert!(!out.stdout.contains("reflect=0"), "{}", out.stdout);
    let seen = model.seen();
    let key = |path: &str| {
        seen.iter()
            .find(|s| s.path() == path)
            .unwrap_or_else(|| panic!("{path} did not arrive: {seen:?}"))
            .header("x-api-key")
    };
    assert_eq!(key("/v1").as_deref(), Some(secret), "substituted");
    assert_eq!(key("/v2").as_deref(), Some(secret), "added when absent");
    assert_eq!(key("/v3"), None, "never on OPTIONS");
    assert_eq!(
        other.seen().iter().map(|s| s.path()).collect::<Vec<_>>(),
        vec!["/plain".to_string()],
        "the placeholder never reached the other host"
    );
    for reason in ["placeholder", "reflection"] {
        assert!(
            out.stderr.contains(&format!("reason=\"{reason}\"")),
            "{reason}: {}",
            out.stderr
        );
    }
    assert!(!out.stdout.contains(secret), "{}", out.stdout);
    assert!(!out.stderr.contains(secret), "{}", out.stderr);
    for entry in walk(dir.path()) {
        let bytes = std::fs::read(&entry).unwrap_or_default();
        assert!(
            !bytes.windows(secret.len()).any(|w| w == secret.as_bytes()),
            "{} holds the key",
            entry.display()
        );
    }
}

#[cfg(target_os = "linux")]
fn walk(dir: &Path) -> Vec<std::path::PathBuf> {
    let mut out = Vec::new();
    for entry in std::fs::read_dir(dir).into_iter().flatten().flatten() {
        let path = entry.path();
        if path.is_dir() {
            out.extend(walk(&path));
        } else {
            out.push(path);
        }
    }
    out
}

/// FW-EGR17 / FW-EGR19 (Linux): the production resolver. An exact-name rule reaches a loopback
/// answer of the host's own resolver; a name that does not resolve is refused as `resolution`
/// before any upstream socket.
#[cfg(target_os = "linux")]
#[test]
fn fw_egr17_the_host_resolver_decides_through_run() {
    let dir = Scratch::new("fep6-resolve");
    if !session_host(dir.path(), &["curl"]) {
        return;
    }
    let cert = fixture_cert(dir.path(), &["localhost"]);
    let up = TlsFixture::start(&cert);
    blueprint(
        dir.path(),
        &[
            format!("allow:localhost:{}", up.port),
            "allow:no-such-host.invalid".to_string(),
        ],
        "",
    );
    let script = format!(
        "curl -sS -m 15 https://localhost:{}/named; \
         curl -sS -m 15 https://no-such-host.invalid/; echo \"invalid=$?\"",
        up.port
    );
    let out = formwork(
        dir.path(),
        &["run", "--", "/bin/sh", "-c", &script],
        &[("SSL_CERT_FILE", cert.root.to_str().unwrap())],
    );
    assert!(
        out.stdout.contains("ok:/named"),
        "{}\n{}",
        out.stdout,
        out.stderr
    );
    assert!(out.stdout.contains("invalid=56"), "{}", out.stdout);
    assert!(
        out.stderr.contains("reason=\"resolution\""),
        "{}",
        out.stderr
    );
}

/// FW-E2E-103 (Linux; FEP-6 S6 rows 1, 2 and 4, `FW-EGR26`): `formwork run`'s own proxy variables
/// send admitted egress through the operator's proxy -- the lowercase spelling winning, as curl
/// reads it -- while `NO_PROXY` exempts the intranet, which the Gateway resolves itself; `explain
/// --hosts` reports the proxied host's address classification `Partial`.
#[cfg(target_os = "linux")]
#[test]
fn fw_e2e_103_the_operators_upstream_proxy_through_run() {
    let dir = Scratch::new("fep6-proxy");
    if !session_host(dir.path(), &["curl"]) {
        return;
    }
    let cert = fixture_cert(dir.path(), &["model.test"]);
    let up = TlsFixture::start(&cert);
    let proxy = ConnectProxy::start(BTreeMap::from([("model.test".to_string(), up.port)]));
    blueprint(
        dir.path(),
        &[
            format!("allow:model.test:{}", up.port),
            format!("allow:git.corp.test:{}", up.port),
        ],
        "",
    );
    let proxy_url = format!("http://127.0.0.1:{}", proxy.port);
    let env = [
        ("SSL_CERT_FILE", cert.root.to_str().unwrap()),
        ("https_proxy", proxy_url.as_str()),
        ("HTTPS_PROXY", "http://127.0.0.1:1"),
        ("no_proxy", ".corp.test"),
    ];
    let script = format!(
        "curl -sS -m 10 https://model.test:{0}/through; \
         curl -sS -m 10 https://git.corp.test:{0}/corp; echo \"corp=$?\"",
        up.port
    );
    let out = formwork(dir.path(), &["run", "--", "/bin/sh", "-c", &script], &env);
    assert!(
        out.stdout.contains("ok:/through"),
        "{}\n{}",
        out.stdout,
        out.stderr
    );
    assert!(out.stdout.contains("corp=56"), "{}", out.stdout);
    assert_eq!(
        proxy.lines(),
        vec![format!("CONNECT model.test:{} HTTP/1.1", up.port)],
        "only the proxied host went through the proxy"
    );
    assert!(
        out.stderr.contains("reason=\"resolution\""),
        "the exempt intranet name was resolved here, not by the proxy: {}",
        out.stderr
    );

    let explained = formwork(dir.path(), &["explain", "--hosts", "--json"], &env);
    assert_eq!(explained.code, 0, "{}", explained.stderr);
    let v: serde_json::Value = serde_json::from_str(&explained.stdout).unwrap();
    let verdict = |host: &str| {
        v["hosts"]
            .as_array()
            .unwrap()
            .iter()
            .find(|h| h["host"] == host)
            .map(|h| h["classification"]["verdict"].clone())
    };
    assert_eq!(verdict("model.test"), Some("partial".into()), "{v}");
    assert_eq!(verdict("git.corp.test"), Some("enforced".into()), "{v}");
    assert!(
        v["upstream-proxy"]
            .as_str()
            .is_some_and(|p| p.contains(&format!("127.0.0.1:{}", proxy.port))),
        "{v}"
    );
}

/// FEP-6 §9 (j), `learn` (Linux): a host whose client rejected the session CA is never proposed
/// as a `tunnel:` rule beside its inspected one (FW-BP14 would refuse the pair); the learning run
/// names the rule to swap in, apart from the proposals.
#[cfg(target_os = "linux")]
#[test]
fn learn_names_the_tunnel_rule_a_rejecting_client_needs() {
    let dir = Scratch::new("fep6-learn");
    if !session_host(dir.path(), &["curl", "strace"]) {
        return;
    }
    let cert = fixture_cert(dir.path(), &["127.0.0.1"]);
    let up = TlsFixture::start(&cert);
    blueprint(dir.path(), &[format!("allow:127.0.0.1:{}", up.port)], "");
    let root = cert.root.to_str().unwrap();
    let url = format!("https://127.0.0.1:{}/x", up.port);
    let learned = formwork(
        dir.path(),
        &[
            "learn", "--", "curl", "-sS", "-m", "10", "--cacert", root, &url,
        ],
        &[("SSL_CERT_FILE", root)],
    );
    assert!(
        learned.stderr.contains(&format!(
            "replace the host's inspected rule with `tunnel:127.0.0.1:{}`",
            up.port
        )),
        "{}",
        learned.stderr
    );
    let list = formwork(dir.path(), &["learn", "--list"], &[]);
    assert!(!list.stdout.contains("tunnel:"), "{}", list.stdout);
}

#[cfg(target_os = "linux")]
const BROKERED: &str = "extends = [\"builtin:default\"]\n\
                        rules = [\"readwrite:$CWD/**\", \"get,post:api.anthropic.com\"]\n\
                        allow-credentials = [\"broker:anthropic\"]\n";

/// FW-CRED16 (Linux): while it brokers a credential, the `formwork` process is not dumpable, so
/// its `/proc` entries belong to root and a same-uid process cannot read its environment.
#[cfg(target_os = "linux")]
#[test]
fn fw_cred16_the_gateway_is_not_dumpable_while_it_brokers() {
    use std::os::unix::fs::MetadataExt;
    let dir = Scratch::new("fep6-custody");
    if !supervision_host(dir.path()) {
        not_exercised("connect supervision unavailable");
        return;
    }
    // SAFETY: geteuid has no preconditions.
    if unsafe { libc::geteuid() } == 0 {
        not_exercised("running as root, which owns every /proc entry either way");
        return;
    }
    std::fs::write(dir.path().join("FORMWORK.toml"), BROKERED).unwrap();
    let mut child = std::process::Command::new(env!("CARGO_BIN_EXE_formwork"))
        .args(["run", "--", "/bin/sh", "-c", "sleep 2"])
        .current_dir(dir.path())
        .env("HOME", dir.path())
        .env("ANTHROPIC_API_KEY", "sk-custody-fixture")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .unwrap();
    let environ = std::path::PathBuf::from(format!("/proc/{}/environ", child.id()));
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    let mut owner = None;
    while std::time::Instant::now() < deadline {
        if let Ok(m) = std::fs::metadata(&environ) {
            owner = Some(m.uid());
            if m.uid() == 0 {
                break;
            }
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    let read = std::fs::read(&environ);
    let _ = child.wait();
    assert_eq!(
        owner,
        Some(0),
        "the Gateway's /proc entries stayed the user's"
    );
    assert!(
        read.is_err(),
        "a same-uid process read the Gateway's environment"
    );
}

/// FW-E2E-104 (FEP-6 S8): blueprints the compiler refuses, each naming the lines at fault, and the
/// near misses it accepts.
#[test]
fn fw_e2e_104_blueprints_the_compiler_refuses() {
    let dir = Scratch::new("fep6-s8");
    let cases: &[(&str, bool, &[&str])] = &[
        (
            "rules = [\"tunnel:api.github.com\", \"get:api.github.com/repos/**\"]",
            false,
            &["tunnel:api.github.com", "get:api.github.com/repos/**"],
        ),
        (
            "rules = [\"tunnel:github.com\"]\nallow-credentials = [\"broker:github\"]",
            false,
            &["allow:github.com", "allow:api.github.com"],
        ),
        (
            "rules = [\"get:status.corp.internal:80/**\"]\nallow-credentials = [{ name = \"status\", env = \"STATUS_TOKEN\", hosts = [\"status.corp.internal\"], scheme = \"bearer\" }]",
            false,
            &["get:status.corp.internal:80"],
        ),
        (
            "net = { ports = [443] }\nrules = [\"allow:api.anthropic.com\"]",
            false,
            &["port tier"],
        ),
        (
            "rules = [\"tunnel:api.github.com\", \"deny:api.github.com/repos/acme/secret/**\"]",
            false,
            &["not inspected"],
        ),
        ("rules = [\"allow:*\"]", false, &["a host target is"]),
        (
            "rules = [\"tunnel:api.anthropic.com/v1/**\"]",
            false,
            &["allow:api.anthropic.com/v1/**"],
        ),
        ("rules = [\"allow:build/**\"]", false, &["no dot"]),
        (
            "rules = [\"tunnel:internal.corp.example:8443\", \"allow:internal.corp.example\"]",
            true,
            &[],
        ),
        ("rules = [\"deny:telemetry.example.com\"]", true, &[]),
    ];
    for (i, (lines, compiles, named)) in cases.iter().enumerate() {
        let file = dir.path().join(format!("s8-{i}.toml"));
        std::fs::write(&file, format!("{lines}\n")).unwrap();
        let out = formwork(
            dir.path(),
            &[
                "compile",
                "--report-only",
                "--blueprint",
                file.to_str().unwrap(),
            ],
            &[],
        );
        assert_eq!(out.code == 0, *compiles, "{lines}: {}", out.stderr);
        for n in *named {
            assert!(
                out.stderr.contains(n),
                "{lines}: expected {n:?} in {}",
                out.stderr
            );
        }
    }
}
