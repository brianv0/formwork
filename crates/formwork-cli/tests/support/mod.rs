//! What the black-box `formwork run` tests share: a scratch directory that is both `$HOME` and the
//! launch directory, the built binary with the operator's proxy variables cleared, the
//! exercised-or-say-why rule, and loopback fixtures (a TLS upstream and an operator's CONNECT
//! proxy) built from real sockets on std threads.

#![allow(dead_code)]

use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Arc, Mutex};

pub struct Scratch(PathBuf);

impl Scratch {
    pub fn new(tag: &str) -> Scratch {
        let root = std::env::temp_dir().join(format!("formwork-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        Scratch(std::fs::canonicalize(&root).unwrap())
    }

    pub fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

pub struct Output {
    pub code: i32,
    pub stdout: String,
    pub stderr: String,
}

/// Run the built `formwork` in `dir`, which is also `$HOME`.
pub fn formwork(dir: &Path, args: &[&str], env: &[(&str, &str)]) -> Output {
    formwork_env(dir, args, env, &[])
}

/// As [`formwork`], without the named variables, or any variable whose name starts with one of
/// them followed by `_`.
pub fn formwork_env(dir: &Path, args: &[&str], env: &[(&str, &str)], without: &[&str]) -> Output {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_formwork"));
    for (name, _) in std::env::vars_os() {
        let name = name.to_string_lossy().into_owned();
        if without
            .iter()
            .any(|w| name == *w || name.starts_with(&format!("{w}_")))
        {
            cmd.env_remove(&name);
        }
    }
    cmd.args(args).current_dir(dir).env("HOME", dir);
    // An operator's upstream proxy would carry the Gateway's egress (FW-EGR26); a test that wants
    // one sets it in `env`.
    for var in [
        "HTTPS_PROXY",
        "https_proxy",
        "HTTP_PROXY",
        "http_proxy",
        "NO_PROXY",
        "no_proxy",
    ] {
        cmd.env_remove(var);
    }
    for (k, v) in env {
        cmd.env(k, v);
    }
    let out = cmd.output().expect("running formwork");
    Output {
        code: out.status.code().unwrap_or(-1),
        stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
    }
}

/// A test that cannot exercise its mechanism on this host says so; on a CI runner, where
/// `FW_REQUIRE_EXERCISED=1`, that is a failure rather than a skip.
pub fn not_exercised(reason: &str) {
    if std::env::var("FW_REQUIRE_EXERCISED").as_deref() == Ok("1") {
        panic!("not exercised on a CI runner: {reason}");
    }
    eprintln!("skipping: {reason}");
}

pub fn on_path(tool: &str) -> bool {
    std::env::var_os("PATH")
        .map(|p| std::env::split_paths(&p).any(|d| d.join(tool).is_file()))
        .unwrap_or(false)
}

pub fn host_profile(dir: &Path) -> serde_json::Value {
    let out = formwork(dir, &["explain", "--json"], &[]);
    serde_json::from_str::<serde_json::Value>(&out.stdout).unwrap()["host"].clone()
}

pub fn supervision_host(dir: &Path) -> bool {
    host_profile(dir)["connect-supervision"].as_bool() == Some(true)
}

/// A host that can carry host-scoped egress through the Gateway: the connect supervisor on Linux,
/// Seatbelt on macOS.
pub fn egress_host(dir: &Path) -> bool {
    if cfg!(target_os = "macos") {
        host_profile(dir)["seatbelt"].as_bool() == Some(true)
    } else {
        supervision_host(dir)
    }
}

/// The Sandbox records the unified log has persisted since `since` that satisfy `want`, polled
/// until one does or 30 seconds pass (macOS; the store persists lazily, FW-E2E-064).
pub fn sandbox_records(since: std::time::Instant, want: impl Fn(&str) -> bool) -> Vec<String> {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
    loop {
        let window = since.elapsed().as_secs() + 5;
        let out = Command::new("/usr/bin/log")
            .args([
                "show",
                "--style",
                "ndjson",
                "--last",
                &format!("{window}s"),
                "--predicate",
                r#"sender == "Sandbox""#,
            ])
            .output()
            .expect("running log show");
        let found: Vec<String> = String::from_utf8_lossy(&out.stdout)
            .lines()
            .filter_map(|l| serde_json::from_str::<serde_json::Value>(l).ok())
            .filter_map(|v| v["eventMessage"].as_str().map(str::to_string))
            .filter(|m| want(m))
            .collect();
        if !found.is_empty() || std::time::Instant::now() > deadline {
            return found;
        }
        std::thread::sleep(std::time::Duration::from_secs(1));
    }
}

/// Whether a Sandbox deny record naming `operation` (and `argument`, when given) arrived since
/// `since`.
pub fn denied_since(since: std::time::Instant, operation: &str, argument: &str) -> bool {
    let needle = if argument.is_empty() {
        format!(") {operation}")
    } else {
        format!(") {operation} {argument}")
    };
    !sandbox_records(since, |m| m.contains(" deny(") && m.contains(&needle)).is_empty()
}

/// One request a fixture upstream received: its head, request line first.
#[derive(Clone, Debug)]
pub struct Seen {
    pub head: String,
}

impl Seen {
    pub fn path(&self) -> String {
        self.head.split(' ').nth(1).unwrap_or("").to_string()
    }

    pub fn header(&self, name: &str) -> Option<String> {
        self.head.lines().skip(1).find_map(|l| {
            let (n, v) = l.split_once(':')?;
            n.eq_ignore_ascii_case(name).then(|| v.trim().to_string())
        })
    }
}

/// A test root CA and a leaf it issues for `names` (DNS names or IP addresses), shaped like a
/// real origin's: the leaf carries `serverAuth` and a short validity window. The root's PEM is
/// written to `<dir>/fixture-root.pem` for the operator's `SSL_CERT_FILE` (FEP-6 §7.1: the
/// Gateway's upstream trust comes from its own environment). A self-signed leaf would not do:
/// clients that verify through the platform (pip's `truststore` on macOS) pass only CA
/// certificates from a bundle on as anchors.
pub struct FixtureCert {
    pub root: PathBuf,
    config: Arc<rustls::ServerConfig>,
}

pub fn fixture_cert(dir: &Path, names: &[&str]) -> FixtureCert {
    use rcgen::{
        BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, KeyPair,
        KeyUsagePurpose,
    };
    use std::time::{Duration, SystemTime, UNIX_EPOCH};
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
    let epoch = rcgen::date_time_ymd(1970, 1, 1);
    let day = Duration::from_secs(86_400);
    let window = |params: &mut CertificateParams| {
        params.not_before = epoch + (now - day);
        params.not_after = epoch + (now + 30 * day);
    };

    let ca_key = KeyPair::generate().unwrap();
    let mut ca = CertificateParams::default();
    ca.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    ca.distinguished_name
        .push(DnType::CommonName, "Formwork test fixture root");
    window(&mut ca);
    let ca = ca.self_signed(&ca_key).unwrap();

    let key = KeyPair::generate().unwrap();
    let mut leaf =
        CertificateParams::new(names.iter().map(|n| n.to_string()).collect::<Vec<_>>()).unwrap();
    leaf.distinguished_name.push(DnType::CommonName, names[0]);
    leaf.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    leaf.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    window(&mut leaf);
    let leaf = leaf.signed_by(&key, &ca, &ca_key).unwrap();

    let root = dir.join("fixture-root.pem");
    std::fs::write(&root, ca.pem()).unwrap();
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let config = rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![leaf.der().clone()],
            rustls::pki_types::PrivateKeyDer::Pkcs8(rustls::pki_types::PrivatePkcs8KeyDer::from(
                key.serialize_der(),
            )),
        )
        .unwrap();
    FixtureCert {
        root,
        config: Arc::new(config),
    }
}

/// A TLS upstream on `127.0.0.1` that records every request head and answers one request per
/// connection: `/reflect` echoes the request head in the body, anything else answers
/// `ok:<path>`.
pub struct TlsFixture {
    pub port: u16,
    pub seen: Arc<Mutex<Vec<Seen>>>,
}

impl TlsFixture {
    pub fn start(cert: &FixtureCert) -> TlsFixture {
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        let seen = Arc::new(Mutex::new(Vec::new()));
        let log = seen.clone();
        let config = cert.config.clone();
        std::thread::spawn(move || {
            for tcp in listener.incoming().flatten() {
                let config = config.clone();
                let log = log.clone();
                std::thread::spawn(move || serve_tls(tcp, config, log));
            }
        });
        TlsFixture { port, seen }
    }

    pub fn seen(&self) -> Vec<Seen> {
        self.seen.lock().unwrap().clone()
    }
}

fn serve_tls(tcp: TcpStream, config: Arc<rustls::ServerConfig>, log: Arc<Mutex<Vec<Seen>>>) {
    let _ = tcp.set_read_timeout(Some(std::time::Duration::from_secs(10)));
    let Ok(conn) = rustls::ServerConnection::new(config) else {
        return;
    };
    let mut tls = rustls::StreamOwned::new(conn, tcp);
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    let end = loop {
        if let Some(end) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break end;
        }
        match tls.read(&mut chunk) {
            Ok(0) | Err(_) => return,
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
        }
    };
    let head = String::from_utf8_lossy(&buf[..end]).into_owned();
    let seen = Seen { head: head.clone() };
    let length = seen
        .header("content-length")
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(0);
    while buf.len() < end + 4 + length {
        match tls.read(&mut chunk) {
            Ok(0) | Err(_) => break,
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
        }
    }
    let path = seen.path();
    log.lock().unwrap().push(seen);
    let body = if path.starts_with("/reflect") {
        format!("echo:\n{head}\n")
    } else {
        format!("ok:{path}\n")
    };
    let _ = write!(
        tls,
        "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    let _ = tls.flush();
    tls.conn.send_close_notify();
    let _ = tls.flush();
}

/// An operator's CONNECT proxy on `127.0.0.1`: it records each request line and tunnels a
/// `CONNECT name:port` to `127.0.0.1:<the port `names` maps the name to>`, so the names it carries
/// need no DNS.
pub struct ConnectProxy {
    pub port: u16,
    pub lines: Arc<Mutex<Vec<String>>>,
}

impl ConnectProxy {
    pub fn start(names: BTreeMap<String, u16>) -> ConnectProxy {
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        let lines = Arc::new(Mutex::new(Vec::new()));
        let log = lines.clone();
        std::thread::spawn(move || {
            for mut client in listener.incoming().flatten() {
                let log = log.clone();
                let names = names.clone();
                std::thread::spawn(move || {
                    let mut buf = Vec::new();
                    let mut chunk = [0u8; 1024];
                    while !buf.windows(4).any(|w| w == b"\r\n\r\n") {
                        match client.read(&mut chunk) {
                            Ok(0) | Err(_) => return,
                            Ok(n) => buf.extend_from_slice(&chunk[..n]),
                        }
                    }
                    let head = String::from_utf8_lossy(&buf).into_owned();
                    let line = head.lines().next().unwrap_or("").to_string();
                    log.lock().unwrap().push(line.clone());
                    let authority = line.split(' ').nth(1).unwrap_or("");
                    let name = authority.rsplit_once(':').map(|(h, _)| h).unwrap_or("");
                    let upstream = match (line.starts_with("CONNECT "), names.get(name)) {
                        (true, Some(port)) => TcpStream::connect(("127.0.0.1", *port)).ok(),
                        _ => None,
                    };
                    let Some(upstream) = upstream else {
                        let _ = client.write_all(b"HTTP/1.1 502 Bad Gateway\r\n\r\n");
                        return;
                    };
                    let _ = client.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n");
                    splice(client, upstream);
                });
            }
        });
        ConnectProxy { port, lines }
    }

    pub fn lines(&self) -> Vec<String> {
        self.lines.lock().unwrap().clone()
    }
}

fn splice(a: TcpStream, b: TcpStream) {
    let (mut a_r, mut b_w) = (a.try_clone().unwrap(), b.try_clone().unwrap());
    let forward = std::thread::spawn(move || {
        let _ = std::io::copy(&mut a_r, &mut b_w);
        let _ = b_w.shutdown(std::net::Shutdown::Write);
    });
    let (mut b_r, mut a_w) = (b, a);
    let _ = std::io::copy(&mut b_r, &mut a_w);
    let _ = a_w.shutdown(std::net::Shutdown::Write);
    let _ = forward.join();
}
