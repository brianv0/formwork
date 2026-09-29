//! The brokered URL open (FW-ISO17, FW-ISO18; FEP-5 §3.4). The Launcher places a Formwork-owned
//! opener shim first in `PATH` and in `BROWSER`; the shim writes each URL, one per line, to a
//! socket the session inherits. This side -- in the `formwork` process, outside the sandbox --
//! accepts `http` and `https` URLs when the blueprint lifts `open-url`, records each on the operator
//! channel, and opens it with the host opener. No host service is lifted on either platform.
//!
//! The transport is one-way: the shim cannot learn the verdict, so a refused URL simply does not
//! open (the confined process sees nothing that distinguishes a refusal), and the operator channel
//! carries the reason with the `explain` invocation that reproduces it (FW-FID9).

use std::io::{BufRead, BufReader, Read};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;

/// The confined environment names the inherited descriptor here.
pub const OPENER_FD_ENV: &str = "FORMWORK_OPENER_FD";

/// The names the shim answers to: the XDG opener, macOS `open`, and the Debian browser
/// alternatives that tools fall back to.
pub const SHIM_NAMES: &[&str] = &[
    "xdg-open",
    "open",
    "sensible-browser",
    "x-www-browser",
    "www-browser",
];

/// URLs kept for `learn`; the operator channel records every one.
const MAX_RECORDS: usize = 1024;

/// URLs longer than this are refused; a login URL is a few hundred bytes.
const MAX_URL: usize = 8 * 1024;

/// The shim, a POSIX shell script: every shell-capable workload can run it, and it needs no grant
/// beyond `/bin/sh`. Flag arguments (`open -g`) are skipped; each other argument is one URL.
///
/// The transport is one-way, so the script cannot hear the Gateway's verdict. It hands every URL
/// over (the Gateway decides, opens, and keeps the record `learn` reads) and mirrors the decision
/// locally: with `lifted` false, or for a URL [`decide`] refuses, it exits 1 with a generic
/// refusal, so the calling program is not told a refused URL opened. Only a host-opener launch
/// failure stays invisible to the session.
pub fn shim_script(lifted: bool) -> String {
    format!(
        r#"#!/bin/sh
# Formwork opener shim (FW-ISO17): hands each URL to Formwork outside the session, which opens
# it in the host browser when the blueprint lifts `open-url` (FW-ISO18). The checks below mirror
# the Gateway's decision so the caller learns of a refusal; the Gateway's decision is the one that
# counts.
LC_ALL=C
export LC_ALL
fd="${{{env}:-}}"
lifted={lifted}
case "$fd" in
  ''|*[!0-9]*) echo "formwork: open-url: the opener is not available in this process" >&2; exit 1 ;;
esac
status=2
for url in "$@"; do
  case "$url" in -*) continue ;; esac
  printf '%s\n' "$url" >&"$fd" 2>/dev/null || {{
    echo "formwork: open-url: the opener is not available in this process" >&2
    exit 1
  }}
  [ "$status" -eq 2 ] && status=0
  ok=$lifted
  case "$url" in
    [hH][tT][tT][pP]://[!/]*|[hH][tT][tT][pP][sS]://[!/]*) ;;
    *) ok=0 ;;
  esac
  case "$url" in *[![:graph:]]*) ok=0 ;; esac
  [ "${{#url}}" -le {max} ] || ok=0
  if [ "$ok" -ne 1 ]; then
    echo "formwork: open-url: refused" >&2
    status=1
  fi
done
[ "$status" -ne 2 ] || echo "usage: $(basename "$0") URL" >&2
exit "$status"
"#,
        env = OPENER_FD_ENV,
        lifted = u8::from(lifted),
        max = MAX_URL,
    )
}

/// One URL the shim handed over, and what became of it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OpenRecord {
    pub url: String,
    /// `None` when opened; otherwise why it was refused.
    pub refused: Option<String>,
}

/// The FW-ISO18 decision, pure: `http` and `https` only, printable ASCII, bounded, and only when
/// the channel is lifted.
pub fn decide(url: &str, lifted: bool) -> Result<(), String> {
    if !lifted {
        return Err("the `open-url` channel is not lifted; add `channels = [\"open-url\"]`".into());
    }
    if url.len() > MAX_URL {
        return Err(format!("the URL is longer than {MAX_URL} bytes"));
    }
    if url.bytes().any(|b| !(0x21..=0x7e).contains(&b)) {
        return Err("the URL carries whitespace, control or non-ASCII bytes".into());
    }
    let scheme = url
        .split_once(':')
        .map(|(s, _)| s.to_ascii_lowercase())
        .unwrap_or_default();
    match scheme.as_str() {
        "http" | "https"
            if url[scheme.len() + 1..]
                .strip_prefix("//")
                .is_some_and(|rest| !rest.is_empty() && !rest.starts_with('/')) =>
        {
            Ok(())
        }
        "http" | "https" => {
            Err("an http(s) URL must carry an authority (`https://host/...`)".into())
        }
        "" => Err("not a URL (no scheme)".into()),
        other => Err(format!(
            "the `{other}:` scheme is refused; only http and https URLs open"
        )),
    }
}

/// The host side of the channel: read URLs until every session copy of the socket is closed.
pub struct OpenerService {
    records: Arc<Mutex<Vec<OpenRecord>>>,
    thread: Option<JoinHandle<()>>,
    /// Disconnects when the serving thread returns.
    done: std::sync::mpsc::Receiver<()>,
}

impl OpenerService {
    /// `host_opener` is run with the URL as its only argument, outside the sandbox.
    pub fn start(stream: UnixStream, lifted: bool, host_opener: PathBuf) -> std::io::Result<Self> {
        let records = Arc::new(Mutex::new(Vec::new()));
        let sink = records.clone();
        let (finished, done) = std::sync::mpsc::channel::<()>();
        let thread = std::thread::Builder::new()
            .name("formwork-opener".into())
            .spawn(move || {
                let _finished = finished;
                serve(stream, lifted, &host_opener, &sink);
            })?;
        Ok(OpenerService {
            records,
            thread: Some(thread),
            done,
        })
    }

    /// Every URL handed over so far.
    pub fn records(&self) -> Vec<OpenRecord> {
        self.records.lock().map(|r| r.clone()).unwrap_or_default()
    }

    /// Wait until the session's copies are closed and every URL is handled.
    pub fn finish(mut self) -> Vec<OpenRecord> {
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
        self.records()
    }

    /// As [`OpenerService::finish`], but give up waiting after `limit`: a process the session
    /// left running may still hold the socket.
    pub fn records_within(&self, limit: std::time::Duration) -> Vec<OpenRecord> {
        let _ = self.done.recv_timeout(limit);
        self.records()
    }
}

fn serve(
    stream: UnixStream,
    lifted: bool,
    host_opener: &std::path::Path,
    sink: &Mutex<Vec<OpenRecord>>,
) {
    let mut reader = BufReader::new(stream);
    let mut line = Vec::new();
    loop {
        line.clear();
        // Bounded read: a line past the cap is consumed and refused, never buffered without limit.
        let n = match (&mut reader)
            .take(MAX_URL as u64 + 2)
            .read_until(b'\n', &mut line)
        {
            Ok(0) | Err(_) => break,
            Ok(n) => n,
        };
        let complete = line.last() == Some(&b'\n');
        if complete {
            line.pop();
        } else if n as u64 >= MAX_URL as u64 + 2 {
            // Drain the rest of the oversize line.
            let mut rest = Vec::new();
            if reader.read_until(b'\n', &mut rest).is_err() {
                break;
            }
        }
        let url = String::from_utf8_lossy(&line).into_owned();
        let verdict = if complete || n as u64 >= MAX_URL as u64 + 2 {
            decide(&url, lifted)
        } else {
            Err("the URL was not terminated".into())
        };
        let refused = match verdict {
            Ok(()) => match Command::new(host_opener)
                .arg(&url)
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
            {
                Ok(mut child) => {
                    tracing::info!(url = %url, "opened a URL for the session (open-url, FW-ISO18)");
                    std::thread::spawn(move || {
                        let _ = child.wait();
                    });
                    None
                }
                Err(e) => {
                    let reason = format!("the host opener {} failed: {e}", host_opener.display());
                    tracing::warn!(url = %url, "{reason}");
                    Some(reason)
                }
            },
            Err(reason) => {
                tracing::warn!(
                    url = %url,
                    reproduce = "formwork explain open-url",
                    "refused open-url: {reason} (FW-ISO18)"
                );
                Some(reason)
            }
        };
        if let Ok(mut r) = sink.lock() {
            // Bounded: the operator line is the record; this list only feeds `learn`.
            if r.len() >= MAX_RECORDS {
                continue;
            }
            r.push(OpenRecord { url, refused });
        }
    }
}

/// The host's own opener: `open` on macOS, `xdg-open` elsewhere.
pub fn host_opener() -> PathBuf {
    if cfg!(target_os = "macos") {
        PathBuf::from("/usr/bin/open")
    } else {
        PathBuf::from("xdg-open")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_http_and_https_open_and_only_when_lifted() {
        assert!(decide("https://example.com/login?x=1", true).is_ok());
        assert!(decide("HTTP://example.com/", true).is_ok());
        for bad in [
            "file:///etc/passwd",
            "javascript:alert(1)",
            "vscode://x",
            "https:example.com",
            "https://",
            "https:///etc/passwd",
            "https://exa mple.com",
            "no-scheme",
        ] {
            assert!(decide(bad, true).is_err(), "{bad}");
        }
        assert!(decide("https://example.com/", false)
            .unwrap_err()
            .contains("not lifted"));
        assert!(decide(&format!("https://x/{}", "a".repeat(MAX_URL)), true).is_err());
    }

    /// The script's local mirror and the Gateway's decision agree on every URL, lifted or not.
    /// (Pointing the handoff at stdout lets the script run without a socket.)
    #[test]
    fn the_shim_mirrors_the_gateway_decision() {
        let urls = [
            "https://example.com/login?x=1".to_string(),
            "HTTP://example.com/".to_string(),
            "file:///etc/passwd".to_string(),
            "javascript:alert(1)".to_string(),
            "vscode://x".to_string(),
            "https:example.com".to_string(),
            "https://".to_string(),
            "https:///path".to_string(),
            "https://exa mple.com".to_string(),
            format!("https://x/{}", "a".repeat(MAX_URL)),
        ];
        for lifted in [true, false] {
            let dir = std::env::temp_dir().join(format!("fw-shim-{}-{lifted}", std::process::id()));
            std::fs::create_dir_all(&dir).unwrap();
            let script = dir.join("xdg-open");
            std::fs::write(&script, shim_script(lifted)).unwrap();
            for url in &urls {
                let out = Command::new("/bin/sh")
                    .arg(&script)
                    .arg(url)
                    .env(OPENER_FD_ENV, "1")
                    .output()
                    .unwrap();
                let shim_ok = out.status.code() == Some(0);
                let gateway_ok = decide(url, lifted).is_ok();
                assert_eq!(shim_ok, gateway_ok, "lifted={lifted} url={:.60}", url);
            }
            let _ = std::fs::remove_dir_all(&dir);
        }
    }

    #[test]
    fn the_service_opens_and_refuses_and_records_each() {
        let dir = std::env::temp_dir().join(format!("fw-opener-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let log = dir.join("opened");
        let fixture = dir.join("opener");
        std::fs::write(
            &fixture,
            format!("#!/bin/sh\nprintf '%s\\n' \"$1\" >> {}\n", log.display()),
        )
        .unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&fixture, std::fs::Permissions::from_mode(0o700)).unwrap();

        let (host, session) = UnixStream::pair().unwrap();
        let service = OpenerService::start(host, true, fixture).unwrap();
        use std::io::Write;
        let mut s = session;
        s.write_all(b"https://example.com/a\nfile:///etc/passwd\n")
            .unwrap();
        drop(s);
        let records = service.finish();
        assert_eq!(records.len(), 2);
        assert_eq!(records[0].refused, None);
        assert!(records[1].refused.as_deref().unwrap().contains("file:"));
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while !log.exists() && std::time::Instant::now() < deadline {
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        assert_eq!(
            std::fs::read_to_string(&log).unwrap(),
            "https://example.com/a\n"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
