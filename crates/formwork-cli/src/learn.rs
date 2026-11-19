//! `formwork learn` and its `--list`/`--accept` review -- observe-then-widen discovery (FEP-2 Part D).
//!
//! A learning run is an ENFORCED run plus observation: the policy is compiled and installed
//! exactly as `run` would (FW-INV10 -- observation never weakens the live session), and the
//! denials the kernel produced during the run are collected and reverse-compiled into a proposal
//! (FW-DISC2). Two feeds exist (FW-XR6 parity on the discovery axis):
//!
//! - **macOS**: the unified log's Sandbox records, read live with `log stream` attached before the
//!   workload starts and post-hoc with `log show` over the run window, so neither the stream's
//!   startup nor the store's persistence latency loses a record. Attribution is the run window plus
//!   dedup -- deliberately tolerant of
//!   over-capture, because a candidate has no effect until accepted (FW-INV10), credentials are
//!   floored regardless (FW-DISC3), and everything else waits for review.
//! - **Linux**: the workload runs under an *unconfined* `strace` ancestor (FW-E2E-071) that
//!   traces a `run --confine-self` shim; denied file syscalls (`= -1 EACCES/EPERM`) are the
//!   kernel's Landlock denials. Attribution is exact -- only this run's process tree is traced --
//!   and the trace is complete when the tracee exits, so no persistence latency exists to poll
//!   away.
//!
//! On hosts with neither feed, learning says so loudly and proposes nothing -- never a silent
//! pretend (FW-INV5/6, FW-XR9).
//!
//! Beyond paths, a learning run proposes host rules from the Gateway's refusals and channels from
//! the opener shim's and the connect supervisor's refusals (FW-DISC12). These always wait for
//! review: the auto-widen zone is a filesystem notion.

use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};

use formwork_blueprint::{
    propose_channels, propose_host_rules, reverse_compile, Blueprint, BlueprintLayer, Candidate,
    CandidateTag, Channel, ChannelPolicy, DenialAccess, DenialRecord, EgressObservation,
    LauncherDeny, ProvenanceEntry, ResolvedCatalog,
};

/// The reviewable proposal artifact (FW-DISC5). Candidates only: withheld credential matches are
/// operator-channel material and never written here -- the file may sit inside the confined
/// grant, and itemizing catalog matches in it would hand the agent an oracle (FW-INV9).
/// Unreviewed entries ACCUMULATE across learning runs (each stamped with the run that observed
/// it, so acceptance provenance stays truthful); a re-observed entry is refreshed in place.
#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct ProposalFile {
    /// The blueprint the proposal was learned against. `accept` refuses a proposal whose
    /// blueprint is not the one its invocation resolved (FW-DISC19).
    pub blueprint: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub candidates: Vec<ProposalEntry>,
    /// Host rules the Gateway's refusals call for (FW-DISC12); always needs-review.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub hosts: Vec<RuleProposal>,
    /// Channels the session was refused (FW-DISC12); always needs-review.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub channels: Vec<ChannelProposal>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct RuleProposal {
    /// A host rule in `rules` syntax (`allow:host`, `post:host/path`).
    pub rule: String,
    pub run_id: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct ChannelProposal {
    pub channel: String,
    pub run_id: String,
}

/// What a run was refused beyond paths (FW-DISC12). It crosses the Linux learning shim as JSON
/// over an inherited descriptor, so the shim's Gateway and supervisor can report to `learn`.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct SessionObservations {
    #[serde(default)]
    pub egress: Vec<EgressObservation>,
    /// Channel names.
    #[serde(default)]
    pub channels: Vec<String>,
    /// `(what, why)` withheld before proposal, for the operator channel.
    #[serde(default)]
    pub withheld: Vec<(String, String)>,
    /// `tunnel:` rules for hosts whose clients rejected the session CA. Never proposed: the host
    /// already has an inspected rule, and a tunnel would drop its request checks and brokering,
    /// so the operator swaps the rule by hand (FEP-6 §9 j).
    #[serde(default)]
    pub tunnel_candidates: Vec<String>,
}

/// The environment variable naming the descriptor the Linux learning shim reports on.
pub const REPORT_FD_ENV: &str = "FORMWORK_LEARN_REPORT_FD";

/// The environment variable naming the write end of the denial feed (FW-DISC17). strace leaves
/// that descriptor open in the process it traces, so the shim is told which one to close before
/// any workload exists.
pub const FEED_FD_ENV: &str = "FORMWORK_LEARN_FEED_FD";

/// Provenance keys for non-path discovered entries.
pub(crate) fn rule_key(rule: &str) -> String {
    format!("rule:{rule}")
}

pub(crate) fn channel_key(channel: &str) -> String {
    format!("channel:{channel}")
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct ProposalEntry {
    #[serde(flatten)]
    pub candidate: Candidate,
    /// The learning run that (last) observed this need.
    pub run_id: String,
}

/// Both discovery artifacts derive from the CANONICAL blueprint path, computed here and nowhere
/// else. A learning run, `accept` and the loader each reach the blueprint through a CLI-given
/// path -- a symlinked or relative one would otherwise make them derive different files, and an
/// accepted grant would land in a discovered layer no run ever loads (silent no-op, the FW-INV6
/// shape).
fn canonical_blueprint(blueprint: &Path) -> PathBuf {
    std::fs::canonicalize(blueprint).unwrap_or_else(|_| blueprint.to_path_buf())
}

pub fn proposal_path(blueprint: &Path) -> PathBuf {
    PathBuf::from(format!(
        "{}.proposal.toml",
        canonical_blueprint(blueprint).display()
    ))
}

pub fn discovered_path(blueprint: &Path) -> PathBuf {
    PathBuf::from(format!(
        "{}.discovered.toml",
        canonical_blueprint(blueprint).display()
    ))
}

/// One unified-log Sandbox record: `Sandbox: cat(29810) deny(1) file-read-data /private/tmp/x`.
/// Returns the denial with the kernel-resolved path, or None for lines that are not fs denials.
fn parse_sandbox_denial(event_message: &str) -> Option<DenialRecord> {
    let message = event_message
        .strip_prefix("Sandbox: ")
        .unwrap_or(event_message);
    let deny_at = message.find(" deny(")?;
    let rest = &message[deny_at + 1..];
    let close = rest.find(") ")?;
    let (operation, path) = rest[close + 2..].split_once(' ')?;
    if !path.starts_with('/') {
        return None;
    }
    let access = if operation.starts_with("file-write") {
        DenialAccess::Write
    } else if operation.starts_with("file-read") || operation == "process-exec" {
        // An exec denial is a read-grant gap in the unrestricted-exec default.
        DenialAccess::Read
    } else {
        return None; // mach-lookup, network*, etc. -- not filesystem discovery material
    };
    Some(DenialRecord {
        path: path.to_string(),
        access,
    })
}

/// Unified-log records persist lazily: under low logging pressure a short-lived process's buffered
/// denials can take well over the old fixed 4-second slack to reach the store `log show` reads --
/// and a workload that dies on its first denied read in a millisecond (the canonical discovery
/// case) is exactly the shape that loses its records to that latency. So collection polls to
/// quiescence with a floor: re-read the whole run window until two consecutive reads agree, but
/// never conclude before MIN_SETTLE of observation -- two equal reads two seconds apart prove the
/// store was briefly quiet, not that a millisecond workload's buffered records ever flushed
/// (an empty read repeated is the trap: it looks quiescent precisely when nothing has landed
/// yet). Bounded by a cap. Over-capture is safe by design (candidates are inert until accepted,
/// credentials floored regardless), so the slack, floor, and cap can all be generous.
const PERSISTENCE_SLACK_SECS: u64 = 2;
const QUIESCENCE_POLL: std::time::Duration = std::time::Duration::from_secs(2);
const QUIESCENCE_MIN_SETTLE: std::time::Duration = std::time::Duration::from_secs(6);
const QUIESCENCE_CAP: std::time::Duration = std::time::Duration::from_secs(30);

/// The macOS feed (FW-E2E-064): the run's Sandbox records from the unified log, from two readers.
/// A live `log stream`, attached before the workload starts, sees a record as the kernel emits
/// it, so a millisecond workload's denial never waits on the store's persistence latency; the
/// post-hoc `log show` over the run window covers whatever the stream missed. Records are the raw
/// messages, deduplicated: filesystem denials and service denials are parsed from them apart.
pub struct UnifiedLogFeed {
    started: std::time::Instant,
    stream: Option<LogStream>,
}

struct LogStream {
    child: std::process::Child,
    messages: std::sync::Arc<std::sync::Mutex<Vec<String>>>,
    /// The liveness probe's file, whose records are the feed's own and never a proposal.
    probe: Option<String>,
}

/// How long a learning run waits for the live stream to attach before spawning the workload.
const STREAM_ATTACH: std::time::Duration = std::time::Duration::from_secs(5);

/// Proof the live stream is delivering events. `log stream` prints its filter banner before the
/// events flow, so a workload spawned on the banner can lose its first records to the gap -- with
/// the store's lazy persistence, a millisecond workload's only denial. A throwaway `cat` under
/// `sandbox-exec` (deprecated, still shipped) is denied a probe file until the stream reports
/// that denial. Without `sandbox-exec` the banner is all there is.
struct StreamProbe {
    path: std::path::PathBuf,
}

impl StreamProbe {
    fn new() -> Option<StreamProbe> {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.subsec_nanos())
            .unwrap_or(0);
        let path =
            std::env::temp_dir().join(format!("formwork-log-probe-{}-{nanos}", std::process::id()));
        std::fs::write(&path, b"probe").ok()?;
        // Seatbelt matches the resolved path (/var is /private/var).
        let path = std::fs::canonicalize(&path).ok()?;
        Some(StreamProbe { path })
    }

    fn name(&self) -> String {
        self.path.display().to_string()
    }

    /// One denial for the stream to report; false when `sandbox-exec` cannot run.
    fn fire(&self) -> bool {
        let literal = self.name().replace('\\', "\\\\").replace('"', "\\\"");
        Command::new("/usr/bin/sandbox-exec")
            .arg("-p")
            .arg(format!(
                "(version 1)(allow default)(deny file-read-data (literal \"{literal}\"))"
            ))
            .arg("/bin/cat")
            .arg(&self.path)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .is_ok()
    }
}

impl Drop for StreamProbe {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

const SANDBOX_PREDICATE: &str = r#"sender == "Sandbox""#;

impl UnifiedLogFeed {
    /// Attach the live stream (bounded by STREAM_ATTACH; `log show` alone if it cannot attach)
    /// and start the run window. Call before the workload is spawned.
    pub fn start() -> UnifiedLogFeed {
        let stream = LogStream::start();
        UnifiedLogFeed {
            started: std::time::Instant::now(),
            stream,
        }
    }

    /// Collect the run window's records, polling until the log store stops yielding new ones.
    /// Anchored to the run's start (the window is recomputed as elapsed-since-start each poll),
    /// never to collection time -- a `--last N` fixed at collection would drift off the run it
    /// brackets.
    pub fn collect_quiescent(self) -> Result<Vec<String>> {
        let started = self.started;
        let stream = self.stream;
        let messages = collect_until_quiescent(
            || {
                let mut all =
                    collect_messages(started.elapsed().as_secs() + PERSISTENCE_SLACK_SECS)?;
                if let Some(s) = &stream {
                    all.extend(s.messages());
                    if let Some(probe) = &s.probe {
                        all.retain(|m| !m.contains(probe.as_str()));
                    }
                }
                all.sort();
                all.dedup();
                Ok(all)
            },
            QUIESCENCE_POLL,
            QUIESCENCE_MIN_SETTLE,
            QUIESCENCE_CAP,
        );
        if let Some(mut s) = stream {
            let _ = s.child.kill();
            let _ = s.child.wait();
        }
        messages
    }
}

impl LogStream {
    fn start() -> Option<LogStream> {
        use std::io::BufRead;
        let mut child = match Command::new("/usr/bin/log")
            .args([
                "stream",
                "--style",
                "ndjson",
                "--predicate",
                SANDBOX_PREDICATE,
            ])
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::null())
            .spawn()
        {
            Ok(child) => child,
            Err(e) => {
                tracing::debug!(error = %e, "no live log stream; collecting with `log show` alone");
                return None;
            }
        };
        let stdout = child.stdout.take()?;
        let messages = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let sink = messages.clone();
        let (attached, ready) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let mut attached = Some(attached);
            for line in std::io::BufReader::new(stdout).lines() {
                let Ok(line) = line else { break };
                // `log stream` prints the filter it applied once attached, before any event.
                if let Some(a) = attached.take() {
                    let _ = a.send(());
                }
                if let Some(message) = event_message(&line) {
                    if let Ok(mut m) = sink.lock() {
                        m.push(message);
                    }
                }
            }
        });
        let deadline = std::time::Instant::now() + STREAM_ATTACH;
        let probe = StreamProbe::new();
        let mut live = false;
        if let Some(p) = &probe {
            let name = p.name();
            'probing: while std::time::Instant::now() < deadline && p.fire() {
                let next = std::time::Instant::now() + std::time::Duration::from_millis(500);
                while std::time::Instant::now() < next.min(deadline) {
                    if messages
                        .lock()
                        .map(|m| m.iter().any(|m| m.contains(&name)))
                        .unwrap_or(false)
                    {
                        live = true;
                        break 'probing;
                    }
                    std::thread::sleep(std::time::Duration::from_millis(20));
                }
            }
        }
        if !live {
            let left = deadline.saturating_duration_since(std::time::Instant::now());
            if ready.recv_timeout(left).is_err() {
                tracing::debug!(
                    "the live log stream did not attach in time; `log show` still covers the run"
                );
            } else if probe.is_some() {
                tracing::debug!(
                    "the live log stream never reported its probe; trusting its banner"
                );
            }
        }
        Some(LogStream {
            child,
            messages,
            probe: probe.map(|p| {
                let name = p.name();
                // The file can go; its name still marks the probe's records.
                drop(p);
                name
            }),
        })
    }

    fn messages(&self) -> Vec<String> {
        self.messages.lock().map(|m| m.clone()).unwrap_or_default()
    }
}

/// The records this session produced: those carrying its deny tag on their own line, with the
/// tag removed (characterized: `(with message …)` appends it to the record). Without a tag, every
/// record in the run window -- over-capture, which is safe (FW-INV10).
pub fn this_session(messages: Vec<String>, tag: Option<&str>) -> Vec<String> {
    let Some(tag) = tag else {
        return messages;
    };
    messages
        .into_iter()
        .filter_map(|m| {
            let (record, rest) = m.split_once('\n')?;
            rest.lines()
                .any(|l| l.trim() == tag)
                .then(|| record.to_string())
        })
        .collect()
}

/// The filesystem denials among a feed's records (FW-DISC2).
pub fn fs_denials(messages: &[String]) -> Vec<DenialRecord> {
    messages
        .iter()
        .filter_map(|m| parse_sandbox_denial(m))
        .collect()
}

/// What a macOS learning run's service denials call for (FW-DISC12): the channel whose Mach
/// service or operation the session was refused, by the characterized map (FEP-5 §6.3 C3), and
/// the keychain -- a credential type, not a channel -- withheld with its lift. LaunchServices is
/// withheld too: `open` reaches the opener shim, and `open-url` never lifts LaunchServices
/// (FW-ISO18), so a client that calls it directly cannot be served by any proposal.
pub fn service_observations(
    messages: &[String],
    catalog: &ResolvedCatalog,
    observations: &mut SessionObservations,
) {
    let keyring: Vec<&str> = catalog
        .types
        .iter()
        .filter(|(name, _)| name.as_str() == formwork_blueprint::OS_KEYRING)
        .flat_map(|(_, entry)| entry.services.iter())
        .filter_map(|s| s.strip_prefix("mach:"))
        .collect();
    for message in messages {
        let Some((operation, argument)) = parse_service_denial(message) else {
            continue;
        };
        let channel = match operation {
            "appleevent-send" | "job-creation" => Some(Channel::RunOutside),
            "mach-lookup" => {
                let service = argument.split_whitespace().next().unwrap_or("");
                if keyring.contains(&service) {
                    observations.withheld.push((
                        service.to_string(),
                        "the keychain is a credential type; lift it with allow-credentials = \
                         [\"os-keyring\"]"
                            .to_string(),
                    ));
                    None
                } else {
                    formwork_compile::CHANNEL_SERVICES
                        .iter()
                        .find(|(_, services)| services.iter().any(|s| s.matches(service)))
                        .map(|(channel, _)| *channel)
                }
            }
            "lsopen" => {
                observations.withheld.push((
                    "LaunchServices".to_string(),
                    "a client opened a URL or an application through LaunchServices, which stays \
                     denied; `open` and $BROWSER reach the opener shim, which `open-url` lifts"
                        .to_string(),
                ));
                None
            }
            _ => None,
        };
        if let Some(c) = channel {
            observations.channels.push(c.name().to_string());
        }
    }
    observations.channels.sort();
    observations.channels.dedup();
    observations.withheld.sort();
    observations.withheld.dedup();
}

/// One Sandbox record's operation and its argument: `Sandbox: pbcopy(9) deny(1) mach-lookup
/// com.apple.pasteboard.1` is `("mach-lookup", "com.apple.pasteboard.1")`.
fn parse_service_denial(event_message: &str) -> Option<(&str, &str)> {
    let message = event_message
        .strip_prefix("Sandbox: ")
        .unwrap_or(event_message);
    let deny_at = message.find(" deny(")?;
    let rest = &message[deny_at + 1..];
    let close = rest.find(") ")?;
    let rest = &rest[close + 2..];
    Some(rest.split_once(' ').unwrap_or((rest, "")))
}

/// The quiescence control flow, separated from the impure `log show` collector so the
/// stabilization-with-floor property (FW-E2E-064's mechanism) is testable as a pure function of a
/// chosen record sequence -- the same substitution the constitution allows for the compiler's
/// HostProfile; the feed itself is exercised by the macOS E2E tests, never mocked there.
fn collect_until_quiescent<T: PartialEq>(
    mut collect: impl FnMut() -> Result<Vec<T>>,
    poll: std::time::Duration,
    min_settle: std::time::Duration,
    cap: std::time::Duration,
) -> Result<Vec<T>> {
    let polling_started = std::time::Instant::now();
    let mut last = collect()?;
    loop {
        if polling_started.elapsed() >= cap {
            tracing::warn!(
                cap_secs = cap.as_secs(),
                "denial collection hit its quiescence cap (late-flushing records may be missing -- re-run `formwork learn` -- or unrelated sandboxed processes kept the feed busy; over-capture is safe either way)"
            );
            return Ok(last);
        }
        std::thread::sleep(poll);
        let next = collect()?;
        if next == last && polling_started.elapsed() >= min_settle {
            return Ok(next);
        }
        last = next;
    }
}

/// The `eventMessage` of one ndjson log line.
fn event_message(line: &str) -> Option<String> {
    let value = serde_json::from_str::<serde_json::Value>(line).ok()?;
    value
        .get("eventMessage")
        .and_then(|m| m.as_str())
        .map(str::to_string)
}

/// Post-hoc collection over the run window (plus slack for log-persistence latency).
fn collect_messages(window_secs: u64) -> Result<Vec<String>> {
    let output = Command::new("/usr/bin/log")
        .args([
            "show",
            "--style",
            "ndjson",
            "--last",
            &format!("{window_secs}s"),
            "--predicate",
            SANDBOX_PREDICATE,
        ])
        .output()
        .context("running `log show` to collect sandbox denials")?;
    if !output.status.success() {
        bail!(
            "`log show` failed (status {:?}): {}",
            output.status.code(),
            String::from_utf8_lossy(&output.stderr)
        );
    }
    Ok(String::from_utf8_lossy(&output.stdout)
        .lines()
        .filter_map(event_message)
        .collect())
}

/// Locate `strace`, the Linux denial feed's tap (FW-E2E-071). PATH-based on purpose: feed
/// availability must be decidable *before* the workload runs (FW-XR9), and PATH is the honest
/// answer to "would the spawn below find it".
pub fn find_strace() -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path)
        .map(|dir| dir.join("strace"))
        .find(|candidate| candidate.is_file())
}

/// The strace options the parser below reads: every process (`-f`), descriptors printed with
/// their paths (`-y`), strings whole (`-s 4096`: the default abbreviates at 32 bytes, which
/// would truncate real paths and lose their denials), and the file calls plus the calls that
/// decide what a relative path is relative to -- `%process` for `clone`/`fork`, and `fchdir`.
pub const STRACE_OPTIONS: &[&str] = &[
    "-f",
    "-y",
    "-qq",
    "-s",
    "4096",
    "-e",
    "trace=%file,%process,fchdir",
];

/// What the strace feed yielded: the denials it attributed to a path, and how many denied file
/// calls it could not. Those are reported, never given a guessed path (FW-INV5): a wrong path in
/// a proposal is a grant nobody asked for, a missing one is another learning run (FW-INV10).
#[derive(Debug, Default)]
pub struct StraceDenials {
    pub records: Vec<DenialRecord>,
    pub unattributed: usize,
}

/// Parse a [`STRACE_OPTIONS`] log into denial records: only *failed* file syscalls with
/// `EACCES`/`EPERM` -- the errno a Landlock denial surfaces as -- and only syscall families
/// Landlock actually governs. `stat`/`access` probes are excluded: Landlock does not hook them,
/// so their failures are ordinary unix-permission noise, not discovery material.
pub fn parse_strace_denials(trace: &str, launch_dir: &Path) -> StraceDenials {
    let (observed, mut unattributed) = observe_strace(trace, launch_dir);
    let mut records = Vec::new();
    for denial in observed {
        match kernel_path(&denial.path, denial.names_entry) {
            Some(path) => records.push(DenialRecord {
                path,
                access: denial.access,
            }),
            None => unattributed += 1,
        }
    }
    StraceDenials {
        records,
        unattributed,
    }
}

/// A denied call as the trace states it, before the filesystem is consulted.
#[derive(Debug, PartialEq, Eq)]
struct ObservedDenial {
    path: String,
    access: DenialAccess,
    /// The call acts on a directory entry (`unlink`, `rename`, `mkdir`), not on what the entry
    /// leads to.
    names_entry: bool,
}

/// Resolve symlinks as the kernel did, like the macOS feed's kernel-resolved paths, so the
/// credential floor's shape match (FW-DISC3) sees the real location and not an alias of it. A
/// call on a directory entry was refused for the entry's directory, so the entry's own name
/// stands; any other call followed the last link too. `None` when neither the path nor its
/// directory resolves and the path still has `..` left to interpret.
fn kernel_path(path: &str, names_entry: bool) -> Option<String> {
    use std::path::Component;
    let path = Path::new(path);
    let followed = (!names_entry)
        .then(|| std::fs::canonicalize(path).ok())
        .flatten();
    let resolved = match followed {
        Some(resolved) => resolved,
        None => {
            let name = path.file_name()?;
            match path
                .parent()
                .and_then(|dir| std::fs::canonicalize(dir).ok())
            {
                Some(dir) => dir.join(name),
                None if path
                    .components()
                    .all(|c| matches!(c, Component::RootDir | Component::Normal(_))) =>
                {
                    path.to_path_buf()
                }
                None => return None,
            }
        }
    };
    resolved.to_str().map(str::to_string)
}

/// The denied calls in a trace, each with the absolute path it names, and the number that name
/// none the trace can establish. Pure: [`parse_strace_denials`] resolves the paths on disk.
fn observe_strace(trace: &str, launch_dir: &Path) -> (Vec<ObservedDenial>, usize) {
    let (calls, mut unattributed) = rejoin_calls(trace);
    let mut dirs = WorkingDirs::default();
    let mut denials = Vec::new();
    for (pid, text) in &calls {
        let Some(call) = Call::parse(text) else {
            continue;
        };
        let view = dirs.view_of(*pid, launch_dir);
        // `-y` prints the working directory beside AT_FDCWD: the kernel's own answer, which
        // also corrects whatever the tracking below could not follow.
        if let Some(cwd) = call
            .args
            .iter()
            .filter(|arg| arg.starts_with("AT_FDCWD<"))
            .find_map(|arg| annotated_path(arg))
        {
            dirs.views[view].cwd = Some(cwd);
        }
        match call.name {
            "chdir" if call.succeeded() => {
                dirs.views[view].cwd = call
                    .args
                    .first()
                    .and_then(|arg| unquote(arg))
                    .and_then(|path| dirs.views[view].locate(None, &path));
            }
            "fchdir" if call.succeeded() => {
                dirs.views[view].cwd = call.args.first().and_then(|arg| annotated_path(arg));
            }
            // Past a chroot the paths a process passes are relative to a root the trace does
            // not name.
            "chroot" if call.succeeded() => dirs.views[view].rerooted = true,
            "clone" | "clone3" | "fork" | "vfork" => {
                let child = call.result.split_whitespace().next();
                if let Some(child) = child.and_then(|pid| pid.parse::<u32>().ok()) {
                    let flags = match call.name {
                        "clone" => field(&call.args, "flags"),
                        "clone3" => call.args.first().and_then(|arg| struct_field(arg, "flags")),
                        _ => None,
                    };
                    let shares = flags.is_some_and(|f| f.split('|').any(|f| f == "CLONE_FS"));
                    dirs.adopt(child, view, shares);
                }
            }
            name => {
                let Some(shape) = governed(name) else {
                    continue;
                };
                if !denied(call.result) {
                    continue;
                }
                let dirfd = match shape.dirfd {
                    Some(at) => call.args.get(at).copied().map(Some),
                    None => Some(None),
                };
                let path = dirfd.and_then(|dirfd| {
                    let path = unquote(call.args.get(shape.path)?)?;
                    dirs.views[view].locate(dirfd, &path)
                });
                let Some(path) = path else {
                    unattributed += 1;
                    continue;
                };
                let flags = match shape.access {
                    Grade::Read | Grade::Write => None,
                    Grade::OpenFlags(at) => call.args.get(at).copied(),
                    Grade::OpenHow(at) => {
                        call.args.get(at).and_then(|how| struct_field(how, "flags"))
                    }
                };
                // The write grade comes from the open flags, taken from the flags argument, or
                // from the mutating verb -- mirroring the macOS feed's file-write* vs file-read*.
                let writes = match shape.access {
                    Grade::Read => false,
                    Grade::Write => true,
                    Grade::OpenFlags(_) | Grade::OpenHow(_) => flags.is_some_and(|flags| {
                        flags
                            .split('|')
                            .any(|f| matches!(f, "O_WRONLY" | "O_RDWR" | "O_CREAT" | "O_TRUNC"))
                    }),
                };
                denials.push(ObservedDenial {
                    path,
                    access: if writes {
                        DenialAccess::Write
                    } else {
                        DenialAccess::Read
                    },
                    names_entry: shape.names_entry,
                });
            }
        }
    }
    (denials, unattributed)
}

/// Where a syscall Landlock governs names the path it was refused on, by argument position. The
/// first quoted argument is not it for the two-path calls: that is the link text of `symlink`
/// and the source of `rename` and `link`, and the refusal is for the entry being made.
struct Governed {
    dirfd: Option<usize>,
    path: usize,
    access: Grade,
    names_entry: bool,
}

enum Grade {
    Read,
    Write,
    /// `open` flags at this argument.
    OpenFlags(usize),
    /// `openat2`'s `struct open_how` at this argument.
    OpenHow(usize),
}

fn governed(syscall: &str) -> Option<Governed> {
    let shape = |dirfd, path, access, names_entry| Governed {
        dirfd,
        path,
        access,
        names_entry,
    };
    Some(match syscall {
        "open" => shape(None, 0, Grade::OpenFlags(1), false),
        "openat" => shape(Some(0), 1, Grade::OpenFlags(2), false),
        "openat2" => shape(Some(0), 1, Grade::OpenHow(2), false),
        "creat" | "truncate" => shape(None, 0, Grade::Write, false),
        // An exec denial is a read-grant gap in the unrestricted-exec default, as on macOS.
        "execve" => shape(None, 0, Grade::Read, false),
        "execveat" => shape(Some(0), 1, Grade::Read, false),
        "mkdir" | "unlink" | "rmdir" => shape(None, 0, Grade::Write, true),
        "mkdirat" | "unlinkat" => shape(Some(0), 1, Grade::Write, true),
        "rename" | "link" | "symlink" => shape(None, 1, Grade::Write, true),
        "renameat" | "renameat2" | "linkat" => shape(Some(2), 3, Grade::Write, true),
        "symlinkat" => shape(Some(1), 2, Grade::Write, true),
        _ => return None,
    })
}

/// What a process's paths are relative to, as far as the trace establishes it.
#[derive(Clone, Default)]
struct FsView {
    cwd: Option<String>,
    rerooted: bool,
}

impl FsView {
    /// The absolute path a call names through `dirfd` (`None` for a call that takes none), or
    /// `None` when the trace does not say what a relative path is relative to.
    fn locate(&self, dirfd: Option<&str>, path: &str) -> Option<String> {
        if self.rerooted || path.is_empty() {
            return None;
        }
        if path.starts_with('/') {
            return Some(path.to_string());
        }
        let base = match dirfd {
            None | Some("AT_FDCWD") => self.cwd.clone()?,
            Some(descriptor) => annotated_path(descriptor)?,
        };
        Some(format!("{}/{path}", base.trim_end_matches('/')))
    }
}

/// Each traced process's [`FsView`]: `chdir` and `fchdir` move it, a forked child starts with a
/// copy, and tasks cloned with `CLONE_FS` hold one between them.
#[derive(Default)]
struct WorkingDirs {
    of_pid: std::collections::HashMap<u32, usize>,
    views: Vec<FsView>,
}

impl WorkingDirs {
    fn view_of(&mut self, pid: u32, launch_dir: &Path) -> usize {
        if let Some(view) = self.of_pid.get(&pid) {
            return *view;
        }
        // The first process in the trace is the one `learn` launched, in the launch directory.
        // A later one with no `clone` on record started somewhere the trace does not say.
        let cwd = self
            .views
            .is_empty()
            .then(|| launch_dir.to_str().map(str::to_string))
            .flatten();
        self.views.push(FsView {
            cwd,
            rerooted: false,
        });
        self.of_pid.insert(pid, self.views.len() - 1);
        self.views.len() - 1
    }

    fn adopt(&mut self, child: u32, parent_view: usize, shares: bool) {
        let view = if shares {
            parent_view
        } else {
            self.views.push(self.views[parent_view].clone());
            self.views.len() - 1
        };
        self.of_pid.insert(child, view);
    }
}

/// One process's calls, whole, at the position each began. `strace -f` writes a call that
/// another process's output interrupts as `name(args <unfinished ...>` and, later,
/// `<... name resumed>rest`; the halves are rejoined by pid in the first half's place, so a
/// process's calls keep their order and a `clone` precedes its child's calls. A call that never
/// resumed is left out. Also counts the denied file calls that arrived as a second half with no
/// first.
fn rejoin_calls(trace: &str) -> (Vec<TracedCall<'_>>, usize) {
    use std::borrow::Cow;
    const UNFINISHED: &str = " <unfinished ...>";
    let mut calls: Vec<Option<TracedCall<'_>>> = Vec::new();
    let mut pending: std::collections::HashMap<u32, (usize, &str)> = Default::default();
    let mut orphaned = 0;
    for line in trace.lines() {
        let Some((pid, rest)) = line.split_once(' ') else {
            continue;
        };
        let Ok(pid) = pid.parse::<u32>() else {
            continue;
        };
        let rest = rest.trim_start();
        if let Some(resumed) = rest.strip_prefix("<... ") {
            let Some((name, tail)) = resumed.split_once(" resumed>") else {
                continue;
            };
            match pending.remove(&pid) {
                Some((slot, head))
                    if head.strip_prefix(name).is_some_and(|h| h.starts_with('(')) =>
                {
                    calls[slot] = Some((pid, Cow::Owned(format!("{head}{tail}"))));
                }
                _ => {
                    let result = split_args(tail, ')').and_then(|(_, rest)| result_of(rest));
                    if governed(name).is_some() && result.is_some_and(denied) {
                        orphaned += 1;
                    }
                }
            }
            continue;
        }
        match rest.strip_suffix(UNFINISHED) {
            Some(head) => {
                pending.insert(pid, (calls.len(), head));
                calls.push(None);
            }
            None => calls.push(Some((pid, Cow::Borrowed(rest)))),
        }
    }
    (calls.into_iter().flatten().collect(), orphaned)
}

/// A pid and one whole call it made.
type TracedCall<'a> = (u32, std::borrow::Cow<'a, str>);

/// One strace call: `openat(AT_FDCWD, "/path", O_RDONLY) = -1 EACCES (Permission denied)`.
struct Call<'a> {
    name: &'a str,
    args: Vec<&'a str>,
    /// What follows ` = `.
    result: &'a str,
}

impl<'a> Call<'a> {
    fn parse(text: &'a str) -> Option<Call<'a>> {
        let (name, rest) = text.split_once('(')?;
        let is_name = |b: u8| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_';
        if name.is_empty() || !name.bytes().all(is_name) {
            return None;
        }
        let (args, rest) = split_args(rest, ')')?;
        Some(Call {
            name,
            args,
            result: result_of(rest)?,
        })
    }

    fn succeeded(&self) -> bool {
        self.result.split_whitespace().next() == Some("0")
    }
}

fn result_of(after_args: &str) -> Option<&str> {
    after_args.trim_start().strip_prefix("= ")
}

fn denied(result: &str) -> bool {
    let mut tokens = result.split_whitespace();
    tokens.next() == Some("-1") && matches!(tokens.next(), Some("EACCES" | "EPERM"))
}

/// Split strace arguments at their top-level commas, up to the `close` that ends them; `text`
/// begins just inside the opener. Returns the arguments and what follows `close`, or `None` when
/// they do not close on this line. A quoted string and a `-y` annotation (`3</path>`) are
/// skipped whole: the traced process chose those bytes, and strace escapes `"` in the one and
/// `>` in the other, so nothing inside either can end an argument or forge a result.
fn split_args(text: &str, close: char) -> Option<(Vec<&str>, &str)> {
    let mut args = Vec::new();
    let mut start = 0;
    let mut depth = 0usize;
    let mut chars = text.char_indices();
    while let Some((at, c)) = chars.next() {
        match c {
            '"' | '<' => {
                let end = if c == '"' { '"' } else { '>' };
                loop {
                    match chars.next()?.1 {
                        '\\' => {
                            chars.next()?;
                        }
                        c if c == end => break,
                        _ => {}
                    }
                }
            }
            '(' | '[' | '{' => depth += 1,
            ')' | ']' | '}' if depth > 0 => depth -= 1,
            c if c == close => {
                let last = text[start..at].trim();
                if !(last.is_empty() && args.is_empty()) {
                    args.push(last);
                }
                return Some((args, &text[at + c.len_utf8()..]));
            }
            ')' | ']' | '}' => return None,
            ',' if depth == 0 => {
                args.push(text[start..at].trim());
                start = at + 1;
            }
            _ => {}
        }
    }
    None
}

/// The value of `key=` among arguments strace prints by name.
fn field<'a>(args: &[&'a str], key: &str) -> Option<&'a str> {
    args.iter()
        .find_map(|arg| arg.strip_prefix(key)?.strip_prefix('='))
}

/// The value of `key=` inside a `{...}` argument (`clone3`'s `clone_args`, `openat2`'s `open_how`).
fn struct_field<'a>(arg: &'a str, key: &str) -> Option<&'a str> {
    let (fields, _) = split_args(arg.strip_prefix('{')?, '}')?;
    field(&fields, key)
}

/// A whole quoted string argument. `None` for one strace cut short (`"..."...`).
fn unquote(arg: &str) -> Option<String> {
    unescape(arg.strip_prefix('"')?.strip_suffix('"')?)
}

/// The path `-y` printed beside a descriptor: `3</srv/data>`, `AT_FDCWD</work>`. `None` for a
/// bare descriptor and for one that is not a file (`<pipe:[7]>`).
fn annotated_path(arg: &str) -> Option<String> {
    let (_, annotation) = arg.split_once('<')?;
    let path = unescape(annotation.strip_suffix('>')?)?;
    path.starts_with('/').then_some(path)
}

/// Undo strace's quoting: C escapes, and octal for each byte outside printable ASCII. `None` for
/// bytes that are not UTF-8, which no grant can spell (FW-INV6).
fn unescape(quoted: &str) -> Option<String> {
    let mut bytes = Vec::with_capacity(quoted.len());
    let mut rest = quoted.bytes().peekable();
    while let Some(byte) = rest.next() {
        if byte != b'\\' {
            bytes.push(byte);
            continue;
        }
        match rest.next()? {
            b'n' => bytes.push(b'\n'),
            b't' => bytes.push(b'\t'),
            b'r' => bytes.push(b'\r'),
            b'v' => bytes.push(0x0b),
            b'f' => bytes.push(0x0c),
            literal @ (b'"' | b'\\') => bytes.push(literal),
            digit @ b'0'..=b'7' => {
                let mut value = u32::from(digit - b'0');
                for _ in 0..2 {
                    let Some(digit @ b'0'..=b'7') = rest.peek().copied() else {
                        break;
                    };
                    value = value * 8 + u32::from(digit - b'0');
                    rest.next();
                }
                bytes.push(u8::try_from(value).ok()?);
            }
            _ => return None,
        }
    }
    String::from_utf8(bytes).ok()
}

/// What the observed session gives its proposal: the merged blueprint (the zone and the
/// exclusions), the file its artifacts sit beside, and the floor -- the Catalog and the denies
/// the Launcher added for this session (FW-DISC15).
#[derive(Clone, Copy)]
pub struct LearnedSession<'a> {
    pub blueprint: &'a Blueprint,
    pub blueprint_path: &'a Path,
    pub catalog: &'a ResolvedCatalog,
    pub launcher_denies: &'a [LauncherDeny],
}

/// The learn phase after the confined child has exited: reverse-compile the feed's records, merge
/// into the proposal, self-accept in-zone candidates into the discovered layer, and itemize on
/// the operator channel. Feed-agnostic -- the caller collected `records` from whichever tap this
/// host carries (unified log or strace), and both are one shape here. `unattributed` counts the
/// denied calls the feed saw and could not name a path for.
pub fn conclude_learning_run(
    session: &LearnedSession,
    run_id: &str,
    records: Vec<DenialRecord>,
    unattributed: usize,
    observations: &SessionObservations,
    workload_status: &std::process::ExitStatus,
) -> Result<()> {
    let LearnedSession {
        blueprint,
        blueprint_path,
        catalog,
        launcher_denies,
    } = *session;
    let outcome = reverse_compile(
        &records,
        catalog,
        launcher_denies,
        &blueprint.exposed_credentials(),
        &blueprint.discovery.auto_widen,
    );

    // FW-CRED7: the withheld itemization -- names and types -- goes to the operator channel only.
    for withheld in &outcome.withheld {
        tracing::info!(
            path = %withheld.path,
            credential_type = %withheld.credential_type,
            "learning: denial withheld by the credential floor (FW-DISC3); lift only via --allow-cred"
        );
    }
    for path in &outcome.unproposable {
        tracing::warn!(
            path = %path,
            "learning: denial not proposed -- the path has a `**` component, which a grant reads \
             as a pattern; grant it by hand through its directory if the session needs it"
        );
    }
    if unattributed > 0 {
        tracing::warn!(
            unattributed,
            "learning: denied file calls the feed could not attribute to a path are not in the \
             proposal (a path relative to a directory the trace does not name, bytes that are \
             not UTF-8, or a call cut short); another learning run may observe them"
        );
    }

    // FW-DISC12: hosts at the grade the host already has; restricted destinations withheld.
    let egress = propose_host_rules(&observations.egress, blueprint.net.host_table());
    for (target, why) in egress.withheld.iter().chain(observations.withheld.iter()) {
        tracing::info!(target = %target, "learning: withheld, not proposed (FW-DISC12): {why}");
    }
    for rule in &observations.tunnel_candidates {
        tracing::warn!(
            rule = %rule,
            "learning: a client rejected the session CA; to serve it, replace the host's \
             inspected rule with `{rule}`, which drops its method, path and Host checks and its \
             brokering (not proposed: the grade drop is an authoring decision)"
        );
    }
    let observed_channels: Vec<Channel> = observations
        .channels
        .iter()
        .filter_map(|c| Channel::from_name(c))
        .collect();
    let channels = propose_channels(&observed_channels, &blueprint.channels);

    let auto: Vec<ProposalEntry> = outcome
        .candidates
        .iter()
        .filter(|c| c.tag == CandidateTag::AutoAccepted)
        .map(|c| ProposalEntry {
            candidate: c.clone(),
            run_id: run_id.to_string(),
        })
        .collect();
    if !auto.is_empty() {
        let discovered = discovered_path(blueprint_path);
        let auto_refs: Vec<&ProposalEntry> = auto.iter().collect();
        let count = merge_into_discovered(&discovered, &auto_refs, "discovery-auto")?;
        tracing::info!(
            file = %discovered.display(),
            grants = count,
            "learning: in-zone candidates self-granted for the NEXT run (FW-DISC4)"
        );
    }

    let path = proposal_path(blueprint_path);
    let previous: ProposalFile = match std::fs::read_to_string(&path) {
        Ok(text) => toml::from_str::<ProposalFile>(&text)
            .with_context(|| format!("parsing existing proposal {}", path.display()))?,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => ProposalFile::default(),
        Err(e) => return Err(e).context(format!("reading {}", path.display())),
    };
    let observed: Vec<ProposalEntry> = outcome
        .candidates
        .iter()
        .map(|c| ProposalEntry {
            candidate: c.clone(),
            run_id: run_id.to_string(),
        })
        .collect();
    let (candidates, carried) = merge_proposal_entries(previous.candidates, observed);
    let hosts = merge_keyed(
        previous.hosts,
        egress
            .rules
            .iter()
            .map(|r| RuleProposal {
                rule: r.to_string(),
                run_id: run_id.to_string(),
            })
            .collect(),
        |e| e.rule.clone(),
    );
    let channel_entries = merge_keyed(
        previous.channels,
        channels
            .iter()
            .map(|c| ChannelProposal {
                channel: c.name().to_string(),
                run_id: run_id.to_string(),
            })
            .collect(),
        |e| e.channel.clone(),
    );
    if carried > 0 {
        tracing::info!(
            carried,
            "unreviewed candidates from earlier learning runs kept in the proposal"
        );
    }

    let proposal = ProposalFile {
        blueprint: blueprint_path
            .canonicalize()
            .unwrap_or_else(|_| blueprint_path.to_path_buf())
            .display()
            .to_string(),
        candidates,
        hosts,
        channels: channel_entries,
    };
    let body = format!(
        "# formwork learn proposal -- list with `formwork learn --list`, then accept per entry\n\
         # (`formwork learn --accept <N>` or `--accept <pattern>`, repeatable; `--accept-all`).\n\
         # Paths are kernel-resolved (macOS: /tmp appears as /private/tmp). Nothing here has any\n\
         # effect until accepted (FW-INV10).\n{body}",
        body = toml::to_string_pretty(&proposal).context("serializing proposal")?
    );
    std::fs::write(&path, body).with_context(|| format!("writing {}", path.display()))?;
    let needs_review = proposal
        .candidates
        .iter()
        .filter(|c| c.candidate.tag == CandidateTag::NeedsReview)
        .count()
        + proposal.hosts.len()
        + proposal.channels.len();
    let total = proposal.candidates.len() + proposal.hosts.len() + proposal.channels.len();
    // The proposal pointer is the run's RESULT, so it goes to stdout; telemetry stays on stderr.
    let missing = match unattributed {
        0 => String::new(),
        n => format!(", {n} denied calls not attributed to a path"),
    };
    println!(
        "proposal: {} ({} candidates, {} needs review{missing}) -- review with `formwork learn \
         --list`",
        path.display(),
        total,
        needs_review
    );
    tracing::info!(
        workload_exit = workload_status.code().unwrap_or(-1),
        proposal = %path.display(),
        candidates = total,
        needs_review,
        withheld = outcome.withheld.len(),
        "learning run complete (proposal written regardless of workload exit)"
    );
    Ok(())
}

/// Pure merge: unreviewed entries from earlier runs are kept (sticky learning), a re-observed
/// (pattern, access) is refreshed with the newest run's tag and run id. Prior auto-accepted
/// entries are NOT carried -- they already live in the discovered layer with provenance, which
/// is the durable audit trail; re-listing them here forever would only accrete noise. Returns
/// the merged, deterministic list and how many prior entries were carried forward un-refreshed.
fn merge_proposal_entries(
    previous: Vec<ProposalEntry>,
    observed: Vec<ProposalEntry>,
) -> (Vec<ProposalEntry>, usize) {
    let key = |e: &ProposalEntry| (e.candidate.pattern.canonical(), e.candidate.access);
    let mut merged: std::collections::BTreeMap<_, ProposalEntry> = previous
        .into_iter()
        .filter(|e| e.candidate.tag == CandidateTag::NeedsReview)
        .map(|e| (key(&e), e))
        .collect();
    let before = merged.len();
    let mut refreshed = 0;
    for entry in observed {
        if merged.insert(key(&entry), entry).is_some() {
            refreshed += 1;
        }
    }
    let carried = before - refreshed;
    (merged.into_values().collect(), carried)
}

/// Sticky merge for the non-path entries: earlier unreviewed entries are kept, a re-observed one
/// is refreshed with the newest run id. Deterministic by key.
fn merge_keyed<T, K: Ord>(previous: Vec<T>, observed: Vec<T>, key: impl Fn(&T) -> K) -> Vec<T> {
    let mut merged: std::collections::BTreeMap<K, T> =
        previous.into_iter().map(|e| (key(&e), e)).collect();
    for entry in observed {
        merged.insert(key(&entry), entry);
    }
    merged.into_values().collect()
}

/// Append accepted entries to the discovered layer with provenance (FW-DISC6), deduped and
/// canonical. The file is itself a BlueprintLayer, so the next run stacks it like any base.
fn merge_into_discovered(
    path: &Path,
    accepted: &[&ProposalEntry],
    added_via: &str,
) -> Result<usize> {
    merge_all_into_discovered(path, accepted, &[], &[], added_via)
}

/// As [`merge_into_discovered`], with host rules (kept in `rules`, host syntax only) and channels
/// (the `channels` allow scope), each with provenance (FW-DISC12).
fn merge_all_into_discovered(
    path: &Path,
    accepted: &[&ProposalEntry],
    rules: &[&RuleProposal],
    channels: &[&ChannelProposal],
    added_via: &str,
) -> Result<usize> {
    let mut layer: BlueprintLayer = match std::fs::read_to_string(path) {
        Ok(text) => {
            let value: toml::Value = toml::from_str(&text)
                .with_context(|| format!("parsing existing discovered layer {}", path.display()))?;
            // The rewrite below would carry a key from elsewhere forward under this run's name.
            crate::blueprint_load::refuse_unlearned_keys(&value, path)?;
            value.try_into().with_context(|| {
                format!("interpreting existing discovered layer {}", path.display())
            })?
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => BlueprintLayer::default(),
        Err(e) => return Err(e).context(format!("reading {}", path.display())),
    };
    let attribute = |layer: &mut BlueprintLayer, key: String, run_id: &str| {
        layer.discovery.provenance.insert(
            key,
            ProvenanceEntry {
                added_via: added_via.to_string(),
                run_id: run_id.to_string(),
            },
        );
    };
    for entry in accepted {
        match entry.candidate.access {
            DenialAccess::Read => layer.fs.reads.push(entry.candidate.pattern.clone()),
            DenialAccess::Write => layer.fs.writes.push(entry.candidate.pattern.clone()),
        }
        attribute(
            &mut layer,
            entry.candidate.pattern.canonical(),
            &entry.run_id,
        );
    }
    for entry in rules {
        if !layer.rules.contains(&entry.rule) {
            layer.rules.push(entry.rule.clone());
        }
        attribute(&mut layer, rule_key(&entry.rule), &entry.run_id);
    }
    layer.rules.sort();
    if !channels.is_empty() {
        let mut lifted: Vec<Channel> = layer
            .channels
            .as_ref()
            .map(|c| c.allowed().iter().copied().collect())
            .unwrap_or_default();
        for entry in channels {
            let channel = Channel::from_name(&entry.channel)
                .ok_or_else(|| anyhow::anyhow!("unknown channel {:?}", entry.channel))?;
            lifted.push(channel);
            attribute(&mut layer, channel_key(&entry.channel), &entry.run_id);
        }
        layer.channels = Some(ChannelPolicy::allow(lifted));
    }
    layer.fs.reads = formwork_blueprint::canonicalize_set(&layer.fs.reads);
    layer.fs.writes = formwork_blueprint::canonicalize_set(&layer.fs.writes);
    let body = format!(
        "# Discovered grants (formwork learn/accept). Every grant carries provenance (FW-DISC6);\n\
         # authored grants belong in the blueprint, not here.\n{}",
        toml::to_string_pretty(&layer).context("serializing discovered layer")?
    );
    std::fs::write(path, body).with_context(|| format!("writing {}", path.display()))?;
    Ok(accepted.len() + rules.len() + channels.len())
}

/// `formwork learn --list`/`--accept`: per-entry,
/// human-in-the-loop acceptance (FW-DISC5). With no selection it
/// lists the candidates by number instead of erroring, so the review loop is self-describing.
/// A selection names an entry by its 1-based number or by its exact pattern. The credential
/// floor is re-checked here with NO exclusions -- even a forged proposal cannot move a catalog
/// location into the discovered layer through this door (FW-INV8). The destination is the
/// discovered layer of `blueprint_path`, the blueprint this invocation resolved, and never a
/// path the proposal names (FW-DISC19).
pub fn accept(
    proposal_file: &Path,
    blueprint_path: &Path,
    entries: &[String],
    all: bool,
    home: &str,
) -> Result<()> {
    let text = match std::fs::read_to_string(proposal_file) {
        Ok(text) => text,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => bail!(
            "no proposal at {} -- run `formwork learn -- <cmd> …` first to observe one",
            proposal_file.display()
        ),
        Err(e) => return Err(e).context(format!("reading proposal {}", proposal_file.display())),
    };
    let proposal: ProposalFile = toml::from_str(&text)
        .with_context(|| format!("parsing proposal {}", proposal_file.display()))?;

    // FW-DISC19: a proposal learned against another blueprint -- a moved or copied project, or a
    // file from elsewhere -- holds another session's denials, and its entries are not written
    // into this blueprint's layer or into the one it names.
    let resolved = canonical_blueprint(blueprint_path);
    let learned_against = canonical_blueprint(Path::new(&proposal.blueprint));
    if learned_against != resolved {
        bail!(
            "the proposal {} was learned against the blueprint {}, and this invocation resolved \
             {}; accept writes only to the resolved blueprint's discovered layer (FW-DISC19). \
             Run `formwork learn -- <cmd> …` against this blueprint to observe a proposal for it.",
            proposal_file.display(),
            learned_against.display(),
            resolved.display()
        );
    }
    let discovered = discovered_path(blueprint_path);
    let access_name = |access: DenialAccess| match access {
        DenialAccess::Read => "read",
        DenialAccess::Write => "write",
    };

    // The listing IS this invocation's result, so it goes to stdout -- under RUST_LOG=warn a
    // stderr listing would silently vanish, hiding the one thing the user asked for. Numbering
    // runs through paths, then host rules, then channels.
    let paths_n = proposal.candidates.len();
    let hosts_n = proposal.hosts.len();
    let total = paths_n + hosts_n + proposal.channels.len();
    if !all && entries.is_empty() {
        if total == 0 {
            println!("proposal has no candidates; nothing to review");
            return Ok(());
        }
        println!(
            "proposal for {}; accepted entries go to {}",
            resolved.display(),
            discovered.display()
        );
        for (index, entry) in proposal.candidates.iter().enumerate() {
            let access = access_name(entry.candidate.access);
            let tag = match entry.candidate.tag {
                CandidateTag::NeedsReview => "needs-review",
                CandidateTag::AutoAccepted => "auto-accepted",
            };
            println!(
                "{:>3}. {} ({access}, {tag}, observed by {})",
                index + 1,
                entry.candidate.pattern.canonical(),
                entry.run_id
            );
        }
        for (index, entry) in proposal.hosts.iter().enumerate() {
            println!(
                "{:>3}. rules += {:?} (host rule, needs-review, observed by {})",
                paths_n + index + 1,
                entry.rule,
                entry.run_id
            );
        }
        for (index, entry) in proposal.channels.iter().enumerate() {
            println!(
                "{:>3}. channels += {:?} (channel, needs-review, observed by {})",
                paths_n + hosts_n + index + 1,
                entry.channel,
                entry.run_id
            );
        }
        println!(
            "select with `formwork learn --accept <number|pattern|rule|channel>` (repeatable) or \
             --accept-all; auto-accepted entries are already in the discovered layer and are \
             listed for audit only"
        );
        return Ok(());
    }

    // Every selector is honored or refused (FW-INV6 at the CLI surface): one that names no
    // entry, or only an entry a learning run already accepted, stops the accept before anything
    // is written -- beside a valid selector it would otherwise pass for accepted.
    let names: Vec<String> = proposal
        .candidates
        .iter()
        .map(|e| e.candidate.pattern.canonical())
        .chain(proposal.hosts.iter().map(|e| e.rule.clone()))
        .chain(proposal.channels.iter().map(|e| e.channel.clone()))
        .collect();
    let awaits_review = |number: usize| {
        proposal
            .candidates
            .get(number - 1)
            .is_none_or(|e| e.candidate.tag == CandidateTag::NeedsReview)
    };
    let unmatched: Vec<&str> = entries
        .iter()
        .filter(|sel| {
            let selects = |number: usize, name: &str| match sel.parse::<usize>() {
                Ok(n) => n == number,
                Err(_) => *sel == name,
            };
            !names
                .iter()
                .enumerate()
                .any(|(i, name)| selects(i + 1, name) && awaits_review(i + 1))
        })
        .map(String::as_str)
        .collect();
    if !unmatched.is_empty() {
        bail!(
            "no needs-review entry matches {}; nothing was accepted (list the entries with \
             `formwork learn --list`; auto-accepted ones are already in the discovered layer)",
            unmatched.join(", ")
        );
    }
    let picked = |number: usize, name: &str| -> bool {
        all || entries
            .iter()
            .any(|sel| sel.parse::<usize>().map(|n| n == number).unwrap_or(false) || sel == name)
    };
    // Entries are numbered paths first, then hosts, then channels, as listed above.
    fn pick<'a, T>(
        entries: &'a [T],
        first: usize,
        name: impl Fn(&T) -> String,
        picked: &impl Fn(usize, &str) -> bool,
    ) -> Vec<&'a T> {
        entries
            .iter()
            .enumerate()
            .filter(|(i, e)| picked(first + i, &name(e)))
            .map(|(_, e)| e)
            .collect()
    }
    let selected: Vec<&ProposalEntry> = pick(
        &proposal.candidates,
        1,
        |e| e.candidate.pattern.canonical(),
        &picked,
    )
    .into_iter()
    .filter(|e| e.candidate.tag == CandidateTag::NeedsReview)
    .collect();
    let selected_rules = pick(&proposal.hosts, paths_n + 1, |e| e.rule.clone(), &picked);
    let selected_channels = pick(
        &proposal.channels,
        paths_n + hosts_n + 1,
        |e| e.channel.clone(),
        &picked,
    );
    if selected.is_empty() && selected_rules.is_empty() && selected_channels.is_empty() {
        bail!("no needs-review candidate matched the selection (run with no selection to list)");
    }
    // The proposal is untrusted input (FW-DISC3): an entry of a kind no learning run proposes is
    // an authoring decision, and it does not reach the discovered layer through this door. A
    // forged proposal must not smuggle a path rule through the host-rule door either.
    for entry in &selected_rules {
        let is_host = entry
            .rule
            .split_once(':')
            .is_some_and(|(_, target)| formwork_blueprint::target_is_host(target));
        if !is_host {
            bail!("refusing to accept {:?}: not a host rule", entry.rule);
        }
        entry
            .rule
            .parse::<formwork_blueprint::HostRule>()
            .and_then(|rule| formwork_blueprint::proposable_host_rule(&rule))
            .map_err(|e| {
                anyhow::anyhow!(
                    "refusing to accept {:?}: {e}; author it in the blueprint",
                    entry.rule
                )
            })?;
    }
    for entry in &selected {
        if entry.candidate.pattern.is_any_depth() {
            bail!(
                "refusing to accept {}: discovery proposes a path or its directory's subtree, \
                 never an any-depth pattern; author it in the blueprint",
                entry.candidate.pattern.canonical()
            );
        }
    }

    // Same enforcement-time resolution as a run: proposal paths are kernel-resolved, so a
    // catalog left unresolved (a `/tmp`-based home vs the kernel's `/private/tmp`) would let a
    // forged entry slip past the type rows -- the floor must be held in kernel coordinates.
    let catalog = ResolvedCatalog::builtin_for_home(home)
        .context("resolving credential catalog for the acceptance floor check")?;
    let catalog = crate::blueprint_load::canonicalize_catalog_for_enforcement(&catalog)
        .context("canonicalizing credential catalog paths")?;
    for entry in &selected {
        if let Some(credential_type) = catalog.floor_type_of(&[], &entry.candidate.pattern) {
            bail!(
                "refusing to accept {}: it matches the credential floor (type: {credential_type}); \
                 the only lift is the explicit typed exclude, --allow-cred (FW-INV8)",
                entry.candidate.pattern.canonical()
            );
        }
    }

    let count = merge_all_into_discovered(
        &discovered,
        &selected,
        &selected_rules,
        &selected_channels,
        "discovery",
    )?;

    // Rewrite the proposal without the accepted entries so acceptance is visibly consumed.
    // Keyed by (pattern, access), matching the merge key: a same-pattern read and write are
    // distinct candidates, and accepting one must not consume the other unreviewed.
    let accepted: Vec<(String, DenialAccess)> = selected
        .iter()
        .map(|e| (e.candidate.pattern.canonical(), e.candidate.access))
        .collect();
    let remaining = ProposalFile {
        blueprint: proposal.blueprint.clone(),
        candidates: proposal
            .candidates
            .iter()
            .filter(|e| !accepted.contains(&(e.candidate.pattern.canonical(), e.candidate.access)))
            .cloned()
            .collect(),
        hosts: proposal
            .hosts
            .iter()
            .filter(|e| !selected_rules.contains(e))
            .cloned()
            .collect(),
        channels: proposal
            .channels
            .iter()
            .filter(|e| !selected_channels.contains(e))
            .cloned()
            .collect(),
    };
    let body = toml::to_string_pretty(&remaining).context("serializing remaining proposal")?;
    std::fs::write(proposal_file, body)
        .with_context(|| format!("rewriting {}", proposal_file.display()))?;

    // FW-DISC19: the operator sees what this accept wrote, entry by entry, not a count.
    for entry in &selected {
        println!(
            "accepted {} ({}, observed by {})",
            entry.candidate.pattern.canonical(),
            access_name(entry.candidate.access),
            entry.run_id
        );
    }
    for entry in &selected_rules {
        println!(
            "accepted rules += {:?} (host rule, observed by {})",
            entry.rule, entry.run_id
        );
    }
    for entry in &selected_channels {
        println!(
            "accepted channels += {:?} (channel, observed by {})",
            entry.channel, entry.run_id
        );
    }
    println!(
        "accepted {count} grant{} into {}; they apply from the next run",
        if count == 1 { "" } else { "s" },
        discovered.display()
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use formwork_blueprint::PathPattern;

    #[test]
    fn proposal_merge_is_sticky_and_refreshes_reobserved() {
        let entry = |path: &str, run: &str| ProposalEntry {
            candidate: Candidate {
                pattern: PathPattern::parse(path).unwrap(),
                access: DenialAccess::Read,
                tag: CandidateTag::NeedsReview,
            },
            run_id: run.to_string(),
        };
        let previous = vec![
            entry("/opt/toolchain/**", "learn-1"),
            entry("/srv/data", "learn-1"),
        ];
        let observed = vec![
            entry("/srv/data", "learn-2"),
            entry("/var/cache/x", "learn-2"),
        ];
        let (merged, carried) = merge_proposal_entries(previous, observed);
        assert_eq!(
            carried, 1,
            "the un-reobserved toolchain entry is carried, not dropped"
        );
        let by_path: std::collections::BTreeMap<String, String> = merged
            .iter()
            .map(|e| (e.candidate.pattern.canonical(), e.run_id.clone()))
            .collect();
        assert_eq!(by_path["/opt/toolchain/**"], "learn-1");
        assert_eq!(
            by_path["/srv/data"], "learn-2",
            "re-observed entry refreshed"
        );
        assert_eq!(by_path["/var/cache/x"], "learn-2");
        assert_eq!(merged.len(), 3);
    }

    /// The stabilization property behind FW-E2E-064: a feed that is still flushing (each read
    /// yields more than the last) keeps being re-read; the first repeated read is the answer.
    #[test]
    fn quiescence_returns_the_first_repeated_read() {
        let read = |path: &str| DenialRecord {
            path: path.to_string(),
            access: DenialAccess::Read,
        };
        let sequence = [
            vec![read("/a")],
            vec![read("/a"), read("/b")], // a late-flushing record arrived between polls
            vec![read("/a"), read("/b")], // ...and now the store is quiet
            vec![read("/a"), read("/b"), read("/never-reached")],
        ];
        let mut calls = 0;
        let result = collect_until_quiescent(
            || {
                let batch = sequence[calls].clone();
                calls += 1;
                Ok(batch)
            },
            std::time::Duration::from_millis(1),
            std::time::Duration::ZERO,
            std::time::Duration::from_secs(30),
        )
        .unwrap();
        assert_eq!(result, sequence[2]);
        assert_eq!(calls, 3, "polling stops at the first repeated read");
    }

    /// The millisecond-workload trap (FW-E2E-064): before anything has flushed, the store reads
    /// empty and "stable" -- the floor forbids trusting that until real settle time has passed.
    #[test]
    fn a_session_keeps_only_its_tagged_records() {
        let messages = vec![
            "Sandbox: cat(1) deny(1) file-read-data /x\nfw-session-a".to_string(),
            "Sandbox: mdworker(2) deny(1) file-read-data /y".to_string(),
            "Sandbox: cat(3) deny(1) file-read-data /z\nfw-session-b".to_string(),
        ];
        assert_eq!(
            this_session(messages.clone(), Some("fw-session-a")),
            vec!["Sandbox: cat(1) deny(1) file-read-data /x".to_string()]
        );
        assert_eq!(this_session(messages.clone(), None), messages);
    }

    #[test]
    fn macos_service_denials_map_to_channels_and_withhold_the_keychain() {
        let catalog = ResolvedCatalog::builtin_for_home("/Users/x").unwrap();
        let messages: Vec<String> = [
            "Sandbox: pbcopy(12) deny(1) mach-lookup com.apple.pasteboard.1",
            "Sandbox: screencapture(13) deny(1) mach-lookup com.apple.windowserver.active",
            "Sandbox: osascript(14) deny(1) appleevent-send",
            "Sandbox: security(15) deny(1) mach-lookup com.apple.SecurityServer",
            "Sandbox: open(16) deny(1) lsopen",
            "Sandbox: mdworker(17) deny(1) mach-lookup com.apple.FileProvider",
            "Sandbox: cat(18) deny(1) file-read-data /etc/x",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();
        let mut obs = SessionObservations::default();
        service_observations(&messages, &catalog, &mut obs);
        assert_eq!(obs.channels, vec!["clipboard", "run-outside", "screen"]);
        let withheld: Vec<&str> = obs.withheld.iter().map(|(w, _)| w.as_str()).collect();
        assert_eq!(withheld, vec!["LaunchServices", "com.apple.SecurityServer"]);
    }

    #[test]
    fn quiescence_does_not_trust_empty_reads_before_the_floor() {
        let floor = std::time::Duration::from_millis(300);
        let started = std::time::Instant::now();
        let result = collect_until_quiescent(
            || Ok(Vec::<DenialRecord>::new()),
            std::time::Duration::from_millis(25),
            floor,
            std::time::Duration::from_secs(5),
        )
        .unwrap();
        assert!(result.is_empty());
        assert!(
            started.elapsed() >= floor,
            "an all-empty feed concluded after {:?}, before the {floor:?} floor",
            started.elapsed()
        );
    }

    #[test]
    fn quiescence_floor_catches_a_record_that_flushes_after_empty_reads() {
        let flushed_at = std::time::Duration::from_millis(150);
        let record = DenialRecord {
            path: "/late/flush".to_string(),
            access: DenialAccess::Read,
        };
        let started = std::time::Instant::now();
        let expected = record.clone();
        let result = collect_until_quiescent(
            move || {
                // The store is empty until "persistence latency" elapses -- longer than several
                // polls, shorter than the floor -- then the record appears.
                if started.elapsed() < flushed_at {
                    Ok(Vec::new())
                } else {
                    Ok(vec![record.clone()])
                }
            },
            std::time::Duration::from_millis(25),
            std::time::Duration::from_millis(400),
            std::time::Duration::from_secs(5),
        )
        .unwrap();
        assert_eq!(
            result,
            vec![expected],
            "the late-flushing record must be captured"
        );
    }

    #[test]
    fn quiescence_cap_bounds_a_feed_that_never_settles() {
        let mut calls: usize = 0;
        let result = collect_until_quiescent(
            || {
                calls += 1;
                // Every read yields something new, so only the cap can end the loop.
                Ok((0..calls)
                    .map(|i| DenialRecord {
                        path: format!("/flush/{i}"),
                        access: DenialAccess::Write,
                    })
                    .collect())
            },
            std::time::Duration::from_millis(1),
            std::time::Duration::ZERO,
            std::time::Duration::from_millis(20),
        )
        .unwrap();
        // Bounded, and what WAS collected is returned rather than discarded (over-capture is
        // safe; under-capture just means another learning run).
        assert_eq!(result.len(), calls);
        assert!(
            calls >= 2,
            "the cap must not fire before a re-read happened"
        );
    }

    #[test]
    fn quiescence_propagates_collector_errors() {
        let result = collect_until_quiescent::<DenialRecord>(
            || bail!("log show failed"),
            std::time::Duration::from_millis(1),
            std::time::Duration::ZERO,
            std::time::Duration::from_millis(10),
        );
        assert!(result.is_err());
    }

    #[test]
    fn parses_real_sandbox_messages() {
        // Shape captured live from `log show` on macOS 15 (see docs/fep-2-plan.md §4).
        let record = parse_sandbox_denial(
            "Sandbox: cat(29810) deny(1) file-read-data /private/tmp/fw-spike/home/.aws/credentials",
        )
        .unwrap();
        assert_eq!(record.path, "/private/tmp/fw-spike/home/.aws/credentials");
        assert_eq!(record.access, DenialAccess::Read);

        let write =
            parse_sandbox_denial("Sandbox: sh(123) deny(1) file-write-create /work/out.txt")
                .unwrap();
        assert_eq!(write.access, DenialAccess::Write);

        // Non-fs denials and unparsable lines yield nothing.
        assert!(parse_sandbox_denial("Sandbox: x(1) deny(1) mach-lookup com.apple.foo").is_none());
        assert!(parse_sandbox_denial("unrelated log line").is_none());
    }

    /// The denial a one-call trace states, before the filesystem is consulted.
    fn observed(trace: &str, launch_dir: &Path) -> Option<ObservedDenial> {
        let (mut denials, _) = observe_strace(trace, launch_dir);
        assert!(denials.len() <= 1, "{denials:?}");
        denials.pop()
    }

    #[test]
    fn parses_real_strace_denials() {
        // Shapes captured from `strace -f -e trace=%file` on Linux 6.x.
        let cwd = Path::new("/work/proj");
        let denied = observed(
            "12345 openat(AT_FDCWD, \"/home/x/.ssh/id_rsa\", O_RDONLY) = -1 EACCES (Permission denied)",
            cwd,
        )
        .unwrap();
        assert_eq!(denied.path, "/home/x/.ssh/id_rsa");
        assert_eq!(denied.access, DenialAccess::Read);

        let write = observed(
            "12345 openat(AT_FDCWD, \"/srv/out.txt\", O_WRONLY|O_CREAT|O_TRUNC, 0666) = -1 EACCES (Permission denied)",
            cwd,
        )
        .unwrap();
        assert_eq!(write.access, DenialAccess::Write);

        let exec = observed(
            "9 execve(\"/opt/tool/bin/run\", [\"run\"], 0x7ffd deadbeef) = -1 EACCES (Permission denied)",
            cwd,
        )
        .unwrap();
        assert_eq!(
            exec.access,
            DenialAccess::Read,
            "exec denial is a read-grant gap"
        );
        assert_eq!(exec.path, "/opt/tool/bin/run");

        let mkdir = observed(
            "9 mkdir(\"/srv/newdir\", 0777) = -1 EACCES (Permission denied)",
            cwd,
        )
        .unwrap();
        assert_eq!(mkdir.access, DenialAccess::Write);
    }

    #[test]
    fn strace_relative_paths_resolve_against_the_launch_directory() {
        let cwd = Path::new("/work/proj");
        let rel = observed(
            "7 openat(AT_FDCWD, \"data/input.csv\", O_RDONLY) = -1 EACCES (Permission denied)",
            cwd,
        )
        .unwrap();
        assert_eq!(rel.path, "/work/proj/data/input.csv");

        // A real (numeric) dirfd base is unattributable from the trace alone: dropped, never
        // guessed (under-capture is safe; a wrong absolute path would poison the proposal).
        let bare = "7 openat(5, \"nested.txt\", O_RDONLY) = -1 EACCES (Permission denied)";
        assert!(observed(bare, cwd).is_none());
        assert_eq!(observe_strace(bare, cwd).1, 1, "dropped, and counted");
    }

    const DENIED: &str = "= -1 EACCES (Permission denied)";

    /// Issue #51's substring grading: the open flags are the flags ARGUMENT. A name the
    /// workload chose is opaque, whatever it spells -- a flag, or a whole result.
    #[test]
    fn fw_disc2_strace_grades_an_open_by_its_flags_argument() {
        let cwd = Path::new("/work");
        let named_like_a_flag = observed(
            &format!(
                "7 openat(AT_FDCWD</work>, \"O_WRONLY-notes.txt\", O_RDONLY|O_CLOEXEC) {DENIED}"
            ),
            cwd,
        )
        .unwrap();
        assert_eq!(named_like_a_flag.access, DenialAccess::Read);
        assert_eq!(named_like_a_flag.path, "/work/O_WRONLY-notes.txt");

        let write = observed(
            &format!("7 openat(AT_FDCWD</work>, \"/srv/out\", O_WRONLY|O_CREAT, 0666) {DENIED}"),
            cwd,
        )
        .unwrap();
        assert_eq!(write.access, DenialAccess::Write);
        let how = observed(
            &format!(
                "7 openat2(AT_FDCWD</work>, \"/srv/out\", {{flags=O_RDWR|O_CLOEXEC, \
                 resolve=RESOLVE_NO_SYMLINKS}}, 24) {DENIED}"
            ),
            cwd,
        )
        .unwrap();
        assert_eq!(how.access, DenialAccess::Write);
        let legacy = observed(&format!("7 open(\"/srv/in\", O_RDONLY) {DENIED}"), cwd).unwrap();
        assert_eq!(legacy.access, DenialAccess::Read);

        // Captured from strace 6.8 (directories shortened): a SUCCESSFUL open of a file whose
        // name spells a denial, printed in the argument and again beside the descriptor.
        let forged = concat!(
            r#"7 openat(AT_FDCWD</work>, "x\", O_RDONLY) = -1 EACCES (Permission denied)\n"#,
            r#"9 openat(AT_FDCWD, \"etc-shadow", O_RDONLY|O_CLOEXEC) = "#,
            r#"3</work/x\", O_RDONLY) = -1 EACCES (Permission denied)\n"#,
            r#"9 openat(AT_FDCWD, \"etc-shadow>"#,
        );
        assert_eq!(observe_strace(forged, cwd), (Vec::new(), 0));
    }

    /// Issue #51 (a): the refused path of a two-path call is the entry being made, not the link
    /// text or the source that precedes it.
    #[test]
    fn fw_disc2_strace_two_path_calls_name_the_entry_that_was_refused() {
        let cwd = Path::new("/work");
        for (call, refused) in [
            (
                "symlink(\"/etc/hostname\", \"/out/sub/newlink\")",
                "/out/sub/newlink",
            ),
            (
                "symlinkat(\"/etc/hostname\", AT_FDCWD</work>, \"link\")",
                "/work/link",
            ),
            ("rename(\"a.txt\", \"/out/b\")", "/out/b"),
            (
                "renameat2(AT_FDCWD</work>, \"a.txt\", 5</out>, \"b\", RENAME_NOREPLACE)",
                "/out/b",
            ),
            ("link(\"/work/a.txt\", \"/out/hard\")", "/out/hard"),
            (
                "linkat(AT_FDCWD</work>, \"a.txt\", AT_FDCWD</work>, \"/out/hard\", 0)",
                "/out/hard",
            ),
        ] {
            let denial = observed(&format!("7 {call} {DENIED}"), cwd).expect(call);
            assert_eq!(denial.path, refused, "{call}");
            assert_eq!(denial.access, DenialAccess::Write, "{call}");
            assert!(denial.names_entry, "{call}");
        }
    }

    /// Issue #51 (b): a relative path is relative to the directory of the process that passed
    /// it -- its own `chdir`, its parent's at the fork, its thread group's -- and never to the
    /// launch directory by default.
    #[test]
    fn fw_disc2_strace_relative_paths_follow_each_process_directory() {
        let cwd = Path::new("/launch");
        let trace = [
            "10 execve(\"/bin/sh\", [\"sh\"], 0x7ffc /* 3 vars */) = 0",
            "10 chdir(\"/usr/share\") = 0",
            // The child's first call lands before the parent's fork returns, as strace prints it.
            "10 vfork( <unfinished ...>",
            "11 mkdir(\"made-by-child\", 0777) = -1 EACCES (Permission denied)",
            "10 <... vfork resumed>) = 11",
            "11 chdir(\"doc\") = 0",
            "11 unlink(\"gone\") = -1 EACCES (Permission denied)",
            // The child's chdir did not move the parent.
            "10 mkdir(\"made-by-parent\", 0777) = -1 EACCES (Permission denied)",
            // A thread shares its creator's directory, and moves it.
            "10 clone3({flags=CLONE_VM|CLONE_FS|CLONE_FILES|CLONE_THREAD, child_tid=0x7f, \
             exit_signal=0, stack=0x7f, stack_size=0x7fff80} => {parent_tid=[12]}, 88) = 12",
            "12 chdir(\"/srv\") = 0",
            "10 rmdir(\"after-thread\") = -1 EACCES (Permission denied)",
            // fchdir: only `-y`'s annotation says where the descriptor leads.
            "11 fchdir(3</opt/tool>) = 0",
            "11 mkdir(\"plugins\", 0777) = -1 EACCES (Permission denied)",
            "11 fchdir(4) = 0",
            "11 mkdir(\"nowhere\", 0777) = -1 EACCES (Permission denied)",
            // A real dirfd is attributable once strace prints its path.
            "11 openat(5</var/cache>, \"x/y\", O_RDONLY) = -1 EACCES (Permission denied)",
            // A process the trace never saw being created has no known directory...
            "99 mkdir(\"orphan\", 0777) = -1 EACCES (Permission denied)",
            // ...until the kernel's own answer appears beside AT_FDCWD.
            "99 openat(AT_FDCWD</home/u>, \"notes\", O_RDONLY) = -1 EACCES (Permission denied)",
            "99 mkdir(\"known-now\", 0777) = -1 EACCES (Permission denied)",
            // Past a chroot, even an absolute path names something else.
            "10 chroot(\"/srv/jail\") = 0",
            "10 mkdir(\"/etc/inside-the-jail\", 0777) = -1 EACCES (Permission denied)",
        ]
        .join("\n");
        let (denials, unattributed) = observe_strace(&trace, cwd);
        let paths: Vec<&str> = denials.iter().map(|d| d.path.as_str()).collect();
        assert_eq!(
            paths,
            [
                "/usr/share/made-by-child",
                "/usr/share/doc/gone",
                "/usr/share/made-by-parent",
                "/srv/after-thread",
                "/opt/tool/plugins",
                "/var/cache/x/y",
                "/home/u/notes",
                "/home/u/known-now",
            ]
        );
        assert_eq!(unattributed, 3, "nowhere, orphan and the jailed mkdir");
    }

    /// Issue #51 (c): strace prints bytes outside ASCII as octal escapes; the path is the bytes.
    #[test]
    fn fw_disc2_strace_decodes_escaped_path_bytes() {
        let cwd = Path::new("/work");
        let accented = observed(
            &format!(
                "7 openat(AT_FDCWD</work>, \"/out/caf\\303\\251/notes.txt\", O_RDONLY) {DENIED}"
            ),
            cwd,
        )
        .unwrap();
        assert_eq!(accented.path, "/out/café/notes.txt");
        let quoted = observed(
            &format!("7 mkdir(\"/out/a\\\"b\\\\c\\td\\1e\", 0777) {DENIED}"),
            cwd,
        )
        .unwrap();
        assert_eq!(quoted.path, "/out/a\"b\\c\td\u{1}e");
        let through_dirfd = observed(
            &format!("7 openat(3</out/a\\76b, \\\"c\\303\\251>, \"f\", O_RDONLY) {DENIED}"),
            cwd,
        )
        .unwrap();
        assert_eq!(through_dirfd.path, "/out/a>b, \"cé/f");

        // Bytes no grant can spell, and a string strace cut short: counted, never proposed.
        for unspellable in [
            format!("7 mkdir(\"/out/bad\\377\", 0777) {DENIED}"),
            format!("7 mkdir(\"/out/cut\"..., 0777) {DENIED}"),
        ] {
            assert_eq!(
                observe_strace(&unspellable, cwd),
                (Vec::new(), 1),
                "{unspellable}"
            );
        }
    }

    /// Issue #51 (d): `-f` splits a call another process interrupts; the halves are one call.
    #[test]
    fn fw_disc2_strace_rejoins_interleaved_calls() {
        let cwd = Path::new("/work");
        let trace = [
            "10 execve(\"/bin/sh\", [\"sh\"], 0x7ffc /* 3 vars */) = 0",
            "10 clone(child_stack=NULL, flags=CLONE_CHILD_CLEARTID|SIGCHLD, child_tidptr=0x7f) = 11",
            "10 openat(AT_FDCWD</work>, \"/srv/a\", O_RDONLY <unfinished ...>",
            "11 openat(AT_FDCWD</work>, \"/srv/b\", O_WRONLY|O_CREAT, 0666 <unfinished ...>",
            "10 <... openat resumed>) = -1 EACCES (Permission denied)",
            "11 <... openat resumed>) = -1 EACCES (Permission denied)",
            // Captured from strace 6.8: a whole call on a file named like the split marker.
            "10 openat(AT_FDCWD</work>, \"x <unfinished ...\", O_RDONLY) = 4</work/x \\74unfinished ...>",
            "10 mkdir(\"/srv/c\", 0777) = -1 EACCES (Permission denied)",
            // A second half with no first (the tracer attached mid-call): counted.
            "12 <... openat resumed>) = -1 EACCES (Permission denied)",
            // A first half that never resumes (the process was killed) refused nothing.
            "11 unlink(\"/srv/d\" <unfinished ...>",
        ]
        .join("\n");
        let (denials, unattributed) = observe_strace(&trace, cwd);
        let seen: Vec<(&str, DenialAccess)> = denials
            .iter()
            .map(|d| (d.path.as_str(), d.access))
            .collect();
        assert_eq!(
            seen,
            [
                ("/srv/a", DenialAccess::Read),
                ("/srv/b", DenialAccess::Write),
                ("/srv/c", DenialAccess::Write),
            ]
        );
        assert_eq!(unattributed, 1);
    }

    /// The path a grant must name is the one the kernel resolved: through a symlink for an open,
    /// to the entry's own directory for a call on the entry, and through `..` as the filesystem
    /// has it -- never collapsed as text (issue #51 (b)).
    #[cfg(unix)]
    #[test]
    fn fw_disc2_strace_paths_resolve_as_the_kernel_resolved_them() {
        let root =
            std::env::temp_dir().join(format!("formwork-kernel-path-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("real/deep")).unwrap();
        let root = std::fs::canonicalize(&root).unwrap();
        std::fs::write(root.join("real/target"), "x").unwrap();
        std::os::unix::fs::symlink(root.join("real/target"), root.join("alias")).unwrap();
        std::os::unix::fs::symlink(root.join("real/deep"), root.join("jump")).unwrap();
        let at = |rel: &str| format!("{}/{rel}", root.display());

        assert_eq!(kernel_path(&at("alias"), false), Some(at("real/target")));
        assert_eq!(kernel_path(&at("alias"), true), Some(at("alias")));
        // `jump/..` is `real`, not the directory `jump` sits in.
        assert_eq!(kernel_path(&at("jump/../new"), true), Some(at("real/new")));
        assert_eq!(kernel_path(&at("jump/../new"), false), Some(at("real/new")));
        // Nothing on disk to resolve `..` against: no path is proposed.
        assert_eq!(kernel_path(&at("missing/../new"), false), None);
        assert_eq!(
            kernel_path("/formwork-no-such-dir/a/b", false).as_deref(),
            Some("/formwork-no-such-dir/a/b")
        );

        let trace = format!(
            "7 chdir(\"{jump}\") = 0\n7 openat(AT_FDCWD, \"../new\", O_WRONLY|O_CREAT, 0666) {DENIED}\n\
             7 mkdir(\"/formwork-no-such-dir/x/../y\", 0777) {DENIED}",
            jump = at("jump")
        );
        let parsed = parse_strace_denials(&trace, Path::new("/"));
        assert_eq!(
            parsed.records,
            vec![DenialRecord {
                path: at("real/new"),
                access: DenialAccess::Write
            }]
        );
        assert_eq!(parsed.unattributed, 1);
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn strace_noise_is_not_discovery_material() {
        let cwd = Path::new("/w");
        // Successful opens, ENOENT probes, and stat/access failures (unix perms, not Landlock).
        for line in [
            "1 openat(AT_FDCWD, \"/etc/ld.so.cache\", O_RDONLY|O_CLOEXEC) = 3",
            "1 openat(AT_FDCWD, \"/missing\", O_RDONLY) = -1 ENOENT (No such file or directory)",
            "1 access(\"/etc/shadow\", R_OK) = -1 EACCES (Permission denied)",
            "1 newfstatat(AT_FDCWD, \"/root/x\", 0x7ffc, 0) = -1 EACCES (Permission denied)",
            "1 +++ exited with 1 +++",
            "unrelated",
        ] {
            assert!(observed(line, cwd).is_none(), "{line}");
        }
    }
}
