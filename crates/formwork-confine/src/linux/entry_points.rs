//! The entry-point table of `docs/linux-backend.md` against the code (FW-ISO32, FW-FID32,
//! FW-ADV-051): each call a `mediated` row puts under a filter gets that verdict from the compiled
//! filter, each `open` row's clause is in the reason of every report row it names, and every
//! system call the running kernel offers is named in the table or in the list beneath it.

use std::collections::BTreeSet;

use formwork_blueprint::{
    Blueprint, ExecPosture, HostRule, HostTable, NetPosture, PathPattern, ResolvedCatalog,
};
use formwork_compile::{Capability, CompiledPolicy, ConfinerPolicy, Fidelity};
use formwork_detect::HostProfile;

use super::bpf_eval::eval;
use super::supervise::{notify_filter, AUDIT_ARCH};

const DOC: &str = include_str!("../../../../docs/linux-backend.md");

struct Row {
    effect: String,
    reports: Vec<String>,
    calls: Vec<String>,
    mechanism: String,
    /// `None` for a mediated row; the postures named in its parenthesis and its clause for an open
    /// one.
    open: Option<(Vec<String>, String)>,
}

fn between<'a>(text: &'a str, begin: &str, end: &str) -> &'a str {
    let start = text
        .find(begin)
        .unwrap_or_else(|| panic!("{begin} is missing"))
        + begin.len();
    let len = text[start..]
        .find(end)
        .unwrap_or_else(|| panic!("{end} is missing"));
    &text[start..start + len]
}

/// Backticked tokens that are system-call names: lower-case identifiers.
fn names(cell: &str) -> Vec<String> {
    cell.split('`')
        .skip(1)
        .step_by(2)
        .filter(|t| {
            t.chars().next().is_some_and(|c| c.is_ascii_lowercase())
                && t.chars()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
        })
        .map(str::to_string)
        .collect()
}

fn table() -> Vec<Row> {
    let body = between(
        DOC,
        "<!-- entry-points: begin -->",
        "<!-- entry-points: end -->",
    );
    let mut rows: Vec<Row> = Vec::new();
    for line in body.lines().filter(|l| l.starts_with('|')).skip(2) {
        let cells: Vec<&str> = line
            .trim()
            .trim_matches('|')
            .split('|')
            .map(str::trim)
            .collect();
        assert_eq!(cells.len(), 5, "a table row has five cells: {line}");
        let (effect, reports) = match (cells[0].is_empty(), rows.last()) {
            (true, Some(prev)) => (prev.effect.clone(), prev.reports.clone()),
            (true, None) => panic!("the first row has no effect: {line}"),
            (false, _) => (
                cells[0].to_string(),
                cells[1]
                    .split('`')
                    .skip(1)
                    .step_by(2)
                    .map(str::to_string)
                    .collect(),
            ),
        };
        let status = cells[4];
        let open = if status == "mediated" {
            None
        } else {
            let rest = status
                .strip_prefix("open")
                .unwrap_or_else(|| panic!("a status is `mediated` or `open`: {line}"));
            let (postures, clause) = rest.split_once(':').expect("an open row quotes its clause");
            let postures = postures
                .trim()
                .trim_start_matches('(')
                .trim_end_matches(')')
                .split(',')
                .map(|p| p.trim().to_string())
                .filter(|p| !p.is_empty())
                .collect();
            let clause = clause.trim().trim_matches('"').to_string();
            assert!(!clause.is_empty(), "an open row quotes its clause: {line}");
            Some((postures, clause))
        };
        rows.push(Row {
            effect,
            reports,
            calls: names(cells[2]),
            mechanism: cells[3].to_string(),
            open,
        });
    }
    assert!(rows.len() > 20, "the table parsed into {} rows", rows.len());
    rows
}

fn number(name: &str) -> Option<libc::c_long> {
    Some(match name {
        "add_key" => libc::SYS_add_key,
        "bpf" => libc::SYS_bpf,
        "clone" => libc::SYS_clone,
        "connect" => libc::SYS_connect,
        "execveat" => libc::SYS_execveat,
        "finit_module" => libc::SYS_finit_module,
        "init_module" => libc::SYS_init_module,
        "io_uring_enter" => libc::SYS_io_uring_enter,
        "io_uring_register" => libc::SYS_io_uring_register,
        "io_uring_setup" => libc::SYS_io_uring_setup,
        "kexec_file_load" => libc::SYS_kexec_file_load,
        "kexec_load" => libc::SYS_kexec_load,
        "keyctl" => libc::SYS_keyctl,
        "listen" => libc::SYS_listen,
        "mount" => libc::SYS_mount,
        "mount_setattr" => libc::SYS_mount_setattr,
        "move_mount" => libc::SYS_move_mount,
        "open_by_handle_at" => libc::SYS_open_by_handle_at,
        "perf_event_open" => libc::SYS_perf_event_open,
        "pidfd_getfd" => libc::SYS_pidfd_getfd,
        "pivot_root" => libc::SYS_pivot_root,
        "process_vm_readv" => libc::SYS_process_vm_readv,
        "process_vm_writev" => libc::SYS_process_vm_writev,
        "ptrace" => libc::SYS_ptrace,
        "request_key" => libc::SYS_request_key,
        "sendmmsg" => libc::SYS_sendmmsg,
        "sendmsg" => libc::SYS_sendmsg,
        "sendto" => libc::SYS_sendto,
        "setns" => libc::SYS_setns,
        "socket" => libc::SYS_socket,
        "socketpair" => libc::SYS_socketpair,
        "unshare" => libc::SYS_unshare,
        _ => return None,
    })
}

fn host() -> HostProfile {
    HostProfile::synthetic_linux(Some(6))
}

fn compiled(net: NetPosture, exec: ExecPosture) -> CompiledPolicy {
    let blueprint = Blueprint {
        net,
        exec,
        ..Blueprint::empty()
    };
    formwork_compile::compile(&blueprint, &host(), &ResolvedCatalog::empty_no_floor())
}

fn postures() -> Vec<(&'static str, NetPosture)> {
    let rule: HostRule = serde_json::from_str("\"tunnel:allowed.test\"").unwrap();
    vec![
        ("deny", NetPosture::Deny),
        ("ports", NetPosture::Ports(vec![443])),
        ("hosts", NetPosture::AllowHosts(HostTable::new(vec![rule]))),
    ]
}

fn allowlist() -> ExecPosture {
    ExecPosture::Allowlist(vec![PathPattern::parse("/usr/bin/true").unwrap()])
}

fn filters(policy: &CompiledPolicy) -> super::seccomp::Built {
    match &policy.confiner {
        ConfinerPolicy::Linux(l) => super::seccomp::build(&l.seccomp).expect("the plan builds"),
        other => panic!("expected a Linux confiner, got {other:?}"),
    }
}

fn with(i: usize, v: u64) -> [u64; 6] {
    let mut a = [0u64; 6];
    a[i] = v;
    a
}

fn refused(action: u32) -> bool {
    action & libc::SECCOMP_RET_ACTION_FULL == libc::SECCOMP_RET_ERRNO
}

/// FW-ISO32: every call a `mediated` row puts under the notify filter, the baseline, the second
/// filter or the socket allow-list gets that verdict from the filter the compiler's plan builds.
#[test]
fn fw_iso32_every_mediated_call_gets_its_verdict_from_the_filters() {
    let deny = filters(&compiled(NetPosture::Deny, ExecPosture::Unrestricted));
    let ports = filters(&compiled(NetPosture::Ports(vec![443]), allowlist()));
    let notify = notify_filter();
    let mut checked = 0;
    for row in table().iter().filter(|r| r.open.is_none()) {
        let m = &row.mechanism;
        let mechanisms = [
            m.contains("notify filter"),
            m.contains("baseline"),
            m.contains("second filter"),
            m.contains("allow-list"),
        ];
        if !mechanisms.contains(&true) {
            continue;
        }
        for call in &row.calls {
            let nr = number(call)
                .unwrap_or_else(|| panic!("{}: `{call}` is not a known system call", row.effect));
            let mut covered = false;
            if mechanisms[0] {
                let args = if call == "sendto" {
                    with(4, 0x1000)
                } else {
                    [0; 6]
                };
                let v = eval(&notify, AUDIT_ARCH, nr as u32, args);
                assert_eq!(
                    v,
                    libc::SECCOMP_RET_USER_NOTIF,
                    "{}: `{call}` notifies",
                    row.effect
                );
                covered = true;
            }
            if mechanisms[1] {
                let args = match call.as_str() {
                    "unshare" | "clone" => with(0, libc::CLONE_NEWUSER as u64),
                    _ => [0; 6],
                };
                assert!(
                    refused(deny.verdicts(nr, args).0),
                    "{}: baseline refuses `{call}`",
                    row.effect
                );
                covered = true;
            }
            if mechanisms[2] {
                let args = match call.as_str() {
                    "sendto" | "sendmmsg" => with(3, libc::MSG_FASTOPEN as u64),
                    "sendmsg" => with(2, libc::MSG_FASTOPEN as u64),
                    "execveat" => with(4, libc::AT_EMPTY_PATH as u64),
                    _ => [0; 6],
                };
                assert!(
                    refused(ports.verdicts(nr, args).1),
                    "{}: second filter refuses `{call}`",
                    row.effect
                );
                covered = true;
            }
            if mechanisms[3] && (call == "socket" || call == "socketpair") {
                for args in [
                    [libc::AF_VSOCK as u64, libc::SOCK_STREAM as u64, 0, 0, 0, 0],
                    [libc::AF_INET as u64, libc::SOCK_DGRAM as u64, 0, 0, 0, 0],
                    [libc::AF_INET6 as u64, libc::SOCK_RAW as u64, 0, 0, 0, 0],
                ] {
                    assert!(
                        refused(ports.verdict(nr, args)),
                        "{}: `{call}` {args:?}",
                        row.effect
                    );
                }
                let stream = [libc::AF_INET as u64, libc::SOCK_STREAM as u64, 0, 0, 0, 0];
                assert!(
                    !refused(ports.verdict(nr, stream)),
                    "the port tier admits a TCP stream"
                );
                covered = true;
            }
            assert!(
                covered,
                "{}: no filter the row names covers `{call}`",
                row.effect
            );
            checked += 1;
        }
    }
    assert!(checked > 30, "{checked} mediated calls checked");
}

/// FW-E2E-190 (FW-FID32): for each `open` row, every report row it names is `Partial` on Linux,
/// with a reason that carries the row's clause, under each posture the row applies to -- unless
/// the host cannot enforce the report row at all.
#[test]
fn fw_e2e_190_every_open_entry_point_names_itself_in_the_report() {
    let mut matrix = Vec::new();
    for (name, net) in postures() {
        for exec in [ExecPosture::Unrestricted, allowlist()] {
            let listed = matches!(exec, ExecPosture::Allowlist(_));
            matrix.push((name, listed, compiled(net.clone(), exec)));
        }
    }
    let mut checked = 0;
    for row in table() {
        let Some((only, clause)) = &row.open else {
            continue;
        };
        let nets: Vec<&str> = only
            .iter()
            .map(String::as_str)
            .filter(|p| ["deny", "ports", "hosts"].contains(p))
            .collect();
        let needs_allowlist = only.iter().any(|p| p == "allow-list");
        for (net, listed, policy) in &matrix {
            if (!nets.is_empty() && !nets.contains(net)) || (needs_allowlist && !listed) {
                continue;
            }
            for key in &row.reports {
                let cap = Capability::from_key(key)
                    .unwrap_or_else(|| panic!("{}: `{key}` is not a report row", row.effect));
                match policy.report.per_capability.get(&cap) {
                    None | Some(Fidelity::Unenforceable { .. }) => {}
                    Some(Fidelity::Partial { reason, .. }) => {
                        assert!(
                            reason.contains(clause.as_str()),
                            "{} ({net}): `{key}` does not name {clause:?}: {reason}",
                            row.effect
                        );
                        checked += 1;
                    }
                    Some(other) => panic!(
                        "{} ({net}): `{key}` is {other:?} with an open entry point",
                        row.effect
                    ),
                }
            }
        }
    }
    assert!(checked > 20, "{checked} report rows checked");
}

/// FW-ADV-051, bounded: every system call the running kernel offers is named in the table or in
/// the list of calls with none of its effects, so a call a new kernel adds fails here until it
/// is classified. The kernel's entries are read from `/proc/kallsyms`, not called: a sweep that
/// issued each with zeroed arguments would act on the host for some of them.
#[cfg(target_arch = "x86_64")]
#[test]
fn fw_adv_051_every_system_call_the_kernel_offers_is_classified() {
    let Ok(symbols) = std::fs::read_to_string("/proc/kallsyms") else {
        if std::env::var("FW_REQUIRE_EXERCISED").as_deref() == Ok("1") {
            panic!("not exercised on a CI runner: /proc/kallsyms is unreadable");
        }
        eprintln!("skipping: /proc/kallsyms is unreadable");
        return;
    };
    let offered: BTreeSet<&str> = symbols
        .lines()
        .filter_map(|l| l.split_whitespace().nth(2))
        .filter_map(|s| s.strip_prefix("__x64_sys_"))
        .map(|s| s.split('.').next().unwrap_or(s))
        .collect();
    if offered.len() < 300 {
        if std::env::var("FW_REQUIRE_EXERCISED").as_deref() == Ok("1") {
            panic!("not exercised on a CI runner: /proc/kallsyms lists no syscall entries");
        }
        eprintln!(
            "skipping: /proc/kallsyms lists {} syscall entries",
            offered.len()
        );
        return;
    }
    let mut known: BTreeSet<String> = table().into_iter().flat_map(|r| r.calls).collect();
    let listed = between(DOC, "<!-- inert: begin -->", "<!-- inert: end -->");
    known.extend(
        listed
            .lines()
            .filter(|l| !l.starts_with("```"))
            .flat_map(str::split_whitespace)
            .map(str::to_string),
    );
    let unclassified: Vec<&str> = offered
        .iter()
        .copied()
        .filter(|s| !known.contains(*s))
        .collect();
    assert!(
        unclassified.is_empty(),
        "system calls this kernel offers that docs/linux-backend.md does not classify: \
         {unclassified:?}"
    );
}
