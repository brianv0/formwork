//! Human renderings of the observability surfaces: the host summary (the `--help` epilogue and
//! `explain`'s first line), per-path verdicts, and the fidelity-report summary. `compile` and
//! `explain --json` stay the machine door with stable JSON; everything here is prose for a person
//! at a terminal, so wording favors "what can I do about it" over field names.

use formwork_blueprint::{Explanation, RuleSource, Verdict};
use formwork_compile::{Backend, Fidelity, FidelityReport};
use formwork_detect::{HostProfile, Os};

/// One line answering "will this machine enforce, and can `learn` observe?".
/// `strace_on_path` is the CLI edge's answer to [`crate::learn::find_strace`]: strace is a
/// userspace tool, not a kernel capability, so it stays out of the HostProfile data model and
/// rides in as the one extra fact the Linux feed line needs.
pub fn host_summary(profile: &HostProfile, strace_on_path: bool) -> String {
    match profile.os {
        Os::MacOs => format!(
            "macOS ({}) -- Seatbelt: kernel enforcement ready; `learn` denial feed: unified log",
            profile.os_version
        ),
        Os::Linux => {
            match profile.landlock_abi {
                Some(abi) => format!(
                    "Linux {} -- Landlock ABI v{abi} + seccomp: kernel enforcement ready; `learn` \
                 denial feed: {}",
                    profile.os_version,
                    if strace_on_path {
                        "ptrace (strace)"
                    } else {
                        "install strace to enable"
                    }
                ),
                None => {
                    format!(
                "Linux {} -- no Landlock (kernel 5.13+ needed){}: fs enforcement unavailable; \
                 compile/dry-run still work",
                profile.os_version,
                if profile.seccomp { ", seccomp only" } else { ", no seccomp" }
            )
                }
            }
        }
    }
}

fn source(s: &RuleSource) -> String {
    match s {
        RuleSource::BuiltIn => "built-in".to_string(),
        RuleSource::Profile(name) => format!("profile {name}"),
        RuleSource::File(name) => format!("blueprint {name}"),
        RuleSource::Cli => "cli override".to_string(),
        RuleSource::Discovered(name) => format!("discovered layer {name}"),
    }
}

fn verdict(v: &Verdict) -> String {
    match v {
        Verdict::Granted { rule, source: s } => format!("granted by {rule} ({})", source(s)),
        Verdict::Denied { rule, source: s } => format!("denied by {rule} ({})", source(s)),
        Verdict::Ambient => "allowed by default (no rule names it)".to_string(),
        Verdict::Hidden => "not granted (nothing reaches it in this policy)".to_string(),
    }
}

/// One path's three verdicts, indented under the path.
pub fn explanation(e: &Explanation) -> String {
    format!(
        "{}\n  read:  {}\n  write: {}\n  exec:  {}\n",
        e.path,
        verdict(&e.read),
        verdict(&e.write),
        verdict(&e.exec)
    )
}

/// The remedy line under a credential-floor denial: the `allow-credentials` entry that lifts it.
/// The floor is the one deny `explain` can never show a grant for (FW-CAP8), so naming the lever
/// is the operator channel (FW-CRED7) the confined tool's bare EACCES lacks. The backstop also
/// names its `shape`, since that is the surprise: it fires even inside a granted directory.
pub fn floor_remedy(floor_type: &str, shape: Option<&str>) -> String {
    if floor_type == "backstop" {
        format!(
            "  hint: credential backstop (shape {}) -- fires at any depth, even inside a granted \
             directory. Lift with allow-credentials = [\"backstop\"] (coarse: un-denies every \
             backstop shape everywhere; prefer narrowing a real type when one fits).\n",
            shape.unwrap_or("**/<name>")
        )
    } else {
        format!(
            "  hint: credential floor (type {floor_type}) -- lift with \
             allow-credentials = [\"{floor_type}\"].\n"
        )
    }
}

fn backend(b: Backend) -> &'static str {
    match b {
        Backend::Landlock => "landlock",
        Backend::Seccomp => "seccomp",
        Backend::Seatbelt => "seatbelt",
        Backend::Gateway => "gateway",
        Backend::Launcher => "launcher",
        Backend::None => "none",
    }
}

fn fidelity(f: &Fidelity) -> String {
    match f {
        Fidelity::Enforced { backend: b } => format!("enforced ({})", backend(*b)),
        Fidelity::Partial { backend: b, reason } => {
            format!("partial ({}) -- {reason}", backend(*b))
        }
        Fidelity::Unenforceable { reason } => format!("unavailable -- {reason}"),
    }
}

/// The fidelity report as prose: per-capability honesty plus the credential floor's shape. The
/// full itemization stays in `compile --report-only`; this is the at-a-glance form.
pub fn report_summary(report: &FidelityReport) -> String {
    let mut out = String::from("capabilities:\n");
    let width = report
        .per_capability
        .keys()
        .map(|c| c.as_key().len())
        .max()
        .unwrap_or(0);
    for (capability, f) in &report.per_capability {
        out.push_str(&format!(
            "  {:width$}  {}\n",
            capability.as_key(),
            fidelity(f),
            width = width
        ));
    }
    let creds = &report.credentials;
    let path_types = creds.per_type.values().filter(|f| f.path.is_some()).count();
    let env_types = creds.per_type.values().filter(|f| f.env.is_some()).count();
    out.push_str(&format!(
        "credential floor: catalog v{} -- {path_types} path type{} denied, {env_types} env \
         type{} stripped; allowed through: {}\n",
        creds.catalog_version,
        if path_types == 1 { "" } else { "s" },
        if env_types == 1 { "" } else { "s" },
        if creds.allowed.is_empty() {
            "(none)".to_string()
        } else {
            creds.allowed.join(", ")
        }
    ));
    // The backstop denies inside the operator's own granted set, so it earns its own line with the
    // lift (FW-CRED6/CRED7); `None` means already lifted.
    if creds.backstop.is_some() {
        out.push_str(
            "backstop: filename shapes (credentials, id_rsa, id_ed25519, .netrc, …) denied at any \
             depth, even inside granted directories; lift with allow-credentials = [\"backstop\"]\n",
        );
    }
    out.push_str(&format!("note: {}\n", creds.launcher_contingency));
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_summary_states_enforcement_and_learn_availability() {
        let mac = host_summary(&HostProfile::synthetic_macos(), false);
        assert!(
            mac.contains("Seatbelt") && mac.contains("unified log"),
            "{mac}"
        );

        let linux_v6 = host_summary(&HostProfile::synthetic_linux(Some(6)), true);
        assert!(
            linux_v6.contains("Landlock ABI v6") && linux_v6.contains("ptrace (strace)"),
            "{linux_v6}"
        );

        let no_strace = host_summary(&HostProfile::synthetic_linux(Some(6)), false);
        assert!(no_strace.contains("install strace"), "{no_strace}");

        let degraded = host_summary(&HostProfile::synthetic_linux(None), false);
        assert!(
            degraded.contains("no Landlock") && degraded.contains("compile/dry-run still work"),
            "{degraded}"
        );
    }

    #[test]
    fn verdicts_name_rule_and_origin() {
        let e = Explanation {
            path: "/work/secret".to_string(),
            read: Verdict::Denied {
                rule: "/work/secret".to_string(),
                source: RuleSource::Cli,
            },
            write: Verdict::Hidden,
            exec: Verdict::Ambient,
        };
        let text = explanation(&e);
        assert!(
            text.contains("read:  denied by /work/secret (cli override)"),
            "{text}"
        );
        assert!(text.contains("write: not granted"), "{text}");
        assert!(text.contains("exec:  allowed by default"), "{text}");
    }

    #[test]
    fn floor_remedy_names_the_shape_and_the_lift() {
        // The backstop remedy names the surprising shape and the coarse lift...
        let bs = floor_remedy("backstop", Some("**/credentials"));
        assert!(bs.contains("**/credentials"), "{bs}");
        assert!(bs.contains("allow-credentials = [\"backstop\"]"), "{bs}");
        assert!(bs.contains("any depth"), "{bs}");
        // ...a curated type names itself as the lift instead.
        let ssh = floor_remedy("ssh", None);
        assert!(ssh.contains("allow-credentials = [\"ssh\"]"), "{ssh}");
        assert!(!ssh.contains("backstop"), "{ssh}");
    }
}
