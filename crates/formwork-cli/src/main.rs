//! `formwork` -- the CLI and v1 embedding surface.
//!
//! ```text
//! formwork run     [--blueprint s.toml] -- cmd args…  # spawn-confined (--confine-self to exec in place)
//! formwork learn   [--blueprint s.toml] -- cmd args…  # enforced run + denial observation
//! formwork learn   --list | --accept <n|pattern> | --accept-all   # review the proposal
//! formwork explain [--blueprint s.toml] [path…]       # human observability: host, policy, verdicts
//! formwork compile [--blueprint s.toml] [--host h.json | --target linux-v6|macos] [--report-only]
//! formwork gateway [--blueprint s.toml] --server files -- cmd…  # MCP policy proxy over stdio
//! ```
//!
//! The blueprint is `--blueprint`, or a `FORMWORK.toml` discovered from the launch directory
//! upward -- always announced, never silent. Every blueprint-taking subcommand accepts the same
//! override surface (FW-BP1/BP2): `--set '<toml>'` fragments and the sugar flags
//! (`--read/--write/--subtract/--write-subtract/--allow-cred/--net/--extends`) layer over the
//! file, additively, deny-beats-allow.
//!
//! `compile`/`explain` don't enforce and run on any host (including compiling a Linux policy on a
//! Mac); `run`/`gateway` need a real confiner and error honestly where the backend is
//! unimplemented. The machine-readable host profile is `explain --json` (the `host` field);
//! `run --confine-self` and `learn --list`/`--accept` carry what the retired `enforce-self` and
//! `accept` plumbing aliases used to.

mod blueprint_load;
mod learn;
mod render;

use std::path::PathBuf;
use std::process::Command;

use anyhow::{anyhow, bail, Context, Result};
use clap::{CommandFactory, FromArgMatches, Parser, Subcommand, ValueEnum};

use blueprint_load::ResolvedBlueprint;
use formwork_blueprint::{
    Blueprint, BlueprintLayer, NetPosture, PathPattern, ResolvedCatalog, Verdict,
};
use formwork_compile::compile;
use formwork_detect::{detect, HostProfile};

const AFTER_HELP: &str = "With no --blueprint, every subcommand looks for a FORMWORK.toml in the \
current directory and its parents (up to $HOME) and says so when it uses one.\n\nPath patterns \
(in blueprint files and flags) accept two sigils, expanded before compilation: ~ for $HOME and \
$CWD for the launch directory -- so `--read '$CWD/**'` scopes a grant to the project you run \
from.\n\nTelemetry goes to stderr (stdout stays a clean result stream). RUST_LOG=warn quiets it; \
RUST_LOG=debug itemizes the credential floor per type.";

#[derive(Parser)]
#[command(
    name = "formwork",
    version,
    about = "OS-level sandbox for agent sessions"
)]
struct Cli {
    #[command(subcommand)]
    command: Cmd,
}

/// Parse argv with a computed help epilogue: probing the host is two cheap syscalls, and "will
/// this machine enforce?" is the first question a new user brings to `--help`.
fn parse_cli() -> Cli {
    let epilogue = format!(
        "{AFTER_HELP}\n\nThis host: {}",
        render::host_summary(&detect(), learn::find_strace().is_some())
    );
    let matches = Cli::command().after_help(epilogue).get_matches();
    match Cli::from_arg_matches(&matches) {
        Ok(cli) => cli,
        Err(e) => e.exit(),
    }
}

#[derive(Subcommand)]
enum Cmd {
    /// Compile a blueprint into a policy + fidelity report without enforcing (dry-run, JSON).
    Compile {
        #[command(flatten)]
        blueprint: BlueprintArgs,
        /// Compile against a host profile loaded from JSON (overrides --target and live detection).
        #[arg(long)]
        host: Option<PathBuf>,
        /// Convenience synthetic host, e.g. for cross-platform dry-run.
        #[arg(long, value_enum)]
        target: Option<Target>,
        /// Print only the fidelity report, not the full compiled policy.
        #[arg(long)]
        report_only: bool,
    },
    /// Spawn a command under confinement (spawn-confined posture).
    Run {
        #[command(flatten)]
        blueprint: BlueprintArgs,
        /// Confine THIS process, then exec the command in place (the confine-self posture:
        /// PID-preserving, no launcher left in the tree). Default is the safer spawn posture.
        #[arg(long)]
        confine_self: bool,
        #[arg(trailing_var_arg = true, allow_hyphen_values = true, required = true)]
        argv: Vec<String>,
    },
    /// Learning run (observe-then-widen, FW-DISC1): enforce exactly like `run`, record the
    /// denials the kernel logged during the window, and reverse-compile them into a reviewable
    /// proposal. Observation never widens the live session (FW-INV10). Exits with the WORKLOAD's
    /// status -- a first learning run usually fails on the very denials it is there to observe;
    /// the proposal is written regardless. Review the proposal with --list / --accept /
    /// --accept-all (no command after --).
    Learn {
        #[command(flatten)]
        blueprint: BlueprintArgs,
        /// List the proposal's candidates by number (review mode; no command after --).
        #[arg(long)]
        list: bool,
        /// Accept one needs-review candidate by its 1-based number or exact pattern (repeatable;
        /// review mode). Credential-floor matches are refused regardless of what the proposal
        /// claims (FW-INV8).
        #[arg(long)]
        accept: Vec<String>,
        /// Accept every needs-review candidate (review mode).
        #[arg(long)]
        accept_all: bool,
        /// Review a proposal file that is not beside its blueprint (default:
        /// <blueprint>.proposal.toml).
        #[arg(long)]
        proposal: Option<PathBuf>,
        /// On a host with no denial feed (a Linux kernel without Landlock, or Linux without
        /// `strace` installed), run enforced anyway. No proposal will be written -- observation
        /// is impossible, not just skipped.
        #[arg(long)]
        observe_anyway: bool,
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        argv: Vec<String>,
    },
    /// Front a stdio MCP backend with the policy gateway: shade its tools/resources/prompts per the
    /// blueprint's `[mcp.<server>]` entry and confine the spawned backend to the blueprint's fs/net grant.
    /// Speaks newline-delimited JSON-RPC on stdin/stdout, so an MCP host launches it as the server.
    Gateway {
        #[command(flatten)]
        blueprint: BlueprintArgs,
        /// Which `[mcp.<server>]` policy from the blueprint governs this connection.
        #[arg(long)]
        server: String,
        #[arg(trailing_var_arg = true, allow_hyphen_values = true, required = true)]
        argv: Vec<String>,
    },
    /// Explain the session without enforcing (FW-FID6), human-readably. With paths: each path's
    /// read, write, and exec verdict, the rule that decides it under the deny-terminal model
    /// (FW-CAP8), and the layer that rule came from. With no path: this host's enforcement
    /// capabilities plus the merged blueprint's fidelity summary (host-only when no blueprint is
    /// found). Reflects the merged blueprint like `compile`, not the session-only denies `run`
    /// adds (FW-CRED3 env-file refs, FW-XR8 policy-input write-protection). Same override surface.
    /// Default output became human-readable in the usability rework, with `--json` carrying the
    /// machine shape -- a pre-release surface change, no version bump (canary consumers only; the
    /// FW-CRED8 Backend-rename precedent).
    Explain {
        #[command(flatten)]
        blueprint: BlueprintArgs,
        /// Machine-readable JSON instead of the human rendering.
        #[arg(long)]
        json: bool,
        /// Print the resolved host table: one host rule per line with its grade, methods, paths,
        /// and the layer that wrote it (FW-FID11). (`--net` is the net-posture override every
        /// blueprint-taking subcommand already accepts.)
        #[arg(long)]
        hosts: bool,
        /// Paths to explain; a `scheme://` URL explains egress to it, and a channel or group name
        /// (`clipboard`, `desktop`) explains that channel. Sigils `~`/`$CWD` expand as in a grant; a bare relative path
        /// resolves against the current directory, so `explain ./credentials` just works.
        paths: Vec<String>,
    },
}

/// One blueprint, two surfaces (FW-BP1): the file plus the CLI override layer. `--set` fragments
/// are TOML parsed by the same serde model as the file -- parity is by construction -- and the
/// sugar flags desugar into one final layer (postures here beat `--set`, both beat the file).
#[derive(clap::Args)]
struct BlueprintArgs {
    /// The blueprint file. Omitted: a FORMWORK.toml discovered from the launch directory upward
    /// (announced, never silent).
    #[arg(long)]
    blueprint: Option<PathBuf>,
    /// Override layer as a TOML fragment in blueprint syntax (repeatable, applied in order),
    /// e.g. --set 'net = "deny"' or --set '[fs]
    /// subtract = ["~/other/**"]'.
    #[arg(long)]
    set: Vec<String>,
    /// Append a read grant path pattern.
    #[arg(long)]
    read: Vec<String>,
    /// Append a write grant path pattern.
    #[arg(long)]
    write: Vec<String>,
    /// Append a read+write deny hole (deny beats allow at any layer).
    #[arg(long)]
    subtract: Vec<String>,
    /// Append a write-deny-keep-readable hole (tamper vectors, FW-TRA7).
    #[arg(long)]
    write_subtract: Vec<String>,
    /// Let one credential type through the catalog floor (FW-CRED5), e.g. --allow-cred aws.
    /// The only mechanism that lifts a catalog entry; path grants never do.
    #[arg(long = "allow-cred")]
    allow_cred: Vec<String>,
    /// Net posture: "deny" or "ports:443,8080".
    #[arg(long)]
    net: Option<String>,
    /// Append a flat capability rule "<verb>:<target>" (repeatable), the same vocabulary as a file
    /// `rules` line (FW-BP1). A target starting with `/`, `~`, `$` or `**` is a path, and takes
    /// read/readonly, readwrite, modify (write without create), allow, readexec, exec or deny,
    /// e.g. --rule "deny:~/.ssh". Any other target is a host, host[:port][/glob] (FW-BP13/FW-BP16),
    /// and puts all egress behind the session Gateway: allow:host (every method, TLS inspected),
    /// HTTP method verbs such as get,post:github.com/acme/**, tunnel:host[:port] (TLS passed
    /// through, not inspected; no path), or deny:host[:port][/glob].
    #[arg(long)]
    rule: Vec<String>,
    /// Reads posture: "unveil" (empty universe) or "subtractive" (ambient minus catalog);
    /// a friendlier alias of `[fs] read-mode`.
    #[arg(long)]
    mode: Option<String>,
    /// Extra base blueprints layered under the CLI overrides (repeatable, resolved against cwd).
    #[arg(long)]
    extends: Vec<String>,
}

impl BlueprintArgs {
    /// Which blueprint file governs this invocation, or a teaching error when none is named and
    /// none is discoverable. The resolved source travels into logs and `compile`/`explain` output
    /// so auto-discovery is never silent.
    fn resolve(&self) -> Result<ResolvedBlueprint> {
        self.try_resolve()?.ok_or_else(no_blueprint_error)
    }

    /// As [`Self::resolve`], but `Ok(None)` when nothing is named or discoverable -- for the one
    /// caller (`explain` with no path) that degrades to a host-only summary instead of erroring.
    fn try_resolve(&self) -> Result<Option<ResolvedBlueprint>> {
        let cwd = cwd()?;
        blueprint_load::resolve_blueprint(
            self.blueprint.as_deref(),
            std::path::Path::new(&cwd),
            &home(),
        )
    }

    /// Whether any override flag was given -- overrides without a base blueprint are an error,
    /// not a silent no-op (the user expressed intent that would otherwise be dropped).
    fn has_overrides(&self) -> bool {
        !(self.set.is_empty()
            && self.read.is_empty()
            && self.write.is_empty()
            && self.subtract.is_empty()
            && self.write_subtract.is_empty()
            && self.allow_cred.is_empty()
            && self.rule.is_empty()
            && self.extends.is_empty())
            || self.net.is_some()
            || self.mode.is_some()
    }

    /// Re-emit the override surface as argv for the `run --confine-self` shim the Linux learning
    /// run traces, so the shim compiles the same session this invocation described. Lossless by
    /// construction: flags are one surface onto the one model (FW-BP1), and the shim re-parses
    /// them with this very parser.
    fn forward_overrides(&self) -> Vec<String> {
        let mut out = Vec::new();
        let repeatable: [(&str, &[String]); 7] = [
            ("--set", &self.set),
            ("--read", &self.read),
            ("--write", &self.write),
            ("--subtract", &self.subtract),
            ("--write-subtract", &self.write_subtract),
            ("--allow-cred", &self.allow_cred),
            ("--rule", &self.rule),
        ];
        for (flag, values) in repeatable {
            for value in values {
                out.push(flag.to_string());
                out.push(value.clone());
            }
        }
        for extend in &self.extends {
            out.push("--extends".to_string());
            out.push(extend.clone());
        }
        if let Some(net) = &self.net {
            out.push("--net".to_string());
            out.push(net.clone());
        }
        if let Some(mode) = &self.mode {
            out.push("--mode".to_string());
            out.push(mode.clone());
        }
        out
    }

    /// Resolve the full layer stack and merge (FW-BP2). Path sigils (`~`, `$CWD`) in flag values
    /// expand against the same `$HOME`/launch directory as file contents, via one shared
    /// [`blueprint_load::Sigils`], so the two surfaces stay one model.
    fn load(&self, path: &std::path::Path, home: &str) -> Result<Blueprint> {
        let cwd = cwd()?;
        let sigils = blueprint_load::Sigils::new(home, &cwd);
        let sugar = self.sugar_layer(&sigils)?;
        blueprint_load::load_stack(path, &self.set, sugar, &sigils)
    }

    /// As [`Self::load`], but also returns the per-layer provenance for `explain` (FW-FID6).
    fn load_with_provenance(
        &self,
        path: &std::path::Path,
        home: &str,
    ) -> Result<(Blueprint, formwork_blueprint::Provenance)> {
        let cwd = cwd()?;
        let sigils = blueprint_load::Sigils::new(home, &cwd);
        let sugar = self.sugar_layer(&sigils)?;
        blueprint_load::load_stack_with_provenance(path, &self.set, sugar, &sigils)
    }

    fn sugar_layer(&self, sigils: &blueprint_load::Sigils) -> Result<BlueprintLayer> {
        let patterns = |flag: &str, values: &[String]| -> Result<Vec<PathPattern>> {
            values
                .iter()
                .map(|v| {
                    PathPattern::parse(&sigils.expand(v)).with_context(|| format!("--{flag} {v:?}"))
                })
                .collect()
        };
        Ok(BlueprintLayer {
            // Sigils expand in `extends` too, matching a file's `extends` (FW-BP1/FW-BP5 parity).
            extends: self.extends.iter().map(|e| sigils.expand(e)).collect(),
            // Verbs and `mode` are desugared into `fs`/`exec` by the loader (blueprint_load), the
            // same edge that resolves a file's `rules`/`mode`, so `--rule` and a file agree.
            rules: self.rule.clone(),
            mode: self.mode.as_deref().map(parse_mode).transpose()?,
            fs: formwork_blueprint::FsLayer {
                read_mode: None,
                reads: patterns("read", &self.read)?,
                writes: patterns("write", &self.write)?,
                // The write-without-create grant (FW-CAP9) is authored via the `modify:` verb
                // (`--rule`) or the nested `[fs] writes-no-create` key, not a dedicated sugar flag.
                writes_no_create: Vec::new(),
                subtract: patterns("subtract", &self.subtract)?,
                write_subtract: patterns("write-subtract", &self.write_subtract)?,
            },
            net: self.net.as_deref().map(parse_net).transpose()?,
            exec: None,
            env: None,
            mcp: Default::default(),
            allow_credentials: self
                .allow_cred
                .iter()
                .map(|c| formwork_blueprint::CredentialEntry::parse(c))
                .collect(),
            discovery: Default::default(),
            channels: None,
            isolate: Vec::new(),
            hosts: Vec::new(),
        })
    }
}

fn parse_net(s: &str) -> Result<NetPosture> {
    if s == "deny" {
        return Ok(NetPosture::Deny);
    }
    if let Some(list) = s.strip_prefix("ports:") {
        let ports = list
            .split(',')
            .map(|p| {
                p.trim()
                    .parse::<u16>()
                    .with_context(|| format!("--net port {p:?}"))
            })
            .collect::<Result<Vec<u16>>>()?;
        if ports.is_empty() {
            bail!("--net ports: requires at least one port (use \"deny\" for none)");
        }
        return Ok(NetPosture::Ports(ports));
    }
    bail!("--net accepts \"deny\" or \"ports:<p1,p2,…>\", got {s:?}")
}

fn parse_mode(s: &str) -> Result<formwork_blueprint::Mode> {
    match s {
        "unveil" => Ok(formwork_blueprint::Mode::Unveil),
        "subtractive" => Ok(formwork_blueprint::Mode::Subtractive),
        other => bail!("--mode accepts \"unveil\" or \"subtractive\", got {other:?}"),
    }
}

#[derive(Clone, Copy, ValueEnum)]
enum Target {
    #[value(name = "linux-v1")]
    LinuxV1,
    #[value(name = "linux-v4")]
    LinuxV4,
    #[value(name = "linux-v6")]
    LinuxV6,
    Macos,
}

impl Target {
    fn profile(self) -> HostProfile {
        match self {
            Target::LinuxV1 => HostProfile::synthetic_linux(Some(1)),
            Target::LinuxV4 => HostProfile::synthetic_linux(Some(4)),
            Target::LinuxV6 => HostProfile::synthetic_linux(Some(6)),
            Target::Macos => HostProfile::synthetic_macos(),
        }
    }
}

fn home() -> String {
    std::env::var("HOME").unwrap_or_else(|_| "/".to_string())
}

/// The launch directory, for the `$CWD` sigil. Unlike `home()`'s "/" fallback, an unavailable or
/// non-UTF-8 cwd fails loud: silently expanding `$CWD` to "/" would turn a `$CWD/**` grant into a
/// filesystem-wide one -- exactly the fail-open the sensitive-set model forbids (FW-INV6).
fn cwd() -> Result<String> {
    let dir = std::env::current_dir().context("resolving the current directory for $CWD")?;
    dir.into_os_string()
        .into_string()
        .map_err(|_| anyhow!("current directory is not valid UTF-8; cannot expand $CWD (FW-INV6)"))
}

fn resolve_host(host: &Option<PathBuf>, target: &Option<Target>) -> Result<HostProfile> {
    if let Some(path) = host {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("reading host {}", path.display()))?;
        let profile: HostProfile =
            serde_json::from_str(&text).context("parsing host profile JSON")?;
        Ok(profile)
    } else if let Some(t) = target {
        Ok(t.profile())
    } else {
        Ok(detect())
    }
}

/// Libraries only emit, never configure -- so this installs the subscriber once, at the entrypoint.
/// Telemetry goes to stderr so stdout stays a clean machine-readable result stream.
fn init_telemetry() {
    use std::io::IsTerminal;
    use tracing_subscriber::{fmt, EnvFilter};
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    let _ = fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .with_target(false)
        // Color codes belong to humans at terminals; a piped stderr (a host's journal, a test
        // harness) gets clean text it can grep without stripping escapes first.
        .with_ansi(std::io::stderr().is_terminal())
        .try_init();
}

fn main() -> Result<()> {
    // The isolation stage (FW-ISO10) is this binary re-executed by `run` before any thread starts;
    // in every other process this returns `None` at once.
    #[cfg(target_os = "linux")]
    if let Some(code) = formwork_confine::isolation_stage() {
        std::process::exit(code);
    }
    // FW-CRED16 / FW-ISO16 on macOS: a confined workload reads same-uid environments through
    // kern.procargs2, which Seatbelt does not mediate, and this process's holds the operator's
    // credentials. Single-threaded here: nothing else has started.
    #[cfg(target_os = "macos")]
    // SAFETY: first thing in main, before any thread or environment pointer exists.
    unsafe {
        formwork_confine::conceal_environment();
    }
    take_learning_report_fd();
    init_telemetry();
    let cli = parse_cli();
    let cmd = match &cli.command {
        Cmd::Compile { .. } => "compile",
        Cmd::Run { .. } => "run",
        Cmd::Learn { .. } => "learn",
        Cmd::Gateway { .. } => "gateway",
        Cmd::Explain { .. } => "explain",
    };
    // One correlation id per invocation, propagated to every layer's events via the current span.
    let _root = tracing::info_span!("formwork", run_id = std::process::id(), cmd).entered();
    match cli.command {
        Cmd::Compile {
            blueprint,
            host,
            target,
            report_only,
        } => {
            let resolved = blueprint.resolve()?;
            let blueprint = blueprint.load(&resolved.path, &home())?;
            let host = resolve_host(&host, &target)?;
            let catalog = ResolvedCatalog::builtin_for_home(&home())
                .context("resolving credential catalog")?;
            let policy = compile(&blueprint, &host, &catalog);
            let mut value = if report_only {
                serde_json::to_value(&policy.report)?
            } else {
                serde_json::to_value(&policy)?
            };
            attach_blueprint_info(&mut value, &resolved);
            println!("{}", serde_json::to_string_pretty(&value)?);
        }
        Cmd::Run {
            blueprint,
            confine_self,
            argv,
        } => run(blueprint, argv, confine_self)?,
        Cmd::Learn {
            blueprint,
            list,
            accept,
            accept_all,
            proposal,
            observe_anyway,
            argv,
        } => {
            let review = list || !accept.is_empty() || accept_all;
            if review && !argv.is_empty() {
                bail!(
                    "give either a command to observe (after --) or review flags \
                     (--list/--accept/--accept-all), not both"
                );
            }
            // Every flag is honored or refused, never silently dropped (the FW-INV6 shape at the
            // CLI surface): a mode that ignores expressed intent teaches the wrong contract.
            if review {
                if blueprint.has_overrides() {
                    bail!(
                        "review mode (--list/--accept/--accept-all) reads the proposal; blueprint \
                         override flags (--rule, --set, --allow-cred, …) shape a run and would be \
                         ignored here (the acceptance floor check ignores exclusions by design, \
                         FW-INV8). Overrides belong on the observing run (`formwork learn -- cmd \
                         …`) or in the blueprint file."
                    );
                }
                if observe_anyway {
                    bail!(
                        "--observe-anyway applies to an observing run (`formwork learn -- cmd …`), \
                         not to review mode -- review reads a proposal and needs no denial feed"
                    );
                }
                let proposal = match proposal {
                    Some(p) => p,
                    None => learn::proposal_path(&blueprint.resolve()?.path),
                };
                learn::accept(&proposal, &accept, accept_all, &home())?;
            } else if argv.is_empty() {
                bail!(
                    "nothing to do: give a command to observe (`formwork learn -- cmd …`) or \
                     review the proposal (--list, --accept <n|pattern>, --accept-all)"
                );
            } else {
                if proposal.is_some() {
                    bail!(
                        "--proposal names a proposal file for review mode; an observing run \
                         always writes <blueprint>.proposal.toml beside its blueprint, so the \
                         flag would be ignored. Review with `formwork learn --list --proposal \
                         <file>` instead."
                    );
                }
                learn_run(blueprint, argv, observe_anyway)?;
            }
        }
        Cmd::Gateway {
            blueprint,
            server,
            argv,
        } => gateway(blueprint, server, argv)?,
        Cmd::Explain {
            blueprint,
            json,
            hosts,
            paths,
        } => explain(blueprint, paths, json, hosts)?,
    }
    Ok(())
}

/// The teaching error for "no blueprint anywhere" -- one constructor, so the two places that can
/// hit it (resolution, and `explain`'s override-without-base arm) cannot drift apart.
fn no_blueprint_error() -> anyhow::Error {
    anyhow!(
        "no blueprint: pass --blueprint <file>, or create a {name} in this directory (or \
         a parent, up to $HOME). A minimal {name}:\n\n    \
         extends = [\"builtin:default\"]\n    \
         rules = [\"readwrite:$CWD/**\"]\n",
        name = blueprint_load::DEFAULT_BLUEPRINT_NAME
    )
}

/// Stamp which blueprint the output reflects, and how it was chosen, into a `compile`/`explain`
/// JSON result -- the dry-run must always say what it dry-ran, or auto-discovery turns opaque.
fn attach_blueprint_info(value: &mut serde_json::Value, resolved: &ResolvedBlueprint) {
    if let serde_json::Value::Object(map) = value {
        map.insert(
            "blueprint".to_string(),
            serde_json::json!({
                "path": resolved.path.display().to_string(),
                "source": resolved.source.as_str(),
            }),
        );
    }
}

/// Explain paths against the merged blueprint (FW-FID6), no enforcement. Evaluates the
/// deny-terminal model (FW-CAP8) against the authored -- not enforcement-canonicalized -- grants,
/// so the rule it names is the one the operator wrote. The credential floor is a built-in,
/// un-liftable deny, resolved here the way `compile --report-only` resolves it. Scope matches
/// `compile`: the session-only denies `prepare_session` adds (FW-CRED3 env-file refs, FW-XR8
/// policy-input write-protection) are not applied -- explain reflects the blueprint, not a run.
/// With no path, summarizes the session instead: host capabilities plus the merged blueprint's
/// fidelity report (host-only when no blueprint exists) -- the human door `detect`'s JSON never was.
fn explain(args: BlueprintArgs, paths: Vec<String>, json: bool, hosts: bool) -> Result<()> {
    if hosts {
        return explain_net(&args, json);
    }
    if paths.is_empty() {
        return explain_summary(&args, json);
    }
    let home = home();
    let resolved = args.resolve()?;
    let (blueprint, provenance) = args.load_with_provenance(&resolved.path, &home)?;
    let cwd = cwd()?;
    let sigils = blueprint_load::Sigils::new(&home, &cwd);
    let catalog =
        ResolvedCatalog::builtin_for_home(&home).context("resolving credential catalog")?;
    let host = detect();
    // Channel verdicts and the per-path host notes come from the compiled policy, so both say what
    // this host's kernel is given, not what the model says (FW-INV5).
    let policy = compile(&blueprint, &host, &catalog);
    let report = &policy.report;
    let fs_unconfined = matches!(
        report
            .per_capability
            .get(&formwork_compile::Capability::FsRead),
        None | Some(formwork_compile::Fidelity::Unenforceable { .. })
    );
    let landlock_withholds = host.os == formwork_detect::Os::Linux && host.landlock_abi.is_some();
    let landlock_holes = match &policy.confiner {
        formwork_compile::ConfinerPolicy::Linux(linux) if landlock_withholds => {
            Some(&linux.subtract)
        }
        _ => None,
    };
    // Shape rides beside the verdict, not into the JSON: only the human door prints the lift hint,
    // the machine shape stays stable (FW-CRED7).
    let mut rows = Vec::new();
    let mut channel_rows = Vec::new();
    let mut url_rows = Vec::new();
    for arg in &paths {
        if arg.contains("://") {
            url_rows.push(explain_url(&blueprint, &provenance, arg)?);
            continue;
        }
        // Typed by shape (FW-FID11): a channel or group name is a channel, anything else a path.
        if let Some(channel) = formwork_blueprint::Channel::from_name(arg) {
            channel_rows.push(provenance.explain_channel(channel));
            continue;
        }
        if let Some(group) = formwork_blueprint::ChannelGroup::from_name(arg) {
            for channel in group.members() {
                channel_rows.push(provenance.explain_channel(*channel));
            }
            continue;
        }
        let path = arg;
        // A bare relative path resolves against cwd here: blueprint rules stay absolute/sigil to be
        // location-independent, but `explain` is a live diagnostic, not a stored grant.
        let expanded = sigils.expand(path);
        let expanded = if expanded.starts_with('/') {
            expanded
        } else {
            std::path::Path::new(&cwd)
                .join(&expanded)
                .to_string_lossy()
                .into_owned()
        };
        let target =
            PathPattern::parse(&expanded).with_context(|| format!("explaining {path:?}"))?;
        let floor = catalog.floor_type_of(&blueprint.exposed_credentials(), &target);
        let shape = floor
            .as_deref()
            .filter(|t| *t == formwork_blueprint::BACKSTOP)
            .and_then(|_| {
                catalog
                    .backstop
                    .iter()
                    .find(|p| p.matches_path(target.base()))
                    .map(|p| p.to_string())
            });
        let mut explanation = provenance.explain(&blueprint, target.base(), floor.clone());
        // D2: the model verdict above is not always what this kernel does. With no filesystem
        // confinement nothing is denied; on Landlock a floor row that exists only in any-depth form
        // is withheld, unless an installed hole or the absence of any grant stops the path anyway.
        let floor_here = if fs_unconfined {
            render::FloorOnHost::Unconfined
        } else {
            match (&floor, landlock_holes) {
                (Some(_), Some(holes)) => {
                    let held = holes.iter().any(|hole| {
                        hole == &target
                            || hole.covers(&target)
                            || target.covers(hole)
                            || (!target.is_any_depth() && hole.matches_path(target.base()))
                    });
                    let reachable = matches!(
                        provenance.explain(&blueprint, target.base(), None).read,
                        Verdict::Granted { .. } | Verdict::Ambient
                    );
                    if held || !reachable {
                        render::FloorOnHost::Denied
                    } else {
                        render::FloorOnHost::Withheld
                    }
                }
                _ => render::FloorOnHost::Denied,
            }
        };
        if floor_here == render::FloorOnHost::Withheld {
            explanation.host_note = Some(
                "withheld on this host -- Landlock cannot root the any-depth floor row, so this \
                 path is not denied by the kernel here (see `withheld` in the report)"
                    .to_string(),
            );
        } else if landlock_withholds && provenance.write_subtract_only_any_depth(target.base()) {
            explanation.host_note = Some(
                "write denial withheld on this host -- Landlock cannot root the any-depth \
                 write-subtract row, so writes here are not denied by the kernel"
                    .to_string(),
            );
        }
        rows.push((explanation, floor, shape, floor_here));
    }
    if json {
        let explanations: Vec<_> = rows.iter().map(|(e, ..)| e).collect();
        let mut value = serde_json::json!({ "explanations": explanations });
        if !channel_rows.is_empty() {
            value["channels"] = serde_json::to_value(&channel_rows)?;
        }
        if !url_rows.is_empty() {
            value["egress"] = serde_json::to_value(&url_rows)?;
        }
        attach_blueprint_info(&mut value, &resolved);
        println!("{}", serde_json::to_string_pretty(&value)?);
    } else {
        println!(
            "blueprint: {} ({})",
            resolved.path.display(),
            resolved.source.as_str()
        );
        for (explanation, floor, shape, here) in &rows {
            print!("{}", render::explanation(explanation));
            if let Some(floor_type) = floor {
                print!(
                    "{}",
                    render::floor_remedy(floor_type, shape.as_deref(), *here)
                );
            }
        }
        for channel in &channel_rows {
            print!("{}", render::channel_explanation(channel, report));
        }
        for url in &url_rows {
            print!("{}", render::egress_explanation(url));
        }
    }
    Ok(())
}

/// One URL's egress verdict (FW-FID11): the host's grade, which methods the path admits, the
/// deciding rule and the layer that wrote it.
#[derive(serde::Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct EgressExplanation {
    pub url: String,
    pub host: String,
    pub port: u16,
    /// `tunnel`, `inspected`, or `denied`.
    pub grade: &'static str,
    /// Per HTTP method on an inspected host: admitted or not, and the deciding rule.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub methods: Vec<MethodVerdict>,
    pub rule: Option<String>,
    pub source: Option<formwork_blueprint::RuleSource>,
    pub reason: Option<String>,
}

#[derive(serde::Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct MethodVerdict {
    pub method: String,
    pub admitted: bool,
    pub rule: Option<String>,
}

fn explain_url(
    blueprint: &Blueprint,
    provenance: &formwork_blueprint::Provenance,
    url: &str,
) -> Result<EgressExplanation> {
    use formwork_blueprint::{ConnectDecision, Denial, HttpMethod, RequestDecision};
    let (raw_host, port, raw_path) =
        formwork_blueprint::split_url(url).map_err(|e| anyhow!("explain: {e}"))?;
    let host =
        formwork_blueprint::canonicalize_host(raw_host).map_err(|e| anyhow!("{url}: {e}"))?;
    let path =
        formwork_blueprint::CanonicalPath::parse(raw_path).map_err(|e| anyhow!("{url}: {e}"))?;
    let empty = formwork_blueprint::HostTable::default();
    let table = blueprint.net.host_table().unwrap_or(&empty);
    let source_of = |rule: Option<&formwork_blueprint::HostRule>| {
        rule.and_then(|r| provenance.host_rule_source(r).cloned())
    };
    let mut out = EgressExplanation {
        url: url.to_string(),
        host: host.to_string(),
        port,
        grade: "denied",
        methods: Vec::new(),
        rule: None,
        source: None,
        reason: None,
    };
    if blueprint.net.host_table().is_none() {
        out.reason = Some(match &blueprint.net {
            formwork_blueprint::NetPosture::Ports(p) => format!(
                "the net posture is a direct port tier ({p:?}): any host on those ports, no \
                 Gateway, no host scoping"
            ),
            _ => "the net posture is deny: no egress at all".to_string(),
        });
        return Ok(out);
    }
    match table.decide_connect(&host, port) {
        ConnectDecision::Tunnel(rule) => {
            out.grade = "tunnel";
            out.source = source_of(Some(rule));
            out.rule = Some(rule.to_string());
            out.reason = Some(
                "forwarded after the ClientHello's server name matches the host (FW-EGR16); the \
                 request itself is opaque (FW-EGR5)"
                    .to_string(),
            );
        }
        ConnectDecision::Inspect => {
            out.grade = "inspected";
            for m in HttpMethod::ALL {
                let (admitted, rule) = match table.decide_request(&host, port, Some(m), &path) {
                    RequestDecision::Allow(rule) => (true, Some(rule)),
                    RequestDecision::Deny(Denial { rule, .. }) => (false, rule),
                };
                out.methods.push(MethodVerdict {
                    method: m.atom().to_ascii_uppercase(),
                    admitted,
                    rule: rule.map(|r| r.to_string()),
                });
            }
        }
        ConnectDecision::Deny(Denial {
            reason,
            detail,
            rule,
        }) => {
            out.source = source_of(rule);
            out.rule = rule.map(|r| r.to_string());
            out.reason = Some(format!("{reason}: {detail}"));
        }
    }
    Ok(out)
}

/// `explain --hosts` (FW-FID11): every host rule once, with its grade and the layer that wrote it.
fn explain_net(args: &BlueprintArgs, json: bool) -> Result<()> {
    let resolved = args.resolve()?;
    let (blueprint, provenance) = args.load_with_provenance(&resolved.path, &home())?;
    let upstream = upstream_proxy()?;
    // FW-EGR26: a name the upstream proxy carries is resolved there, so its addresses are not
    // classified here.
    let classification = |host: &formwork_blueprint::HostPattern, tls: bool| {
        let name = match host {
            formwork_blueprint::HostPattern::Exact(n)
            | formwork_blueprint::HostPattern::Wildcard(n) => {
                formwork_blueprint::CanonicalHost::Name(n.clone())
            }
            formwork_blueprint::HostPattern::Ip(_) => {
                return serde_json::json!({ "verdict": "enforced" })
            }
        };
        match upstream.as_ref().and_then(|u| u.endpoint_for(&name, tls)) {
            Some(proxy) => serde_json::json!({
                "verdict": "partial",
                "reason": format!(
                    "egress to {host} goes through the upstream proxy {}, which resolves the name; \
                     its addresses are not classified here (FW-EGR26)",
                    proxy.describe()
                ),
            }),
            None => serde_json::json!({ "verdict": "enforced" }),
        }
    };
    let rules: Vec<serde_json::Value> = blueprint
        .net
        .host_table()
        .map(|t| t.rules.clone())
        .unwrap_or_default()
        .iter()
        .map(|r| {
            let (grade, methods, path) = match &r.access {
                formwork_blueprint::HostAccess::Tunnel => {
                    ("tunnel", "(opaque)".to_string(), "(opaque)".to_string())
                }
                formwork_blueprint::HostAccess::Inspected { methods, path } => (
                    "inspected",
                    formwork_blueprint::HttpMethod::atoms(methods),
                    path.as_str().to_string(),
                ),
                formwork_blueprint::HostAccess::Deny { path } => (
                    "deny",
                    "-".to_string(),
                    path.as_ref()
                        .map(|p| p.as_str().to_string())
                        .unwrap_or_else(|| "(all)".into()),
                ),
            };
            let tls = r.port != Some(formwork_blueprint::DEFAULT_HTTP_PORT);
            serde_json::json!({
                "rule": r.to_string(),
                "host": r.host.to_string(),
                "port": r.port,
                "grade": grade,
                "methods": methods,
                "paths": path,
                "broker": serde_json::Value::Null,
                "classification": classification(&r.host, tls),
                "source": provenance.host_rule_source(r),
                "layer": provenance.host_rule_source(r).map(render::source),
            })
        })
        .collect();
    if json {
        let mut value = serde_json::json!({
            "net": blueprint.net,
            "hosts": rules,
            "upstream-trust": formwork_gateway::native_roots_source(),
            "upstream-proxy": upstream.as_ref().map(|u| u.describe()),
        });
        attach_blueprint_info(&mut value, &resolved);
        println!("{}", serde_json::to_string_pretty(&value)?);
        return Ok(());
    }
    println!(
        "blueprint: {} ({})",
        resolved.path.display(),
        resolved.source.as_str()
    );
    print!("{}", render::net_table(&blueprint.net, &rules));
    Ok(())
}

/// The no-path `explain`: what this session would be, before running anything. With a blueprint
/// (named or discovered): host + the merged policy's fidelity summary. Without one: the host
/// summary alone -- unless override flags were given, which need a base and error like any other
/// blueprint-taking use.
fn explain_summary(args: &BlueprintArgs, json: bool) -> Result<()> {
    let host = detect();
    let resolved = match args.try_resolve()? {
        Some(resolved) => resolved,
        None if !args.has_overrides() && args.blueprint.is_none() => {
            if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({ "host": host }))?
                );
            } else {
                println!(
                    "host: {}",
                    render::host_summary(&host, learn::find_strace().is_some())
                );
                println!(
                    "\nno blueprint found (no --blueprint, no {} here or in a parent); showing \
                     host capabilities only",
                    blueprint_load::DEFAULT_BLUEPRINT_NAME
                );
            }
            return Ok(());
        }
        // Overrides (or an explicit --blueprint that resolved to nothing) need a base blueprint;
        // no second resolution here -- re-resolving could succeed if a file appeared meanwhile,
        // and `unwrap_err` on that success was a panic waiting for the race.
        None => return Err(no_blueprint_error()),
    };
    let blueprint = args.load(&resolved.path, &home())?;
    let catalog =
        ResolvedCatalog::builtin_for_home(&home()).context("resolving credential catalog")?;
    let policy = compile(&blueprint, &host, &catalog);
    if json {
        let mut value = serde_json::json!({ "host": host, "report": policy.report });
        attach_blueprint_info(&mut value, &resolved);
        println!("{}", serde_json::to_string_pretty(&value)?);
    } else {
        println!(
            "blueprint: {} ({})",
            resolved.path.display(),
            resolved.source.as_str()
        );
        println!(
            "host: {}",
            render::host_summary(&host, learn::find_strace().is_some())
        );
        print!("{}", render::report_summary(&policy.report));
        // Advisory: the summary above is the command's result, so a note that cannot be worked
        // out (an unreadable launch directory) is left out rather than failing it.
        if let Ok(Some(note)) = split_root_note(&blueprint, &resolved.path, &host) {
            println!("\nnote: {note}");
        }
    }
    Ok(())
}

/// `exit_code=1`, never Rust's `Some(1)`; a signal death is named, not `None`.
fn log_exit(what: &'static str, status: &std::process::ExitStatus) {
    match status.code() {
        Some(code) => tracing::info!(exit_code = code, "{what}"),
        None => {
            use std::os::unix::process::ExitStatusExt;
            tracing::info!(signal = status.signal(), "{what} (terminated by signal)");
        }
    }
}

/// Everything every enforcing subcommand shares: load the stack (discovered layer included),
/// add the FW-CRED3 env-file-ref denies, write-protect the policy inputs themselves, resolve
/// against the real filesystem, compile against the catalog, and itemize the floor.
struct Session {
    blueprint: Blueprint,
    catalog: ResolvedCatalog,
    policy: formwork_compile::CompiledPolicy,
    /// The resolved blueprint file this session was built from (flag or discovered FORMWORK.toml);
    /// `learn` derives the proposal/discovered-layer paths from it.
    blueprint_path: PathBuf,
    /// The per-session temporary directory (FW-TRA10), removed when the spawned child exits.
    tmp_dir: SessionTmp,
    /// The Gateway egress listener, when the blueprint carries host rules (FW-EGR14).
    egress: Option<Egress>,
    /// Variables the Launcher sets for inspection and brokering: the trust-bundle variables
    /// (FW-EGR13) and each brokered credential's placeholder (FW-CRED14).
    egress_env: Vec<(String, String)>,
    /// The opener shim and its socket (FW-ISO17), in the spawn posture.
    opener: Option<OpenerSetup>,
    /// The host this session was compiled for; `learn` maps refused sockets to channels by it.
    host: HostProfile,
    /// Pathname sockets the connect supervisor refused (FW-DISC12).
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    refused_sockets: std::sync::Arc<std::sync::Mutex<Vec<PathBuf>>>,
    /// The tag this session's macOS denies carry into the unified log (FW-DISC2).
    deny_tag: Option<String>,
}

/// A host-scoped session's egress door: the in-process Gateway listener and, on Linux, the port
/// registry the connect supervisor fills, or on macOS the marker its peer check asks for (FW-EGR9).
struct Egress {
    proxy: formwork_gateway::EgressProxy,
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    registry: Option<std::sync::Arc<std::sync::Mutex<std::collections::HashSet<u16>>>>,
    /// The marker the session's profile carries for the macOS peer check (FW-EGR9).
    marker: formwork_compile::SessionMarker,
}

/// What a session is prepared for: which postures can carry host-scoped egress differs (FEP-5
/// §3.1 -- only the spawn posture leaves a process outside the sandbox to host the Gateway).
#[derive(Clone, Copy, PartialEq, Eq)]
enum Purpose {
    Spawn,
    ConfineSelf,
    GatewayBackend,
}

/// A per-session secret from the kernel's CSPRNG, hex-encoded.
fn session_nonce() -> Result<String> {
    use std::io::Read;
    let mut bytes = [0u8; 24];
    std::fs::File::open("/dev/urandom")
        .and_then(|mut f| f.read_exact(&mut bytes))
        .context("reading /dev/urandom for the session credential")?;
    Ok(bytes.iter().map(|b| format!("{b:02x}")).collect())
}

/// The Launcher-owned per-session temporary directory (FW-TRA9/FW-TRA10). Created 0700 beneath the
/// host temp root (`$TMPDIR` on macOS is the per-user `DARWIN_USER_TEMP_DIR`), granted read-write
/// in every read mode, and exported as `TMPDIR`/`TMP`/`TEMP` to the confined child.
struct SessionTmp {
    path: PathBuf,
    /// Launcher-owned read-only directories beside `path` (FW-TRA9): the inspection trust bundle
    /// and the opener shim. Siblings, never inside `path`: the session may write its temp
    /// directory, and a writable bundle or shim would let it trust a CA or run code of its own.
    siblings: Vec<PathBuf>,
}

impl SessionTmp {
    fn create() -> Result<SessionTmp> {
        use std::os::unix::fs::DirBuilderExt;
        let root = std::env::temp_dir();
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.subsec_nanos())
            .unwrap_or(0);
        let path = root.join(format!(
            "formwork-session-{}-{nanos:08x}",
            std::process::id()
        ));
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&path)
            .with_context(|| format!("creating the session temp directory {}", path.display()))?;
        let path = std::fs::canonicalize(&path).context("resolving the session temp directory")?;
        Ok(SessionTmp {
            path,
            siblings: Vec::new(),
        })
    }

    /// A fresh 0700 sibling directory `<path>-<suffix>`, removed with the session.
    fn sibling(&mut self, suffix: &str) -> Result<PathBuf> {
        use std::os::unix::fs::DirBuilderExt;
        let mut name = self.path.as_os_str().to_owned();
        name.push(format!("-{suffix}"));
        let dir = PathBuf::from(name);
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&dir)
            .with_context(|| format!("creating the session directory {}", dir.display()))?;
        self.siblings.push(dir.clone());
        Ok(dir)
    }

    fn remove(&self) {
        let _ = std::fs::remove_dir_all(&self.path);
        for dir in &self.siblings {
            let _ = std::fs::remove_dir_all(dir);
        }
    }
}

/// Write a Launcher-owned file, created fresh with `mode`.
fn write_launcher_file(path: &std::path::Path, bytes: &[u8], mode: u32) -> Result<()> {
    use std::os::unix::fs::OpenOptionsExt;
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode)
        .open(path)
        .with_context(|| format!("writing {}", path.display()))?;
    std::io::Write::write_all(&mut f, bytes).with_context(|| format!("writing {}", path.display()))
}

/// FW-TRA9: grant a Launcher-owned directory readable (and, for the shim, executable under an
/// exec allowlist) in every read mode, and write-protect it: it sits under the host temp root,
/// which a profile commonly grants writable.
fn grant_launcher_dir(
    blueprint: &mut Blueprint,
    dir: &std::path::Path,
    executable: bool,
) -> Result<()> {
    let rendered = dir
        .to_str()
        .ok_or_else(|| anyhow!("session directory is not valid UTF-8 (FW-INV6)"))?;
    let subtree =
        PathPattern::parse(&format!("{rendered}/**")).context("granting a session directory")?;
    blueprint.fs.reads.push(subtree.clone());
    blueprint
        .fs
        .write_subtract
        .push(PathPattern::parse(rendered).context("write-protecting a session directory")?);
    blueprint.fs.write_subtract.push(subtree.clone());
    if executable {
        if let formwork_blueprint::ExecPosture::Allowlist(allowed) = &mut blueprint.exec {
            allowed.push(subtree);
        }
    }
    Ok(())
}

/// The opener shim (FW-ISO17): a read-only directory first in `PATH`, and the socket its scripts
/// write URLs to. The host end is served after the spawn (FW-ISO18).
struct OpenerSetup {
    dir: PathBuf,
    /// Served from this process once the workload is spawned.
    host_end: Option<std::os::unix::net::UnixStream>,
    /// The workload's copy, dropped here once it has inherited it.
    session_end: Option<std::os::fd::OwnedFd>,
    /// `session_end`'s number, which the workload's environment names.
    session_fd: std::os::fd::RawFd,
    service: Option<formwork_gateway::OpenerService>,
}

fn prepare_opener(blueprint: &mut Blueprint, tmp: &mut SessionTmp) -> Result<OpenerSetup> {
    use std::os::fd::AsRawFd;
    let dir = tmp.sibling("opener")?;
    let script = formwork_gateway::opener::shim_script(
        blueprint
            .channels
            .lifted(formwork_blueprint::Channel::OpenUrl),
    );
    for name in formwork_gateway::opener::SHIM_NAMES {
        write_launcher_file(&dir.join(name), script.as_bytes(), 0o500)?;
    }
    grant_launcher_dir(blueprint, &dir, true)?;
    tracing::info!(shim = %dir.display(), "opener shim first in PATH and BROWSER (FW-ISO17)");
    let (host_end, session_end) =
        std::os::unix::net::UnixStream::pair().context("creating the opener socket")?;
    let session_end = std::os::fd::OwnedFd::from(session_end);
    Ok(OpenerSetup {
        dir,
        host_end: Some(host_end),
        session_fd: session_end.as_raw_fd(),
        session_end: Some(session_end),
        service: None,
    })
}

fn prepare_session(args: &BlueprintArgs, purpose: Purpose, host: HostProfile) -> Result<Session> {
    let resolved = args.resolve()?;
    let mut blueprint = args.load(&resolved.path, &home())?;
    refuse_unavailable_isolation(&blueprint, &host, purpose)?;
    let catalog =
        ResolvedCatalog::builtin_for_home(&home()).context("resolving credential catalog")?;
    // FW-CRED3: deny the files that enforced env-points-to-file credentials name, before the
    // blueprint's enforcement-time canonicalization resolves everything together.
    blueprint
        .fs
        .subtract
        .extend(blueprint_load::env_file_ref_denies(
            &catalog,
            &blueprint.exposed_credentials(),
        )?);
    // The policy inputs are write-denied inside the session: a confined agent must not be able
    // to edit the blueprint, forge the discovered layer, or doctor the proposal that shapes its
    // own NEXT run (FW-XR8 / FW-INV8). Keys off the RESOLVED path, so a discovered FORMWORK.toml
    // is protected exactly like an explicit one.
    blueprint_load::protect_policy_inputs(&mut blueprint, &resolved.path)?;
    if let Some(note) = split_root_note(&blueprint, &resolved.path, &host)? {
        tracing::info!("{note}");
    }
    // FW-TRA9/FW-TRA10: the Launcher-owned temporary directory is a write grant in every read mode.
    let tmp_dir = SessionTmp::create()?;
    let tmp_rendered = tmp_dir
        .path
        .to_str()
        .ok_or_else(|| anyhow!("session temp directory is not valid UTF-8 (FW-INV6)"))?;
    blueprint.fs.writes.push(
        PathPattern::parse(&format!("{tmp_rendered}/**"))
            .context("granting the session temp directory")?,
    );
    tracing::info!(tmp = %tmp_dir.path.display(), "session temp directory (TMPDIR/TMP/TEMP)");
    let mut tmp_dir = tmp_dir;
    let tls = prepare_inspection(&mut blueprint, &catalog, &mut tmp_dir, purpose)?;
    let opener = match purpose {
        Purpose::Spawn => Some(prepare_opener(&mut blueprint, &mut tmp_dir)?),
        Purpose::ConfineSelf | Purpose::GatewayBackend => None,
    };
    // Resolve symlinks in grant paths so the kernel's resolved-path matching lines up (macOS
    // firmlinks). Enforcement path only, never dry-run. Fails loud on a path that can't be
    // faithfully rendered (FW-INV6). The catalog's paths get the same treatment -- a floor hole
    // that silently failed to match would be a fail-open of the sensitive set.
    let blueprint = blueprint_load::canonicalize_for_enforcement(&blueprint)
        .context("canonicalizing grant paths")?;
    let catalog = blueprint_load::canonicalize_catalog_for_enforcement(&catalog)
        .context("canonicalizing credential catalog paths")?;
    let (egress_env, inspection, brokers) = match tls {
        Some(t) => (t.env, Some(t.inspection), t.brokers),
        None => (Vec::new(), None, Vec::new()),
    };
    let egress = start_egress(&blueprint, &host, purpose, inspection, brokers)?;
    let spec = formwork_compile::SessionSpec {
        gateway: egress.as_ref().map(|e| formwork_compile::SessionGateway {
            port: e.proxy.addr().port(),
            marker: e.marker.clone(),
        }),
        // FW-DISC2 on macOS: the unified log carries every sandboxed process's records; the tag
        // lets `learn` keep this session's.
        deny_tag: (host.os == formwork_detect::Os::MacOs && purpose == Purpose::Spawn)
            .then(|| session_nonce().map(|n| format!("fw-session-{}", &n[..16])))
            .transpose()?,
    };
    let policy = formwork_compile::compile_for_session(&blueprint, &host, &catalog, &spec);
    itemize_credential_floor(&policy.report, &catalog);
    Ok(Session {
        deny_tag: spec.deny_tag,
        blueprint,
        catalog,
        policy,
        blueprint_path: resolved.path,
        tmp_dir,
        egress,
        egress_env,
        opener,
        host,
        refused_sockets: Default::default(),
    })
}

/// FW-ISO18: serve the opener socket from this process, outside the sandbox.
fn start_opener(opener: &mut OpenerSetup, lifted: bool) {
    let Some(host_end) = opener.host_end.take() else {
        return;
    };
    let host_opener = std::env::var_os("FORMWORK_HOST_OPENER")
        .map(PathBuf::from)
        .unwrap_or_else(formwork_gateway::opener::host_opener);
    match formwork_gateway::OpenerService::start(host_end, lifted, host_opener) {
        Ok(service) => opener.service = Some(service),
        Err(e) => tracing::warn!(error = %e, "the open-url service failed to start"),
    }
}

/// What inspection and brokering add to a session.
struct PreparedInspection {
    inspection: formwork_gateway::Inspection,
    brokers: Vec<formwork_gateway::Broker>,
    env: Vec<(String, String)>,
}

/// Clients that honor one of these read the trust bundle; the list is the common set across
/// OpenSSL, Node, Python requests, curl, git, pip and cargo (FW-EGR13).
const TRUST_VARS: &[&str] = &[
    "SSL_CERT_FILE",
    "NODE_EXTRA_CA_CERTS",
    "REQUESTS_CA_BUNDLE",
    "CURL_CA_BUNDLE",
    "GIT_SSL_CAINFO",
    "PIP_CERT",
    "CARGO_HTTP_CAINFO",
];

/// FW-EGR13 / FW-CRED11-14: when any host rule is inspected, mint the session CA, write the trust
/// bundle (the CA plus the host's roots, so uninspected tunnels still verify) into a read-only
/// directory the session may read, and resolve each brokered credential's secret on this side of
/// the sandbox. A brokered credential with no value is refused before spawn (FW-XR9): the
/// workload would otherwise start and fail on its first request.
fn prepare_inspection(
    blueprint: &mut Blueprint,
    catalog: &ResolvedCatalog,
    tmp: &mut SessionTmp,
    purpose: Purpose,
) -> Result<Option<PreparedInspection>> {
    let Some(table) = blueprint.net.host_table() else {
        return Ok(None);
    };
    if purpose != Purpose::Spawn || !table.rules.iter().any(|r| r.is_inspected()) {
        return Ok(None);
    }
    let plans =
        formwork_blueprint::resolve_brokers(&blueprint.allow_credentials, catalog, Some(table))
            .map_err(|errors| anyhow!("allow-credentials:\n  {}", errors.join("\n  ")))?;
    // FW-EGR25: the CA may certify exactly the hosts the blueprint inspects.
    let ca = formwork_gateway::SessionCa::generate(&table.inspected_hosts())
        .context("generating the session CA")?;
    let roots = formwork_gateway::native_roots();
    tracing::info!(
        source = %formwork_gateway::native_roots_source(),
        roots = roots.len(),
        "upstream trust store (FW-EGR24)"
    );
    let trust_dir = tmp.sibling("trust")?;
    let file = trust_dir.join("ca-bundle.pem");
    write_launcher_file(&file, ca.trust_bundle(&roots).as_bytes(), 0o400)?;
    grant_launcher_dir(blueprint, &trust_dir, false)?;
    let file = file.display().to_string();
    let mut env: Vec<(String, String)> = TRUST_VARS
        .iter()
        .map(|v| (v.to_string(), file.clone()))
        .collect();
    tracing::info!(bundle = %file, "inspection trust bundle");

    if !plans.is_empty() {
        // FW-CRED16: this process's environment already holds the credentials it will broker.
        formwork_confine::deny_inspection_of_self()
            .context("protecting the brokered credentials")?;
    }
    let mut brokers = Vec::new();
    for plan in plans {
        let Some((var, secret)) = plan.env_sources.iter().find_map(|v| {
            std::env::var(v)
                .ok()
                .filter(|s| !s.is_empty())
                .map(|s| (v, s))
        }) else {
            bail!(
                "{} is brokered, but none of its variables is set here ({}); set one, or drop \
                  `broker:{}` from allow-credentials",
                plan.name,
                plan.env_sources.join(", "),
                plan.name
            );
        };
        let placeholder = format!(
            "{}{}-{}",
            formwork_gateway::PLACEHOLDER_PREFIX,
            plan.name,
            session_nonce()?
        );
        tracing::info!(credential = %plan.name, var = %var, "brokered; the session holds a placeholder");
        env.push((var.clone(), placeholder.clone()));
        brokers.push(formwork_gateway::Broker {
            name: plan.name,
            placeholder,
            secret,
            bindings: plan.bindings,
        });
    }
    Ok(Some(PreparedInspection {
        inspection: formwork_gateway::Inspection::new(std::sync::Arc::new(ca), &roots),
        brokers,
        env,
    }))
}

/// FW-EGR14: a blueprint with host rules gets its Gateway egress listener here, in the `formwork`
/// process that stays outside the sandbox. Refused before the workload starts wherever it cannot
/// be carried (FW-XR9): under confine-self, behind the MCP gateway, and on a Linux host without
/// connect supervision.
fn start_egress(
    blueprint: &Blueprint,
    host: &HostProfile,
    purpose: Purpose,
    inspection: Option<formwork_gateway::Inspection>,
    brokers: Vec<formwork_gateway::Broker>,
) -> Result<Option<Egress>> {
    let Some(table) = blueprint.net.host_table() else {
        return Ok(None);
    };
    match purpose {
        Purpose::Spawn => {}
        Purpose::ConfineSelf => bail!(
            "host rules route egress through the Gateway, which runs in the `formwork` process \
             outside the sandbox; `run --confine-self` leaves no such process. Use the spawn \
             posture (`formwork run -- …`)"
        ),
        Purpose::GatewayBackend => bail!(
            "host rules apply to `formwork run`; an MCP backend behind `formwork gateway` takes \
             `net = \"deny\"` or a port tier"
        ),
    }
    if host.os == formwork_detect::Os::Linux && !host.can_supervise_connect() {
        bail!(
            "host rules need connect supervision, which this host lacks: {}. Alternatives: \
             `net = {{ ports = [443] }}` (any host on the port), or `net = \"deny\"`",
            formwork_detect::CONNECT_SUPERVISION_NEEDS
        );
    }
    let registry = (host.os == formwork_detect::Os::Linux)
        .then(|| std::sync::Arc::new(std::sync::Mutex::new(std::collections::HashSet::new())));
    let marker = formwork_compile::SessionMarker::new(&session_nonce()?);
    let peer_check = peer_check(&marker);
    let host_addresses = formwork_detect::interface_addresses().unwrap_or_else(|e| {
        tracing::warn!(
            error = %e,
            "enumerating the host's interface addresses failed; the other address classes still \
             apply (FW-EGR19)"
        );
        Vec::new()
    });
    let proxy = formwork_gateway::EgressProxy::start(formwork_gateway::EgressConfig {
        table: table.clone(),
        resolver: formwork_gateway::Resolver::System,
        admission: formwork_gateway::Admission {
            credential: session_nonce()?,
            registry: registry.clone(),
            peer_check,
        },
        inspection,
        brokers,
        host_addresses,
        upstream_proxy: upstream_proxy()?,
    })
    .context("starting the Gateway egress listener")?;
    for rule in &table.rules {
        tracing::info!(rule = %rule, "egress host rule");
    }
    Ok(Some(Egress {
        proxy,
        registry,
        marker,
    }))
}

/// FW-EGR9 on macOS: the listener admits a connection only when a process carrying the session's
/// marker holds its client end. Linux has the supervisor's registry instead.
#[cfg(target_os = "macos")]
fn peer_check(marker: &formwork_compile::SessionMarker) -> Option<formwork_gateway::PeerCheck> {
    let marker = marker.clone();
    Some(formwork_gateway::PeerCheck(std::sync::Arc::new(
        move |peer, local| formwork_confine::session_holds_connection(&marker, peer, local),
    )))
}

#[cfg(not(target_os = "macos"))]
fn peer_check(_marker: &formwork_compile::SessionMarker) -> Option<formwork_gateway::PeerCheck> {
    None
}

/// FW-EGR26: the operator's upstream proxy, read from `formwork run`'s own environment -- never
/// the session's, which the Launcher points at the Gateway. The lowercase spelling wins, as curl
/// reads it.
fn upstream_proxy() -> Result<Option<formwork_gateway::UpstreamProxy>> {
    let var = |lower: &str, upper: &str| {
        std::env::var(lower)
            .ok()
            .filter(|v| !v.is_empty())
            .or_else(|| std::env::var(upper).ok())
    };
    formwork_gateway::UpstreamProxy::from_values(
        var("https_proxy", "HTTPS_PROXY").as_deref(),
        var("http_proxy", "HTTP_PROXY").as_deref(),
        var("no_proxy", "NO_PROXY").as_deref(),
    )
    .map_err(|e| anyhow!("{e}"))
}

/// Variables the Launcher sets after the posture ran (FW-TRA10, FEP-5 §3.1, FEP-6 §4.11): the
/// session temp directory and, under host rules, the proxy that reaches the Gateway, in both
/// spellings (curl reads `http_proxy` only in lowercase), an empty `no_proxy`, and Node's opt-in
/// to the proxy variables.
fn session_env(session: &Session) -> Vec<(String, String)> {
    let tmp = session.tmp_dir.path.display().to_string();
    let mut vars: Vec<(String, String)> = ["TMPDIR", "TMP", "TEMP"]
        .iter()
        .map(|v| (v.to_string(), tmp.clone()))
        .collect();
    if let Some(egress) = &session.egress {
        let url = egress.proxy.proxy_url();
        for var in [
            "HTTP_PROXY",
            "HTTPS_PROXY",
            "http_proxy",
            "https_proxy",
            "ALL_PROXY",
            "all_proxy",
        ] {
            if std::env::var_os(var).is_some() {
                tracing::info!(
                    var,
                    "overriding an inherited proxy variable with the session Gateway"
                );
            }
            vars.push((var.to_string(), url.clone()));
        }
        for var in ["NO_PROXY", "no_proxy"] {
            vars.push((var.to_string(), String::new()));
        }
        vars.push(("NODE_USE_ENV_PROXY".to_string(), "1".to_string()));
        // npm reads its own config variables, in any case, before the proxy variables; an
        // inherited one would send npm around the Gateway, where the supervisor refuses it.
        for (name, _) in std::env::vars_os() {
            let name = name.to_string_lossy().into_owned();
            let value = match name.to_ascii_lowercase().as_str() {
                "npm_config_proxy" | "npm_config_https_proxy" => url.clone(),
                "npm_config_noproxy" => String::new(),
                _ => continue,
            };
            tracing::info!(
                var = %name,
                "overriding an inherited npm proxy setting with the session Gateway"
            );
            vars.push((name, value));
        }
    }
    vars.extend(session.egress_env.iter().cloned());
    if let Some(opener) = &session.opener {
        // `PATH` is prefixed with the shim directory in `apply_env`, over the posture's own value.
        let shim = opener.dir.display().to_string();
        vars.push(("BROWSER".to_string(), format!("{shim}/xdg-open")));
        vars.push((
            formwork_gateway::opener::OPENER_FD_ENV.to_string(),
            opener.session_fd.to_string(),
        ));
    }
    vars
}

/// FW-XR10: the workload's status; a signal death is 128 + the signal, as a shell reports it.
fn exit_code(status: &std::process::ExitStatus) -> i32 {
    use std::os::unix::process::ExitStatusExt;
    status
        .code()
        .unwrap_or_else(|| 128 + status.signal().unwrap_or(0))
}

/// FW-XR11: a Formwork failure after the workload started exits 125 with one attributed line on
/// stderr; stdout stays the workload's.
fn formwork_failure(what: &str) -> ! {
    eprintln!("formwork: {what}");
    std::process::exit(125);
}

/// FW-XR9: an isolation member the host cannot provide is refused before the workload starts,
/// naming every alternative, never run weaker than the blueprint asked (FW-INV6).
fn refuse_unavailable_isolation(
    blueprint: &Blueprint,
    host: &HostProfile,
    purpose: Purpose,
) -> Result<()> {
    if blueprint.isolate.is_empty() || host.os != formwork_detect::Os::Linux {
        return Ok(());
    }
    let members: Vec<&str> = blueprint.isolate.iter().map(|m| m.name()).collect();
    if !host.user_namespaces {
        bail!(
            "isolate = {members:?} needs unprivileged user namespaces that can mount a fresh \
             /proc, which this host does not allow. Alternatives: on Ubuntu 24.04 lift the \
             AppArmor restriction with `sudo sysctl kernel.apparmor_restrict_unprivileged_userns=0`; \
             check `user.max_user_namespaces` is non-zero; run formwork under bwrap, which \
             provides the namespaces itself; or drop the member from `isolate`"
        );
    }
    match purpose {
        Purpose::Spawn => Ok(()),
        Purpose::ConfineSelf => bail!(
            "isolate = {members:?} creates namespaces around the workload, which needs the spawn \
             posture (`formwork run -- …`); `run --confine-self` execs in place. Use the spawn \
             posture, or drop the member from `isolate`"
        ),
        Purpose::GatewayBackend => bail!(
            "isolate = {members:?} applies to `formwork run`; an MCP backend behind `formwork \
             gateway` runs without the isolation tier. Drop the member from `isolate`"
        ),
    }
}

/// FEP-5 D3: the policy inputs are write-protected during a run (FW-XR8), and on Linux a protected
/// path inside a write grant splits the grant: Landlock cannot carve a path out of a directory's
/// grant, so the grant goes to the entries around it. Names the directories that lose create,
/// delete and rename; `None` when nothing is split. When the launch directory is among them, the
/// split is load-bearing (a launch directory the session can create in is one it can leave a
/// blueprint in for the next discovery walk), and the note names `--blueprint` from outside every
/// write grant as the way to a whole root, with that residual.
fn split_root_note(
    blueprint: &Blueprint,
    blueprint_path: &std::path::Path,
    host: &HostProfile,
) -> Result<Option<String>> {
    if host.os != formwork_detect::Os::Linux || host.landlock_abi.is_none() {
        return Ok(None);
    }
    let split = blueprint_load::dirs_split_by_policy_inputs(blueprint, blueprint_path)?;
    // The split directories are one chain, from the outermost grant root down to the inputs' own.
    let (Some(outer), Some(inner)) = (split.first(), split.last()) else {
        return Ok(None);
    };
    let dirs = if outer == inner {
        outer.display().to_string()
    } else {
        format!(
            "any directory from {} down to {}",
            outer.display(),
            inner.display()
        )
    };
    let mut note = format!(
        "{} and its learned and proposed layers are write-protected during a run, so the session \
         cannot rewrite its own next one. Landlock can only allow, so on Linux a protected file \
         inside a write grant is carved out by granting the entries around it: nothing can be \
         created, deleted or renamed directly in {dirs}, while the rest of what exists at launch \
         stays writable",
        blueprint_path.display()
    );
    let launch = std::env::current_dir().and_then(std::fs::canonicalize).ok();
    if launch.is_some_and(|d| split.contains(&d)) {
        note.push_str(
            ". That also keeps the session from leaving a blueprint there for discovery to find. \
             For a creatable project root, pass --blueprint with a file outside every write \
             grant, and keep passing it: the session can then leave a FORMWORK.toml in the \
             project that a run without --blueprint would use",
        );
    }
    Ok(Some(note))
}

fn spawn_confined_child(
    session: &mut Session,
    program: &str,
    args: &[String],
) -> Result<std::process::ExitStatus> {
    #[cfg(target_os = "linux")]
    let isolated = !session.blueprint.isolate.is_empty();
    #[cfg(not(target_os = "linux"))]
    let isolated = false;
    // Under the isolation tier the spawned process is this binary as the isolation stage, which
    // execs the workload inside the namespaces (FW-ISO10); it carries the workload's environment.
    let mut command = if isolated {
        Command::new("/proc/self/exe")
    } else {
        let mut c = Command::new(program);
        c.args(args);
        c
    };
    apply_env(
        &mut command,
        &session.blueprint,
        &session.catalog,
        &session_env(session),
        session.opener.as_ref().map(|o| o.dir.as_path()),
    );
    #[cfg(target_os = "linux")]
    let pending = if isolated {
        let argv: Vec<String> = std::iter::once(program.to_string())
            .chain(args.iter().cloned())
            .collect();
        formwork_confine::spawn_isolated(
            &mut command,
            &argv,
            &session.policy,
            Some(&session.tmp_dir.path),
        )
        .context("applying confinement with the isolation tier")?
    } else {
        formwork_confine::spawn_confined_supervised(&mut command, &session.policy)
            .context("applying confinement")?
    };
    #[cfg(not(target_os = "linux"))]
    formwork_confine::spawn_confined(&mut command, &session.policy)
        .context("applying confinement")?;
    if let Some(opener) = &session.opener {
        // The session holds the descriptor open until after the spawn.
        formwork_confine::inherit_fd(&mut command, opener.session_fd);
    }
    tracing::info!(program = %program, "spawning confined command");
    let child = command.spawn();
    let lifted = session
        .blueprint
        .channels
        .lifted(formwork_blueprint::Channel::OpenUrl);
    if let Some(opener) = &mut session.opener {
        // The session holds the only copies now; EOF arrives when its last process exits.
        opener.session_end = None;
        if child.is_ok() {
            start_opener(opener, lifted);
        }
    }
    let mut child = match child {
        Ok(c) => c,
        Err(e) => {
            session.tmp_dir.remove();
            return Err(e).context("spawning confined command");
        }
    };
    #[cfg(target_os = "linux")]
    if let Some(pending) = pending {
        let Some(egress) = &session.egress else {
            let _ = child.kill();
            formwork_failure("the policy needs the connect supervisor but no Gateway is running");
        };
        let unix_grants = match &session.policy.confiner {
            formwork_compile::ConfinerPolicy::Linux(l) => l.unix_socket_grants.clone(),
            _ => Vec::new(),
        };
        let config = formwork_confine::SupervisorConfig {
            gateway: egress.proxy.addr(),
            registry: egress.registry.clone().unwrap_or_default(),
            unix_grants,
            refused_sockets: session.refused_sockets.clone(),
        };
        if let Err(e) = pending.start(config) {
            let _ = child.kill();
            let _ = child.wait();
            session.tmp_dir.remove();
            formwork_failure(&format!("the connect supervisor failed to start: {e}"));
        }
    }
    let status = child.wait();
    session.tmp_dir.remove();
    let status = status.context("waiting for the confined command")?;
    // The opener logs each URL from its own thread; let it drain before the session ends, or the
    // line for a URL handed over just before the workload exited races this process's exit.
    if let Some(service) = session.opener.as_ref().and_then(|o| o.service.as_ref()) {
        service.records_within(std::time::Duration::from_millis(500));
    }
    log_exit("confined command exited", &status);
    if let Some(egress) = &session.egress {
        if !egress.proxy.is_alive() {
            formwork_failure("the Gateway egress listener stopped during the session");
        }
    }
    Ok(status)
}

/// The descriptor a Linux `learn` handed this `run` for its observations (FW-DISC12), taken
/// from the environment before anything else reads it, so no workload inherits it.
static LEARNING_REPORT_FD: std::sync::OnceLock<std::os::fd::RawFd> = std::sync::OnceLock::new();

fn take_learning_report_fd() {
    let Some(raw) = std::env::var_os(learn::REPORT_FD_ENV) else {
        return;
    };
    // Single-threaded here: telemetry and every runtime start after this.
    std::env::remove_var(learn::REPORT_FD_ENV);
    let Some(fd) = raw
        .to_str()
        .and_then(|s| s.parse::<std::os::fd::RawFd>().ok())
    else {
        return;
    };
    // SAFETY: F_SETFD on a descriptor the learning parent handed us; the workload must not
    // inherit it.
    if unsafe { libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) } == 0 {
        let _ = LEARNING_REPORT_FD.set(fd);
    }
}

/// What this session was refused beyond paths (FW-DISC12): the Gateway's policy refusals, the
/// opener's `open-url` refusals, and pathname sockets the supervisor refused, mapped onto the
/// channels whose facilities `detect` found. The keyring's sockets are a credential type, not a
/// channel, so they are withheld rather than proposed.
fn session_observations(session: &Session) -> learn::SessionObservations {
    use formwork_blueprint::Channel;
    let mut obs = learn::SessionObservations::default();
    if let Some(egress) = &session.egress {
        obs.egress = egress
            .proxy
            .violations()
            .into_iter()
            .filter_map(|v| v.need)
            .collect();
        obs.tunnel_candidates = egress
            .proxy
            .ca_rejections()
            .into_iter()
            .map(|(host, port)| {
                if port == formwork_blueprint::DEFAULT_HTTPS_PORT {
                    format!("tunnel:{host}")
                } else {
                    format!("tunnel:{host}:{port}")
                }
            })
            .collect();
    }
    if let Some(service) = session.opener.as_ref().and_then(|o| o.service.as_ref()) {
        // Unlifted, every URL is refused for the channel alone (FW-DISC12).
        let records = service.records_within(std::time::Duration::from_millis(500));
        if !session.blueprint.channels.lifted(Channel::OpenUrl) && !records.is_empty() {
            obs.channels.push(Channel::OpenUrl.name().to_string());
        }
    }
    let f = &session.host.facilities;
    let refused = session
        .refused_sockets
        .lock()
        .map(|r| r.clone())
        .unwrap_or_default();
    for path in refused {
        let p = path.display().to_string();
        let is = |candidate: &Option<String>| candidate.as_deref() == Some(p.as_str());
        let channel = if is(&f.keyring) {
            obs.withheld.push((
                p.clone(),
                "the keyring is a credential type; lift it with allow-credentials = \
                 [\"os-keyring\"]"
                    .to_string(),
            ));
            None
        } else if is(&f.session_bus) || is(&f.user_manager) {
            Some(Channel::RunOutside)
        } else if f.display.contains(&p) {
            Some(Channel::Clipboard)
        } else if is(&f.audio) {
            Some(Channel::Microphone)
        } else {
            None
        };
        if let Some(c) = channel {
            obs.channels.push(c.name().to_string());
        }
    }
    obs
}

/// Hand this session's observations to the Linux `learn` that spawned it, if one did.
fn report_to_learning_run(session: &Session) {
    let Some(&fd) = LEARNING_REPORT_FD.get() else {
        return;
    };
    use std::os::fd::FromRawFd;
    // SAFETY: the descriptor was handed to this process for exactly this write; it is owned here.
    let mut file = unsafe { std::fs::File::from_raw_fd(fd) };
    let body = serde_json::to_vec(&session_observations(session)).unwrap_or_default();
    if let Err(e) = std::io::Write::write_all(&mut file, &body) {
        tracing::warn!(error = %e, "could not report observations to the learning run");
    }
}

fn run(blueprint: BlueprintArgs, argv: Vec<String>, confine_self: bool) -> Result<()> {
    let purpose = if confine_self {
        Purpose::ConfineSelf
    } else {
        Purpose::Spawn
    };
    let mut session = prepare_session(&blueprint, purpose, detect())?;
    let (program, args) = argv.split_first().expect("argv is required");
    if !confine_self {
        let status = spawn_confined_child(&mut session, program, args)?;
        report_to_learning_run(&session);
        std::process::exit(exit_code(&status));
    }
    formwork_confine::enforce_self(&session.policy).context("confining self")?;
    tracing::info!(program = %program, "exec after confine-self");
    // The session temp directory outlives an exec in place: no launcher remains to remove it.
    let err = exec_replace(
        program,
        args,
        &session.blueprint,
        &session.catalog,
        &session_env(&session),
    );
    bail!("exec failed after confine-self: {err}");
}

/// Which denial feed this host carries (FW-XR6 parity on the discovery axis), or -- as the error
/// -- why none does, phrased for the fail-fast message (FW-XR9).
enum DenialFeed {
    /// macOS: post-hoc `log show` over the run window, polled to quiescence.
    MacosUnifiedLog,
    /// Linux: the workload runs under an unconfined `strace` at this path (FW-E2E-071).
    LinuxPtrace(PathBuf),
}

fn denial_feed(host: &formwork_detect::HostProfile) -> Result<DenialFeed, String> {
    match host.os {
        formwork_detect::Os::MacOs => Ok(DenialFeed::MacosUnifiedLog),
        formwork_detect::Os::Linux => {
            if host.landlock_abi.is_none() {
                Err(
                    "this Linux kernel has no Landlock (5.13+ needed), so nothing is enforced \
                     and no denial exists to observe."
                        .to_string(),
                )
            } else if let Some(strace) = learn::find_strace() {
                Ok(DenialFeed::LinuxPtrace(strace))
            } else {
                Err(
                    "the Linux feed traces the workload with `strace` (ptrace), and no `strace` \
                     is on PATH -- install strace to enable learning here."
                        .to_string(),
                )
            }
        }
    }
}

/// `formwork learn`: an enforced run bracketed by observation (FW-DISC1). Visibly distinct from
/// a plain run, changes nothing about the live policy, and concludes by writing the proposal /
/// self-accepting in-zone candidates for the NEXT run. On a host with no denial feed this fails
/// BEFORE the workload runs (FW-XR9/FW-INV5): running an entire session and only then announcing
/// that observation was impossible would waste the run while looking like it worked.
fn learn_run(blueprint: BlueprintArgs, argv: Vec<String>, observe_anyway: bool) -> Result<()> {
    let host = detect();
    let feed = denial_feed(&host);
    match (&feed, observe_anyway) {
        (Err(reason), false) => bail!(
            "`formwork learn` needs a kernel denial feed: {reason} The policy itself may still \
             be enforceable: use `formwork run` and author grants by hand, or pass \
             --observe-anyway to run enforced without observation (no proposal will be written)."
        ),
        // A feed exists, so the flag would silently change nothing -- refuse it (FW-DISC11).
        (Ok(_), true) => bail!(
            "--observe-anyway is for hosts without a denial feed, and this host has one; drop \
             the flag to learn normally"
        ),
        _ => {}
    }
    let run_id = format!(
        "learn-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    );
    let feed = match feed {
        Ok(feed) => feed,
        Err(_) => {
            // --observe-anyway: enforced run, loudly observation-free, no proposal (FW-E2E-062).
            let mut session = prepare_session(&blueprint, Purpose::Spawn, host.clone())?;
            let (program, args) = argv.split_first().expect("argv is non-empty");
            let status = spawn_confined_child(&mut session, program, args)?;
            tracing::warn!(
                "--observe-anyway: ran enforced, but this host has no denial feed -- no proposal was written (FW-INV5: reported, not pretended)"
            );
            std::process::exit(exit_code(&status));
        }
    };
    match feed {
        DenialFeed::MacosUnifiedLog => {
            let mut session = prepare_session(&blueprint, Purpose::Spawn, host.clone())?;
            tracing::info!(
                "LEARNING MODE (observe-then-widen): the policy below is enforced unchanged; denials are recorded and proposed, never granted live (FW-DISC1/FW-INV10)"
            );
            let feed = learn::UnifiedLogFeed::start();
            let (program, args) = argv.split_first().expect("argv is non-empty");
            let status = spawn_confined_child(&mut session, program, args)?;
            let mut observations = session_observations(&session);
            let messages =
                learn::this_session(feed.collect_quiescent()?, session.deny_tag.as_deref());
            learn::service_observations(&messages, &session.catalog, &mut observations);
            let records = learn::fs_denials(&messages);
            learn::conclude_learning_run(
                &session.blueprint,
                &session.blueprint_path,
                &session.catalog,
                &run_id,
                records,
                &observations,
                &status,
            )?;
            std::process::exit(exit_code(&status));
        }
        DenialFeed::LinuxPtrace(strace) => learn_run_linux(strace, &blueprint, &argv, &run_id),
    }
}

/// The Linux learning run (FW-E2E-071): the enforced workload runs under an UNCONFINED `strace`
/// ancestor, which spawns a `formwork run --confine-self` shim; the shim applies Landlock/seccomp
/// to itself and execs the workload, so the tracer stays outside the wall it observes and needs
/// no grant, no ptrace hole in the policy, and no Yama exception (it is the tracee's ancestor).
/// Session preparation, env construction, and the operator itemization all happen once, in the
/// shim -- this side only resolves what `conclude_learning_run` needs. Unlike the macOS window
/// there is no persistence latency: the trace file is complete when strace exits, and only this
/// run's process tree is in it.
fn learn_run_linux(
    strace: PathBuf,
    args: &BlueprintArgs,
    argv: &[String],
    run_id: &str,
) -> Result<()> {
    let resolved = args.resolve()?;
    let home = home();
    let loaded = args.load(&resolved.path, &home)?;
    // Kernel-resolved coordinates for the auto-widen zone and the catalog floor, exactly as the
    // shim will enforce them (FW-DISC3/FW-DISC4).
    let blueprint = blueprint_load::canonicalize_for_enforcement(&loaded)
        .context("canonicalizing grant paths")?;
    let catalog =
        ResolvedCatalog::builtin_for_home(&home).context("resolving credential catalog")?;
    let catalog = blueprint_load::canonicalize_catalog_for_enforcement(&catalog)
        .context("canonicalizing credential catalog paths")?;

    tracing::info!(
        "LEARNING MODE (observe-then-widen): the policy below is enforced unchanged; denials are recorded and proposed, never granted live (FW-DISC1/FW-INV10)"
    );
    let trace_path = std::env::temp_dir().join(format!("formwork-{run_id}.strace"));
    let current_exe = std::env::current_exe()
        .context("locating the formwork binary for the confine-self shim")?;
    let mut command = Command::new(&strace);
    command
        // -s 4096: strace abbreviates strings at 32 bytes by default, which would truncate real
        // paths and silently lose their denials (the FW-INV6 shape).
        .args(["-f", "-qq", "-s", "4096", "-e", "trace=%file", "-o"])
        .arg(&trace_path)
        .arg("--")
        .arg(&current_exe)
        // Host rules need the spawn posture's Gateway and supervisor outside the sandbox, and the
        // isolation tier its stage; the tracer follows the spawned child the same way it follows
        // a confine-self exec.
        .args(
            if loaded.net.host_table().is_some() || !loaded.isolate.is_empty() {
                &["run", "--blueprint"][..]
            } else {
                &["run", "--confine-self", "--blueprint"][..]
            },
        )
        .arg(&resolved.path)
        .args(args.forward_overrides())
        .arg("--")
        .args(argv);
    // FW-DISC12: the shim's Gateway, opener and supervisor report over a pipe it inherits.
    let (report_read, report_write) =
        cloexec_pipe().context("creating the learning report pipe")?;
    let report_fd = {
        use std::os::fd::AsRawFd;
        report_write.as_raw_fd()
    };
    command.env(learn::REPORT_FD_ENV, report_fd.to_string());
    // `report_write` stays open until the spawn returns.
    formwork_confine::inherit_fd(&mut command, report_fd);
    let reader = std::thread::spawn(move || {
        let mut body = Vec::new();
        let _ = std::io::Read::read_to_end(&mut &report_read, &mut body);
        body
    });
    tracing::info!(tracer = %strace.display(), "spawning the workload under the ptrace denial feed");
    let status = command.status();
    drop(command);
    drop(report_write);
    let status = status.context("spawning strace")?;
    log_exit("traced workload exited", &status);
    let observations: learn::SessionObservations = reader
        .join()
        .ok()
        .filter(|b| !b.is_empty())
        .and_then(|b| serde_json::from_slice(&b).ok())
        .unwrap_or_default();

    let trace = std::fs::read_to_string(&trace_path)
        .with_context(|| format!("reading the strace log {}", trace_path.display()))?;
    let _ = std::fs::remove_file(&trace_path);
    let cwd = cwd()?;
    let records = learn::parse_strace_denials(&trace, std::path::Path::new(&cwd));
    learn::conclude_learning_run(
        &blueprint,
        &resolved.path,
        &catalog,
        run_id,
        records,
        &observations,
        &status,
    )?;
    std::process::exit(exit_code(&status));
}

/// A close-on-exec pipe, read end first (`std::io::pipe` postdates the MSRV, and macOS has no
/// `pipe2`). Created before any child is spawned from this thread.
fn cloexec_pipe() -> std::io::Result<(std::fs::File, std::fs::File)> {
    use std::os::fd::FromRawFd;
    let mut fds = [0 as libc::c_int; 2];
    // SAFETY: pipe writes two descriptors into `fds`; both are owned below.
    if unsafe { libc::pipe(fds.as_mut_ptr()) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: fresh descriptors from pipe, owned from here on.
    let (read, write) = unsafe {
        (
            std::fs::File::from_raw_fd(fds[0]),
            std::fs::File::from_raw_fd(fds[1]),
        )
    };
    for fd in fds {
        // SAFETY: F_SETFD on a descriptor owned above.
        if unsafe { libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) } != 0 {
            return Err(std::io::Error::last_os_error());
        }
    }
    Ok((read, write))
}

/// The operator channel's compile-time itemization (FW-CRED7). The full roll-call is identical
/// on every run, so the default (info) line is a summary whose only varying part -- the
/// deliberate exclusions -- is spelled out; the per-type roll-call itemizes at debug
/// (RUST_LOG=debug). The active backstop gets its own info line, because it is the one floor row
/// that denies inside the operator's own granted working set (FW-CRED6). The compile report stays
/// the canonical itemized form. The confined agent never sees any of this -- its channel is the
/// bare EACCES / the absent variable (FW-INV9).
fn itemize_credential_floor(report: &formwork_compile::FidelityReport, catalog: &ResolvedCatalog) {
    let creds = &report.credentials;
    // Counted by this host's verdict: a type whose any-depth rows are withheld (FW-CRED9), or
    // that no mechanism carries here, is itemized apart and never called denied (FW-INV5).
    let paths = render::FloorArm::paths(creds);
    let envs = render::FloorArm::envs(creds);
    tracing::info!(
        path_types_denied = paths.enforced.len(),
        path_types_partial = paths.partial.len(),
        path_types_unenforceable = paths.unenforceable.len(),
        env_types_stripped = envs.enforced.len(),
        catalog_version = creds.catalog_version,
        allowed = ?creds.allowed,
        "credential floor active (RUST_LOG=debug itemizes per type)"
    );
    tracing::debug!(
        denied_path_types = ?paths.enforced,
        partial_path_types = ?paths.partial,
        unenforceable_path_types = ?paths.unenforceable,
        stripped_env_types = ?envs.enforced,
        "credential catalog floor, itemized"
    );
    // The backstop is the one floor row that denies inside the operator's OWN granted set, so its
    // bare EACCES (FW-CRED7) has no visible cause -- name it at spawn (`None` means lifted). Where
    // the host withholds it (FW-CRED9), say that instead: there is no EACCES to explain.
    if let Some(f) = &creds.backstop {
        if f.is_enforced() {
            tracing::info!(
                "credential backstop active: {}, and a confined tool hitting one sees a bare \
                 EACCES -- run `formwork explain <path>` for the shape and the lift",
                render::backstop(f)
            );
        } else {
            tracing::info!(
                "credential backstop not enforced on this host: {} -- `formwork explain <path>` \
                 marks the paths it would deny",
                render::backstop(f)
            );
        }
        let shapes: Vec<String> = catalog.backstop.iter().map(|p| p.to_string()).collect();
        tracing::debug!(backstop_shapes = ?shapes, "credential backstop shapes");
    }
}

/// The launcher arm (FEP-2 §6): build the confined child's environment -- the credential-catalog
/// strip partitions first (FW-CRED2/4), then the posture (FW-ENV1/2). Impure -- it reads the real
/// process environment -- so it lives in the CLI shell; the decision itself is the pure
/// `construct_env`. Itemization is names and types only, never values (FW-CRED7).
fn apply_env(
    command: &mut Command,
    blueprint: &Blueprint,
    catalog: &ResolvedCatalog,
    session_vars: &[(String, String)],
    path_prefix: Option<&std::path::Path>,
) {
    let vars: Vec<(String, String)> = std::env::vars().collect();
    let built = formwork_blueprint::construct_env(
        &blueprint.env,
        catalog,
        &blueprint.exposed_credentials(),
        &blueprint.channels,
        vars,
    );
    command.env_clear();
    command.envs(built.kept.iter().cloned());
    // Set after the posture ran, so no scrub or allowlist can drop the session's own variables.
    command.envs(session_vars.iter().map(|(k, v)| (k, v)));
    // FW-ISO17: the opener shim goes first in the PATH the posture built (or, when the posture
    // dropped it, this process's own).
    if let Some(prefix) = path_prefix {
        let base = built
            .kept
            .iter()
            .find(|(k, _)| k == "PATH")
            .map(|(_, v)| v.clone())
            .or_else(|| std::env::var("PATH").ok())
            .unwrap_or_else(|| "/usr/bin:/bin".to_string());
        command.env("PATH", format!("{}:{base}", prefix.display()));
    }
    if !built.locator_stripped.is_empty() {
        tracing::info!(stripped = ?built.locator_stripped, "channel locator variables stripped (channels not lifted, FW-BP11)");
    }
    if !built.posture_dropped.is_empty() {
        tracing::info!(count = built.posture_dropped.len(), dropped = ?built.posture_dropped, "scrubbed environment variables");
    }
    if !built.stripped.is_empty() {
        tracing::info!(stripped = ?built.stripped, "credential catalog: env vars stripped by the launcher");
    }
}

/// Proxy MCP traffic between the launching host (this process's stdin/stdout) and a confined stdio
/// backend, applying the blueprint's `[mcp.<server>]` policy. One blueprint governs both surfaces: its
/// `[mcp.<server>]` entry shades the protocol, its fs/net grant confines the backend the same way
/// `run` confines any command (FW-GW5), so the backend spawns behind the same wall.
fn gateway(blueprint: BlueprintArgs, server: String, argv: Vec<String>) -> Result<()> {
    let session = prepare_session(&blueprint, Purpose::GatewayBackend, detect())?;

    // An unlisted server is a config error, not a silent deny: a typo would otherwise masquerade as
    // a backend that legitimately exposes nothing, hiding the mistake.
    let policy = session.blueprint.mcp.get(&server).cloned().ok_or_else(|| {
        let known: Vec<&str> = session.blueprint.mcp.keys().map(String::as_str).collect();
        anyhow!("blueprint has no [mcp.{server}] policy (known servers: {known:?})")
    })?;

    let (program, args) = argv.split_first().expect("argv is required");
    let mut backend = formwork_gateway::confined_command(program, args, &session.policy)
        .context("building confined backend command")?;
    // The gateway is a launcher too: the backend it spawns is part of the session, so the same
    // env construction applies (FW-CRED2 env arm; FW-INV7 covers the whole tree).
    apply_env(
        &mut backend,
        &session.blueprint,
        &session.catalog,
        &session_env(&session),
        None,
    );

    tracing::info!(server = %server, backend = %program, "starting MCP gateway");
    // The async runtime lives entirely in `formwork-gateway` (constitution Layers): the CLI stays
    // synchronous and hands the confined backend over as a plain command.
    let served = formwork_gateway::serve_stdio(backend, policy).context("proxying MCP traffic");
    session.tmp_dir.remove();
    served
}

#[cfg(unix)]
fn exec_replace(
    program: &str,
    args: &[String],
    blueprint: &Blueprint,
    catalog: &ResolvedCatalog,
    session_vars: &[(String, String)],
) -> std::io::Error {
    use std::os::unix::process::CommandExt;
    let mut command = Command::new(program);
    command.args(args);
    apply_env(&mut command, blueprint, catalog, session_vars, None);
    command.exec()
}
