//! `formwork` -- the CLI and v1 embedding surface.
//!
//! ```text
//! formwork detect
//! formwork compile --blueprint s.toml [--host h.json | --target linux-v6|macos] [--report-only]
//! formwork run     --blueprint s.toml -- cmd args…   # spawn-confined
//! formwork enforce-self --blueprint s.toml -- cmd…   # confine-self, then exec
//! formwork gateway --blueprint s.toml --server files -- cmd…  # MCP policy proxy over stdio
//! ```
//!
//! The capability blueprint is passed with `--blueprint`; `--spec` is accepted as a back-compat
//! alias. Every blueprint-taking subcommand accepts the same override surface (FW-BP1/BP2):
//! `--set '<toml>'` fragments and the sugar flags (`--read/--write/--subtract/--write-subtract/`
//! `--allow-cred/--net/--extends`) layer over the file, additively, deny-beats-allow.
//!
//! `detect`/`compile` don't enforce and run on any host (including compiling a Linux policy on a Mac);
//! `run`/`enforce-self`/`gateway` need a real confiner and error honestly where the backend is
//! unimplemented.

mod blueprint_load;
mod learn;

use std::path::PathBuf;
use std::process::Command;

use anyhow::{anyhow, bail, Context, Result};
use clap::{Parser, Subcommand, ValueEnum};

use formwork_blueprint::{
    Blueprint, BlueprintLayer, McpPolicy, NetPosture, PathPattern, ResolvedCatalog,
};
use formwork_compile::compile;
use formwork_detect::{detect, HostProfile};

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

#[derive(Subcommand)]
enum Cmd {
    /// Probe this host's enforcement capabilities and print a HostProfile as JSON.
    Detect,
    /// Compile a blueprint into a policy + fidelity report without enforcing (dry-run).
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
        #[arg(trailing_var_arg = true, allow_hyphen_values = true, required = true)]
        argv: Vec<String>,
    },
    /// Confine the current process, then exec the given command (confine-self posture).
    EnforceSelf {
        #[command(flatten)]
        blueprint: BlueprintArgs,
        #[arg(trailing_var_arg = true, allow_hyphen_values = true, required = true)]
        argv: Vec<String>,
    },
    /// Learning run (observe-then-widen, FW-DISC1): enforce exactly like `run`, record the
    /// denials the kernel logged during the window, and reverse-compile them into a reviewable
    /// proposal. Observation never widens the live session (FW-INV10).
    Learn {
        #[command(flatten)]
        blueprint: BlueprintArgs,
        #[arg(trailing_var_arg = true, allow_hyphen_values = true, required = true)]
        argv: Vec<String>,
    },
    /// Accept needs-review entries from a `formwork learn` proposal into the discovered layer,
    /// per entry (FW-DISC5). Credential-floor matches are refused here regardless of what the
    /// proposal claims (FW-INV8).
    Accept {
        #[arg(long)]
        proposal: PathBuf,
        /// Accept one candidate by its exact pattern (repeatable).
        #[arg(long)]
        entry: Vec<String>,
        /// Accept every needs-review candidate.
        #[arg(long)]
        all: bool,
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
}

/// One blueprint, two surfaces (FW-BP1): the file plus the CLI override layer. `--set` fragments
/// are TOML parsed by the same serde model as the file -- parity is by construction -- and the
/// sugar flags desugar into one final layer (postures here beat `--set`, both beat the file).
#[derive(clap::Args)]
struct BlueprintArgs {
    #[arg(long, visible_alias = "spec")]
    blueprint: PathBuf,
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
    /// Extra base blueprints layered under the CLI overrides (repeatable, resolved against cwd).
    #[arg(long)]
    extends: Vec<String>,
}

impl BlueprintArgs {
    /// Resolve the full layer stack and merge (FW-BP2). `~` in flag values expands against the
    /// same `$HOME` as file contents, so the two surfaces stay one model.
    fn load(&self, home: &str) -> Result<Blueprint> {
        blueprint_load::load_stack(&self.blueprint, &self.set, self.sugar_layer(home)?, home)
    }

    fn sugar_layer(&self, home: &str) -> Result<BlueprintLayer> {
        let patterns = |flag: &str, values: &[String]| -> Result<Vec<PathPattern>> {
            values
                .iter()
                .map(|v| {
                    PathPattern::parse(&blueprint_load::expand_tilde_str(v, home))
                        .with_context(|| format!("--{flag} {v:?}"))
                })
                .collect()
        };
        Ok(BlueprintLayer {
            extends: self.extends.clone(),
            fs: formwork_blueprint::FsLayer {
                read_mode: None,
                reads: patterns("read", &self.read)?,
                writes: patterns("write", &self.write)?,
                subtract: patterns("subtract", &self.subtract)?,
                write_subtract: patterns("write-subtract", &self.write_subtract)?,
            },
            net: self.net.as_deref().map(parse_net).transpose()?,
            exec: None,
            env: None,
            mcp: Default::default(),
            allow_credentials: self.allow_cred.clone(),
            discovery: Default::default(),
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
    use tracing_subscriber::{fmt, EnvFilter};
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    let _ = fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .with_target(false)
        .try_init();
}

fn main() -> Result<()> {
    init_telemetry();
    let cli = Cli::parse();
    let cmd = match &cli.command {
        Cmd::Detect => "detect",
        Cmd::Compile { .. } => "compile",
        Cmd::Run { .. } => "run",
        Cmd::EnforceSelf { .. } => "enforce-self",
        Cmd::Learn { .. } => "learn",
        Cmd::Accept { .. } => "accept",
        Cmd::Gateway { .. } => "gateway",
    };
    // One correlation id per invocation, propagated to every layer's events via the current span.
    let _root = tracing::info_span!("formwork", run_id = std::process::id(), cmd).entered();
    match cli.command {
        Cmd::Detect => {
            let profile = detect();
            println!("{}", serde_json::to_string_pretty(&profile)?);
        }
        Cmd::Compile {
            blueprint,
            host,
            target,
            report_only,
        } => {
            let blueprint = blueprint.load(&home())?;
            let host = resolve_host(&host, &target)?;
            let catalog = ResolvedCatalog::builtin_for_home(&home())
                .context("resolving credential catalog")?;
            let policy = compile(&blueprint, &host, &catalog);
            if report_only {
                println!("{}", serde_json::to_string_pretty(&policy.report)?);
            } else {
                println!("{}", serde_json::to_string_pretty(&policy)?);
            }
        }
        Cmd::Run { blueprint, argv } => run(blueprint, argv, Posture::Spawn)?,
        Cmd::EnforceSelf { blueprint, argv } => run(blueprint, argv, Posture::Self_)?,
        Cmd::Learn { blueprint, argv } => learn_run(blueprint, argv)?,
        Cmd::Accept {
            proposal,
            entry,
            all,
        } => learn::accept(&proposal, &entry, all, &home())?,
        Cmd::Gateway {
            blueprint,
            server,
            argv,
        } => gateway(blueprint, server, argv)?,
    }
    Ok(())
}

enum Posture {
    Spawn,
    Self_,
}

/// Everything every enforcing subcommand shares: load the stack (discovered layer included),
/// add the FW-CRED3 env-file-ref denies, write-protect the policy inputs themselves, resolve
/// against the real filesystem, compile against the catalog, and itemize the floor.
struct Session {
    blueprint: Blueprint,
    catalog: ResolvedCatalog,
    policy: formwork_compile::CompiledPolicy,
}

fn prepare_session(args: &BlueprintArgs) -> Result<Session> {
    let mut blueprint = args.load(&home())?;
    let catalog =
        ResolvedCatalog::builtin_for_home(&home()).context("resolving credential catalog")?;
    // FW-CRED3: deny the files that enforced env-points-to-file credentials name, before the
    // blueprint's enforcement-time canonicalization resolves everything together.
    blueprint
        .fs
        .subtract
        .extend(blueprint_load::env_file_ref_denies(
            &catalog,
            &blueprint.allow_credentials,
        )?);
    // The policy inputs are write-denied inside the session: a confined agent must not be able
    // to edit the blueprint, forge the discovered layer, or doctor the proposal that shapes its
    // own NEXT run (FW-XR8 / FW-INV8).
    blueprint_load::protect_policy_inputs(&mut blueprint, &args.blueprint)?;
    // Resolve symlinks in grant paths so the kernel's resolved-path matching lines up (macOS
    // firmlinks). Enforcement path only, never dry-run. Fails loud on a path that can't be
    // faithfully rendered (FW-INV6). The catalog's paths get the same treatment -- a floor hole
    // that silently failed to match would be a fail-open of the sensitive set.
    let blueprint = blueprint_load::canonicalize_for_enforcement(&blueprint)
        .context("canonicalizing grant paths")?;
    let catalog = blueprint_load::canonicalize_catalog_for_enforcement(&catalog)
        .context("canonicalizing credential catalog paths")?;
    let host = detect();
    let policy = compile(&blueprint, &host, &catalog);
    itemize_credential_floor(&policy.report);
    Ok(Session {
        blueprint,
        catalog,
        policy,
    })
}

fn spawn_confined_child(
    session: &Session,
    program: &str,
    args: &[String],
) -> Result<std::process::ExitStatus> {
    let mut command = Command::new(program);
    command.args(args);
    apply_env(&mut command, &session.blueprint, &session.catalog);
    formwork_confine::spawn_confined(&mut command, &session.policy)
        .context("applying confinement")?;
    tracing::info!(program = %program, "spawning confined command");
    let status = command.status().context("spawning confined command")?;
    tracing::info!(exit_code = ?status.code(), "confined command exited");
    Ok(status)
}

fn run(blueprint: BlueprintArgs, argv: Vec<String>, posture: Posture) -> Result<()> {
    let session = prepare_session(&blueprint)?;
    let (program, args) = argv.split_first().expect("argv is required");
    match posture {
        Posture::Spawn => {
            let status = spawn_confined_child(&session, program, args)?;
            std::process::exit(status.code().unwrap_or(1));
        }
        Posture::Self_ => {
            formwork_confine::enforce_self(&session.policy).context("confining self")?;
            tracing::info!(program = %program, "exec after confine-self");
            let err = exec_replace(program, args, &session.blueprint, &session.catalog);
            bail!("exec failed after confine-self: {err}");
        }
    }
}

/// `formwork learn`: an enforced run bracketed by observation (FW-DISC1). Visibly distinct from
/// a plain run, changes nothing about the live policy, and concludes by writing the proposal /
/// self-accepting in-zone candidates for the NEXT run.
fn learn_run(blueprint: BlueprintArgs, argv: Vec<String>) -> Result<()> {
    let session = prepare_session(&blueprint)?;
    let host = detect();
    tracing::info!(
        "LEARNING MODE (observe-then-widen): the policy below is enforced unchanged; denials are          recorded and proposed, never granted live (FW-DISC1/FW-INV10)"
    );
    let started = std::time::Instant::now();
    let run_id = format!(
        "learn-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    );
    let (program, args) = argv.split_first().expect("argv is required");
    let status = spawn_confined_child(&session, program, args)?;

    if matches!(host.os, formwork_detect::Os::MacOs) {
        // Slack covers unified-log persistence latency; over-capture within the window is safe
        // (floored or review-gated), under-capture just means another learning run.
        let window_secs = started.elapsed().as_secs() + 4;
        learn::conclude_learning_run(
            &session.blueprint,
            &blueprint.blueprint,
            &session.catalog,
            &run_id,
            window_secs,
        )?;
    } else {
        tracing::warn!(
            "learning ran enforced, but this host has no denial feed (the macOS unified-log tap              is the only wired source; Landlock audit needs kernel 6.15+ and is unwired) -- no              proposal was written (FW-INV5: reported, not pretended)"
        );
    }
    std::process::exit(status.code().unwrap_or(1));
}

/// The operator channel's compile-time itemization (FW-CRED7): which catalog types are enforced
/// and which were deliberately let through. The confined agent never sees this -- its channel is
/// the bare EACCES / the absent variable (FW-INV9).
fn itemize_credential_floor(report: &formwork_compile::FidelityReport) {
    let creds = &report.credentials;
    let path_types: Vec<&str> = creds
        .per_type
        .iter()
        .filter(|(_, f)| f.path.is_some())
        .map(|(name, _)| name.as_str())
        .collect();
    let env_types: Vec<&str> = creds
        .per_type
        .iter()
        .filter(|(_, f)| f.env.is_some())
        .map(|(name, _)| name.as_str())
        .collect();
    tracing::info!(
        catalog_version = creds.catalog_version,
        denied_path_types = ?path_types,
        stripped_env_types = ?env_types,
        allowed = ?creds.allowed,
        "credential catalog floor"
    );
}

/// The launcher arm (FEP-2 §6): build the confined child's environment -- posture first
/// (FW-ENV1/2), then the credential-catalog strip (FW-CRED2/4). Impure -- it reads the real
/// process environment -- so it lives in the CLI shell; the decision itself is the pure
/// `construct_env`. Itemization is names and types only, never values (FW-CRED7).
fn apply_env(command: &mut Command, blueprint: &Blueprint, catalog: &ResolvedCatalog) {
    let vars: Vec<(String, String)> = std::env::vars().collect();
    let built = formwork_blueprint::construct_env(
        &blueprint.env,
        catalog,
        &blueprint.allow_credentials,
        vars,
    );
    command.env_clear();
    command.envs(built.kept.iter().cloned());
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
    let session = prepare_session(&blueprint)?;

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
    apply_env(&mut backend, &session.blueprint, &session.catalog);

    tracing::info!(server = %server, backend = %program, "starting MCP gateway");
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("building async runtime")?;
    runtime.block_on(proxy(backend, policy))
}

async fn proxy(backend: Command, policy: McpPolicy) -> Result<()> {
    use std::process::Stdio;

    let mut backend = tokio::process::Command::from(backend);
    backend.stdin(Stdio::piped()).stdout(Stdio::piped());
    let mut child = backend.spawn().context("spawning confined backend")?;
    let backend_read = child.stdout.take().expect("stdout is piped");
    let backend_write = child.stdin.take().expect("stdin is piped");

    formwork_gateway::Gateway::new(policy)
        .run(
            tokio::io::stdin(),
            tokio::io::stdout(),
            backend_read,
            backend_write,
        )
        .await
        .context("proxying MCP traffic")?;
    let status = child.wait().await.context("awaiting confined backend")?;
    tracing::info!(exit_code = ?status.code(), "confined MCP backend exited");
    Ok(())
}

#[cfg(unix)]
fn exec_replace(
    program: &str,
    args: &[String],
    blueprint: &Blueprint,
    catalog: &ResolvedCatalog,
) -> std::io::Error {
    use std::os::unix::process::CommandExt;
    let mut command = Command::new(program);
    command.args(args);
    apply_env(&mut command, blueprint, catalog);
    command.exec()
}
