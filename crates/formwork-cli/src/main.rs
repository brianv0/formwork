//! `formwork` -- the CLI and v1 embedding surface.
//!
//! ```text
//! formwork detect
//! formwork compile --spec s.toml [--host h.json | --target linux-v6|macos] [--report-only]
//! formwork run     --spec s.toml -- cmd args…   # spawn-confined
//! formwork enforce-self --spec s.toml -- cmd…   # confine-self, then exec
//! formwork gateway --spec s.toml --server files -- cmd…  # MCP policy proxy over stdio
//! ```
//!
//! `detect`/`compile` are pure and run on any host (including compiling a Linux policy on a Mac);
//! `run`/`enforce-self`/`gateway` need a real confiner and error honestly where the backend is
//! unimplemented.

mod spec_load;

use std::path::PathBuf;
use std::process::Command;

use anyhow::{anyhow, bail, Context, Result};
use clap::{Parser, Subcommand, ValueEnum};

use formwork_compile::compile;
use formwork_detect::{detect, HostProfile};
use formwork_spec::McpPolicy;

#[derive(Parser)]
#[command(name = "formwork", version, about = "OS-level sandbox for agent sessions")]
struct Cli {
    #[command(subcommand)]
    command: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Probe this host's enforcement capabilities and print a HostProfile as JSON.
    Detect,
    /// Compile a spec into a policy + fidelity report without enforcing (dry-run).
    Compile {
        #[arg(long)]
        spec: PathBuf,
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
        #[arg(long)]
        spec: PathBuf,
        #[arg(trailing_var_arg = true, allow_hyphen_values = true, required = true)]
        argv: Vec<String>,
    },
    /// Confine the current process, then exec the given command (confine-self posture).
    EnforceSelf {
        #[arg(long)]
        spec: PathBuf,
        #[arg(trailing_var_arg = true, allow_hyphen_values = true, required = true)]
        argv: Vec<String>,
    },
    /// Front a stdio MCP backend with the policy gateway: shade its tools/resources/prompts per the
    /// spec's `[mcp.<server>]` entry and confine the spawned backend to the spec's fs/net grant.
    /// Speaks newline-delimited JSON-RPC on stdin/stdout, so an MCP host launches it as the server.
    Gateway {
        #[arg(long)]
        spec: PathBuf,
        /// Which `[mcp.<server>]` policy from the spec governs this connection.
        #[arg(long)]
        server: String,
        #[arg(trailing_var_arg = true, allow_hyphen_values = true, required = true)]
        argv: Vec<String>,
    },
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
            spec,
            host,
            target,
            report_only,
        } => {
            let spec = spec_load::load(&spec, &home())?;
            let host = resolve_host(&host, &target)?;
            let policy = compile(&spec, &host);
            if report_only {
                println!("{}", serde_json::to_string_pretty(&policy.report)?);
            } else {
                println!("{}", serde_json::to_string_pretty(&policy)?);
            }
        }
        Cmd::Run { spec, argv } => run(spec, argv, Posture::Spawn)?,
        Cmd::EnforceSelf { spec, argv } => run(spec, argv, Posture::Self_)?,
        Cmd::Gateway {
            spec,
            server,
            argv,
        } => gateway(spec, server, argv)?,
    }
    Ok(())
}

enum Posture {
    Spawn,
    Self_,
}

fn run(spec: PathBuf, argv: Vec<String>, posture: Posture) -> Result<()> {
    let spec = spec_load::load(&spec, &home())?;
    // Resolve symlinks in grant paths so the kernel's resolved-path matching lines up (macOS
    // firmlinks). Enforcement path only, never dry-run. Fails loud on a path that can't be
    // faithfully rendered (FW-INV6).
    let spec = spec_load::canonicalize_for_enforcement(&spec).context("canonicalizing grant paths")?;
    let host = detect();
    let policy = compile(&spec, &host);

    let (program, args) = argv.split_first().expect("argv is required");
    match posture {
        Posture::Spawn => {
            let mut command = Command::new(program);
            command.args(args);
            formwork_confine::spawn_confined(&mut command, &policy)
                .context("applying confinement")?;
            tracing::info!(program = %program, "spawning confined command");
            let status = command.status().context("spawning confined command")?;
            tracing::info!(exit_code = ?status.code(), "confined command exited");
            std::process::exit(status.code().unwrap_or(1));
        }
        Posture::Self_ => {
            formwork_confine::enforce_self(&policy).context("confining self")?;
            tracing::info!(program = %program, "exec after confine-self");
            let err = exec_replace(program, args);
            bail!("exec failed after confine-self: {err}");
        }
    }
}

/// Proxy MCP traffic between the launching host (this process's stdin/stdout) and a confined stdio
/// backend, applying the spec's `[mcp.<server>]` policy. One spec governs both surfaces: its
/// `[mcp.<server>]` entry shades the protocol, its fs/net grant confines the backend the same way
/// `run` confines any command (FW-GW5), so the backend spawns behind the same wall.
fn gateway(spec: PathBuf, server: String, argv: Vec<String>) -> Result<()> {
    let spec = spec_load::load(&spec, &home())?;
    let spec =
        spec_load::canonicalize_for_enforcement(&spec).context("canonicalizing grant paths")?;

    // An unlisted server is a config error, not a silent deny: a typo would otherwise masquerade as
    // a backend that legitimately exposes nothing, hiding the mistake.
    let policy = spec.mcp.get(&server).cloned().ok_or_else(|| {
        let known: Vec<&str> = spec.mcp.keys().map(String::as_str).collect();
        anyhow!("spec has no [mcp.{server}] policy (known servers: {known:?})")
    })?;

    let backend_policy = compile(&spec, &detect());
    let (program, args) = argv.split_first().expect("argv is required");
    let backend = formwork_gateway::confined_command(program, args, &backend_policy)
        .context("building confined backend command")?;

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
fn exec_replace(program: &str, args: &[String]) -> std::io::Error {
    use std::os::unix::process::CommandExt;
    Command::new(program).args(args).exec()
}
