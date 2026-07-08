//! The Landlock half of the confiner: filesystem scope and TCP net, built as a `RulesetCreated` in
//! the parent and `restrict_self()`-applied in the child (inherited across `execve`, FW-XR4). Landlock
//! is allow-list only, so two things the macOS SBPL got for free are done here explicitly: Closed-mode
//! runtime *essentials* (or nothing loads), and *subtractive expansion* -- `subtract` holes become the
//! shape of the grants, since Landlock has no deny rule (docs/linux-backend.md).
//!
//! ABI fidelity (FW-INV5/INV6): we enforce at exactly the compiler's `landlock_abi_target` and, after
//! `restrict_self`, assert the kernel reported *fully* enforced -- a partial/negotiated-down apply is
//! an error, never a silent weakening.

use std::collections::BTreeSet;
use std::io;
use std::path::{Path, PathBuf};

use landlock::{
    Access, AccessFs, AccessNet, BitFlags, CompatLevel, Compatible, NetPort, PathBeneath, PathFd,
    Ruleset, RulesetAttr, RulesetCreated, RulesetCreatedAttr, RulesetStatus, Scope, ABI,
};

use formwork_blueprint::{PathPattern, ReadMode};
use formwork_compile::{ExecPlan, LinuxNetPlan, LinuxPolicy};

use super::ConfineError;

fn fail(msg: impl Into<String>) -> ConfineError {
    ConfineError::MechanismFailed(msg.into())
}

/// Closed-mode runtime essentials: without these an `execve` cannot load `ld.so`/libraries and every
/// child dies before `main` (the Linux analogue of the macOS `dyld` failure). Curated literals; a
/// broad `/dev` is deliberately avoided (it would expose block devices -- an out-of-band fs read).
///
/// `/proc/self` is deliberately absent: it is a per-process symlink, so a rule built here (in the
/// parent) binds the *launcher's* `/proc/<pid>`, not the child's. The child's own `/proc/self` is
/// added post-fork in `apply` (runtimes read `/proc/self/{maps,exe,status}` and would otherwise die).
const READ_ESSENTIALS: &[&str] = &[
    "/usr",
    "/lib",
    "/lib64",
    "/bin",
    "/sbin",
    "/etc/ld.so.cache",
    "/etc/ld.so.preload",
];
const RW_DEVICES: &[&str] = &[
    "/dev/null",
    "/dev/zero",
    "/dev/urandom",
    "/dev/random",
    "/dev/tty",
];

fn abi_of(v: u32) -> ABI {
    match v {
        0 => ABI::Unsupported,
        1 => ABI::V1,
        2 => ABI::V2,
        3 => ABI::V3,
        4 => ABI::V4,
        5 => ABI::V5,
        6 => ABI::V6,
        _ => ABI::V7, // crate 0.4.5 tops out at V7; a higher host ABI clamps to what we can emit
    }
}

/// A concrete (absolute) subtract hole. Any-depth `**/` patterns are handled separately (they cannot
/// be a rooted Landlock rule); the caller rejects them so nothing is silently missed.
struct Hole {
    base: PathBuf,
    subtree: bool,
}

fn holes_of(patterns: &[PathPattern]) -> Result<Vec<Hole>, ConfineError> {
    patterns
        .iter()
        .map(|p| {
            if p.is_any_depth() {
                Err(fail(format!(
                    "any-depth pattern {p} cannot be a rooted Landlock rule; \
                     Linux enforcement of `**/` is pending (see docs/linux-backend.md)"
                )))
            } else {
                Ok(Hole {
                    base: p.base().to_path_buf(),
                    subtree: p.is_subtree(),
                })
            }
        })
        .collect()
}

impl Hole {
    /// The hole denies `path` outright (it is the hole, or lies within a subtree hole).
    fn covers(&self, path: &Path) -> bool {
        if self.subtree {
            path.starts_with(&self.base)
        } else {
            path == self.base
        }
    }
    /// The hole sits strictly below `dir` -- so `dir` must be split, not granted whole.
    fn strictly_under(&self, dir: &Path) -> bool {
        self.base != dir && self.base.starts_with(dir)
    }
}

/// Subtractive expansion (docs/linux-backend.md): the largest set of subtrees under `root` that
/// excludes every hole. Bounded by the number of holes, not filesystem size -- a directory with no
/// hole beneath it is granted whole. Fail-closed by construction: anything created under a *split*
/// directory after this runs is simply ungranted.
fn expand(root: &Path, holes: &[Hole]) -> Vec<PathBuf> {
    if holes.iter().any(|h| h.covers(root)) {
        return Vec::new(); // whole root denied
    }
    if !holes.iter().any(|h| h.strictly_under(root)) {
        return vec![root.to_path_buf()]; // no hole below -> grant the whole subtree
    }
    let mut out = Vec::new();
    let entries = match std::fs::read_dir(root) {
        Ok(e) => e,
        // Unreadable directory (e.g. permission): grant nothing under it, fail-closed.
        Err(_) => return out,
    };
    for entry in entries.flatten() {
        // Skip symlinks. `PathFd` opens with `O_PATH` (no `O_NOFOLLOW`), so granting or recursing a
        // symlink entry would bind the rule to its *target* -- an escape out of the wall. Access
        // *through* a symlink still resolves to the real path, which is governed by whatever rule
        // covers that path (or denied), exactly as macOS checks the resolved path. A failed type
        // probe is treated as a symlink and skipped too (fail-closed).
        if entry.file_type().map(|t| t.is_symlink()).unwrap_or(true) {
            continue;
        }
        let child = entry.path();
        if holes.iter().any(|h| h.covers(&child)) {
            continue;
        }
        if holes.iter().any(|h| h.strictly_under(&child)) {
            out.extend(expand(&child, holes));
        } else {
            out.push(child);
        }
    }
    out
}

/// A built ruleset plus the one thing that can only be finished in the child: whether to add the
/// child's own `/proc/self` (Closed mode) once its pid exists.
pub struct Built {
    ruleset: RulesetCreated,
    grant_proc_self: bool,
}

/// Build the ruleset in the parent. Returns `None` when the policy needs no Landlock (no ABI target),
/// in which case the seccomp half carries whatever net-deny the host allows.
pub fn build(policy: &LinuxPolicy) -> Result<Option<Built>, ConfineError> {
    let abi_ver = match policy.landlock_abi_target {
        Some(v) if v >= 1 => v,
        _ => return Ok(None),
    };
    let abi = abi_of(abi_ver);

    let govern_exec = matches!(policy.exec, ExecPlan::Allowlist { .. });
    // The access rights the ruleset governs. Governed-but-ungranted == denied; so we exclude Execute
    // unless an allow-list asked for it, keeping the default `execve` transparent (FW-ISO4).
    let mut handled_fs = AccessFs::from_all(abi);
    if !govern_exec {
        handled_fs &= !AccessFs::Execute;
    }
    // Do not govern device ioctls (IOCTL_DEV, ABI v5+). Governing it denies *every* ioctl on a device
    // node -- including the winsize/termios calls every interactive TUI makes on its inherited stdio,
    // whose controlling pty is dynamic and cannot be pre-granted. macOS has no separate device-ioctl
    // gate either (parity). The residual surface is small and well-mitigated: a process can only ioctl
    // a device it can already open (open is gated), and the dangerous device ioctls (e.g. TIOCSTI
    // terminal injection) are CAP_SYS_ADMIN-gated on modern kernels, which NO_NEW_PRIVS keeps out of
    // reach. `& !IoctlDev` is a no-op below v5, where the right does not exist.
    handled_fs &= !AccessFs::IoctlDev;
    let read_access = AccessFs::from_read(abi) & !AccessFs::Execute;
    let write_access = handled_fs; // read+write (+exec if governed); writes imply reads

    let mut ruleset = Ruleset::default()
        .set_compatibility(CompatLevel::HardRequirement) // no silent downgrade (FW-INV6)
        .handle_access(handled_fs)
        .map_err(|e| fail(format!("landlock handle_access(fs): {e}")))?;
    let net_governed = matches!(policy.net, LinuxNetPlan::LandlockTcp { .. }) && abi_ver >= 4;
    if net_governed {
        ruleset = ruleset
            .handle_access(AccessNet::from_all(abi))
            .map_err(|e| fail(format!("landlock handle_access(net): {e}")))?;
    }
    // Abstract-unix-socket + signal scoping (ABI v6+): the confined process can neither connect to an
    // abstract unix socket nor signal a process *outside* its Landlock domain. Abstract sockets carry
    // no path, so the filesystem rules cannot reach them -- without scoping, a confined process could
    // reach an unconfined sibling's abstract socket (an exfil/escape channel). This is exactly what
    // the report calls CrossDomainSocket = Partial at abi>=6 (FW-INV5: enforce what we claim).
    if abi_ver >= 6 {
        ruleset = ruleset
            .scope(Scope::from_all(abi))
            .map_err(|e| fail(format!("landlock scope: {e}")))?;
    }
    let mut created = ruleset
        .create()
        .map_err(|e| fail(format!("landlock create: {e}")))?;

    // --- filesystem grants ---
    let read_holes = holes_of(&policy.subtract)?;
    let mut write_holes = holes_of(&policy.subtract)?;
    write_holes.extend(holes_of(&policy.write_subtract)?); // write-subtract denies writes only

    let mut read_roots: Vec<PathBuf> = policy.reads.iter().map(root_of).collect();
    if policy.read_mode == ReadMode::Closed {
        read_roots.extend(READ_ESSENTIALS.iter().map(PathBuf::from));
        read_roots.extend(RW_DEVICES.iter().map(PathBuf::from)); // readable; write handled below
    }
    let read_paths = expand_all(&read_roots, &read_holes);
    let write_paths = expand_all(
        &policy.writes.iter().map(root_of).collect::<Vec<_>>(),
        &write_holes,
    );

    created = add_path_rules(created, &read_paths, read_access)?;
    created = add_path_rules(created, &write_paths, write_access)?;
    // The safe device nodes are writable regardless of mode (e.g. `cmd > /dev/null`).
    let dev_paths: Vec<PathBuf> = RW_DEVICES.iter().map(PathBuf::from).collect();
    created = add_path_rules(
        created,
        &dev_paths,
        AccessFs::WriteFile | AccessFs::ReadFile,
    )?;

    if let ExecPlan::Allowlist { paths } = &policy.exec {
        let exec_paths = expand_all(&paths.iter().map(root_of).collect::<Vec<_>>(), &[]);
        created = add_path_rules(created, &exec_paths, AccessFs::Execute | AccessFs::ReadFile)?;
    }

    // --- net grants ---
    if let LinuxNetPlan::LandlockTcp { ports } = &policy.net {
        if net_governed {
            for &port in ports {
                let rule = NetPort::new(port, AccessNet::ConnectTcp);
                created = created
                    .add_rule(rule)
                    .map_err(|e| fail(format!("landlock add net rule: {e}")))?;
            }
        }
    }

    Ok(Some(Built {
        ruleset: created,
        // Add the child's own /proc/self post-fork (below). Ambient mode already covers /proc via `/`.
        grant_proc_self: policy.read_mode == ReadMode::Closed,
    }))
}

/// Apply the built ruleset to the calling thread (the forked child, or in place for confine-self).
/// Runs post-`fork`, so it is allocation-free on the success path: it issues only syscalls and returns
/// raw OS errors. Asserts the kernel *fully* enforced -- a downgraded apply is a failure, not a
/// warning (FW-INV5/INV6).
pub fn apply(built: Built) -> io::Result<()> {
    let Built {
        ruleset,
        grant_proc_self,
    } = built;
    let ruleset = if grant_proc_self {
        add_proc_self(ruleset)?
    } else {
        ruleset
    };
    let status = ruleset
        .restrict_self()
        .map_err(|_| io::Error::last_os_error())?;
    match status.ruleset {
        RulesetStatus::FullyEnforced => Ok(()),
        // PartiallyEnforced/NotEnforced carry no errno; surface a fixed EPERM. Fail-closed: the caller
        // aborts the spawn, so there is no weakly-confined child.
        _ => Err(io::Error::from_raw_os_error(libc::EPERM)),
    }
}

/// Grant the child read of its OWN `/proc/self`, resolved here (post-fork) so it binds the child's
/// pid. Landlock rules are inode-keyed and `/proc/<pid>` is per-process, so this cannot be done at
/// build time in the parent. A missing `/proc` (rare, minimal container) is not an error.
fn add_proc_self(ruleset: RulesetCreated) -> io::Result<RulesetCreated> {
    let fd = match PathFd::new("/proc/self") {
        Ok(fd) => fd,
        Err(_) => return Ok(ruleset),
    };
    ruleset
        .add_rule(PathBeneath::new(fd, AccessFs::ReadFile | AccessFs::ReadDir))
        .map_err(|_| io::Error::last_os_error())
}

fn expand_all(roots: &[PathBuf], holes: &[Hole]) -> Vec<PathBuf> {
    // Dedup: essentials or overlapping roots can expand to the same path.
    let mut seen = BTreeSet::new();
    let mut out = Vec::new();
    for root in roots {
        for p in expand(root, holes) {
            if seen.insert(p.clone()) {
                out.push(p);
            }
        }
    }
    out
}

/// A grant pattern's root directory. Subtree `/a/**` and literal `/a` both root at `/a`; Landlock
/// governs the path and everything beneath it either way.
fn root_of(p: &PathPattern) -> PathBuf {
    p.base().to_path_buf()
}

/// Directory-only access rights (`ReadDir`, `MakeReg`, ...) are rejected when applied to a regular
/// file, so a grant on a file must be masked down to the file-applicable subset.
fn file_applicable() -> BitFlags<AccessFs> {
    AccessFs::ReadFile | AccessFs::WriteFile | AccessFs::Execute | AccessFs::Truncate
}

fn add_path_rules(
    ruleset: RulesetCreated,
    paths: &[PathBuf],
    access: BitFlags<AccessFs>,
) -> Result<RulesetCreated, ConfineError> {
    let mut ruleset = ruleset;
    for path in paths {
        // A grant path that does not exist is the one allowed softness (docs/linux-backend.md): skip
        // it rather than fail. Anything else (the fd opened but rejected) is a real error.
        let fd = match PathFd::new(path) {
            Ok(fd) => fd,
            Err(_) => continue,
        };
        // A file cannot carry directory-only rights; a directory carries the full set.
        let effective = if path.is_dir() {
            access
        } else {
            access & file_applicable()
        };
        if effective.is_empty() {
            continue;
        }
        ruleset = ruleset
            .add_rule(PathBeneath::new(fd, effective))
            .map_err(|e| fail(format!("landlock add rule for {}: {e}", path.display())))?;
    }
    Ok(ruleset)
}
