//! The isolation tier (FW-ISO10, FEP-5 §3.3): user, PID, mount and UTS namespaces for `processes`,
//! an IPC namespace for `ipc`, created before Landlock and seccomp are installed.
//!
//! The namespaces cannot be created in the `formwork` process (a multi-threaded process cannot
//! `unshare(CLONE_NEWUSER)`), nor in a `pre_exec` closure (a new PID namespace needs a further
//! fork, and Landlock's rules must be built after the fresh `/proc` and tmpfs are mounted, which
//! allocates). So the spawn runs the `formwork` binary itself as a single-threaded *stage*, marked
//! by [`STAGE_ENV`] naming an inherited descriptor that carries the [`StageSpec`]:
//!
//! 1. the stage unshares the namespaces and maps its own uid and gid;
//! 2. under `processes` it forks a minimal init, PID 1 of the new namespace, which mounts a fresh
//!    `/proc` and a tmpfs over the session temp directory, then forks the workload's process;
//! 3. that process builds and applies the ordinary Landlock + seccomp plan (the baseline then
//!    denies `CLONE_NEWUSER` and the mount family, FW-ISO8) and execs the workload.
//!
//! The stage and the init relay user-sent signals down and exit with the workload's status, so
//! `formwork` sees the workload's exit code (FW-XR10). A setup failure exits 125 with one
//! `formwork:` line (FW-XR11); nothing runs weaker than asked (FW-INV6).

use std::convert::Infallible;
use std::ffi::{CStr, CString};
use std::fs::File;
use std::io::{self, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::Command;

use formwork_blueprint::IsolateMember;
use formwork_compile::LinuxPolicy;
use serde::{Deserialize, Serialize};

use super::supervise;
use crate::ConfineError;

/// Set on the stage process only; names the descriptor holding the JSON [`StageSpec`].
pub const STAGE_ENV: &str = "FORMWORK_ISOLATE_STAGE";

/// FW-XR11: a Formwork failure after the workload was requested.
const SETUP_FAILED: i32 = 125;

#[derive(Serialize, Deserialize)]
struct StageSpec {
    policy: LinuxPolicy,
    argv: Vec<String>,
    /// The session temp directory, mounted over with a tmpfs under `processes` (FW-TRA10).
    private_tmp: Option<PathBuf>,
    /// The child end of the supervisor handoff, when the policy is supervised (FW-EGR7).
    handoff: Option<RawFd>,
}

/// Parent side: turn `command` -- already `Command::new("/proc/self/exe")` with the workload's
/// environment applied -- into the isolation stage for `argv`.
pub fn configure(
    command: &mut Command,
    argv: &[String],
    policy: &LinuxPolicy,
    private_tmp: Option<&Path>,
) -> Result<Option<supervise::Pending>, ConfineError> {
    if argv.is_empty() {
        return Err(ConfineError::MechanismFailed(
            "no command to run in the isolation tier".into(),
        ));
    }
    let (handoff, pending) = if policy.seccomp.supervise_connect {
        let (plan, pending) = supervise::prepare()?;
        (Some(plan.child_end()), Some(pending))
    } else {
        (None, None)
    };
    let spec = StageSpec {
        policy: policy.clone(),
        argv: argv.to_vec(),
        private_tmp: private_tmp.map(Path::to_path_buf),
        handoff,
    };
    let json = serde_json::to_vec(&spec)
        .map_err(|e| ConfineError::MechanismFailed(format!("isolation stage spec: {e}")))?;
    let spec_fd = memfd_with(&json)?;
    command.env(STAGE_ENV, spec_fd.as_raw_fd().to_string());
    // The command owns the spec until it is dropped, after the spawn; the handoff is held open
    // by `pending`.
    crate::inherit_fd(command, spec_fd);
    if let Some(fd) = handoff {
        crate::inherit_fd(command, fd);
    }
    Ok(pending)
}

fn memfd_with(bytes: &[u8]) -> Result<OwnedFd, ConfineError> {
    // SAFETY: memfd_create with a valid name; the result is checked and owned.
    let fd = unsafe { libc::memfd_create(c"formwork-isolate-spec".as_ptr(), libc::MFD_CLOEXEC) };
    if fd < 0 {
        return Err(io::Error::last_os_error().into());
    }
    // SAFETY: a fresh descriptor this function owns.
    let owned = unsafe { OwnedFd::from_raw_fd(fd) };
    let mut file = File::from(owned);
    file.write_all(bytes)?;
    // SAFETY: rewinding a descriptor we own.
    if unsafe { libc::lseek(file.as_raw_fd(), 0, libc::SEEK_SET) } < 0 {
        return Err(io::Error::last_os_error().into());
    }
    Ok(OwnedFd::from(file))
}

/// Stage side: call first thing in `main`, before any thread starts. Returns `None` in every
/// process but the stage; in the stage it never returns on success (the workload is exec'd) and
/// returns the exit code on failure, after one `formwork:` line on stderr.
pub fn stage_if_requested() -> Option<i32> {
    let raw = std::env::var_os(STAGE_ENV)?;
    // Single-threaded here, so mutating the environment is sound; the workload never sees it.
    std::env::remove_var(STAGE_ENV);
    let Err((code, message)) = stage(&raw.to_string_lossy());
    eprintln!("formwork: isolation tier: {message}");
    Some(code)
}

type StageError = (i32, String);

fn setup<E: std::fmt::Display>(what: &str) -> impl FnOnce(E) -> StageError + '_ {
    move |e| (SETUP_FAILED, format!("{what}: {e}"))
}

fn stage(raw_fd: &str) -> Result<Infallible, StageError> {
    let fd: RawFd = raw_fd
        .parse()
        .map_err(setup("the stage descriptor is malformed"))?;
    // SAFETY: the parent handed this descriptor to the stage and nothing else holds it here.
    let file = unsafe { File::from_raw_fd(fd) };
    let spec: StageSpec = serde_json::from_reader(file).map_err(setup("reading the stage spec"))?;
    let processes = spec.policy.isolate.contains(&IsolateMember::Processes);
    let ipc = spec.policy.isolate.contains(&IsolateMember::Ipc);

    // SAFETY: getuid/getgid have no failure modes.
    let (uid, gid) = unsafe { (libc::getuid(), libc::getgid()) };
    let mut flags = libc::CLONE_NEWUSER;
    if processes {
        flags |= libc::CLONE_NEWPID | libc::CLONE_NEWNS | libc::CLONE_NEWUTS;
    }
    if ipc {
        flags |= libc::CLONE_NEWIPC;
    }
    // SAFETY: unshare with scalar flags; this process is single-threaded.
    if unsafe { libc::unshare(flags) } != 0 {
        return Err(setup("creating the namespaces")(io::Error::last_os_error()));
    }
    std::fs::write("/proc/self/setgroups", "deny").map_err(setup("writing setgroups"))?;
    std::fs::write("/proc/self/uid_map", format!("{uid} {uid} 1\n"))
        .map_err(setup("mapping the uid"))?;
    std::fs::write("/proc/self/gid_map", format!("{gid} {gid} 1\n"))
        .map_err(setup("mapping the gid"))?;

    if processes {
        let original = block_relayed_signals();
        // SAFETY: fork in a single-threaded process.
        let init = unsafe { libc::fork() };
        if init < 0 {
            return Err(setup("forking the session init")(io::Error::last_os_error()));
        }
        if init > 0 {
            close_extra_fds();
            std::process::exit(relay(init, false));
        }
        // PID 1 of the new namespace. It dies with the stage, taking the namespace with it.
        // SAFETY: prctl with scalar arguments.
        unsafe { libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL, 0, 0, 0) };
        mount_session_filesystems(spec.private_tmp.as_deref())?;
        // SAFETY: fork in a single-threaded process.
        let workload = unsafe { libc::fork() };
        if workload < 0 {
            return Err(setup("forking the workload")(io::Error::last_os_error()));
        }
        if workload > 0 {
            close_extra_fds();
            std::process::exit(relay(workload, true));
        }
        restore_signals(&original);
    }
    confine_and_exec(spec)
}

fn mount_session_filesystems(private_tmp: Option<&Path>) -> Result<(), StageError> {
    mount(
        None,
        c"/",
        None,
        libc::MS_REC | libc::MS_PRIVATE,
        None,
        "making the mount namespace private",
    )?;
    mount(
        Some(c"proc"),
        c"/proc",
        Some(c"proc"),
        libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC,
        None,
        "mounting a fresh /proc",
    )?;
    if let Some(tmp) = private_tmp {
        let target = CString::new(tmp.as_os_str().as_encoded_bytes())
            .map_err(setup("the session temp directory"))?;
        mount(
            Some(c"tmpfs"),
            &target,
            Some(c"tmpfs"),
            libc::MS_NOSUID | libc::MS_NODEV,
            Some(c"mode=0700"),
            "mounting the session tmpfs",
        )?;
    }
    Ok(())
}

/// mount(2), its failure named by `what`.
fn mount(
    source: Option<&CStr>,
    target: &CStr,
    fstype: Option<&CStr>,
    flags: libc::c_ulong,
    data: Option<&CStr>,
    what: &str,
) -> Result<(), StageError> {
    let ptr = |s: Option<&CStr>| s.map_or(std::ptr::null(), CStr::as_ptr);
    // SAFETY: mount(2) with NUL-terminated strings or NULLs that outlive the call.
    if unsafe {
        libc::mount(
            ptr(source),
            target.as_ptr(),
            ptr(fstype),
            flags,
            ptr(data).cast(),
        )
    } != 0
    {
        return Err(setup(what)(io::Error::last_os_error()));
    }
    Ok(())
}

fn confine_and_exec(spec: StageSpec) -> Result<Infallible, StageError> {
    let mut plan = super::build(&spec.policy).map_err(setup("building the confinement plan"))?;
    if let Some(fd) = spec.handoff {
        plan.supervise = Some(supervise::Plan::from_handoff(fd));
    }
    super::apply(&mut plan).map_err(setup("applying confinement"))?;
    let err = Command::new(&spec.argv[0]).args(&spec.argv[1..]).exec();
    let code = if err.kind() == io::ErrorKind::NotFound {
        127
    } else {
        126
    };
    Err((code, format!("running {}: {err}", spec.argv[0])))
}

/// Signals the stage and the init pass on to their child when a process sent them. Kernel-sent
/// ones (a terminal's ^C reaches the whole foreground process group already) are not relayed, so
/// the workload sees each once.
const RELAYED: &[libc::c_int] = &[
    libc::SIGHUP,
    libc::SIGINT,
    libc::SIGQUIT,
    libc::SIGTERM,
    libc::SIGUSR1,
    libc::SIGUSR2,
    libc::SIGALRM,
    libc::SIGWINCH,
];

fn relayed_set() -> libc::sigset_t {
    // SAFETY: sigemptyset/sigaddset initialize and fill a local set.
    unsafe {
        let mut set: libc::sigset_t = std::mem::zeroed();
        libc::sigemptyset(&mut set);
        for s in RELAYED {
            libc::sigaddset(&mut set, *s);
        }
        libc::sigaddset(&mut set, libc::SIGCHLD);
        set
    }
}

fn block_relayed_signals() -> libc::sigset_t {
    let set = relayed_set();
    // SAFETY: sigprocmask with valid sets.
    unsafe {
        let mut old: libc::sigset_t = std::mem::zeroed();
        libc::sigprocmask(libc::SIG_BLOCK, &set, &mut old);
        old
    }
}

fn restore_signals(original: &libc::sigset_t) {
    // SAFETY: sigprocmask with a set saved earlier.
    unsafe { libc::sigprocmask(libc::SIG_SETMASK, original, std::ptr::null_mut()) };
}

/// Wait for `child`, relaying user-sent signals to it; return its status as an exit code
/// (128 + signal for a signal death). As PID 1 (`reap_all`), also reap every orphan.
fn relay(child: libc::pid_t, reap_all: bool) -> i32 {
    let set = relayed_set();
    loop {
        // SAFETY: a zeroed siginfo is a valid output buffer for sigwaitinfo.
        let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
        // SAFETY: waits on the blocked set.
        let sig = unsafe { libc::sigwaitinfo(&set, &mut info) };
        if sig < 0 {
            continue;
        }
        if sig == libc::SIGCHLD {
            loop {
                let mut status = 0;
                let target = if reap_all { -1 } else { child };
                // SAFETY: non-blocking wait on our own children.
                let pid = unsafe { libc::waitpid(target, &mut status, libc::WNOHANG) };
                if pid <= 0 {
                    break;
                }
                if pid == child {
                    return exit_code(status);
                }
            }
        } else if info.si_code <= 0 {
            // SAFETY: kill with a scalar pid and signal.
            unsafe { libc::kill(child, sig) };
        }
    }
}

fn exit_code(status: libc::c_int) -> i32 {
    if libc::WIFEXITED(status) {
        libc::WEXITSTATUS(status)
    } else if libc::WIFSIGNALED(status) {
        128 + libc::WTERMSIG(status)
    } else {
        SETUP_FAILED
    }
}

/// The stage and the init only wait: they keep stdio (for the one failure line) and drop every
/// other descriptor, so the workload holds the only copy of the supervisor handoff and of any
/// pipe it was given.
fn close_extra_fds() {
    // SAFETY: close_range over descriptors this process no longer needs.
    let rc = unsafe { libc::syscall(libc::SYS_close_range, 3u32, u32::MAX, 0u32) };
    if rc != 0 {
        for fd in 3..1024 {
            // SAFETY: closing a possibly-unopened descriptor is harmless.
            unsafe { libc::close(fd) };
        }
    }
}
