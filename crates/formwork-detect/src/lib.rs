//! `HostProfile`: the single impure input to compilation. `detect()` probes the running kernel;
//! profiles can also be synthesized (a Linux profile on a Mac) for cross-platform dry-run. The
//! compiler only reads the value it is handed, which is what keeps `compile()` pure.

use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Os {
    Linux,
    #[serde(rename = "macos")]
    MacOs,
}

/// Serializable so it can be captured on one machine (`formwork detect > host.json`) and fed to
/// `compile --host host.json` on another.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct HostProfile {
    pub os: Os,
    /// Landlock ABI version semantics: v1 = fs; v4 = + TCP-port net; v6 = + abstract-unix-socket &
    /// signal scoping.
    #[serde(default)]
    pub landlock_abi: Option<u32>,
    #[serde(default)]
    pub seccomp: bool,
    #[serde(default)]
    pub seatbelt: bool,
    /// For the report only; nothing depends on it.
    #[serde(default)]
    pub os_version: String,
    /// Whether an unprivileged process can create a user namespace here -- what the Linux
    /// isolation tier needs (FW-ISO10). `false` on macOS and wherever policy forbids it (an
    /// AppArmor-restricted Ubuntu 24.04, `user.max_user_namespaces = 0`).
    #[serde(default)]
    pub user_namespaces: bool,
    /// Whether the spawning process can service a confined process's `connect()` (FW-EGR7):
    /// seccomp user notification, `pidfd_getfd`, and a Yama `ptrace_scope` that lets an ancestor
    /// reach its descendants' descriptors. Linux only.
    #[serde(default)]
    pub connect_supervision: bool,
    /// The host facilities that make host-service channels reachable, and PID-namespace nesting
    /// (FW-FID10). Recorded here so `compile` stays pure (FW-CAP5).
    #[serde(default, skip_serializing_if = "HostFacilities::is_empty")]
    pub facilities: HostFacilities,
}

/// What `detect` found running on this host that a confined process could ask to act for it
/// (FW-FID10). Each entry is the socket or service found, `None` when absent. Container and CI
/// hosts usually run no user session, which is why every channel line in the report says whether
/// the facility is present on this host.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct HostFacilities {
    /// The D-Bus session bus socket (Linux).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_bus: Option<String>,
    /// The `systemd --user` private socket (Linux).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user_manager: Option<String>,
    /// Display-server sockets: X11 under `/tmp/.X11-unix`, Wayland under `$XDG_RUNTIME_DIR`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub display: Vec<String>,
    /// A keyring service socket under `$XDG_RUNTIME_DIR` (Linux).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub keyring: Option<String>,
    /// An audio server socket (PulseAudio/PipeWire) -- the Linux `microphone` path besides
    /// `/dev/snd`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audio: Option<String>,
    /// A video capture device node (`/dev/video*`), the Linux `camera` path (Linux).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub video_device: Option<String>,
    /// macOS: whether a GUI login session owns this process (LaunchServices, the pasteboard and
    /// WindowServer are reachable only then).
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub gui_session: bool,
    /// Linux: this process already runs inside a nested PID namespace (a multi-field `NSpid`),
    /// so other host processes are not visible to it regardless of the blueprint.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub pid_ns_nested: bool,
    /// Linux: this process holds `CAP_SYS_ADMIN`, `CAP_PERFMON` or `CAP_SYS_PTRACE`, which a
    /// confined child keeps. Landlock refuses a confined process ptrace-class access to processes
    /// outside its domain, `/proc/<pid>/environ` included; a process with `CAP_SYS_ADMIN` or
    /// `CAP_PERFMON` gets past that refusal (observed on 6.18), and `CAP_SYS_PTRACE` is counted
    /// too, as the capability that means "may inspect any process" (FW-ISO16).
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub ptrace_privileged: bool,
}

impl HostFacilities {
    pub fn is_empty(&self) -> bool {
        self == &HostFacilities::default()
    }
}

/// What the Linux `connect()` supervisor needs from the host (FW-EGR7), for messages naming why a
/// host cannot carry it.
pub const CONNECT_SUPERVISION_NEEDS: &str =
    "seccomp user notification, pidfd_getfd (Linux 5.6+), and Yama ptrace_scope 0 or 1";

impl HostProfile {
    /// Can the Linux `connect()` supervisor carry host-scoped egress here (FW-EGR7)?
    pub fn can_supervise_connect(&self) -> bool {
        self.os == Os::Linux && self.seccomp && self.connect_supervision
    }

    pub fn synthetic_linux(landlock_abi: Option<u32>) -> Self {
        HostProfile {
            os: Os::Linux,
            landlock_abi,
            seccomp: true,
            seatbelt: false,
            os_version: "synthetic-linux".to_string(),
            user_namespaces: true,
            connect_supervision: true,
            facilities: HostFacilities::default(),
        }
    }

    pub fn synthetic_macos() -> Self {
        HostProfile {
            os: Os::MacOs,
            landlock_abi: None,
            seccomp: false,
            seatbelt: true,
            os_version: "synthetic-macos".to_string(),
            user_namespaces: false,
            connect_supervision: false,
            facilities: HostFacilities::default(),
        }
    }
}

/// The only function that inspects the live kernel; everything downstream is a pure function of the
/// value it returns.
pub fn detect() -> HostProfile {
    #[cfg(target_os = "linux")]
    {
        linux::detect()
    }
    #[cfg(target_os = "macos")]
    {
        macos::detect()
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        HostProfile {
            os: Os::Linux,
            landlock_abi: None,
            seccomp: false,
            seatbelt: false,
            os_version: "unsupported".to_string(),
            user_namespaces: false,
            connect_supervision: false,
            facilities: HostFacilities::default(),
        }
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use std::path::{Path, PathBuf};

    use super::{HostFacilities, HostProfile, Os};

    /// Can this process carry the isolation tier (FW-ISO10)? Probed by doing it in short-lived
    /// forked children, so the probe never changes this process's own namespaces: create the user,
    /// PID, mount, IPC and UTS namespaces, map the uid and gid, and mount a fresh `/proc` from the
    /// new namespace's first process. An AppArmor-restricted Ubuntu 24.04 fails the first step; a
    /// container whose `/proc` is partly masked fails the last. The children call only
    /// async-signal-safe functions over strings built before the fork.
    fn user_namespaces() -> bool {
        use std::ffi::CStr;
        // SAFETY: getuid/getgid have no failure modes.
        let (uid, gid) = unsafe { (libc::getuid(), libc::getgid()) };
        let uid_line = format!("{uid} {uid} 1\n");
        let gid_line = format!("{gid} {gid} 1\n");

        // SAFETY: async-signal-safe open/write/close only.
        let write_file = |path: &CStr, bytes: &[u8]| -> bool {
            unsafe {
                let fd = libc::open(path.as_ptr(), libc::O_WRONLY | libc::O_CLOEXEC);
                if fd < 0 {
                    return false;
                }
                let n = libc::write(fd, bytes.as_ptr().cast(), bytes.len());
                libc::close(fd);
                n == bytes.len() as isize
            }
        };
        // SAFETY: waitpid on our own child.
        let wait = |pid: libc::pid_t| -> i32 {
            let mut status = 0;
            if unsafe { libc::waitpid(pid, &mut status, 0) } != pid || !libc::WIFEXITED(status) {
                return -1;
            }
            libc::WEXITSTATUS(status)
        };

        // SAFETY: fork in a possibly multi-threaded process; the children call only
        // async-signal-safe functions (unshare, open, write, close, fork, mount, waitpid, _exit).
        let pid = unsafe { libc::fork() };
        if pid < 0 {
            return false;
        }
        if pid == 0 {
            unsafe {
                let flags = libc::CLONE_NEWUSER
                    | libc::CLONE_NEWPID
                    | libc::CLONE_NEWNS
                    | libc::CLONE_NEWIPC
                    | libc::CLONE_NEWUTS;
                if libc::unshare(flags) != 0 {
                    libc::_exit(1);
                }
                if !write_file(c"/proc/self/setgroups", b"deny")
                    || !write_file(c"/proc/self/uid_map", uid_line.as_bytes())
                    || !write_file(c"/proc/self/gid_map", gid_line.as_bytes())
                {
                    libc::_exit(2);
                }
                let init = libc::fork();
                if init < 0 {
                    libc::_exit(3);
                }
                if init == 0 {
                    let none = std::ptr::null::<libc::c_char>();
                    let private = libc::mount(
                        none,
                        c"/".as_ptr(),
                        none,
                        libc::MS_REC | libc::MS_PRIVATE,
                        std::ptr::null(),
                    ) == 0;
                    let procfs = private
                        && libc::mount(
                            c"proc".as_ptr(),
                            c"/proc".as_ptr(),
                            c"proc".as_ptr(),
                            libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC,
                            std::ptr::null(),
                        ) == 0;
                    libc::_exit(if procfs { 0 } else { 4 });
                }
                libc::_exit(wait(init));
            }
        }
        wait(pid) == 0
    }

    /// The three facilities the `connect()` supervisor needs (FW-EGR7), each probed for real:
    /// the notification-size query succeeds only where user notification exists (5.0+);
    /// `pidfd_getfd` on this process's own descriptor succeeds only where it exists (5.6+) and is
    /// not blocked; and Yama scope 2 or 3 forbids an ancestor's access to its descendants.
    fn connect_supervision() -> bool {
        let mut sizes = [0u16; 3];
        // SAFETY: SECCOMP_GET_NOTIF_SIZES writes three u16 into the buffer; no other effect.
        let notif = unsafe {
            libc::syscall(
                libc::SYS_seccomp,
                libc::SECCOMP_GET_NOTIF_SIZES,
                0,
                sizes.as_mut_ptr(),
            )
        } == 0;
        if !notif {
            return false;
        }
        // SAFETY: pidfd_open on our own pid, then pidfd_getfd of our stderr; both descriptors
        // are closed before returning.
        let getfd = unsafe {
            let pidfd = libc::syscall(libc::SYS_pidfd_open, libc::getpid(), 0);
            if pidfd < 0 {
                false
            } else {
                let dup = libc::syscall(libc::SYS_pidfd_getfd, pidfd as i32, 2, 0);
                if dup >= 0 {
                    libc::close(dup as i32);
                }
                libc::close(pidfd as i32);
                dup >= 0
            }
        };
        let yama_ok = std::fs::read_to_string("/proc/sys/kernel/yama/ptrace_scope")
            .ok()
            .and_then(|s| s.trim().parse::<u32>().ok())
            .is_none_or(|scope| scope <= 1);
        getfd && yama_ok
    }

    fn is_socket(path: &Path) -> bool {
        use std::os::unix::fs::FileTypeExt;
        std::fs::metadata(path).is_ok_and(|m| m.file_type().is_socket())
    }

    /// `$XDG_RUNTIME_DIR`, falling back to `/run/user/<uid>` (a login session sets both; a CI
    /// job sets neither, and the fallback then does not exist).
    fn runtime_dir() -> Option<PathBuf> {
        let dir = std::env::var_os("XDG_RUNTIME_DIR").map_or_else(
            || PathBuf::from(format!("/run/user/{}", unsafe { libc::getuid() })),
            PathBuf::from,
        );
        dir.is_dir().then_some(dir)
    }

    fn session_bus(runtime: Option<&Path>) -> Option<String> {
        // `unix:path=/run/user/1000/bus[,guid=…]` is the common shape; an abstract address has
        // no path and is scoped by Landlock ABI 6, so it is not a pathname-socket facility.
        let from_env = std::env::var_os("DBUS_SESSION_BUS_ADDRESS").and_then(|addr| {
            addr.to_string_lossy()
                .split(';')
                .filter_map(|part| part.strip_prefix("unix:"))
                .flat_map(|rest| rest.split(','))
                .filter_map(|kv| kv.strip_prefix("path="))
                .find(|path| is_socket(Path::new(path)))
                .map(str::to_string)
        });
        if from_env.is_some() {
            return from_env;
        }
        let bus = runtime?.join("bus");
        is_socket(&bus).then(|| bus.display().to_string())
    }

    fn facilities() -> HostFacilities {
        let runtime = runtime_dir();
        let rt = runtime.as_deref();
        let in_runtime = |rel: &str| -> Option<String> {
            let p = rt?.join(rel);
            is_socket(&p).then(|| p.display().to_string())
        };
        let mut display = sockets_in(Path::new("/tmp/.X11-unix"), |_| true);
        if let Some(rt) = rt {
            display.extend(sockets_in(rt, |n| {
                n.starts_with("wayland-") && !n.ends_with(".lock")
            }));
        }
        let status = std::fs::read_to_string("/proc/self/status").unwrap_or_default();
        HostFacilities {
            session_bus: session_bus(rt),
            user_manager: in_runtime("systemd/private"),
            display,
            // Only the control socket: `keyring/ssh` is an SSH agent, an ssh credential that
            // lifting `os-keyring` must not admit.
            keyring: in_runtime("keyring/control"),
            audio: in_runtime("pulse/native").or_else(|| in_runtime("pipewire-0")),
            video_device: first_device("video"),
            gui_session: false,
            pid_ns_nested: pid_ns_nested(&status),
            ptrace_privileged: ptrace_privileged(&status),
        }
    }

    /// The sockets directly in `dir` whose names pass `keep`, sorted.
    fn sockets_in(dir: &Path, keep: impl Fn(&str) -> bool) -> Vec<String> {
        let Ok(entries) = std::fs::read_dir(dir) else {
            return Vec::new();
        };
        let mut found: Vec<String> = entries
            .flatten()
            .map(|e| e.path())
            .filter(|p| p.file_name().and_then(|n| n.to_str()).is_some_and(&keep) && is_socket(p))
            .map(|p| p.display().to_string())
            .collect();
        found.sort();
        found
    }

    /// `CAP_SYS_PTRACE` (19), `CAP_SYS_ADMIN` (21) or `CAP_PERFMON` (38) in the effective set of
    /// `/proc/self/status`; assumed held when unreadable.
    fn ptrace_privileged(status: &str) -> bool {
        const MASK: u64 = (1 << 19) | (1 << 21) | (1 << 38);
        status
            .lines()
            .find_map(|l| l.strip_prefix("CapEff:"))
            .and_then(|v| u64::from_str_radix(v.trim(), 16).ok())
            .is_none_or(|eff| eff & MASK != 0)
    }

    fn first_device(prefix: &str) -> Option<String> {
        std::fs::read_dir("/dev")
            .ok()?
            .flatten()
            .filter(|e| e.file_name().to_string_lossy().starts_with(prefix))
            .map(|e| e.path().display().to_string())
            .min()
    }

    /// A multi-field `NSpid` line in `/proc/self/status` means this process sits in a nested PID
    /// namespace.
    fn pid_ns_nested(status: &str) -> bool {
        status
            .lines()
            .find(|l| l.starts_with("NSpid:"))
            .is_some_and(|l| l.split_whitespace().count() > 2)
    }

    // ABI-version query: landlock_create_ruleset(NULL, 0, VERSION).
    const LANDLOCK_CREATE_RULESET_VERSION: u32 = 1 << 0;

    fn landlock_abi() -> Option<u32> {
        // SAFETY: the version query takes a null attr and size 0 by ABI contract; no side effects.
        let ret = unsafe {
            libc::syscall(
                libc::SYS_landlock_create_ruleset,
                std::ptr::null::<libc::c_void>(),
                0usize,
                LANDLOCK_CREATE_RULESET_VERSION,
            )
        };
        if ret > 0 {
            Some(ret as u32)
        } else {
            None // ENOSYS / EOPNOTSUPP (LSM off) / etc.
        }
    }

    fn seccomp_available() -> bool {
        // SAFETY: PR_GET_SECCOMP takes no arguments and has no side effects.
        unsafe { libc::prctl(libc::PR_GET_SECCOMP) >= 0 }
    }

    // `c_char` is `i8` on x86_64 but `u8` on aarch64, so `c as u8` is a genuine conversion on one
    // arch and an identity on the other; silence the arch-dependent unnecessary-cast lint.
    #[allow(clippy::unnecessary_cast)]
    fn kernel_version() -> String {
        // SAFETY: uname writes into a fully-owned zeroed struct.
        let mut uts: libc::utsname = unsafe { std::mem::zeroed() };
        if unsafe { libc::uname(&mut uts) } == 0 {
            let bytes: Vec<u8> = uts
                .release
                .iter()
                .take_while(|&&c| c != 0)
                .map(|&c| c as u8)
                .collect();
            String::from_utf8_lossy(&bytes).into_owned()
        } else {
            "linux-unknown".to_string()
        }
    }

    pub fn detect() -> HostProfile {
        HostProfile {
            os: Os::Linux,
            landlock_abi: landlock_abi(),
            seccomp: seccomp_available(),
            seatbelt: false,
            os_version: kernel_version(),
            user_namespaces: user_namespaces(),
            connect_supervision: connect_supervision(),
            facilities: facilities(),
        }
    }
}

#[cfg(target_os = "macos")]
mod macos {
    use super::{HostFacilities, HostProfile, Os};

    /// A GUI login session owns this process when the per-user bootstrap namespace is the Aqua
    /// session's. `launchctl managername` prints `Aqua` there and `Background`/`System` for a
    /// ssh or CI session, where LaunchServices and the pasteboard are not reachable.
    fn gui_session() -> bool {
        std::process::Command::new("/bin/launchctl")
            .arg("managername")
            .output()
            .map(|o| String::from_utf8_lossy(&o.stdout).trim() == "Aqua")
            .unwrap_or(false)
    }

    fn product_version() -> String {
        // Read `kern.osrelease` via the standard two-call sysctlbyname sizing pattern.
        // SAFETY: owned buffers; the length comes from the first (sizing) call.
        let name = c"kern.osrelease";
        let mut len: libc::size_t = 0;
        let ok = unsafe {
            libc::sysctlbyname(
                name.as_ptr(),
                std::ptr::null_mut(),
                &mut len,
                std::ptr::null_mut(),
                0,
            )
        };
        if ok != 0 || len == 0 {
            return "macos-unknown".to_string();
        }
        let mut buf = vec![0u8; len];
        let ok = unsafe {
            libc::sysctlbyname(
                name.as_ptr(),
                buf.as_mut_ptr() as *mut libc::c_void,
                &mut len,
                std::ptr::null_mut(),
                0,
            )
        };
        if ok != 0 {
            return "macos-unknown".to_string();
        }
        buf.truncate(len.saturating_sub(1));
        format!("darwin-{}", String::from_utf8_lossy(&buf))
    }

    pub fn detect() -> HostProfile {
        HostProfile {
            os: Os::MacOs,
            landlock_abi: None,
            seccomp: false,
            seatbelt: true,
            os_version: product_version(),
            user_namespaces: false,
            connect_supervision: false,
            facilities: HostFacilities {
                gui_session: gui_session(),
                ..HostFacilities::default()
            },
        }
    }
}
