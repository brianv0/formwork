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
}

impl HostFacilities {
    pub fn is_empty(&self) -> bool {
        self == &HostFacilities::default()
    }
}

impl HostProfile {
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

    /// Can this process create a user namespace? Probed by doing it in a short-lived forked
    /// child, so the probe never changes this process's own namespaces. The child only calls
    /// `unshare` and `_exit`, both async-signal-safe.
    fn user_namespaces() -> bool {
        // SAFETY: fork in a possibly multi-threaded process; the child calls only
        // async-signal-safe functions (unshare, _exit) before exiting.
        let pid = unsafe { libc::fork() };
        if pid < 0 {
            return false;
        }
        if pid == 0 {
            let rc = unsafe { libc::unshare(libc::CLONE_NEWUSER) };
            unsafe { libc::_exit(if rc == 0 { 0 } else { 1 }) };
        }
        let mut status = 0;
        // SAFETY: waiting on the child we just forked.
        if unsafe { libc::waitpid(pid, &mut status, 0) } != pid {
            return false;
        }
        libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0
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
            .map(|scope| scope <= 1)
            .unwrap_or(true);
        getfd && yama_ok
    }

    fn is_socket(path: &Path) -> bool {
        use std::os::unix::fs::FileTypeExt;
        std::fs::metadata(path)
            .map(|m| m.file_type().is_socket())
            .unwrap_or(false)
    }

    /// `$XDG_RUNTIME_DIR`, falling back to `/run/user/<uid>` (a login session sets both; a CI
    /// job sets neither, and the fallback then does not exist).
    fn runtime_dir() -> Option<PathBuf> {
        let dir = std::env::var_os("XDG_RUNTIME_DIR")
            .map(PathBuf::from)
            // SAFETY: getuid is always successful and has no memory effects.
            .unwrap_or_else(|| PathBuf::from(format!("/run/user/{}", unsafe { libc::getuid() })));
        dir.is_dir().then_some(dir)
    }

    fn session_bus(runtime: Option<&Path>) -> Option<String> {
        // `unix:path=/run/user/1000/bus[,guid=…]` is the common shape; an abstract address has
        // no path and is scoped by Landlock ABI 6, so it is not a pathname-socket facility.
        if let Some(addr) = std::env::var_os("DBUS_SESSION_BUS_ADDRESS") {
            let addr = addr.to_string_lossy().into_owned();
            for part in addr.split(';') {
                if let Some(rest) = part.strip_prefix("unix:") {
                    for kv in rest.split(',') {
                        if let Some(path) = kv.strip_prefix("path=") {
                            if is_socket(Path::new(path)) {
                                return Some(path.to_string());
                            }
                        }
                    }
                }
            }
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
        let mut display = Vec::new();
        if let Ok(entries) = std::fs::read_dir("/tmp/.X11-unix") {
            let mut found: Vec<String> = entries
                .flatten()
                .map(|e| e.path())
                .filter(|p| is_socket(p))
                .map(|p| p.display().to_string())
                .collect();
            found.sort();
            display.extend(found);
        }
        if let Some(rt) = rt {
            if let Ok(entries) = std::fs::read_dir(rt) {
                let mut found: Vec<String> = entries
                    .flatten()
                    .map(|e| e.path())
                    .filter(|p| {
                        p.file_name()
                            .and_then(|n| n.to_str())
                            .map(|n| n.starts_with("wayland-") && !n.ends_with(".lock"))
                            .unwrap_or(false)
                            && is_socket(p)
                    })
                    .map(|p| p.display().to_string())
                    .collect();
                found.sort();
                display.extend(found);
            }
        }
        HostFacilities {
            session_bus: session_bus(rt),
            user_manager: in_runtime("systemd/private"),
            display,
            keyring: in_runtime("keyring/control").or_else(|| in_runtime("keyring/ssh")),
            audio: in_runtime("pulse/native").or_else(|| in_runtime("pipewire-0")),
            video_device: first_device("video"),
            gui_session: false,
            pid_ns_nested: pid_ns_nested(),
        }
    }

    fn first_device(prefix: &str) -> Option<String> {
        let mut found: Vec<String> = std::fs::read_dir("/dev")
            .ok()?
            .flatten()
            .filter(|e| e.file_name().to_string_lossy().starts_with(prefix))
            .map(|e| e.path().display().to_string())
            .collect();
        found.sort();
        found.into_iter().next()
    }

    /// A multi-field `NSpid` line means this process sits in a nested PID namespace.
    fn pid_ns_nested() -> bool {
        std::fs::read_to_string("/proc/self/status")
            .ok()
            .and_then(|s| {
                s.lines()
                    .find(|l| l.starts_with("NSpid:"))
                    .map(|l| l.split_whitespace().count() > 2)
            })
            .unwrap_or(false)
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
