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
    /// For the report only; not load-bearing.
    #[serde(default)]
    pub os_version: String,
}

impl HostProfile {
    pub fn synthetic_linux(landlock_abi: Option<u32>) -> Self {
        HostProfile {
            os: Os::Linux,
            landlock_abi,
            seccomp: true,
            seatbelt: false,
            os_version: "synthetic-linux".to_string(),
        }
    }

    pub fn synthetic_macos() -> Self {
        HostProfile {
            os: Os::MacOs,
            landlock_abi: None,
            seccomp: false,
            seatbelt: true,
            os_version: "synthetic-macos".to_string(),
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
        }
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use super::{HostProfile, Os};

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
        }
    }
}

#[cfg(target_os = "macos")]
mod macos {
    use super::{HostProfile, Os};

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
        }
    }
}
