//! Test-support binary: the x32 syscall-number probe (FW-E2E-205, kernel half). On x86_64 a
//! syscall number with bit 30 set selects the x32 table, where a kernel built with that ABI offers
//! every syscall under a number the baseline's per-number rules do not name (FW-ISO33). The probe
//! calls `getpid` under its x32 number and reports purely via exit code:
//!
//!   0  refused with EPERM -- the filter answered before the kernel dispatched (PASS)
//!   4  the call ran -- the x32 table is reachable (FAIL)
//!   8  another errno (ENOSYS on a kernel without the ABI: no filter answered first)
//!
//! Deliberately libc-only so it starts wherever `/bin/cat` does under Closed-mode essentials.

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn main() {
    // <asm/unistd_x32.h>
    const X32_SYSCALL_BIT: libc::c_long = 0x4000_0000;
    // SAFETY: getpid takes no arguments and has no effect.
    let rc = unsafe { libc::syscall(X32_SYSCALL_BIT | libc::SYS_getpid) };
    let refused = std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM);
    std::process::exit(match (rc, refused) {
        (0.., _) => 4,
        (_, true) => 0,
        _ => 8,
    });
}

#[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
fn main() {}
