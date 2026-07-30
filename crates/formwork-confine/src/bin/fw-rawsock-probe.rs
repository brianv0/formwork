//! Test-support binary: the raw-socket probe (FW-INV3). A confined process has no network path
//! except the injected gateway fd, so a direct raw socket -- a classic way to hand-roll egress and
//! sidestep connect() -- must fail closed. Under net-deny the seccomp inet-family filter rejects
//! socket(AF_INET, SOCK_RAW) at creation. Reports purely via exit code:
//!   0  raw socket creation was denied (fail-closed, expected)
//!   4  a raw socket was created -- a direct egress path (LEAK/FAIL)
//!
//! Deliberately libc-only so it starts wherever `/bin/cat` does under Closed-mode essentials.

#[cfg(target_os = "linux")]
fn main() {
    // SAFETY: socket() takes scalar args; on the (unexpected) success path we own and close the fd.
    let raw = unsafe { libc::socket(libc::AF_INET, libc::SOCK_RAW, libc::IPPROTO_ICMP) };
    if raw >= 0 {
        // SAFETY: closing an fd we just created and own.
        unsafe { libc::close(raw) };
        std::process::exit(4);
    }
    std::process::exit(0);
}

#[cfg(not(target_os = "linux"))]
fn main() {}
