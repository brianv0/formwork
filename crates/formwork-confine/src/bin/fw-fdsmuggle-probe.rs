//! Test-support binary: the fd-smuggling probe (FW-ADV-005). A confined stdio backend must not be
//! able to manufacture a new egress socket or hand off a broader capability -- only the seam mints
//! egress fds. Run inside net-deny confinement, this probe proves the backend cannot create an inet
//! socket (the raw material of a smuggled egress fd), while the seam's own AF_UNIX socketpair
//! transport stays available, so the deny is scoped to egress, not the seam (FW-XR7). Reports purely
//! via exit code:
//!   0  inet socket() denied AND the AF_UNIX socketpair transport still works (PASS)
//!   4  an inet egress socket was manufactured -- a broader fd the backend could smuggle (FAIL)
//!   5  AF_UNIX socketpair was denied -- the seam transport is broken (unexpected)
//!
//! Deliberately libc-only so it starts wherever `/bin/cat` does under Closed-mode essentials.

#[cfg(target_os = "linux")]
fn main() {
    // Attempt to create a new outbound (inet) socket -- the fd a smuggler would pass on to widen
    // access. Under net-deny the seccomp inet-family filter rejects socket(AF_INET) at creation.
    // SAFETY: socket() takes scalar args; on the (unexpected) success path we own and close the fd.
    let inet = unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0) };
    if inet >= 0 {
        // SAFETY: closing an fd we just created and own.
        unsafe { libc::close(inet) };
        std::process::exit(4); // manufactured an egress fd -- a smuggling primitive LEAKED
    }

    // The seam's transport is an AF_UNIX socketpair; it must remain available (the deny is scoped to
    // egress families, never AF_UNIX). A socketpair is not egress -- it connects only to its peer.
    let mut sv = [0i32; 2];
    // SAFETY: socketpair writes two fds into the owned array on success.
    let rc = unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, sv.as_mut_ptr()) };
    if rc != 0 {
        std::process::exit(5);
    }
    // SAFETY: closing the two fds socketpair just handed us.
    unsafe {
        libc::close(sv[0]);
        libc::close(sv[1]);
    }
    std::process::exit(0);
}

#[cfg(not(target_os = "linux"))]
fn main() {}
