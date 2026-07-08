//! Test-support binary: probes whether an ioctl on a *granted* device node is permitted. Formwork's
//! safe device nodes (and the inherited controlling terminal) must stay fully usable -- including
//! their ioctls (winsize, termios), or interactive agents cannot set raw mode. So an ioctl on a
//! granted device must NOT be denied by the sandbox. Reports purely via exit code:
//!   0  the ioctl reached the device (returned, incl. ENOTTY) -- device ioctls work
//!   7  ioctl -> EPERM/EACCES -- the sandbox denied the device ioctl (a transparency break)
//!   8  could not open the device

#[cfg(target_os = "linux")]
fn main() {
    use std::os::fd::AsRawFd;
    // A safe, always-granted char device. TIOCGWINSZ on a non-tty returns ENOTTY *if the ioctl is
    // permitted at all*; Landlock's IOCTL_DEV gate turns it into EPERM instead.
    let f = match std::fs::File::open("/dev/null") {
        Ok(f) => f,
        Err(_) => std::process::exit(8),
    };
    let mut ws: libc::winsize = unsafe { std::mem::zeroed() };
    let rc = unsafe { libc::ioctl(f.as_raw_fd(), libc::TIOCGWINSZ, &mut ws) };
    if rc == 0 {
        std::process::exit(0);
    }
    match std::io::Error::last_os_error().raw_os_error().unwrap_or(0) {
        libc::EPERM | libc::EACCES => std::process::exit(7),
        _ => std::process::exit(0), // ENOTTY and friends: the ioctl was permitted, just not a tty
    }
}

#[cfg(not(target_os = "linux"))]
fn main() {}
