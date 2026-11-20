//! Signal forwarding in the spawn posture (FW-XR12, FW-XR13).
//!
//! The Gateway, the connect supervisor and the opener service run in this process, and the
//! session root is removed by it, so a signal that ended `formwork` would leave the workload
//! running with no egress, its status unreported and its root behind. While a [`Forwarder`] is
//! installed the four signals below are caught instead, and [`Forwarder::wait`] passes them on.
//!
//! The isolation stage relays for a single-threaded process with `sigwaitinfo`
//! (`formwork_confine`, `linux/isolate.rs`). This process has threads that do not block
//! signals, and macOS has no `sigwaitinfo`, so the handler here writes each signal to a pipe the
//! waiting thread polls.

use std::fs::File;
use std::io::Read;
use std::os::fd::{AsRawFd, RawFd};
use std::process::{Child, ExitStatus};
use std::sync::atomic::{AtomicI32, Ordering};
use std::time::{Duration, Instant};

/// **term-grace**: how long a workload has to exit after a forwarded `SIGTERM` before the
/// Launcher kills it (FW-XR13).
pub const TERM_GRACE: Duration = Duration::from_secs(10);

const FORWARDED: [libc::c_int; 4] = [libc::SIGINT, libc::SIGTERM, libc::SIGHUP, libc::SIGQUIT];

/// Set in a pipe byte when `si_code` says a process sent the signal.
const BY_PROCESS: u8 = 0x80;

/// The pipe's write end while a [`Forwarder`] is installed, else -1.
static WAKE: AtomicI32 = AtomicI32::new(-1);

extern "C" fn on_signal(signo: libc::c_int, info: *mut libc::siginfo_t, _: *mut libc::c_void) {
    let fd = WAKE.load(Ordering::Relaxed);
    if fd < 0 {
        return;
    }
    let errno = std::io::Error::last_os_error().raw_os_error();
    // SAFETY: the kernel passes a valid siginfo to an SA_SIGINFO handler.
    let by_process = !info.is_null() && unsafe { (*info).si_code } <= 0;
    let byte = [(signo as u8 & !BY_PROCESS) | if by_process { BY_PROCESS } else { 0 }];
    // SAFETY: write(2) is async-signal-safe; the descriptor is non-blocking, and a full pipe
    // already holds a wake-up.
    unsafe { libc::write(fd, byte.as_ptr().cast(), 1) };
    if let Some(errno) = errno {
        set_errno(errno);
    }
}

/// The interrupted code may be between a failed call and its read of `errno`.
fn set_errno(value: i32) {
    #[cfg(target_os = "linux")]
    // SAFETY: the thread's own errno.
    unsafe {
        *libc::__errno_location() = value;
    }
    #[cfg(target_os = "macos")]
    // SAFETY: the thread's own errno.
    unsafe {
        *libc::__error() = value;
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    let _ = value;
}

/// One signal read back from the pipe.
struct Received {
    signo: libc::c_int,
    by_process: bool,
}

/// Installed before the session root exists and dropped once it is removed, so no forwarded
/// signal ends this process while a root or a workload is its to clean up.
pub struct Forwarder {
    read: File,
    /// Closed on drop, after the handlers are gone.
    _write: File,
    previous: Vec<(libc::c_int, libc::sigaction)>,
}

impl Forwarder {
    pub fn install() -> std::io::Result<Forwarder> {
        let (read, write) = crate::cloexec_pipe()?;
        for fd in [read.as_raw_fd(), write.as_raw_fd()] {
            set_nonblocking(fd)?;
        }
        WAKE.store(write.as_raw_fd(), Ordering::Relaxed);
        let mut forwarder = Forwarder {
            read,
            _write: write,
            previous: Vec::new(),
        };
        for signo in FORWARDED.into_iter().chain([libc::SIGCHLD]) {
            // SAFETY: a zeroed sigaction is a valid output buffer, and a valid input once its
            // handler, mask and flags are set below.
            let mut old: libc::sigaction = unsafe { std::mem::zeroed() };
            // SAFETY: querying a disposition.
            if unsafe { libc::sigaction(signo, std::ptr::null(), &mut old) } != 0 {
                return Err(std::io::Error::last_os_error());
            }
            // A signal this process was started ignoring (`nohup`, a background job of a
            // non-interactive shell) stays ignored, here and so in the workload.
            if signo != libc::SIGCHLD && old.sa_sigaction == libc::SIG_IGN {
                continue;
            }
            // SAFETY: as above.
            let mut new: libc::sigaction = unsafe { std::mem::zeroed() };
            new.sa_sigaction = on_signal as *const () as usize;
            new.sa_flags = libc::SA_SIGINFO | libc::SA_RESTART;
            // SAFETY: sigemptyset initializes the mask; the handler only calls write(2).
            if unsafe {
                libc::sigemptyset(&mut new.sa_mask);
                libc::sigaction(signo, &new, std::ptr::null_mut())
            } != 0
            {
                return Err(std::io::Error::last_os_error());
            }
            forwarder.previous.push((signo, old));
        }
        Ok(forwarder)
    }

    /// A forwarded signal that arrived since [`install`](Forwarder::install), if any.
    pub fn pending(&mut self) -> Option<libc::c_int> {
        std::iter::from_fn(|| self.read_one())
            .map(|r| r.signo)
            .find(|s| FORWARDED.contains(s))
    }

    /// Wait for `child`, forwarding signals to it (FW-XR12) and killing it **term-grace** after
    /// a forwarded `SIGTERM` (FW-XR13). Returns only once the child has exited.
    pub fn wait(&mut self, child: &mut Child) -> std::io::Result<ExitStatus> {
        let mut kill_at: Option<Instant> = None;
        let mut killed = false;
        loop {
            if let Some(status) = child.try_wait()? {
                return Ok(status);
            }
            let timeout = match kill_at {
                Some(at) if !killed => Some(at.saturating_duration_since(Instant::now())),
                _ => None,
            };
            self.poll(timeout)?;
            while let Some(received) = self.read_one() {
                if !FORWARDED.contains(&received.signo) {
                    continue;
                }
                let keyboard = from_keyboard(&received);
                if keyboard {
                    // The terminal signalled its whole foreground group, the workload included.
                    // An interrupt during the grace period means the operator will not wait.
                    if received.signo == libc::SIGINT && kill_at.is_some() {
                        kill_at = Some(Instant::now());
                    }
                    continue;
                }
                tracing::info!(
                    signal = received.signo,
                    "forwarding a signal to the workload"
                );
                signal(child, received.signo);
                if received.signo == libc::SIGTERM && kill_at.is_none() {
                    kill_at = Some(Instant::now() + TERM_GRACE);
                }
            }
            if kill_at.is_some_and(|at| !killed && Instant::now() >= at) {
                tracing::warn!(
                    grace_secs = TERM_GRACE.as_secs(),
                    "the workload outlived the grace period after SIGTERM; killing it (FW-XR13)"
                );
                signal(child, libc::SIGKILL);
                killed = true;
            }
        }
    }

    fn read_one(&mut self) -> Option<Received> {
        let mut byte = [0u8; 1];
        match self.read.read(&mut byte) {
            Ok(1) => Some(Received {
                signo: libc::c_int::from(byte[0] & !BY_PROCESS),
                by_process: byte[0] & BY_PROCESS != 0,
            }),
            _ => None,
        }
    }

    fn poll(&self, timeout: Option<Duration>) -> std::io::Result<()> {
        let mut fds = libc::pollfd {
            fd: self.read.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        let millis = timeout.map_or(-1, |t| {
            libc::c_int::try_from(t.as_millis().saturating_add(1)).unwrap_or(libc::c_int::MAX)
        });
        // SAFETY: poll over one descriptor this struct owns.
        if unsafe { libc::poll(&mut fds, 1, millis) } < 0 {
            let e = std::io::Error::last_os_error();
            if e.kind() != std::io::ErrorKind::Interrupted {
                return Err(e);
            }
        }
        Ok(())
    }
}

impl Drop for Forwarder {
    fn drop(&mut self) {
        for (signo, old) in &self.previous {
            // SAFETY: restoring a disposition sigaction returned.
            unsafe { libc::sigaction(*signo, old, std::ptr::null_mut()) };
        }
        WAKE.store(-1, Ordering::Relaxed);
    }
}

/// Whether the terminal's keyboard generated this signal, in which case every process of the
/// foreground group -- the workload among them -- already has it. Linux says so in `si_code`.
/// Elsewhere `si_code` does not tell a keyboard from `kill(2)`, so an interrupt or quit that
/// arrives while this process is in its terminal's foreground group is taken for the keyboard's.
fn from_keyboard(received: &Received) -> bool {
    if !matches!(received.signo, libc::SIGINT | libc::SIGQUIT) {
        return false;
    }
    if cfg!(target_os = "linux") {
        !received.by_process
    } else {
        in_foreground_group()
    }
}

fn in_foreground_group() -> bool {
    let Ok(tty) = File::open("/dev/tty") else {
        return false;
    };
    // SAFETY: tcgetpgrp on a descriptor owned above; getpgrp has no failure modes.
    unsafe { libc::tcgetpgrp(tty.as_raw_fd()) == libc::getpgrp() }
}

/// The workload's process group where it has one of its own, else the workload process: a
/// workload shares this process's group unless it left it, and signalling that group would
/// signal this process, its parent and its siblings.
fn signal(child: &Child, signo: libc::c_int) {
    let Ok(pid) = libc::pid_t::try_from(child.id()) else {
        return;
    };
    // SAFETY: getpgid, getpgrp and kill take scalars; the child is unreaped, so the pid is its.
    unsafe {
        let group = libc::getpgid(pid);
        let target = if group > 0 && group != libc::getpgrp() {
            -group
        } else {
            pid
        };
        libc::kill(target, signo);
    }
}

fn set_nonblocking(fd: RawFd) -> std::io::Result<()> {
    // SAFETY: fcntl on a descriptor the caller owns.
    unsafe {
        let flags = libc::fcntl(fd, libc::F_GETFL);
        if flags < 0 || libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) < 0 {
            return Err(std::io::Error::last_os_error());
        }
    }
    Ok(())
}

/// End this process the way `signo` would have without a handler, so a caller that inspects the
/// wait status (a shell deciding whether to go on after ^C) sees the signal.
pub fn die_of(signo: libc::c_int) -> ! {
    // SAFETY: signal and raise take scalars.
    unsafe {
        libc::signal(signo, libc::SIG_DFL);
        libc::raise(signo);
    }
    std::process::exit(128 + signo);
}
