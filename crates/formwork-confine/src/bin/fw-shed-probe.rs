//! Test-support binary: the sandbox-shedding probe (FW-ADV-001 / FW-INV2). Run *inside* Formwork's
//! confinement, it attempts, in sequence, the documented ways to shed the sandbox and reports the
//! outcome purely via exit code, so the confined parent can tell a real break apart from any other
//! failure. See `crates/formwork-confine/tests/linux_confine.rs`.
//!
//!   0   every shedding attempt failed and confinement persisted across a re-exec (PASS)
//!   20  NO_NEW_PRIVS was not set at entry -- the process was not actually confined (inconclusive)
//!   21  NO_NEW_PRIVS was cleared -- the setuid/setgid-exec defense was shed (FAIL)
//!   22  a seccomp-denied shedding syscall succeeded before the re-exec (FAIL)
//!   23  could not re-exec self (setup failure, not a security result)
//!   24  the seccomp filter did not survive the re-exec (FAIL)
//!   25  NO_NEW_PRIVS did not survive the re-exec (FAIL)
//!
//! Deliberately libc-only so it starts wherever `/bin/cat` does under Closed-mode essentials.

#[cfg(target_os = "linux")]
fn main() {
    use std::os::unix::process::CommandExt;

    // A confinement-shedding syscall the seccomp baseline denies: unshare(CLONE_NEWUSER) would open a
    // fresh user namespace in which capabilities are regained. Under the filter it returns EPERM.
    // Returns true when the attempt was denied (any nonzero return; a denied call is a no-op).
    fn new_userns_denied() -> bool {
        // SAFETY: unshare() takes a flag scalar and has no memory effects; a denied call changes nothing.
        (unsafe { libc::unshare(libc::CLONE_NEWUSER) }) != 0
    }
    // The NO_NEW_PRIVS flag: 1 once set. It is what neutralizes setuid/setgid bits on execve.
    fn nnp_set() -> bool {
        // SAFETY: PR_GET_NO_NEW_PRIVS reads the per-thread flag; arg2..arg5 must be 0 or it EINVALs.
        unsafe { libc::prctl(libc::PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) == 1 }
    }

    if std::env::var("FW_SHED_STAGE").as_deref() == Ok("2") {
        // Post-re-exec image: both the seccomp filter and NO_NEW_PRIVS are inherited across execve, so
        // a re-exec cannot drop them. Re-check the two that a shed would have relaxed.
        if !new_userns_denied() {
            std::process::exit(24);
        }
        if !nnp_set() {
            std::process::exit(25);
        }
        std::process::exit(0);
    }

    // Stage 1: still the originally-confined image.
    // Vector A (setuid-binary exec): NO_NEW_PRIVS makes execve honor no setuid/setgid bit, so a
    // setuid binary cannot regain privilege. Prove the flag that guarantees this is set.
    if !nnp_set() {
        std::process::exit(20);
    }
    // Vector B (clear NO_NEW_PRIVS): the flag is a one-way latch -- the kernel only accepts arg==1, so
    // a request to clear it is rejected and the flag must remain set afterward.
    // SAFETY: fixed scalar args; PR_SET_NO_NEW_PRIVS only touches the per-thread flag.
    let _ = unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 0, 0, 0, 0) };
    if !nnp_set() {
        std::process::exit(21);
    }
    // Vector C (shedding syscall): a confinement-relaxing syscall must be denied by the filter.
    if !new_userns_denied() {
        std::process::exit(22);
    }

    // Vector D (re-exec to drop the seccomp filter): replace this process image with a fresh copy of
    // self. The filter and NNP survive execve; stage 2 re-checks both. exec() returns only on failure.
    let exe = match std::env::current_exe() {
        Ok(p) => p,
        Err(_) => std::process::exit(23),
    };
    let _ = std::process::Command::new(exe)
        .env("FW_SHED_STAGE", "2")
        .exec();
    std::process::exit(23);
}

#[cfg(not(target_os = "linux"))]
fn main() {}
