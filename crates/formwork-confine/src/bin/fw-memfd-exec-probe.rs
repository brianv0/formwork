//! Test-support binary: the exec-by-descriptor probe (FW-E2E-188). An exec allow-list judges a
//! path; a descriptor has none, so `execveat(fd, "", .., AT_EMPTY_PATH)` -- what `fexecve` is -- of
//! an anonymous memory file runs whatever bytes the process can read (FW-ISO31). Reports purely via
//! exit code:
//!
//!   42  this image was started with `argv[1] = ran`: an exec landed
//!   7   the exec was refused with EACCES
//!   8   the exec failed with another errno
//!   3   setup failed (bad arguments, unreadable file, no memfd)
//!
//! `argv[1] = memfd <file>` copies `<file>` into a memfd and execs the descriptor;
//! `argv[1] = path <file>` execs `<file>` by path, the control the allow-list already refuses.
//! Either way the new image is told `ran`, so a copy of this probe is the natural `<file>`.

#[cfg(target_os = "linux")]
fn main() {
    use std::ffi::CString;
    use std::fs::File;
    use std::os::fd::{AsRawFd, FromRawFd};
    use std::os::unix::ffi::OsStrExt;
    use std::process::exit;

    let args: Vec<_> = std::env::args_os().skip(1).collect();
    let (how, file) = match args.as_slice() {
        [ran] if ran == "ran" => exit(42),
        [how, file] => (how.to_str().unwrap_or(""), file),
        _ => exit(3),
    };
    let argv = [
        c"fw-memfd-exec-probe".as_ptr(),
        c"ran".as_ptr(),
        std::ptr::null(),
    ];
    let envp = [std::ptr::null::<libc::c_char>()];
    match how {
        "path" => {
            let Ok(path) = CString::new(file.as_bytes()) else {
                exit(3);
            };
            // SAFETY: NUL-terminated strings and NULL-terminated arrays, alive for the call.
            unsafe { libc::execve(path.as_ptr(), argv.as_ptr(), envp.as_ptr()) };
        }
        "memfd" => {
            // <linux/memfd.h>, 6.3+: where `vm.memfd_noexec` makes a memfd non-executable by
            // default, the flag asks for an executable one. An older kernel rejects the flag.
            const MFD_EXEC: libc::c_uint = 0x10;
            // SAFETY: memfd_create takes a NUL-terminated name and flags; the fd is owned below.
            let create = |flags: libc::c_uint| unsafe {
                libc::syscall(libc::SYS_memfd_create, c"fw-probe".as_ptr(), flags)
            };
            let fd = match create(MFD_EXEC) {
                fd if fd >= 0 => fd,
                _ => create(0),
            };
            if fd < 0 {
                exit(3);
            }
            // SAFETY: `fd` is a fresh descriptor nothing else owns.
            let mut memfd = unsafe { File::from_raw_fd(fd as i32) };
            let copied = File::open(file).and_then(|mut src| std::io::copy(&mut src, &mut memfd));
            if copied.is_err() {
                exit(3);
            }
            // SAFETY: as for execve above; the empty path with AT_EMPTY_PATH names the fd itself.
            unsafe {
                libc::syscall(
                    libc::SYS_execveat,
                    memfd.as_raw_fd(),
                    c"".as_ptr(),
                    argv.as_ptr(),
                    envp.as_ptr(),
                    libc::AT_EMPTY_PATH,
                )
            };
        }
        _ => exit(3),
    }
    // exec returns only on failure.
    let refused = std::io::Error::last_os_error().raw_os_error() == Some(libc::EACCES);
    exit(if refused { 7 } else { 8 });
}

#[cfg(not(target_os = "linux"))]
fn main() {}
