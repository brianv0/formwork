//! The fd seam (FW-XR7, FW-GW6): the transport by which a confined agent reaches the gateway
//! without an in-sandbox `connect()` or any dependence on the filesystem sandbox allowing a socket
//! path. Everything here is an inherited or `SCM_RIGHTS`-passed descriptor, identical on Linux and
//! macOS. The launcher (which holds real network + fs) opens connections and hands the agent a
//! *connected* fd; inside the sandbox it is just an inherited fd, untouched by `net: Deny` or the fs
//! scope. Two postures: pre-open at spawn (the default), and on-demand `SCM_RIGHTS` minting over an
//! injected CONTROL fd (the escape hatch). Minting is the only way a new descriptor appears in the
//! sandbox, which keeps the gateway the single door (FW-GW4).
//!
//! No production crate consumes this yet -- it is proven against a real confined child by its own
//! tests (FW-E2E-010/011/012), ahead of the CLI/gateway wiring that will connect it. The public
//! surface is deliberately minimal: methods are added when that consumer needs them, not before
//! (Growth). If the wiring is abandoned, delete the crate rather than let it drift.

#[derive(Debug, thiserror::Error)]
pub enum SeamError {
    #[error("i/o error on the seam: {0}")]
    Io(#[from] std::io::Error),
    #[error("control protocol error: {0}")]
    Protocol(String),
    /// A missing/invalid `FORMWORK_FD_*` advertisement -- the child was not spawned via the seam.
    #[error("seam environment error: {0}")]
    Env(String),
}

#[cfg(unix)]
pub use imp::{child, inject, recv_fd, send_fd, Minted, Seam, SeamHost, SeamPlan};

#[cfg(unix)]
mod imp {
    use std::collections::{BTreeMap, BTreeSet};
    use std::io::{self, Read};
    use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd, RawFd};
    use std::os::unix::net::UnixStream;
    use std::os::unix::process::CommandExt;
    use std::process::{Child, Command};

    use crate::SeamError;

    const ENV_PREFIX: &str = "FORMWORK_FD_";
    const ENV_CONTROL: &str = "FORMWORK_FD_CONTROL";

    const STATUS_OK: u8 = b'+';
    const STATUS_ERR: u8 = b'-';

    /// Bound on a control request line, so a wedged or hostile child cannot make the launcher buffer
    /// without limit (fail-closed).
    const MAX_CONTROL_LINE: usize = 4096;

    /// ```no_run
    /// use formwork_seam::SeamPlan;
    /// let plan = SeamPlan::new().with_control().preopen("gateway");
    /// ```
    #[derive(Clone, Debug, Default)]
    pub struct SeamPlan {
        /// Inject a CONTROL fd for on-demand `SCM_RIGHTS` minting.
        pub control: bool,
        /// Each advertised to the child as `FORMWORK_FD_<NAME>`.
        pub preopen: Vec<String>,
    }

    impl SeamPlan {
        pub fn new() -> Self {
            SeamPlan::default()
        }

        pub fn with_control(mut self) -> Self {
            self.control = true;
            self
        }

        pub fn preopen(mut self, name: impl Into<String>) -> Self {
            self.preopen.push(name.into());
            self
        }
    }

    /// Holds the child ends open across the fork; consume with [`Seam::spawn`] (preferred) or
    /// [`Seam::into_host`].
    pub struct Seam {
        child_ends: Vec<OwnedFd>,
        control: Option<UnixStream>,
        preopened: BTreeMap<String, UnixStream>,
    }

    impl Seam {
        /// The misuse-resistant path: forks, then closes the parent's copies of the child ends -- the
        /// order EOF propagation requires (see [`Seam::into_host`]).
        pub fn spawn(self, command: &mut Command) -> Result<(Child, SeamHost), SeamError> {
            let child = command.spawn()?;
            Ok((child, self.into_host()))
        }

        /// Call only *after* `command.spawn()`: each channel is one socketpair, and until the parent
        /// drops its copy of the child's end that end is not fully closed, so the parent would never
        /// see EOF on child exit. Dropping here -- after the fork duplicated the end into the child --
        /// leaves the child sole owner, so its close is observable.
        pub fn into_host(self) -> SeamHost {
            let Seam {
                child_ends,
                control,
                preopened,
            } = self;
            drop(child_ends);
            SeamHost { control, preopened }
        }
    }

    /// Does not spawn: compose with confinement on the same `Command`, then spawn via
    /// [`Seam::spawn`]. Fail-closed: empty or colliding channel names are rejected here rather than
    /// yielding a missing/aliased descriptor.
    pub fn inject(command: &mut Command, plan: &SeamPlan) -> Result<Seam, SeamError> {
        tracing::info!(
            control = plan.control,
            preopen = plan.preopen.len(),
            "injecting fd seam"
        );
        let mut child_ends: Vec<OwnedFd> = Vec::new();
        let mut control: Option<UnixStream> = None;
        let mut preopened: BTreeMap<String, UnixStream> = BTreeMap::new();
        let mut slots: Vec<(String, RawFd)> = Vec::new();
        let mut seen_vars: BTreeSet<String> = BTreeSet::new();

        if plan.control {
            let (parent, child) = UnixStream::pair()?;
            let child = OwnedFd::from(child);
            slots.push((ENV_CONTROL.to_string(), child.as_raw_fd()));
            seen_vars.insert(ENV_CONTROL.to_string());
            child_ends.push(child);
            control = Some(parent);
        }

        for name in &plan.preopen {
            if name.is_empty() {
                return Err(SeamError::Protocol(
                    "connection name must not be empty".into(),
                ));
            }
            let var = env_var_for(name);
            if !seen_vars.insert(var.clone()) {
                return Err(SeamError::Protocol(format!(
                    "connection name {name:?} maps to environment variable {var}, which collides \
                     with another channel"
                )));
            }
            let (parent, child) = UnixStream::pair()?;
            let child = OwnedFd::from(child);
            slots.push((var, child.as_raw_fd()));
            child_ends.push(child);
            preopened.insert(name.clone(), parent);
        }

        // Target fd numbers strictly above every descriptor we just created, so the child's dup2
        // never overwrites a source it still needs and never collides with 0/1/2. The child learns
        // where each landed from the env vars (FW-XR7 "fixed, known fd numbers").
        let mut ceiling: RawFd = 2;
        for fd in &child_ends {
            ceiling = ceiling.max(fd.as_raw_fd());
        }
        if let Some(p) = &control {
            ceiling = ceiling.max(p.as_raw_fd());
        }
        for p in preopened.values() {
            ceiling = ceiling.max(p.as_raw_fd());
        }

        let mut pairs: Vec<(RawFd, RawFd)> = Vec::with_capacity(slots.len());
        for (i, (var, source)) in slots.iter().enumerate() {
            let target = ceiling + 1 + i as RawFd;
            command.env(var, target.to_string());
            pairs.push((*source, target));
        }

        // SAFETY: the closure runs in the forked child before `execve`. It only calls `dup2`
        // (async-signal-safe) over integer fds copied into `pairs` before the fork; it allocates
        // nothing and takes no locks. `dup2` clears CLOEXEC on the target so the descriptor survives
        // `execve`; each source is CLOEXEC (std sets it) and closes at `execve`.
        unsafe {
            command.pre_exec(move || {
                for (source, target) in &pairs {
                    if libc::dup2(*source, *target) < 0 {
                        return Err(io::Error::last_os_error());
                    }
                }
                Ok(())
            });
        }

        Ok(Seam {
            child_ends,
            control,
            preopened,
        })
    }

    pub struct SeamHost {
        control: Option<UnixStream>,
        preopened: BTreeMap<String, UnixStream>,
    }

    pub struct Minted {
        pub name: String,
        pub parent_end: UnixStream,
    }

    impl SeamHost {
        pub fn take_connection(&mut self, name: &str) -> Option<UnixStream> {
            self.preopened.remove(name)
        }

        fn control_mut(&mut self) -> Result<&mut UnixStream, SeamError> {
            self.control
                .as_mut()
                .ok_or_else(|| SeamError::Protocol("no CONTROL channel was injected".into()))
        }

        /// `Ok(None)` means the child closed CONTROL. Reads byte-by-byte so it never consumes into a
        /// following request or reply.
        pub fn recv_mint_request(&mut self) -> Result<Option<String>, SeamError> {
            let control = self.control_mut()?;
            let mut line: Vec<u8> = Vec::new();
            let mut byte = [0u8; 1];
            loop {
                match control.read(&mut byte)? {
                    0 => {
                        if line.is_empty() {
                            return Ok(None);
                        }
                        return Err(SeamError::Protocol(
                            "CONTROL channel closed mid-request".into(),
                        ));
                    }
                    _ => {
                        if byte[0] == b'\n' {
                            break;
                        }
                        line.push(byte[0]);
                        if line.len() > MAX_CONTROL_LINE {
                            return Err(SeamError::Protocol(
                                "CONTROL request exceeded the maximum length".into(),
                            ));
                        }
                    }
                }
            }
            let text = String::from_utf8(line)
                .map_err(|_| SeamError::Protocol("CONTROL request was not valid UTF-8".into()))?;
            match text.strip_prefix("mint ") {
                Some(name) if !name.is_empty() => Ok(Some(name.to_string())),
                _ => Err(SeamError::Protocol(format!(
                    "unrecognized CONTROL request: {text:?}"
                ))),
            }
        }

        pub fn fulfill_mint(&mut self, fd: BorrowedFd<'_>) -> Result<(), SeamError> {
            let control = self.control_mut()?;
            send_fd(control.as_fd(), STATUS_OK, fd)?;
            Ok(())
        }

        /// The stub-gateway path the seam tests use; a production gateway substitutes a real backend
        /// connection.
        pub fn mint_socketpair(&mut self) -> Result<UnixStream, SeamError> {
            let (parent_end, child_end) = UnixStream::pair()?;
            self.fulfill_mint(child_end.as_fd())?;
            // `child_end` drops here: once the child holds its own kernel-duplicated copy, the
            // launcher must close its copy so EOF works.
            Ok(parent_end)
        }

        /// `Ok(None)` on CONTROL EOF.
        pub fn accept_mint(&mut self) -> Result<Option<Minted>, SeamError> {
            match self.recv_mint_request()? {
                None => Ok(None),
                Some(name) => {
                    let parent_end = self.mint_socketpair()?;
                    Ok(Some(Minted { name, parent_end }))
                }
            }
        }
    }

    /// The in-sandbox side: never `connect()`s or opens a path -- adopts inherited descriptors and,
    /// for minting, exchanges one message.
    pub mod child {
        use std::io::Write;
        use std::os::fd::{AsFd, FromRawFd};
        use std::os::unix::net::UnixStream;

        use super::{env_var_for, fd_from_env, recv_fd, ENV_CONTROL, STATUS_ERR, STATUS_OK};
        use crate::SeamError;

        /// Call once.
        pub fn control() -> Result<UnixStream, SeamError> {
            let fd = fd_from_env(ENV_CONTROL)?;
            // SAFETY: the seam advertised this fd and `fd_from_env` verified it is open; we take
            // unique ownership exactly once.
            Ok(unsafe { UnixStream::from_raw_fd(fd) })
        }

        /// Call once per name.
        pub fn connection(name: &str) -> Result<UnixStream, SeamError> {
            let fd = fd_from_env(&env_var_for(name))?;
            // SAFETY: as in `control` -- advertised, verified-open, adopted exactly once.
            Ok(unsafe { UnixStream::from_raw_fd(fd) })
        }

        /// No `connect()` occurs in the sandbox.
        pub fn mint(control: &mut UnixStream, name: &str) -> Result<UnixStream, SeamError> {
            if name.contains(['\n', '\r']) {
                return Err(SeamError::Protocol(
                    "connection name must not contain a newline".into(),
                ));
            }
            control.write_all(format!("mint {name}\n").as_bytes())?;
            control.flush()?;
            match recv_fd(control.as_fd())? {
                None => Err(SeamError::Protocol(
                    "gateway closed the CONTROL channel before replying".into(),
                )),
                Some((STATUS_OK, Some(fd))) => Ok(UnixStream::from(fd)),
                Some((STATUS_OK, None)) => Err(SeamError::Protocol(
                    "gateway acknowledged the mint but passed no descriptor".into(),
                )),
                Some((STATUS_ERR, _)) => Err(SeamError::Protocol(format!(
                    "gateway refused to mint a connection named {name:?}"
                ))),
                Some((other, _)) => Err(SeamError::Protocol(format!(
                    "gateway replied with an unknown status byte 0x{other:02x}"
                ))),
            }
        }
    }

    /// One `SCM_RIGHTS` fd needs `CMSG_SPACE(4)` (~24 bytes on 64-bit); 64 is comfortably larger and
    /// asserted at runtime before use.
    const CMSG_BYTES: usize = 64;

    /// Aligned to hold a `cmsghdr` (8-byte on the LP64 targets Formwork supports), as the `CMSG_*`
    /// macros require.
    #[repr(C, align(8))]
    struct CmsgBuf {
        bytes: [u8; CMSG_BYTES],
    }

    /// `SCM_RIGHTS` needs at least one data byte, which `byte` provides.
    pub fn send_fd(sock: BorrowedFd<'_>, byte: u8, fd: BorrowedFd<'_>) -> io::Result<()> {
        let fd_raw: RawFd = fd.as_raw_fd();
        let mut data = [byte];
        let mut iov = libc::iovec {
            iov_base: data.as_mut_ptr().cast(),
            iov_len: 1,
        };
        let mut cmsg = CmsgBuf {
            bytes: [0u8; CMSG_BYTES],
        };

        // SAFETY: `msghdr` is C POD; zeroing yields a valid empty message we fully initialize below.
        // Every pointer stored into it refers to a stack local that outlives the `sendmsg` call.
        let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
        msg.msg_iov = &mut iov;
        msg.msg_iovlen = 1;
        msg.msg_control = cmsg.bytes.as_mut_ptr().cast();
        let space = unsafe { libc::CMSG_SPACE(std::mem::size_of::<RawFd>() as u32) };
        assert!(
            space as usize <= CMSG_BYTES,
            "cmsg buffer too small for one fd"
        );
        msg.msg_controllen = space as _;

        // SAFETY: `msg_control` is an aligned, zeroed buffer of at least `CMSG_SPACE` bytes, so
        // `CMSG_FIRSTHDR`/`CMSG_DATA` yield valid pointers within it; we write one header + one
        // `RawFd`, then `sendmsg` reads the fully-formed message.
        unsafe {
            let cmsgp = libc::CMSG_FIRSTHDR(&msg);
            (*cmsgp).cmsg_level = libc::SOL_SOCKET;
            (*cmsgp).cmsg_type = libc::SCM_RIGHTS;
            (*cmsgp).cmsg_len = libc::CMSG_LEN(std::mem::size_of::<RawFd>() as u32) as _;
            std::ptr::copy_nonoverlapping(
                std::ptr::addr_of!(fd_raw).cast::<u8>(),
                libc::CMSG_DATA(cmsgp),
                std::mem::size_of::<RawFd>(),
            );
            if libc::sendmsg(sock.as_raw_fd(), &msg, 0) < 0 {
                return Err(io::Error::last_os_error());
            }
        }
        Ok(())
    }

    /// `Ok(None)` is a clean EOF. A received fd is materialized once and set CLOEXEC so a minted
    /// descriptor cannot leak into any grandchild the receiver later spawns (FW-ADV-005).
    pub fn recv_fd(sock: BorrowedFd<'_>) -> io::Result<Option<(u8, Option<OwnedFd>)>> {
        let mut data = [0u8; 1];
        let mut iov = libc::iovec {
            iov_base: data.as_mut_ptr().cast(),
            iov_len: 1,
        };
        let mut cmsg = CmsgBuf {
            bytes: [0u8; CMSG_BYTES],
        };

        // SAFETY: as in `send_fd` -- zeroed C POD with pointers to stack locals live across `recvmsg`.
        let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
        msg.msg_iov = &mut iov;
        msg.msg_iovlen = 1;
        msg.msg_control = cmsg.bytes.as_mut_ptr().cast();
        let space = unsafe { libc::CMSG_SPACE(std::mem::size_of::<RawFd>() as u32) };
        assert!(
            space as usize <= CMSG_BYTES,
            "cmsg buffer too small for one fd"
        );
        msg.msg_controllen = space as _;

        // SAFETY: `sock` is valid and `msg` describes valid, sufficiently sized buffers; `recvmsg`
        // fills `data`, the control buffer, and `msg_flags`.
        let n = unsafe { libc::recvmsg(sock.as_raw_fd(), &mut msg, 0) };
        if n < 0 {
            return Err(io::Error::last_os_error());
        }

        // SAFETY: after a successful `recvmsg` the control buffer holds well-formed cmsg headers we
        // walk with the `CMSG_*` macros; an `SCM_RIGHTS` payload is a `RawFd` the kernel installed,
        // taken ownership of exactly once.
        let mut received: Option<OwnedFd> = None;
        unsafe {
            let mut cmsgp = libc::CMSG_FIRSTHDR(&msg);
            while !cmsgp.is_null() {
                if (*cmsgp).cmsg_level == libc::SOL_SOCKET && (*cmsgp).cmsg_type == libc::SCM_RIGHTS
                {
                    let mut raw: RawFd = -1;
                    std::ptr::copy_nonoverlapping(
                        libc::CMSG_DATA(cmsgp),
                        std::ptr::addr_of_mut!(raw).cast::<u8>(),
                        std::mem::size_of::<RawFd>(),
                    );
                    received = Some(OwnedFd::from_raw_fd(raw));
                    break;
                }
                cmsgp = libc::CMSG_NXTHDR(&msg, cmsgp);
            }
        }

        if (msg.msg_flags & libc::MSG_CTRUNC) != 0 {
            return Err(io::Error::other(
                "SCM_RIGHTS ancillary data was truncated; a descriptor may have been dropped",
            ));
        }
        if n == 0 && received.is_none() {
            return Ok(None);
        }
        if let Some(f) = &received {
            set_cloexec(f.as_fd())?;
        }
        Ok(Some((data[0], received)))
    }

    fn set_cloexec(fd: BorrowedFd<'_>) -> io::Result<()> {
        // SAFETY: `F_GETFD`/`F_SETFD` query and set the flags of a valid fd; no memory is touched.
        unsafe {
            let flags = libc::fcntl(fd.as_raw_fd(), libc::F_GETFD);
            if flags < 0 {
                return Err(io::Error::last_os_error());
            }
            if libc::fcntl(fd.as_raw_fd(), libc::F_SETFD, flags | libc::FD_CLOEXEC) < 0 {
                return Err(io::Error::last_os_error());
            }
        }
        Ok(())
    }

    /// Deterministic and total, so launcher and child compute the same `FORMWORK_FD_*` var.
    fn env_var_for(name: &str) -> String {
        let mut s = String::with_capacity(ENV_PREFIX.len() + name.len());
        s.push_str(ENV_PREFIX);
        for ch in name.chars() {
            if ch.is_ascii_alphanumeric() {
                s.push(ch.to_ascii_uppercase());
            } else {
                s.push('_');
            }
        }
        s
    }

    /// Fails closed if the variable is absent, unparseable, or names a descriptor that is not open.
    fn fd_from_env(var: &str) -> Result<RawFd, SeamError> {
        let val = std::env::var(var).map_err(|_| {
            SeamError::Env(format!(
                "{var} is not set; was this process spawned through the seam?"
            ))
        })?;
        let fd: RawFd = val.parse().map_err(|_| {
            SeamError::Env(format!(
                "{var}={val:?} is not a valid file-descriptor number"
            ))
        })?;
        // SAFETY: `F_GETFD` only queries the descriptor's flags; no side effects.
        if unsafe { libc::fcntl(fd, libc::F_GETFD) } < 0 {
            return Err(SeamError::Env(format!(
                "{var}={fd} does not refer to an open descriptor"
            )));
        }
        Ok(fd)
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn env_var_for_uppercases_and_sanitizes() {
            assert_eq!(env_var_for("gateway"), "FORMWORK_FD_GATEWAY");
            assert_eq!(env_var_for("mcp-files"), "FORMWORK_FD_MCP_FILES");
            assert_eq!(env_var_for("a.b/c"), "FORMWORK_FD_A_B_C");
        }

        #[test]
        fn send_and_recv_fd_roundtrips_a_descriptor() {
            // Pass a pipe's read end across a socketpair; a byte written to the original write end
            // must appear on the received read end -- same open file.
            let (a, b) = UnixStream::pair().unwrap();
            let mut fds = [0 as RawFd; 2];
            // SAFETY: standard pipe(2) call into a two-element array.
            assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0);
            let read_end = unsafe { OwnedFd::from_raw_fd(fds[0]) };
            let write_end = unsafe { OwnedFd::from_raw_fd(fds[1]) };

            send_fd(a.as_fd(), b'+', read_end.as_fd()).unwrap();
            let (status, got) = recv_fd(b.as_fd()).unwrap().unwrap();
            assert_eq!(status, b'+');
            let got = got.expect("an fd should have been received");

            // SAFETY: valid fds; single-byte read/write into owned buffers.
            let wrote = unsafe { libc::write(write_end.as_raw_fd(), [b'z'].as_ptr().cast(), 1) };
            assert_eq!(wrote, 1);
            let mut buf = [0u8; 1];
            let read = unsafe { libc::read(got.as_raw_fd(), buf.as_mut_ptr().cast(), 1) };
            assert_eq!(read, 1);
            assert_eq!(buf[0], b'z');
        }
    }
}
