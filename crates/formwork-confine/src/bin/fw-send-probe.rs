//! Test-support binary: the send probe for supervised connect (FW-ISO30, FW-ISO12, FW-ADV-018).
//! Exit codes, unless a mode says otherwise: 0 the step succeeded, 7 refused with `EACCES`,
//! 8 a failure of the probe itself, 100 + errno any other errno.
//!
//! - `sendmsg <path>` / `sendmmsg1 <path>`: one datagram to the socket at `path` (`@name`: the
//!   abstract name `name`), from an unbound UNIX datagram socket, by `sendmsg` or by a one-entry
//!   `sendmmsg`.
//! - `own <path>`: bind a datagram socket at `path` in the session, `sendmsg` to it, read it back.
//! - `mixed <granted> <foreign>`: one `sendmmsg` of three datagrams, to `granted`, `foreign` and
//!   `granted`; exits 50 + the count it returns.
//! - `mixed-connected <granted> <foreign>`: the same from a socket connected to `granted`, the
//!   first and third entries naming no destination.
//! - `inet <ip:port>`: `sendmsg`, then `sendmmsg`, with an inet destination on an unconnected TCP
//!   socket; 0 when both are refused with `EACCES`, otherwise 20 + the step that was not.
//! - `connected <gateway ip:port>`: sends that name no destination, which must behave as without
//!   supervision: on a TCP connection to `ip:port`, carrying descriptors over a UNIX stream pair,
//!   to the route netlink kernel peer, blocking on a full UNIX socket while another thread
//!   connects, and to a closed peer. 0, or 10 + the step that failed.
//! - `rewrite <own> <foreign> <ms>`: for `ms` milliseconds one thread rewrites the `msghdr` of a
//!   socket connected to `own` (bound here) between no destination, `own` and `foreign`, while
//!   another sends with it.
//! - `fdswap <foreign> <ip:port> <ms>`: one thread flips a descriptor number between a TCP
//!   connection to `ip:port` and an unconnected UNIX datagram socket, and the `msghdr` between no
//!   destination and `foreign`, while another sends.
//! - `nlswap-send <foreign> <ms>`: one thread flips a descriptor number between a route netlink
//!   socket and a UNIX datagram socket, and one destination buffer between a netlink address and
//!   `foreign`, while another sends with it.
//! - `nlswap <ip:port> <ms>`: one thread flips a descriptor number between a route netlink socket
//!   and a TCP socket while another calls `connect()` on it to `ip:port`; 23 if the TCP socket
//!   connected.
//! - `bench <pair|tcp ip:port> <bytes> <count> <out>`: the mean nanoseconds of `count` `sendmsg`
//!   calls of `bytes` each on a connected socket, written to `out`.

#[cfg(target_os = "linux")]
mod probe {
    use std::mem::{size_of, zeroed};
    use std::net::SocketAddrV4;
    use std::sync::atomic::{AtomicBool, AtomicI32, AtomicUsize, Ordering};
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    fn errno() -> i32 {
        std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
    }

    fn code(rc: isize) -> i32 {
        match (rc, errno()) {
            (0.., _) => 0,
            (_, libc::EACCES) => 7,
            (_, e) => 100 + e.min(150),
        }
    }

    fn sockaddr_in(addr: SocketAddrV4) -> libc::sockaddr_in {
        libc::sockaddr_in {
            sin_family: libc::AF_INET as libc::sa_family_t,
            sin_port: addr.port().to_be(),
            sin_addr: libc::in_addr {
                s_addr: u32::from_ne_bytes(addr.ip().octets()),
            },
            sin_zero: [0; 8],
        }
    }

    fn sockaddr_un(path: &str) -> (libc::sockaddr_un, libc::socklen_t) {
        // SAFETY: an all-zero sockaddr_un is valid.
        let mut sun: libc::sockaddr_un = unsafe { zeroed() };
        sun.sun_family = libc::AF_UNIX as libc::sa_family_t;
        // `@name` is the abstract name `name`: a leading NUL and no terminator.
        let (bytes, abstract_name) = match path.strip_prefix('@') {
            Some(name) => (name.as_bytes(), true),
            None => (path.as_bytes(), false),
        };
        let start = usize::from(abstract_name);
        let n = bytes.len().min(sun.sun_path.len() - 1 - start);
        for (i, b) in bytes[..n].iter().enumerate() {
            sun.sun_path[start + i] = *b as libc::c_char;
        }
        let len = size_of::<libc::sa_family_t>() + start + n + usize::from(!abstract_name);
        (sun, len as libc::socklen_t)
    }

    fn socket(domain: i32, ty: i32, protocol: i32) -> i32 {
        // SAFETY: socket() takes scalars; the descriptor is owned by the probe.
        unsafe { libc::socket(domain, ty, protocol) }
    }

    fn dgram() -> i32 {
        socket(libc::AF_UNIX, libc::SOCK_DGRAM, 0)
    }

    fn tcp() -> i32 {
        socket(libc::AF_INET, libc::SOCK_STREAM, 0)
    }

    fn connect_in(fd: i32, to: SocketAddrV4) -> bool {
        let dest = sockaddr_in(to);
        // SAFETY: connect reads one sockaddr_in alive for the call.
        unsafe {
            libc::connect(
                fd,
                (&dest as *const libc::sockaddr_in).cast(),
                size_of::<libc::sockaddr_in>() as libc::socklen_t,
            ) == 0
        }
    }

    fn connect_un(fd: i32, path: &str) -> bool {
        let (sun, len) = sockaddr_un(path);
        // SAFETY: connect reads one sockaddr_un alive for the call.
        unsafe { libc::connect(fd, (&sun as *const libc::sockaddr_un).cast(), len) == 0 }
    }

    /// A `msghdr` over one iovec, naming `name` (`len` bytes) or nothing.
    fn msghdr(iov: &mut libc::iovec, name: *const u8, len: usize) -> libc::msghdr {
        // SAFETY: an all-zero msghdr is valid.
        let mut msg: libc::msghdr = unsafe { zeroed() };
        msg.msg_name = name as *mut libc::c_void;
        msg.msg_namelen = len as libc::socklen_t;
        msg.msg_iov = iov;
        msg.msg_iovlen = 1;
        msg
    }

    fn sendmsg_to(
        fd: i32,
        name: Option<(&libc::sockaddr_un, libc::socklen_t)>,
        data: &[u8],
    ) -> isize {
        let mut iov = libc::iovec {
            iov_base: data.as_ptr() as *mut libc::c_void,
            iov_len: data.len(),
        };
        let (ptr, len) = match name {
            Some((sun, len)) => ((sun as *const libc::sockaddr_un).cast(), len as usize),
            None => (std::ptr::null(), 0),
        };
        let msg = msghdr(&mut iov, ptr, len);
        // SAFETY: the msghdr and what it points at are alive for the call.
        unsafe { libc::sendmsg(fd, &msg, libc::MSG_NOSIGNAL) }
    }

    /// One `sendmmsg` whose entries name the given destinations (`None`: no destination).
    fn sendmmsg_to(fd: i32, names: &[Option<&str>]) -> isize {
        let addrs: Vec<_> = names.iter().map(|n| n.map(sockaddr_un)).collect();
        let byte = *b"m";
        let mut iovs: Vec<libc::iovec> = names
            .iter()
            .map(|_| libc::iovec {
                iov_base: byte.as_ptr() as *mut libc::c_void,
                iov_len: 1,
            })
            .collect();
        let mut vec: Vec<libc::mmsghdr> = addrs
            .iter()
            .zip(iovs.iter_mut())
            .map(|(a, iov)| {
                let (ptr, len) = match a {
                    Some((sun, len)) => ((sun as *const libc::sockaddr_un).cast(), *len as usize),
                    None => (std::ptr::null(), 0),
                };
                libc::mmsghdr {
                    msg_hdr: msghdr(iov, ptr, len),
                    msg_len: 0,
                }
            })
            .collect();
        // SAFETY: the array and what its entries point at are alive for the call.
        unsafe {
            libc::sendmmsg(fd, vec.as_mut_ptr(), vec.len() as u32, libc::MSG_NOSIGNAL) as isize
        }
    }

    fn one(path: &str, many: bool) -> i32 {
        let fd = dgram();
        if fd < 0 {
            return 8;
        }
        let rc = if many {
            sendmmsg_to(fd, &[Some(path)])
        } else {
            let (sun, len) = sockaddr_un(path);
            sendmsg_to(fd, Some((&sun, len)), b"s")
        };
        if many && rc == 0 {
            return 8;
        }
        code(rc)
    }

    fn own(path: &str) -> i32 {
        let (rx, tx) = (dgram(), dgram());
        let (sun, len) = sockaddr_un(path);
        // SAFETY: bind reads one sockaddr_un alive for the call.
        if rx < 0
            || tx < 0
            || unsafe { libc::bind(rx, (&sun as *const libc::sockaddr_un).cast(), len) } != 0
        {
            return 8;
        }
        let rc = sendmsg_to(tx, Some((&sun, len)), b"o");
        if rc != 1 {
            return code(rc.min(-1));
        }
        let mut buf = [0u8; 4];
        // SAFETY: recv into a stack buffer.
        let n = unsafe { libc::recv(rx, buf.as_mut_ptr().cast(), buf.len(), libc::MSG_DONTWAIT) };
        if n == 1 && buf[0] == b'o' {
            0
        } else {
            8
        }
    }

    fn mixed(granted: &str, foreign: &str, connected: bool) -> i32 {
        let fd = dgram();
        if fd < 0 || (connected && !connect_un(fd, granted)) {
            return 8;
        }
        let names: [Option<&str>; 3] = if connected {
            [None, Some(foreign), None]
        } else {
            [Some(granted), Some(foreign), Some(granted)]
        };
        match sendmmsg_to(fd, &names) {
            n @ 0..=9 => 50 + n as i32,
            rc => code(rc),
        }
    }

    fn inet(to: SocketAddrV4) -> i32 {
        let dest = sockaddr_in(to);
        let ptr = (&dest as *const libc::sockaddr_in).cast::<u8>();
        let byte = *b"i";
        let mut iov = libc::iovec {
            iov_base: byte.as_ptr() as *mut libc::c_void,
            iov_len: 1,
        };
        let fd = tcp();
        if fd < 0 {
            return 8;
        }
        let msg = msghdr(&mut iov, ptr, size_of::<libc::sockaddr_in>());
        // SAFETY: the msghdr and what it points at are alive for the call.
        if unsafe { libc::sendmsg(fd, &msg, libc::MSG_NOSIGNAL) } != -1 || errno() != libc::EACCES {
            return 21;
        }
        let mut vec = [libc::mmsghdr {
            msg_hdr: msghdr(&mut iov, ptr, size_of::<libc::sockaddr_in>()),
            msg_len: 0,
        }];
        // SAFETY: as above.
        if unsafe { libc::sendmmsg(fd, vec.as_mut_ptr(), 1, libc::MSG_NOSIGNAL) } != -1
            || errno() != libc::EACCES
        {
            return 22;
        }
        0
    }

    /// Send all of `data` with plain `sendmsg` calls naming no destination.
    fn send_all(fd: i32, data: &[u8], flags: i32) -> bool {
        let mut sent = 0;
        while sent < data.len() {
            let mut iov = libc::iovec {
                iov_base: data[sent..].as_ptr() as *mut libc::c_void,
                iov_len: data.len() - sent,
            };
            let msg = msghdr(&mut iov, std::ptr::null(), 0);
            // SAFETY: the msghdr and what it points at are alive for the call.
            let n = unsafe { libc::sendmsg(fd, &msg, flags) };
            if n <= 0 {
                return false;
            }
            sent += n as usize;
        }
        true
    }

    fn pair(ty: i32) -> Option<(i32, i32)> {
        let mut fds = [-1; 2];
        // SAFETY: socketpair writes two descriptors into the array.
        (unsafe { libc::socketpair(libc::AF_UNIX, ty, 0, fds.as_mut_ptr()) } == 0)
            .then_some((fds[0], fds[1]))
    }

    /// A pipe's write end, carried over a stream pair with `SCM_RIGHTS`, writes into the pipe.
    fn carries_descriptors() -> bool {
        let Some((a, b)) = pair(libc::SOCK_STREAM) else {
            return false;
        };
        let mut pipe = [-1; 2];
        // SAFETY: pipe writes two descriptors into the array.
        if unsafe { libc::pipe(pipe.as_mut_ptr()) } != 0 {
            return false;
        }
        #[repr(C, align(8))]
        struct Cmsg([u8; 64]);
        let mut cmsg = Cmsg([0u8; 64]);
        let byte = *b"r";
        let mut iov = libc::iovec {
            iov_base: byte.as_ptr() as *mut libc::c_void,
            iov_len: 1,
        };
        // SAFETY: the control buffer is aligned and larger than CMSG_SPACE(4); every pointer
        // refers to a local alive across the calls.
        unsafe {
            let mut msg = msghdr(&mut iov, std::ptr::null(), 0);
            msg.msg_control = cmsg.0.as_mut_ptr().cast();
            msg.msg_controllen = libc::CMSG_SPACE(4) as _;
            let c = libc::CMSG_FIRSTHDR(&msg);
            (*c).cmsg_level = libc::SOL_SOCKET;
            (*c).cmsg_type = libc::SCM_RIGHTS;
            (*c).cmsg_len = libc::CMSG_LEN(4) as _;
            std::ptr::copy_nonoverlapping(
                (&pipe[1] as *const i32).cast::<u8>(),
                libc::CMSG_DATA(c),
                4,
            );
            if libc::sendmsg(a, &msg, libc::MSG_NOSIGNAL) != 1 {
                return false;
            }
            libc::close(pipe[1]);
            let mut back = Cmsg([0u8; 64]);
            let mut got = [0u8; 1];
            let mut riov = libc::iovec {
                iov_base: got.as_mut_ptr().cast(),
                iov_len: 1,
            };
            let mut rmsg = msghdr(&mut riov, std::ptr::null(), 0);
            rmsg.msg_control = back.0.as_mut_ptr().cast();
            rmsg.msg_controllen = back.0.len() as _;
            if libc::recvmsg(b, &mut rmsg, 0) != 1 || got[0] != b'r' {
                return false;
            }
            let c = libc::CMSG_FIRSTHDR(&rmsg);
            if c.is_null() || (*c).cmsg_type != libc::SCM_RIGHTS {
                return false;
            }
            let mut fd = -1i32;
            std::ptr::copy_nonoverlapping(
                libc::CMSG_DATA(c),
                (&mut fd as *mut i32).cast::<u8>(),
                4,
            );
            if libc::write(fd, b"p".as_ptr().cast(), 1) != 1 {
                return false;
            }
            let mut out = [0u8; 1];
            libc::read(pipe[0], out.as_mut_ptr().cast(), 1) == 1 && out[0] == b'p'
        }
    }

    /// An `RTM_GETLINK` dump request to the kernel, by `sendmsg` with a netlink destination, is
    /// answered.
    fn route_netlink() -> bool {
        let fd = socket(libc::AF_NETLINK, libc::SOCK_RAW, libc::NETLINK_ROUTE);
        if fd < 0 {
            return false;
        }
        // nlmsghdr (16) + rtgenmsg (1), padded to 20.
        let mut req = [0u8; 20];
        req[0..4].copy_from_slice(&20u32.to_ne_bytes());
        req[4..6].copy_from_slice(&libc::RTM_GETLINK.to_ne_bytes());
        let flags = (libc::NLM_F_REQUEST | libc::NLM_F_DUMP) as u16;
        req[6..8].copy_from_slice(&flags.to_ne_bytes());
        req[8..12].copy_from_slice(&1u32.to_ne_bytes());
        req[16] = libc::AF_UNSPEC as u8;
        // SAFETY: an all-zero sockaddr_nl names the kernel.
        let mut kernel: libc::sockaddr_nl = unsafe { zeroed() };
        kernel.nl_family = libc::AF_NETLINK as libc::sa_family_t;
        let mut iov = libc::iovec {
            iov_base: req.as_mut_ptr().cast(),
            iov_len: req.len(),
        };
        let msg = msghdr(
            &mut iov,
            (&kernel as *const libc::sockaddr_nl).cast(),
            size_of::<libc::sockaddr_nl>(),
        );
        // SAFETY: the msghdr and what it points at are alive for the call.
        if unsafe { libc::sendmsg(fd, &msg, 0) } != req.len() as isize {
            return false;
        }
        let mut buf = vec![0u8; 1 << 16];
        // SAFETY: recv into a buffer the probe owns.
        let n = unsafe { libc::recv(fd, buf.as_mut_ptr().cast(), buf.len(), 0) };
        n >= 16 && {
            let kind = u16::from_ne_bytes([buf[4], buf[5]]);
            kind == libc::RTM_NEWLINK || kind == libc::NLMSG_DONE as u16
        }
    }

    /// A blocking `sendmsg` that waits for a full socket does not hold up another thread's
    /// `connect()` to the Gateway.
    fn blocking_does_not_stall(gateway: SocketAddrV4) -> bool {
        let Some((a, b)) = pair(libc::SOCK_STREAM) else {
            return false;
        };
        let payload = vec![b'b'; 1 << 20];
        let connected = Arc::new(AtomicBool::new(false));
        let reader = {
            let connected = connected.clone();
            std::thread::spawn(move || {
                let fd = tcp();
                let ok = fd >= 0 && connect_in(fd, gateway);
                connected.store(ok, Ordering::SeqCst);
                // Drain only after the connect, so the sender stays blocked until then.
                let mut buf = vec![0u8; 1 << 16];
                let mut total = 0;
                while total < 1 << 20 {
                    // SAFETY: read into a buffer this thread owns.
                    let n = unsafe { libc::read(b, buf.as_mut_ptr().cast(), buf.len()) };
                    if n <= 0 {
                        break;
                    }
                    total += n as usize;
                }
                ok && total == 1 << 20
            })
        };
        let sent = send_all(a, &payload, libc::MSG_NOSIGNAL);
        sent && reader.join().unwrap_or(false) && connected.load(Ordering::SeqCst)
    }

    static PIPES: AtomicUsize = AtomicUsize::new(0);

    extern "C" fn on_sigpipe(_: libc::c_int) {
        PIPES.fetch_add(1, Ordering::SeqCst);
    }

    /// A send to a closed peer fails with `EPIPE`, and raises `SIGPIPE` only without
    /// `MSG_NOSIGNAL`.
    fn broken_pipe() -> bool {
        // SAFETY: installs an async-signal-safe handler.
        unsafe { libc::signal(libc::SIGPIPE, on_sigpipe as *const () as libc::sighandler_t) };
        let Some((a, b)) = pair(libc::SOCK_STREAM) else {
            return false;
        };
        // SAFETY: closing a descriptor the probe owns.
        unsafe { libc::close(b) };
        let quiet = !send_all(a, b"q", libc::MSG_NOSIGNAL) && errno() == libc::EPIPE;
        let after_quiet = PIPES.load(Ordering::SeqCst);
        let loud = !send_all(a, b"l", 0) && errno() == libc::EPIPE;
        let deadline = Instant::now() + Duration::from_secs(2);
        while PIPES.load(Ordering::SeqCst) == after_quiet && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(5));
        }
        quiet && after_quiet == 0 && loud && PIPES.load(Ordering::SeqCst) == 1
    }

    fn connected(gateway: SocketAddrV4) -> i32 {
        // A supervisor that blocks on one send while the other waits on it never answers either:
        // the alarm turns that into a failure rather than a hang.
        // SAFETY: alarm takes a scalar.
        unsafe { libc::alarm(20) };
        let fd = tcp();
        if fd < 0 || !connect_in(fd, gateway) || !send_all(fd, b"abc", libc::MSG_NOSIGNAL) {
            return 11;
        }
        if !carries_descriptors() {
            return 12;
        }
        if !route_netlink() {
            return 13;
        }
        if !blocking_does_not_stall(gateway) {
            return 14;
        }
        if !broken_pipe() {
            return 15;
        }
        // SAFETY: alarm takes a scalar.
        unsafe { libc::alarm(0) };
        0
    }

    /// Run `send` repeatedly for `ms` milliseconds while `flip` runs on another thread.
    fn race(ms: u64, flip: impl FnMut() + Send + 'static, mut send: impl FnMut()) {
        let stop = Arc::new(AtomicBool::new(false));
        let flipper = {
            let stop = stop.clone();
            let mut flip = flip;
            std::thread::spawn(move || {
                while !stop.load(Ordering::Relaxed) {
                    flip();
                }
            })
        };
        let deadline = Instant::now() + Duration::from_millis(ms);
        while Instant::now() < deadline {
            send();
        }
        stop.store(true, Ordering::Relaxed);
        let _ = flipper.join();
    }

    /// A leaked `msghdr` and its iovec, shared with a thread that rewrites them.
    fn shared_msghdr() -> usize {
        let byte: &'static [u8] = b"r";
        let iov: &'static mut libc::iovec = Box::leak(Box::new(libc::iovec {
            iov_base: byte.as_ptr() as *mut libc::c_void,
            iov_len: 1,
        }));
        Box::leak(Box::new(msghdr(iov, std::ptr::null(), 0))) as *mut libc::msghdr as usize
    }

    /// Point the shared `msghdr` at `name` (`len` bytes), or at nothing.
    fn aim(msg: usize, name: usize, len: usize) {
        // SAFETY: a deliberate data race on leaked buffers -- the point of the probe.
        unsafe {
            let m = msg as *mut libc::msghdr;
            std::ptr::write_volatile(&mut (*m).msg_name, name as *mut libc::c_void);
            std::ptr::write_volatile(&mut (*m).msg_namelen, len as libc::socklen_t);
        }
    }

    fn leak_un(path: &str) -> (usize, usize) {
        let (sun, len) = sockaddr_un(path);
        (
            Box::leak(Box::new(sun)) as *mut libc::sockaddr_un as usize,
            len as usize,
        )
    }

    fn rewrite(own: &str, foreign: &str, ms: u64) -> i32 {
        let (rx, tx) = (dgram(), dgram());
        let (sun, len) = sockaddr_un(own);
        // SAFETY: bind reads one sockaddr_un alive for the call.
        if rx < 0
            || tx < 0
            || unsafe { libc::bind(rx, (&sun as *const libc::sockaddr_un).cast(), len) } != 0
        {
            return 8;
        }
        if !connect_un(tx, own) {
            return 8;
        }
        let msg = shared_msghdr();
        let (own_at, own_len) = leak_un(own);
        let (foreign_at, foreign_len) = leak_un(foreign);
        let mut state = 0;
        race(
            ms,
            move || {
                match state {
                    0 => aim(msg, 0, 0),
                    1 => aim(msg, own_at, own_len),
                    _ => aim(msg, foreign_at, foreign_len),
                }
                state = (state + 1) % 3;
            },
            || {
                // SAFETY: the racing msghdr points at leaked buffers.
                unsafe { libc::sendmsg(tx, msg as *const libc::msghdr, libc::MSG_DONTWAIT) };
                let mut buf = [0u8; 4];
                // SAFETY: drain into a stack buffer so the receiver never fills.
                while unsafe { libc::recv(rx, buf.as_mut_ptr().cast(), 4, libc::MSG_DONTWAIT) } > 0
                {
                }
            },
        );
        0
    }

    fn fdswap(foreign: &str, to: SocketAddrV4, ms: u64) -> i32 {
        let (stream, datagram) = (tcp(), dgram());
        if stream < 0 || datagram < 0 || !connect_in(stream, to) {
            return 8;
        }
        // SAFETY: dup() takes a scalar; the descriptor is owned by the probe.
        let number = unsafe { libc::dup(stream) };
        if number < 0 {
            return 8;
        }
        let msg = shared_msghdr();
        let (foreign_at, foreign_len) = leak_un(foreign);
        let mut state = 0;
        race(
            ms,
            move || {
                // SAFETY: dup2 between descriptors owned by this process.
                unsafe { libc::dup2(if state & 1 == 0 { stream } else { datagram }, number) };
                if state & 2 == 0 {
                    aim(msg, 0, 0);
                } else {
                    aim(msg, foreign_at, foreign_len);
                }
                state = (state + 1) % 4;
            },
            || {
                // SAFETY: the racing msghdr points at leaked buffers.
                unsafe {
                    libc::sendmsg(
                        number,
                        msg as *const libc::msghdr,
                        libc::MSG_DONTWAIT | libc::MSG_NOSIGNAL,
                    )
                };
            },
        );
        0
    }

    fn nlswap_send(foreign: &str, ms: u64) -> i32 {
        let (nl, datagram) = (
            socket(libc::AF_NETLINK, libc::SOCK_RAW, libc::NETLINK_ROUTE),
            dgram(),
        );
        // SAFETY: dup() takes a scalar; the descriptor is owned by the probe.
        let number = unsafe { libc::dup(nl) };
        if nl < 0 || datagram < 0 || number < 0 {
            return 8;
        }
        // One destination buffer, rewritten between a netlink address and `foreign`.
        // SAFETY: an all-zero sockaddr_nl names the kernel.
        let mut kernel: libc::sockaddr_nl = unsafe { zeroed() };
        kernel.nl_family = libc::AF_NETLINK as libc::sa_family_t;
        let (sun, sun_len) = sockaddr_un(foreign);
        let dest: &'static mut libc::sockaddr_un = Box::leak(Box::new(sun));
        let dest_at = dest as *mut libc::sockaddr_un as usize;
        let msg = shared_msghdr();
        aim(msg, dest_at, sun_len as usize);
        let mut state = 0;
        race(
            ms,
            move || {
                // SAFETY: dup2 between descriptors owned by this process; a deliberate data race
                // on the leaked destination buffer.
                unsafe {
                    if state == 0 {
                        libc::dup2(nl, number);
                        std::ptr::write_volatile(dest_at as *mut libc::sockaddr_nl, kernel);
                    } else {
                        libc::dup2(datagram, number);
                        std::ptr::write_volatile(dest_at as *mut libc::sockaddr_un, sun);
                    }
                }
                state ^= 1;
            },
            || {
                // SAFETY: the racing msghdr points at leaked buffers.
                unsafe { libc::sendmsg(number, msg as *const libc::msghdr, libc::MSG_DONTWAIT) };
            },
        );
        0
    }

    fn connected_to(fd: i32) -> bool {
        // SAFETY: getpeername writes at most `len` bytes into the zeroed storage.
        unsafe {
            let mut ss: libc::sockaddr_storage = zeroed();
            let mut len = size_of::<libc::sockaddr_storage>() as libc::socklen_t;
            libc::getpeername(
                fd,
                (&mut ss as *mut libc::sockaddr_storage).cast(),
                &mut len,
            ) == 0
        }
    }

    fn nlswap(to: SocketAddrV4, ms: u64) -> i32 {
        let nl = socket(libc::AF_NETLINK, libc::SOCK_RAW, libc::NETLINK_ROUTE);
        // SAFETY: dup() takes a scalar; the descriptor is owned by the probe.
        let number = unsafe { libc::dup(nl) };
        let first = tcp();
        if nl < 0 || number < 0 || first < 0 {
            return 8;
        }
        let current = Arc::new(AtomicI32::new(first));
        let stop = Arc::new(AtomicBool::new(false));
        let flipper = {
            let (current, stop) = (current.clone(), stop.clone());
            std::thread::spawn(move || {
                while !stop.load(Ordering::Relaxed) {
                    // SAFETY: dup2 between descriptors owned by this process.
                    unsafe {
                        libc::dup2(nl, number);
                        libc::dup2(current.load(Ordering::Relaxed), number);
                    }
                }
            })
        };
        let dest = sockaddr_in(to);
        let deadline = Instant::now() + Duration::from_millis(ms);
        let mut escaped = false;
        while Instant::now() < deadline && !escaped {
            // SAFETY: connect reads one sockaddr_in alive for the call.
            unsafe {
                libc::connect(
                    number,
                    (&dest as *const libc::sockaddr_in).cast(),
                    size_of::<libc::sockaddr_in>() as libc::socklen_t,
                );
            }
            let fd = current.load(Ordering::Relaxed);
            if connected_to(fd) {
                escaped = true;
            } else {
                // A refused or failed attempt can leave the socket unusable for another try.
                let fresh = tcp();
                if fresh >= 0 {
                    current.store(fresh, Ordering::Relaxed);
                    // SAFETY: the old socket is no longer published to the flipper.
                    unsafe { libc::close(fd) };
                }
            }
        }
        stop.store(true, Ordering::Relaxed);
        let _ = flipper.join();
        if escaped {
            23
        } else {
            0
        }
    }

    fn drain(fd: i32) {
        std::thread::spawn(move || {
            let mut buf = vec![0u8; 1 << 16];
            // SAFETY: read into a buffer owned by this thread.
            while unsafe { libc::read(fd, buf.as_mut_ptr().cast(), buf.len()) } > 0 {}
        });
    }

    fn bench(to: Option<SocketAddrV4>, bytes: usize, count: u32, out: &str) -> i32 {
        let fd = match to {
            Some(to) => {
                let fd = tcp();
                if fd < 0 || !connect_in(fd, to) {
                    return 8;
                }
                fd
            }
            None => match pair(libc::SOCK_STREAM) {
                Some((a, b)) => {
                    drain(b);
                    a
                }
                None => return 8,
            },
        };
        let payload = vec![b'x'; bytes];
        let start = Instant::now();
        for _ in 0..count {
            if !send_all(fd, &payload, libc::MSG_NOSIGNAL) {
                return 8;
            }
        }
        let ns = start.elapsed().as_nanos() / u128::from(count.max(1));
        match std::fs::write(out, ns.to_string()) {
            Ok(()) => 0,
            Err(_) => 8,
        }
    }

    pub fn main() -> i32 {
        let args: Vec<String> = std::env::args().skip(1).collect();
        let arg = |i: usize| args.get(i).map(String::as_str);
        let num = |i: usize| arg(i).and_then(|v| v.parse::<u64>().ok());
        let addr = |i: usize| arg(i).and_then(|v| v.parse::<SocketAddrV4>().ok());
        match (arg(0), arg(1), arg(2)) {
            (Some("sendmsg"), Some(p), _) => one(p, false),
            (Some("sendmmsg1"), Some(p), _) => one(p, true),
            (Some("own"), Some(p), _) => own(p),
            (Some("mixed"), Some(g), Some(f)) => mixed(g, f, false),
            (Some("mixed-connected"), Some(g), Some(f)) => mixed(g, f, true),
            (Some("inet"), Some(_), _) => addr(1).map_or(8, inet),
            (Some("connected"), Some(_), _) => addr(1).map_or(8, connected),
            (Some("rewrite"), Some(o), Some(f)) => rewrite(o, f, num(3).unwrap_or(300)),
            (Some("fdswap"), Some(f), Some(_)) => {
                addr(2).map_or(8, |to| fdswap(f, to, num(3).unwrap_or(300)))
            }
            (Some("nlswap-send"), Some(f), _) => nlswap_send(f, num(2).unwrap_or(300)),
            (Some("nlswap"), Some(_), _) => {
                addr(1).map_or(8, |to| nlswap(to, num(2).unwrap_or(300)))
            }
            (Some("bench"), Some(kind), _) => {
                let (to, rest) = match kind {
                    "pair" => (None, 2),
                    "tcp" => match addr(2) {
                        Some(to) => (Some(to), 3),
                        None => return 8,
                    },
                    _ => return 8,
                };
                match (num(rest), num(rest + 1), arg(rest + 2)) {
                    (Some(bytes), Some(count), Some(out)) => {
                        bench(to, bytes as usize, count as u32, out)
                    }
                    _ => 8,
                }
            }
            _ => 8,
        }
    }
}

#[cfg(target_os = "linux")]
fn main() {
    std::process::exit(probe::main());
}

#[cfg(not(target_os = "linux"))]
fn main() {}
