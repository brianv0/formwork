//! Test-support binary for FW-ADV-018: a second thread rewrites the `sockaddr` passed to
//! `connect()` between an allowed and a denied destination while the call is pending, over many
//! attempts. The supervisor must decide on its own copy of the address, so no attempt may land on
//! the denied destination; the test's listener there counts accepts.
//!
//! `fw-race-probe <allowed ip:port> <denied ip:port> <attempts>`; exits 0 when done.

#[cfg(target_os = "linux")]
use std::net::SocketAddrV4;
#[cfg(target_os = "linux")]
use std::sync::atomic::{AtomicBool, Ordering};
#[cfg(target_os = "linux")]
use std::sync::Arc;

#[cfg(target_os = "linux")]
fn raw(addr: SocketAddrV4) -> libc::sockaddr_in {
    libc::sockaddr_in {
        sin_family: libc::AF_INET as libc::sa_family_t,
        sin_port: addr.port().to_be(),
        sin_addr: libc::in_addr {
            s_addr: u32::from_ne_bytes(addr.ip().octets()),
        },
        sin_zero: [0; 8],
    }
}

#[cfg(target_os = "linux")]
fn main() {
    let mut args = std::env::args().skip(1);
    let allowed: SocketAddrV4 = args.next().and_then(|a| a.parse().ok()).expect("allowed");
    let denied: SocketAddrV4 = args.next().and_then(|a| a.parse().ok()).expect("denied");
    let attempts: usize = args.next().and_then(|a| a.parse().ok()).unwrap_or(200);
    let good = raw(allowed);
    let bad = raw(denied);
    // One shared buffer the flipper thread rewrites while `connect` reads it.
    let shared: &'static mut libc::sockaddr_in = Box::leak(Box::new(good));
    let ptr = shared as *mut libc::sockaddr_in as usize;
    let stop = Arc::new(AtomicBool::new(false));
    let flipper = {
        let stop = stop.clone();
        std::thread::spawn(move || {
            let mut toggle = false;
            while !stop.load(Ordering::Relaxed) {
                // SAFETY: a deliberate data race on a leaked buffer -- the point of the probe.
                unsafe {
                    std::ptr::write_volatile(
                        ptr as *mut libc::sockaddr_in,
                        if toggle { bad } else { good },
                    );
                }
                toggle = !toggle;
            }
        })
    };
    for _ in 0..attempts {
        // SAFETY: a socket we own and close; connect reads the racing buffer.
        unsafe {
            let fd = libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0);
            if fd < 0 {
                continue;
            }
            libc::connect(
                fd,
                ptr as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
            );
            libc::close(fd);
        }
    }
    stop.store(true, Ordering::Relaxed);
    let _ = flipper.join();
}

#[cfg(not(target_os = "linux"))]
fn main() {}
