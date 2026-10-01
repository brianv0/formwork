# macOS characterization

FEP-5 §6.3 asked a set of questions only a real macOS host answers: what an SBPL rule admits,
which service a channel's client reaches, and what Seatbelt leaves unmediated. This records the
answers as observed on GitHub's hosted `macos-14` (14.8) and `macos-15` runners, and what Formwork
does with each. The answers are not prose only: each is an assertion in
`crates/formwork-confine/tests/macos_characterize.rs` (C1–C8) or a requirement test through
`formwork run` (`crates/formwork-cli/tests/fep5_macos.rs`, `fep6_run.rs`). CI runs them on both
releases with `FW_REQUIRE_EXERCISED=1`, so a release that behaves differently fails the build
instead of widening the sandbox unnoticed.

The runners are virtual machines with System Integrity Protection disabled and Developer Mode on.
Nothing below depends on either, but a characterization on a SIP-enabled physical Mac is still
worth repeating before a release that changes the verdicts.

## The answers

| # | Question | Observed on 14 and 15 | What Formwork does |
|---|---|---|---|
| C1 | Do SBPL remote filters take only `*` or `localhost`? | Yes: `(remote tcp "127.0.0.1:80")` fails to compile with "host must be * or localhost". `localhost:<P>` admits 127.0.0.1 and ::1 on that port, nothing else. In a **local** filter `localhost` matches every local address: under `(allow network-bind/network-inbound (local ip "localhost:*"))` a process listens on the wildcard address and on the host's network address, and accepts a connection to it | The profile names the Gateway by port; the peer check authenticates the connection (C2). `net-default-deny` is `Partial` on macOS: the loopback-callback grant (`FW-EGR15`) also listens on the host's other addresses |
| C2 | Is the peer lookup reliable under churn and for reparented descendants? | Yes: 1,000 connections from a confined tree that is still forking, 10 % from reparented grandchildren, are each attributed to the session; an unconfined process's connection is not. `struct socket_fdinfo` is 792 bytes, `in_sockinfo` at offset 264 | The listener admits a connection only when a process carrying the session marker holds its client end (`FW-EGR9`); `net-host-scope` is `Enforced` |
| C3 | Which Mach services do the channel clients reach? | `pbcopy`/`pbpaste`: `com.apple.pasteboard.1`. `screencapture`: `com.apple.windowserver.active` and `com.apple.CARenderServer` (and `com.apple.replayd` on 15; denying only replayd and screencapture leaves 14 open). `security`: `com.apple.SecurityServer`. `osascript`: `com.apple.coreservices.appleevents` plus `appleevent-send`. `launchctl submit`: the `job-creation` operation | The map in `formwork-compile` (`CHANNEL_SERVICES`); the screen channel now denies WindowServer, run-outside denies `job-creation`, and the keychain's services are denied until `os-keyring` is lifted. TLS clients (curl, git, Node, URLSession, Go) verify through `trustd` and are unaffected |
| C4 | Are `lsopen` and `appleevent-send` checked for a `sandbox_init` process? | Yes: under `(allow default)` both work, and `(deny lsopen)` / `(deny appleevent-send)` close them with a record. Two services refuse every sandboxed caller whatever the profile: launchd denies `job-creation`, and System Events answers a sandboxed sender with a privilege violation (-10004) | Both stay denied; lifting `run-outside` on macOS does not reach launchd or System Events |
| C5 | Does `kern.procargs2` return same-uid environments, and does a deny close it? | It returns them, and nothing closes it: not `(deny sysctl-read (sysctl-name "kern.procargs2"))`, not `(deny sysctl-read)` whole, not `(deny process-info*)`. A process that overwrites its own exec-time strings is read as blank. No sandboxed process may exec a setuid binary (`ps`, `sudo`, `top`): `forbidden-exec-sugid` | `process-environment` is `Unenforceable` on macOS. `formwork` zeroes its own exec-time environment first thing in `main`, so the operator's credentials -- a brokered one included -- are not readable from the session |
| C6 | Which `(target …)` forms keep in-session process management working? | `self`, `children`, `pgrp`, `others` and `same-sandbox` compile (`descendants` does not). `others` excludes the session's process group, which holds `formwork` and whatever shares its job. `(deny signal)` with `(allow signal (target same-sandbox))` keeps job control, `multiprocessing`, `make -j`, Node's child processes and reparented descendants working, and refuses the parent and other processes. `sysctl` still lists every pid and argument vector | `isolate = ["processes"]` denies `signal` and `process-info*` whole and re-allows `same-sandbox` (and pid listing); the verdict is `Partial`, naming what stays visible |
| C7 | Can POSIX IPC be confined to a session prefix? | Not without breaking tools: under an `ipc-posix-name-prefix` rule Python's `multiprocessing` cannot create its semaphore (`/mp-…`) or shared memory (`/psm_…`), which it names itself | `isolate = ["ipc"]` denies SysV IPC; POSIX names stay global, `Partial` |
| C8 | What does the toolchain need from IOKit? | Nothing: git, Python, cc, cargo, curl, xcrun, caffeinate, URLSession and `swift build` run with `iokit-open` denied outright. Metal opens the GPU's user client (`AppleParavirtDeviceUserClient` on the runners) and `IOSurfaceRootUserClient`; `screencapture` the latter. SwiftPM applies its own sandbox to the manifest build, which no sandboxed process may do: a session runs `swift build --disable-sandbox` | IOKit stays open: an allowlist built from a paravirtual GPU's class names would break GPU work on real hardware. `privileged-interfaces` is `Partial` with that reason |
| C9 | Claude Code's keychain item and login flow | Claude Code (`claude.exe`, signed `com.anthropic.claude-code`) looks up `com.apple.SecurityServer` and `com.apple.securityd.xpc` and shells out through `PATH`: `security find-generic-password -a <user> -w -s "Claude Code-credentials"`, then the same for `"Claude Code"`. Without a login `claude -p` prints `Not logged in · Please run /login`, exits 1 and opens no browser. The `agent-examples` macOS job records the calls through a `security` shim, unconfined and in the session | The `claude` type lists the keychain's services, so `allow-credentials = ["claude"]` lifts the keychain on macOS (FEP-5 §3.4); `com.apple.securityd.xpc` joins the `os-keyring` services |
| — | `confstr(_CS_DARWIN_USER_TEMP_DIR)` | The per-user directory, whatever `TMPDIR` says | The session's `TMPDIR` is the per-session directory; the per-user one is not granted |
| — | `PT_DENY_ATTACH` (`FW-CRED16`) | `lldb` attaches to a plain process and fails to attach to one that called it ("attach failed") | The Gateway calls it before spawning a workload whose blueprint brokers a credential |
| — | Attributing a Sandbox record to its session | A `(with message "…")` modifier on a deny appends the text to the record, on its own line | Every deny in a spawned session's profile carries a per-session tag; macOS `learn` keeps only the records that carry it |

## How the tests decide

Every negative test runs its probe unconfined first and asserts the channel is live on the runner
(FEP-5 §6.1): the fixture app writes its marker, the clipboard round-trips, System Events creates
the folder, the keychain item reads back. The confined run must then fail, leave no marker, and
leave the Sandbox record the unified log persisted; the tests poll `log show` for the record, since
the store persists lazily. Markers land in a directory no session may write.
