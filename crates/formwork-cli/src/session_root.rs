//! The session root (FW-TRA18): the one directory holding every path the Launcher creates for a
//! session.
//!
//! ```text
//! <runtime>/formwork/<session-id>/    0700, owned by the invoking uid
//!     .lock      held with flock for the session's life (FW-TRA21)
//!     tmp/       the session's TMPDIR (FW-TRA10); the only part the session may write
//!     opener/    the opener shim (FW-ISO17)
//!     trust/     the inspection trust bundle (FW-EGR13)
//! ```
//!
//! `<runtime>` is never a shared temp root: a profile commonly grants `/tmp/**` for writing, and
//! a root there is reachable by every other session of the user. Placement protects the default
//! profile only; the compiled policy closes every root but the session's own under any blueprint
//! (FW-TRA19, [`SessionRoot::policy_roots`]).

use std::fs::{DirBuilder, File, OpenOptions};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

use anyhow::{anyhow, bail, Context, Result};
use formwork_blueprint::PathPattern;

/// The per-user directory the platform gives a login session: the XDG runtime directory, or on
/// macOS the per-user temporary directory under `/var/folders`.
const RUNTIME_VAR: &str = if cfg!(target_os = "macos") {
    "TMPDIR"
} else {
    "XDG_RUNTIME_DIR"
};

/// Where the roots go when `RUNTIME_VAR` does not name a private directory.
const FALLBACK: &str = ".local/state";

const PARENT_NAME: &str = "formwork";
const LOCK_NAME: &str = ".lock";
/// 128 bits from the OS random source, hex-encoded: a name another session cannot predict.
const ID_LEN: usize = 32;

pub struct SessionRoot {
    parent: PathBuf,
    path: PathBuf,
    tmp: PathBuf,
    /// Released when this process ends, however it ends; the next Launcher then removes the root.
    lock: File,
    removed: bool,
}

impl SessionRoot {
    /// Remove every dead session's root, then create and lock this session's. Both happen under
    /// a lock on the parent directory, so no Launcher sees a root between its creation and its
    /// lock.
    pub fn create() -> Result<SessionRoot> {
        let parent = parent_dir()?;
        let guard = lock_parent(&parent)?;
        remove_dead_roots(&parent);
        let path = parent.join(session_id()?);
        DirBuilder::new()
            .mode(0o700)
            .create(&path)
            .with_context(|| format!("creating the session root {}", path.display()))?;
        let created = (|| -> Result<(File, PathBuf)> {
            let lock = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(path.join(LOCK_NAME))
                .context("creating the session lock")?;
            flock(&lock, libc::LOCK_EX | libc::LOCK_NB).context("locking the session root")?;
            let tmp = path.join("tmp");
            DirBuilder::new()
                .mode(0o700)
                .create(&tmp)
                .context("creating the session temp directory")?;
            Ok((lock, tmp))
        })();
        let (lock, tmp) = match created {
            Ok(parts) => parts,
            Err(e) => {
                let _ = std::fs::remove_dir_all(&path);
                return Err(e.context(format!("preparing the session root {}", path.display())));
            }
        };
        drop(guard);
        Ok(SessionRoot {
            parent,
            path,
            tmp,
            lock,
            removed: false,
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// The private temporary directory (FW-TRA10).
    pub fn tmp(&self) -> &Path {
        &self.tmp
    }

    /// A fresh 0700 directory in the root, for files the session reads and never writes.
    pub fn subdir(&self, name: &str) -> Result<PathBuf> {
        let dir = self.path.join(name);
        DirBuilder::new()
            .mode(0o700)
            .create(&dir)
            .with_context(|| format!("creating the session directory {}", dir.display()))?;
        Ok(dir)
    }

    /// What the compiled policy needs to close every other session's root (FW-TRA19). A path
    /// that cannot be rendered faithfully fails loud: a deny that silently did not match would
    /// leave the other roots open (FW-INV6).
    pub fn policy_roots(&self) -> Result<formwork_compile::SessionRoots> {
        let literal = |path: &Path| -> Result<PathPattern> {
            let rendered = path
                .to_str()
                .ok_or_else(|| anyhow!("{} is not valid UTF-8 (FW-INV6)", path.display()))?;
            PathPattern::parse(rendered).with_context(|| format!("naming {rendered} in the policy"))
        };
        Ok(formwork_compile::SessionRoots {
            parent: literal(&self.parent)?,
            own: literal(&self.path)?,
            tmp: literal(&self.tmp)?,
        })
    }

    /// FW-TRA20. Idempotent; also runs on drop, for the paths that return an error.
    pub fn remove(&mut self) {
        if !std::mem::replace(&mut self.removed, true) {
            if let Err(e) = std::fs::remove_dir_all(&self.path) {
                tracing::warn!(root = %self.path.display(), error = %e, "could not remove the session root");
            }
        }
    }

    /// `run --confine-self` execs the workload in place: no Launcher remains to remove the root,
    /// so the workload inherits the lock and the root stays, locked, until its last process
    /// exits. The next Launcher removes it (FW-TRA21).
    pub fn outlive_this_process(&self) -> std::io::Result<()> {
        // SAFETY: F_SETFD on a descriptor this struct owns.
        if unsafe { libc::fcntl(self.lock.as_raw_fd(), libc::F_SETFD, 0) } != 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(())
    }
}

impl Drop for SessionRoot {
    fn drop(&mut self) {
        self.remove();
    }
}

/// FW-TRA21 for a Launcher that creates no root of its own: remove what its child left.
pub fn remove_dead_session_roots() -> Result<()> {
    let parent = parent_dir()?;
    let _guard = lock_parent(&parent)?;
    remove_dead_roots(&parent);
    Ok(())
}

fn runtime_dir() -> Result<PathBuf> {
    // SAFETY: geteuid has no failure modes.
    let uid = unsafe { libc::geteuid() };
    if let Some(dir) = std::env::var_os(RUNTIME_VAR).map(PathBuf::from) {
        let private = dir.is_absolute()
            && std::fs::metadata(&dir)
                .map(|m| m.is_dir() && m.uid() == uid && m.mode() & 0o777 == 0o700)
                .unwrap_or(false);
        if private {
            return Ok(dir);
        }
        tracing::debug!(
            var = RUNTIME_VAR,
            dir = %dir.display(),
            "not an absolute 0700 directory of this user; session roots go under ~/{FALLBACK}"
        );
    }
    let home = std::env::var_os("HOME")
        .map(PathBuf::from)
        .filter(|h| h.is_absolute())
        .ok_or_else(|| {
            anyhow!(
                "no directory for the session root: {RUNTIME_VAR} does not name an absolute 0700 \
                 directory owned by uid {uid}, and HOME is not an absolute path (FW-TRA18)"
            )
        })?;
    let dir = home.join(FALLBACK);
    DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(&dir)
        .with_context(|| format!("creating {} for the session root (FW-TRA18)", dir.display()))?;
    Ok(dir)
}

/// `<runtime>/formwork`, created 0700 and resolved. Refused unless it is a directory of the
/// invoking uid that no other uid can write (FW-TRA18): a root created in a directory someone
/// else controls could be replaced under the session.
fn parent_dir() -> Result<PathBuf> {
    let parent = runtime_dir()?.join(PARENT_NAME);
    match DirBuilder::new().mode(0o700).create(&parent) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(e) => {
            return Err(e).with_context(|| {
                format!(
                    "creating {} for the session root (FW-TRA18)",
                    parent.display()
                )
            })
        }
    }
    let meta = std::fs::symlink_metadata(&parent)
        .with_context(|| format!("inspecting {}", parent.display()))?;
    // SAFETY: geteuid has no failure modes.
    let uid = unsafe { libc::geteuid() };
    if !meta.is_dir() || meta.uid() != uid || meta.mode() & 0o022 != 0 {
        bail!(
            "{} must be a directory owned by uid {uid} that no one else can write; refusing to \
             keep session state there (FW-TRA18)",
            parent.display()
        );
    }
    std::fs::canonicalize(&parent).with_context(|| format!("resolving {}", parent.display()))
}

fn session_id() -> Result<String> {
    let mut id = crate::session_nonce()?;
    id.truncate(ID_LEN);
    Ok(id)
}

fn is_session_id(name: &std::ffi::OsStr) -> bool {
    name.to_str()
        .is_some_and(|n| n.len() == ID_LEN && n.bytes().all(|b| b.is_ascii_hexdigit()))
}

/// Serializes creation and removal across Launchers; released when the returned file closes.
fn lock_parent(parent: &Path) -> Result<File> {
    let dir = File::open(parent).with_context(|| format!("opening {}", parent.display()))?;
    flock(&dir, libc::LOCK_EX).with_context(|| format!("locking {}", parent.display()))?;
    Ok(dir)
}

/// FW-TRA21. Call with the parent locked. A root this cannot remove is left for the next
/// Launcher; every session is denied it meanwhile (FW-TRA19).
fn remove_dead_roots(parent: &Path) {
    let Ok(entries) = std::fs::read_dir(parent) else {
        return;
    };
    for entry in entries.flatten() {
        // Only what a Launcher created: a directory (never a link to one) named by a session id.
        let is_dir = entry.file_type().map(|t| t.is_dir()).unwrap_or(false);
        if !is_dir || !is_session_id(&entry.file_name()) {
            continue;
        }
        let root = entry.path();
        let Some(_held) = dead_session_lock(&root) else {
            continue;
        };
        match std::fs::remove_dir_all(&root) {
            Ok(()) => {
                tracing::info!(root = %root.display(), "removed a dead session's root (FW-TRA21)")
            }
            Err(e) => {
                tracing::warn!(root = %root.display(), error = %e, "could not remove a dead session's root")
            }
        }
    }
}

/// The root's lock, acquired, when its session is dead: no process holds the lock, or the root
/// has none, which under the parent lock means its creation never finished. `None` for a live
/// session and for a lock that cannot be examined.
fn dead_session_lock(root: &Path) -> Option<Option<File>> {
    match OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(root.join(LOCK_NAME))
    {
        Ok(lock) => flock(&lock, libc::LOCK_EX | libc::LOCK_NB)
            .is_ok()
            .then_some(Some(lock)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Some(None),
        Err(_) => None,
    }
}

fn flock(file: &File, operation: libc::c_int) -> std::io::Result<()> {
    loop {
        // SAFETY: flock on a descriptor the caller owns.
        if unsafe { libc::flock(file.as_raw_fd(), operation) } == 0 {
            return Ok(());
        }
        let e = std::io::Error::last_os_error();
        if e.kind() != std::io::ErrorKind::Interrupted {
            return Err(e);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_a_session_id_names_a_root_the_launcher_may_remove() {
        assert!(is_session_id(std::ffi::OsStr::new(
            "0123456789abcdef0123456789abcdef"
        )));
        for other in ["", "sessions", "0123456789abcdef0123456789abcde", ".lock"] {
            assert!(!is_session_id(std::ffi::OsStr::new(other)), "{other}");
        }
    }
}
