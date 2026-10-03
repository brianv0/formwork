//! The dynamic loader an exec allow-list grants beside its binaries (FW-ISO4). `execve` of a
//! dynamically linked ELF makes the kernel open the interpreter the binary names (`PT_INTERP`) for
//! execute, and Landlock checks that open like any other: a listed binary whose loader is
//! ungranted fails with EACCES before `main`, where macOS runs it (FW-XR6). Read at enforce time,
//! like the other essentials, so `compile()` stays pure (FW-FID4).

use std::collections::BTreeSet;
use std::ffi::OsStr;
use std::fs::{File, OpenOptions};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{FileExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

use formwork_blueprint::{PathPattern, ReadMode};
use formwork_compile::{CompiledPolicy, ConfinerPolicy, ExecPlan, LinuxPolicy};

use super::landlock::READ_ESSENTIALS;

/// The loaders the psABI fixes for this architecture, glibc's and musl's: the only loaders the
/// confiner grants. A listed file's `PT_INTERP` picks among them and cannot add to them, because a
/// listed binary may be one the session can rewrite, and the next session's allow-list must not
/// follow what the agent wrote there (FW-XR8). A listed directory gets all of them rather than the
/// loader of every file beneath it: that walk grows with the tree (`/usr/**`), not the allow-list.
#[cfg(target_arch = "x86_64")]
const STANDARD_LOADERS: &[&str] = &["/lib64/ld-linux-x86-64.so.2", "/lib/ld-musl-x86_64.so.1"];
#[cfg(target_arch = "aarch64")]
const STANDARD_LOADERS: &[&str] = &["/lib/ld-linux-aarch64.so.1", "/lib/ld-musl-aarch64.so.1"];

const PT_INTERP: u64 = 3;
/// `load_elf_phdrs` refuses a program header table larger than a page.
const MAX_PHDR_TABLE: u64 = 4096;
/// `load_elf_binary` refuses an interpreter name longer than `PATH_MAX`.
const MAX_INTERP: u64 = 4096;
/// `binfmt_script` reads the `#!` line from the first `BINPRM_BUF_SIZE` bytes.
const BINPRM_BUF_SIZE: usize = 256;
/// The kernel's interpreter nesting limit for scripts run by scripts.
const MAX_SCRIPT_DEPTH: usize = 4;

/// The loaders to grant execute beside the allow-list `roots`: the standard loader each listed
/// file names, and every standard loader for a listed directory. Only loaders that exist, so the
/// list can be reported as granted.
pub(super) fn loaders_for(roots: &[PathBuf]) -> Vec<PathBuf> {
    let standard = || STANDARD_LOADERS.iter().map(PathBuf::from);
    let mut out = BTreeSet::new();
    for root in roots {
        if root.is_dir() {
            out.extend(standard());
        } else if let Some(loader) = elf_interpreter(root) {
            out.extend(standard().filter(|s| *s == loader));
        }
    }
    out.into_iter().filter(|p| p.exists()).collect()
}

/// The loaders the confiner grants beside the exec allow-list `paths` on this host, for `explain`.
pub fn granted_loaders(paths: &[PathPattern]) -> Vec<PathBuf> {
    loaders_for(
        &paths
            .iter()
            .map(|p| p.base().to_path_buf())
            .collect::<Vec<_>>(),
    )
}

/// `path` opened for reading when it is a regular file; a listed FIFO never blocks the launch.
fn open_regular(path: &Path) -> Option<File> {
    if !std::fs::metadata(path).ok()?.is_file() {
        return None;
    }
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NONBLOCK)
        .open(path)
        .ok()?;
    file.metadata().ok()?.is_file().then_some(file)
}

/// The absolute `PT_INTERP` path of the ELF at `path`. Any read or parse failure is `None`: no
/// loader is granted, and the exec fails closed.
fn elf_interpreter(path: &Path) -> Option<PathBuf> {
    let file = open_regular(path)?;
    let mut header = [0u8; 64];
    file.read_exact_at(&mut header, 0).ok()?;
    if header[..4] != *b"\x7fELF" {
        return None;
    }
    let wide = match header[4] {
        1 => false,
        2 => true,
        _ => return None,
    };
    let big = match header[5] {
        1 => false,
        2 => true,
        _ => return None,
    };
    let field = |bytes: &[u8]| -> u64 {
        let fold = |v: u64, b: &u8| (v << 8) | u64::from(*b);
        if big {
            bytes.iter().fold(0, fold)
        } else {
            bytes.iter().rev().fold(0, fold)
        }
    };
    let (phoff, phentsize, phnum, min_entry) = if wide {
        (
            field(&header[0x20..0x28]),
            field(&header[0x36..0x38]),
            field(&header[0x38..0x3a]),
            56,
        )
    } else {
        (
            field(&header[0x1c..0x20]),
            field(&header[0x2a..0x2c]),
            field(&header[0x2c..0x2e]),
            32,
        )
    };
    let table_len = phentsize * phnum;
    if phentsize < min_entry || table_len == 0 || table_len > MAX_PHDR_TABLE {
        return None;
    }
    let mut table = vec![0u8; table_len as usize];
    file.read_exact_at(&mut table, phoff).ok()?;
    let entry = table
        .chunks_exact(phentsize as usize)
        .find(|e| field(&e[0..4]) == PT_INTERP)?;
    let (offset, size) = if wide {
        (field(&entry[8..16]), field(&entry[32..40]))
    } else {
        (field(&entry[4..8]), field(&entry[16..20]))
    };
    if !(2..=MAX_INTERP).contains(&size) {
        return None;
    }
    let mut name = vec![0u8; size as usize];
    file.read_exact_at(&mut name, offset).ok()?;
    // The kernel requires the terminating NUL and reads the name as a C string.
    if name.last() != Some(&0) {
        return None;
    }
    let len = name.iter().position(|&b| b == 0)?;
    let loader = PathBuf::from(OsStr::from_bytes(&name[..len]));
    loader.is_absolute().then_some(loader)
}

/// The interpreter a `#!` script names.
fn script_interpreter(path: &Path) -> Option<PathBuf> {
    let file = open_regular(path)?;
    let mut head = [0u8; BINPRM_BUF_SIZE];
    let n = file.read_at(&mut head, 0).ok()?;
    let line = head[..n].strip_prefix(b"#!")?;
    let line = &line[..line.iter().position(|&b| b == b'\n').unwrap_or(line.len())];
    let blank = |b: &u8| *b == b' ' || *b == b'\t';
    let start = line.iter().position(|b| !blank(b))?;
    let rest = &line[start..];
    let end = rest.iter().position(blank).unwrap_or(rest.len());
    Some(PathBuf::from(OsStr::from_bytes(&rest[..end])))
}

/// What the policy grants execute and read on, resolved as Landlock binds a rule: to the inode a
/// path names, symlinks followed. `execve` opens the file it runs, and the loader, for read as well
/// as execute, so a file runs only where both cover it.
struct Grants {
    exec: Vec<PathBuf>,
    read: Vec<PathBuf>,
    holes: Vec<PathBuf>,
}

fn real(paths: impl IntoIterator<Item = PathBuf>) -> Vec<PathBuf> {
    paths
        .into_iter()
        .filter_map(|p| std::fs::canonicalize(p).ok())
        .collect()
}

impl Grants {
    /// `None` unless Landlock carries the allow-list here: without it no exec rule is installed.
    fn of(linux: &LinuxPolicy) -> Option<Grants> {
        let ExecPlan::Allowlist { paths } = &linux.exec else {
            return None;
        };
        linux.landlock_abi_target.filter(|v| *v >= 1)?;
        let base = |p: &PathPattern| p.base().to_path_buf();
        let roots: Vec<PathBuf> = paths.iter().map(base).collect();
        let mut read: Vec<PathBuf> = linux.reads.iter().map(base).collect();
        if linux.read_mode == ReadMode::Closed {
            read.extend(READ_ESSENTIALS.iter().map(PathBuf::from));
        }
        let holes = linux
            .subtract
            .iter()
            .filter(|p| !p.is_any_depth())
            .map(base);
        Some(Grants {
            exec: real(roots.iter().cloned().chain(loaders_for(&roots))),
            read: real(read),
            holes: real(holes),
        })
    }

    fn covered(grants: &[PathBuf], real: &Path) -> bool {
        grants.iter().any(|g| real.starts_with(g))
    }

    /// The grant `file` lacks for `execve` to open it, as the rule that adds it.
    fn lacks(&self, file: &Path) -> Option<String> {
        let real = std::fs::canonicalize(file).ok()?;
        let exec = Grants::covered(&self.exec, &real);
        let read = Grants::covered(&self.read, &real) && !Grants::covered(&self.holes, &real);
        let shown = file.display();
        match (exec, read) {
            (true, true) => None,
            (false, true) => Some(format!(
                "is not on the exec allow-list (add `exec:{shown}`)"
            )),
            (false, false) => Some(format!(
                "is neither on the exec allow-list nor readable, and execve reads the file it \
                 runs (add `readexec:{shown}`)"
            )),
            (true, false) => Some(format!(
                "is on the exec allow-list but not readable, and execve reads the file it runs \
                 (add `readexec:{shown}`)"
            )),
        }
    }

    /// The grant `file` is missing, if the policy is why it cannot run.
    fn missing(&self, file: &Path, depth: usize) -> Option<String> {
        if let Some(why) = self.lacks(file) {
            return Some(format!("{} {why}", file.display()));
        }
        if let Some(loader) = elf_interpreter(file) {
            return self.lacks(&loader).map(|why| {
                format!(
                    "{} needs its dynamic loader {}, which {why}",
                    file.display(),
                    loader.display()
                )
            });
        }
        let interpreter = script_interpreter(file)?;
        if depth >= MAX_SCRIPT_DEPTH {
            return None;
        }
        self.missing(&interpreter, depth + 1).map(|why| {
            format!(
                "{} is a script run by {}: {why}",
                file.display(),
                interpreter.display()
            )
        })
    }
}

/// `program` as `execvp` finds it: as given when it contains a slash, else the first match on the
/// child's `path`.
fn resolve(program: &Path, path: Option<&OsStr>) -> Option<PathBuf> {
    if program.as_os_str().as_bytes().contains(&b'/') {
        return Some(program.to_path_buf());
    }
    std::env::split_paths(path?)
        .map(|dir| dir.join(program))
        .find(|candidate| candidate.is_file())
}

/// Why `program` cannot be exec'd under `linux`'s allow-list, when the policy is the cause; `path`
/// is the child's `PATH`.
pub(super) fn denial_hint(
    linux: &LinuxPolicy,
    program: &Path,
    path: Option<&OsStr>,
) -> Option<String> {
    Grants::of(linux)?.missing(&resolve(program, path)?, 0)
}

/// Why `program` failed to exec under `policy`, when an exec allow-list is the cause: the
/// program, the dynamic loader it names, or the interpreter of a script lacks an exec or read
/// grant. `path` is the child's `PATH`. A message for a spawn that already failed with EACCES; it
/// decides nothing.
pub fn exec_denial_hint(
    policy: &CompiledPolicy,
    program: &Path,
    path: Option<&OsStr>,
) -> Option<String> {
    match &policy.confiner {
        ConfinerPolicy::Linux(linux) => denial_hint(linux, program, path),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn existing_standard_loaders() -> Vec<PathBuf> {
        STANDARD_LOADERS
            .iter()
            .map(PathBuf::from)
            .filter(|p| p.exists())
            .collect()
    }

    #[test]
    fn reads_the_interpreter_of_a_dynamic_elf_and_none_of_a_script() {
        // The test binary itself is a dynamically linked ELF on every glibc host CI runs.
        let me = std::env::current_exe().unwrap();
        let loader = elf_interpreter(&me).expect("the test binary names a loader");
        assert!(loader.is_absolute() && loader.exists(), "{loader:?}");
        assert_eq!(elf_interpreter(Path::new("/nonexistent")), None);

        let dir = std::env::temp_dir().join(format!("fw-loader-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let script = dir.join("s.sh");
        std::fs::write(&script, "#!  /bin/sh -e\necho hi\n").unwrap();
        assert_eq!(elf_interpreter(&script), None);
        assert_eq!(script_interpreter(&script), Some(PathBuf::from("/bin/sh")));
        assert!(
            loaders_for(&[script]).is_empty(),
            "a script names no loader"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_listed_directory_gets_every_standard_loader_that_exists() {
        assert_eq!(
            loaders_for(&[PathBuf::from("/usr/bin")]),
            existing_standard_loaders()
        );
    }

    /// Without Landlock no exec rule is installed, so an EACCES is never the allow-list's.
    #[test]
    fn no_hint_where_landlock_carries_no_allow_list() {
        use formwork_blueprint::{Blueprint, ExecPosture, ResolvedCatalog};
        let blueprint = Blueprint {
            exec: ExecPosture::Allowlist(vec![PathPattern::parse("/usr/bin/git").unwrap()]),
            ..Blueprint::empty()
        };
        let policy = |abi| {
            let mut host = formwork_detect::HostProfile::synthetic_linux(abi);
            host.seccomp = true;
            formwork_compile::compile(&blueprint, &host, &ResolvedCatalog::empty_no_floor())
        };
        let unlisted = Path::new("/bin/sh");
        assert_eq!(exec_denial_hint(&policy(None), unlisted, None), None);
        let hint = exec_denial_hint(&policy(Some(6)), unlisted, None).unwrap();
        assert!(hint.contains("not on the exec allow-list"), "{hint}");
    }

    /// FW-XR8: a listed binary the session can rewrite names its interpreter, so a non-standard
    /// `PT_INTERP` -- a directory, or any other program -- is never granted.
    #[test]
    fn a_listed_file_grants_only_a_standard_loader() {
        let me = std::env::current_exe().unwrap();
        let named = elf_interpreter(&me).unwrap();
        let expected: Vec<PathBuf> = existing_standard_loaders()
            .into_iter()
            .filter(|s| *s == named)
            .collect();
        assert_eq!(loaders_for(std::slice::from_ref(&me)), expected);

        let dir = std::env::temp_dir().join(format!("fw-loader-interp-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let mut forged = std::fs::read(&me).unwrap();
        let offset = forged
            .windows(named.as_os_str().len())
            .position(|w| w == named.as_os_str().as_bytes())
            .unwrap();
        // Rewrite the interpreter name in place to "/" and pad with NULs, as an agent could.
        forged[offset] = b'/';
        for b in &mut forged[offset + 1..offset + named.as_os_str().len()] {
            *b = 0;
        }
        let path = dir.join("forged");
        std::fs::write(&path, &forged).unwrap();
        assert_eq!(elf_interpreter(&path), Some(PathBuf::from("/")));
        assert!(
            loaders_for(&[path]).is_empty(),
            "a forged interpreter is not granted"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
