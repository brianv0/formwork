//! What a path pattern confers under Landlock (FW-BP27, FW-BP28), probed against the real kernel:
//! paired allow and deny at the boundary, never the policy read back (FW-INV5). The Seatbelt half
//! of each pair is asserted on the rendered profile in `formwork-compile/tests/path_patterns.rs`.

#![cfg(target_os = "linux")]

use std::fs;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use formwork_blueprint::{Blueprint, FsBlueprint, PathPattern, ReadMode, ResolvedCatalog};
use formwork_compile::{CompiledPolicy, ConfinerPolicy};
use formwork_detect::detect;

fn compile(fs: FsBlueprint) -> CompiledPolicy {
    let home = std::env::var("HOME").unwrap_or_else(|_| "/".to_string());
    let blueprint = Blueprint {
        fs: FsBlueprint {
            read_mode: ReadMode::Closed,
            ..fs
        },
        ..Blueprint::empty()
    };
    formwork_compile::compile(
        &blueprint,
        &detect(),
        &ResolvedCatalog::builtin_for_home(&home).unwrap(),
    )
}

fn have_landlock() -> bool {
    let present = detect().landlock_abi.is_some();
    if !present {
        eprintln!("skipping: no Landlock on this host");
    }
    present
}

fn literal(path: &Path) -> PathPattern {
    PathPattern::literal(path).unwrap()
}

fn subtree(path: &Path) -> PathPattern {
    PathPattern::subtree(path).unwrap()
}

fn status(policy: &CompiledPolicy, mut cmd: Command) -> i32 {
    cmd.stdout(Stdio::null()).stderr(Stdio::null());
    formwork_confine::spawn_confined(&mut cmd, policy).expect("confinement applies");
    cmd.status().expect("child runs").code().unwrap_or(-1)
}

fn cat(path: &Path) -> Command {
    let mut c = Command::new("/bin/cat");
    c.arg(path);
    c
}

fn ls(path: &Path) -> Command {
    let mut c = Command::new("/bin/ls");
    c.arg(path);
    c
}

/// `data/top.txt`, `data/sub/inner.txt` and `secret/key`, under a symlink-resolved scratch root.
struct Tree {
    root: PathBuf,
}

impl Tree {
    fn new(tag: &str) -> Self {
        let root = std::env::temp_dir().join(format!("fw-patterns-{tag}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(root.join("data/sub")).unwrap();
        fs::create_dir_all(root.join("secret/deep")).unwrap();
        let root = fs::canonicalize(&root).unwrap();
        fs::write(root.join("data/top.txt"), b"top\n").unwrap();
        fs::write(root.join("data/sub/inner.txt"), b"inner\n").unwrap();
        fs::write(root.join("secret/key"), b"key\n").unwrap();
        fs::write(root.join("secret/deep/key"), b"deep key\n").unwrap();
        fs::write(root.join("plain.txt"), b"plain\n").unwrap();
        Tree { root }
    }
    fn at(&self, rel: &str) -> PathBuf {
        self.root.join(rel)
    }
}

impl Drop for Tree {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

/// Characterization behind FW-BP27: a Landlock rule that carries only the directory right
/// `ReadDir` still reaches below the directory it is added on, so no rule expresses "this
/// directory and nothing beneath it". Built from the `landlock` crate directly, because the
/// confiner installs no such rule.
#[test]
fn landlock_directory_rights_reach_nested_directories() {
    use landlock::{AccessFs, PathBeneath, PathFd, Ruleset, RulesetAttr, RulesetCreatedAttr, ABI};
    if !have_landlock() {
        return;
    }
    let tree = Tree::new("readdir");
    let read = AccessFs::from_read(ABI::V1);
    let mut ruleset = Ruleset::default()
        .handle_access(read)
        .unwrap()
        .create()
        .unwrap();
    for essential in ["/usr", "/lib", "/lib64", "/bin", "/etc"] {
        if let Ok(fd) = PathFd::new(essential) {
            ruleset = ruleset.add_rule(PathBeneath::new(fd, read)).unwrap();
        }
    }
    let data = PathFd::new(tree.at("data")).unwrap();
    let ruleset = ruleset
        .add_rule(PathBeneath::new(data, AccessFs::ReadDir))
        .unwrap();
    let mut pending = Some(ruleset);
    let confined = |mut cmd: Command, pending: &mut Option<landlock::RulesetCreated>| -> i32 {
        let mut ruleset = pending.as_ref().map(|r| r.try_clone().unwrap());
        cmd.stdout(Stdio::null()).stderr(Stdio::null());
        // SAFETY: the closure issues only the prctl and landlock_restrict_self syscalls.
        unsafe {
            cmd.pre_exec(move || {
                ruleset
                    .take()
                    .expect("one exec per command")
                    .restrict_self()
                    .map(|_| ())
                    .map_err(|_| std::io::Error::last_os_error())
            });
        }
        cmd.status().unwrap().code().unwrap_or(-1)
    };
    assert_eq!(
        confined(ls(&tree.at("data")), &mut pending),
        0,
        "the directory lists"
    );
    assert_ne!(
        confined(cat(&tree.at("data/top.txt")), &mut pending),
        0,
        "ReadDir alone reads no file"
    );
    assert_eq!(
        confined(ls(&tree.at("data/sub")), &mut pending),
        0,
        "the right reaches the nested directory: its names are listed"
    );
    assert_ne!(
        confined(ls(&tree.at("secret")), &mut pending),
        0,
        "a directory outside the rule does not list"
    );
}

/// FW-E2E-178 (Linux arm): a literal grant that names a directory confers nothing beneath it --
/// and, because of the characterization above, not the directory either -- while a literal on a
/// file reads that file and the `/**` spelling reads the contents.
#[test]
fn fw_e2e_178_a_literal_directory_grant_confers_nothing_beneath_it() {
    if !have_landlock() {
        return;
    }
    let tree = Tree::new("e2e178");
    let on_directory = compile(FsBlueprint {
        reads: vec![literal(&tree.at("data")), literal(&tree.at("plain.txt"))],
        ..FsBlueprint::default()
    });
    assert_eq!(
        status(&on_directory, cat(&tree.at("plain.txt"))),
        0,
        "a literal grant on a file reads the file (the policy is live)"
    );
    for beneath in ["data/top.txt", "data/sub/inner.txt"] {
        assert_ne!(
            status(&on_directory, cat(&tree.at(beneath))),
            0,
            "{beneath} sits beneath a literal directory grant and must not be readable"
        );
    }
    for directory in ["data", "data/sub"] {
        assert_ne!(
            status(&on_directory, ls(&tree.at(directory))),
            0,
            "{directory}: Landlock cannot grant the directory without its contents, so it \
             grants neither"
        );
    }

    let contents = compile(FsBlueprint {
        reads: vec![subtree(&tree.at("data"))],
        ..FsBlueprint::default()
    });
    for beneath in ["data/top.txt", "data/sub/inner.txt"] {
        assert_eq!(status(&contents, cat(&tree.at(beneath))), 0, "{beneath}");
    }
    assert_eq!(status(&contents, ls(&tree.at("data"))), 0);
}

/// FW-E2E-178 on the write and exec axes: a literal on a directory grants no write beneath it,
/// no create in it, and no execute of what it holds.
#[test]
fn fw_e2e_178_a_literal_directory_grant_confers_no_write_or_exec_beneath_it() {
    if !have_landlock() {
        return;
    }
    let tree = Tree::new("e2e178w");
    let tool = tree.at("data/tool");
    fs::copy("/bin/true", &tool).unwrap();
    let write = |path: &Path| {
        let mut c = Command::new("/bin/sh");
        c.arg("-c").arg(format!("echo x >> '{}'", path.display()));
        c
    };

    let on_directory = compile(FsBlueprint {
        reads: vec![subtree(&tree.root)],
        writes: vec![literal(&tree.at("data")), literal(&tree.at("plain.txt"))],
        ..FsBlueprint::default()
    });
    assert_eq!(status(&on_directory, write(&tree.at("plain.txt"))), 0);
    for target in ["data/top.txt", "data/new.txt", "data/sub/inner.txt"] {
        assert_ne!(
            status(&on_directory, write(&tree.at(target))),
            0,
            "{target} must not be writable through a literal grant on its directory"
        );
    }
    assert!(!tree.at("data/new.txt").exists());

    // Exec: the loader and libraries stay executable by subtree, so the only variable is the
    // literal that names the tool or its directory.
    let exec_policy = |row: PathPattern| {
        let home = std::env::var("HOME").unwrap_or_else(|_| "/".to_string());
        let mut paths: Vec<PathPattern> = ["/usr", "/lib", "/lib64", "/bin"]
            .iter()
            .map(|dir| subtree(Path::new(dir)))
            .collect();
        paths.push(row);
        let blueprint = Blueprint {
            fs: FsBlueprint {
                read_mode: ReadMode::Closed,
                reads: vec![subtree(&tree.root)],
                ..FsBlueprint::default()
            },
            exec: formwork_blueprint::ExecPosture::Allowlist(paths),
            ..Blueprint::empty()
        };
        formwork_compile::compile(
            &blueprint,
            &detect(),
            &ResolvedCatalog::builtin_for_home(&home).unwrap(),
        )
    };
    // A sibling test forking while the copy above was open for writing leaves the tool busy for
    // a moment; that is the harness, not the policy, so it is retried.
    let run_tool = |policy: &CompiledPolicy| loop {
        let mut cmd = Command::new(&tool);
        cmd.stdout(Stdio::null()).stderr(Stdio::null());
        formwork_confine::spawn_confined(&mut cmd, policy).expect("confinement applies");
        match cmd.status() {
            Err(e) if e.kind() == std::io::ErrorKind::ExecutableFileBusy => {
                std::thread::sleep(std::time::Duration::from_millis(20))
            }
            outcome => break outcome.map(|s| s.code()).map_err(|e| e.kind()),
        }
    };
    assert_eq!(
        run_tool(&exec_policy(literal(&tool))),
        Ok(Some(0)),
        "a literal exec grant on the binary executes it (the allow-list is live)"
    );
    assert_eq!(
        run_tool(&exec_policy(literal(&tree.at("data")))),
        Err(std::io::ErrorKind::PermissionDenied),
        "a literal exec grant on the directory must not execute what it holds"
    );
}

/// FW-E2E-179 (Linux arm): a literal deny that names a directory takes the directory's contents
/// out of the grant that covers it. That is more than the rule names -- the divergence `explain`
/// and `run` report -- and it never reaches a grant rooted beneath the directory.
#[test]
fn fw_e2e_179_a_literal_directory_deny_takes_its_contents_on_linux() {
    if !have_landlock() {
        return;
    }
    let tree = Tree::new("e2e179");
    let covered = compile(FsBlueprint {
        reads: vec![subtree(&tree.root)],
        subtract: vec![literal(&tree.at("secret"))],
        ..FsBlueprint::default()
    });
    assert_eq!(
        status(&covered, cat(&tree.at("data/top.txt"))),
        0,
        "a sibling of the denied directory stays readable"
    );
    for denied in ["secret/key", "secret/deep/key"] {
        assert_ne!(status(&covered, cat(&tree.at(denied))), 0, "{denied}");
    }
    assert_ne!(status(&covered, ls(&tree.at("secret"))), 0);

    let rooted_beneath = compile(FsBlueprint {
        reads: vec![subtree(&tree.at("secret/deep"))],
        subtract: vec![literal(&tree.at("secret"))],
        ..FsBlueprint::default()
    });
    assert_eq!(
        status(&rooted_beneath, cat(&tree.at("secret/deep/key"))),
        0,
        "a literal deny names the directory entry; a grant rooted beneath it is its own rule"
    );
    assert_ne!(status(&rooted_beneath, cat(&tree.at("secret/key"))), 0);
}

/// FW-ADV-048: an any-depth grant has a relative suffix for a base. Installed as a rule it would
/// open that suffix against the launch directory and grant whatever sits there, outside the
/// pattern's anchor. The compiler hands such a blueprint no policy, and a policy that carries the
/// row anyway is refused before any child is spawned.
#[test]
fn fw_adv_048_an_any_depth_grant_never_binds_to_the_launch_directory() {
    if !have_landlock() {
        return;
    }
    let tree = Tree::new("adv048");
    let anchored = PathPattern::parse(&format!(
        "{}/**/data/**",
        PathPattern::escape(&tree.at("elsewhere").display().to_string())
    ))
    .unwrap();
    assert!(anchored.is_any_depth());

    let refused = compile(FsBlueprint {
        writes: vec![anchored.clone()],
        ..FsBlueprint::default()
    });
    assert!(
        matches!(refused.confiner, ConfinerPolicy::Unavailable { .. }),
        "{:?}",
        refused.confiner
    );
    let mut cmd = cat(&tree.at("data/top.txt"));
    assert!(formwork_confine::spawn_confined(&mut cmd, &refused).is_err());

    // The same row placed into an otherwise valid policy, one field at a time, launched from
    // the directory whose `data/` the suffix would resolve to.
    let valid = compile(FsBlueprint {
        reads: vec![subtree(&tree.at("secret"))],
        ..FsBlueprint::default()
    });
    type Place = fn(&mut formwork_compile::LinuxPolicy, PathPattern);
    let fields: [(&str, Place); 4] = [
        ("reads", |p, row| p.reads.push(row)),
        ("writes", |p, row| p.writes.push(row)),
        ("writes-no-create", |p, row| p.writes_no_create.push(row)),
        ("exec", |p, row| {
            p.exec = formwork_compile::ExecPlan::Allowlist { paths: vec![row] }
        }),
    ];
    for (field, place) in fields {
        let mut policy = valid.clone();
        let ConfinerPolicy::Linux(linux) = &mut policy.confiner else {
            panic!("expected a Linux policy");
        };
        place(linux, anchored.clone());
        let mut cmd = Command::new("/bin/sh");
        cmd.arg("-c")
            .arg("cat data/top.txt && echo planted > data/planted.txt")
            .current_dir(&tree.root)
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        match formwork_confine::spawn_confined(&mut cmd, &policy) {
            Err(e) => assert!(e.to_string().contains("any-depth"), "{field}: {e}"),
            Ok(()) => {
                let code = cmd.status().unwrap().code();
                panic!("{field}: an any-depth grant was installed; the workload exited {code:?}")
            }
        }
        assert!(
            !tree.at("data/planted.txt").exists(),
            "{field}: wrote outside the anchor"
        );
    }
}
