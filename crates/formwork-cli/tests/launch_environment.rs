//! Black-box tests of what the launching environment and the files around a blueprint do to a
//! session: a variable that relocates a credential store moves the floor with it (FW-CRED32), the
//! report names the variable and never its value (FW-CRED35), the name shapes the Catalog adopted
//! are denied or reported withheld, and an `extends` base another account can change is named
//! (FW-BP32). Each drives the built binary with `$HOME` and the launch directory pinned inside a
//! scratch directory, table-driven from the Catalog the binary embeds.

mod support;

use std::path::{Path, PathBuf};

use formwork_blueprint::{Catalog, ResolvedCatalog};
use support::*;

const BLUEPRINT: &str = "extends = [\"builtin:default\"]\nrules = [\"readwrite:$CWD/**\"]\n";

/// Prints `read:<n>` or `denied:<n>` for each argument, by position: the paths stay out of the
/// output, so the output can be searched for them.
const PROBE: &str = r#"n=0; for f in "$@"; do n=$((n+1));
if cat "$f" >/dev/null 2>&1; then echo "read:$n"; else echo "denied:$n"; fi; done"#;

/// Every variable the Catalog reads a location from, so a run can start without the ones the
/// machine running the tests happens to export.
fn reference_variables() -> Vec<String> {
    let mut vars: Vec<String> = Catalog::builtin()
        .types
        .values()
        .flat_map(|entry| {
            let dirs = entry.env_dir_refs.iter().map(|r| r.var.clone());
            dirs.chain(entry.env_file_refs.iter().map(|r| r.var.clone()))
        })
        .collect();
    vars.sort();
    vars.dedup();
    vars
}

/// `formwork` in `dir` with exactly the reference variables in `env` set.
fn formwork_with(dir: &Path, args: &[&str], env: &[(&str, &str)]) -> Output {
    let vars = reference_variables();
    let without: Vec<&str> = vars.iter().map(String::as_str).collect();
    formwork_env(dir, args, env, &without)
}

/// A host whose kernel denies a file read, or a stated reason why not.
fn confiner_host(dir: &Path) -> bool {
    let host = host_profile(dir);
    let confines = !host["landlock-abi"].is_null() || host["seatbelt"].as_bool() == Some(true);
    if !confines {
        not_exercised("no filesystem confiner on this host");
    }
    confines
}

/// One file at each place a type keeps a credential below a relocated root: the file a literal
/// row names, or two files at different depths under a subtree row.
fn plant(root: &Path, below: &[String], marker: &str) -> Vec<PathBuf> {
    let mut files = Vec::new();
    for rest in below {
        let rest = rest.trim_start_matches('/');
        match rest.strip_suffix("**") {
            Some(subtree) => {
                files.push(root.join(subtree).join("fake-credential"));
                files.push(root.join(subtree).join("nested/deeper/fake-credential"));
            }
            None => files.push(root.join(rest)),
        }
    }
    for file in &files {
        std::fs::create_dir_all(file.parent().unwrap()).unwrap();
        std::fs::write(file, format!("{marker}\n")).unwrap();
    }
    files
}

/// The probe's verdict per file, in argument order.
fn probe(dir: &Path, flags: &[&str], files: &[PathBuf], env: &[(&str, &str)]) -> Vec<String> {
    let mut args = vec!["run"];
    args.extend(flags);
    args.extend(["--", "/bin/sh", "-c", PROBE, "probe"]);
    args.extend(files.iter().map(|f| f.to_str().unwrap()));
    let out = formwork_with(dir, &args, env);
    assert_eq!(out.code, 0, "{}", out.stderr);
    let verdicts: Vec<String> = out
        .stdout
        .lines()
        .map(|l| l.split(':').next().unwrap().to_string())
        .collect();
    assert_eq!(verdicts.len(), files.len(), "{}", out.stdout);
    verdicts
}

fn report(dir: &Path, env: &[(&str, &str)]) -> serde_json::Value {
    let out = formwork_with(dir, &["compile", "--report-only"], env);
    assert_eq!(out.code, 0, "{}", out.stderr);
    serde_json::from_str(&out.stdout).unwrap()
}

/// FW-E2E-197 (both; FW-CRED32, FW-CRED35): for each `env-dir-refs` entry the binary embeds, with
/// the variable naming a scratch directory inside a `readwrite` grant, the kernel denies a file
/// at each place the type keeps a credential there, `explain` names the type, and the report
/// names the variable with the rows it added. A file beside the store stays readable, the typed
/// exclude lifts the relocated store with its type, and with the variable unset every file is an
/// ordinary in-grant read that `explain` grants.
#[test]
fn fw_e2e_197_a_relocated_credential_store_is_denied_where_its_variable_points() {
    let dir = Scratch::new("reloc-197");
    std::fs::write(dir.path().join("FORMWORK.toml"), BLUEPRINT).unwrap();
    if !confiner_host(dir.path()) {
        return;
    }
    let resolved = ResolvedCatalog::builtin_for_home("/home/x").unwrap();
    let mut entries = 0;
    for (type_name, entry) in &resolved.types {
        for relocation in &entry.env_dir_refs {
            entries += 1;
            let var = relocation.var.as_str();
            let case = format!("{type_name} via {var}");
            let store = dir.path().join(format!("stores/{type_name}-{var}"));
            let credentials = plant(&store, &relocation.below, "fake-credential");
            let beside = dir
                .path()
                .join(format!("stores/beside-{type_name}-{var}.txt"));
            std::fs::write(&beside, "ordinary\n").unwrap();
            let mut files = credentials.clone();
            files.push(beside);
            let set = [(var, store.to_str().unwrap())];

            let mut expected = vec!["denied".to_string(); credentials.len()];
            expected.push("read".to_string());
            assert_eq!(probe(dir.path(), &[], &files, &set), expected, "{case}");
            let unset = vec!["read".to_string(); files.len()];
            assert_eq!(probe(dir.path(), &[], &files, &[]), unset, "{case}, unset");
            let lifted = probe(dir.path(), &["--allow-cred", type_name], &files, &set);
            assert_eq!(lifted, unset, "{case}, type excluded");

            let credential = credentials[0].to_str().unwrap();
            let floored = format!("denied by credential floor ({type_name})");
            let explained = formwork_with(dir.path(), &["explain", credential], &set);
            assert!(
                explained.stdout.contains(&floored),
                "{case}: {}",
                explained.stdout
            );
            let explained = formwork_with(dir.path(), &["explain", credential], &[]);
            assert!(
                !explained.stdout.contains("credential floor"),
                "{case}, unset: {}",
                explained.stdout
            );

            let named = &report(dir.path(), &set)["credentials"]["per-type"][type_name];
            assert_eq!(
                named["references"],
                serde_json::json!([{ "var": var, "rows": relocation.below.len() }]),
                "{case}"
            );
            assert_eq!(named["path"]["status"], "enforced", "{case}");
            let silent = &report(dir.path(), &[])["credentials"]["per-type"][type_name];
            assert!(
                silent.get("references").is_none(),
                "{case}, unset: {silent}"
            );
        }
    }
    assert!(entries > 0, "the embedded Catalog carries env-dir-refs");
}

/// FW-ADV-054 (both; FW-CRED32, FW-CRED35): with every reference variable the Catalog models set
/// at once -- each store variable to its own directory inside a `readwrite` grant, each file
/// variable to a file there -- a confined process reads the planted files by path and sweeps the
/// directories the variables it inherits name. Nothing planted is readable, a non-credential
/// file inside a store whose type names two files is, and no variable's value is in the report or
/// on the operator channel, which name each variable instead.
#[test]
fn fw_adv_054_no_relocated_credential_is_readable_and_no_value_is_reported() {
    let dir = Scratch::new("reloc-adv054");
    std::fs::write(dir.path().join("FORMWORK.toml"), BLUEPRINT).unwrap();
    if !confiner_host(dir.path()) {
        return;
    }
    let resolved = ResolvedCatalog::builtin_for_home("/home/x").unwrap();
    let mut env: Vec<(String, String)> = Vec::new();
    let mut planted: Vec<PathBuf> = Vec::new();
    let mut dir_refs: Vec<(String, String, usize)> = Vec::new();
    let mut file_refs: Vec<(String, String, usize)> = Vec::new();
    for (type_name, entry) in &resolved.types {
        for relocation in &entry.env_dir_refs {
            let var = &relocation.var;
            let store = dir.path().join(format!("relocated/{var}"));
            planted.extend(plant(&store, &relocation.below, "PLANTED-CREDENTIAL"));
            dir_refs.push((type_name.clone(), var.clone(), relocation.below.len()));
            if !env.iter().any(|(set, _)| set == var) {
                env.push((var.clone(), store.to_str().unwrap().to_string()));
            }
        }
        for reference in &entry.env_file_refs {
            let var = &reference.var;
            let names: &[&str] = if reference.list { &["a", "b"] } else { &["a"] };
            let files: Vec<PathBuf> = names
                .iter()
                .map(|n| dir.path().join(format!("referenced/{var}-{n}")))
                .collect();
            for file in &files {
                std::fs::create_dir_all(file.parent().unwrap()).unwrap();
                std::fs::write(file, "PLANTED-CREDENTIAL\n").unwrap();
            }
            let value: Vec<&str> = files.iter().map(|f| f.to_str().unwrap()).collect();
            env.push((var.clone(), value.join(":")));
            file_refs.push((type_name.clone(), var.clone(), files.len()));
            planted.extend(files);
        }
    }
    // cargo's rows are two files, so the rest of a relocated CARGO_HOME is the toolchain's.
    let ordinary = dir.path().join("relocated/CARGO_HOME/registry/index");
    std::fs::create_dir_all(ordinary.parent().unwrap()).unwrap();
    std::fs::write(&ordinary, "ordinary\n").unwrap();
    let env: Vec<(&str, &str)> = env.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
    let store_vars: Vec<&str> = dir_refs.iter().map(|(_, var, _)| var.as_str()).collect();

    // The sweep goes where the session's own environment points, not only where the test knows.
    let sweep = format!(
        "{PROBE}; for v in {}; do eval \"d=\\${{$v-}}\"; [ -n \"$d\" ] && find \"$d\" -type f \
         -exec cat {{}} + 2>/dev/null; done; true",
        store_vars.join(" ")
    );
    let mut args = vec!["run", "--", "/bin/sh", "-c", sweep.as_str(), "sweep"];
    args.extend(planted.iter().map(|f| f.to_str().unwrap()));
    args.push(ordinary.to_str().unwrap());
    let run_with = |env: &[(&str, &str)]| {
        let mut env = env.to_vec();
        env.push(("RUST_LOG", "debug"));
        let out = formwork_with(dir.path(), &args, &env);
        assert_eq!(out.code, 0, "{}", out.stderr);
        out
    };

    // Control: with no variable set these are ordinary files of the grant.
    let open = run_with(&[]);
    assert!(!open.stdout.contains("denied:"), "{}", open.stdout);

    let swept = run_with(&env);
    let mut expected: Vec<String> = (1..=planted.len()).map(|n| format!("denied:{n}")).collect();
    expected.push(format!("read:{}", planted.len() + 1));
    let verdicts: Vec<&str> = swept.stdout.lines().take(expected.len()).collect();
    assert_eq!(verdicts, expected, "{}", swept.stdout);
    assert!(
        !swept.stdout.contains("PLANTED-CREDENTIAL"),
        "the sweep read a planted credential: {}",
        swept.stdout
    );

    let compiled = formwork_with(dir.path(), &["compile", "--report-only"], &env);
    let summary = formwork_with(dir.path(), &["explain"], &env);
    let summary_json = formwork_with(dir.path(), &["explain", "--json"], &env);
    for out in [&compiled, &summary, &summary_json] {
        assert_eq!(out.code, 0, "{}", out.stderr);
    }
    let surfaces = [
        ("run, operator channel at debug", &swept.stderr),
        ("run, session output", &swept.stdout),
        ("compile --report-only", &compiled.stdout),
        ("compile --report-only, operator channel", &compiled.stderr),
        ("explain", &summary.stdout),
        ("explain, operator channel", &summary.stderr),
        ("explain --json", &summary_json.stdout),
    ];
    for (_, value) in &env {
        for location in value.split(':') {
            for (surface, text) in &surfaces {
                assert!(
                    !text.contains(location),
                    "{surface} carries a reference variable's value {location}:\n{text}"
                );
            }
        }
    }

    // What the surfaces carry instead: the variable, its type and the rows it added.
    let per_type = &serde_json::from_str::<serde_json::Value>(&compiled.stdout).unwrap()
        ["credentials"]["per-type"];
    for (type_name, var, rows) in &dir_refs {
        let named = serde_json::json!({ "var": var, "rows": rows });
        let references = per_type[type_name]["references"].as_array().unwrap();
        assert!(references.contains(&named), "{type_name}: {references:?}");
        assert!(summary
            .stdout
            .contains(&format!("{var} ({type_name}, +{rows})")));
    }
    for (type_name, var, rows) in dir_refs.iter().chain(&file_refs) {
        let line = format!("({type_name:?}, {var:?}, {rows})");
        assert!(swept.stderr.contains(&line), "{line}: {}", swept.stderr);
    }
}

/// The name shapes the Catalog adopted (FW-CRED6, FW-CRED9): `explain` names the floor row for
/// each, and what the kernel does matches what `explain` says on this host -- denied where the
/// backend carries any-depth rows, readable and marked withheld where Landlock cannot root them.
/// A project `.npmrc` is not one of the shapes: it is readable until the blueprint denies it.
#[test]
fn fw_cred9_an_adopted_name_shape_is_denied_or_reported_withheld() {
    let dir = Scratch::new("shapes");
    std::fs::write(dir.path().join("FORMWORK.toml"), BLUEPRINT).unwrap();
    if !confiner_host(dir.path()) {
        return;
    }
    let shapes = [
        ("app/.env.development.local", "dotenv"),
        ("app/.env.test.local", "dotenv"),
        ("app/.env.staging.local", "dotenv"),
        ("app/.env.production.local", "dotenv"),
        ("app/deploy/id_dsa", "backstop"),
        ("app/deploy/id_ecdsa_sk", "backstop"),
        ("app/deploy/id_ed25519_sk", "backstop"),
        ("app/vendor/tool/.git-credentials", "backstop"),
    ];
    let files: Vec<PathBuf> = shapes.iter().map(|(p, _)| dir.path().join(p)).collect();
    for file in &files {
        std::fs::create_dir_all(file.parent().unwrap()).unwrap();
        std::fs::write(file, "fake\n").unwrap();
    }
    let withholds = !host_profile(dir.path())["landlock-abi"].is_null();
    let verdicts = probe(dir.path(), &[], &files, &[]);
    for (((path, floor), file), verdict) in shapes.iter().zip(&files).zip(&verdicts) {
        let explained = formwork_with(dir.path(), &["explain", file.to_str().unwrap()], &[]);
        let model = format!("denied by credential floor ({floor})");
        assert!(
            explained.stdout.contains(&model),
            "{path}: {}",
            explained.stdout
        );
        let marked = explained.stdout.contains("withheld on this host");
        assert_eq!(marked, withholds, "{path}: {}", explained.stdout);
        let expected = if withholds { "read" } else { "denied" };
        assert_eq!(verdict, expected, "{path}");
    }

    let npmrc = dir.path().join("app/.npmrc");
    std::fs::write(&npmrc, "//registry.example/:_authToken=fake\n").unwrap();
    let explained = formwork_with(dir.path(), &["explain", npmrc.to_str().unwrap()], &[]);
    assert!(
        !explained.stdout.contains("credential"),
        "{}",
        explained.stdout
    );
    let npmrc = [npmrc];
    assert_eq!(probe(dir.path(), &[], &npmrc, &[]), ["read"]);
    // The operator's recipe, which both backends carry: one file, by its place in the project.
    std::fs::write(
        dir.path().join("app/FORMWORK.toml"),
        "extends = [\"../FORMWORK.toml\"]\nrules = [\"deny:$CWD/.npmrc\"]\n",
    )
    .unwrap();
    let app = dir.path().join("app");
    std::fs::write(app.join("package.json"), "{}\n").unwrap();
    let out = formwork_env(
        &app,
        &[
            "run",
            "--",
            "/bin/sh",
            "-c",
            PROBE,
            "probe",
            ".npmrc",
            "package.json",
        ],
        &[("HOME", dir.path().to_str().unwrap())],
        &[],
    );
    assert_eq!(out.stdout, "denied:1\nread:2\n", "{}", out.stderr);
}

/// The FW-BP32 lines of one invocation, each as the operator channel wrote it.
fn base_notices(stderr: &str) -> Vec<&str> {
    stderr.lines().filter(|l| l.contains("FW-BP32")).collect()
}

fn set_mode(path: &Path, mode: u32) {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
}

/// FW-E2E-218 (both; FW-BP32): an `extends` base that is group- or world-writable is named once
/// on the operator channel -- also when two layers extend it -- and is loaded all the same; a
/// base only its owner can write is not named. Where the test runs as root it also changes
/// owners: a base owned by a third account is named, and to an unprivileged invoking user a
/// root-owned base and its own base are not.
#[test]
fn fw_e2e_218_an_extends_base_others_can_change_is_named_and_still_loads() {
    let dir = Scratch::new("bases-218");
    let base = |name: &str, grant: &str, mode: u32| -> PathBuf {
        let path = dir.path().join(name);
        std::fs::write(&path, format!("rules = [\"read:/opt/{grant}/**\"]\n")).unwrap();
        set_mode(&path, mode);
        path
    };
    let private = base("private.toml", "private", 0o644);
    let shared = base("shared.toml", "shared", 0o666);
    base("group.toml", "group", 0o664);
    // A layer of its own that extends the world-writable base a second time; its mode is set,
    // so the umask of the machine running the test decides nothing.
    let mid = dir.path().join("mid.toml");
    std::fs::write(
        &mid,
        format!("extends = [{:?}]\n", shared.to_str().unwrap()),
    )
    .unwrap();
    set_mode(&mid, 0o644);
    std::fs::write(
        dir.path().join("FORMWORK.toml"),
        format!(
            "extends = [{:?}, {:?}, \"group.toml\", \"mid.toml\"]\n",
            private.to_str().unwrap(),
            shared.to_str().unwrap()
        ),
    )
    .unwrap();
    let out = formwork(
        dir.path(),
        &["explain", "/opt/shared/x", "/opt/group/x", "/opt/private/x"],
        &[],
    );
    assert_eq!(out.code, 0, "{}", out.stderr);
    let notices = base_notices(&out.stderr);
    assert_eq!(notices.len(), 2, "{}", out.stderr);
    for (name, mode) in [("shared.toml", "0666"), ("group.toml", "0664")] {
        let named: Vec<&&str> = notices.iter().filter(|l| l.contains(name)).collect();
        assert_eq!(named.len(), 1, "{name}: {}", out.stderr);
        assert!(named[0].contains(mode), "{}", named[0]);
    }
    for grant in ["shared", "group", "private"] {
        assert!(
            out.stdout
                .contains(&format!("read:  granted by /opt/{grant}/**")),
            "the {grant} base did not load: {}",
            out.stdout
        );
    }

    // SAFETY: geteuid is a trivial always-successful syscall with no memory effects.
    if unsafe { libc::geteuid() } != 0 {
        eprintln!(
            "not root: a base owned by another account cannot be created here; the owner rows \
             of FW-BP32 are covered by its unit test"
        );
        return;
    }
    use std::os::unix::process::CommandExt;
    const INVOKING: u32 = 65534;
    const THIRD: u32 = 54321;
    let owned = |name: &str, owner: u32| -> String {
        let path = base(name, name.trim_end_matches(".toml"), 0o644);
        std::os::unix::fs::chown(&path, Some(owner), None).unwrap();
        path.to_str().unwrap().to_string()
    };
    let project = dir.path().join("owners");
    std::fs::create_dir(&project).unwrap();
    std::fs::write(
        project.join("FORMWORK.toml"),
        format!(
            "extends = [{:?}, {:?}, {:?}]\n",
            owned("root-owned.toml", 0),
            owned("own.toml", INVOKING),
            owned("third.toml", THIRD)
        ),
    )
    .unwrap();
    let explain_as = |uid: u32| {
        let args = ["explain", "--blueprint", "FORMWORK.toml", "/opt/third/x"];
        let mut command = formwork_command(&project, &args, &[], &[]);
        if uid != 0 {
            command.uid(uid).gid(uid);
        }
        let out = command.output().expect("running formwork");
        let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
        assert!(out.status.success(), "{stderr}");
        let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
        assert!(
            stdout.contains("read:  granted by /opt/third/**"),
            "{stdout}"
        );
        stderr
    };
    // To root, the two bases it does not own belong to other accounts.
    let as_root = explain_as(0);
    let notices = base_notices(&as_root);
    assert_eq!(notices.len(), 2, "{as_root}");
    assert!(notices
        .iter()
        .any(|l| l.contains("own.toml") && l.contains("uid 65534")));
    assert!(notices
        .iter()
        .any(|l| l.contains("third.toml") && l.contains("uid 54321")));
    // To the account that owns `own.toml`, only the third account's base is another's.
    let as_user = explain_as(INVOKING);
    let notices = base_notices(&as_user);
    assert_eq!(notices.len(), 1, "{as_user}");
    assert!(notices[0].contains("third.toml") && notices[0].contains("uid 54321"));
}
