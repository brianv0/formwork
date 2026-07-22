//! A real open-trace, synthesized. A subprocess is run under `strace`, its actual `openat` log is
//! parsed into `AccessRecord`s, and `synthesize_blueprint` is checked against what the process
//! really touched -- the grant covers the files it read and wrote, and a credential it opened is
//! floored, never a grant (FW-DISC3 / FW-INV8). strace stands in for the macOS observation feed;
//! the value here is that synthesis is verified against a live process's opens, not authored records.

#![cfg(target_os = "linux")]

use std::fs;
use std::process::Command;

use formwork_blueprint::{synthesize_blueprint, AccessRecord, DenialAccess, ResolvedCatalog};

/// Successful `openat` opens of absolute paths under `root`, so loader/libc noise and failed probes
/// (`= -1 …`) drop out. Read vs write is taken from the real open flags.
fn parse_openat(trace: &str, root: &str) -> Vec<AccessRecord> {
    let mut records = Vec::new();
    for line in trace.lines() {
        let Some(call) = line.find("openat(") else {
            continue;
        };
        let rest = &line[call..];
        let Some(eq) = rest.rfind("= ") else {
            continue;
        };
        if !rest[eq + 2..]
            .trim_start()
            .starts_with(|c: char| c.is_ascii_digit())
        {
            continue;
        }
        let Some(q1) = rest.find('"') else { continue };
        let Some(q2) = rest[q1 + 1..].find('"') else {
            continue;
        };
        let path = &rest[q1 + 1..q1 + 1 + q2];
        if !path.starts_with(root) {
            continue;
        }
        let flags = &rest[q1 + 1 + q2 + 1..eq];
        let access = if flags.contains("O_WRONLY")
            || flags.contains("O_RDWR")
            || flags.contains("O_CREAT")
        {
            DenialAccess::Write
        } else {
            DenialAccess::Read
        };
        records.push(AccessRecord {
            path: path.to_string(),
            access,
        });
    }
    records
}

#[test]
fn synthesizes_a_blueprint_from_a_real_open_trace() {
    let home = std::env::temp_dir().join(format!("fw-record-{}", std::process::id()));
    let proj = home.join("proj");
    let ssh = home.join(".ssh");
    fs::create_dir_all(&proj).unwrap();
    fs::create_dir_all(&ssh).unwrap();
    fs::write(proj.join("a.txt"), b"a").unwrap();
    fs::write(proj.join("b.txt"), b"b").unwrap();
    fs::write(ssh.join("id_rsa"), b"PRIVATE KEY").unwrap();

    let home_s = home.to_str().unwrap().to_string();
    // A real workload: read two project files, write a third, read a credential.
    let script = format!(
        "cat {p}/a.txt {p}/b.txt > /dev/null; echo x > {p}/out.txt; cat {s}/id_rsa > /dev/null",
        p = proj.display(),
        s = ssh.display(),
    );
    let trace_file = std::env::temp_dir().join(format!("fw-record-trace-{}", std::process::id()));
    let output = Command::new("strace")
        .args(["-f", "-e", "trace=openat", "-o"])
        .arg(&trace_file)
        .args(["/bin/sh", "-c", &script])
        .output();

    // strace may be absent, or ptrace blocked (some CI sandboxes); that is a skip, not a failure.
    let ran = matches!(&output, Ok(o) if o.status.success());
    if !ran {
        let _ = fs::remove_dir_all(&home);
        let _ = fs::remove_file(&trace_file);
        eprintln!("skipping: strace could not trace a subprocess in this environment");
        return;
    }

    let trace = fs::read_to_string(&trace_file).unwrap();
    let records = parse_openat(&trace, &home_s);
    assert!(
        !records.is_empty(),
        "strace ran but no opens under {home_s} were parsed; trace was:\n{trace}"
    );

    let catalog = ResolvedCatalog::builtin_for_home(&home_s).unwrap();
    let blueprint = synthesize_blueprint(&records, &catalog, &[]);
    let reads: Vec<String> = blueprint.fs.reads.iter().map(|p| p.canonical()).collect();
    let writes: Vec<String> = blueprint.fs.writes.iter().map(|p| p.canonical()).collect();

    let touches_ssh = |set: &[String]| set.iter().any(|p| p.contains("/.ssh/"));
    assert!(
        !touches_ssh(&reads) && !touches_ssh(&writes),
        "the credential the process opened must be floored: reads={reads:?} writes={writes:?}"
    );
    // The two files it read fold into their parent subtree; the file it wrote is a write grant.
    assert!(
        reads.contains(&format!("{home_s}/proj/**")),
        "expected the read files granted as a subtree: {reads:?}"
    );
    assert!(
        writes.contains(&format!("{home_s}/proj/out.txt")),
        "expected the written file as a write grant: {writes:?}"
    );

    let _ = fs::remove_dir_all(&home);
    let _ = fs::remove_file(&trace_file);
}
