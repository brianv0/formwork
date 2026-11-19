//! Report rows that follow the host (FW-INV5), named for the requirements they discharge. Each
//! compiles for a synthesized `HostProfile`, the one substitution the pure compiler admits.

use formwork_blueprint::{Blueprint, PathPattern, ResolvedCatalog};
use formwork_compile::{Backend, Capability, Fidelity, FidelityReport};
use formwork_detect::HostProfile;

fn report(blueprint: &Blueprint, host: &HostProfile) -> FidelityReport {
    formwork_compile::compile(
        blueprint,
        host,
        &ResolvedCatalog::builtin_for_home("/home/x").unwrap(),
    )
    .report
}

fn pp(s: &str) -> PathPattern {
    PathPattern::parse(s).unwrap()
}

fn writes_only() -> Blueprint {
    let mut blueprint = Blueprint::empty();
    blueprint.fs.writes = vec![pp("/work/project/**")];
    blueprint
}

/// A write grant with one absolute write-subtract row, so no any-depth row is withheld and the
/// verdict turns on the ABI alone.
fn write_subtract() -> Blueprint {
    let mut blueprint = writes_only();
    blueprint.fs.write_subtract = vec![pp("/work/project/.envrc")];
    blueprint
}

const LANDLOCK: Fidelity = Fidelity::Enforced {
    backend: Backend::Landlock,
};

fn partial_reason(fidelity: &Fidelity, backend: Backend) -> &str {
    match fidelity {
        Fidelity::Partial { backend: b, reason } if *b == backend => reason,
        other => panic!("expected Partial({backend:?}), got {other:?}"),
    }
}

/// FW-E2E-214 (FW-FID34): Landlock's truncate right arrives at ABI 3, so below it a write deny
/// does not stop truncation and the write rows say so; from ABI 3 they are `Enforced`.
#[test]
fn fw_fid34_write_rows_are_partial_below_the_truncate_abi() {
    for abi in [1, 2] {
        let host = HostProfile::synthetic_linux(Some(abi));
        let rows = report(&write_subtract(), &host).per_capability;
        for cap in [Capability::TamperVectors, Capability::FsWrite] {
            let reason = partial_reason(&rows[&cap], Backend::Landlock);
            assert!(reason.contains("truncation"), "ABI {abi} {cap}: {reason}");
            assert!(
                reason.contains(&format!("ABI v{abi}")),
                "ABI {abi} {cap}: {reason}"
            );
        }
        // The read row makes no write claim and is untouched.
        assert_eq!(rows[&Capability::FsRead], LANDLOCK, "ABI {abi}");

        let rows = report(&writes_only(), &host).per_capability;
        let reason = partial_reason(&rows[&Capability::FsWrite], Backend::Landlock);
        assert!(reason.contains("truncation"), "ABI {abi}: {reason}");
        assert!(!rows.contains_key(&Capability::TamperVectors), "ABI {abi}");
    }

    for abi in [3, 7] {
        let host = HostProfile::synthetic_linux(Some(abi));
        let rows = report(&write_subtract(), &host).per_capability;
        assert_eq!(rows[&Capability::TamperVectors], LANDLOCK, "ABI {abi}");
        assert_eq!(rows[&Capability::FsWrite], LANDLOCK, "ABI {abi}");
        let rows = report(&writes_only(), &host).per_capability;
        assert_eq!(rows[&Capability::FsWrite], LANDLOCK, "ABI {abi}");
    }

    let rows = report(&write_subtract(), &HostProfile::synthetic_linux(None)).per_capability;
    for cap in [Capability::TamperVectors, Capability::FsWrite] {
        assert!(
            matches!(rows[&cap], Fidelity::Unenforceable { .. }),
            "{cap} without Landlock: {:?}",
            rows[&cap]
        );
    }
}

/// FW-E2E-214 (FW-FID34): where any-depth rows are withheld as well, the reason carries both
/// gaps, and it calls the absolute rows enforced only on a host that stops truncation.
#[test]
fn fw_fid34_truncation_joins_the_withheld_reason() {
    let mut blueprint = write_subtract();
    blueprint.fs.write_subtract.push(pp("**/.git/config"));
    let reason_at = |abi: u32| {
        let rows = report(&blueprint, &HostProfile::synthetic_linux(Some(abi))).per_capability;
        partial_reason(&rows[&Capability::TamperVectors], Backend::Landlock).to_string()
    };

    let below = reason_at(2);
    assert!(below.contains("withheld on Linux"), "{below}");
    assert!(below.contains("truncation"), "{below}");
    assert!(!below.contains("absolute rows are enforced"), "{below}");

    let at = reason_at(3);
    assert!(at.contains("withheld on Linux"), "{at}");
    assert!(at.contains("absolute rows are enforced"), "{at}");
    assert!(!at.contains("truncation"), "{at}");
}
