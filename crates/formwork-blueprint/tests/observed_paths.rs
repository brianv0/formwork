//! Discovery holds an observed path as the one object it names (FW-BP31). A confined process
//! chooses its own file names, so a name that spells pattern grammar must never become a grant
//! that reaches further than the file that was opened.

use std::path::Path;

use formwork_blueprint::{
    synthesize_blueprint, AccessRecord, DenialAccess, PathPattern, ResolvedCatalog,
};

/// Names a process can create that the pattern grammar gives a meaning to, one per directory so
/// the sibling fold (two denials under one parent become `parent/**`) stays out of the picture.
const HOSTILE: &[&str] = &[
    "/zone/a/**",
    "/zone/b/**/config",
    "/zone/c/x/**/y/**",
    "/zone/d/*.pem",
    "/zone/e/key?",
    "/zone/f/[id]",
    "/zone/g/back\\*slash",
    "/zone/h/back\\\\slash",
];

/// Paths each hostile name would reach if any character of it were read as grammar.
const NEIGHBOURS: &[&str] = &[
    "/zone/a/other",
    "/zone/b/deep/down/config",
    "/zone/c/x/1/y/2",
    "/zone/d/prod.pem",
    "/zone/e/keys",
    "/zone/f/i",
    "/zone/g/back*slash",
    "/zone/h/back\\slash",
];

/// FW-ADV-049: every grant synthesized from a hostile name is a literal for exactly that name.
#[test]
fn fw_adv_049_a_hostile_file_name_never_widens_a_candidate() {
    for access in [DenialAccess::Read, DenialAccess::Write] {
        let records: Vec<AccessRecord> = HOSTILE
            .iter()
            .map(|path| AccessRecord {
                path: path.to_string(),
                access,
            })
            .collect();
        let blueprint = synthesize_blueprint(&records, &ResolvedCatalog::empty_no_floor(), &[]);
        let grants: Vec<&PathPattern> = blueprint
            .fs
            .reads
            .iter()
            .chain(blueprint.fs.writes.iter())
            .collect();
        // A grant may be withheld; one that is made names an observed path and nothing else.
        for grant in &grants {
            assert!(
                !grant.is_subtree() && !grant.is_any_depth(),
                "{grant} is wider than one path"
            );
            assert!(
                HOSTILE.iter().any(|path| grant.base() == Path::new(path)),
                "{grant} names a path that was never observed"
            );
            for neighbour in NEIGHBOURS {
                assert!(
                    !grant.matches_path(Path::new(neighbour)),
                    "{grant} reaches {neighbour}"
                );
            }
            // The discovered layer stores the canonical string; it reads back as the same grant.
            assert_eq!(&&PathPattern::parse(&grant.canonical()).unwrap(), grant);
        }
        // The names with no `**` component are ordinary files: each is proposed, as itself.
        for path in HOSTILE.iter().filter(|p| !p.contains("**")) {
            assert!(
                grants.iter().any(|g| g.base() == Path::new(path)),
                "{path} was dropped instead of proposed as a literal"
            );
        }
    }
}
