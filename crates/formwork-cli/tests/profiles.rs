//! Catalog-consistency canaries. The credential catalog (profiles/credential-catalog.toml,
//! compiled into the binary, FW-CRED1) superseded the old sensitive-set/default-profile pair;
//! the drift these tests forbid is a core credential location silently falling OUT of the
//! catalog -- that would un-deny a secret under every broad grant with no diff to any blueprint
//! (fail-open of the floor, FW-INV6).

use formwork_blueprint::{Catalog, ResolvedCatalog};

/// Locations that must never leave the floor. Grow this list; shrinking it is a human decision
/// with a review, which is the point.
const CORE_LOCATIONS: &[&str] = &[
    "/home/x/.ssh/**",
    "/home/x/.gnupg/**",
    "/home/x/.aws/**",
    "/home/x/.config/gcloud/**",
    "/home/x/.azure/**",
    "/home/x/.kube/**",
    "/home/x/.docker/**",
    "/home/x/.netrc",
    "/home/x/.npmrc",
    "/home/x/.pypirc",
    "/home/x/.config/gh/**",
    "/home/x/.git-credentials",
    "/home/x/.claude/**",
    "/home/x/.codex/**",
    "/home/x/.gemini/**",
    "/home/x/.cursor/**",
    "/home/x/Library/Keychains/**",
    "/Library/Keychains/**",
    "/etc/shadow",
    "/etc/sudoers",
    "**/.env",
];

const CORE_ENV_STRIPS: &[&str] = &[
    "AWS_SECRET_ACCESS_KEY",
    "GOOGLE_APPLICATION_CREDENTIALS",
    "GITHUB_TOKEN",
    "ANTHROPIC_API_KEY",
    "SLACK_BOT_TOKEN",
];

#[test]
fn catalog_floor_covers_the_core_sensitive_locations() {
    let resolved = ResolvedCatalog::builtin_for_home("/home/x").expect("builtin catalog resolves");
    let denied: Vec<String> = resolved
        .denied_paths(&[])
        .iter()
        .map(|p| p.canonical())
        .collect();
    let missing: Vec<&&str> = CORE_LOCATIONS
        .iter()
        .filter(|loc| !denied.iter().any(|d| d == **loc))
        .collect();
    assert!(
        missing.is_empty(),
        "core sensitive locations fell out of the catalog floor: {missing:?}"
    );
}

#[test]
fn catalog_floor_strips_the_core_env_credentials() {
    let resolved = ResolvedCatalog::builtin_for_home("/home/x").expect("builtin catalog resolves");
    let stripped: Vec<&str> = resolved
        .enforced_types(&[])
        .flat_map(|(_, e)| e.envs.iter().map(String::as_str))
        .collect();
    let missing: Vec<&&str> = CORE_ENV_STRIPS
        .iter()
        .filter(|v| !stripped.contains(*v))
        .collect();
    assert!(
        missing.is_empty(),
        "core env credentials fell out of the catalog floor: {missing:?}"
    );
}

#[test]
fn catalog_is_versioned_and_non_trivial() {
    let catalog = Catalog::builtin();
    assert!(catalog.version >= 1);
    assert!(
        catalog.types.len() >= 15,
        "catalog looks unexpectedly small: {} types",
        catalog.types.len()
    );
}
