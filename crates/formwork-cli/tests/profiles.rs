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
    "/run/secrets/**",
    "/var/run/secrets/**",
];

const CORE_ENV_STRIPS: &[&str] = &[
    "AWS_SECRET_ACCESS_KEY",
    "AWS_WEB_IDENTITY_TOKEN_FILE",
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

/// What the Catalog does with one variable a tool reads a configuration or credential location
/// from.
enum Reach {
    /// The named type carries it as an `env-dir-refs` or `env-file-refs` entry.
    Modelled(&'static str),
    /// Left out on purpose, with the reason.
    NotModelled(&'static str),
}
use Reach::{Modelled, NotModelled};

/// FW-E2E-202: per tool, the variables it reads such a location from. A row is `Modelled` once
/// the Catalog carries the variable, or `NotModelled` with a reason a reviewer can disagree with
/// -- never absent.
const RELOCATION_VARIABLES: &[(&str, &str, Reach)] = &[
    ("gh", "GH_CONFIG_DIR", Modelled("github")),
    ("gh", "XDG_CONFIG_HOME", Modelled("github")),
    (
        "gh",
        "XDG_STATE_HOME",
        NotModelled("holds gh's update-check state, no token"),
    ),
    (
        "gh",
        "XDG_DATA_HOME",
        NotModelled("holds gh's extensions, no token"),
    ),
    (
        "git",
        "GIT_CONFIG_GLOBAL",
        NotModelled("relocates ~/.gitconfig, which is not a Catalog path; git needs to read it"),
    ),
    (
        "git",
        "GIT_CONFIG_SYSTEM",
        NotModelled("relocates /etc/gitconfig, which is not a Catalog path"),
    ),
    (
        "git",
        "XDG_CONFIG_HOME",
        NotModelled(
            "moves git's second credential-store file, $XDG_CONFIG_HOME/git/credentials, which is \
             not a Catalog path; the backstop's `credentials` shape covers it where any-depth \
             rows are enforced",
        ),
    ),
    ("docker", "DOCKER_CONFIG", Modelled("docker")),
    ("docker", "DOCKER_CERT_PATH", Modelled("docker")),
    (
        "docker",
        "DOCKER_HOST",
        NotModelled("names the daemon's endpoint, not a store; its socket needs a grant (FW-ISO12)"),
    ),
    ("kubectl", "KUBECONFIG", Modelled("kube")),
    (
        "kubectl",
        "KUBECACHEDIR",
        NotModelled("holds the discovery and HTTP caches, no credential"),
    ),
    ("aws", "AWS_CONFIG_FILE", Modelled("aws")),
    ("aws", "AWS_SHARED_CREDENTIALS_FILE", Modelled("aws")),
    ("aws", "AWS_WEB_IDENTITY_TOKEN_FILE", Modelled("aws")),
    (
        "aws",
        "AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE",
        Modelled("aws"),
    ),
    (
        "aws",
        "AWS_CA_BUNDLE",
        NotModelled("names a certificate bundle, which is public"),
    ),
    ("gcloud", "CLOUDSDK_CONFIG", Modelled("gcp")),
    ("gcloud", "GOOGLE_APPLICATION_CREDENTIALS", Modelled("gcp")),
    (
        "gcloud",
        "BOTO_CONFIG",
        NotModelled("relocates ~/.boto, which is not a Catalog path"),
    ),
    (
        "npm",
        "NPM_CONFIG_USERCONFIG",
        NotModelled(
            "an .npmrc outside ~ is the operator's to deny (examples/README.md): CI points this at \
             a file with no secret in it, and denying that breaks installs",
        ),
    ),
    (
        "npm",
        "NPM_CONFIG_GLOBALCONFIG",
        NotModelled("as NPM_CONFIG_USERCONFIG: an .npmrc outside ~ is the operator's to deny"),
    ),
    (
        "npm",
        "NPM_CONFIG_CACHE",
        NotModelled("holds the package cache, no credential"),
    ),
    ("cargo", "CARGO_HOME", Modelled("cargo")),
    (
        "pip",
        "PIP_CONFIG_FILE",
        NotModelled(
            "relocates pip.conf, which is not a Catalog path; ~/.pypirc does not move with it",
        ),
    ),
    (
        "pip",
        "XDG_CONFIG_HOME",
        NotModelled("moves pip.conf, which is not a Catalog path"),
    ),
    ("gpg", "GNUPGHOME", Modelled("gpg")),
    (
        "ssh",
        "SSH_AUTH_SOCK",
        NotModelled(
            "names the agent's socket, not a store: a pathname socket is reached only through a \
             grant on it (FW-ISO12), and OpenSSH has no variable that moves ~/.ssh",
        ),
    ),
    ("go", "NETRC", Modelled("netrc")),
    ("az", "AZURE_CONFIG_DIR", Modelled("azure")),
    ("az", "AZURE_FEDERATED_TOKEN_FILE", Modelled("azure")),
    ("az", "AZURE_CLIENT_CERTIFICATE_PATH", Modelled("azure")),
    ("claude", "CLAUDE_CONFIG_DIR", Modelled("claude")),
    ("codex", "CODEX_HOME", Modelled("codex")),
    ("chrome", "XDG_CONFIG_HOME", Modelled("browser")),
    ("chrome", "CHROME_CONFIG_HOME", Modelled("browser")),
    (
        "chrome",
        "CHROME_USER_DATA_DIR",
        NotModelled(
            "names one profile directory; the headless build this was checked against did not \
             honour it, and an entry is added only for behaviour that is documented or was seen",
        ),
    ),
];

/// The tools the agent examples document; each has at least one row above.
const DOCUMENTED_TOOLS: &[&str] = &[
    "gh", "git", "docker", "kubectl", "aws", "gcloud", "npm", "cargo", "pip", "gpg", "ssh",
];

/// A type whose path sits under an XDG base directory while its tool reads no XDG variable.
const XDG_EXEMPT: &[(&str, &str)] = &[(
    "gcp",
    "gcloud and the Google auth libraries read CLOUDSDK_CONFIG and ignore XDG_CONFIG_HOME",
)];

fn reference_variables(entry: &formwork_blueprint::CatalogEntry) -> Vec<&str> {
    let dirs = entry.env_dir_refs.iter().map(|r| r.var.as_str());
    dirs.chain(entry.env_file_refs.iter().map(|r| r.var.as_str()))
        .collect()
}

#[test]
fn fw_e2e_202_each_documented_relocation_variable_is_modelled_or_listed_with_a_reason() {
    let catalog = Catalog::builtin();
    for tool in DOCUMENTED_TOOLS {
        assert!(
            RELOCATION_VARIABLES.iter().any(|(t, ..)| t == tool),
            "{tool} has no row"
        );
    }
    for (tool, var, reach) in RELOCATION_VARIABLES {
        match reach {
            Modelled(type_name) => {
                let entry = catalog
                    .types
                    .get(*type_name)
                    .unwrap_or_else(|| panic!("{tool}/{var}: no Catalog type {type_name}"));
                assert!(
                    reference_variables(entry).contains(var),
                    "{tool}: {var} is listed as modelled, and type {type_name} does not carry it"
                );
            }
            NotModelled(reason) => assert!(
                reason.len() > 20,
                "{tool}: {var} is left out and the reason does not say why"
            ),
        }
    }
    // The other direction: a reference the Catalog gains has to be claimed here, so the list
    // above stays the whole of what the Catalog follows.
    for (type_name, entry) in &catalog.types {
        for var in reference_variables(entry) {
            assert!(
                RELOCATION_VARIABLES.iter().any(
                    |(_, v, reach)| *v == var && matches!(reach, Modelled(t) if t == type_name)
                ),
                "{type_name} follows {var}, and no row lists it as modelled for that type"
            );
        }
    }
}

/// The XDG base directories move every store beneath them, so a type with a path under one
/// follows the variable or says why its tool does not. No type has a path under the data or state
/// directory today; the first that does has to follow `XDG_DATA_HOME` or `XDG_STATE_HOME`.
#[test]
fn fw_e2e_202_every_type_under_an_xdg_directory_follows_its_variable() {
    const BASES: &[(&str, &str)] = &[
        ("XDG_CONFIG_HOME", "~/.config"),
        ("XDG_DATA_HOME", "~/.local/share"),
        ("XDG_STATE_HOME", "~/.local/state"),
    ];
    let catalog = Catalog::builtin();
    let mut followed = 0;
    for (type_name, entry) in &catalog.types {
        for (var, base) in BASES {
            let under = entry.paths.iter().any(|p| {
                p.strip_prefix(base)
                    .is_some_and(|rest| rest.starts_with('/'))
            });
            if !under || XDG_EXEMPT.iter().any(|(t, _)| t == type_name) {
                continue;
            }
            followed += 1;
            assert!(
                entry
                    .env_dir_refs
                    .iter()
                    .any(|r| r.var == *var && r.replaces == *base),
                "{type_name} has a path under {base} and does not follow {var}"
            );
        }
    }
    assert!(followed >= 2, "github and browser sit under ~/.config");
    for (type_name, reason) in XDG_EXEMPT {
        assert!(catalog.types.contains_key(*type_name) && reason.len() > 20);
    }
}
