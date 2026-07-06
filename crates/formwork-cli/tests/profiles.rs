//! Profile-consistency tests. `profiles/sensitive-set.toml` is the canonical, category-grouped
//! sensitive superset (FW-TRA3); `profiles/default.toml` mirrors it into its flat `fs.subtract`.
//! Dropping a category from `default.toml` while it stays in `sensitive-set.toml` would silently
//! un-deny a secret location under the broad default read grant -- this test forbids that drift.

use std::collections::BTreeSet;
use std::path::PathBuf;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .canonicalize()
        .expect("repo root resolves")
}

fn read_toml(rel: &str) -> toml::Value {
    let path = repo_root().join(rel);
    let text = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {rel}: {e}"));
    toml::from_str(&text).unwrap_or_else(|e| panic!("parse {rel}: {e}"))
}

fn sensitive_set_paths() -> BTreeSet<String> {
    let doc = read_toml("profiles/sensitive-set.toml");
    let mut paths = BTreeSet::new();
    for (_category, table) in doc.as_table().expect("sensitive-set is a table") {
        let table = table
            .as_table()
            .expect("each category is a table of arrays");
        for (_key, val) in table {
            for entry in val.as_array().expect("each entry is an array") {
                paths.insert(entry.as_str().expect("entries are strings").to_string());
            }
        }
    }
    paths
}

fn default_subtract_paths() -> BTreeSet<String> {
    let doc = read_toml("profiles/default.toml");
    doc["fs"]["subtract"]
        .as_array()
        .expect("default.toml [fs].subtract is an array")
        .iter()
        .map(|v| {
            v.as_str()
                .expect("subtract entries are strings")
                .to_string()
        })
        .collect()
}

#[test]
fn default_subtract_covers_the_whole_sensitive_set() {
    let sensitive = sensitive_set_paths();
    let subtract = default_subtract_paths();
    let missing: Vec<&String> = sensitive.difference(&subtract).collect();
    assert!(
        missing.is_empty(),
        "default.toml [fs].subtract is missing sensitive-set.toml paths (a secret would be readable \
         under the broad default grant): {missing:?}"
    );
}

#[test]
fn sensitive_set_is_non_empty() {
    // Guard against the sync test passing vacuously if the list is emptied or mis-parsed.
    assert!(
        sensitive_set_paths().len() >= 10,
        "sensitive-set.toml looks unexpectedly small"
    );
}
