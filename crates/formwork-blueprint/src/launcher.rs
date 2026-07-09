//! The launcher's environment construction (FEP-2 §6, FW-CRED2 env arm). Pure: given the ambient
//! variables, the env posture, and the resolved catalog, decide what the confined child receives.
//! The impure application -- reading the real environment, building the `Command` -- stays in the
//! CLI shell. Order matters and is fixed: the posture filters first (FW-ENV1/2), then the catalog
//! strip removes every non-excluded type's variables from whatever survived (FW-CRED4). A stripped
//! variable is absent, not empty -- the child and its whole descendant tree can never inherit it
//! (FW-INV7) and cannot distinguish it from never-set (FW-INV9).

use crate::{EnvPosture, ResolvedCatalog};

/// The launcher's decision, with the operator-channel itemization (FW-CRED7). Names only, never
/// values -- secrets never hit logs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EnvConstruction {
    pub kept: Vec<(String, String)>,
    /// Catalog strips: `(variable name, credential type)`, sorted by name.
    pub stripped: Vec<(String, String)>,
    /// Names the posture itself dropped (FW-ENV1/2 telemetry, unchanged semantics).
    pub posture_dropped: Vec<String>,
}

/// Build the confined child's environment. The catalog strip is the floor, so it partitions
/// FIRST -- a catalog variable is stripped and attributed to its type no matter what the posture
/// would have said (FW-CRED4; the FW-CRED7 detector names the type, not the heuristic that also
/// happened to match). The posture then filters the remainder. `allow` (FW-CRED5) lifts a type's
/// variables from the strip *and* exempts them from the scrub's secret-shape heuristic, so an
/// excluded credential is usable, not merely present-in-theory. A variable claimed by both an
/// allowed and an enforced type stays stripped -- deny wins.
pub fn construct_env(
    posture: &EnvPosture,
    catalog: &ResolvedCatalog,
    allow: &[String],
    vars: Vec<(String, String)>,
) -> EnvConstruction {
    let mut strip: Vec<(String, String)> = Vec::new();
    for (type_name, entry) in catalog.enforced_types(allow) {
        for var in &entry.envs {
            strip.push((var.clone(), type_name.to_string()));
        }
    }
    strip.sort();
    strip.dedup();

    let (stripped_pairs, remainder): (Vec<_>, Vec<_>) = vars
        .into_iter()
        .partition(|(name, _)| strip.iter().any(|(s, _)| s == name));
    let mut stripped: Vec<(String, String)> = stripped_pairs
        .into_iter()
        .map(|(name, _)| {
            let type_name = strip
                .iter()
                .find(|(s, _)| s == &name)
                .map(|(_, t)| t.clone())
                .unwrap_or_default();
            (name, type_name)
        })
        .collect();
    stripped.sort();

    let mut lifted: Vec<String> = catalog
        .types
        .iter()
        .filter(|(name, _)| allow.iter().any(|a| a == name.as_str()))
        .flat_map(|(_, entry)| entry.envs.iter().cloned())
        .filter(|var| !strip.iter().any(|(s, _)| s == var))
        .collect();
    lifted.sort();
    lifted.dedup();

    // An excluded type's variables must survive the FW-ENV2 shape heuristic (they are secrets by
    // shape, deliberately admitted), so they join the scrub's allow list. Allowlist postures stay
    // exact: the operator's explicit list is not widened.
    let effective = match posture {
        EnvPosture::Scrub(scrub) => {
            let mut widened = scrub.clone();
            widened.allow.extend(lifted.iter().cloned());
            EnvPosture::Scrub(widened)
        }
        other => other.clone(),
    };

    let posture_dropped = effective.dropped_names(&remainder);
    let kept = effective.apply(remainder);

    EnvConstruction {
        kept,
        stripped,
        posture_dropped,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::EnvScrub;

    fn vars(pairs: &[(&str, &str)]) -> Vec<(String, String)> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    fn catalog() -> ResolvedCatalog {
        ResolvedCatalog::builtin_for_home("/home/x").unwrap()
    }

    #[test]
    fn catalog_vars_are_stripped_even_under_passthrough() {
        let out = construct_env(
            &EnvPosture::Passthrough,
            &catalog(),
            &[],
            vars(&[("AWS_SECRET_ACCESS_KEY", "x"), ("PATH", "/usr/bin")]),
        );
        let kept: Vec<&str> = out.kept.iter().map(|(k, _)| k.as_str()).collect();
        assert_eq!(kept, vec!["PATH"]);
        assert_eq!(
            out.stripped,
            vec![("AWS_SECRET_ACCESS_KEY".to_string(), "aws".to_string())]
        );
    }

    #[test]
    fn allowed_type_survives_strip_and_scrub_shape() {
        // --allow-cred aws under the default scrub: the AWS vars must come through usable even
        // though their names are secret-shaped (FW-CRED5).
        let out = construct_env(
            &EnvPosture::Scrub(EnvScrub::default()),
            &catalog(),
            &["aws".to_string()],
            vars(&[
                ("AWS_SECRET_ACCESS_KEY", "k"),
                ("ANTHROPIC_API_KEY", "sk-1"),
                ("PATH", "/usr/bin"),
            ]),
        );
        let kept: Vec<&str> = out.kept.iter().map(|(k, _)| k.as_str()).collect();
        assert!(kept.contains(&"AWS_SECRET_ACCESS_KEY"), "{kept:?}");
        assert!(kept.contains(&"PATH"));
        assert!(
            !kept.contains(&"ANTHROPIC_API_KEY"),
            "adjacent type must stay stripped (FW-E2E-048)"
        );
        assert!(out
            .stripped
            .contains(&("ANTHROPIC_API_KEY".to_string(), "anthropic".to_string())));
    }

    #[test]
    fn explicit_allowlist_posture_is_not_widened() {
        let out = construct_env(
            &EnvPosture::Allowlist(vec!["PATH".to_string()]),
            &catalog(),
            &["aws".to_string()],
            vars(&[("AWS_SECRET_ACCESS_KEY", "k"), ("PATH", "/usr/bin")]),
        );
        let kept: Vec<&str> = out.kept.iter().map(|(k, _)| k.as_str()).collect();
        assert_eq!(kept, vec!["PATH"], "allowlist stays exact");
    }

    #[test]
    fn strip_is_absence_not_empty_value() {
        let out = construct_env(
            &EnvPosture::Passthrough,
            &catalog(),
            &[],
            vars(&[("GITHUB_TOKEN", "t")]),
        );
        assert!(out.kept.is_empty());
        assert!(!out.kept.iter().any(|(k, _)| k == "GITHUB_TOKEN"));
    }
}
