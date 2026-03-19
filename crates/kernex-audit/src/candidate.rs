use std::collections::{HashMap, HashSet};

use serde::{Deserialize, Serialize};

use crate::error::AuditError;
use crate::observation::{AuditObservation, ObservedResource, SensitiveResource, SensitiveWarning};

/// The union of all resource observations from one or more audit sessions,
/// annotated with per-resource confidence scores.
///
/// Produced by [`crate::session::AuditSession::finish`] for a single session,
/// or by [`merge`] to accumulate observations across multiple sessions.
///
/// # Lifecycle
///
/// ```text
/// AuditSession::finish()  →  PolicyCandidate (sessions_seen = 1)
/// merge(&[c1, c2, c3])    →  PolicyCandidate (sessions_seen per resource = 1–3)
/// kernex-cli              →  converts PolicyCandidate → KernexPolicy → kernex.yaml
/// ```
///
/// `kernex-audit` does not perform the final conversion to `KernexPolicy` —
/// that is the CLI's responsibility (it must handle sensitive-path prompts and
/// user confirmations before writing).
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct PolicyCandidate {
    /// Human-readable agent name (passed to [`crate::session::AuditSession::finish`]).
    pub agent_name: String,

    /// Deduplicated, non-sensitive resource observations.
    ///
    /// Sensitive paths and env vars are **never** present here; they appear
    /// only in [`PolicyCandidate::sensitive_warnings`].
    pub observations: Vec<AuditObservation>,

    /// Warnings for sensitive resources accessed during the audit.
    ///
    /// These must be shown to the user and explicitly approved before being
    /// written to `kernex.yaml`.
    pub sensitive_warnings: Vec<SensitiveWarning>,
}

impl PolicyCandidate {
    /// Iterate over file-read observations.
    pub fn fs_reads(&self) -> impl Iterator<Item = &AuditObservation> {
        self.observations
            .iter()
            .filter(|o| matches!(o.resource, ObservedResource::FileRead(_)))
    }

    /// Iterate over file-write observations.
    pub fn fs_writes(&self) -> impl Iterator<Item = &AuditObservation> {
        self.observations
            .iter()
            .filter(|o| matches!(o.resource, ObservedResource::FileWrite(_)))
    }

    /// Iterate over file-execution observations.
    pub fn fs_execs(&self) -> impl Iterator<Item = &AuditObservation> {
        self.observations
            .iter()
            .filter(|o| matches!(o.resource, ObservedResource::FileExec(_)))
    }

    /// Iterate over network-connection observations.
    pub fn network_connections(&self) -> impl Iterator<Item = &AuditObservation> {
        self.observations
            .iter()
            .filter(|o| matches!(o.resource, ObservedResource::Network { .. }))
    }

    /// Iterate over environment-variable-read observations.
    pub fn env_var_reads(&self) -> impl Iterator<Item = &AuditObservation> {
        self.observations
            .iter()
            .filter(|o| matches!(o.resource, ObservedResource::EnvVar(_)))
    }
}

/// Merge multiple [`PolicyCandidate`]s from different audit sessions.
///
/// The result contains the union of all observations. A resource seen in N
/// sessions has `sessions_seen = N` and a proportionally higher `confidence`.
/// Sensitive warnings are deduplicated.
///
/// # Errors
///
/// Returns [`AuditError::EmptyCandidateList`] if `candidates` is empty.
pub fn merge(candidates: &[PolicyCandidate]) -> Result<PolicyCandidate, AuditError> {
    if candidates.is_empty() {
        return Err(AuditError::EmptyCandidateList);
    }

    // Use the first non-empty agent name.
    let agent_name = candidates
        .iter()
        .find(|c| !c.agent_name.is_empty())
        .map(|c| c.agent_name.clone())
        .unwrap_or_default();

    // Accumulate session counts per unique resource.
    let mut counts: HashMap<ObservedResource, u32> = HashMap::new();
    // Deduplicate sensitive warnings by resource.
    let mut warned: HashSet<SensitiveResource> = HashSet::new();
    let mut sensitive_warnings: Vec<SensitiveWarning> = Vec::new();

    for candidate in candidates {
        for obs in &candidate.observations {
            *counts.entry(obs.resource.clone()).or_insert(0) += 1;
        }
        for warning in &candidate.sensitive_warnings {
            if warned.insert(warning.resource.clone()) {
                sensitive_warnings.push(warning.clone());
            }
        }
    }

    let observations = counts
        .into_iter()
        .map(|(resource, sessions_seen)| AuditObservation::with_sessions(resource, sessions_seen))
        .collect();

    Ok(PolicyCandidate {
        agent_name,
        observations,
        sensitive_warnings,
    })
}

// ---------------------------------------------------------------------------
// Tests — Red phase: written before implementation.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::observation::ObservedResource;
    use crate::session::{AuditEvent, AuditSession};
    use std::path::PathBuf;

    // Helper: build a candidate from a list of non-sensitive events.
    fn candidate_with_events(agent: &str, events: Vec<AuditEvent>) -> PolicyCandidate {
        let mut session = AuditSession::new();
        for e in events {
            session.record(e);
        }
        session.finish(agent)
    }

    // -- Iterator helpers ----------------------------------------------------

    #[test]
    fn test_policy_candidate_fs_reads_filters_correctly() {
        let mut session = AuditSession::new();
        session.record(AuditEvent::FileRead(PathBuf::from("./src/lib.rs")));
        session.record(AuditEvent::FileWrite(PathBuf::from("./out/result.txt")));
        session.record(AuditEvent::NetworkConnect {
            host: "example.com".to_string(),
            port: 80,
        });
        let candidate = session.finish("agent");

        assert_eq!(candidate.fs_reads().count(), 1);
        assert_eq!(candidate.fs_writes().count(), 1);
        assert_eq!(candidate.network_connections().count(), 1);
        assert_eq!(candidate.env_var_reads().count(), 0);
    }

    #[test]
    fn test_policy_candidate_env_var_reads_filters_correctly() {
        let candidate =
            candidate_with_events("agent", vec![AuditEvent::EnvVarRead("PATH".to_string())]);
        assert_eq!(candidate.env_var_reads().count(), 1);
        assert_eq!(candidate.fs_reads().count(), 0);
    }

    // -- merge: empty input --------------------------------------------------

    #[test]
    fn test_merge_empty_slice_returns_error() {
        let err = merge(&[]).expect_err("merge of empty slice should fail");
        assert!(matches!(err, AuditError::EmptyCandidateList));
    }

    // -- merge: single candidate ---------------------------------------------

    #[test]
    fn test_merge_single_candidate_preserves_all_observations() {
        let candidate = candidate_with_events(
            "agent",
            vec![
                AuditEvent::FileRead(PathBuf::from("./src/lib.rs")),
                AuditEvent::NetworkConnect {
                    host: "api.anthropic.com".to_string(),
                    port: 443,
                },
            ],
        );
        let original_count = candidate.observations.len();
        let merged = merge(&[candidate]).expect("single-candidate merge should succeed");
        assert_eq!(merged.observations.len(), original_count);
    }

    #[test]
    fn test_merge_single_candidate_preserves_sessions_seen_one() {
        let candidate = candidate_with_events(
            "agent",
            vec![AuditEvent::FileRead(PathBuf::from("./src/lib.rs"))],
        );
        let merged = merge(&[candidate]).expect("should succeed");
        let obs = merged
            .observations
            .iter()
            .find(|o| o.resource == ObservedResource::FileRead(PathBuf::from("./src/lib.rs")))
            .expect("observation should be present");
        assert_eq!(obs.sessions_seen, 1);
    }

    #[test]
    fn test_merge_single_candidate_preserves_agent_name() {
        let candidate = candidate_with_events("my-agent", vec![]);
        let merged = merge(&[candidate]).expect("should succeed");
        assert_eq!(merged.agent_name, "my-agent");
    }

    // -- merge: union of observations ----------------------------------------

    #[test]
    fn test_merge_two_candidates_unions_distinct_observations() {
        let c1 = candidate_with_events(
            "agent",
            vec![AuditEvent::FileRead(PathBuf::from("./a.txt"))],
        );
        let c2 = candidate_with_events(
            "agent",
            vec![AuditEvent::FileRead(PathBuf::from("./b.txt"))],
        );
        let merged = merge(&[c1, c2]).expect("should succeed");
        assert_eq!(
            merged.observations.len(),
            2,
            "union of two distinct observations should have 2 entries"
        );
    }

    #[test]
    fn test_merge_path_seen_in_both_sessions_has_sessions_seen_two() {
        let path = PathBuf::from("/tmp/data.csv");
        let c1 = candidate_with_events("agent", vec![AuditEvent::FileRead(path.clone())]);
        let c2 = candidate_with_events("agent", vec![AuditEvent::FileRead(path.clone())]);

        let merged = merge(&[c1, c2]).expect("should succeed");
        let obs = merged
            .observations
            .iter()
            .find(|o| o.resource == ObservedResource::FileRead(path.clone()))
            .expect("merged observation should exist");
        assert_eq!(
            obs.sessions_seen, 2,
            "path seen in two sessions must have sessions_seen = 2"
        );
    }

    #[test]
    fn test_merge_confidence_higher_after_two_sessions_than_one() {
        let path = PathBuf::from("/tmp/data.csv");
        let c1 = candidate_with_events("agent", vec![AuditEvent::FileRead(path.clone())]);
        let c2 = candidate_with_events("agent", vec![AuditEvent::FileRead(path.clone())]);

        // Confidence after one session (from c1 alone).
        let single = merge(&[c1.clone()]).expect("should succeed");
        let conf1 = single
            .observations
            .iter()
            .find(|o| o.resource == ObservedResource::FileRead(path.clone()))
            .map(|o| o.confidence)
            .expect("observation should exist");

        // Confidence after two sessions.
        let merged = merge(&[c1, c2]).expect("should succeed");
        let conf2 = merged
            .observations
            .iter()
            .find(|o| o.resource == ObservedResource::FileRead(path.clone()))
            .map(|o| o.confidence)
            .expect("observation should exist");

        assert!(
            conf2 > conf1,
            "confidence should be higher after 2 sessions ({conf2}) than 1 ({conf1})"
        );
    }

    #[test]
    fn test_merge_path_seen_in_four_sessions_has_max_confidence() {
        let path = PathBuf::from("/tmp/hot.csv");
        let candidates: Vec<PolicyCandidate> = (0..4)
            .map(|_| candidate_with_events("agent", vec![AuditEvent::FileRead(path.clone())]))
            .collect();

        let merged = merge(&candidates).expect("should succeed");
        let obs = merged
            .observations
            .iter()
            .find(|o| o.resource == ObservedResource::FileRead(path.clone()))
            .expect("observation should exist");
        assert!(
            (obs.confidence - 1.0).abs() < f32::EPSILON,
            "4-session observation should have confidence 1.0, got {}",
            obs.confidence
        );
    }

    #[test]
    fn test_merge_only_one_session_has_path_sessions_seen_is_one() {
        let c1 = candidate_with_events(
            "agent",
            vec![AuditEvent::FileRead(PathBuf::from("./a.txt"))],
        );
        let c2 = candidate_with_events(
            "agent",
            vec![AuditEvent::FileRead(PathBuf::from("./b.txt"))],
        );

        let merged = merge(&[c1, c2]).expect("should succeed");
        let obs = merged
            .observations
            .iter()
            .find(|o| o.resource == ObservedResource::FileRead(PathBuf::from("./a.txt")))
            .expect("a.txt should be in merged candidate");
        assert_eq!(
            obs.sessions_seen, 1,
            "path seen in only one of two sessions should have sessions_seen = 1"
        );
    }

    // -- merge: network observations -----------------------------------------

    #[test]
    fn test_merge_network_observations_are_deduped_across_sessions() {
        let make = || {
            candidate_with_events(
                "agent",
                vec![AuditEvent::NetworkConnect {
                    host: "api.anthropic.com".to_string(),
                    port: 443,
                }],
            )
        };
        let merged = merge(&[make(), make(), make()]).expect("should succeed");
        let count = merged
            .observations
            .iter()
            .filter(|o| {
                matches!(&o.resource, ObservedResource::Network { host, port }
                    if host == "api.anthropic.com" && *port == 443)
            })
            .count();
        assert_eq!(count, 1, "same network endpoint seen 3× must appear once");

        let obs = merged
            .observations
            .iter()
            .find(|o| {
                matches!(&o.resource, ObservedResource::Network { host, .. }
                    if host == "api.anthropic.com")
            })
            .expect("network observation must exist");
        assert_eq!(obs.sessions_seen, 3);
    }

    // -- merge: env var observations -----------------------------------------

    #[test]
    fn test_merge_env_var_observations_are_deduped_across_sessions() {
        let make = || {
            candidate_with_events(
                "agent",
                vec![AuditEvent::EnvVarRead("ANTHROPIC_API_KEY".to_string())],
            )
        };
        let merged = merge(&[make(), make()]).expect("should succeed");
        let count = merged
            .observations
            .iter()
            .filter(|o| o.resource == ObservedResource::EnvVar("ANTHROPIC_API_KEY".to_string()))
            .count();
        assert_eq!(count, 1);

        let obs = merged
            .observations
            .iter()
            .find(|o| o.resource == ObservedResource::EnvVar("ANTHROPIC_API_KEY".to_string()))
            .expect("env var must be in merged candidate");
        assert_eq!(obs.sessions_seen, 2);
    }

    // -- merge: sensitive warnings -------------------------------------------

    #[test]
    fn test_merge_sensitive_warnings_are_unioned_and_deduplicated() {
        // Both sessions access the same sensitive path.
        let make_with_ssh = || {
            let mut session = AuditSession::new();
            session.record(AuditEvent::FileRead(PathBuf::from("~/.ssh/id_rsa")));
            session.finish("agent")
        };
        let merged = merge(&[make_with_ssh(), make_with_ssh()]).expect("should succeed");
        assert_eq!(
            merged.sensitive_warnings.len(),
            1,
            "the same sensitive warning from two sessions must be deduplicated"
        );
    }

    #[test]
    fn test_merge_distinct_sensitive_warnings_both_appear() {
        let mut s1 = AuditSession::new();
        s1.record(AuditEvent::FileRead(PathBuf::from("~/.ssh/id_rsa")));
        let c1 = s1.finish("agent");

        let mut s2 = AuditSession::new();
        s2.record(AuditEvent::EnvVarRead("AWS_SECRET_ACCESS_KEY".to_string()));
        let c2 = s2.finish("agent");

        let merged = merge(&[c1, c2]).expect("should succeed");
        assert_eq!(
            merged.sensitive_warnings.len(),
            2,
            "two distinct sensitive warnings must both appear in the merged candidate"
        );
    }

    #[test]
    fn test_merge_sensitive_paths_not_in_observations() {
        let mut session = AuditSession::new();
        session.record(AuditEvent::FileRead(PathBuf::from("~/.aws/credentials")));
        let candidate = session.finish("agent");
        let merged = merge(&[candidate]).expect("should succeed");

        assert!(
            merged.observations.iter().all(|o| {
                !matches!(&o.resource, ObservedResource::FileRead(p)
                    if p == &PathBuf::from("~/.aws/credentials"))
            }),
            "sensitive path must not appear in merged observations"
        );
    }

    // -- merge: agent name ---------------------------------------------------

    #[test]
    fn test_merge_uses_first_non_empty_agent_name() {
        let c1 = PolicyCandidate {
            agent_name: String::new(),
            observations: vec![],
            sensitive_warnings: vec![],
        };
        let c2 = PolicyCandidate {
            agent_name: "my-agent".to_string(),
            observations: vec![],
            sensitive_warnings: vec![],
        };
        let merged = merge(&[c1, c2]).expect("should succeed");
        assert_eq!(merged.agent_name, "my-agent");
    }

    // -- merge: many sessions ------------------------------------------------

    #[test]
    fn test_merge_three_sessions_with_mixed_observations() {
        // Session 1: reads a.txt and b.txt
        let c1 = candidate_with_events(
            "agent",
            vec![
                AuditEvent::FileRead(PathBuf::from("./a.txt")),
                AuditEvent::FileRead(PathBuf::from("./b.txt")),
            ],
        );
        // Session 2: reads b.txt and c.txt
        let c2 = candidate_with_events(
            "agent",
            vec![
                AuditEvent::FileRead(PathBuf::from("./b.txt")),
                AuditEvent::FileRead(PathBuf::from("./c.txt")),
            ],
        );
        // Session 3: reads a.txt and c.txt
        let c3 = candidate_with_events(
            "agent",
            vec![
                AuditEvent::FileRead(PathBuf::from("./a.txt")),
                AuditEvent::FileRead(PathBuf::from("./c.txt")),
            ],
        );

        let merged = merge(&[c1, c2, c3]).expect("should succeed");
        assert_eq!(merged.observations.len(), 3, "union of a, b, c = 3 paths");

        let sessions_for = |path: &str| -> u32 {
            merged
                .observations
                .iter()
                .find(|o| o.resource == ObservedResource::FileRead(PathBuf::from(path)))
                .map(|o| o.sessions_seen)
                .unwrap_or(0)
        };

        assert_eq!(sessions_for("./a.txt"), 2, "a.txt seen in sessions 1 and 3");
        assert_eq!(sessions_for("./b.txt"), 2, "b.txt seen in sessions 1 and 2");
        assert_eq!(sessions_for("./c.txt"), 2, "c.txt seen in sessions 2 and 3");
    }
}
