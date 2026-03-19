use std::collections::HashSet;
use std::path::PathBuf;

use crate::candidate::PolicyCandidate;
use crate::observation::{AuditObservation, ObservedResource, SensitiveResource, SensitiveWarning};
use crate::sensitive;

/// A single raw event captured during an audit run.
///
/// Events are produced by the platform adapter (`kernex-linux` or
/// `kernex-macos`) via syscall interception and passed to
/// [`AuditSession::record`]. The adapter crates own the observation loop;
/// `AuditSession` only aggregates.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuditEvent {
    /// The agent read a file or directory.
    FileRead(PathBuf),
    /// The agent wrote to or created a file.
    FileWrite(PathBuf),
    /// The agent ran an executable (implies read access under Landlock).
    FileExecuted(PathBuf),
    /// The agent opened a network connection.
    NetworkConnect { host: String, port: u16 },
    /// The agent read an environment variable.
    EnvVarRead(String),
}

/// Collects raw [`AuditEvent`]s for a single agent run.
///
/// On completion, call [`AuditSession::finish`] to produce a
/// [`PolicyCandidate`] with:
/// - Deduplicated [`AuditObservation`]s for non-sensitive resources.
/// - [`SensitiveWarning`]s for any sensitive paths or env vars accessed
///   (these are **never** silently included in observations).
///
/// # Concurrency
///
/// `AuditSession` is intentionally synchronous. Syscall interception runs in
/// a tight loop where async yield points and allocations must be avoided.
/// Platform adapters call [`AuditSession::record`] directly; no locking is
/// needed if the session is owned by a single thread.
#[derive(Debug, Default)]
pub struct AuditSession {
    events: Vec<AuditEvent>,
}

impl AuditSession {
    /// Create a new, empty audit session.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a single observed event.
    ///
    /// Events are buffered in insertion order and processed lazily in
    /// [`AuditSession::finish`]. Duplicate events are deduplicated there.
    pub fn record(&mut self, event: AuditEvent) {
        self.events.push(event);
    }

    /// Finalise the session and produce a [`PolicyCandidate`].
    ///
    /// - Events are deduplicated within this session (each unique resource
    ///   appears at most once in the output).
    /// - Sensitive paths (`.ssh`, `.aws`, …) and env vars (`AWS_*`, …) are
    ///   moved to [`PolicyCandidate::sensitive_warnings`] and are **not**
    ///   included in [`PolicyCandidate::observations`].
    ///
    /// The returned candidate has `sessions_seen = 1` on all observations.
    /// Use [`crate::candidate::merge`] to accumulate across multiple sessions.
    #[must_use]
    pub fn finish(self, agent_name: impl Into<String>) -> PolicyCandidate {
        let mut observations: Vec<AuditObservation> = Vec::new();
        let mut sensitive_warnings: Vec<SensitiveWarning> = Vec::new();

        // Seen-sets for within-session deduplication.
        let mut seen_resources: HashSet<ObservedResource> = HashSet::new();
        let mut warned_resources: HashSet<SensitiveResource> = HashSet::new();

        for event in self.events {
            let resource = event_to_resource(event);

            // Check for sensitivity before inserting into observations.
            // SECURITY: sensitive resources must never fall through to the
            // observations branch — the `continue` below enforces this.
            if let Some((sensitive_resource, reason)) = classify_sensitive(&resource) {
                // Warn exactly once per unique sensitive resource per session.
                if warned_resources.insert(sensitive_resource.clone()) {
                    sensitive_warnings.push(SensitiveWarning {
                        resource: sensitive_resource,
                        reason: reason.to_string(),
                    });
                }
                continue; // SECURITY: do NOT add to observations
            }

            // Deduplicate within this session: each unique resource observed once.
            if seen_resources.insert(resource.clone()) {
                observations.push(AuditObservation::new(resource));
            }
        }

        PolicyCandidate {
            agent_name: agent_name.into(),
            observations,
            sensitive_warnings,
        }
    }
}

// ---------------------------------------------------------------------------
// Private helpers
// ---------------------------------------------------------------------------

fn event_to_resource(event: AuditEvent) -> ObservedResource {
    match event {
        AuditEvent::FileRead(p) => ObservedResource::FileRead(p),
        AuditEvent::FileWrite(p) => ObservedResource::FileWrite(p),
        AuditEvent::FileExecuted(p) => ObservedResource::FileExec(p),
        AuditEvent::NetworkConnect { host, port } => ObservedResource::Network { host, port },
        AuditEvent::EnvVarRead(name) => ObservedResource::EnvVar(name),
    }
}

/// If `resource` is sensitive, return the [`SensitiveResource`] variant and
/// the human-readable reason string. Returns `None` for non-sensitive
/// resources (including all `Network` resources, which are never matched
/// against the sensitive-path patterns).
fn classify_sensitive(resource: &ObservedResource) -> Option<(SensitiveResource, &'static str)> {
    match resource {
        ObservedResource::FileRead(p)
        | ObservedResource::FileWrite(p)
        | ObservedResource::FileExec(p) => sensitive::sensitive_path_reason(p)
            .map(|reason| (SensitiveResource::Path(p.clone()), reason)),

        ObservedResource::EnvVar(name) => sensitive::sensitive_env_reason(name)
            .map(|reason| (SensitiveResource::EnvVar(name.clone()), reason)),

        // Network connections are never matched against sensitive patterns.
        ObservedResource::Network { .. } => None,
    }
}

// ---------------------------------------------------------------------------
// Tests — Red phase: written before implementation to describe behaviour.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    // -- Recording -----------------------------------------------------------

    #[test]
    fn test_audit_session_records_file_read() {
        let mut session = AuditSession::new();
        session.record(AuditEvent::FileRead(PathBuf::from("/tmp/data.csv")));
        let candidate = session.finish("test-agent");
        assert!(
            candidate
                .observations
                .iter()
                .any(|o| o.resource == ObservedResource::FileRead(PathBuf::from("/tmp/data.csv"))),
            "file read should appear in observations"
        );
    }

    #[test]
    fn test_audit_session_records_file_write() {
        let mut session = AuditSession::new();
        session.record(AuditEvent::FileWrite(PathBuf::from("/tmp/output.txt")));
        let candidate = session.finish("agent");
        assert!(candidate.observations.iter().any(|o| {
            o.resource == ObservedResource::FileWrite(PathBuf::from("/tmp/output.txt"))
        }));
    }

    #[test]
    fn test_audit_session_records_file_executed() {
        let mut session = AuditSession::new();
        session.record(AuditEvent::FileExecuted(PathBuf::from("/usr/bin/python3")));
        let candidate = session.finish("agent");
        assert!(candidate.observations.iter().any(|o| {
            o.resource == ObservedResource::FileExec(PathBuf::from("/usr/bin/python3"))
        }));
    }

    #[test]
    fn test_audit_session_records_network_connect() {
        let mut session = AuditSession::new();
        session.record(AuditEvent::NetworkConnect {
            host: "api.anthropic.com".to_string(),
            port: 443,
        });
        let candidate = session.finish("agent");
        assert!(candidate.observations.iter().any(|o| {
            o.resource
                == ObservedResource::Network {
                    host: "api.anthropic.com".to_string(),
                    port: 443,
                }
        }));
    }

    #[test]
    fn test_audit_session_records_env_var_read() {
        let mut session = AuditSession::new();
        session.record(AuditEvent::EnvVarRead("ANTHROPIC_API_KEY".to_string()));
        let candidate = session.finish("agent");
        assert!(candidate
            .observations
            .iter()
            .any(|o| { o.resource == ObservedResource::EnvVar("ANTHROPIC_API_KEY".to_string()) }));
    }

    // -- Agent name ----------------------------------------------------------

    #[test]
    fn test_audit_session_finish_sets_agent_name() {
        let session = AuditSession::new();
        let candidate = session.finish("my-agent");
        assert_eq!(candidate.agent_name, "my-agent");
    }

    // -- Deduplication -------------------------------------------------------

    #[test]
    fn test_audit_session_deduplicates_identical_file_reads_within_session() {
        let mut session = AuditSession::new();
        let path = PathBuf::from("/tmp/data.csv");
        session.record(AuditEvent::FileRead(path.clone()));
        session.record(AuditEvent::FileRead(path.clone()));
        session.record(AuditEvent::FileRead(path));
        let candidate = session.finish("agent");
        let count = candidate
            .observations
            .iter()
            .filter(|o| {
                matches!(&o.resource, ObservedResource::FileRead(p)
                    if p == &PathBuf::from("/tmp/data.csv"))
            })
            .count();
        assert_eq!(
            count, 1,
            "duplicate reads must be deduplicated within a session"
        );
    }

    #[test]
    fn test_audit_session_deduplicates_identical_network_connects() {
        let mut session = AuditSession::new();
        for _ in 0..5 {
            session.record(AuditEvent::NetworkConnect {
                host: "api.anthropic.com".to_string(),
                port: 443,
            });
        }
        let candidate = session.finish("agent");
        let count = candidate
            .observations
            .iter()
            .filter(|o| {
                matches!(&o.resource, ObservedResource::Network { host, port }
                    if host == "api.anthropic.com" && *port == 443)
            })
            .count();
        assert_eq!(count, 1, "duplicate network connects must be deduplicated");
    }

    #[test]
    fn test_audit_session_read_and_write_same_path_are_distinct_resources() {
        let mut session = AuditSession::new();
        let path = PathBuf::from("/tmp/file.txt");
        session.record(AuditEvent::FileRead(path.clone()));
        session.record(AuditEvent::FileWrite(path));
        let candidate = session.finish("agent");
        // FileRead and FileWrite are different ObservedResource variants.
        assert_eq!(
            candidate.observations.len(),
            2,
            "read and write of the same path are distinct observations"
        );
    }

    // -- Single-session confidence -------------------------------------------

    #[test]
    fn test_audit_session_single_session_observation_has_sessions_seen_one() {
        let mut session = AuditSession::new();
        session.record(AuditEvent::FileRead(PathBuf::from("/tmp/a")));
        let candidate = session.finish("agent");
        let obs = &candidate.observations[0];
        assert_eq!(obs.sessions_seen, 1);
    }

    #[test]
    fn test_audit_session_single_session_confidence_is_quarter() {
        let mut session = AuditSession::new();
        session.record(AuditEvent::FileRead(PathBuf::from("/tmp/a")));
        let candidate = session.finish("agent");
        let obs = &candidate.observations[0];
        assert!(
            (obs.confidence - 0.25).abs() < f32::EPSILON,
            "single-session confidence should be 0.25, got {}",
            obs.confidence
        );
    }

    // -- Sensitive path detection --------------------------------------------

    #[test]
    fn test_audit_session_sensitive_ssh_path_goes_to_warnings_not_observations() {
        let mut session = AuditSession::new();
        session.record(AuditEvent::FileRead(PathBuf::from("~/.ssh/id_rsa")));
        let candidate = session.finish("agent");

        // Must NOT appear in observations.
        let in_observations = candidate.observations.iter().any(|o| {
            matches!(&o.resource, ObservedResource::FileRead(p)
                if p == &PathBuf::from("~/.ssh/id_rsa"))
        });
        assert!(
            !in_observations,
            "sensitive path must not be silently included in observations"
        );

        // Must appear in sensitive_warnings.
        let warned = candidate
            .sensitive_warnings
            .iter()
            .any(|w| w.resource == SensitiveResource::Path(PathBuf::from("~/.ssh/id_rsa")));
        assert!(
            warned,
            "sensitive path must be present in sensitive_warnings"
        );
    }

    #[test]
    fn test_audit_session_sensitive_aws_credentials_absolute_path_goes_to_warnings() {
        let mut session = AuditSession::new();
        session.record(AuditEvent::FileRead(PathBuf::from(
            "/home/user/.aws/credentials",
        )));
        let candidate = session.finish("agent");

        assert!(
            candidate.observations.iter().all(|o| {
                !matches!(&o.resource, ObservedResource::FileRead(p)
                    if p == &PathBuf::from("/home/user/.aws/credentials"))
            }),
            "AWS credentials path must not be in observations"
        );
        assert!(
            !candidate.sensitive_warnings.is_empty(),
            "AWS credentials path must generate a warning"
        );
    }

    #[test]
    fn test_audit_session_sensitive_gnupg_path_goes_to_warnings() {
        let mut session = AuditSession::new();
        session.record(AuditEvent::FileRead(PathBuf::from("~/.gnupg/secring.gpg")));
        let candidate = session.finish("agent");
        assert!(!candidate.sensitive_warnings.is_empty());
        assert!(candidate.observations.is_empty());
    }

    #[test]
    fn test_audit_session_sensitive_etc_shadow_goes_to_warnings() {
        let mut session = AuditSession::new();
        session.record(AuditEvent::FileRead(PathBuf::from("/etc/shadow")));
        let candidate = session.finish("agent");
        assert!(!candidate.sensitive_warnings.is_empty());
        assert!(candidate.observations.iter().all(|o| {
            !matches!(&o.resource, ObservedResource::FileRead(p)
                if p == &PathBuf::from("/etc/shadow"))
        }));
    }

    #[test]
    fn test_audit_session_sensitive_env_var_goes_to_warnings_not_observations() {
        let mut session = AuditSession::new();
        session.record(AuditEvent::EnvVarRead("AWS_SECRET_ACCESS_KEY".to_string()));
        let candidate = session.finish("agent");

        let in_observations = candidate
            .observations
            .iter()
            .any(|o| o.resource == ObservedResource::EnvVar("AWS_SECRET_ACCESS_KEY".to_string()));
        assert!(
            !in_observations,
            "sensitive env var must not be in observations"
        );

        let warned = candidate
            .sensitive_warnings
            .iter()
            .any(|w| w.resource == SensitiveResource::EnvVar("AWS_SECRET_ACCESS_KEY".to_string()));
        assert!(warned, "sensitive env var must be in sensitive_warnings");
    }

    #[test]
    fn test_audit_session_sensitive_github_token_goes_to_warnings() {
        let mut session = AuditSession::new();
        session.record(AuditEvent::EnvVarRead("GITHUB_TOKEN".to_string()));
        let candidate = session.finish("agent");
        assert!(!candidate.sensitive_warnings.is_empty());
    }

    #[test]
    fn test_audit_session_sensitive_path_warning_contains_non_empty_reason() {
        let mut session = AuditSession::new();
        session.record(AuditEvent::FileRead(PathBuf::from("~/.ssh/id_rsa")));
        let candidate = session.finish("agent");
        let warning = &candidate.sensitive_warnings[0];
        assert!(
            !warning.reason.is_empty(),
            "sensitive warning must have a human-readable reason"
        );
    }

    #[test]
    fn test_audit_session_sensitive_path_deduplicated_in_warnings() {
        // Same sensitive path accessed 3 times in one session → only one warning.
        let mut session = AuditSession::new();
        let path = PathBuf::from("~/.aws/credentials");
        session.record(AuditEvent::FileRead(path.clone()));
        session.record(AuditEvent::FileRead(path.clone()));
        session.record(AuditEvent::FileRead(path));
        let candidate = session.finish("agent");
        assert_eq!(
            candidate.sensitive_warnings.len(),
            1,
            "identical sensitive path accessed multiple times must produce exactly one warning"
        );
    }

    #[test]
    fn test_audit_session_non_sensitive_path_is_not_flagged() {
        let mut session = AuditSession::new();
        session.record(AuditEvent::FileRead(PathBuf::from("./src/main.rs")));
        let candidate = session.finish("agent");
        assert!(
            candidate.sensitive_warnings.is_empty(),
            "non-sensitive path must not produce warnings"
        );
        assert_eq!(candidate.observations.len(), 1);
    }

    #[test]
    fn test_audit_session_network_connections_are_never_sensitive() {
        let mut session = AuditSession::new();
        session.record(AuditEvent::NetworkConnect {
            host: "secret.internal".to_string(),
            port: 443,
        });
        let candidate = session.finish("agent");
        assert!(
            candidate.sensitive_warnings.is_empty(),
            "network connections should never produce sensitive warnings"
        );
        assert_eq!(candidate.observations.len(), 1);
    }

    // -- Mixed events --------------------------------------------------------

    #[test]
    fn test_audit_session_mixed_events_correctly_separated() {
        let mut session = AuditSession::new();
        session.record(AuditEvent::FileRead(PathBuf::from("./src/lib.rs")));
        session.record(AuditEvent::FileRead(PathBuf::from("~/.ssh/id_rsa"))); // sensitive
        session.record(AuditEvent::NetworkConnect {
            host: "api.anthropic.com".to_string(),
            port: 443,
        });
        session.record(AuditEvent::EnvVarRead("AWS_SECRET_ACCESS_KEY".to_string())); // sensitive
        session.record(AuditEvent::EnvVarRead("ANTHROPIC_API_KEY".to_string()));
        let candidate = session.finish("agent");

        // 3 non-sensitive observations: file read, network, env var
        assert_eq!(
            candidate.observations.len(),
            3,
            "expected 3 non-sensitive observations"
        );
        // 2 sensitive warnings: ssh path + AWS env var
        assert_eq!(
            candidate.sensitive_warnings.len(),
            2,
            "expected 2 sensitive warnings"
        );
    }

    #[test]
    fn test_audit_session_empty_produces_empty_candidate() {
        let session = AuditSession::new();
        let candidate = session.finish("agent");
        assert!(candidate.observations.is_empty());
        assert!(candidate.sensitive_warnings.is_empty());
    }
}
