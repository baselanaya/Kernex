use std::path::PathBuf;

use serde::{Deserialize, Serialize};

/// Confidence score increment per session in which a resource was observed.
///
/// At 4 sessions the confidence saturates at 1.0 (100%).
pub const CONFIDENCE_PER_SESSION: f32 = 0.25;

/// Computes the confidence score for `sessions` observed sessions.
///
/// The score grows linearly at [`CONFIDENCE_PER_SESSION`] per session,
/// capped at `1.0`.
///
/// | sessions | confidence |
/// |---------|------------|
/// | 1       | 0.25       |
/// | 2       | 0.50       |
/// | 3       | 0.75       |
/// | 4+      | 1.00       |
pub fn compute_confidence(sessions: u32) -> f32 {
    (sessions as f32 * CONFIDENCE_PER_SESSION).min(1.0)
}

/// A specific resource observed during one or more audit sessions.
///
/// `FileExec` accesses are tracked separately so the CLI can explain why
/// an executable path appears in the policy, but they produce a
/// `filesystem.allow_read` rule in the generated `KernexPolicy` (execution
/// requires read access under Landlock).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "kind", content = "value", rename_all = "snake_case")]
pub enum ObservedResource {
    /// A file or directory that the agent read.
    FileRead(PathBuf),
    /// A file or directory that the agent wrote to or created.
    FileWrite(PathBuf),
    /// A file that the agent executed.
    FileExec(PathBuf),
    /// An outbound TCP connection the agent made.
    Network { host: String, port: u16 },
    /// An environment variable the agent read.
    EnvVar(String),
}

/// A deduplicated resource access annotated with multi-session statistics.
///
/// Produced by [`crate::session::AuditSession::finish`] (single session,
/// `sessions_seen = 1`) or by [`crate::candidate::merge`] (accumulated across
/// N sessions).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AuditObservation {
    /// The resource that was accessed.
    pub resource: ObservedResource,
    /// Number of distinct audit sessions in which this resource was observed.
    pub sessions_seen: u32,
    /// Confidence score in the range `[0.0, 1.0]`.
    ///
    /// Increases monotonically with `sessions_seen`. Reaches `1.0` at 4 sessions.
    /// Always a finite, non-NaN value.
    pub confidence: f32,
}

impl AuditObservation {
    /// Create a new observation seen in exactly one session.
    pub fn new(resource: ObservedResource) -> Self {
        Self {
            confidence: compute_confidence(1),
            resource,
            sessions_seen: 1,
        }
    }

    /// Create an observation with an explicit session count.
    ///
    /// Used by [`crate::candidate::merge`] to build accumulated observations.
    pub(crate) fn with_sessions(resource: ObservedResource, sessions_seen: u32) -> Self {
        Self {
            confidence: compute_confidence(sessions_seen),
            resource,
            sessions_seen,
        }
    }
}

/// The kind of sensitive resource that triggered a warning.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "kind", content = "value", rename_all = "snake_case")]
pub enum SensitiveResource {
    /// A filesystem path containing credentials or system-level data.
    Path(PathBuf),
    /// An environment variable containing credentials or secrets.
    EnvVar(String),
}

/// A warning that the agent accessed a sensitive resource during audit.
///
/// Sensitive resources are **never** silently included in
/// [`crate::candidate::PolicyCandidate::observations`]. They appear only here
/// and must be explicitly approved by the user via `--allow-sensitive` before
/// they are written to `kernex.yaml`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SensitiveWarning {
    /// The resource that triggered the warning.
    pub resource: SensitiveResource,
    /// Human-readable explanation of why this resource is sensitive.
    pub reason: String,
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn test_compute_confidence_one_session_is_quarter() {
        assert!((compute_confidence(1) - 0.25).abs() < f32::EPSILON);
    }

    #[test]
    fn test_compute_confidence_two_sessions_is_half() {
        assert!((compute_confidence(2) - 0.50).abs() < f32::EPSILON);
    }

    #[test]
    fn test_compute_confidence_four_sessions_is_max() {
        assert!((compute_confidence(4) - 1.0).abs() < f32::EPSILON);
    }

    #[test]
    fn test_compute_confidence_many_sessions_does_not_exceed_one() {
        assert!(compute_confidence(100) <= 1.0);
        assert!((compute_confidence(100) - 1.0).abs() < f32::EPSILON);
    }

    #[test]
    fn test_compute_confidence_increases_monotonically() {
        let c1 = compute_confidence(1);
        let c2 = compute_confidence(2);
        let c3 = compute_confidence(3);
        assert!(c1 < c2, "confidence must increase from 1 to 2 sessions");
        assert!(c2 < c3, "confidence must increase from 2 to 3 sessions");
    }

    #[test]
    fn test_audit_observation_new_has_sessions_seen_one() {
        let obs = AuditObservation::new(ObservedResource::FileRead(PathBuf::from("/tmp/a")));
        assert_eq!(obs.sessions_seen, 1);
    }

    #[test]
    fn test_audit_observation_new_confidence_matches_one_session() {
        let obs = AuditObservation::new(ObservedResource::EnvVar("PATH".to_string()));
        assert!((obs.confidence - compute_confidence(1)).abs() < f32::EPSILON);
    }

    #[test]
    fn test_audit_observation_with_sessions_sets_correct_confidence() {
        let obs = AuditObservation::with_sessions(
            ObservedResource::Network {
                host: "api.example.com".to_string(),
                port: 443,
            },
            3,
        );
        assert_eq!(obs.sessions_seen, 3);
        assert!((obs.confidence - compute_confidence(3)).abs() < f32::EPSILON);
    }

    #[test]
    fn test_observed_resource_file_read_eq() {
        let a = ObservedResource::FileRead(PathBuf::from("/tmp/a"));
        let b = ObservedResource::FileRead(PathBuf::from("/tmp/a"));
        let c = ObservedResource::FileRead(PathBuf::from("/tmp/b"));
        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn test_observed_resource_network_eq() {
        let a = ObservedResource::Network {
            host: "api.example.com".to_string(),
            port: 443,
        };
        let b = ObservedResource::Network {
            host: "api.example.com".to_string(),
            port: 443,
        };
        let c = ObservedResource::Network {
            host: "api.example.com".to_string(),
            port: 80,
        };
        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn test_sensitive_warning_eq() {
        let w1 = SensitiveWarning {
            resource: SensitiveResource::Path(PathBuf::from("~/.ssh")),
            reason: "SSH keys".to_string(),
        };
        let w2 = w1.clone();
        assert_eq!(w1, w2);
    }
}
