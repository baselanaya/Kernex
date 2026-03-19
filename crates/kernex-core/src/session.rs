//! Per-session enforcement orchestrator.
//!
//! [`EnforcementSession`] ties together policy evaluation, JIT deduplication,
//! and session statistics. It is the core state machine for a single agent run.
//!
//! # State machine
//!
//! ```text
//! ┌────────────────────────────────────────────────────┐
//! │  EnforcementSession                                │
//! │                                                    │
//! │  evaluate_query(query)                             │
//! │    ├─ silent deny?     → QueryOutcome::Decide(Deny)│
//! │    ├─ session allow?   → QueryOutcome::Decide(Allow)│
//! │    ├─ policy Allow     → QueryOutcome::Decide(Allow)│
//! │    ├─ policy Deny      → QueryOutcome::Decide(Deny) │
//! │    └─ policy Prompt    → QueryOutcome::Prompt(…)   │
//! │                                                    │
//! │  record_jit_response(key, decision)                │
//! │    ├─ AllowOnce  → Allow (no dedup update)         │
//! │    ├─ AddToPolicy → Allow + record session_allow   │
//! │    └─ Deny       → Deny + record silent_deny       │
//! └────────────────────────────────────────────────────┘
//! ```

use std::sync::atomic::{AtomicU64, Ordering};

use kernex_ipc::{JitDecision, JitPrompt, PolicyDecision, PolicyQuery, SessionSummary, Verdict};
use kernex_policy::KernexPolicy;

use crate::dedupe::{DedupeKey, JitDedupeState};
use crate::evaluator::{self, EvalVerdict};

// ---------------------------------------------------------------------------
// Session ID generator
// ---------------------------------------------------------------------------

static SESSION_COUNTER: AtomicU64 = AtomicU64::new(0);

fn next_session_id() -> String {
    let n = SESSION_COUNTER.fetch_add(1, Ordering::Relaxed);
    format!("kernex-session-{n}")
}

// ---------------------------------------------------------------------------
// QueryOutcome
// ---------------------------------------------------------------------------

/// The result of processing one [`PolicyQuery`] before any JIT interaction.
#[derive(Debug)]
pub enum QueryOutcome {
    /// A definitive decision is ready; send this [`PolicyDecision`] immediately.
    Decide(PolicyDecision),
    /// A JIT prompt must be shown to the user before a decision can be made.
    Prompt(JitPrompt),
}

// ---------------------------------------------------------------------------
// EnforcementSession
// ---------------------------------------------------------------------------

/// Stateful orchestrator for a single agent enforcement session.
///
/// Holds the loaded policy, per-session JIT deduplication state, and
/// aggregate counters for the session summary.
pub struct EnforcementSession {
    /// The policy loaded at session start.
    policy: KernexPolicy,
    /// JIT deduplication state — which keys are silent-denied or auto-allowed.
    dedupe: JitDedupeState,
    /// Total blocks (including silent re-denials).
    total_blocks: u64,
    /// Unique blocked keys (first occurrence only).
    unique_blocks: u64,
    /// JIT prompts shown.
    prompts_shown: u64,
    /// JIT prompts where the user allowed.
    prompts_allowed: u64,
    /// JIT prompts where the user denied.
    prompts_denied: u64,
    /// Operations that triggered a sensitive-path/credential heuristic.
    injection_signals: u64,
    /// Monotonically increasing counter for JIT prompt IDs within this session.
    prompt_counter: u64,
    /// Unique identifier for this session.
    session_id: String,
}

impl EnforcementSession {
    /// Create a new enforcement session for `policy`.
    pub fn new(policy: KernexPolicy) -> Self {
        Self {
            policy,
            dedupe: JitDedupeState::new(),
            total_blocks: 0,
            unique_blocks: 0,
            prompts_shown: 0,
            prompts_allowed: 0,
            prompts_denied: 0,
            injection_signals: 0,
            prompt_counter: 0,
            session_id: next_session_id(),
        }
    }

    /// Process a [`PolicyQuery`] and return the appropriate [`QueryOutcome`].
    ///
    /// Checks JIT deduplication state first (silent-deny / session-allow),
    /// then falls through to policy evaluation.
    pub fn evaluate_query(&mut self, query: &PolicyQuery) -> QueryOutcome {
        let key = DedupeKey::from_parts(&query.operation, &query.resource);

        // Dedup: silent deny — already rejected in this session.
        if self.dedupe.is_silent_deny(&key) {
            self.total_blocks += 1;
            return QueryOutcome::Decide(PolicyDecision {
                query_id: query.id,
                verdict: Verdict::Deny,
            });
        }

        // Dedup: session allow — user chose AddToPolicy earlier.
        if self.dedupe.is_session_allow(&key) {
            return QueryOutcome::Decide(PolicyDecision {
                query_id: query.id,
                verdict: Verdict::Allow,
            });
        }

        // Evaluate against policy.
        let result = evaluator::evaluate(&self.policy, query);

        if result.injection_signal {
            self.injection_signals += 1;
        }

        match result.verdict {
            EvalVerdict::Allow => QueryOutcome::Decide(PolicyDecision {
                query_id: query.id,
                verdict: Verdict::Allow,
            }),
            EvalVerdict::Deny => {
                self.total_blocks += 1;
                self.unique_blocks += 1;
                self.dedupe.record_deny(key);
                QueryOutcome::Decide(PolicyDecision {
                    query_id: query.id,
                    verdict: Verdict::Deny,
                })
            }
            EvalVerdict::Prompt(risk_tier) => {
                self.prompts_shown += 1;
                self.prompt_counter += 1;
                QueryOutcome::Prompt(JitPrompt {
                    id: self.prompt_counter,
                    risk_tier,
                    operation: query.operation.clone(),
                    resource: query.resource.clone(),
                    message: result.reason,
                })
            }
        }
    }

    /// Record the user's response to a JIT prompt and return the final verdict.
    ///
    /// Updates deduplication state according to the decision:
    /// - `AllowOnce`: allow, no dedup update (will prompt again next time)
    /// - `AddToPolicy`: allow, record session_allow (auto-allow for session)
    /// - `Deny`: deny, record silent_deny (silent re-deny for session)
    ///
    /// `query_id` is the original [`PolicyQuery::id`] for correlation.
    pub fn record_jit_response(
        &mut self,
        key: DedupeKey,
        query_id: u64,
        decision: JitDecision,
    ) -> PolicyDecision {
        match decision {
            JitDecision::AllowOnce => {
                self.prompts_allowed += 1;
                PolicyDecision {
                    query_id,
                    verdict: Verdict::Allow,
                }
            }
            JitDecision::AddToPolicy => {
                self.prompts_allowed += 1;
                self.dedupe.record_session_allow(key);
                PolicyDecision {
                    query_id,
                    verdict: Verdict::Allow,
                }
            }
            JitDecision::Deny => {
                self.prompts_denied += 1;
                self.total_blocks += 1;
                self.unique_blocks += 1;
                self.dedupe.record_deny(key);
                PolicyDecision {
                    query_id,
                    verdict: Verdict::Deny,
                }
            }
        }
    }

    /// Consume the session and produce the final [`SessionSummary`].
    pub fn into_summary(self) -> SessionSummary {
        SessionSummary {
            session_id: self.session_id,
            total_blocks: self.total_blocks,
            unique_blocks: self.unique_blocks,
            prompts_shown: self.prompts_shown,
            prompts_allowed: self.prompts_allowed,
            prompts_denied: self.prompts_denied,
            injection_signals: self.injection_signals,
        }
    }

    /// The loaded policy (for inspection/scoring in the runner).
    pub fn policy(&self) -> &KernexPolicy {
        &self.policy
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use kernex_ipc::{JitDecision, Operation, PolicyQuery, Resource, RiskTier, Verdict};
    use kernex_policy::{FilesystemPolicy, KernexPolicy, NetworkPolicy, NetworkRule};

    use super::*;

    fn minimal_policy() -> KernexPolicy {
        KernexPolicy {
            version: 1,
            agent_name: "test".to_string(),
            filesystem: FilesystemPolicy::default(),
            network: NetworkPolicy::default(),
            environment: kernex_policy::EnvironmentPolicy::default(),
            resource_limits: None,
            mcp_servers: vec![],
        }
    }

    fn read_query(id: u64, path: &str) -> PolicyQuery {
        PolicyQuery {
            id,
            operation: Operation::FileRead,
            resource: Resource::Path(PathBuf::from(path)),
        }
    }

    fn net_query(id: u64, host: &str, port: u16) -> PolicyQuery {
        PolicyQuery {
            id,
            operation: Operation::NetworkConnect,
            resource: Resource::Network {
                host: host.to_string(),
                port,
            },
        }
    }

    // -- Basic evaluation ----------------------------------------------------

    #[test]
    fn test_session_allows_path_in_policy() {
        let mut policy = minimal_policy();
        policy.filesystem.allow_read = vec![PathBuf::from("/tmp/src")];
        let mut session = EnforcementSession::new(policy);

        let outcome = session.evaluate_query(&read_query(1, "/tmp/src/main.rs"));
        assert!(matches!(
            outcome,
            QueryOutcome::Decide(PolicyDecision {
                verdict: Verdict::Allow,
                ..
            })
        ));
    }

    #[test]
    fn test_session_denies_blocked_network_not_in_allowlist() {
        let policy = minimal_policy(); // block_all_other: true
        let mut session = EnforcementSession::new(policy);

        let outcome = session.evaluate_query(&net_query(1, "evil.com", 80));
        assert!(matches!(
            outcome,
            QueryOutcome::Decide(PolicyDecision {
                verdict: Verdict::Deny,
                ..
            })
        ));
    }

    #[test]
    fn test_session_prompts_medium_for_path_outside_policy() {
        let policy = minimal_policy();
        let mut session = EnforcementSession::new(policy);

        // Empty allow_read → outside scope → Prompt(Medium)
        let outcome = session.evaluate_query(&read_query(1, "/tmp/data.csv"));
        assert!(matches!(
            outcome,
            QueryOutcome::Prompt(JitPrompt {
                risk_tier: RiskTier::Medium,
                ..
            })
        ));
    }

    // -- JIT deduplication ---------------------------------------------------

    #[test]
    fn test_session_silently_redenies_after_first_deny() {
        let policy = minimal_policy();
        let mut session = EnforcementSession::new(policy);

        // First query: Deny by policy.
        let outcome1 = session.evaluate_query(&net_query(1, "blocked.com", 443));
        assert!(matches!(
            outcome1,
            QueryOutcome::Decide(PolicyDecision {
                verdict: Verdict::Deny,
                ..
            })
        ));

        // Second identical query: silent re-deny.
        let outcome2 = session.evaluate_query(&net_query(2, "blocked.com", 443));
        assert!(matches!(
            outcome2,
            QueryOutcome::Decide(PolicyDecision {
                verdict: Verdict::Deny,
                ..
            })
        ));
    }

    #[test]
    fn test_session_auto_allows_after_add_to_policy() {
        let mut policy = minimal_policy();
        policy.network.block_all_other = false; // allow prompts for unrecognised hosts
        let mut session = EnforcementSession::new(policy);
        let query = net_query(1, "example.com", 443);

        // First query prompts.
        let outcome = session.evaluate_query(&query);
        let QueryOutcome::Prompt(prompt) = outcome else {
            panic!("expected a prompt");
        };

        // User chooses AddToPolicy.
        let key = DedupeKey::from_parts(&query.operation, &query.resource);
        session.record_jit_response(key, query.id, JitDecision::AddToPolicy);

        // Second identical query: auto-allow.
        let outcome2 = session.evaluate_query(&net_query(2, "example.com", 443));
        assert!(
            matches!(
                outcome2,
                QueryOutcome::Decide(PolicyDecision {
                    verdict: Verdict::Allow,
                    ..
                })
            ),
            "prompt id was {}",
            prompt.id
        );
    }

    #[test]
    fn test_session_re_prompts_after_allow_once() {
        let mut policy = minimal_policy();
        policy.network.block_all_other = false; // allow prompts
        let mut session = EnforcementSession::new(policy);
        let query = net_query(1, "example.com", 443);

        // First query prompts.
        let outcome = session.evaluate_query(&query);
        assert!(matches!(outcome, QueryOutcome::Prompt(_)));

        // User chooses AllowOnce — no dedup update.
        let key = DedupeKey::from_parts(&query.operation, &query.resource);
        session.record_jit_response(key, query.id, JitDecision::AllowOnce);

        // Second identical query: prompts again.
        let outcome2 = session.evaluate_query(&net_query(2, "example.com", 443));
        assert!(matches!(outcome2, QueryOutcome::Prompt(_)));
    }

    // -- Stats ---------------------------------------------------------------

    #[test]
    fn test_session_summary_counts_blocks_correctly() {
        let policy = minimal_policy(); // block_all_other: true
        let mut session = EnforcementSession::new(policy);

        session.evaluate_query(&net_query(1, "a.com", 80));
        session.evaluate_query(&net_query(2, "a.com", 80)); // silent re-deny
        session.evaluate_query(&net_query(3, "b.com", 80));

        let summary = session.into_summary();
        assert_eq!(
            summary.total_blocks, 3,
            "should count all blocks including deduped"
        );
        assert_eq!(
            summary.unique_blocks, 2,
            "only first occurrence of each key is unique"
        );
    }

    #[test]
    fn test_session_summary_counts_prompts_correctly() {
        let mut policy = minimal_policy();
        policy.network.block_all_other = false; // allow prompts
        let mut session = EnforcementSession::new(policy);

        // Trigger a prompt.
        let query = net_query(1, "example.com", 443);
        let outcome = session.evaluate_query(&query);
        let QueryOutcome::Prompt(_prompt) = outcome else {
            panic!("expected prompt");
        };

        // User denies via JIT.
        let key = DedupeKey::from_parts(&query.operation, &query.resource);
        session.record_jit_response(key, query.id, JitDecision::Deny);

        let summary = session.into_summary();
        assert_eq!(summary.prompts_shown, 1);
        assert_eq!(summary.prompts_denied, 1);
        assert_eq!(summary.prompts_allowed, 0);
    }

    #[test]
    fn test_session_injection_signals_counted_for_sensitive_paths() {
        let mut policy = minimal_policy();
        policy.filesystem.block_hidden = false;
        let mut session = EnforcementSession::new(policy);

        session.evaluate_query(&PolicyQuery {
            id: 1,
            operation: Operation::FileRead,
            resource: Resource::Path(PathBuf::from("/home/user/.aws/credentials")),
        });

        let summary = session.into_summary();
        assert_eq!(summary.injection_signals, 1);
    }

    #[test]
    fn test_session_ids_are_unique_across_sessions() {
        let session_a = EnforcementSession::new(minimal_policy());
        let session_b = EnforcementSession::new(minimal_policy());
        assert_ne!(session_a.session_id, session_b.session_id);
    }

    #[test]
    fn test_session_prompt_ids_are_monotonically_increasing() {
        let mut policy = minimal_policy();
        policy.network.block_all_other = false; // allow prompts
        let mut session = EnforcementSession::new(policy);

        let outcome1 = session.evaluate_query(&net_query(1, "a.com", 80));
        let outcome2 = session.evaluate_query(&net_query(2, "b.com", 80));

        let id1 = if let QueryOutcome::Prompt(p) = outcome1 {
            p.id
        } else {
            panic!("expected prompt 1");
        };
        let id2 = if let QueryOutcome::Prompt(p) = outcome2 {
            p.id
        } else {
            panic!("expected prompt 2");
        };

        assert!(id2 > id1, "prompt IDs must be monotonically increasing");
    }

    // -- Deduplication: exhaustive per-resource-type -------------------------

    /// Silent re-deny must work for filesystem reads.
    #[test]
    fn test_session_silently_redenies_fs_read_after_first_deny() {
        let policy = minimal_policy(); // block_hidden=true → hidden paths denied
        let mut session = EnforcementSession::new(policy);

        // Policy denies .bashrc (hidden). Second identical query is silent.
        let q = PolicyQuery {
            id: 1,
            operation: Operation::FileRead,
            resource: Resource::Path(PathBuf::from("/home/user/.bashrc")),
        };
        let _ = session.evaluate_query(&q);

        let q2 = PolicyQuery { id: 2, ..q.clone() };
        let outcome = session.evaluate_query(&q2);
        assert!(
            matches!(
                outcome,
                QueryOutcome::Decide(PolicyDecision {
                    verdict: Verdict::Deny,
                    ..
                })
            ),
            "second identical denied fs query must be silently re-denied"
        );
    }

    /// Silent re-deny must work for env-var reads.
    #[test]
    fn test_session_silently_redenies_env_read_after_first_deny() {
        let policy = minimal_policy(); // block_all_other=true → unknown env denied
        let mut session = EnforcementSession::new(policy);

        let q = PolicyQuery {
            id: 1,
            operation: Operation::EnvRead,
            resource: Resource::EnvVar("MY_VAR".to_string()),
        };
        let _ = session.evaluate_query(&q);

        let q2 = PolicyQuery { id: 2, ..q.clone() };
        let outcome = session.evaluate_query(&q2);
        assert!(
            matches!(
                outcome,
                QueryOutcome::Decide(PolicyDecision {
                    verdict: Verdict::Deny,
                    ..
                })
            ),
            "second identical denied env query must be silently re-denied"
        );
    }

    /// Different operations on the same path must NOT share a dedup key.
    /// A read denial must not suppress a subsequent write query.
    #[test]
    fn test_session_different_ops_same_path_have_independent_dedup_keys() {
        let policy = minimal_policy(); // block_hidden=true
        let mut session = EnforcementSession::new(policy);

        // Deny hidden path read.
        let read_q = PolicyQuery {
            id: 1,
            operation: Operation::FileRead,
            resource: Resource::Path(PathBuf::from("/home/user/.bashrc")),
        };
        let _ = session.evaluate_query(&read_q);

        // Write query for same path must NOT be a silent dedup — it must be
        // independently evaluated (and also denied, but via policy not dedup).
        let write_q = PolicyQuery {
            id: 2,
            operation: Operation::FileWrite,
            resource: Resource::Path(PathBuf::from("/home/user/.bashrc")),
        };
        // The write is also denied by the hidden-path rule, but we verify
        // it is NOT counted as a "unique block" dedup hit from the read.
        let outcome = session.evaluate_query(&write_q);
        assert!(
            matches!(
                outcome,
                QueryOutcome::Decide(PolicyDecision {
                    verdict: Verdict::Deny,
                    ..
                })
            ),
            "write query must be independently evaluated"
        );
    }

    /// Silent re-deny for a JIT-denied prompt: after the user denies a prompt,
    /// subsequent identical queries are re-denied without re-prompting.
    #[test]
    fn test_session_silently_redenies_after_user_jit_deny() {
        let mut policy = minimal_policy();
        policy.network.block_all_other = false; // allow prompts
        let mut session = EnforcementSession::new(policy);

        let query = net_query(1, "example.com", 443);
        // First query prompts.
        let outcome = session.evaluate_query(&query);
        let QueryOutcome::Prompt(_) = outcome else {
            panic!("expected initial prompt");
        };

        // User denies via JIT.
        let key = DedupeKey::from_parts(&query.operation, &query.resource);
        session.record_jit_response(key, query.id, JitDecision::Deny);

        // Second identical query must be silently re-denied without prompting.
        let q2 = net_query(2, "example.com", 443);
        let outcome2 = session.evaluate_query(&q2);
        assert!(
            matches!(
                outcome2,
                QueryOutcome::Decide(PolicyDecision {
                    verdict: Verdict::Deny,
                    ..
                })
            ),
            "after user JIT deny, identical queries must be silently re-denied"
        );
        // And it must not be counted as a new prompt.
        let summary = session.into_summary();
        assert_eq!(
            summary.prompts_shown, 1,
            "only one prompt should have been shown"
        );
    }

    /// The silent-deny counter increments on every dedup hit, not just first.
    #[test]
    fn test_session_total_blocks_counts_every_silent_redeny() {
        let policy = minimal_policy(); // block_all_other=true for net
        let mut session = EnforcementSession::new(policy);

        // Three queries for the same blocked destination.
        session.evaluate_query(&net_query(1, "evil.com", 443));
        session.evaluate_query(&net_query(2, "evil.com", 443));
        session.evaluate_query(&net_query(3, "evil.com", 443));

        let summary = session.into_summary();
        assert_eq!(summary.total_blocks, 3, "all three queries count as blocks");
        assert_eq!(summary.unique_blocks, 1, "only the first is a unique block");
    }

    /// Unknown IP destinations are classified Tier 3 (High) inside a session.
    #[test]
    fn test_session_unknown_ip_prompts_high_tier() {
        let mut policy = minimal_policy();
        policy.network.block_all_other = false; // allow prompts to surface
        let mut session = EnforcementSession::new(policy);

        let outcome = session.evaluate_query(&net_query(1, "203.0.113.99", 80));
        assert!(
            matches!(
                outcome,
                QueryOutcome::Prompt(JitPrompt {
                    risk_tier: RiskTier::High,
                    ..
                })
            ),
            "unknown IP address must surface a High-tier prompt"
        );
    }

    /// High-tier prompts for sensitive filesystem paths include injection_signal
    /// in the session counter.
    #[test]
    fn test_session_injection_signals_counted_for_all_sensitive_fs_patterns() {
        let mut policy = minimal_policy();
        policy.filesystem.block_hidden = false;
        let mut session = EnforcementSession::new(policy);

        let sensitive_paths = [
            "/home/user/.ssh/id_rsa",
            "/home/user/.aws/credentials",
            "/home/user/.gnupg/secring.gpg",
            "/home/user/.config/gcloud/credentials.json",
            "/home/user/.config/gh/hosts.yml",
            "/home/user/.kube/config",
            "/home/user/.netrc",
            "/etc/passwd",
            "/etc/shadow",
            "/etc/sudoers",
        ];

        for (i, path) in sensitive_paths.iter().enumerate() {
            session.evaluate_query(&PolicyQuery {
                id: i as u64 + 1,
                operation: Operation::FileRead,
                resource: Resource::Path(PathBuf::from(path)),
            });
        }

        let summary = session.into_summary();
        assert_eq!(
            summary.injection_signals,
            sensitive_paths.len() as u64,
            "every sensitive path access must increment injection_signals"
        );
    }

    /// High-tier prompts for sensitive env vars include injection_signal.
    #[test]
    fn test_session_injection_signals_counted_for_all_sensitive_env_patterns() {
        let mut policy = minimal_policy();
        policy.environment.block_all_other = false;
        let mut session = EnforcementSession::new(policy);

        let sensitive_vars = [
            "AWS_SECRET_ACCESS_KEY",
            "GOOGLE_APPLICATION_CREDENTIALS",
            "GITHUB_TOKEN",
            "NPM_TOKEN",
            "DATABASE_URL",
            "APP_SECRET_KEY",
            "DB_PASSWORD",
            "SSH_PRIVATE_KEY",
        ];

        for (i, var) in sensitive_vars.iter().enumerate() {
            session.evaluate_query(&PolicyQuery {
                id: i as u64 + 1,
                operation: Operation::EnvRead,
                resource: Resource::EnvVar((*var).to_string()),
            });
        }

        let summary = session.into_summary();
        assert_eq!(
            summary.injection_signals,
            sensitive_vars.len() as u64,
            "every sensitive env var access must increment injection_signals"
        );
    }
}
