//! Async IPC session loop and pre-run policy scoring.
//!
//! # Pre-run scoring
//!
//! Before entering the enforcement loop, `run_session` scores the loaded
//! policy. If the score is below 60, a one-line warning is emitted via
//! `tracing::warn!`. The run is never blocked by a low score.
//!
//! # Session loop
//!
//! The loop reads [`IpcMessage::PolicyQuery`] messages from `conn`, evaluates
//! each one via [`EnforcementSession`], and writes back a
//! [`IpcMessage::PolicyDecision`]. When a JIT prompt is needed, the loop:
//!
//! 1. Sends [`IpcMessage::JitPrompt`] to the CLI.
//! 2. Waits for [`IpcMessage::JitResponse`] within [`JIT_TIMEOUT_SECS`].
//! 3. Updates dedup state and sends the final [`IpcMessage::PolicyDecision`].
//!
//! When the peer closes the connection ([`IpcError::ConnectionClosed`]), the
//! loop exits cleanly and sends [`IpcMessage::SessionSummary`].

use std::time::Duration;

use kernex_ipc::{IpcConnection, IpcError, IpcMessage, JitResponse};
use kernex_policy::KernexPolicy;
use tokio::time::timeout;

use crate::backend::SandboxBackend;
use crate::dedupe::DedupeKey;
use crate::error::CoreError;
use crate::session::{EnforcementSession, QueryOutcome};

/// Seconds to wait for a [`JitResponse`] before aborting with [`CoreError::JitTimeout`].
pub const JIT_TIMEOUT_SECS: u64 = 60;

/// Score threshold below which a warning is emitted before running.
const SCORE_WARN_THRESHOLD: u8 = 60;

/// Set up the sandbox and run the full enforcement IPC loop for one session.
///
/// # Arguments
///
/// - `backend` — OS sandbox implementation (real or mock in tests).
/// - `conn` — bidirectional IPC connection to the CLI.
/// - `policy` — the loaded and validated `kernex.yaml` policy.
/// - `strict` — if `true`, enforcement failures abort instead of degrading.
///
/// # Errors
///
/// - [`CoreError::Sandbox`] — enforcement layer failed to set up.
/// - [`CoreError::Ipc`] — unrecoverable IPC error.
/// - [`CoreError::UnexpectedMessage`] — protocol state machine violation.
/// - [`CoreError::JitTimeout`] — CLI did not respond to a JIT prompt in time.
pub async fn run_session(
    backend: &dyn SandboxBackend,
    conn: &mut IpcConnection,
    policy: KernexPolicy,
    strict: bool,
) -> Result<(), CoreError> {
    // Score the policy and warn if below threshold.
    let score = policy.score();
    if score.total < SCORE_WARN_THRESHOLD {
        tracing::warn!(
            score = score.total,
            findings = ?score.findings,
            "Policy score is below {SCORE_WARN_THRESHOLD}/100 — consider improving your kernex.yaml"
        );
    }

    // Set up OS enforcement layers.
    backend.setup(&policy, strict)?;

    // Enter the session loop.
    let mut session = EnforcementSession::new(policy);

    loop {
        let msg = match conn.recv().await {
            Ok(msg) => msg,
            Err(IpcError::ConnectionClosed) => break,
            Err(e) => return Err(CoreError::Ipc(e)),
        };

        match msg {
            IpcMessage::PolicyQuery(query) => {
                let key = DedupeKey::from_parts(&query.operation, &query.resource);
                let query_id = query.id;

                match session.evaluate_query(&query) {
                    QueryOutcome::Decide(decision) => {
                        conn.send(&IpcMessage::PolicyDecision(decision)).await?;
                    }
                    QueryOutcome::Prompt(prompt) => {
                        conn.send(&IpcMessage::JitPrompt(prompt)).await?;

                        let response = receive_jit_response(conn).await?;
                        let decision =
                            session.record_jit_response(key, query_id, response.decision);
                        conn.send(&IpcMessage::PolicyDecision(decision)).await?;
                    }
                }
            }
            other => {
                return Err(CoreError::UnexpectedMessage {
                    expected: "PolicyQuery",
                    got: message_type_name(&other),
                });
            }
        }
    }

    // Session ended — send summary.
    let summary = session.into_summary();
    conn.send(&IpcMessage::SessionSummary(summary)).await?;

    Ok(())
}

/// Wait for a [`IpcMessage::JitResponse`] within [`JIT_TIMEOUT_SECS`].
async fn receive_jit_response(conn: &mut IpcConnection) -> Result<JitResponse, CoreError> {
    let duration = Duration::from_secs(JIT_TIMEOUT_SECS);
    let msg = timeout(duration, conn.recv())
        .await
        .map_err(|_| CoreError::JitTimeout {
            seconds: JIT_TIMEOUT_SECS,
        })??;

    match msg {
        IpcMessage::JitResponse(resp) => Ok(resp),
        other => Err(CoreError::UnexpectedMessage {
            expected: "JitResponse",
            got: message_type_name(&other),
        }),
    }
}

/// Return a static string naming the message variant (for error messages).
fn message_type_name(msg: &IpcMessage) -> &'static str {
    match msg {
        IpcMessage::PolicyQuery(_) => "PolicyQuery",
        IpcMessage::PolicyDecision(_) => "PolicyDecision",
        IpcMessage::JitPrompt(_) => "JitPrompt",
        IpcMessage::JitResponse(_) => "JitResponse",
        IpcMessage::SessionSummary(_) => "SessionSummary",
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_message_type_name_covers_all_variants() {
        use kernex_ipc::{
            IpcMessage, JitDecision, JitResponse, Operation, PolicyDecision, PolicyQuery, Resource,
            SessionSummary, Verdict,
        };
        use std::path::PathBuf;

        let msgs = vec![
            IpcMessage::PolicyQuery(PolicyQuery {
                id: 1,
                operation: Operation::FileRead,
                resource: Resource::Path(PathBuf::from("/tmp")),
            }),
            IpcMessage::PolicyDecision(PolicyDecision {
                query_id: 1,
                verdict: Verdict::Allow,
            }),
            IpcMessage::JitPrompt(kernex_ipc::JitPrompt {
                id: 1,
                risk_tier: kernex_ipc::RiskTier::Medium,
                operation: Operation::FileRead,
                resource: Resource::Path(PathBuf::from("/tmp")),
                message: "test".to_string(),
            }),
            IpcMessage::JitResponse(JitResponse {
                prompt_id: 1,
                decision: JitDecision::AllowOnce,
            }),
            IpcMessage::SessionSummary(SessionSummary {
                session_id: "s".to_string(),
                total_blocks: 0,
                unique_blocks: 0,
                prompts_shown: 0,
                prompts_allowed: 0,
                prompts_denied: 0,
                injection_signals: 0,
            }),
        ];

        for msg in &msgs {
            let name = message_type_name(msg);
            assert!(
                !name.is_empty(),
                "message_type_name must return non-empty string"
            );
        }
    }
}
