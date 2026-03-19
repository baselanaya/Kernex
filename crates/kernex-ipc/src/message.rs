use std::path::PathBuf;

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Tests — written first (Red), types defined below (Green)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Serialize to JSON then deserialize back; assert the value is identical.
    fn round_trip(msg: &IpcMessage) -> IpcMessage {
        let json = serde_json::to_string(msg).expect("serialize should succeed");
        serde_json::from_str(&json).expect("deserialize should succeed")
    }

    #[test]
    fn test_ipc_message_policy_query_file_read_roundtrips() {
        let msg = IpcMessage::PolicyQuery(PolicyQuery {
            id: 42,
            operation: Operation::FileRead,
            resource: Resource::Path(PathBuf::from("/home/user/data.csv")),
        });
        assert_eq!(round_trip(&msg), msg);
    }

    #[test]
    fn test_ipc_message_policy_query_network_connect_roundtrips() {
        let msg = IpcMessage::PolicyQuery(PolicyQuery {
            id: 1,
            operation: Operation::NetworkConnect,
            resource: Resource::Network {
                host: "api.anthropic.com".to_string(),
                port: 443,
            },
        });
        assert_eq!(round_trip(&msg), msg);
    }

    #[test]
    fn test_ipc_message_policy_query_env_var_roundtrips() {
        let msg = IpcMessage::PolicyQuery(PolicyQuery {
            id: 2,
            operation: Operation::EnvRead,
            resource: Resource::EnvVar("ANTHROPIC_API_KEY".to_string()),
        });
        assert_eq!(round_trip(&msg), msg);
    }

    #[test]
    fn test_ipc_message_policy_query_syscall_with_name_roundtrips() {
        let msg = IpcMessage::PolicyQuery(PolicyQuery {
            id: 3,
            operation: Operation::Syscall,
            resource: Resource::Syscall {
                nr: 62,
                name: Some("kill".to_string()),
            },
        });
        assert_eq!(round_trip(&msg), msg);
    }

    #[test]
    fn test_ipc_message_policy_query_syscall_without_name_roundtrips() {
        let msg = IpcMessage::PolicyQuery(PolicyQuery {
            id: 4,
            operation: Operation::Syscall,
            resource: Resource::Syscall {
                nr: 999,
                name: None,
            },
        });
        assert_eq!(round_trip(&msg), msg);
    }

    #[test]
    fn test_ipc_message_policy_decision_allow_roundtrips() {
        let msg = IpcMessage::PolicyDecision(PolicyDecision {
            query_id: 42,
            verdict: Verdict::Allow,
        });
        assert_eq!(round_trip(&msg), msg);
    }

    #[test]
    fn test_ipc_message_policy_decision_deny_roundtrips() {
        let msg = IpcMessage::PolicyDecision(PolicyDecision {
            query_id: 99,
            verdict: Verdict::Deny,
        });
        assert_eq!(round_trip(&msg), msg);
    }

    #[test]
    fn test_ipc_message_policy_decision_prompt_roundtrips() {
        let msg = IpcMessage::PolicyDecision(PolicyDecision {
            query_id: 7,
            verdict: Verdict::Prompt,
        });
        assert_eq!(round_trip(&msg), msg);
    }

    #[test]
    fn test_ipc_message_jit_prompt_medium_risk_roundtrips() {
        let msg = IpcMessage::JitPrompt(JitPrompt {
            id: 1,
            risk_tier: RiskTier::Medium,
            operation: Operation::NetworkConnect,
            resource: Resource::Network {
                host: "example.com".to_string(),
                port: 443,
            },
            message: "Agent wants to connect to example.com:443".to_string(),
        });
        assert_eq!(round_trip(&msg), msg);
    }

    #[test]
    fn test_ipc_message_jit_prompt_high_risk_roundtrips() {
        let msg = IpcMessage::JitPrompt(JitPrompt {
            id: 2,
            risk_tier: RiskTier::High,
            operation: Operation::FileRead,
            resource: Resource::Path(PathBuf::from("/home/user/.aws/credentials")),
            message: "Agent attempted to read AWS credentials — possible prompt injection"
                .to_string(),
        });
        assert_eq!(round_trip(&msg), msg);
    }

    #[test]
    fn test_ipc_message_jit_response_allow_once_roundtrips() {
        let msg = IpcMessage::JitResponse(JitResponse {
            prompt_id: 1,
            decision: JitDecision::AllowOnce,
        });
        assert_eq!(round_trip(&msg), msg);
    }

    #[test]
    fn test_ipc_message_jit_response_add_to_policy_roundtrips() {
        let msg = IpcMessage::JitResponse(JitResponse {
            prompt_id: 2,
            decision: JitDecision::AddToPolicy,
        });
        assert_eq!(round_trip(&msg), msg);
    }

    #[test]
    fn test_ipc_message_jit_response_deny_roundtrips() {
        let msg = IpcMessage::JitResponse(JitResponse {
            prompt_id: 3,
            decision: JitDecision::Deny,
        });
        assert_eq!(round_trip(&msg), msg);
    }

    #[test]
    fn test_ipc_message_session_summary_roundtrips() {
        let msg = IpcMessage::SessionSummary(SessionSummary {
            session_id: "550e8400-e29b-41d4-a716-446655440000".to_string(),
            total_blocks: 12,
            unique_blocks: 3,
            prompts_shown: 1,
            prompts_allowed: 0,
            prompts_denied: 1,
            injection_signals: 1,
        });
        assert_eq!(round_trip(&msg), msg);
    }

    #[test]
    fn test_ipc_message_envelope_has_type_and_data_fields() {
        let msg = IpcMessage::PolicyQuery(PolicyQuery {
            id: 1,
            operation: Operation::FileRead,
            resource: Resource::Path(PathBuf::from("/tmp/test")),
        });
        let json = serde_json::to_string(&msg).expect("serialize should succeed");
        let value: serde_json::Value = serde_json::from_str(&json).expect("parse should succeed");
        assert_eq!(
            value["type"], "PolicyQuery",
            "envelope must have 'type' discriminant"
        );
        assert!(
            value["data"].is_object(),
            "envelope must have 'data' object"
        );
    }

    #[test]
    fn test_operation_serializes_to_snake_case() {
        assert_eq!(
            serde_json::to_string(&Operation::FileRead).unwrap(),
            "\"file_read\""
        );
        assert_eq!(
            serde_json::to_string(&Operation::NetworkConnect).unwrap(),
            "\"network_connect\""
        );
    }

    #[test]
    fn test_verdict_serializes_to_snake_case() {
        assert_eq!(serde_json::to_string(&Verdict::Allow).unwrap(), "\"allow\"");
        assert_eq!(serde_json::to_string(&Verdict::Deny).unwrap(), "\"deny\"");
        assert_eq!(
            serde_json::to_string(&Verdict::Prompt).unwrap(),
            "\"prompt\""
        );
    }

    #[test]
    fn test_risk_tier_serializes_to_snake_case() {
        assert_eq!(
            serde_json::to_string(&RiskTier::Medium).unwrap(),
            "\"medium\""
        );
        assert_eq!(serde_json::to_string(&RiskTier::High).unwrap(), "\"high\"");
    }

    #[test]
    fn test_jit_decision_serializes_to_snake_case() {
        assert_eq!(
            serde_json::to_string(&JitDecision::AllowOnce).unwrap(),
            "\"allow_once\""
        );
        assert_eq!(
            serde_json::to_string(&JitDecision::AddToPolicy).unwrap(),
            "\"add_to_policy\""
        );
    }
}

// ---------------------------------------------------------------------------
// Message types
// ---------------------------------------------------------------------------

/// All IPC messages exchanged between the Kernex CLI and the core engine.
///
/// Direction:
/// - CLI → Core: [`IpcMessage::PolicyQuery`], [`IpcMessage::JitResponse`]
/// - Core → CLI: [`IpcMessage::PolicyDecision`], [`IpcMessage::JitPrompt`],
///   [`IpcMessage::SessionSummary`]
///
/// Wire format: a `"type"` discriminant field plus a `"data"` payload object.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", content = "data")]
pub enum IpcMessage {
    /// CLI asks the core whether a specific operation on a resource is permitted.
    PolicyQuery(PolicyQuery),
    /// Core answers a [`PolicyQuery`].
    PolicyDecision(PolicyDecision),
    /// Core asks the CLI to display a JIT confirmation prompt to the user.
    JitPrompt(JitPrompt),
    /// User's response to a [`JitPrompt`], relayed from the CLI to the core.
    JitResponse(JitResponse),
    /// Emitted by the core on session exit. Contains aggregate session statistics.
    SessionSummary(SessionSummary),
}

/// A request from the CLI to the core engine asking whether an operation is permitted.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PolicyQuery {
    /// Monotonically increasing per-session request identifier.
    ///
    /// The corresponding [`PolicyDecision`] carries the same `id` in its
    /// `query_id` field, enabling the CLI to correlate async responses.
    pub id: u64,
    /// The type of operation being attempted by the agent.
    pub operation: Operation,
    /// The resource being accessed.
    pub resource: Resource,
}

/// The core engine's verdict on a [`PolicyQuery`].
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PolicyDecision {
    /// Matches [`PolicyQuery::id`].
    pub query_id: u64,
    /// The enforcement verdict.
    pub verdict: Verdict,
}

/// Core instructs the CLI to surface a JIT confirmation prompt to the user.
///
/// The pending operation is held until the CLI sends back a [`JitResponse`]
/// with the matching `id`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct JitPrompt {
    /// Unique identifier for this prompt. Matched by [`JitResponse::prompt_id`].
    pub id: u64,
    /// Risk classification that determines prompt styling (standard vs red).
    pub risk_tier: RiskTier,
    /// The operation that triggered the prompt.
    pub operation: Operation,
    /// The resource being accessed.
    pub resource: Resource,
    /// Human-readable explanation displayed in the prompt box.
    pub message: String,
}

/// The user's response to a [`JitPrompt`], sent from the CLI back to the core.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct JitResponse {
    /// Matches [`JitPrompt::id`].
    pub prompt_id: u64,
    /// What the user chose.
    pub decision: JitDecision,
}

/// Session-exit statistics emitted by the core engine.
///
/// Maps directly to the `--output=json` `summary` field in the CLI UX spec.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SessionSummary {
    /// Unique session identifier (UUID-formatted string).
    pub session_id: String,
    /// Total blocked operations, including deduplicated silent re-denials.
    pub total_blocks: u64,
    /// Unique path/operation pairs that were blocked (before deduplication).
    pub unique_blocks: u64,
    /// Number of JIT prompts shown to the user.
    pub prompts_shown: u64,
    /// Number of JIT prompts where the user chose to allow.
    pub prompts_allowed: u64,
    /// Number of JIT prompts where the user chose to deny.
    pub prompts_denied: u64,
    /// Number of operations that triggered a prompt-injection heuristic signal.
    pub injection_signals: u64,
}

/// The class of operation the agent attempted.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Operation {
    /// Read a file or directory listing.
    FileRead,
    /// Create or write a file.
    FileWrite,
    /// Execute a file (`execve`).
    FileExec,
    /// Establish an outbound network connection.
    NetworkConnect,
    /// Read an environment variable.
    EnvRead,
    /// Invoke a syscall not covered by the above categories.
    Syscall,
}

/// The resource the agent attempted to access.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "value", rename_all = "snake_case")]
pub enum Resource {
    /// A filesystem path.
    Path(PathBuf),
    /// A network destination.
    Network { host: String, port: u16 },
    /// An environment variable name.
    EnvVar(String),
    /// A raw syscall identified by number and optional symbolic name.
    Syscall { nr: u32, name: Option<String> },
}

/// The enforcement verdict returned by the core engine.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Verdict {
    /// The operation is permitted by the active policy.
    Allow,
    /// The operation is denied by the active policy.
    Deny,
    /// The policy does not cover this case; the core will surface a [`JitPrompt`].
    Prompt,
}

/// Risk classification used to style JIT prompts in the CLI.
///
/// Corresponds directly to the Tier 2 / Tier 3 distinction in the CLI UX spec.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RiskTier {
    /// New path or destination outside policy scope — standard bordered prompt.
    Medium,
    /// Sensitive credential or system path — red high-risk prompt with explicit warning.
    High,
}

/// The user's response to a JIT prompt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum JitDecision {
    /// Allow this specific instance only. Do not persist to `kernex.yaml`.
    AllowOnce,
    /// Allow and append to the active `kernex.yaml` policy.
    AddToPolicy,
    /// Deny the operation.
    Deny,
}
