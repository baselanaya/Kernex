use thiserror::Error;

/// Top-level error type for the `kernex-core` policy engine.
#[derive(Debug, Error)]
pub enum CoreError {
    /// An IPC communication error occurred.
    #[error("IPC error: {0}")]
    Ipc(#[from] kernex_ipc::IpcError),

    /// Policy parsing or validation failed.
    #[error("policy error: {0}")]
    Policy(#[from] kernex_policy::PolicyError),

    /// OS sandbox enforcement layer failed to set up.
    #[error("sandbox setup failed: {0}")]
    Sandbox(String),

    /// The enforcement session was aborted before the agent process exited.
    #[error("session aborted: {reason}")]
    SessionAborted { reason: String },

    /// The core received an IPC message of the wrong type at this point in the
    /// protocol state machine.
    #[error("unexpected IPC message: expected {expected}, received {got}")]
    UnexpectedMessage {
        expected: &'static str,
        got: &'static str,
    },

    /// A JIT prompt was sent but the CLI did not respond within the timeout.
    #[error("JIT prompt timed out after {seconds}s with no user response")]
    JitTimeout { seconds: u64 },
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -- Display messages ----------------------------------------------------

    #[test]
    fn test_core_error_sandbox_has_meaningful_message() {
        let err = CoreError::Sandbox("prctl failed with EPERM".into());
        let msg = err.to_string();
        assert!(msg.contains("sandbox"));
        assert!(msg.contains("prctl failed with EPERM"));
    }

    #[test]
    fn test_core_error_session_aborted_includes_reason() {
        let err = CoreError::SessionAborted {
            reason: "agent exited unexpectedly".into(),
        };
        let msg = err.to_string();
        assert!(msg.contains("agent exited unexpectedly"));
    }

    #[test]
    fn test_core_error_unexpected_message_names_both_types() {
        let err = CoreError::UnexpectedMessage {
            expected: "JitResponse",
            got: "PolicyQuery",
        };
        let msg = err.to_string();
        assert!(msg.contains("JitResponse"));
        assert!(msg.contains("PolicyQuery"));
    }

    #[test]
    fn test_core_error_jit_timeout_includes_seconds() {
        let err = CoreError::JitTimeout { seconds: 30 };
        let msg = err.to_string();
        assert!(msg.contains("30"));
    }

    // -- From conversions ----------------------------------------------------

    #[test]
    fn test_core_error_from_policy_error() {
        let policy_err = kernex_policy::PolicyError::MissingField("agent_name".into());
        let core_err: CoreError = policy_err.into();
        assert!(matches!(core_err, CoreError::Policy(_)));
    }
}
