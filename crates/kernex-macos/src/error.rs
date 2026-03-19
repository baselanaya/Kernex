use thiserror::Error;

/// Errors from macOS Endpoint Security sandbox operations.
///
/// All variants carry a human-readable message suitable for display to the
/// operator. `EntitlementMissing` is the expected error in development
/// environments where the binary is not signed with the ES entitlement.
#[derive(Debug, Error)]
pub enum MacosError {
    /// `es_new_client()` failed to create an ES client.
    ///
    /// The inner string contains the raw error from the framework.
    /// For entitlement-related failures, see [`MacosError::EntitlementMissing`].
    #[error("Endpoint Security client creation failed: {0}")]
    ClientCreate(String),

    /// `es_subscribe()` failed after the client was created.
    #[error("Endpoint Security event subscription failed: {0}")]
    Subscribe(String),

    /// `es_respond_auth_result()` failed — the kernel did not accept the response.
    ///
    /// If this persists, the ES framework may have timed out and failed open,
    /// which is a security regression. Treat this as a fatal error.
    #[error("Endpoint Security auth event response failed: {0}")]
    Respond(String),

    /// The binary lacks the `com.apple.developer.endpoint-security.client`
    /// entitlement required to register an Endpoint Security client.
    ///
    /// In non-strict mode this causes graceful degradation to unprotected
    /// execution with a warning. In `--strict` mode this is fatal.
    #[error(
        "Endpoint Security requires the \
         com.apple.developer.endpoint-security.client entitlement. \
         Obtain a provisioning profile from Apple and re-sign the binary. \
         See https://developer.apple.com/documentation/endpointsecurity"
    )]
    EntitlementMissing,

    /// The Endpoint Security API is not available on this macOS version.
    ///
    /// Endpoint Security requires macOS 10.15 (Catalina) or later.
    #[error(
        "Endpoint Security API is not available on this macOS version \
         (requires macOS 10.15+)"
    )]
    NotAvailable,

    /// The pre-warmed monitor or audit thread exited unexpectedly.
    #[error("ES monitoring thread exited unexpectedly: {0}")]
    MonitorPanicked(String),
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_entitlement_missing_message_contains_entitlement_name() {
        let msg = MacosError::EntitlementMissing.to_string();
        assert!(msg.contains("com.apple.developer.endpoint-security.client"));
    }

    #[test]
    fn test_client_create_includes_reason() {
        let err = MacosError::ClientCreate("mock reason".to_string());
        assert!(err.to_string().contains("mock reason"));
    }

    #[test]
    fn test_subscribe_includes_reason() {
        let err = MacosError::Subscribe("EPERM".to_string());
        assert!(err.to_string().contains("EPERM"));
    }

    #[test]
    fn test_respond_error_includes_reason() {
        let err = MacosError::Respond("timeout".to_string());
        assert!(err.to_string().contains("timeout"));
    }

    #[test]
    fn test_monitor_panicked_includes_reason() {
        let err = MacosError::MonitorPanicked("thread died".to_string());
        assert!(err.to_string().contains("thread died"));
    }

    #[test]
    fn test_not_available_mentions_macos_version() {
        let msg = MacosError::NotAvailable.to_string();
        assert!(msg.contains("10.15") || msg.contains("macOS"));
    }
}
