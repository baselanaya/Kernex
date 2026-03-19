use kernex_policy::FilesystemPolicy;

use crate::error::MacosError;
use crate::spawn::{EsClientBuilt, EsMonitorActive, MacosSandboxReady};

// ---------------------------------------------------------------------------
// SandboxBackend trait
// ---------------------------------------------------------------------------

/// Abstraction over the macOS Endpoint Security enforcement API.
///
/// Mirrors the structure of `kernex_linux::SandboxBackend` but maps to macOS
/// concepts: building an ES client replaces building a Landlock ruleset, and
/// activating the monitor replaces calling `restrict_self()`.
///
/// # Ordering
///
/// `setup_sandbox` calls the methods in this exact order:
///
/// 1. `build_es_client` — creates the ES client with event subscriptions.
/// 2. `activate_monitor` — assigns the agent PID and starts event handling.
///
/// The type system enforces it: [`EsMonitorActive`] can only be constructed
/// from a consumed [`EsClientBuilt`] returned by `build_es_client`.
///
/// # Entitlement requirement
///
/// `build_es_client` returns [`MacosError::EntitlementMissing`] when the
/// binary lacks `com.apple.developer.endpoint-security.client`. In non-strict
/// mode `setup_sandbox` degrades gracefully to unprotected execution.
#[cfg_attr(test, mockall::automock)]
pub trait SandboxBackend {
    /// Build and configure the Endpoint Security client.
    ///
    /// Creates the ES client, subscribes to `AUTH_OPEN`, `AUTH_CREATE`,
    /// `AUTH_UNLINK`, `AUTH_RENAME`, `AUTH_EXEC`, and `AUTH_MMAP` event
    /// types, and pre-warms the audit thread. Does **not** start filtering
    /// by PID yet — that happens in [`activate_monitor`].
    ///
    /// # Errors
    ///
    /// - [`MacosError::EntitlementMissing`] — binary lacks the ES entitlement.
    /// - [`MacosError::ClientCreate`] — `es_new_client()` failed.
    /// - [`MacosError::Subscribe`] — `es_subscribe()` failed.
    fn build_es_client(&self, policy: &FilesystemPolicy) -> Result<EsClientBuilt, MacosError>;

    /// Activate ES monitoring for the specified agent PID.
    ///
    /// Consumes the prepared [`EsClientBuilt`] and returns an
    /// [`EsMonitorActive`] that must be kept alive for the duration of the
    /// agent's execution. Every `AUTH` event from `agent_pid` is evaluated
    /// against the policy and responded to before the kernel timeout (~30 s).
    ///
    /// # Errors
    ///
    /// - [`MacosError::MonitorPanicked`] — monitor thread failed to start.
    fn activate_monitor(
        &self,
        built: EsClientBuilt,
        agent_pid: u32,
    ) -> Result<EsMonitorActive, MacosError>;
}

// ---------------------------------------------------------------------------
// setup_sandbox — orchestrator
// ---------------------------------------------------------------------------

/// Set up the macOS sandbox for an agent process.
///
/// Calls `backend` methods in the required order:
/// 1. `build_es_client(policy)` — prepare the ES client with subscriptions.
/// 2. `activate_monitor(built, agent_pid)` — start PID-scoped monitoring.
///
/// Returns [`MacosSandboxReady::Full`] on success. Returns
/// [`MacosSandboxReady::Degraded`] when the ES entitlement is missing and
/// `strict = false`.
///
/// # Errors
///
/// - [`MacosError::EntitlementMissing`] when `strict = true`.
/// - Any [`MacosError`] from `activate_monitor`.
///
/// # Panics
///
/// Never panics.
pub fn setup_sandbox<B: SandboxBackend>(
    backend: &B,
    policy: &FilesystemPolicy,
    agent_pid: u32,
    strict: bool,
) -> Result<MacosSandboxReady, MacosError> {
    match backend.build_es_client(policy) {
        Ok(built) => {
            let monitor = backend.activate_monitor(built, agent_pid)?;
            Ok(MacosSandboxReady::Full(monitor))
        }
        Err(MacosError::EntitlementMissing) if !strict => {
            tracing::warn!(
                "Endpoint Security entitlement missing; \
                 falling back to unprotected execution. \
                 Obtain com.apple.developer.endpoint-security.client \
                 to enable enforcement."
            );
            Ok(MacosSandboxReady::Degraded)
        }
        Err(e) => Err(e),
    }
}

// ---------------------------------------------------------------------------
// MacosSandboxBackend — real implementation (macOS only)
// ---------------------------------------------------------------------------

/// The production implementation of [`SandboxBackend`].
///
/// Makes real Endpoint Security API calls via the `endpoint-sec` crate.
/// Only available on macOS; requires the
/// `com.apple.developer.endpoint-security.client` entitlement.
///
/// # Beta status
///
/// This implementation is marked beta. Entitlement acquisition and binary
/// signing setup are not automated. See `docs/adr/` for macOS enforcement
/// architecture decisions.
#[cfg(target_os = "macos")]
pub struct MacosSandboxBackend;

#[cfg(target_os = "macos")]
impl SandboxBackend for MacosSandboxBackend {
    fn build_es_client(&self, policy: &FilesystemPolicy) -> Result<EsClientBuilt, MacosError> {
        let handle = crate::es_client::build_client(policy)?;
        Ok(EsClientBuilt {
            activate: Box::new(move |agent_pid: u32| {
                crate::es_client::activate_for_pid(handle, agent_pid)
            }),
        })
    }

    fn activate_monitor(
        &self,
        built: EsClientBuilt,
        agent_pid: u32,
    ) -> Result<EsMonitorActive, MacosError> {
        (built.activate)(agent_pid)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use mockall::Sequence;

    fn default_policy() -> FilesystemPolicy {
        FilesystemPolicy::default()
    }

    // -- Ordering: build must precede activate --------------------------------

    #[test]
    fn test_setup_sandbox_calls_build_before_activate() {
        let mut seq = Sequence::new();
        let mut mock = MockSandboxBackend::new();

        mock.expect_build_es_client()
            .times(1)
            .in_sequence(&mut seq)
            .returning(|_| Ok(EsClientBuilt::dummy()));

        mock.expect_activate_monitor()
            .times(1)
            .in_sequence(&mut seq)
            .returning(|_, _| Ok(EsMonitorActive::dummy()));

        let result = setup_sandbox(&mock, &default_policy(), 1234, false);
        assert!(result.is_ok());
        assert!(result.unwrap().is_full());
    }

    // -- Entitlement missing: non-strict degrades ----------------------------

    #[test]
    fn test_setup_sandbox_degrades_on_entitlement_missing_non_strict() {
        let mut mock = MockSandboxBackend::new();

        mock.expect_build_es_client()
            .returning(|_| Err(MacosError::EntitlementMissing));

        // activate_monitor must NOT be called when build fails.
        mock.expect_activate_monitor().times(0);

        let result = setup_sandbox(&mock, &default_policy(), 1234, false);
        assert!(result.is_ok());
        assert!(result.unwrap().is_degraded());
    }

    // -- Entitlement missing: strict aborts -----------------------------------

    #[test]
    fn test_setup_sandbox_strict_aborts_on_entitlement_missing() {
        let mut mock = MockSandboxBackend::new();

        mock.expect_build_es_client()
            .returning(|_| Err(MacosError::EntitlementMissing));

        mock.expect_activate_monitor().times(0);

        let result = setup_sandbox(&mock, &default_policy(), 1234, true);
        assert!(matches!(result, Err(MacosError::EntitlementMissing)));
    }

    // -- Other errors propagate regardless of strict mode --------------------

    #[test]
    fn test_setup_sandbox_propagates_client_create_error() {
        let mut mock = MockSandboxBackend::new();

        mock.expect_build_es_client()
            .returning(|_| Err(MacosError::ClientCreate("internal".to_string())));

        mock.expect_activate_monitor().times(0);

        let result = setup_sandbox(&mock, &default_policy(), 1234, false);
        assert!(matches!(result, Err(MacosError::ClientCreate(_))));
    }

    #[test]
    fn test_setup_sandbox_propagates_subscribe_error() {
        let mut mock = MockSandboxBackend::new();

        mock.expect_build_es_client()
            .returning(|_| Err(MacosError::Subscribe("EPERM".to_string())));

        let result = setup_sandbox(&mock, &default_policy(), 9999, true);
        assert!(matches!(result, Err(MacosError::Subscribe(_))));
    }

    // -- activate_monitor propagates its errors ------------------------------

    #[test]
    fn test_setup_sandbox_propagates_monitor_panic_error() {
        let mut mock = MockSandboxBackend::new();

        mock.expect_build_es_client()
            .returning(|_| Ok(EsClientBuilt::dummy()));

        mock.expect_activate_monitor()
            .returning(|_, _| Err(MacosError::MonitorPanicked("thread died".to_string())));

        let result = setup_sandbox(&mock, &default_policy(), 42, false);
        assert!(matches!(result, Err(MacosError::MonitorPanicked(_))));
    }

    // -- Policy is forwarded to build_es_client ------------------------------

    #[test]
    fn test_setup_sandbox_passes_policy_to_build() {
        let mut mock = MockSandboxBackend::new();
        let policy = FilesystemPolicy {
            allow_read: vec!["/tmp".into()],
            ..FilesystemPolicy::default()
        };

        mock.expect_build_es_client()
            .withf(|p| p.allow_read == vec![std::path::PathBuf::from("/tmp")])
            .times(1)
            .returning(|_| Ok(EsClientBuilt::dummy()));

        mock.expect_activate_monitor()
            .returning(|_, _| Ok(EsMonitorActive::dummy()));

        let _ = setup_sandbox(&mock, &policy, 1, false);
    }

    // -- agent_pid is forwarded to activate_monitor --------------------------

    #[test]
    fn test_setup_sandbox_passes_agent_pid_to_activate() {
        let mut mock = MockSandboxBackend::new();

        mock.expect_build_es_client()
            .returning(|_| Ok(EsClientBuilt::dummy()));

        mock.expect_activate_monitor()
            .withf(|_, pid| *pid == 5678)
            .times(1)
            .returning(|_, _| Ok(EsMonitorActive::dummy()));

        let result = setup_sandbox(&mock, &default_policy(), 5678, false);
        assert!(result.is_ok());
    }
}
