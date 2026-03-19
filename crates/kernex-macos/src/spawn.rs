use std::fmt;

use crate::error::MacosError;

// ---------------------------------------------------------------------------
// EsClientBuilt — intermediate state: client prepared, PID not yet assigned
// ---------------------------------------------------------------------------

/// A prepared Endpoint Security client with event subscriptions active but
/// not yet scoped to a specific agent PID.
///
/// Analogous to [`kernex_linux::LandlockBuilt`]: holds the built enforcement
/// context before it is activated. Consuming it via
/// [`crate::backend::SandboxBackend::activate_monitor`] locks monitoring to
/// the agent PID.
///
/// # Test support
///
/// [`EsClientBuilt::dummy`] creates a no-op instance for use in mock tests.
/// The real implementation stores a closure that activates the ES client for
/// the given PID.
pub struct EsClientBuilt {
    /// Activation closure: stores the ES handle and activates monitoring for
    /// the given agent PID when called. Stored as a trait object so the
    /// concrete `EsHandle` type is hidden behind the public API.
    ///
    /// Read by `MacosSandboxBackend::activate_monitor` on macOS. On other
    /// platforms only the mock tests exercise this field via `dummy()`.
    #[cfg_attr(not(target_os = "macos"), allow(dead_code))]
    pub(crate) activate: Box<dyn FnOnce(u32) -> Result<EsMonitorActive, MacosError> + Send>,
}

impl EsClientBuilt {
    /// Creates a no-op `EsClientBuilt` for use in mock tests.
    ///
    /// Calling the inner activation closure succeeds immediately without
    /// making any Endpoint Security API calls.
    #[cfg(test)]
    pub(crate) fn dummy() -> Self {
        Self {
            activate: Box::new(|_pid| Ok(EsMonitorActive::dummy())),
        }
    }
}

impl fmt::Debug for EsClientBuilt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EsClientBuilt").finish_non_exhaustive()
    }
}

// ---------------------------------------------------------------------------
// EsMonitorActive — proof that ES monitoring is live for the agent PID
// ---------------------------------------------------------------------------

/// Proof that Endpoint Security monitoring is active for the agent process.
///
/// Created only by consuming [`EsClientBuilt`] via
/// [`crate::backend::SandboxBackend::activate_monitor`]. Keeping this value
/// alive keeps the ES client running. Dropping it signals the ES client to
/// stop (the client's destructor calls `es_delete_client()`).
///
/// # Thread safety
///
/// `EsMonitorActive` is `Send` but not `Sync`. It must not be cloned.
pub struct EsMonitorActive {
    /// On macOS: `Box<EsHandle>` keeping the ES client and audit thread alive.
    /// In tests / non-macOS builds: `Box<()>` as a zero-cost sentinel.
    ///
    /// The `Box<dyn Any + Send>` indirection hides the concrete `EsHandle`
    /// type so that `EsMonitorActive` can be used in cross-platform code and
    /// mock tests without exposing macOS-specific types.
    _guard: Box<dyn std::any::Any + Send>,
}

impl EsMonitorActive {
    /// Wrap an `EsHandle` (macOS production path).
    #[cfg(target_os = "macos")]
    pub(crate) fn from_handle(handle: crate::es_client::EsHandle) -> Self {
        Self {
            _guard: Box::new(handle),
        }
    }

    /// Create a no-op sentinel for use in mock tests and non-macOS builds.
    #[cfg(test)]
    pub(crate) fn dummy() -> Self {
        Self {
            _guard: Box::new(()),
        }
    }
}

impl fmt::Debug for EsMonitorActive {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EsMonitorActive").finish_non_exhaustive()
    }
}

// ---------------------------------------------------------------------------
// MacosSandboxReady — outcome of setup_sandbox
// ---------------------------------------------------------------------------

/// The result of a successful `setup_sandbox` call on macOS.
///
/// Unlike the Linux analog, macOS degradation (`Degraded`) means **no**
/// enforcement is active — the Endpoint Security API has no partial mode.
/// Degradation only occurs when `strict = false` and the ES entitlement is
/// missing.
#[derive(Debug)]
pub enum MacosSandboxReady {
    /// ES enforcement is fully active: the client is monitoring the agent PID.
    Full(EsMonitorActive),

    /// ES entitlement is missing. No enforcement is active.
    ///
    /// Only possible when `strict = false`.
    Degraded,
}

impl MacosSandboxReady {
    /// Returns `true` if full ES enforcement is active.
    pub fn is_full(&self) -> bool {
        matches!(self, Self::Full(_))
    }

    /// Returns `true` if enforcement is unavailable (entitlement missing).
    pub fn is_degraded(&self) -> bool {
        matches!(self, Self::Degraded)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_es_client_built_dummy_activates_successfully() {
        let built = EsClientBuilt::dummy();
        let result = (built.activate)(1234);
        assert!(result.is_ok());
    }

    #[test]
    fn test_es_client_built_debug_does_not_panic() {
        let built = EsClientBuilt::dummy();
        let _ = format!("{:?}", built);
    }

    #[test]
    fn test_es_monitor_active_dummy_is_constructible() {
        let _ = EsMonitorActive::dummy();
    }

    #[test]
    fn test_es_monitor_active_debug_does_not_panic() {
        let _ = format!("{:?}", EsMonitorActive::dummy());
    }

    #[test]
    fn test_sandbox_ready_full_is_full() {
        let ready = MacosSandboxReady::Full(EsMonitorActive::dummy());
        assert!(ready.is_full());
        assert!(!ready.is_degraded());
    }

    #[test]
    fn test_sandbox_ready_degraded_is_degraded() {
        let ready = MacosSandboxReady::Degraded;
        assert!(ready.is_degraded());
        assert!(!ready.is_full());
    }

    #[test]
    fn test_sandbox_ready_debug_does_not_panic() {
        let _ = format!("{:?}", MacosSandboxReady::Degraded);
    }
}
