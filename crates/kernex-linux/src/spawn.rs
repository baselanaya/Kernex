use std::fmt;

use crate::error::LandlockError;

// ---------------------------------------------------------------------------
// Marker types — type-system enforcement of sandbox setup ordering
// ---------------------------------------------------------------------------

/// Proof that the Landlock filesystem ruleset has been applied and
/// `landlock_restrict_self()` has been called on the current process.
///
/// # Ordering invariant
///
/// This type is only produced by [`LandlockBuilt::restrict_self`].
/// `LandlockBuilt` is only produced by [`crate::backend::SandboxBackend::build_landlock_ruleset`].
/// Therefore, a `LandlockApplied` value is proof that the correct Landlock
/// sequence has been completed.
#[derive(Debug)]
pub struct LandlockApplied(());

impl LandlockApplied {
    /// Construct the marker. Only callable within this crate.
    pub(crate) fn new() -> Self {
        Self(())
    }
}

/// Proof that a seccomp BPF filter has been installed via
/// `prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, ...)`.
///
/// # Ordering invariant
///
/// This type is only produced by [`crate::backend::SandboxBackend::apply_seccomp`].
/// Therefore, a `SeccompApplied` value is proof that the seccomp filter is active.
#[derive(Debug)]
pub struct SeccompApplied(());

impl SeccompApplied {
    /// Construct the marker. Only callable within this crate.
    pub(crate) fn new() -> Self {
        Self(())
    }
}

// ---------------------------------------------------------------------------
// LandlockBuilt — intermediate state between ruleset build and restrict_self
// ---------------------------------------------------------------------------

/// A Landlock ruleset that has been fully built (paths added) but not yet
/// applied via `restrict_self()`.
///
/// Holding this separately from [`LandlockApplied`] lets `setup_sandbox` insert
/// the seccomp filter installation between the two Landlock steps, matching
/// the required kernel ordering:
///
/// 1. Build Landlock ruleset          → [`LandlockBuilt`]
/// 2. Install seccomp BPF filter      → [`SeccompApplied`]
/// 3. `restrict_self()` (lock Landlock) → [`LandlockApplied`]
/// 4. `execve()`
///
/// # Test support
///
/// [`LandlockBuilt::dummy`] creates a no-op instance for use in mock tests.
/// The real implementation stores a closure that calls `landlock_restrict_self()`.
pub struct LandlockBuilt {
    /// Closure that calls `landlock_restrict_self()` (or is a no-op in tests).
    pub(crate) restrict: Box<dyn FnOnce() -> Result<(), LandlockError> + Send>,
}

impl LandlockBuilt {
    /// Invoke `restrict_self()`, locking this process into the Landlock ruleset.
    ///
    /// Returns [`LandlockApplied`] on success, proving enforcement is active.
    ///
    /// # Errors
    ///
    /// Returns [`LandlockError::DepthLimitExceeded`] if the kernel returns `E2BIG`
    /// (16 rulesets already stacked). The caller should handle this for graceful
    /// degradation.
    pub(crate) fn restrict_self(self) -> Result<LandlockApplied, LandlockError> {
        (self.restrict)()?;
        Ok(LandlockApplied::new())
    }

    /// Creates a no-op `LandlockBuilt` for use in mock tests.
    ///
    /// Calling `restrict_self()` on a dummy instance succeeds immediately
    /// without making any kernel calls.
    #[cfg(test)]
    pub(crate) fn dummy() -> Self {
        Self {
            restrict: Box::new(|| Ok(())),
        }
    }
}

impl fmt::Debug for LandlockBuilt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LandlockBuilt").finish_non_exhaustive()
    }
}

// ---------------------------------------------------------------------------
// SandboxedSpawn — type-safe spawn handle requiring full enforcement
// ---------------------------------------------------------------------------

/// A spawn handle that proves both Landlock and seccomp enforcement have been
/// fully applied to the current process.
///
/// # Type-system enforcement of ordering
///
/// `SandboxedSpawn::new` requires *both* [`LandlockApplied`] and
/// [`SeccompApplied`]. Those types are only produced by successful kernel
/// calls. This makes it impossible — at the type level — to reach the exec
/// point without completing both enforcement layers in the correct order.
///
/// # Expected usage
///
/// ```ignore
/// let built   = backend.build_landlock_ruleset(&policy)?;  // step 1
/// let seccomp = backend.apply_seccomp()?;                  // step 2
/// let landlock = built.restrict_self()?;                   // step 3
/// let spawn = SandboxedSpawn::new(landlock, seccomp);
/// // exec the agent process here
/// ```
#[derive(Debug)]
pub struct SandboxedSpawn {
    _landlock: LandlockApplied,
    _seccomp: SeccompApplied,
}

impl SandboxedSpawn {
    /// Construct the spawn handle.
    ///
    /// Both markers must have been produced by successful kernel calls:
    /// - `LandlockApplied` from `LandlockBuilt::restrict_self()`
    /// - `SeccompApplied` from `SandboxBackend::apply_seccomp()`
    pub fn new(landlock: LandlockApplied, seccomp: SeccompApplied) -> Self {
        Self {
            _landlock: landlock,
            _seccomp: seccomp,
        }
    }
}

// ---------------------------------------------------------------------------
// SandboxReady — outcome of setup_sandbox, communicates enforcement level
// ---------------------------------------------------------------------------

/// The result of a successful `setup_sandbox` call.
///
/// The variant communicates the active enforcement level so that callers can
/// surface an appropriate warning in degraded mode.
#[derive(Debug)]
pub enum SandboxReady {
    /// Both Landlock and seccomp are fully enforced.
    Full(SandboxedSpawn),

    /// Landlock was skipped because the process hit the 16-ruleset depth limit.
    /// Seccomp is still active. Only possible when `strict = false`.
    SeccompOnly(SeccompApplied),
}

impl SandboxReady {
    /// Returns `true` if full enforcement (Landlock + seccomp) is active.
    pub fn is_full(&self) -> bool {
        matches!(self, Self::Full(_))
    }

    /// Returns `true` if enforcement degraded to seccomp-only.
    pub fn is_degraded(&self) -> bool {
        matches!(self, Self::SeccompOnly(_))
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -- LandlockApplied / SeccompApplied ------------------------------------

    #[test]
    fn test_landlock_applied_is_constructible() {
        let _ = LandlockApplied::new();
    }

    #[test]
    fn test_seccomp_applied_is_constructible() {
        let _ = SeccompApplied::new();
    }

    // -- LandlockBuilt -------------------------------------------------------

    #[test]
    fn test_landlock_built_dummy_restrict_self_succeeds() {
        let built = LandlockBuilt::dummy();
        let result = built.restrict_self();
        assert!(result.is_ok());
    }

    #[test]
    fn test_landlock_built_failing_restrict_self_propagates_error() {
        let built = LandlockBuilt {
            restrict: Box::new(|| Err(LandlockError::DepthLimitExceeded)),
        };
        let err = built.restrict_self().unwrap_err();
        assert!(matches!(err, LandlockError::DepthLimitExceeded));
    }

    #[test]
    fn test_landlock_built_debug_does_not_panic() {
        let built = LandlockBuilt::dummy();
        let _ = format!("{:?}", built);
    }

    // -- SandboxedSpawn ------------------------------------------------------

    #[test]
    fn test_sandboxed_spawn_requires_both_markers() {
        // This test proves the constructor compiles only with both markers.
        let landlock = LandlockApplied::new();
        let seccomp = SeccompApplied::new();
        let spawn = SandboxedSpawn::new(landlock, seccomp);
        let _ = format!("{:?}", spawn);
    }

    // -- SandboxReady --------------------------------------------------------

    #[test]
    fn test_sandbox_ready_full_is_full() {
        let landlock = LandlockApplied::new();
        let seccomp = SeccompApplied::new();
        let ready = SandboxReady::Full(SandboxedSpawn::new(landlock, seccomp));
        assert!(ready.is_full());
        assert!(!ready.is_degraded());
    }

    #[test]
    fn test_sandbox_ready_seccomp_only_is_degraded() {
        let ready = SandboxReady::SeccompOnly(SeccompApplied::new());
        assert!(ready.is_degraded());
        assert!(!ready.is_full());
    }

    #[test]
    fn test_sandbox_ready_debug_does_not_panic() {
        let ready = SandboxReady::SeccompOnly(SeccompApplied::new());
        let _ = format!("{:?}", ready);
    }
}
