//! macOS sandbox adapter — Endpoint Security API enforcement for Kernex.
//!
//! # Status: Beta
//!
//! This crate is marked **beta** in `Cargo.toml` metadata. It requires:
//!
//! - macOS 10.15 (Catalina) or later.
//! - The `com.apple.developer.endpoint-security.client` entitlement.
//!   Without it, `build_es_client` returns [`MacosError::EntitlementMissing`].
//!
//! # Architecture
//!
//! macOS enforcement via the Endpoint Security API differs from Linux
//! Landlock + seccomp. On Linux, enforcement is applied inside the child
//! process before the agent image is loaded. On macOS, enforcement is
//! external: Kernex registers an ES client and the framework delivers AUTH
//! events for the monitored agent PID. The event handler evaluates each
//! event against `FilesystemPolicy` and responds allow/deny.
//!
//! # Event handling
//!
//! The ES framework calls the handler synchronously — the agent process is
//! blocked until `respond_auth_result` returns. The handler must complete
//! within the ~30 second kernel deadline; failure causes fail-open, which is
//! a security regression.
//!
//! Timely responses are guaranteed by:
//! 1. O(n) in-memory path-prefix matching with no I/O.
//! 2. A pre-warmed audit thread for async logging — no thread creation on
//!    the hot path.
//!
//! # Graceful degradation
//!
//! If the ES entitlement is missing and `strict = false`, `setup_sandbox`
//! degrades to unprotected execution with a warning. In `--strict` mode,
//! `MacosError::EntitlementMissing` propagates to the caller.

pub mod backend;
pub mod error;
pub mod spawn;

// The policy evaluator has no macOS-specific deps and is compiled on all
// platforms so that policy unit tests run on Linux CI as well.
pub(crate) mod policy;

// The ES client implementation depends on the `endpoint-sec` crate which is
// only available on macOS.
#[cfg(target_os = "macos")]
pub(crate) mod es_client;

pub use backend::{setup_sandbox, SandboxBackend};
pub use error::MacosError;
pub use spawn::{EsClientBuilt, EsMonitorActive, MacosSandboxReady};

/// The production [`SandboxBackend`] implementation (macOS only).
///
/// Makes real Endpoint Security API calls. Requires the
/// `com.apple.developer.endpoint-security.client` entitlement.
#[cfg(target_os = "macos")]
pub use backend::MacosSandboxBackend;
