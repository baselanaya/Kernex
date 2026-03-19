//! Platform-agnostic policy enforcement orchestration for Kernex.
//!
//! # Architecture
//!
//! This crate contains no `#[cfg(target_os)]` directives. All OS-specific code
//! lives in `kernex-linux` or `kernex-macos`, which implement [`SandboxBackend`]
//! and pass it into [`run_session`] at startup.
//!
//! # Session lifecycle
//!
//! ```ignore
//! // 1. Load and validate the policy.
//! let policy = KernexPolicy::from_file(path)?;
//! policy.validate()?;
//!
//! // 2. Set up OS enforcement (platform-specific crate provides backend).
//! let backend = LinuxSandboxBackend::new(); // or macOS equivalent
//!
//! // 3. Run the enforcement loop over the IPC connection.
//! run_session(&backend, &mut conn, policy, strict).await?;
//! ```

pub mod backend;
pub mod dedupe;
pub mod error;
pub mod evaluator;
pub mod runner;
pub mod session;

pub use backend::SandboxBackend;
pub use error::CoreError;
pub use evaluator::{evaluate, EvalVerdict, EvaluationResult};
pub use runner::{run_session, JIT_TIMEOUT_SECS};
pub use session::{EnforcementSession, QueryOutcome};
