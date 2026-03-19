//! Kernex audit mode — observation, sensitive-path detection, and policy generation.
//!
//! # Overview
//!
//! `kernex-audit` provides the data pipeline for `kernex audit -- <cmd>`:
//!
//! 1. **Record**: the platform adapter (`kernex-linux` / `kernex-macos`) calls
//!    [`AuditSession::record`] for every file access, network call, and env var
//!    read the agent makes. No enforcement happens; the agent runs freely.
//!
//! 2. **Finish**: on agent exit, [`AuditSession::finish`] produces a
//!    [`PolicyCandidate`] with deduplicated observations and
//!    [`SensitiveWarning`]s for any credential-adjacent resources accessed.
//!
//! 3. **Merge** *(optional)*: call [`merge`] to accumulate observations from
//!    multiple audit sessions. Resources seen in more sessions receive higher
//!    `sessions_seen` counts and `confidence` scores.
//!
//! 4. **Convert** *(in `kernex-cli`)*: the CLI converts the final
//!    `PolicyCandidate` into a `KernexPolicy` and writes `kernex.yaml`, after
//!    presenting any [`SensitiveWarning`]s to the user for explicit approval.
//!
//! # Sensitive path policy
//!
//! Resources matching the patterns in [`sensitive`] are **never silently
//! included** in [`PolicyCandidate::observations`]. They appear only in
//! [`PolicyCandidate::sensitive_warnings`]. The CLI must prompt the user
//! and require `--allow-sensitive` before writing them to `kernex.yaml`.

pub mod candidate;
pub mod error;
pub mod observation;
pub mod sensitive;
pub mod session;

pub use candidate::{merge, PolicyCandidate};
pub use error::AuditError;
pub use observation::{
    compute_confidence, AuditObservation, ObservedResource, SensitiveResource, SensitiveWarning,
    CONFIDENCE_PER_SESSION,
};
pub use session::{AuditEvent, AuditSession};
