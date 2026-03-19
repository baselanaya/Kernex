use std::path::PathBuf;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum PolicyError {
    #[error("YAML parse error: {0}")]
    ParseError(#[from] serde_yaml::Error),

    #[error("missing required field: {0}")]
    MissingField(String),

    #[error("validation error: {0}")]
    ValidationError(String),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

/// A non-fatal warning surfaced to the user. Does not prevent the policy
/// from being applied, but should always be shown in `kernex status`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicyWarning {
    /// `filesystem.allow_read` contains `/` — grants full root read access.
    RootReadAccess,
    /// `filesystem.allow_read` contains an absolute path.
    AbsoluteReadPath(PathBuf),
    /// An `allow_write` path is not covered by any `allow_read` entry.
    WriteOutsideReadScope { write_path: PathBuf },
    /// `filesystem.block_hidden` is `false` but `allow_hidden_reason` is absent.
    BlockHiddenDisabledWithoutReason,
    /// A path matches a known sensitive pattern (e.g. `~/.ssh`, `/etc/shadow`).
    SensitivePath(PathBuf),
    /// An environment variable name matches a known sensitive pattern.
    SensitiveEnvVar(String),
    /// A network rule has no `max_requests_per_minute` rate limit.
    NoRateLimit { host: String },
}

/// Returned by a successful `KernexPolicy::validate()` call.
/// Contains zero or more non-fatal warnings that should be surfaced to the user.
#[derive(Debug, Default, Clone)]
pub struct ValidationReport {
    pub warnings: Vec<PolicyWarning>,
}

impl ValidationReport {
    pub fn is_clean(&self) -> bool {
        self.warnings.is_empty()
    }
}
