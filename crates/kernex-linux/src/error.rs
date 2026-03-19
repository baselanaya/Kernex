use std::path::PathBuf;
use thiserror::Error;

/// Errors from Landlock ruleset construction and enforcement.
#[derive(Debug, Error)]
pub enum LandlockError {
    /// The running kernel does not support Landlock LSM.
    #[error("Landlock is not supported by this kernel")]
    NotSupported,

    /// `landlock_restrict_self()` returned `E2BIG`: the process already has 16
    /// stacked rulesets and cannot accept another layer.
    ///
    /// In non-strict mode, `kernex` degrades to seccomp-only enforcement.
    /// In strict mode (`--strict`), this error causes an immediate abort.
    #[error(
        "Landlock ruleset depth limit exceeded (max 16 layers); \
         use --strict to abort or omit it to fall back to seccomp-only enforcement"
    )]
    DepthLimitExceeded,

    /// `landlock_create_ruleset()` or `landlock_add_rule()` failed.
    #[error("failed to build Landlock ruleset: {0}")]
    RulesetCreate(String),

    /// `landlock_add_rule()` failed for a specific path.
    #[error("failed to add Landlock rule for {path}: {reason}")]
    RuleAdd { path: PathBuf, reason: String },

    /// `landlock_restrict_self()` failed for a reason other than `E2BIG`.
    #[error("failed to apply Landlock ruleset (restrict_self): {0}")]
    RestrictSelf(String),
}

/// Errors from seccomp BPF filter construction and installation.
#[derive(Debug, Error)]
pub enum SeccompError {
    /// The BPF filter could not be compiled into a valid BPF program.
    #[error("failed to compile seccomp BPF filter: {0}")]
    CompileError(String),

    /// `prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, ...)` failed.
    #[error("failed to install seccomp BPF filter: {0}")]
    InstallError(String),
}

/// Top-level error type for `kernex-linux`.
#[derive(Debug, Error)]
pub enum LinuxError {
    /// A Landlock operation failed.
    #[error("Landlock enforcement failed: {0}")]
    Landlock(#[from] LandlockError),

    /// A seccomp operation failed.
    #[error("seccomp enforcement failed: {0}")]
    Seccomp(#[from] SeccompError),

    /// An I/O error during sandbox setup (e.g. reading `/proc/self/fd`).
    #[error("I/O error during sandbox setup: {0}")]
    Io(#[from] std::io::Error),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_landlock_error_depth_limit_has_meaningful_message() {
        let msg = LandlockError::DepthLimitExceeded.to_string();
        assert!(msg.contains("depth limit") || msg.contains("16"));
    }

    #[test]
    fn test_landlock_error_rule_add_includes_path() {
        let err = LandlockError::RuleAdd {
            path: PathBuf::from("/tmp/test"),
            reason: "kernel rejected".into(),
        };
        let msg = err.to_string();
        assert!(msg.contains("/tmp/test"));
        assert!(msg.contains("kernel rejected"));
    }

    #[test]
    fn test_seccomp_error_compile_has_message() {
        let err = SeccompError::CompileError("invalid BPF".into());
        assert!(err.to_string().contains("invalid BPF"));
    }

    #[test]
    fn test_linux_error_from_landlock() {
        let err: LinuxError = LandlockError::NotSupported.into();
        assert!(matches!(
            err,
            LinuxError::Landlock(LandlockError::NotSupported)
        ));
    }

    #[test]
    fn test_linux_error_from_seccomp() {
        let err: LinuxError = SeccompError::InstallError("prctl failed".into()).into();
        assert!(matches!(err, LinuxError::Seccomp(_)));
    }
}
