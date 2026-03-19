//! Landlock LSM ruleset construction.
//!
//! # Security notes
//!
//! - `restrict_self()` is intentionally **not** called here. It is deferred
//!   to [`crate::spawn::LandlockBuilt::restrict_self`] so that the seccomp
//!   filter can be installed between ruleset build and restrict_self.
//! - Path rules are always checked for accessibility (via `PathFd`) before
//!   being added. An inaccessible path causes a hard error, not a silent skip.
//! - `block_hidden: true` denies all access to paths whose components begin
//!   with `.`. Landlock cannot directly express this; it is enforced by
//!   refusing to add allow-rules for hidden paths when `block_hidden` is set.

use kernex_policy::FilesystemPolicy;
use landlock::{
    Access, AccessFs, PathBeneath, PathFd, RestrictSelfError, Ruleset, RulesetAttr,
    RulesetCreatedAttr, RulesetError, ABI,
};

use crate::error::LandlockError;
use crate::spawn::LandlockBuilt;

/// Highest Landlock ABI we attempt to use. Falls back to lower ABIs on older
/// kernels thanks to the landlock crate's compatibility layer.
const TARGET_ABI: ABI = ABI::V3;

/// Errno value for `E2BIG` on Linux (too many stacked rulesets).
const E2BIG: i32 = 7;

/// Build a Landlock ruleset from `policy` and return a [`LandlockBuilt`]
/// whose `restrict_self` closure will lock the ruleset when called.
///
/// # Errors
///
/// - [`LandlockError::RulesetCreate`] — kernel rejected `landlock_create_ruleset`.
/// - [`LandlockError::RuleAdd`]       — a path could not be opened or added.
/// - [`LandlockError::DepthLimitExceeded`] — returned from `restrict_self` if
///   the process already has 16 stacked rulesets.
pub fn build_ruleset(policy: &FilesystemPolicy) -> Result<LandlockBuilt, LandlockError> {
    // Build the initial ruleset, declaring all access types we will use.
    let mut ruleset = Ruleset::default()
        .handle_access(AccessFs::from_all(TARGET_ABI))
        .map_err(ruleset_error)?
        .create()
        .map_err(ruleset_error)?;

    // Add read-only rules.
    for path in &policy.allow_read {
        // SECURITY: skip paths that start with '.' when block_hidden is set.
        if policy.block_hidden && is_hidden_path(path) {
            tracing::warn!(
                path = %path.display(),
                "skipping hidden path in allow_read because block_hidden = true"
            );
            continue;
        }

        let fd = PathFd::new(path).map_err(|e| LandlockError::RuleAdd {
            path: path.clone(),
            reason: e.to_string(),
        })?;

        ruleset = ruleset
            .add_rule(PathBeneath::new(fd, AccessFs::from_read(TARGET_ABI)))
            .map_err(|e: RulesetError| LandlockError::RuleAdd {
                path: path.clone(),
                reason: e.to_string(),
            })?;
    }

    // Add read+write rules (allow_write implies read access too).
    for path in &policy.allow_write {
        // SECURITY: same hidden-path guard.
        if policy.block_hidden && is_hidden_path(path) {
            tracing::warn!(
                path = %path.display(),
                "skipping hidden path in allow_write because block_hidden = true"
            );
            continue;
        }

        let fd = PathFd::new(path).map_err(|e| LandlockError::RuleAdd {
            path: path.clone(),
            reason: e.to_string(),
        })?;

        ruleset = ruleset
            .add_rule(PathBeneath::new(fd, AccessFs::from_all(TARGET_ABI)))
            .map_err(|e: RulesetError| LandlockError::RuleAdd {
                path: path.clone(),
                reason: e.to_string(),
            })?;
    }

    // Capture `ruleset` in the closure that will call restrict_self later.
    Ok(LandlockBuilt {
        restrict: Box::new(move || {
            ruleset.restrict_self().map_err(map_restrict_error)?;
            Ok(())
        }),
    })
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Map any `RulesetError` (not from `restrict_self`) into `LandlockError`.
fn ruleset_error(e: RulesetError) -> LandlockError {
    LandlockError::RulesetCreate(e.to_string())
}

/// Map a `restrict_self` error, detecting `E2BIG` for graceful degradation.
///
/// The landlock crate surfaces `E2BIG` as `RestrictSelfError::RestrictSelfCall`
/// with an `io::Error` whose `raw_os_error()` is `E2BIG` (7). We match
/// directly on the enum to avoid fragile string comparisons.
fn map_restrict_error(e: RulesetError) -> LandlockError {
    if let RulesetError::RestrictSelf(RestrictSelfError::RestrictSelfCall { ref source, .. }) = e {
        if source.raw_os_error() == Some(E2BIG) {
            return LandlockError::DepthLimitExceeded;
        }
    }
    LandlockError::RestrictSelf(e.to_string())
}

/// Returns `true` if any *normal* component of `path` starts with `.`.
///
/// The special components `.` (current dir) and `..` (parent dir) are not
/// considered hidden — only actual file/directory names like `.ssh` or `.aws`.
fn is_hidden_path(path: &std::path::Path) -> bool {
    use std::path::Component;
    path.components().any(|c| {
        if let Component::Normal(name) = c {
            name.to_str().map(|s| s.starts_with('.')).unwrap_or(false)
        } else {
            false
        }
    })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;
    use tempfile::tempdir;

    // -- is_hidden_path ------------------------------------------------------

    #[test]
    fn test_is_hidden_path_detects_dotfile() {
        assert!(is_hidden_path(Path::new("~/.ssh")));
    }

    #[test]
    fn test_is_hidden_path_detects_absolute_dotdir() {
        assert!(is_hidden_path(Path::new("/home/user/.aws")));
    }

    #[test]
    fn test_is_hidden_path_does_not_flag_normal_path() {
        assert!(!is_hidden_path(Path::new("/tmp/output.txt")));
    }

    #[test]
    fn test_is_hidden_path_does_not_flag_src() {
        assert!(!is_hidden_path(Path::new("./src/main.rs")));
    }

    #[test]
    fn test_is_hidden_path_flags_nested_dotdir() {
        assert!(is_hidden_path(Path::new("/home/user/.config/gh")));
    }

    // -- build_ruleset with real filesystem (requires Linux) -----------------

    /// Verifies that `build_ruleset` succeeds for a read-only policy pointing
    /// at a directory that exists. The returned `LandlockBuilt` closure is NOT
    /// invoked (no real `restrict_self` call in unit tests).
    #[cfg(target_os = "linux")]
    #[test]
    fn test_build_ruleset_accepts_existing_read_path() {
        let dir = tempdir().unwrap();
        let policy = FilesystemPolicy {
            allow_read: vec![dir.path().to_path_buf()],
            ..FilesystemPolicy::default()
        };
        // We only verify that build succeeds — we do not call restrict_self.
        let result = build_ruleset(&policy);
        assert!(result.is_ok(), "build_ruleset failed: {:?}", result.err());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_build_ruleset_accepts_existing_write_path() {
        let dir = tempdir().unwrap();
        let policy = FilesystemPolicy {
            allow_write: vec![dir.path().to_path_buf()],
            ..FilesystemPolicy::default()
        };
        let result = build_ruleset(&policy);
        assert!(result.is_ok());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_build_ruleset_skips_hidden_read_path_when_block_hidden() {
        // Even if a hidden path is in allow_read, block_hidden must suppress it.
        let policy = FilesystemPolicy {
            allow_read: vec![std::path::PathBuf::from("~/.ssh")],
            block_hidden: true,
            ..FilesystemPolicy::default()
        };
        // build_ruleset should succeed (skipping the hidden path), not error.
        let result = build_ruleset(&policy);
        assert!(result.is_ok());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_build_ruleset_empty_policy_succeeds() {
        let policy = FilesystemPolicy::default();
        let result = build_ruleset(&policy);
        assert!(result.is_ok());
    }
}
