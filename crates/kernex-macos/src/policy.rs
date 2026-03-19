//! Fast in-memory policy evaluator for Endpoint Security AUTH events.
//!
//! [`PolicyEvaluator`] is pre-built from [`FilesystemPolicy`] at ES client
//! creation time and shared across event handler invocations via `Arc`.
//! All evaluation is O(n) path-prefix matching with no I/O or locking,
//! making it safe to call from the hot-path ES event handler.

use std::path::{Component, Path, PathBuf};

use kernex_policy::FilesystemPolicy;

/// Fast in-memory policy evaluator for Endpoint Security AUTH events.
///
/// Pre-built at client creation time from [`FilesystemPolicy`]. Evaluation
/// is a simple path-prefix scan with no I/O, no heap allocation, and no
/// synchronisation — safe to call from the ES framework's event callback
/// thread.
///
/// # Thread safety
///
/// `PolicyEvaluator` is `Send + Sync`. It is shared between the ES event
/// handler (called by the framework thread) and the audit thread via `Arc`.
///
/// On non-macOS platforms this struct is compiled so that the unit tests in
/// this module run on Linux CI without macOS API dependencies.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
pub(crate) struct PolicyEvaluator {
    /// Paths that the agent may read.
    allow_read: Vec<PathBuf>,
    /// Paths that the agent may write; these are also implicitly readable.
    allow_write: Vec<PathBuf>,
    /// When `true`, any path component beginning with `.` is always denied.
    block_hidden: bool,
}

#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
impl PolicyEvaluator {
    /// Build an evaluator from a [`FilesystemPolicy`].
    pub(crate) fn from_policy(policy: &FilesystemPolicy) -> Self {
        Self {
            allow_read: policy.allow_read.clone(),
            allow_write: policy.allow_write.clone(),
            block_hidden: policy.block_hidden,
        }
    }

    /// Returns `true` if a read-only open of `path` is permitted.
    ///
    /// Write-allowed paths are implicitly readable (consistent with the Linux
    /// Landlock adapter which grants `AccessFs::from_all` for write paths).
    pub(crate) fn allows_read(&self, path: &Path) -> bool {
        if self.block_hidden && is_hidden_path(path) {
            return false;
        }
        self.allow_read.iter().any(|p| path.starts_with(p))
            || self.allow_write.iter().any(|p| path.starts_with(p))
    }

    /// Returns `true` if a write, create, rename, or unlink of `path` is
    /// permitted.
    pub(crate) fn allows_write(&self, path: &Path) -> bool {
        if self.block_hidden && is_hidden_path(path) {
            return false;
        }
        self.allow_write.iter().any(|p| path.starts_with(p))
    }
}

#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
/// Returns `true` if any [`Component::Normal`] in `path` starts with `.`.
///
/// The special components `.` (current dir) and `..` (parent dir) are not
/// considered hidden. Only named components beginning with `.` are.
pub(crate) fn is_hidden_path(path: &Path) -> bool {
    path.components().any(|c| {
        if let Component::Normal(name) = c {
            name.to_str().is_some_and(|s| s.starts_with('.'))
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

    fn make_evaluator(reads: &[&str], writes: &[&str], block_hidden: bool) -> PolicyEvaluator {
        PolicyEvaluator {
            allow_read: reads.iter().map(PathBuf::from).collect(),
            allow_write: writes.iter().map(PathBuf::from).collect(),
            block_hidden,
        }
    }

    // -- allows_read ----------------------------------------------------------

    #[test]
    fn test_allows_read_within_allowed_path() {
        let pe = make_evaluator(&["/data"], &[], true);
        assert!(pe.allows_read(Path::new("/data/file.csv")));
    }

    #[test]
    fn test_allows_read_outside_allowed_path_is_denied() {
        let pe = make_evaluator(&["/data"], &[], true);
        assert!(!pe.allows_read(Path::new("/etc/passwd")));
    }

    #[test]
    fn test_allows_read_exact_prefix_match() {
        let pe = make_evaluator(&["/data"], &[], true);
        assert!(pe.allows_read(Path::new("/data")));
    }

    #[test]
    fn test_allows_read_does_not_allow_sibling_directory() {
        // "/dat" must not match the "/data" prefix.
        let pe = make_evaluator(&["/data"], &[], true);
        assert!(!pe.allows_read(Path::new("/dat/file.csv")));
    }

    #[test]
    fn test_write_paths_are_implicitly_readable() {
        // Paths in allow_write must also pass the read check.
        let pe = make_evaluator(&[], &["/output"], true);
        assert!(pe.allows_read(Path::new("/output/result.json")));
    }

    // -- allows_write ---------------------------------------------------------

    #[test]
    fn test_allows_write_within_allowed_path() {
        let pe = make_evaluator(&[], &["/output"], true);
        assert!(pe.allows_write(Path::new("/output/result.json")));
    }

    #[test]
    fn test_allows_write_read_only_path_is_denied() {
        // allow_read paths do not grant write access.
        let pe = make_evaluator(&["/data"], &[], true);
        assert!(!pe.allows_write(Path::new("/data/file.csv")));
    }

    // -- block_hidden ---------------------------------------------------------

    #[test]
    fn test_block_hidden_true_blocks_dot_ssh() {
        let pe = make_evaluator(&["/home/user"], &[], true);
        assert!(!pe.allows_read(Path::new("/home/user/.ssh/id_rsa")));
    }

    #[test]
    fn test_block_hidden_false_allows_dot_ssh() {
        let pe = make_evaluator(&["/home/user"], &[], false);
        assert!(pe.allows_read(Path::new("/home/user/.ssh/id_rsa")));
    }

    #[test]
    fn test_block_hidden_blocks_write_to_hidden_dir() {
        let pe = make_evaluator(&[], &["/home/user"], true);
        assert!(!pe.allows_write(Path::new("/home/user/.aws/credentials")));
    }

    // -- is_hidden_path -------------------------------------------------------

    #[test]
    fn test_dot_alone_component_is_not_hidden() {
        // "." is the current directory, not a hidden file.
        assert!(!is_hidden_path(Path::new("./src/main.rs")));
    }

    #[test]
    fn test_dotdot_component_is_not_hidden() {
        assert!(!is_hidden_path(Path::new("../other/file")));
    }

    #[test]
    fn test_leading_dot_file_is_hidden() {
        assert!(is_hidden_path(Path::new("/home/user/.bashrc")));
    }

    #[test]
    fn test_hidden_directory_in_middle_of_path_is_detected() {
        assert!(is_hidden_path(Path::new("/home/.secret/file.txt")));
    }

    #[test]
    fn test_path_with_no_hidden_components_is_not_hidden() {
        assert!(!is_hidden_path(Path::new("/usr/local/bin/agent")));
    }

    #[test]
    fn test_empty_path_is_not_hidden() {
        assert!(!is_hidden_path(Path::new("")));
    }
}
