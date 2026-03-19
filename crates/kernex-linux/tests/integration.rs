//! Integration tests that make real Landlock and seccomp kernel calls.
//!
//! These tests require a Linux kernel with Landlock support (5.13+) and must
//! be run with the `kernel-integration-tests` feature:
//!
//! ```sh
//! cargo test -p kernex-linux --features kernel-integration-tests
//! ```
//!
//! They are intentionally excluded from the default `cargo test` run because
//! applying `restrict_self()` and seccomp in a test process is irreversible
//! and would affect the entire test binary.

#![cfg(all(target_os = "linux", feature = "kernel-integration-tests"))]

use kernex_linux::backend::{setup_sandbox, LinuxSandboxBackend};
use kernex_policy::FilesystemPolicy;
use tempfile::tempdir;

/// Verifies that `setup_sandbox` with a real backend and an empty policy
/// completes without error.
///
/// # WARNING
///
/// After this test runs, the calling process is sandboxed. The test runner
/// process must not rely on filesystem or syscall access that is now blocked.
/// Run this test in isolation with `cargo test -- --test-threads=1`.
#[test]
fn test_real_setup_sandbox_empty_policy_succeeds() {
    let backend = LinuxSandboxBackend;
    let policy = FilesystemPolicy::default();
    let result = setup_sandbox(&backend, &policy, false);
    assert!(
        result.is_ok(),
        "setup_sandbox failed on real kernel: {:?}",
        result.err()
    );
}

/// Verifies that a policy granting read access to `/tmp` builds successfully.
#[test]
fn test_real_setup_sandbox_with_tmp_read_policy() {
    let dir = tempdir().unwrap();
    let backend = LinuxSandboxBackend;
    let policy = FilesystemPolicy {
        allow_read: vec![dir.path().to_path_buf()],
        ..FilesystemPolicy::default()
    };
    let result = setup_sandbox(&backend, &policy, false);
    assert!(result.is_ok());
}
