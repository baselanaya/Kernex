//! Enforcement behaviour tests.
//!
//! Tests in this file verify that the kernel-level enforcement layers actually
//! restrict the sandboxed process. Tests are platform-gated: Linux tests
//! exercise real Landlock LSM enforcement; macOS tests exercise the
//! Endpoint Security path.
//!
//! # Landlock blocking tests (Linux)
//!
//! These tests verify that Landlock denies access to paths not in the policy.
//! The test sequence is:
//!
//! 1. Create a temporary file in a tempdir (inside /tmp by default).
//! 2. Run `kernex run -- cat <file>` with a policy that does NOT include the
//!    tempdir. Landlock blocks the open; `cat` exits nonzero; kernex propagates.
//! 3. Repeat with a policy that DOES include the tempdir. Access succeeds.
//!
//! # JIT prompt (session summary)
//!
//! The JIT prompt system (ptrace-based interception) is not yet implemented.
//! Enforcement today operates entirely at the kernel level via Landlock: the
//! process receives EACCES and the monitor process never sees the individual
//! event. The session summary therefore reports 0 blocks for kernel-level
//! denials. These tests document this current behaviour and will be updated
//! when ptrace interception is added.
//!
//! # --strict mode
//!
//! `--strict` aborts `kernex run` when enforcement cannot be fully applied.
//! On Linux, this means Landlock is unavailable. On this kernel (6.18+)
//! Landlock is available, so `--strict` with a valid policy succeeds.

use std::fs;

use kernex_integration_tests::{kernex_cmd, LINUX_EXEC_POLICY};

#[cfg(not(target_os = "linux"))]
use kernex_integration_tests::MINIMAL_POLICY;
use tempfile::tempdir;

// ---------------------------------------------------------------------------
// --strict mode
// ---------------------------------------------------------------------------

/// `--strict` succeeds and exits 0 when full enforcement is available.
///
/// On Linux with Landlock available (kernel ≥ 5.13), `--strict` must not
/// abort. On macOS without the ES entitlement, this test would need the
/// entitlement — it is excluded from macOS CI via the platform gate.
#[cfg(target_os = "linux")]
#[test]
fn test_strict_succeeds_when_enforcement_available() {
    let dir = tempdir().unwrap();
    let config = dir.path().join("kernex.yaml");
    fs::write(&config, LINUX_EXEC_POLICY).unwrap();

    let status = kernex_cmd(&config.to_string_lossy())
        .args(["--strict", "run", "--", "true"])
        .status()
        .expect("failed to spawn kernex");

    assert!(
        status.success(),
        "--strict should not abort when Landlock is available; got: {status}"
    );
}

/// With `--strict` and full enforcement active, the JSON output shows
/// `degraded: false`.
#[cfg(target_os = "linux")]
#[test]
fn test_strict_json_shows_not_degraded() {
    let dir = tempdir().unwrap();
    let config = dir.path().join("kernex.yaml");
    fs::write(&config, LINUX_EXEC_POLICY).unwrap();

    let output = kernex_cmd(&config.to_string_lossy())
        .args(["--strict", "--output=json", "run", "--", "true"])
        .output()
        .expect("failed to spawn kernex");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let json: serde_json::Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("JSON parse error: {e}\nstdout: {stdout:?}"));

    assert_eq!(
        json["enforcement"]["degraded"].as_bool(),
        Some(false),
        "expected degraded: false with --strict and Landlock available"
    );
}

// ---------------------------------------------------------------------------
// Landlock blocking (Linux)
// ---------------------------------------------------------------------------

/// Landlock denies access to a path not in the policy.
///
/// The policy allows system paths but excludes the tempdir. `cat` trying to
/// read a file in the tempdir gets EACCES from Landlock and exits nonzero.
/// kernex propagates the nonzero exit code.
#[cfg(target_os = "linux")]
#[test]
fn test_landlock_blocks_read_outside_policy() {
    let dir = tempdir().unwrap();
    let secret = dir.path().join("secret.txt");
    fs::write(&secret, "not allowed").unwrap();

    // Policy does NOT include dir.path() (which is inside /tmp typically).
    let config = dir.path().join("kernex.yaml");
    fs::write(&config, LINUX_EXEC_POLICY).unwrap();

    // `cat <secret>` should be blocked by Landlock.
    let status = kernex_cmd(&config.to_string_lossy())
        .args(["run", "--", "cat", &secret.to_string_lossy()])
        .status()
        .expect("failed to spawn kernex");

    assert!(
        !status.success(),
        "expected nonzero exit: Landlock should block read of path outside policy, got: {status}"
    );
}

/// Landlock allows access to a path that is in the policy.
///
/// Adds the tempdir to `allow_read`. `cat` can now read the file and exits 0.
///
/// Uses a non-hidden tempdir prefix (`kernex-test`) so that `block_hidden: true`
/// does not interfere — `tempfile`'s default `.tmp` prefix would itself be
/// blocked by the hidden-path rule.
#[cfg(target_os = "linux")]
#[test]
fn test_landlock_allows_read_inside_policy() {
    let dir = tempfile::Builder::new()
        .prefix("kernex-test")
        .tempdir()
        .unwrap();
    let allowed_file = dir.path().join("allowed.txt");
    fs::write(&allowed_file, "allowed content").unwrap();

    // Build the policy inline so `dir.path()` appears under allow_read
    // (not after block_hidden, which would produce invalid YAML).
    let policy = format!(
        "\
agent_name: test-agent
filesystem:
  allow_read:
    - /usr
    - /bin
    - /lib
    - /lib64
    - /lib32
    - /usr/lib
    - /etc
    - {dir}
  block_hidden: true
",
        dir = dir.path().display()
    );
    let config = dir.path().join("kernex.yaml");
    fs::write(&config, &policy).unwrap();

    let status = kernex_cmd(&config.to_string_lossy())
        .args(["run", "--", "cat", &allowed_file.to_string_lossy()])
        .status()
        .expect("failed to spawn kernex");

    assert!(
        status.success(),
        "expected zero exit: path is in allow_read, got: {status}"
    );
}

/// Landlock denies write access to a path not in `allow_write`.
///
/// The policy has an empty `allow_write`, so writing anywhere is blocked.
/// `sh -c 'echo x > <file>'` attempts a write and exits nonzero.
#[cfg(target_os = "linux")]
#[test]
fn test_landlock_blocks_write_outside_policy() {
    let dir = tempdir().unwrap();
    let target = dir.path().join("output.txt");

    // Policy has no allow_write — writing anywhere is forbidden.
    let config = dir.path().join("kernex.yaml");
    fs::write(&config, LINUX_EXEC_POLICY).unwrap();

    // sh writes to target; Landlock blocks open(O_WRONLY).
    let status = kernex_cmd(&config.to_string_lossy())
        .args([
            "run",
            "--",
            "sh",
            "-c",
            &format!("echo x > {}", target.display()),
        ])
        .status()
        .expect("failed to spawn kernex");

    assert!(
        !status.success(),
        "expected nonzero exit: write should be blocked by Landlock, got: {status}"
    );
}

/// Landlock allows write access to a path in `allow_write`.
///
/// Uses a non-hidden tempdir prefix (`kernex-test`) so that `block_hidden: true`
/// does not block the tempdir itself.
#[cfg(target_os = "linux")]
#[test]
fn test_landlock_allows_write_inside_policy() {
    let dir = tempfile::Builder::new()
        .prefix("kernex-test")
        .tempdir()
        .unwrap();
    let target = dir.path().join("output.txt");

    // Build policy that includes dir.path() in allow_write (also read).
    let policy = format!(
        "\
agent_name: test-agent
filesystem:
  allow_read:
    - /usr
    - /bin
    - /lib
    - /lib64
    - /lib32
    - /usr/lib
    - /etc
    - {dir}
  allow_write:
    - {dir}
  block_hidden: true
",
        dir = dir.path().display()
    );
    let config = dir.path().join("kernex.yaml");
    fs::write(&config, &policy).unwrap();

    let status = kernex_cmd(&config.to_string_lossy())
        .args([
            "run",
            "--",
            "sh",
            "-c",
            &format!("echo hello > {}", target.display()),
        ])
        .status()
        .expect("failed to spawn kernex");

    assert!(
        status.success(),
        "expected zero exit: write path is in allow_write, got: {status}"
    );
    assert!(target.exists(), "output.txt was not created");
}

// ---------------------------------------------------------------------------
// Session summary — JIT prompt status
// ---------------------------------------------------------------------------

/// After `kernex run` blocks an agent (via Landlock), the session summary is
/// still printed with 0 prompts shown — documenting that JIT prompts are not
/// yet implemented and blocking happens silently at the kernel level.
///
/// This test will be updated when ptrace-based interception is added.
#[cfg(target_os = "linux")]
#[test]
fn test_session_summary_shows_zero_prompts_after_kernel_block() {
    let dir = tempdir().unwrap();
    let secret = dir.path().join("secret.txt");
    fs::write(&secret, "blocked").unwrap();

    let config = dir.path().join("kernex.yaml");
    fs::write(&config, LINUX_EXEC_POLICY).unwrap();

    // The command exits nonzero (blocked by Landlock), but kernex still
    // outputs the session summary before propagating the exit code.
    let output = kernex_cmd(&config.to_string_lossy())
        .args(["run", "--", "cat", &secret.to_string_lossy()])
        .output()
        .expect("failed to spawn kernex");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("Session summary"),
        "expected 'Session summary' in stdout even after a block, got: {stdout:?}"
    );
    assert!(
        stdout.contains("0 prompted"),
        "expected '0 prompted' in session summary (JIT not yet implemented), got: {stdout:?}"
    );
}

/// JSON output after a Landlock block reports `total_blocks: 0` because
/// kernel-level denials are not yet reported back to the kernex process.
///
/// Documents current behaviour — will change when ptrace interception is added.
#[cfg(target_os = "linux")]
#[test]
fn test_json_summary_total_blocks_zero_after_kernel_block() {
    let dir = tempdir().unwrap();
    let secret = dir.path().join("secret.txt");
    fs::write(&secret, "blocked").unwrap();

    let config = dir.path().join("kernex.yaml");
    fs::write(&config, LINUX_EXEC_POLICY).unwrap();

    let output = kernex_cmd(&config.to_string_lossy())
        .args([
            "--output=json",
            "run",
            "--",
            "cat",
            &secret.to_string_lossy(),
        ])
        .output()
        .expect("failed to spawn kernex");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let json: serde_json::Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("JSON parse error: {e}\nstdout: {stdout:?}"));

    assert_eq!(
        json["summary"]["total_blocks"].as_u64(),
        Some(0),
        "expected total_blocks: 0 (kernel blocks not yet surfaced to kernex)"
    );
    assert_eq!(
        json["summary"]["prompts_shown"].as_u64(),
        Some(0),
        "expected prompts_shown: 0 (JIT not yet implemented)"
    );
}

// ---------------------------------------------------------------------------
// Linux JSON enforcement fields
// ---------------------------------------------------------------------------

/// On Linux, `enforcement.landlock` is true when Landlock is available.
#[cfg(target_os = "linux")]
#[test]
fn test_linux_json_landlock_true_when_available() {
    let dir = tempdir().unwrap();
    let config = dir.path().join("kernex.yaml");
    fs::write(&config, LINUX_EXEC_POLICY).unwrap();

    let output = kernex_cmd(&config.to_string_lossy())
        .args(["--output=json", "run", "--", "true"])
        .output()
        .expect("failed to spawn kernex");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let json: serde_json::Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("JSON parse error: {e}\nstdout: {stdout:?}"));

    assert_eq!(
        json["enforcement"]["landlock"].as_bool(),
        Some(true),
        "expected landlock: true on Linux with Landlock-capable kernel"
    );
    assert_eq!(
        json["enforcement"]["endpoint_security"].as_bool(),
        Some(false),
        "expected endpoint_security: false on Linux"
    );
}

// ---------------------------------------------------------------------------
// Platform-agnostic enforcement fields
// ---------------------------------------------------------------------------

/// On any platform, `kernex run --output=json` with a valid policy produces
/// a boolean `degraded` field. When no degradation occurs, it is false.
#[test]
fn test_enforcement_degraded_field_is_boolean() {
    let dir = tempdir().unwrap();
    let config = dir.path().join("kernex.yaml");

    #[cfg(target_os = "linux")]
    fs::write(&config, LINUX_EXEC_POLICY).unwrap();
    #[cfg(not(target_os = "linux"))]
    fs::write(&config, MINIMAL_POLICY).unwrap();

    let output = kernex_cmd(&config.to_string_lossy())
        .args(["--output=json", "run", "--", "true"])
        .output()
        .expect("failed to spawn kernex");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let json: serde_json::Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("JSON parse error: {e}\nstdout: {stdout:?}"));

    assert!(
        json["enforcement"]["degraded"].is_boolean(),
        "field 'enforcement.degraded' must be boolean, got {:?}",
        json["enforcement"]["degraded"]
    );
}
