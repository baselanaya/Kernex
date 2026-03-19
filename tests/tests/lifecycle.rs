//! End-to-end lifecycle tests: audit → policy generation → run.
//!
//! These tests exercise the full CLI workflow as an operator would use it:
//!
//! 1. `kernex audit -- <cmd>` profiles the agent and writes `kernex.yaml`.
//! 2. `kernex run  -- <cmd>` loads the policy and runs under enforcement.
//!
//! # Platform note
//!
//! Audit in the current implementation does not yet capture filesystem
//! observations (that requires ptrace / Endpoint Security integration). The
//! generated policy therefore has an empty `allow_read` list. Separate
//! enforcement tests in `enforcement.rs` use hand-crafted policies that
//! include the system paths required to execute test binaries.

use std::fs;

use kernex_integration_tests::{kernex_cmd, LINUX_EXEC_POLICY, MINIMAL_POLICY};
use tempfile::tempdir;

// ---------------------------------------------------------------------------
// Audit lifecycle
// ---------------------------------------------------------------------------

/// `kernex audit -- true` creates a kernex.yaml in the target directory.
#[test]
fn test_audit_creates_kernex_yaml() {
    let dir = tempdir().unwrap();
    let config = dir.path().join("kernex.yaml");

    let status = kernex_cmd(&config.to_string_lossy())
        .args(["audit", "--", "true"])
        .status()
        .expect("failed to spawn kernex");

    assert!(status.success(), "kernex audit exited nonzero: {status}");
    assert!(config.exists(), "kernex.yaml was not created by audit");
}

/// The generated kernex.yaml is valid YAML that can be loaded again.
#[test]
fn test_audit_generated_policy_is_valid_yaml() {
    let dir = tempdir().unwrap();
    let config = dir.path().join("kernex.yaml");

    kernex_cmd(&config.to_string_lossy())
        .args(["audit", "--", "true"])
        .status()
        .expect("failed to spawn kernex");

    let content = fs::read_to_string(&config).expect("kernex.yaml not readable");
    assert!(!content.is_empty(), "kernex.yaml is empty");
    // Verify it parses as YAML — agent_name must be present.
    assert!(
        content.contains("agent_name"),
        "kernex.yaml missing agent_name field"
    );
}

/// Running `kernex audit` a second time over an existing policy updates it
/// (accepts expansions) without error.
#[test]
fn test_audit_updates_existing_policy() {
    let dir = tempdir().unwrap();
    let config = dir.path().join("kernex.yaml");

    // First run — create initial policy.
    kernex_cmd(&config.to_string_lossy())
        .args(["audit", "--", "true"])
        .status()
        .expect("first audit failed");

    // Second run — update the policy, accepting any expansions.
    let status = kernex_cmd(&config.to_string_lossy())
        .args(["audit", "--accept-expansions", "--", "true"])
        .status()
        .expect("second audit failed");

    assert!(status.success(), "second audit exited nonzero: {status}");
    assert!(config.exists(), "kernex.yaml missing after second audit");
}

// ---------------------------------------------------------------------------
// Run: policy loading
// ---------------------------------------------------------------------------

/// `kernex run` exits nonzero and prints guidance when no kernex.yaml exists.
#[test]
fn test_run_without_policy_exits_nonzero_with_guidance() {
    let dir = tempdir().unwrap();
    // Deliberately point at a path that does not exist.
    let config = dir.path().join("kernex.yaml");

    let output = kernex_cmd(&config.to_string_lossy())
        .args(["run", "--", "true"])
        .output()
        .expect("failed to spawn kernex");

    assert!(
        !output.status.success(),
        "expected nonzero exit when policy missing"
    );

    // Either stdout or stderr must contain guidance text.
    let all_output = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        all_output.contains("kernex init") || all_output.contains("audit"),
        "expected guidance mentioning `kernex init` or `audit`, got: {all_output:?}"
    );
}

/// `kernex run` with no command argument exits nonzero.
#[test]
fn test_run_with_no_command_exits_nonzero() {
    let dir = tempdir().unwrap();
    let config = dir.path().join("kernex.yaml");
    fs::write(&config, MINIMAL_POLICY).unwrap();

    let output = kernex_cmd(&config.to_string_lossy())
        .arg("run")
        .output()
        .expect("failed to spawn kernex");

    // clap treats a missing required positional as an error.
    assert!(
        !output.status.success(),
        "expected nonzero exit for missing command"
    );
}

// ---------------------------------------------------------------------------
// Run: session summary
// ---------------------------------------------------------------------------

/// After a successful `kernex run`, stdout contains the session summary line.
///
/// `Output::print()` is not suppressed by `--quiet`, so the summary is always
/// shown in non-JSON mode.
#[test]
fn test_run_session_summary_present_in_stdout() {
    let dir = tempdir().unwrap();
    let config = dir.path().join("kernex.yaml");

    // Use the platform-appropriate policy so the binary can exec.
    #[cfg(target_os = "linux")]
    fs::write(&config, LINUX_EXEC_POLICY).unwrap();
    #[cfg(not(target_os = "linux"))]
    fs::write(&config, MINIMAL_POLICY).unwrap();

    let output = kernex_cmd(&config.to_string_lossy())
        .args(["run", "--", "true"])
        .output()
        .expect("failed to spawn kernex");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("Session summary"),
        "expected 'Session summary' in stdout, got: {stdout:?}"
    );
}

/// The exit code of the sandboxed command is propagated by `kernex run`.
#[test]
fn test_run_propagates_agent_exit_code() {
    let dir = tempdir().unwrap();
    let config = dir.path().join("kernex.yaml");

    #[cfg(target_os = "linux")]
    fs::write(&config, LINUX_EXEC_POLICY).unwrap();
    #[cfg(not(target_os = "linux"))]
    fs::write(&config, MINIMAL_POLICY).unwrap();

    // `false` always exits with code 1.
    let status = kernex_cmd(&config.to_string_lossy())
        .args(["run", "--", "false"])
        .status()
        .expect("failed to spawn kernex");

    assert_eq!(
        status.code(),
        Some(1),
        "expected kernex to propagate exit code 1 from `false`"
    );
}

// ---------------------------------------------------------------------------
// Status command
// ---------------------------------------------------------------------------

/// `kernex status` succeeds for a valid policy.
#[test]
fn test_status_succeeds_for_valid_policy() {
    let dir = tempdir().unwrap();
    let config = dir.path().join("kernex.yaml");
    fs::write(&config, MINIMAL_POLICY).unwrap();

    let status = kernex_cmd(&config.to_string_lossy())
        .arg("status")
        .status()
        .expect("failed to spawn kernex");

    assert!(status.success(), "kernex status failed: {status}");
}

/// `kernex status` exits nonzero for a missing policy file.
#[test]
fn test_status_fails_for_missing_policy() {
    let dir = tempdir().unwrap();
    let config = dir.path().join("kernex.yaml");
    // Deliberately no file.

    let status = kernex_cmd(&config.to_string_lossy())
        .arg("status")
        .status()
        .expect("failed to spawn kernex");

    assert!(
        !status.success(),
        "expected nonzero exit when policy file is missing"
    );
}

// ---------------------------------------------------------------------------
// Init command
// ---------------------------------------------------------------------------

/// `kernex init --yes` creates a kernex.yaml with safe defaults.
#[test]
fn test_init_creates_policy_with_yes_flag() {
    let dir = tempdir().unwrap();
    let config = dir.path().join("kernex.yaml");

    let status = kernex_cmd(&config.to_string_lossy())
        .args(["init", "--yes"])
        .status()
        .expect("failed to spawn kernex");

    assert!(status.success(), "kernex init --yes failed: {status}");
    assert!(config.exists(), "kernex.yaml not created by init --yes");
}

/// The kernex.yaml created by `init --yes` is non-empty and contains
/// `agent_name`.
#[test]
fn test_init_generated_policy_contains_agent_name() {
    let dir = tempdir().unwrap();
    let config = dir.path().join("kernex.yaml");

    kernex_cmd(&config.to_string_lossy())
        .args(["init", "--yes"])
        .status()
        .expect("failed to spawn kernex");

    let content = fs::read_to_string(&config).expect("kernex.yaml not readable");
    assert!(
        content.contains("agent_name"),
        "init --yes produced a policy without agent_name: {content:?}"
    );
}

/// The kernex.yaml created by `init --yes` contains inline comments.
#[test]
fn test_init_generated_yaml_contains_inline_comments() {
    let dir = tempdir().unwrap();
    let config = dir.path().join("kernex.yaml");

    kernex_cmd(&config.to_string_lossy())
        .args(["init", "--yes"])
        .status()
        .expect("failed to spawn kernex");

    let content = fs::read_to_string(&config).expect("kernex.yaml not readable");
    assert!(
        content.contains("# "),
        "init --yes must produce a YAML with inline comments; got: {content:?}"
    );
}

/// `kernex status` on a policy created by `init --yes` reports score ≥ 60.
#[test]
fn test_init_generated_policy_scores_at_least_60_via_status() {
    let dir = tempdir().unwrap();
    let config = dir.path().join("kernex.yaml");

    kernex_cmd(&config.to_string_lossy())
        .args(["init", "--yes"])
        .status()
        .expect("failed to spawn kernex");

    let output = kernex_cmd(&config.to_string_lossy())
        .args(["--output=json", "status"])
        .output()
        .expect("failed to spawn kernex status");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let json: serde_json::Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("status --output=json must produce JSON: {e}\n{stdout}"));

    let score = json["score"]
        .as_u64()
        .unwrap_or_else(|| panic!("score field must be u64; got: {}", json["score"]));

    assert!(
        score >= 60,
        "init-generated policy must score ≥ 60/100 on `kernex status`; got {score}/100"
    );
}

/// `kernex init` (without `--yes`) does not overwrite an existing kernex.yaml
/// when running in quiet/non-interactive mode.
///
/// The overwrite prompt uses `default_no = true`, so `--quiet` (which makes
/// `confirm()` return `!default_no = false`) preserves the existing file.
/// Only `--yes` bypasses this guard — intentionally.
#[test]
fn test_init_without_yes_does_not_overwrite_existing_policy() {
    let dir = tempdir().unwrap();
    let config = dir.path().join("kernex.yaml");
    let sentinel = "agent_name: sentinel-do-not-overwrite\n";
    fs::write(&config, sentinel).unwrap();

    // --quiet is added by kernex_cmd(); stdin is null → confirm returns false
    // (default_no=true) → init aborts without overwriting.
    kernex_cmd(&config.to_string_lossy())
        .arg("init")
        // NOTE: no --yes — the overwrite guard is active.
        .status()
        .expect("failed to spawn kernex");

    let content = fs::read_to_string(&config).expect("kernex.yaml not readable");
    assert!(
        content.contains("sentinel-do-not-overwrite"),
        "init without --yes should not overwrite the existing policy, but it did"
    );
}
