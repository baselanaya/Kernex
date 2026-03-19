//! Pre-run policy scoring integration tests.
//!
//! Verifies that `kernex run` automatically scores the policy before executing
//! the command and surfaces the correct output depending on the score:
//!
//! - Score ≥ 60: no warning on stderr; command runs normally.
//! - Score < 60: exactly one warning line on stderr mentioning the score.
//!
//! JSON output (`--output=json`) must include a `policy_score` field that is a
//! non-negative integer in the range 0–100.

use std::fs;

use kernex_integration_tests::kernex_cmd;
#[cfg(target_os = "linux")]
use kernex_integration_tests::LINUX_EXEC_POLICY;
#[cfg(not(target_os = "linux"))]
use kernex_integration_tests::MINIMAL_POLICY;
use tempfile::tempdir;

// ---------------------------------------------------------------------------
// High-score policy — no warning
// ---------------------------------------------------------------------------

/// A high-scoring policy (≥ 60) must not produce a score warning on stderr.
#[test]
fn test_run_high_score_policy_emits_no_score_warning() {
    let dir = tempdir().unwrap();
    let config = dir.path().join("kernex.yaml");

    #[cfg(target_os = "linux")]
    fs::write(&config, LINUX_EXEC_POLICY).unwrap();
    #[cfg(not(target_os = "linux"))]
    fs::write(&config, MINIMAL_POLICY).unwrap();

    let output = kernex_cmd(&config.to_string_lossy())
        .args(["run", "--", "true"])
        .output()
        .expect("failed to spawn kernex");

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !stderr.to_lowercase().contains("policy score"),
        "high-score policy must not emit a score warning; got stderr: {stderr:?}"
    );
}

// ---------------------------------------------------------------------------
// Low-score policy — exactly one warning line on stderr
// ---------------------------------------------------------------------------

/// A policy that scores below 60 must emit exactly one warning line on stderr
/// that contains the numeric score.
///
/// The policy here scores 0: root read (0 pts), block_hidden=false (0 pts),
/// network block_all_other=false (0 pts), no env policy (0 pts),
/// no resource limits (0 pts).
#[cfg(target_os = "linux")]
#[test]
fn test_run_low_score_policy_emits_one_score_warning_line() {
    let low_score_policy = "\
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
    - /
  block_hidden: false
network:
  block_all_other: false
";

    let dir = tempdir().unwrap();
    let config = dir.path().join("kernex.yaml");
    fs::write(&config, low_score_policy).unwrap();

    let output = kernex_cmd(&config.to_string_lossy())
        .args(["run", "--", "true"])
        .output()
        .expect("failed to spawn kernex");

    let stderr = String::from_utf8_lossy(&output.stderr);

    // The warning must appear on stderr.
    assert!(
        stderr.to_lowercase().contains("policy score") || stderr.contains("score:"),
        "low-score policy must emit a score warning to stderr; got: {stderr:?}"
    );

    // The warning must be exactly one line (single newline-terminated).
    let score_lines: Vec<&str> = stderr
        .lines()
        .filter(|l| l.to_lowercase().contains("score"))
        .collect();
    assert_eq!(
        score_lines.len(),
        1,
        "expected exactly one score warning line; got: {score_lines:?}"
    );

    // The warning line must contain a digit (the numeric score).
    assert!(
        score_lines[0].chars().any(|c| c.is_ascii_digit()),
        "score warning must contain the numeric score; got: {:?}",
        score_lines[0]
    );
}

/// A low-score policy must not block the command from running — it is a warning
/// only, not an enforcement gate.
#[cfg(target_os = "linux")]
#[test]
fn test_run_low_score_policy_does_not_block_command() {
    let low_score_policy = "\
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
    - /
  block_hidden: false
network:
  block_all_other: false
";

    let dir = tempdir().unwrap();
    let config = dir.path().join("kernex.yaml");
    fs::write(&config, low_score_policy).unwrap();

    // `true` exits 0; if kernex blocked on score the status would be nonzero.
    let status = kernex_cmd(&config.to_string_lossy())
        .args(["run", "--", "true"])
        .status()
        .expect("failed to spawn kernex");

    assert!(
        status.success(),
        "low-score warning must not block command execution; got: {status}"
    );
}

// ---------------------------------------------------------------------------
// JSON output: policy_score field
// ---------------------------------------------------------------------------

/// `--output=json` from `kernex run` includes a `policy_score` field that is
/// a non-negative integer in range 0–100.
#[test]
fn test_run_json_policy_score_in_range() {
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

    let score = json["policy_score"].as_u64().unwrap_or_else(|| {
        panic!(
            "policy_score must be a u64, got: {:?}",
            json["policy_score"]
        )
    });

    assert!(score <= 100, "policy_score {score} out of range 0–100");
}

/// `--output=json` from `kernex run` must not emit score warnings to stdout
/// (warnings belong on stderr only).
#[test]
fn test_run_json_stdout_contains_no_score_warning_text() {
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

    // stdout must parse cleanly as JSON (no interleaved warning text).
    let stdout = String::from_utf8_lossy(&output.stdout);
    let _json: serde_json::Value = serde_json::from_str(&stdout).unwrap_or_else(|e| {
        panic!("stdout must be pure JSON; parse error: {e}\nstdout: {stdout:?}")
    });
}
