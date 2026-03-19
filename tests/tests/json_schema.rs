//! JSON output schema validation tests.
//!
//! Every command that accepts `--output=json` must produce a JSON object whose
//! fields exactly match the schema specified in the cli-ux skill. These tests
//! parse the JSON and assert that all required fields are present and have the
//! correct types.
//!
//! Schema reference (from `crates/kernex-cli/src/output.rs`):
//!
//! `kernex run`:
//! ```json
//! {
//!   "command": "run",
//!   "agent": "<string>",
//!   "policy_score": <u8>,
//!   "enforcement": {
//!     "landlock": <bool>,
//!     "seccomp": <bool>,
//!     "endpoint_security": <bool>,
//!     "degraded": <bool>
//!   },
//!   "exit_code": <i32 | null>,
//!   "summary": {
//!     "total_blocks": <u64>,
//!     "unique_blocks": <u64>,
//!     "prompts_shown": <u64>,
//!     "prompts_allowed": <u64>,
//!     "prompts_denied": <u64>,
//!     "injection_signals": <u64>
//!   }
//! }
//! ```

use std::fs;

#[cfg(target_os = "linux")]
use kernex_integration_tests::LINUX_EXEC_POLICY;
use kernex_integration_tests::{kernex_cmd, MINIMAL_POLICY};
use serde_json::Value;
use tempfile::tempdir;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Assert that `obj[key]` exists and equals the expected string.
fn assert_str_field(obj: &Value, key: &str, expected: &str) {
    assert_eq!(
        obj[key].as_str(),
        Some(expected),
        "field '{key}' expected {:?}, got {:?}",
        expected,
        obj[key]
    );
}

/// Assert that `obj[key]` is a boolean.
fn assert_bool_field(obj: &Value, key: &str) {
    assert!(
        obj[key].is_boolean(),
        "field '{key}' must be boolean, got {:?}",
        obj[key]
    );
}

/// Assert that `obj[key]` is a non-negative integer (u64).
fn assert_u64_field(obj: &Value, key: &str) {
    assert!(
        obj[key].is_u64(),
        "field '{key}' must be a non-negative integer, got {:?}",
        obj[key]
    );
}

/// Assert that `obj[key]` is present as an object.
fn assert_obj_field<'a>(obj: &'a Value, key: &str) -> &'a Value {
    assert!(
        obj[key].is_object(),
        "field '{key}' must be an object, got {:?}",
        obj[key]
    );
    &obj[key]
}

/// Run `kernex <args>` with `--output=json` and return the parsed JSON.
///
/// Panics if the command fails to spawn, produces non-UTF-8 output, or the
/// output cannot be parsed as JSON.
fn run_json(config: &str, args: &[&str]) -> Value {
    let output = kernex_cmd(config)
        .arg("--output=json")
        .args(args)
        .output()
        .expect("failed to spawn kernex");

    let stdout = String::from_utf8_lossy(&output.stdout);
    serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("JSON parse error: {e}\nstdout: {stdout:?}"))
}

// ---------------------------------------------------------------------------
// kernex run --output=json
// ---------------------------------------------------------------------------

/// The JSON output from `kernex run` contains all required top-level fields.
#[test]
fn test_run_json_all_top_level_fields_present() {
    let dir = tempdir().unwrap();
    let config = dir.path().join("kernex.yaml");

    #[cfg(target_os = "linux")]
    fs::write(&config, LINUX_EXEC_POLICY).unwrap();
    #[cfg(not(target_os = "linux"))]
    fs::write(&config, MINIMAL_POLICY).unwrap();

    let json = run_json(&config.to_string_lossy(), &["run", "--", "true"]);

    assert_str_field(&json, "command", "run");
    assert!(json["agent"].is_string(), "field 'agent' must be a string");
    assert!(
        json["policy_score"].is_u64(),
        "field 'policy_score' must be an integer, got {:?}",
        json["policy_score"]
    );
    assert!(json["exit_code"].is_i64() || json["exit_code"].is_null());
    assert_obj_field(&json, "enforcement");
    assert_obj_field(&json, "summary");
}

/// The `enforcement` object contains all four required boolean fields.
#[test]
fn test_run_json_enforcement_has_all_boolean_fields() {
    let dir = tempdir().unwrap();
    let config = dir.path().join("kernex.yaml");

    #[cfg(target_os = "linux")]
    fs::write(&config, LINUX_EXEC_POLICY).unwrap();
    #[cfg(not(target_os = "linux"))]
    fs::write(&config, MINIMAL_POLICY).unwrap();

    let json = run_json(&config.to_string_lossy(), &["run", "--", "true"]);
    let enforcement = &json["enforcement"];

    assert_bool_field(enforcement, "landlock");
    assert_bool_field(enforcement, "seccomp");
    assert_bool_field(enforcement, "endpoint_security");
    assert_bool_field(enforcement, "degraded");
}

/// The `summary` object contains all six required non-negative integer fields.
#[test]
fn test_run_json_summary_has_all_count_fields() {
    let dir = tempdir().unwrap();
    let config = dir.path().join("kernex.yaml");

    #[cfg(target_os = "linux")]
    fs::write(&config, LINUX_EXEC_POLICY).unwrap();
    #[cfg(not(target_os = "linux"))]
    fs::write(&config, MINIMAL_POLICY).unwrap();

    let json = run_json(&config.to_string_lossy(), &["run", "--", "true"]);
    let summary = &json["summary"];

    assert_u64_field(summary, "total_blocks");
    assert_u64_field(summary, "unique_blocks");
    assert_u64_field(summary, "prompts_shown");
    assert_u64_field(summary, "prompts_allowed");
    assert_u64_field(summary, "prompts_denied");
    assert_u64_field(summary, "injection_signals");
}

/// `policy_score` is in the valid range 0–100.
#[test]
fn test_run_json_policy_score_in_valid_range() {
    let dir = tempdir().unwrap();
    let config = dir.path().join("kernex.yaml");

    #[cfg(target_os = "linux")]
    fs::write(&config, LINUX_EXEC_POLICY).unwrap();
    #[cfg(not(target_os = "linux"))]
    fs::write(&config, MINIMAL_POLICY).unwrap();

    let json = run_json(&config.to_string_lossy(), &["run", "--", "true"]);
    let score = json["policy_score"]
        .as_u64()
        .expect("policy_score is not u64");

    assert!(score <= 100, "policy_score {score} out of range 0–100");
}

/// `exit_code` is 0 for a successful command.
#[test]
fn test_run_json_exit_code_zero_for_true() {
    let dir = tempdir().unwrap();
    let config = dir.path().join("kernex.yaml");

    #[cfg(target_os = "linux")]
    fs::write(&config, LINUX_EXEC_POLICY).unwrap();
    #[cfg(not(target_os = "linux"))]
    fs::write(&config, MINIMAL_POLICY).unwrap();

    let json = run_json(&config.to_string_lossy(), &["run", "--", "true"]);
    assert_eq!(
        json["exit_code"].as_i64(),
        Some(0),
        "expected exit_code: 0 for `true`"
    );
}

/// The `agent` field equals the command passed to `kernex run`.
#[test]
fn test_run_json_agent_field_matches_command() {
    let dir = tempdir().unwrap();
    let config = dir.path().join("kernex.yaml");

    #[cfg(target_os = "linux")]
    fs::write(&config, LINUX_EXEC_POLICY).unwrap();
    #[cfg(not(target_os = "linux"))]
    fs::write(&config, MINIMAL_POLICY).unwrap();

    let json = run_json(&config.to_string_lossy(), &["run", "--", "true"]);
    assert_str_field(&json, "agent", "true");
}

// ---------------------------------------------------------------------------
// kernex audit --output=json
// ---------------------------------------------------------------------------

/// The JSON output from `kernex audit` contains all required fields.
#[test]
fn test_audit_json_all_required_fields_present() {
    let dir = tempdir().unwrap();
    let config = dir.path().join("kernex.yaml");

    let json = run_json(&config.to_string_lossy(), &["audit", "--", "true"]);

    assert_str_field(&json, "command", "audit");
    assert!(json["agent"].is_string(), "field 'agent' must be a string");
    assert!(
        json["policy_written"].is_boolean(),
        "field 'policy_written' must be boolean"
    );
    assert!(
        json["config_path"].is_string(),
        "field 'config_path' must be a string"
    );
    assert!(
        json["observations"].is_u64(),
        "field 'observations' must be u64"
    );
    assert!(
        json["sensitive_warnings"].is_u64(),
        "field 'sensitive_warnings' must be u64"
    );
    assert!(
        json["diff_has_expansions"].is_boolean(),
        "field 'diff_has_expansions' must be boolean"
    );
}

/// The `command` field is `"audit"`.
#[test]
fn test_audit_json_command_field_is_audit() {
    let dir = tempdir().unwrap();
    let config = dir.path().join("kernex.yaml");

    let json = run_json(&config.to_string_lossy(), &["audit", "--", "true"]);
    assert_str_field(&json, "command", "audit");
}

/// `policy_written` is true when no prior kernex.yaml existed (auto-accepted
/// in JSON mode).
#[test]
fn test_audit_json_policy_written_true_for_new_policy() {
    let dir = tempdir().unwrap();
    let config = dir.path().join("kernex.yaml");

    let json = run_json(&config.to_string_lossy(), &["audit", "--", "true"]);
    assert_eq!(
        json["policy_written"].as_bool(),
        Some(true),
        "expected policy_written: true when no existing policy"
    );
}

// ---------------------------------------------------------------------------
// kernex status --output=json
// ---------------------------------------------------------------------------

/// The JSON output from `kernex status` contains all required fields.
#[test]
fn test_status_json_all_required_fields_present() {
    let dir = tempdir().unwrap();
    let config = dir.path().join("kernex.yaml");
    fs::write(&config, MINIMAL_POLICY).unwrap();

    let json = run_json(&config.to_string_lossy(), &["status"]);

    assert_str_field(&json, "command", "status");
    assert!(
        json["config_path"].is_string(),
        "field 'config_path' must be a string"
    );
    assert!(
        json["score"].is_u64(),
        "field 'score' must be u64, got {:?}",
        json["score"]
    );
    let dimensions = assert_obj_field(&json, "dimensions");
    assert!(
        json["findings"].is_array(),
        "field 'findings' must be an array"
    );

    // Verify score dimensions object.
    assert_u64_field(dimensions, "path_specificity");
    assert_u64_field(dimensions, "network_surface");
    assert_u64_field(dimensions, "environment_exposure");
    assert_u64_field(dimensions, "hidden_protection");
    assert_u64_field(dimensions, "resource_limits");
}

/// `score` is in the valid range 0–100.
#[test]
fn test_status_json_score_in_valid_range() {
    let dir = tempdir().unwrap();
    let config = dir.path().join("kernex.yaml");
    fs::write(&config, MINIMAL_POLICY).unwrap();

    let json = run_json(&config.to_string_lossy(), &["status"]);
    let score = json["score"].as_u64().expect("score is not u64");
    assert!(score <= 100, "score {score} out of range 0–100");
}

/// Dimension scores sum to no more than 100.
#[test]
fn test_status_json_dimension_scores_sum_to_at_most_100() {
    let dir = tempdir().unwrap();
    let config = dir.path().join("kernex.yaml");
    fs::write(&config, MINIMAL_POLICY).unwrap();

    let json = run_json(&config.to_string_lossy(), &["status"]);
    let d = &json["dimensions"];

    let total: u64 = [
        "path_specificity",
        "network_surface",
        "environment_exposure",
        "hidden_protection",
        "resource_limits",
    ]
    .iter()
    .map(|k| d[k].as_u64().unwrap_or(0))
    .sum();

    assert!(
        total <= 100,
        "dimension scores sum to {total}, exceeding 100"
    );
}

// ---------------------------------------------------------------------------
// kernex init --output=json
// ---------------------------------------------------------------------------

/// The JSON output from `kernex init --yes` contains all required fields.
#[test]
fn test_init_json_all_required_fields_present() {
    let dir = tempdir().unwrap();
    let config = dir.path().join("kernex.yaml");

    let json = run_json(&config.to_string_lossy(), &["init", "--yes"]);

    assert_str_field(&json, "command", "init");
    assert!(
        json["config_path"].is_string(),
        "field 'config_path' must be a string"
    );
    assert!(
        json["status"].is_string(),
        "field 'status' must be a string"
    );
    assert!(
        json["agent_name"].is_string(),
        "field 'agent_name' must be a string"
    );
}
