//! Terminal output helpers and JSON output types.
//!
//! # Text output
//!
//! Always write text output to `stdout` for machine-parseable content
//! (summaries, scores, diffs) and `stderr` for warnings and informational
//! messages that should not appear in piped output.
//!
//! Colours are enabled when:
//! - `NO_COLOR` is NOT set in the environment, AND
//! - stdout is a TTY (`std::io::IsTerminal`)
//!
//! # JSON output
//!
//! When `--output=json`, all command results go to stdout as one JSON object.
//! Warnings and errors still go to stderr so that the JSON is clean.

use std::io::{IsTerminal as _, Write as _};

use serde::Serialize;

// ---------------------------------------------------------------------------
// Prefix symbols — use consistently across all commands
// ---------------------------------------------------------------------------

pub const PREFIX_OK: &str = "✓";
pub const PREFIX_WARN: &str = "⚠";
pub const PREFIX_BLOCK: &str = "✗";
pub const PREFIX_HIGH: &str = "!";
pub const PREFIX_INFO: &str = "→";

// ---------------------------------------------------------------------------
// ANSI colour codes
// ---------------------------------------------------------------------------

const ANSI_GREEN: &str = "\x1b[32m";
const ANSI_YELLOW: &str = "\x1b[33m";
const ANSI_RED: &str = "\x1b[31m";
const ANSI_RESET: &str = "\x1b[0m";

// ---------------------------------------------------------------------------
// Output — controls how messages are rendered
// ---------------------------------------------------------------------------

/// Controls output mode (text vs JSON) and whether colours are active.
#[derive(Debug, Clone)]
pub struct Output {
    /// True when `--output=json` was passed.
    pub json: bool,
    /// True when ANSI colours should be emitted.
    pub color: bool,
    /// True when `--quiet` was passed.
    pub quiet: bool,
}

impl Output {
    /// Create an `Output` instance from CLI flags.
    ///
    /// Colours are enabled automatically when stdout is a TTY and
    /// `NO_COLOR` is not set.
    pub fn new(json: bool, quiet: bool) -> Self {
        let color = !json && std::env::var("NO_COLOR").is_err() && std::io::stdout().is_terminal();
        Self { json, color, quiet }
    }

    // -- Printing helpers ---------------------------------------------------

    /// Print an informational line (→). Suppressed in `--quiet` mode.
    pub fn info(&self, msg: &str) {
        if self.quiet || self.json {
            return;
        }
        println!("{PREFIX_INFO}  {msg}");
    }

    /// Print a success line (✓). Suppressed in `--quiet` mode.
    pub fn success(&self, msg: &str) {
        if self.quiet || self.json {
            return;
        }
        if self.color {
            println!("{ANSI_GREEN}{PREFIX_OK}{ANSI_RESET}  {msg}");
        } else {
            println!("{PREFIX_OK}  {msg}");
        }
    }

    /// Print a warning line (⚠) to stderr. Always shown even in `--quiet`.
    pub fn warn(&self, msg: &str) {
        if self.json {
            return;
        }
        if self.color {
            eprintln!("{ANSI_YELLOW}{PREFIX_WARN}{ANSI_RESET}  {msg}");
        } else {
            eprintln!("{PREFIX_WARN}  {msg}");
        }
    }

    /// Print a block/denial line (✗). Suppressed in `--quiet` mode.
    ///
    /// Used by JIT prompt display when a request is denied.
    #[allow(dead_code)] // Reserved for JIT prompt implementation.
    pub fn block(&self, msg: &str) {
        if self.quiet || self.json {
            return;
        }
        if self.color {
            println!("{ANSI_RED}{PREFIX_BLOCK}{ANSI_RESET}  {msg}");
        } else {
            println!("{PREFIX_BLOCK}  {msg}");
        }
    }

    /// Print a high-risk warning (!) to stderr. Always shown even in `--quiet`.
    pub fn high_risk(&self, msg: &str) {
        if self.json {
            return;
        }
        if self.color {
            eprintln!("{ANSI_RED}{PREFIX_HIGH}{ANSI_RESET}  {msg}");
        } else {
            eprintln!("{PREFIX_HIGH}  {msg}");
        }
    }

    /// Print an error message to stderr and return an error.
    pub fn error(&self, msg: &str) {
        if self.json {
            return;
        }
        if self.color {
            eprintln!("{ANSI_RED}{PREFIX_BLOCK}{ANSI_RESET}  {msg}");
        } else {
            eprintln!("{PREFIX_BLOCK}  {msg}");
        }
    }

    /// Print raw text to stdout (used for multi-line displays like diffs and
    /// status output). Suppressed when `--output=json`.
    pub fn print(&self, msg: &str) {
        if !self.json {
            println!("{msg}");
        }
    }

    /// Emit the final JSON result to stdout.
    ///
    /// Should only be called when `self.json == true`.
    pub fn emit_json<T: Serialize>(&self, value: &T) {
        match serde_json::to_string_pretty(value) {
            Ok(s) => println!("{s}"),
            Err(e) => eprintln!("JSON serialization failed: {e}"),
        }
    }

    /// Ask a yes/no question and return true if the user answers y/Y.
    ///
    /// Returns false immediately in `--quiet` mode (non-interactive).
    pub fn confirm(&self, prompt: &str, default_no: bool) -> bool {
        if self.quiet || self.json {
            return !default_no;
        }
        let hint = if default_no { "[y/N]" } else { "[Y/n]" };
        print!("{prompt} {hint} ");
        let _ = std::io::stdout().flush();

        let mut line = String::new();
        if std::io::stdin().read_line(&mut line).is_err() {
            return !default_no;
        }
        let answer = line.trim().to_lowercase();
        match answer.as_str() {
            "y" | "yes" => true,
            "n" | "no" => false,
            "" => !default_no,
            _ => false,
        }
    }

    /// Display a numbered list of choices and return the selected index (0-based).
    ///
    /// Prints each choice prefixed with `›` (selected) or spaces (others).
    /// The user enters a 1-based number; pressing Enter accepts `default_idx`.
    /// In `--quiet` or `--output=json` mode returns `default_idx` immediately.
    pub fn select(&self, prompt: &str, choices: &[&str], default_idx: usize) -> usize {
        if self.quiet || self.json {
            return default_idx;
        }
        println!("{prompt}");
        for (i, choice) in choices.iter().enumerate() {
            if i == default_idx {
                println!("  \u{203a} {choice}");
            } else {
                println!("    {choice}");
            }
        }
        print!("Enter number (1–{}): ", choices.len());
        let _ = std::io::stdout().flush();

        let mut line = String::new();
        if std::io::stdin().read_line(&mut line).is_err() {
            return default_idx;
        }
        let trimmed = line.trim();
        if trimmed.is_empty() {
            return default_idx;
        }
        match trimmed.parse::<usize>() {
            Ok(n) if n >= 1 && n <= choices.len() => n - 1,
            _ => default_idx,
        }
    }

    /// Read a line of input from stdin. Returns empty string on error or in JSON mode.
    pub fn read_line(&self, prompt: &str, default: &str) -> String {
        if self.quiet || self.json {
            return default.to_string();
        }
        if !default.is_empty() {
            print!("{prompt} ({default}) ");
        } else {
            print!("{prompt} ");
        }
        let _ = std::io::stdout().flush();

        let mut line = String::new();
        if std::io::stdin().read_line(&mut line).is_err() {
            return default.to_string();
        }
        let trimmed = line.trim().to_string();
        if trimmed.is_empty() {
            default.to_string()
        } else {
            trimmed
        }
    }
}

// ---------------------------------------------------------------------------
// JSON output schemas
// ---------------------------------------------------------------------------

/// JSON schema for `kernex init --output=json`.
#[derive(Debug, Serialize)]
pub struct InitJsonOutput {
    pub command: &'static str,
    pub config_path: String,
    pub status: &'static str,
    pub agent_name: String,
}

/// JSON schema for `kernex run --output=json`.
#[derive(Debug, Serialize)]
pub struct RunJsonOutput {
    pub command: &'static str,
    pub agent: String,
    pub policy_score: u8,
    pub enforcement: EnforcementInfo,
    pub exit_code: Option<i32>,
    pub summary: RunSummary,
}

/// Enforcement details for `kernex run` JSON output.
#[derive(Debug, Serialize)]
pub struct EnforcementInfo {
    pub landlock: bool,
    pub seccomp: bool,
    pub endpoint_security: bool,
    pub degraded: bool,
}

/// Per-session statistics for `kernex run` JSON output.
#[derive(Debug, Serialize)]
pub struct RunSummary {
    pub total_blocks: u64,
    pub unique_blocks: u64,
    pub prompts_shown: u64,
    pub prompts_allowed: u64,
    pub prompts_denied: u64,
    pub injection_signals: u64,
}

/// JSON schema for `kernex audit --output=json`.
#[derive(Debug, Serialize)]
pub struct AuditJsonOutput {
    pub command: &'static str,
    pub agent: String,
    pub policy_written: bool,
    pub config_path: String,
    pub observations: u64,
    pub sensitive_warnings: u64,
    pub diff_has_expansions: bool,
}

/// JSON schema for `kernex diff --output=json`.
#[derive(Debug, Serialize)]
pub struct DiffJsonOutput {
    pub command: &'static str,
    pub old: String,
    pub new: String,
    pub entries: Vec<DiffJsonEntry>,
    pub has_scope_expansions: bool,
}

/// A single diff entry in JSON output.
#[derive(Debug, Serialize)]
pub struct DiffJsonEntry {
    pub kind: &'static str,
    pub field: String,
    pub value: Option<String>,
    pub old_value: Option<String>,
    pub new_value: Option<String>,
    pub is_scope_expansion: bool,
}

/// JSON schema for `kernex status --output=json`.
#[derive(Debug, Serialize)]
pub struct StatusJsonOutput {
    pub command: &'static str,
    pub config_path: String,
    pub score: u8,
    pub dimensions: ScoreDimensions,
    pub findings: Vec<String>,
}

/// Score dimensions for `kernex status --output=json`.
#[derive(Debug, Serialize)]
pub struct ScoreDimensions {
    pub path_specificity: u8,
    pub network_surface: u8,
    pub environment_exposure: u8,
    pub hidden_protection: u8,
    pub resource_limits: u8,
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn text_output() -> Output {
        Output {
            json: false,
            color: false,
            quiet: false,
        }
    }

    fn json_output() -> Output {
        Output {
            json: true,
            color: false,
            quiet: false,
        }
    }

    fn quiet_output() -> Output {
        Output {
            json: false,
            color: false,
            quiet: true,
        }
    }

    // -- PREFIX symbols are non-empty ----------------------------------------

    #[test]
    fn test_prefix_symbols_are_non_empty() {
        assert!(!PREFIX_OK.is_empty());
        assert!(!PREFIX_WARN.is_empty());
        assert!(!PREFIX_BLOCK.is_empty());
        assert!(!PREFIX_HIGH.is_empty());
        assert!(!PREFIX_INFO.is_empty());
    }

    // -- Output::new color detection -----------------------------------------

    #[test]
    fn test_output_new_json_mode_disables_color() {
        let o = Output::new(true, false);
        assert!(!o.color, "color must be disabled in JSON mode");
    }

    #[test]
    fn test_output_new_no_color_env_disables_color() {
        std::env::set_var("NO_COLOR", "1");
        let o = Output::new(false, false);
        // Color must be disabled when NO_COLOR is set.
        // Note: IsTerminal may also be false in test context.
        assert!(!o.color);
        std::env::remove_var("NO_COLOR");
    }

    // -- select: quiet mode --------------------------------------------------

    #[test]
    fn test_select_quiet_mode_returns_default_idx() {
        let o = quiet_output();
        // In quiet mode, select() always returns the default index.
        assert_eq!(o.select("?", &["A", "B", "C"], 1), 1);
        assert_eq!(o.select("?", &["A", "B"], 0), 0);
    }

    #[test]
    fn test_select_json_mode_returns_default_idx() {
        let o = Output {
            json: true,
            color: false,
            quiet: false,
        };
        assert_eq!(o.select("?", &["X", "Y", "Z"], 2), 2);
    }

    // -- confirm: quiet mode -------------------------------------------------

    #[test]
    fn test_confirm_quiet_mode_returns_true_for_non_default_no() {
        // quiet=true, default_no=false → returns true (non-interactive accept)
        let o = quiet_output();
        assert!(o.confirm("test?", false));
    }

    #[test]
    fn test_confirm_quiet_mode_returns_false_for_default_no() {
        let o = quiet_output();
        assert!(!o.confirm("test?", true));
    }

    // -- JSON schemas serialize without panic --------------------------------

    #[test]
    fn test_init_json_output_serializes() {
        let v = InitJsonOutput {
            command: "init",
            config_path: "./kernex.yaml".to_string(),
            status: "created",
            agent_name: "test".to_string(),
        };
        let s = serde_json::to_string(&v).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&s).unwrap();
        assert_eq!(parsed["command"], "init");
        assert_eq!(parsed["status"], "created");
    }

    #[test]
    fn test_run_json_output_serializes() {
        let v = RunJsonOutput {
            command: "run",
            agent: "python agent.py".to_string(),
            policy_score: 72,
            enforcement: EnforcementInfo {
                landlock: true,
                seccomp: true,
                endpoint_security: false,
                degraded: false,
            },
            exit_code: Some(0),
            summary: RunSummary {
                total_blocks: 0,
                unique_blocks: 0,
                prompts_shown: 0,
                prompts_allowed: 0,
                prompts_denied: 0,
                injection_signals: 0,
            },
        };
        let s = serde_json::to_string(&v).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&s).unwrap();
        assert_eq!(parsed["command"], "run");
        assert_eq!(parsed["policy_score"], 72);
    }

    #[test]
    fn test_status_json_output_has_required_fields() {
        let v = StatusJsonOutput {
            command: "status",
            config_path: "./kernex.yaml".to_string(),
            score: 80,
            dimensions: ScoreDimensions {
                path_specificity: 20,
                network_surface: 20,
                environment_exposure: 20,
                hidden_protection: 20,
                resource_limits: 0,
            },
            findings: vec!["no resource limits".to_string()],
        };
        let s = serde_json::to_string(&v).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&s).unwrap();
        assert_eq!(parsed["command"], "status");
        assert_eq!(parsed["score"], 80);
        assert!(parsed["findings"].is_array());
    }

    #[test]
    fn test_diff_json_output_has_entries_array() {
        let v = DiffJsonOutput {
            command: "diff",
            old: "old.yaml".to_string(),
            new: "new.yaml".to_string(),
            entries: vec![],
            has_scope_expansions: false,
        };
        let s = serde_json::to_string(&v).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&s).unwrap();
        assert!(parsed["entries"].is_array());
        assert_eq!(parsed["has_scope_expansions"], false);
    }

    // -- Output field values -------------------------------------------------

    #[test]
    fn test_output_json_flag_is_stored() {
        let o = json_output();
        assert!(o.json);
    }

    #[test]
    fn test_output_quiet_flag_is_stored() {
        let o = quiet_output();
        assert!(o.quiet);
    }

    #[test]
    fn test_output_text_mode_is_not_json() {
        let o = text_output();
        assert!(!o.json);
    }
}
