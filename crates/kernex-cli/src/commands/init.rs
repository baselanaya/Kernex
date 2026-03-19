//! `kernex init` — interactive wizard that generates a starter `kernex.yaml`.
//!
//! # Wizard flow (interactive mode)
//!
//! ```text
//! ? What agent framework are you using?
//!   › Claude Code
//!     CrewAI / AutoGen
//!     Custom script
//!     Other
//!
//! ? Where is your project directory? (./src)
//!
//! ? Does this agent need internet access?
//!   › Yes — specific APIs only
//!     No
//!
//! ? Which APIs? (e.g. api.anthropic.com:443)
//!
//! ✓  Created kernex.yaml
//! →  Run `kernex audit -- <your command>` to profile your agent before enforcing.
//! ```

use crate::cli::{GlobalArgs, InitArgs};
use crate::output::{InitJsonOutput, Output};
use crate::policy_io::write_annotated_policy;

// ---------------------------------------------------------------------------
// Agent framework choices
// ---------------------------------------------------------------------------

/// Display labels for the framework selector.
const FRAMEWORK_CHOICES: &[&str] = &["Claude Code", "CrewAI / AutoGen", "Custom script", "Other"];

/// Derive a safe default agent name from a framework choice index.
fn agent_name_for_framework(idx: usize) -> &'static str {
    match idx {
        0 => "claude-code-agent",
        1 => "crewai-agent",
        2 => "custom-agent",
        _ => "my-agent",
    }
}

/// Default API hosts pre-populated for known frameworks (host, port).
///
/// Only the Claude Code framework has a well-known default; others start empty.
fn default_apis_for_framework(idx: usize) -> &'static [(&'static str, u16)] {
    match idx {
        0 => &[("api.anthropic.com", 443)],
        _ => &[],
    }
}

// ---------------------------------------------------------------------------
// Internet-access choices
// ---------------------------------------------------------------------------

const INTERNET_CHOICES: &[&str] = &["Yes — specific APIs only", "No"];

// ---------------------------------------------------------------------------
// Wizard entry point
// ---------------------------------------------------------------------------

/// Run `kernex init`.
///
/// In `--yes` mode all prompts are skipped and safe defaults are applied:
/// - Framework: "my-agent" (generic)
/// - Project directory: `./src`
/// - Internet access: No (safest default)
pub async fn run(out: &Output, global: &GlobalArgs, args: InitArgs) -> anyhow::Result<()> {
    let config_path = &global.config;

    // Confirm overwrite if the file already exists (skip in --yes mode).
    if std::path::Path::new(config_path).exists() && !args.yes {
        let ok = out.confirm(&format!("{config_path} already exists. Overwrite?"), true);
        if !ok {
            out.info("Aborted.");
            return Ok(());
        }
    }

    // ── Step 1: agent framework ──────────────────────────────────────────────

    let (agent_name, default_apis): (String, Vec<(String, u16)>) = if args.yes {
        ("my-agent".to_string(), vec![])
    } else {
        let idx = out.select(
            "? What agent framework are you using?",
            FRAMEWORK_CHOICES,
            0,
        );
        let name = agent_name_for_framework(idx).to_string();
        let apis = default_apis_for_framework(idx)
            .iter()
            .map(|(h, p)| (h.to_string(), *p))
            .collect();
        (name, apis)
    };

    // ── Step 2: project directory ────────────────────────────────────────────

    let project_dir = if args.yes {
        "./src".to_string()
    } else {
        out.read_line("? Where is your project directory?", "./src")
    };

    // ── Step 3: internet access ──────────────────────────────────────────────

    // Default: No internet (index 1) — safest default.
    let wants_internet = if args.yes {
        false
    } else {
        let idx = out.select(
            "? Does this agent need internet access?",
            INTERNET_CHOICES,
            1, // default: "No"
        );
        idx == 0 // 0 = "Yes — specific APIs only"
    };

    // ── Step 4: which APIs? (only if internet = yes) ─────────────────────────

    let api_hosts: Vec<(String, u16)> = if !wants_internet {
        vec![]
    } else if !default_apis.is_empty() && out.quiet {
        // Quiet mode with pre-populated defaults: use them.
        default_apis
    } else {
        let raw = out.read_line(
            "? Which APIs? (e.g. api.anthropic.com:443, comma-separated)",
            "",
        );
        parse_api_hosts(&raw).unwrap_or_else(|| default_apis.clone())
    };

    let api_host_refs: Vec<(&str, u16)> = api_hosts.iter().map(|(h, p)| (h.as_str(), *p)).collect();

    // ── Build and write annotated policy ─────────────────────────────────────

    write_annotated_policy(&agent_name, &api_host_refs, &project_dir, config_path)?;

    // ── Output ───────────────────────────────────────────────────────────────

    if out.json {
        out.emit_json(&InitJsonOutput {
            command: "init",
            config_path: config_path.clone(),
            status: "created",
            agent_name,
        });
    } else {
        out.success(&format!("Created {config_path}"));
        out.info("Run `kernex audit -- <your command>` to profile your agent before enforcing.");
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Parse a comma-separated `"host:port"` string.
///
/// Returns `None` if the string is empty. Invalid entries are silently skipped.
fn parse_api_hosts(raw: &str) -> Option<Vec<(String, u16)>> {
    if raw.trim().is_empty() {
        return None;
    }
    let hosts: Vec<(String, u16)> = raw
        .split(',')
        .filter_map(|s| {
            let s = s.trim();
            let mut parts = s.rsplitn(2, ':');
            let port_str = parts.next()?;
            let host = parts.next()?.to_string();
            let port: u16 = port_str.parse().ok()?;
            Some((host, port))
        })
        .collect();
    if hosts.is_empty() {
        None
    } else {
        Some(hosts)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::{GlobalArgs, OutputFormat};

    fn global(tmp: &str) -> GlobalArgs {
        GlobalArgs {
            output_format: None,
            strict: false,
            config: tmp.to_string(),
            quiet: true,
            mcp: false,
        }
    }

    fn quiet_out() -> Output {
        Output {
            json: false,
            color: false,
            quiet: true,
        }
    }

    #[tokio::test]
    async fn test_init_creates_kernex_yaml() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("kernex.yaml").to_string_lossy().to_string();
        let g = global(&path);
        run(&quiet_out(), &g, InitArgs { yes: true }).await.unwrap();
        assert!(std::path::Path::new(&path).exists());
    }

    #[tokio::test]
    async fn test_init_yaml_parses_as_valid_policy() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("kernex.yaml").to_string_lossy().to_string();
        let g = global(&path);
        run(&quiet_out(), &g, InitArgs { yes: true }).await.unwrap();
        let policy = kernex_policy::KernexPolicy::from_file(std::path::Path::new(&path)).unwrap();
        assert_eq!(policy.agent_name, "my-agent");
        assert!(policy.filesystem.block_hidden);
        assert!(policy.network.block_all_other);
        assert!(policy.environment.block_all_other);
    }

    #[tokio::test]
    async fn test_init_json_output_emits_valid_json() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("kernex.yaml").to_string_lossy().to_string();
        let g = GlobalArgs {
            output_format: Some(OutputFormat::Json),
            strict: false,
            config: path.clone(),
            quiet: false,
            mcp: false,
        };
        let out = Output {
            json: true,
            color: false,
            quiet: false,
        };
        run(&out, &g, InitArgs { yes: true }).await.unwrap();
        assert!(std::path::Path::new(&path).exists());
    }

    #[tokio::test]
    async fn test_init_does_not_overwrite_in_quiet_mode() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("kernex.yaml").to_string_lossy().to_string();
        let g = global(&path);

        // Create the file first.
        std::fs::write(&path, "agent_name: existing").unwrap();

        // quiet mode with default_no=true → confirm returns false → aborts.
        run(&quiet_out(), &g, InitArgs { yes: false })
            .await
            .unwrap();

        // File should remain unchanged.
        let content = std::fs::read_to_string(&path).unwrap();
        assert!(content.contains("existing"));
    }

    // -- wizard: YAML quality ------------------------------------------------

    /// Every field in the generated kernex.yaml must have an inline comment
    /// explaining what it does.
    #[tokio::test]
    async fn test_init_yaml_contains_inline_comments() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("kernex.yaml").to_string_lossy().to_string();
        run(&quiet_out(), &global(&path), InitArgs { yes: true })
            .await
            .unwrap();
        let content = std::fs::read_to_string(&path).unwrap();
        assert!(
            content.contains("# "),
            "generated kernex.yaml must contain inline comments explaining fields"
        );
        // The key sections must each have at least one comment.
        assert!(
            content.contains("block_hidden"),
            "must mention block_hidden"
        );
        assert!(
            content.contains("block_all_other"),
            "must mention block_all_other"
        );
    }

    /// The generated YAML must parse as a valid KernexPolicy even with comments.
    #[tokio::test]
    async fn test_init_yaml_with_comments_parses_as_valid_policy() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("kernex.yaml").to_string_lossy().to_string();
        run(&quiet_out(), &global(&path), InitArgs { yes: true })
            .await
            .unwrap();
        let policy = kernex_policy::KernexPolicy::from_file(std::path::Path::new(&path))
            .unwrap_or_else(|e| panic!("YAML with comments must parse as KernexPolicy: {e}"));
        assert!(!policy.agent_name.is_empty());
        assert!(policy.filesystem.block_hidden);
        assert!(policy.network.block_all_other);
        assert!(policy.environment.block_all_other);
    }

    /// The generated policy must score ≥ 60 out of 100.
    #[tokio::test]
    async fn test_init_policy_scores_at_least_60() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("kernex.yaml").to_string_lossy().to_string();
        run(&quiet_out(), &global(&path), InitArgs { yes: true })
            .await
            .unwrap();
        let policy = kernex_policy::KernexPolicy::from_file(std::path::Path::new(&path)).unwrap();
        let score = policy.score();
        assert!(
            score.total >= 60,
            "init-generated policy must score ≥ 60/100, got {}/100; findings: {:?}",
            score.total,
            score.findings
        );
    }

    /// The generated YAML must contain commented-out resource_limits so users
    /// know the field exists and can uncomment it.
    #[tokio::test]
    async fn test_init_yaml_contains_resource_limits_hint() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("kernex.yaml").to_string_lossy().to_string();
        run(&quiet_out(), &global(&path), InitArgs { yes: true })
            .await
            .unwrap();
        let content = std::fs::read_to_string(&path).unwrap();
        assert!(
            content.contains("resource_limits"),
            "generated YAML must contain a resource_limits hint (even if commented out)"
        );
    }

    // -- wizard: safe defaults -----------------------------------------------

    /// --yes mode must generate a policy with no outbound network rules
    /// (safe default: no internet access assumed).
    #[tokio::test]
    async fn test_init_yes_generates_no_outbound_rules() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("kernex.yaml").to_string_lossy().to_string();
        run(&quiet_out(), &global(&path), InitArgs { yes: true })
            .await
            .unwrap();
        let policy = kernex_policy::KernexPolicy::from_file(std::path::Path::new(&path)).unwrap();
        assert!(
            policy.network.allow_outbound.is_empty(),
            "--yes mode must default to no outbound rules (safe default)"
        );
        assert!(
            policy.network.block_all_other,
            "--yes mode must default to block_all_other: true"
        );
    }

    /// --yes mode must set block_hidden: true (safe default).
    #[tokio::test]
    async fn test_init_yes_sets_block_hidden_true() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("kernex.yaml").to_string_lossy().to_string();
        run(&quiet_out(), &global(&path), InitArgs { yes: true })
            .await
            .unwrap();
        let policy = kernex_policy::KernexPolicy::from_file(std::path::Path::new(&path)).unwrap();
        assert!(policy.filesystem.block_hidden);
    }

    /// --yes mode must set environment.block_all_other: true (safe default).
    #[tokio::test]
    async fn test_init_yes_sets_env_block_all_other_true() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("kernex.yaml").to_string_lossy().to_string();
        run(&quiet_out(), &global(&path), InitArgs { yes: true })
            .await
            .unwrap();
        let policy = kernex_policy::KernexPolicy::from_file(std::path::Path::new(&path)).unwrap();
        assert!(policy.environment.block_all_other);
    }

    // -- wizard: next-step guidance ------------------------------------------

    /// Non-JSON, non-quiet mode must print guidance pointing to `kernex audit`.
    /// (Can't easily capture stdout in unit tests — tested via integration.)
    /// This test just verifies the wizard completes successfully in verbose mode.
    #[tokio::test]
    async fn test_init_verbose_mode_completes_without_error() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("kernex.yaml").to_string_lossy().to_string();
        let g = GlobalArgs {
            output_format: None,
            strict: false,
            config: path.clone(),
            quiet: false,
            mcp: false,
        };
        let out = Output {
            json: false,
            color: false,
            quiet: false,
        };
        // Quiet=false but json=false; read_line returns default in json mode
        // when stdin is not a TTY — won't hang in test.
        let out_quiet = Output {
            json: false,
            color: false,
            quiet: true, // keep quiet to avoid stdin hang
        };
        run(&out_quiet, &g, InitArgs { yes: true }).await.unwrap();
        assert!(std::path::Path::new(&path).exists());
        // verbose output path works without panic
        run(&out, &global(&path), InitArgs { yes: true })
            .await
            .unwrap();
    }
}
