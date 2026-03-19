//! `kernex audit -- <cmd>` — observation mode.
//!
//! Runs the agent without enforcement. When the agent exits, any sensitive
//! path warnings are shown, then the new policy is diff'd against the
//! existing one before writing.
//!
//! # Platform note
//!
//! Full syscall interception (ptrace / Endpoint Security) is wired in by the
//! platform adapter crates. Until that integration is complete, the agent runs
//! freely and only environment-variable observations (gathered without kernel
//! support) are recorded. File and network observations require the platform
//! adapter to call `AuditSession::record`.

use std::process::Command;

use kernex_audit::{AuditSession, SensitiveWarning};
use kernex_policy::DiffEntry;

use crate::cli::{AuditArgs, GlobalArgs};
use crate::output::{AuditJsonOutput, Output};
use crate::policy_io::{candidate_to_policy, load_policy, write_policy};

/// Run `kernex audit -- <cmd>`.
pub async fn run(out: &Output, global: &GlobalArgs, args: AuditArgs) -> anyhow::Result<()> {
    let cmd_str = args.command.join(" ");

    if args.command.is_empty() {
        anyhow::bail!("No command specified. Usage: kernex audit -- <cmd>");
    }

    out.info(&format!("Observing: {cmd_str}"));
    out.info("Enforcement is OFF — agent runs with full OS access.");

    // ── Run the agent ────────────────────────────────────────────────────────

    let mut session = AuditSession::new();

    // Observe current environment variables for the policy candidate.
    // Full syscall-level observation requires the platform adapter.
    for (key, _) in std::env::vars() {
        session.record(kernex_audit::AuditEvent::EnvVarRead(key));
    }

    let status = Command::new(&args.command[0])
        .args(&args.command[1..])
        .status()
        .map_err(|e| anyhow::anyhow!("Failed to launch '{}': {e}", args.command[0]))?;

    let exit_code = status.code();
    let candidate = session.finish(&args.command[0]);

    // ── Show sensitive warnings ──────────────────────────────────────────────

    let sensitive_count = candidate.sensitive_warnings.len() as u64;

    for warn in &candidate.sensitive_warnings {
        show_sensitive_warning(out, warn, args.allow_sensitive);
    }

    // ── Build candidate policy ───────────────────────────────────────────────

    // Sensitive resources require --allow-sensitive to be included.
    let extra_reads: Vec<std::path::PathBuf> = if args.allow_sensitive {
        candidate
            .sensitive_warnings
            .iter()
            .filter_map(|w| match &w.resource {
                kernex_audit::SensitiveResource::Path(p) => Some(p.clone()),
                _ => None,
            })
            .collect()
    } else {
        vec![]
    };

    let new_policy = candidate_to_policy(&candidate, &extra_reads, &[]);

    // ── Diff against existing policy (if any) ────────────────────────────────

    let existing_path = std::path::Path::new(&global.config);
    let (policy_written, diff_has_expansions) = if existing_path.exists() {
        match load_policy(&global.config) {
            Ok(old_policy) => {
                let diff = old_policy.diff(&new_policy);

                if diff.is_empty() {
                    out.info("No changes to the existing policy.");
                } else {
                    out.print("\nPolicy diff:");
                    print_diff(out, &diff);

                    if diff.has_scope_expansions() && !args.accept_expansions {
                        out.warn(
                            "Scope expansions detected. \
                             Pass --accept-expansions to apply them.",
                        );
                        return Ok(());
                    }
                }

                let should_write = out.confirm("Apply and write updated policy?", false);
                if !should_write {
                    out.info("Policy not written.");
                    return Ok(());
                }

                write_policy(&new_policy, &global.config)?;
                out.success(&format!("Updated {}", global.config));
                (true, diff.has_scope_expansions())
            }
            Err(_) => {
                // Existing file is unreadable — treat as new.
                write_if_confirmed(out, &new_policy, &global.config, args.accept_expansions)?;
                (true, false)
            }
        }
    } else {
        // No existing policy — show what will be written and confirm.
        out.print(&format!(
            "\nObservations: {} resources",
            candidate.observations.len()
        ));

        let should_write = out.confirm(&format!("Write {}?", global.config), false);
        if !should_write {
            out.info("Policy not written.");
            if out.json {
                emit_json(
                    out,
                    &global.config,
                    &cmd_str,
                    false,
                    0,
                    sensitive_count,
                    false,
                );
            }
            return Ok(());
        }

        write_policy(&new_policy, &global.config)?;
        out.success(&format!("Created {}", global.config));
        (true, false)
    };

    // ── Output ───────────────────────────────────────────────────────────────

    if let Some(code) = exit_code {
        if !out.json {
            out.info(&format!("Agent exited with code {code}"));
        }
    }

    if out.json {
        emit_json(
            out,
            &global.config,
            &cmd_str,
            policy_written,
            candidate.observations.len() as u64,
            sensitive_count,
            diff_has_expansions,
        );
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn show_sensitive_warning(out: &Output, warn: &SensitiveWarning, allow_sensitive: bool) {
    let resource_str = match &warn.resource {
        kernex_audit::SensitiveResource::Path(p) => p.display().to_string(),
        kernex_audit::SensitiveResource::EnvVar(name) => name.clone(),
    };
    out.high_risk(&format!(
        "Agent accessed sensitive resource: {resource_str}"
    ));
    out.warn(&format!("  Reason: {}", warn.reason));
    if allow_sensitive {
        out.warn("  Included in policy (--allow-sensitive is set).");
    } else {
        out.warn("  NOT included. Pass --allow-sensitive to include.");
    }
}

fn print_diff(out: &Output, diff: &kernex_policy::PolicyDiff) {
    for entry in &diff.entries {
        match entry {
            DiffEntry::Added { field, value } => {
                out.print(&format!("+ added:   {field}: [\"{value}\"]"));
            }
            DiffEntry::Removed { field, value } => {
                out.print(&format!("- removed: {field}: [\"{value}\"]"));
            }
            DiffEntry::Changed {
                field,
                old_value,
                new_value,
                is_scope_expansion,
            } => {
                let marker = if *is_scope_expansion {
                    "  ⚠ scope expansion"
                } else {
                    ""
                };
                out.print(&format!(
                    "~ changed: {field}: {old_value} → {new_value}{marker}"
                ));
            }
        }
    }
}

fn write_if_confirmed(
    out: &Output,
    policy: &kernex_policy::KernexPolicy,
    path: &str,
    accept_expansions: bool,
) -> anyhow::Result<()> {
    if !accept_expansions && !out.confirm(&format!("Write {path}?"), false) {
        out.info("Policy not written.");
        return Ok(());
    }
    write_policy(policy, path)?;
    out.success(&format!("Created {path}"));
    Ok(())
}

fn emit_json(
    out: &Output,
    config_path: &str,
    agent: &str,
    policy_written: bool,
    observations: u64,
    sensitive_warnings: u64,
    diff_has_expansions: bool,
) {
    out.emit_json(&AuditJsonOutput {
        command: "audit",
        agent: agent.to_string(),
        policy_written,
        config_path: config_path.to_string(),
        observations,
        sensitive_warnings,
        diff_has_expansions,
    });
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::{AuditArgs, GlobalArgs};

    fn quiet_out() -> Output {
        Output {
            json: false,
            color: false,
            quiet: true,
        }
    }

    fn global(config: &str) -> GlobalArgs {
        GlobalArgs {
            output_format: None,
            strict: false,
            config: config.to_string(),
            quiet: true,
            mcp: false,
        }
    }

    #[tokio::test]
    async fn test_audit_empty_command_returns_error() {
        let dir = tempfile::tempdir().unwrap();
        let config = dir.path().join("kernex.yaml").to_string_lossy().to_string();
        let g = global(&config);
        let args = AuditArgs {
            command: vec![],
            accept_expansions: false,
            allow_sensitive: false,
        };
        let result = run(&quiet_out(), &g, args).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_audit_nonexistent_command_returns_error() {
        let dir = tempfile::tempdir().unwrap();
        let config = dir.path().join("kernex.yaml").to_string_lossy().to_string();
        let g = global(&config);
        let args = AuditArgs {
            command: vec!["__nonexistent_command__".to_string()],
            accept_expansions: false,
            allow_sensitive: false,
        };
        let result = run(&quiet_out(), &g, args).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_audit_writes_policy_in_quiet_mode() {
        // quiet mode: confirm returns true (default_no=false → !false = true).
        let dir = tempfile::tempdir().unwrap();
        let config = dir.path().join("kernex.yaml").to_string_lossy().to_string();
        let g = global(&config);
        let args = AuditArgs {
            command: vec!["true".to_string()], // always succeeds
            accept_expansions: false,
            allow_sensitive: false,
        };
        run(&quiet_out(), &g, args).await.unwrap();
        assert!(std::path::Path::new(&config).exists());
    }

    /// Regression test for: agent_name was incorrectly set to the config file
    /// path (`./kernex.yaml`) instead of the audited command (`true`).
    #[tokio::test]
    async fn test_audit_agent_name_is_command_not_config_path() {
        let dir = tempfile::tempdir().unwrap();
        let config = dir.path().join("kernex.yaml").to_string_lossy().to_string();
        let g = global(&config);
        let args = AuditArgs {
            command: vec!["true".to_string()],
            accept_expansions: false,
            allow_sensitive: false,
        };
        run(&quiet_out(), &g, args).await.unwrap();
        let content = std::fs::read_to_string(&config).unwrap();
        // serde_yaml quotes 'true' because it is a YAML boolean keyword.
        // Accept either form; the important invariant is that the command name
        // is present and the config file path is not.
        assert!(
            content.contains("agent_name:") && (content.contains("'true'") || content.contains("true")),
            "agent_name must be the command ('true'), not the config path; got:\n{content}"
        );
        assert!(
            !content.contains("kernex.yaml"),
            "agent_name must not contain the config path; got:\n{content}"
        );
    }

    #[tokio::test]
    async fn test_audit_updates_existing_policy_in_quiet_mode() {
        let dir = tempfile::tempdir().unwrap();
        let config = dir.path().join("kernex.yaml").to_string_lossy().to_string();
        // Write an initial policy.
        std::fs::write(&config, "agent_name: test-agent\n").unwrap();

        let g = global(&config);
        let args = AuditArgs {
            command: vec!["true".to_string()],
            accept_expansions: true,
            allow_sensitive: false,
        };
        run(&quiet_out(), &g, args).await.unwrap();
        // Policy should still exist.
        assert!(std::path::Path::new(&config).exists());
    }
}
