//! `kernex status` — human-readable policy summary with score.

use crate::cli::{GlobalArgs, StatusArgs};
use crate::output::{Output, ScoreDimensions, StatusJsonOutput};
use crate::policy_io::load_policy;

/// Run `kernex status`.
pub async fn run(out: &Output, global: &GlobalArgs, _args: StatusArgs) -> anyhow::Result<()> {
    let policy = load_policy(&global.config)?;
    let score = policy.score();

    if out.json {
        out.emit_json(&StatusJsonOutput {
            command: "status",
            config_path: global.config.clone(),
            score: score.total,
            dimensions: ScoreDimensions {
                path_specificity: score.path_specificity,
                network_surface: score.network_surface,
                environment_exposure: score.environment_exposure,
                hidden_protection: score.hidden_protection,
                resource_limits: score.resource_limits,
            },
            findings: score.findings.clone(),
        });
        return Ok(());
    }

    // ── Human-readable output ────────────────────────────────────────────────

    out.print(&format!(
        "Policy: {}  (score: {}/100)\n",
        global.config, score.total
    ));

    // Filesystem
    out.print("Filesystem");
    let reads: Vec<String> = policy
        .filesystem
        .allow_read
        .iter()
        .map(|p| p.display().to_string())
        .collect();
    if reads.is_empty() {
        out.print("  ✓  Can read:   (none)");
    } else {
        out.print(&format!("  ✓  Can read:   {}", reads.join(", ")));
    }
    let writes: Vec<String> = policy
        .filesystem
        .allow_write
        .iter()
        .map(|p| p.display().to_string())
        .collect();
    if writes.is_empty() {
        out.print("  ✓  Can write:  (none)");
    } else {
        out.print(&format!("  ✓  Can write:  {}", writes.join(", ")));
    }
    if policy.filesystem.block_hidden {
        out.print("  ✗  Blocked:    all other paths, all hidden directories (.ssh, .aws, …)");
    } else {
        out.print("  ✗  Blocked:    all other paths (hidden directories NOT blocked)");
    }

    // Network
    out.print("\nNetwork");
    if policy.network.allow_outbound.is_empty() {
        out.print("  ✗  Blocked:    all outbound");
    } else {
        let hosts: Vec<String> = policy
            .network
            .allow_outbound
            .iter()
            .map(|r| format!("{}:{}", r.host, r.port))
            .collect();
        out.print(&format!("  ✓  Allowed:    {}", hosts.join(", ")));
        if policy.network.block_all_other {
            out.print("  ✗  Blocked:    all other outbound");
        } else {
            out.print("  ⚠  Allowed:    all other outbound (block_all_other: false)");
        }
    }

    // Environment
    out.print("\nEnvironment");
    if policy.environment.allow_read.is_empty() {
        out.print("  ✓  Readable:   (none)");
    } else {
        out.print(&format!(
            "  ✓  Readable:   {}",
            policy.environment.allow_read.join(", ")
        ));
    }
    if policy.environment.block_all_other {
        out.print("  ✗  Blocked:    all other environment variables");
    } else {
        out.print("  ⚠  Not blocked: agent can read all environment variables");
    }

    // Resource limits
    out.print("\nResource limits");
    if let Some(limits) = &policy.resource_limits {
        if let Some(mb) = limits.max_memory_mb {
            out.print(&format!("  ✓  Memory:     {mb} MB"));
        }
        if let Some(cpu) = limits.max_cpu_percent {
            out.print(&format!("  ✓  CPU:        {cpu}%"));
        }
        if let Some(procs) = limits.max_procs {
            out.print(&format!("  ✓  Procs:      {procs}"));
        }
        if let Some(disk) = limits.max_disk_write_mb_per_min {
            out.print(&format!("  ✓  Disk I/O:   {disk} MB/min"));
        }
    } else {
        out.print("  ⚠  Not configured — agent can consume unlimited resources");
    }

    // Recommendations
    if !score.findings.is_empty() {
        out.print("\nRecommendations:");
        for finding in &score.findings {
            out.print(&format!("  →  {finding}"));
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::io::Write as _;

    use super::*;
    use crate::cli::{GlobalArgs, StatusArgs};

    fn quiet_out() -> Output {
        Output {
            json: false,
            color: false,
            quiet: true,
        }
    }

    fn global(path: &str) -> GlobalArgs {
        GlobalArgs {
            output_format: None,
            strict: false,
            config: path.to_string(),
            quiet: true,
            mcp: false,
        }
    }

    #[tokio::test]
    async fn test_status_fails_for_missing_file() {
        let g = global("/nonexistent/kernex.yaml");
        let result = run(&quiet_out(), &g, StatusArgs {}).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_status_succeeds_for_valid_policy() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("kernex.yaml");
        let mut f = std::fs::File::create(&path).unwrap();
        writeln!(f, "agent_name: test-agent").unwrap();
        drop(f);
        let g = global(&path.to_string_lossy());
        let result = run(&quiet_out(), &g, StatusArgs {}).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_status_json_output_has_required_fields() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("kernex.yaml");
        let mut f = std::fs::File::create(&path).unwrap();
        writeln!(f, "agent_name: test-agent").unwrap();
        drop(f);
        let g = GlobalArgs {
            output_format: Some(crate::cli::OutputFormat::Json),
            strict: false,
            config: path.to_string_lossy().to_string(),
            quiet: false,
            mcp: false,
        };
        // JSON output goes to stdout — just verify it doesn't error.
        let out = Output {
            json: true,
            color: false,
            quiet: false,
        };
        let result = run(&out, &g, StatusArgs {}).await;
        assert!(result.is_ok());
    }
}
