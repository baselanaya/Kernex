//! Policy file loading, validation, and PolicyCandidate → KernexPolicy conversion.

use std::path::Path;

use kernex_audit::observation::ObservedResource;
use kernex_audit::PolicyCandidate;
use kernex_policy::{
    EnvironmentPolicy, FilesystemPolicy, KernexPolicy, NetworkPolicy, NetworkRule,
};

// ---------------------------------------------------------------------------
// Policy loading
// ---------------------------------------------------------------------------

/// Load and validate `kernex.yaml` from `path`.
///
/// Returns the parsed policy. Validation warnings are returned separately
/// so the caller can display them before proceeding.
///
/// # Errors
///
/// Returns an `anyhow::Error` if the file cannot be read or the YAML is invalid.
pub fn load_policy(path: &str) -> anyhow::Result<KernexPolicy> {
    let p = Path::new(path);
    if !p.exists() {
        anyhow::bail!(
            "kernex.yaml not found at '{path}'.\n\
             Run `kernex init` to generate a policy, or\n\
             `kernex audit -- <cmd>` to profile your agent first."
        );
    }
    let policy =
        KernexPolicy::from_file(p).map_err(|e| anyhow::anyhow!("Failed to parse '{path}': {e}"))?;
    Ok(policy)
}

/// Build the human-readable pre-flight warning for a low policy score.
///
/// Returns `None` when the score is ≥ 60 (no warning needed).
pub fn score_warning(policy: &KernexPolicy) -> Option<String> {
    let score = policy.score();
    if score.total >= 60 {
        return None;
    }
    let top_issue = score
        .findings
        .first()
        .map(|f| f.as_str())
        .unwrap_or("review your policy");
    Some(format!(
        "Policy score: {}/100 — {top_issue}. Run `kernex status` for details.",
        score.total
    ))
}

// ---------------------------------------------------------------------------
// PolicyCandidate → KernexPolicy conversion
// ---------------------------------------------------------------------------

/// Convert a [`PolicyCandidate`] from an audit session into a [`KernexPolicy`].
///
/// Sensitive resources must have been explicitly approved by the user before
/// being included in `extra_paths`. This function only converts the
/// non-sensitive [`PolicyCandidate::observations`].
///
/// # Panics
///
/// Never panics.
pub fn candidate_to_policy(
    candidate: &PolicyCandidate,
    extra_reads: &[std::path::PathBuf],
    extra_writes: &[std::path::PathBuf],
) -> KernexPolicy {
    let mut allow_read: Vec<std::path::PathBuf> = Vec::new();
    let mut allow_write: Vec<std::path::PathBuf> = Vec::new();
    let mut allow_outbound: Vec<NetworkRule> = Vec::new();
    let mut allow_env: Vec<String> = Vec::new();

    for obs in &candidate.observations {
        match &obs.resource {
            ObservedResource::FileRead(p) | ObservedResource::FileExec(p) => {
                if !allow_read.contains(p) {
                    allow_read.push(p.clone());
                }
            }
            ObservedResource::FileWrite(p) => {
                if !allow_write.contains(p) {
                    allow_write.push(p.clone());
                }
            }
            ObservedResource::Network { host, port } => {
                let rule = NetworkRule {
                    host: host.clone(),
                    port: *port,
                    max_requests_per_minute: None,
                    max_payload_bytes: None,
                };
                if !allow_outbound
                    .iter()
                    .any(|r| r.host == rule.host && r.port == rule.port)
                {
                    allow_outbound.push(rule);
                }
            }
            ObservedResource::EnvVar(name) => {
                if !allow_env.contains(name) {
                    allow_env.push(name.clone());
                }
            }
        }
    }

    // Merge in explicitly approved extra paths.
    for p in extra_reads {
        if !allow_read.contains(p) {
            allow_read.push(p.clone());
        }
    }
    for p in extra_writes {
        if !allow_write.contains(p) {
            allow_write.push(p.clone());
        }
    }

    KernexPolicy {
        version: 1,
        agent_name: candidate.agent_name.clone(),
        filesystem: FilesystemPolicy {
            allow_read,
            allow_write,
            block_hidden: true,
            allow_hidden_reason: None,
        },
        network: NetworkPolicy {
            allow_outbound,
            block_all_other: true,
        },
        environment: EnvironmentPolicy {
            allow_read: allow_env,
            block_all_other: true,
        },
        resource_limits: None,
        mcp_servers: vec![],
    }
}

/// Generate a minimal starter [`KernexPolicy`] from wizard inputs.
///
/// Used in tests to verify that the annotated YAML produced by
/// `annotated_yaml` round-trips to the same logical policy.
#[cfg(test)]
pub(crate) fn starter_policy(
    agent_name: &str,
    api_hosts: &[(&str, u16)],
    project_dir: &str,
) -> KernexPolicy {
    let allow_read = if project_dir.is_empty() {
        vec![]
    } else {
        vec![std::path::PathBuf::from(project_dir)]
    };

    let allow_outbound = api_hosts
        .iter()
        .map(|(host, port)| NetworkRule {
            host: host.to_string(),
            port: *port,
            max_requests_per_minute: Some(60),
            max_payload_bytes: None,
        })
        .collect();

    KernexPolicy {
        version: 1,
        agent_name: agent_name.to_string(),
        filesystem: FilesystemPolicy {
            allow_read,
            allow_write: vec![],
            block_hidden: true,
            allow_hidden_reason: None,
        },
        network: NetworkPolicy {
            allow_outbound,
            block_all_other: true,
        },
        environment: EnvironmentPolicy {
            allow_read: vec![],
            block_all_other: true,
        },
        resource_limits: None,
        mcp_servers: vec![],
    }
}

/// Serialise `policy` to YAML and write to `path`.
///
/// # Errors
///
/// Returns an error if serialisation or the file write fails.
pub fn write_policy(policy: &KernexPolicy, path: &str) -> anyhow::Result<()> {
    let yaml =
        serde_yaml::to_string(policy).map_err(|e| anyhow::anyhow!("YAML serialisation: {e}"))?;
    std::fs::write(path, yaml).map_err(|e| anyhow::anyhow!("Write '{path}': {e}"))?;
    Ok(())
}

/// Generate an annotated `kernex.yaml` string with inline comments explaining
/// every field.
///
/// This is used by `kernex init` so that the generated file is self-documenting.
/// The YAML is handcrafted rather than machine-generated so that comments are
/// positioned naturally above the fields they describe.
///
/// The returned string is valid YAML that parses into the same policy as
/// `starter_policy(agent_name, api_hosts, project_dir)`.
pub fn annotated_yaml(agent_name: &str, api_hosts: &[(&str, u16)], project_dir: &str) -> String {
    let mut out = String::new();

    out.push_str("# kernex.yaml — generated by `kernex init`\n");
    out.push_str("# Full reference: https://github.com/kernex-io/kernex\n");
    out.push('\n');

    // version + agent_name
    out.push_str("version: 1\n");
    out.push('\n');
    out.push_str("# Human-readable identifier for this agent. Appears in session summaries.\n");
    out.push_str(&format!("agent_name: {agent_name}\n"));
    out.push('\n');

    // filesystem
    out.push_str("filesystem:\n");
    out.push_str(
        "  # Paths the agent is allowed to read. \
         Use project-relative paths (./src) for the best\n",
    );
    out.push_str(
        "  # security score. Landlock enforces this at the kernel level — \
         no code change needed.\n",
    );
    out.push_str("  allow_read:\n");
    if project_dir.is_empty() {
        out.push_str("    [] # add paths here, e.g. - ./src\n");
    } else {
        out.push_str(&format!("    - {project_dir}\n"));
    }
    out.push('\n');
    out.push_str(
        "  # Paths the agent is allowed to write to. \
         Empty means write-nowhere.\n",
    );
    out.push_str("  allow_write: []\n");
    out.push('\n');
    out.push_str("  # Block access to hidden directories (.ssh, .aws, .gnupg, .kube, etc.).\n");
    out.push_str(
        "  # Set to false only if your agent legitimately needs dotfile access \
         (rare).\n",
    );
    out.push_str("  block_hidden: true\n");
    out.push('\n');

    // network
    out.push_str("network:\n");
    out.push_str("  # Allowed outbound connections. Specify host and port precisely.\n");
    out.push_str(
        "  # max_requests_per_minute adds rate limiting \
         and earns a higher security score.\n",
    );
    out.push_str("  allow_outbound:\n");
    if api_hosts.is_empty() {
        out.push_str("    [] # add entries here once you know which APIs your agent calls\n");
    } else {
        for (host, port) in api_hosts {
            out.push_str(&format!("    - host: {host}\n"));
            out.push_str(&format!("      port: {port}\n"));
            out.push_str("      max_requests_per_minute: 60\n");
        }
    }
    out.push('\n');
    out.push_str(
        "  # Deny all outbound connections not listed above. \
         Strongly recommended.\n",
    );
    out.push_str("  block_all_other: true\n");
    out.push('\n');

    // environment
    out.push_str("environment:\n");
    out.push_str("  # Environment variables the agent is allowed to read.\n");
    out.push_str("  # Example: [ANTHROPIC_API_KEY, OPENAI_API_KEY]\n");
    out.push_str("  allow_read: []\n");
    out.push('\n');
    out.push_str(
        "  # Deny all env-var reads not listed above. \
         Prevents credential theft.\n",
    );
    out.push_str("  block_all_other: true\n");
    out.push('\n');

    // resource_limits (commented out — gives the user a template)
    out.push_str(
        "# Resource limits are optional but earn up to 20 security score points \
         (5 per limit).\n",
    );
    out.push_str("# Uncomment and tune the values for your workload:\n");
    out.push_str("# resource_limits:\n");
    out.push_str("#   max_memory_mb: 2048      # hard RSS cap\n");
    out.push_str("#   max_cpu_percent: 80       # 1–99; enforced via cgroups\n");
    out.push_str("#   max_procs: 64             # max concurrent subprocesses\n");
    out.push_str("#   max_disk_write_mb_per_min: 500\n");

    out
}

/// Write an annotated `kernex.yaml` to `path`.
///
/// Equivalent to `write_policy` but includes inline comments explaining every
/// field. Used by `kernex init`.
///
/// # Errors
///
/// Returns an error if the file write fails.
pub fn write_annotated_policy(
    agent_name: &str,
    api_hosts: &[(&str, u16)],
    project_dir: &str,
    path: &str,
) -> anyhow::Result<()> {
    let yaml = annotated_yaml(agent_name, api_hosts, project_dir);
    std::fs::write(path, yaml).map_err(|e| anyhow::anyhow!("Write '{path}': {e}"))?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use kernex_audit::session::{AuditEvent, AuditSession};

    use super::*;

    fn candidate_from_events(events: Vec<AuditEvent>) -> PolicyCandidate {
        let mut s = AuditSession::new();
        for e in events {
            s.record(e);
        }
        s.finish("test-agent")
    }

    // -- load_policy: missing file -------------------------------------------

    #[test]
    fn test_load_policy_missing_file_returns_error_with_guidance() {
        let result = load_policy("/nonexistent/kernex.yaml");
        assert!(result.is_err());
        let msg = result.unwrap_err().to_string();
        assert!(msg.contains("kernex init") || msg.contains("not found"));
    }

    // -- score_warning -------------------------------------------------------

    #[test]
    fn test_score_warning_none_for_high_scoring_policy() {
        let policy = KernexPolicy {
            version: 1,
            agent_name: "agent".to_string(),
            filesystem: FilesystemPolicy {
                allow_read: vec![PathBuf::from("./src")],
                allow_write: vec![],
                block_hidden: true,
                allow_hidden_reason: None,
            },
            network: NetworkPolicy {
                allow_outbound: vec![],
                block_all_other: true,
            },
            environment: kernex_policy::EnvironmentPolicy {
                allow_read: vec![],
                block_all_other: true,
            },
            resource_limits: None,
            mcp_servers: vec![],
        };
        // Score should be high enough (path_spec=20, net=20, env=20, hidden=20, limits=0 = 80)
        assert!(score_warning(&policy).is_none());
    }

    #[test]
    fn test_score_warning_some_for_low_scoring_policy() {
        let mut policy = KernexPolicy {
            version: 1,
            agent_name: "agent".to_string(),
            filesystem: FilesystemPolicy {
                allow_read: vec![PathBuf::from("/")], // root read = 0 pts
                allow_write: vec![],
                block_hidden: false, // 0 pts
                allow_hidden_reason: None,
            },
            network: kernex_policy::NetworkPolicy {
                allow_outbound: vec![],
                block_all_other: false, // 0 pts
            },
            environment: kernex_policy::EnvironmentPolicy {
                allow_read: vec![],
                block_all_other: false, // 0 pts
            },
            resource_limits: None, // 0 pts
            mcp_servers: vec![],
        };
        let warn = score_warning(&mut policy);
        assert!(warn.is_some());
        let msg = warn.unwrap();
        assert!(msg.contains("score"));
    }

    #[test]
    fn test_score_warning_threshold_is_60() {
        // A policy that scores exactly 60 should produce no warning.
        // block_hidden=true (20) + no read paths (20) + network blocked (20) = 60.
        let policy = KernexPolicy {
            version: 1,
            agent_name: "agent".to_string(),
            filesystem: FilesystemPolicy {
                allow_read: vec![],
                allow_write: vec![],
                block_hidden: true,
                allow_hidden_reason: None,
            },
            network: kernex_policy::NetworkPolicy {
                allow_outbound: vec![],
                block_all_other: true,
            },
            environment: kernex_policy::EnvironmentPolicy {
                allow_read: vec![],
                block_all_other: false, // 0 pts
            },
            resource_limits: None, // 0 pts
            mcp_servers: vec![],
        };
        // 20 + 20 + 0 + 20 + 0 = 60
        assert!(
            score_warning(&policy).is_none(),
            "score of 60 should produce no warning"
        );
    }

    #[test]
    fn test_score_warning_message_contains_numeric_score() {
        let policy = KernexPolicy {
            version: 1,
            agent_name: "agent".to_string(),
            filesystem: FilesystemPolicy {
                allow_read: vec![PathBuf::from("/")], // 0 pts
                allow_write: vec![],
                block_hidden: false, // 0 pts
                allow_hidden_reason: None,
            },
            network: kernex_policy::NetworkPolicy {
                allow_outbound: vec![],
                block_all_other: false, // 0 pts
            },
            environment: kernex_policy::EnvironmentPolicy {
                allow_read: vec![],
                block_all_other: false, // 0 pts
            },
            resource_limits: None, // 0 pts
            mcp_servers: vec![],
        };
        let msg = score_warning(&policy).expect("score-0 policy must produce a warning");
        // Must contain a digit (the numeric score)
        assert!(
            msg.chars().any(|c| c.is_ascii_digit()),
            "warning must contain the numeric score, got: {msg:?}"
        );
    }

    #[test]
    fn test_score_warning_message_is_single_line() {
        let policy = KernexPolicy {
            version: 1,
            agent_name: "agent".to_string(),
            filesystem: FilesystemPolicy {
                allow_read: vec![PathBuf::from("/")],
                allow_write: vec![],
                block_hidden: false,
                allow_hidden_reason: None,
            },
            network: kernex_policy::NetworkPolicy {
                allow_outbound: vec![],
                block_all_other: false,
            },
            environment: kernex_policy::EnvironmentPolicy {
                allow_read: vec![],
                block_all_other: false,
            },
            resource_limits: None,
            mcp_servers: vec![],
        };
        let msg = score_warning(&policy).expect("low-score policy must produce a warning");
        assert!(
            !msg.contains('\n'),
            "warning must be a single line (no newlines), got: {msg:?}"
        );
    }

    // -- candidate_to_policy -------------------------------------------------

    #[test]
    fn test_candidate_to_policy_converts_file_reads() {
        let candidate =
            candidate_from_events(vec![AuditEvent::FileRead(PathBuf::from("/tmp/data.csv"))]);
        let policy = candidate_to_policy(&candidate, &[], &[]);
        assert!(policy
            .filesystem
            .allow_read
            .contains(&PathBuf::from("/tmp/data.csv")));
    }

    #[test]
    fn test_candidate_to_policy_converts_file_writes() {
        let candidate = candidate_from_events(vec![AuditEvent::FileWrite(PathBuf::from(
            "/tmp/output.txt",
        ))]);
        let policy = candidate_to_policy(&candidate, &[], &[]);
        assert!(policy
            .filesystem
            .allow_write
            .contains(&PathBuf::from("/tmp/output.txt")));
    }

    #[test]
    fn test_candidate_to_policy_converts_network_connections() {
        let candidate = candidate_from_events(vec![AuditEvent::NetworkConnect {
            host: "api.anthropic.com".to_string(),
            port: 443,
        }]);
        let policy = candidate_to_policy(&candidate, &[], &[]);
        assert!(policy
            .network
            .allow_outbound
            .iter()
            .any(|r| r.host == "api.anthropic.com" && r.port == 443));
    }

    #[test]
    fn test_candidate_to_policy_converts_env_reads() {
        let candidate = candidate_from_events(vec![AuditEvent::EnvVarRead(
            "ANTHROPIC_API_KEY".to_string(),
        )]);
        let policy = candidate_to_policy(&candidate, &[], &[]);
        assert!(policy
            .environment
            .allow_read
            .contains(&"ANTHROPIC_API_KEY".to_string()));
    }

    #[test]
    fn test_candidate_to_policy_block_hidden_is_true_by_default() {
        let candidate = candidate_from_events(vec![]);
        let policy = candidate_to_policy(&candidate, &[], &[]);
        assert!(
            policy.filesystem.block_hidden,
            "block_hidden must default to true"
        );
    }

    #[test]
    fn test_candidate_to_policy_block_all_other_network_is_true() {
        let candidate = candidate_from_events(vec![]);
        let policy = candidate_to_policy(&candidate, &[], &[]);
        assert!(policy.network.block_all_other);
    }

    #[test]
    fn test_candidate_to_policy_preserves_agent_name() {
        let s = AuditSession::new();
        let c = s.finish("my-agent");
        let policy = candidate_to_policy(&c, &[], &[]);
        assert_eq!(policy.agent_name, "my-agent");
    }

    #[test]
    fn test_candidate_to_policy_deduplicates_reads() {
        let candidate = candidate_from_events(vec![
            AuditEvent::FileRead(PathBuf::from("/tmp/a")),
            AuditEvent::FileRead(PathBuf::from("/tmp/a")), // duplicate
        ]);
        let policy = candidate_to_policy(&candidate, &[], &[]);
        let count = policy
            .filesystem
            .allow_read
            .iter()
            .filter(|p| **p == PathBuf::from("/tmp/a"))
            .count();
        assert_eq!(count, 1, "duplicate paths must be deduplicated");
    }

    // -- starter_policy ------------------------------------------------------

    #[test]
    fn test_starter_policy_has_safe_defaults() {
        let policy = starter_policy("my-agent", &[], "");
        assert!(policy.filesystem.block_hidden);
        assert!(policy.network.block_all_other);
        assert!(policy.environment.block_all_other);
    }

    #[test]
    fn test_starter_policy_includes_api_hosts() {
        let policy = starter_policy("agent", &[("api.anthropic.com", 443)], "");
        assert!(policy
            .network
            .allow_outbound
            .iter()
            .any(|r| r.host == "api.anthropic.com" && r.port == 443));
    }

    // -- write_policy --------------------------------------------------------

    #[test]
    fn test_write_policy_roundtrips_correctly() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("kernex.yaml").to_string_lossy().to_string();
        let policy = starter_policy("roundtrip-agent", &[("api.example.com", 443)], "./src");
        write_policy(&policy, &path).unwrap();

        let loaded = KernexPolicy::from_file(std::path::Path::new(&path)).unwrap();
        assert_eq!(policy.agent_name, loaded.agent_name);
        assert_eq!(
            policy.network.allow_outbound.len(),
            loaded.network.allow_outbound.len()
        );
    }

    // -- annotated_yaml ------------------------------------------------------

    #[test]
    fn test_annotated_yaml_contains_comments() {
        let yaml = annotated_yaml("test-agent", &[], "./src");
        assert!(yaml.contains("# "), "annotated YAML must contain comments");
    }

    #[test]
    fn test_annotated_yaml_parses_as_valid_kernex_policy() {
        let yaml = annotated_yaml("test-agent", &[("api.example.com", 443)], "./src");
        let policy: KernexPolicy = yaml
            .parse()
            .unwrap_or_else(|e| panic!("annotated YAML must parse: {e}\n---\n{yaml}"));
        assert_eq!(policy.agent_name, "test-agent");
        assert!(policy.filesystem.block_hidden);
        assert!(policy.network.block_all_other);
        assert!(policy.environment.block_all_other);
        assert_eq!(policy.network.allow_outbound.len(), 1);
        assert_eq!(policy.network.allow_outbound[0].host, "api.example.com");
        assert_eq!(policy.network.allow_outbound[0].port, 443);
    }

    #[test]
    fn test_annotated_yaml_no_internet_has_empty_outbound() {
        let yaml = annotated_yaml("agent", &[], "./src");
        let policy: KernexPolicy = yaml.parse().expect("must parse");
        assert!(policy.network.allow_outbound.is_empty());
        assert!(policy.network.block_all_other);
    }

    #[test]
    fn test_annotated_yaml_project_dir_in_allow_read() {
        let yaml = annotated_yaml("agent", &[], "./my-project");
        let policy: KernexPolicy = yaml.parse().expect("must parse");
        assert!(
            policy
                .filesystem
                .allow_read
                .iter()
                .any(|p| p.to_string_lossy().contains("my-project")),
            "project dir must appear in allow_read"
        );
    }

    #[test]
    fn test_annotated_yaml_empty_project_dir_gives_empty_allow_read() {
        let yaml = annotated_yaml("agent", &[], "");
        let policy: KernexPolicy = yaml.parse().expect("must parse");
        assert!(
            policy.filesystem.allow_read.is_empty(),
            "empty project_dir must produce empty allow_read"
        );
    }

    #[test]
    fn test_annotated_yaml_scores_at_least_60() {
        let yaml = annotated_yaml("agent", &[], "./src");
        let policy: KernexPolicy = yaml.parse().expect("must parse");
        let score = policy.score();
        assert!(
            score.total >= 60,
            "annotated yaml must score ≥ 60/100; got {}/100; findings: {:?}",
            score.total,
            score.findings
        );
    }

    #[test]
    fn test_annotated_yaml_mentions_resource_limits() {
        let yaml = annotated_yaml("agent", &[], "./src");
        assert!(
            yaml.contains("resource_limits"),
            "annotated YAML must include a resource_limits hint"
        );
    }

    #[test]
    fn test_annotated_yaml_rate_limit_on_outbound_rules() {
        let yaml = annotated_yaml("agent", &[("api.example.com", 443)], "./src");
        let policy: KernexPolicy = yaml.parse().expect("must parse");
        let rule = &policy.network.allow_outbound[0];
        assert!(
            rule.max_requests_per_minute.is_some(),
            "outbound rules must include max_requests_per_minute for a higher score"
        );
    }

    // -- write_annotated_policy ----------------------------------------------

    #[test]
    fn test_write_annotated_policy_file_is_parseable() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("kernex.yaml").to_string_lossy().to_string();
        write_annotated_policy("agent", &[("api.example.com", 8080)], "./src", &path).unwrap();

        let policy = KernexPolicy::from_file(std::path::Path::new(&path))
            .unwrap_or_else(|e| panic!("written annotated policy must parse: {e}"));
        assert_eq!(policy.agent_name, "agent");
        assert_eq!(policy.network.allow_outbound[0].host, "api.example.com");
        assert_eq!(policy.network.allow_outbound[0].port, 8080);
    }
}
