use std::path::Path;

use crate::types::{
    EnvironmentPolicy, FilesystemPolicy, KernexPolicy, NetworkPolicy, ResourceLimits,
};

/// The five-dimension policy score returned by `KernexPolicy::score()`.
///
/// Each dimension contributes 0–20 points; `total` is their sum (0–100).
/// `findings` contains human-readable explanations for any deductions,
/// suitable for display by `kernex status`.
#[derive(Debug, Clone, PartialEq)]
pub struct PolicyScore {
    pub total: u8,
    pub path_specificity: u8,
    pub network_surface: u8,
    pub environment_exposure: u8,
    pub hidden_protection: u8,
    pub resource_limits: u8,
    pub findings: Vec<String>,
}

/// Compute the five-dimension security score for a policy.
///
/// Scoring algorithm (from policy-engine skill):
///
/// | Dimension              | 20 pts                                | 10 pts                         | 0 pts                            |
/// |------------------------|---------------------------------------|--------------------------------|----------------------------------|
/// | Path specificity       | All paths project-relative            | Some absolute paths            | `allow_read: ["/"]`              |
/// | Network surface        | Specific hosts + rate limits          | Specific hosts, no rate limits | `block_all_other: false`         |
/// | Environment exposure   | Allowlist + `block_all_other: true`   | Allowlist, no block_all_other  | No policy (block_all_other false + empty list) |
/// | Hidden dir protection  | `block_hidden: true`                  | —                              | `block_hidden: false`            |
/// | Resource limits        | 5 pts per limit defined (×4)          | —                              | No limits section                |
pub fn score_policy(policy: &KernexPolicy) -> PolicyScore {
    let mut findings = Vec::new();

    let path_specificity = score_path_specificity(&policy.filesystem, &mut findings);
    let network_surface = score_network_surface(&policy.network, &mut findings);
    let environment_exposure = score_environment(&policy.environment, &mut findings);
    let hidden_protection = score_hidden_protection(&policy.filesystem, &mut findings);
    let resource_limits = score_resource_limits(policy.resource_limits.as_ref(), &mut findings);

    let total = path_specificity
        + network_surface
        + environment_exposure
        + hidden_protection
        + resource_limits;

    PolicyScore {
        total,
        path_specificity,
        network_surface,
        environment_exposure,
        hidden_protection,
        resource_limits,
        findings,
    }
}

// ---------------------------------------------------------------------------
// Dimension scorers
// ---------------------------------------------------------------------------

fn score_path_specificity(fs: &FilesystemPolicy, findings: &mut Vec<String>) -> u8 {
    let has_root = fs.allow_read.iter().any(|p| p == Path::new("/"));
    if has_root {
        findings.push(
            "filesystem: allow_read contains '/' — grants unrestricted filesystem read access; \
             use project-relative paths instead"
                .to_string(),
        );
        return 0;
    }

    let has_absolute = fs.allow_read.iter().any(|p| p.is_absolute());
    if has_absolute {
        findings.push(
            "filesystem: allow_read contains absolute paths; \
             use relative paths (e.g. ./src) for better specificity"
                .to_string(),
        );
        return 10;
    }

    20
}

fn score_network_surface(net: &NetworkPolicy, findings: &mut Vec<String>) -> u8 {
    if !net.block_all_other {
        findings.push(
            "network: block_all_other is false — all outbound connections are permitted; \
             set block_all_other: true and list only required hosts"
                .to_string(),
        );
        return 0;
    }

    // block_all_other: true — check rate limits on each allowed rule
    if net.allow_outbound.is_empty() {
        // Fully blocked — perfect network restriction
        return 20;
    }

    let all_rate_limited = net
        .allow_outbound
        .iter()
        .all(|r| r.max_requests_per_minute.is_some());
    if all_rate_limited {
        20
    } else {
        findings.push(
            "network: one or more outbound rules have no max_requests_per_minute rate limit; \
             add rate limits to all rules for full score"
                .to_string(),
        );
        10
    }
}

fn score_environment(env: &EnvironmentPolicy, findings: &mut Vec<String>) -> u8 {
    if env.block_all_other {
        // Whether or not allow_read is empty, block_all_other: true is the most
        // restrictive posture — score full points.
        return 20;
    }

    if !env.allow_read.is_empty() {
        // Explicit allowlist exists but block_all_other is off — partial credit
        findings.push(
            "environment: block_all_other is false — agent can read environment variables \
             beyond the explicit allow_read list; set block_all_other: true"
                .to_string(),
        );
        return 10;
    }

    // No allowlist and no blocking — effectively no environment policy
    findings.push(
        "environment: no policy defined — agent can read all environment variables; \
         add an allow_read list and set block_all_other: true"
            .to_string(),
    );
    0
}

fn score_hidden_protection(fs: &FilesystemPolicy, findings: &mut Vec<String>) -> u8 {
    if fs.block_hidden {
        return 20;
    }
    findings.push(
        "filesystem: block_hidden is false — agent can access hidden directories \
         (.ssh, .aws, .gnupg, …); re-enable block_hidden or document the reason"
            .to_string(),
    );
    0
}

fn score_resource_limits(limits: Option<&ResourceLimits>, findings: &mut Vec<String>) -> u8 {
    let Some(l) = limits else {
        findings.push(
            "resource_limits: not configured — agent can consume unlimited memory, CPU, \
             processes, and disk I/O; add a resource_limits section"
                .to_string(),
        );
        return 0;
    };

    let mut score: u8 = 0;
    let mut missing: Vec<&str> = Vec::new();

    if l.max_memory_mb.is_some() {
        score += 5;
    } else {
        missing.push("max_memory_mb");
    }
    if l.max_cpu_percent.is_some() {
        score += 5;
    } else {
        missing.push("max_cpu_percent");
    }
    if l.max_procs.is_some() {
        score += 5;
    } else {
        missing.push("max_procs");
    }
    if l.max_disk_write_mb_per_min.is_some() {
        score += 5;
    } else {
        missing.push("max_disk_write_mb_per_min");
    }

    if !missing.is_empty() {
        findings.push(format!(
            "resource_limits: missing {} limit(s): {} — add them for a full score",
            missing.len(),
            missing.join(", ")
        ));
    }

    score
}

// ---------------------------------------------------------------------------
// Tests — Red phase: written before implementation
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;
    use crate::types::{
        EnvironmentPolicy, FilesystemPolicy, KernexPolicy, NetworkPolicy, NetworkRule,
        ResourceLimits,
    };

    fn minimal_policy() -> KernexPolicy {
        KernexPolicy {
            version: 1,
            agent_name: "test-agent".to_string(),
            filesystem: FilesystemPolicy::default(),
            network: NetworkPolicy::default(),
            environment: EnvironmentPolicy::default(),
            resource_limits: None,
            mcp_servers: vec![],
        }
    }

    // --- path_specificity ---------------------------------------------------

    #[test]
    fn test_score_relative_paths_give_20_path_specificity() {
        let mut policy = minimal_policy();
        policy.filesystem.allow_read = vec![PathBuf::from("./src"), PathBuf::from("./data")];
        let score = score_policy(&policy);
        assert_eq!(score.path_specificity, 20);
    }

    #[test]
    fn test_score_absolute_paths_give_10_path_specificity() {
        let mut policy = minimal_policy();
        policy.filesystem.allow_read = vec![PathBuf::from("/home/user/project")];
        let score = score_policy(&policy);
        assert_eq!(score.path_specificity, 10);
    }

    #[test]
    fn test_score_root_read_gives_0_path_specificity() {
        let mut policy = minimal_policy();
        policy.filesystem.allow_read = vec![PathBuf::from("/")];
        let score = score_policy(&policy);
        assert_eq!(score.path_specificity, 0);
    }

    #[test]
    fn test_score_no_read_paths_gives_20_path_specificity() {
        let policy = minimal_policy(); // empty allow_read
        let score = score_policy(&policy);
        assert_eq!(score.path_specificity, 20);
    }

    // --- network_surface ----------------------------------------------------

    #[test]
    fn test_score_block_all_other_false_gives_0_network_surface() {
        let mut policy = minimal_policy();
        policy.network.block_all_other = false;
        let score = score_policy(&policy);
        assert_eq!(score.network_surface, 0);
    }

    #[test]
    fn test_score_blocked_network_no_rules_gives_20_network_surface() {
        let policy = minimal_policy(); // block_all_other: true, no outbound
        let score = score_policy(&policy);
        assert_eq!(score.network_surface, 20);
    }

    #[test]
    fn test_score_rules_with_rate_limits_give_20_network_surface() {
        let mut policy = minimal_policy();
        policy.network.allow_outbound = vec![NetworkRule {
            host: "api.anthropic.com".to_string(),
            port: 443,
            max_requests_per_minute: Some(60),
            max_payload_bytes: None,
        }];
        let score = score_policy(&policy);
        assert_eq!(score.network_surface, 20);
    }

    #[test]
    fn test_score_rules_without_rate_limits_give_10_network_surface() {
        let mut policy = minimal_policy();
        policy.network.allow_outbound = vec![NetworkRule {
            host: "api.anthropic.com".to_string(),
            port: 443,
            max_requests_per_minute: None,
            max_payload_bytes: None,
        }];
        let score = score_policy(&policy);
        assert_eq!(score.network_surface, 10);
    }

    // --- environment_exposure -----------------------------------------------

    #[test]
    fn test_score_block_all_other_true_gives_20_environment() {
        let policy = minimal_policy(); // block_all_other: true by default
        let score = score_policy(&policy);
        assert_eq!(score.environment_exposure, 20);
    }

    #[test]
    fn test_score_allowlist_without_block_gives_10_environment() {
        let mut policy = minimal_policy();
        policy.environment.block_all_other = false;
        policy.environment.allow_read = vec!["ANTHROPIC_API_KEY".to_string()];
        let score = score_policy(&policy);
        assert_eq!(score.environment_exposure, 10);
    }

    #[test]
    fn test_score_no_env_policy_gives_0_environment() {
        let mut policy = minimal_policy();
        policy.environment.block_all_other = false;
        policy.environment.allow_read = vec![];
        let score = score_policy(&policy);
        assert_eq!(score.environment_exposure, 0);
    }

    // --- hidden_protection --------------------------------------------------

    #[test]
    fn test_score_block_hidden_true_gives_20_hidden_protection() {
        let policy = minimal_policy();
        assert!(policy.filesystem.block_hidden);
        let score = score_policy(&policy);
        assert_eq!(score.hidden_protection, 20);
    }

    #[test]
    fn test_score_block_hidden_false_gives_0_hidden_protection() {
        let mut policy = minimal_policy();
        policy.filesystem.block_hidden = false;
        let score = score_policy(&policy);
        assert_eq!(score.hidden_protection, 0);
    }

    // --- resource_limits ----------------------------------------------------

    #[test]
    fn test_score_no_resource_limits_gives_0() {
        let policy = minimal_policy();
        let score = score_policy(&policy);
        assert_eq!(score.resource_limits, 0);
    }

    #[test]
    fn test_score_each_resource_limit_is_worth_5_points() {
        let mut policy = minimal_policy();
        policy.resource_limits = Some(ResourceLimits {
            max_memory_mb: Some(512),
            max_cpu_percent: None,
            max_procs: None,
            max_disk_write_mb_per_min: None,
        });
        let score = score_policy(&policy);
        assert_eq!(score.resource_limits, 5);
    }

    #[test]
    fn test_score_all_resource_limits_gives_20() {
        let mut policy = minimal_policy();
        policy.resource_limits = Some(ResourceLimits {
            max_memory_mb: Some(512),
            max_cpu_percent: Some(50),
            max_procs: Some(64),
            max_disk_write_mb_per_min: Some(100),
        });
        let score = score_policy(&policy);
        assert_eq!(score.resource_limits, 20);
    }

    // --- total --------------------------------------------------------------

    #[test]
    fn test_score_total_is_sum_of_dimensions() {
        let policy = minimal_policy();
        let score = score_policy(&policy);
        let expected = score.path_specificity
            + score.network_surface
            + score.environment_exposure
            + score.hidden_protection
            + score.resource_limits;
        assert_eq!(score.total, expected);
    }

    #[test]
    fn test_score_perfect_policy_reaches_100() {
        let policy = KernexPolicy {
            version: 1,
            agent_name: "perfect-agent".to_string(),
            filesystem: FilesystemPolicy {
                allow_read: vec![PathBuf::from("./src"), PathBuf::from("./data")],
                allow_write: vec![PathBuf::from("./src/output")],
                block_hidden: true,
                allow_hidden_reason: None,
            },
            network: NetworkPolicy {
                allow_outbound: vec![NetworkRule {
                    host: "api.anthropic.com".to_string(),
                    port: 443,
                    max_requests_per_minute: Some(60),
                    max_payload_bytes: Some(1_048_576),
                }],
                block_all_other: true,
            },
            environment: EnvironmentPolicy {
                allow_read: vec!["ANTHROPIC_API_KEY".to_string()],
                block_all_other: true,
            },
            resource_limits: Some(ResourceLimits {
                max_memory_mb: Some(512),
                max_cpu_percent: Some(50),
                max_procs: Some(64),
                max_disk_write_mb_per_min: Some(100),
            }),
            mcp_servers: vec![],
        };
        let score = score_policy(&policy);
        assert_eq!(
            score.total, 100,
            "a fully specified safe policy should score 100; findings: {:?}",
            score.findings
        );
    }

    #[test]
    fn test_score_findings_non_empty_for_unsafe_policy() {
        let mut policy = minimal_policy();
        policy.filesystem.allow_read = vec![PathBuf::from("/")];
        policy.network.block_all_other = false;
        let score = score_policy(&policy);
        assert!(
            !score.findings.is_empty(),
            "unsafe policy should produce findings"
        );
    }

    // --- YAML pipeline (parse → score) --------------------------------------

    #[test]
    fn test_score_yaml_pipeline_minimal_policy_parses_and_scores() {
        let yaml = "agent_name: my-agent\n";
        let policy: KernexPolicy = yaml.parse().expect("minimal YAML should parse");
        let score = score_policy(&policy);
        // minimal policy: no read paths (20 pts), network blocked (20 pts),
        // env default block_all_other=false (0 pts), block_hidden=true (20 pts),
        // no resource limits (0 pts) = 60 pts
        assert!(
            score.total <= 100,
            "score must be in range 0-100, got {}",
            score.total
        );
    }

    #[test]
    fn test_score_yaml_pipeline_root_read_gives_zero_path_specificity() {
        let yaml = "\
agent_name: agent
filesystem:
  allow_read:
    - /
  block_hidden: true
";
        let policy: KernexPolicy = yaml.parse().expect("YAML should parse");
        let score = score_policy(&policy);
        assert_eq!(
            score.path_specificity, 0,
            "root read must produce 0 path_specificity"
        );
    }

    #[test]
    fn test_score_yaml_pipeline_relative_paths_give_20_path_specificity() {
        let yaml = "\
agent_name: agent
filesystem:
  allow_read:
    - ./src
    - ./data
  block_hidden: true
";
        let policy: KernexPolicy = yaml.parse().expect("YAML should parse");
        let score = score_policy(&policy);
        assert_eq!(
            score.path_specificity, 20,
            "relative paths must produce 20 path_specificity"
        );
    }

    #[test]
    fn test_score_yaml_pipeline_full_policy_reaches_100() {
        let yaml = "\
agent_name: agent
filesystem:
  allow_read:
    - ./src
  block_hidden: true
network:
  block_all_other: true
  allow_outbound:
    - host: api.example.com
      port: 443
      max_requests_per_minute: 100
environment:
  allow_read:
    - MY_VAR
  block_all_other: true
resource_limits:
  max_memory_mb: 512
  max_cpu_percent: 50
  max_procs: 64
  max_disk_write_mb_per_min: 100
";
        let policy: KernexPolicy = yaml.parse().expect("full policy YAML should parse");
        let score = score_policy(&policy);
        assert_eq!(
            score.total, 100,
            "fully-specified safe policy must reach 100; findings: {:?}",
            score.findings
        );
    }

    #[test]
    fn test_score_yaml_pipeline_findings_match_deductions() {
        let yaml = "\
agent_name: agent
filesystem:
  allow_read:
    - /
  block_hidden: false
network:
  block_all_other: false
";
        let policy: KernexPolicy = yaml.parse().expect("YAML should parse");
        let score = score_policy(&policy);
        // Three deductions: path=0, hidden=0, network=0 → each should produce a finding
        assert!(
            score.findings.len() >= 3,
            "expected at least 3 findings for unsafe policy, got {:?}",
            score.findings
        );
    }

    #[test]
    fn test_score_yaml_pipeline_resource_limits_each_worth_5() {
        let yaml_base = "\
agent_name: agent
resource_limits:
  max_memory_mb: 512
";
        let policy: KernexPolicy = yaml_base.parse().expect("YAML should parse");
        let score = score_policy(&policy);
        assert_eq!(
            score.resource_limits, 5,
            "one resource limit should give 5 pts, got {}",
            score.resource_limits
        );
    }
}
