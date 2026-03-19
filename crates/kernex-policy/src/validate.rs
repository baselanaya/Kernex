use std::path::Path;

use crate::{
    error::{PolicyError, PolicyWarning, ValidationReport},
    types::{FilesystemPolicy, KernexPolicy, McpServerPolicy, McpTransport, NetworkPolicy},
};

// ---------------------------------------------------------------------------
// Sensitive path / env-var patterns (from policy-engine skill)
// ---------------------------------------------------------------------------

const SENSITIVE_FS_SUFFIXES: &[&str] = &[
    ".ssh",
    ".aws",
    ".gnupg",
    ".kube",
    ".netrc",
    ".config/gcloud",
    ".config/gh",
    "etc/passwd",
    "etc/shadow",
    "etc/sudoers",
];

const SENSITIVE_ENV_PREFIXES: &[&str] = &[
    "AWS_",
    "GOOGLE_",
    "GITHUB_TOKEN",
    "NPM_TOKEN",
    "DATABASE_URL",
    "SECRET",
    "PASSWORD",
    "PRIVATE_KEY",
];

// ---------------------------------------------------------------------------
// Public entry point
// ---------------------------------------------------------------------------

/// Validate a parsed `KernexPolicy`.
///
/// Returns `Ok(ValidationReport)` with any non-fatal warnings, or
/// `Err(PolicyError)` on a hard validation failure that must be fixed before
/// the policy can be applied.
pub fn validate_policy(policy: &KernexPolicy) -> Result<ValidationReport, PolicyError> {
    if policy.agent_name.trim().is_empty() {
        return Err(PolicyError::MissingField("agent_name".to_string()));
    }

    let mut report = ValidationReport::default();

    validate_filesystem(&policy.filesystem, &mut report)?;
    validate_network(&policy.network, &mut report)?;
    validate_environment_vars(&policy.environment.allow_read, &mut report);

    if let Some(limits) = &policy.resource_limits {
        if let Some(cpu) = limits.max_cpu_percent {
            if cpu == 0 || cpu >= 100 {
                return Err(PolicyError::ValidationError(format!(
                    "resource_limits.max_cpu_percent must be 1–99, got {cpu}"
                )));
            }
        }
    }

    for server in &policy.mcp_servers {
        validate_mcp_server(server, &mut report)?;
    }

    Ok(report)
}

// ---------------------------------------------------------------------------
// Sub-validators
// ---------------------------------------------------------------------------

fn validate_filesystem(
    fs: &FilesystemPolicy,
    report: &mut ValidationReport,
) -> Result<(), PolicyError> {
    for path in &fs.allow_read {
        // Rule 1: root read access
        if path == Path::new("/") {
            report.warnings.push(PolicyWarning::RootReadAccess);
        }
        // Rule 7: absolute paths (not root — root already flagged above)
        if path.is_absolute() && path != Path::new("/") {
            report
                .warnings
                .push(PolicyWarning::AbsoluteReadPath(path.clone()));
        }
        // Sensitive path check
        if is_sensitive_fs_path(path) {
            report
                .warnings
                .push(PolicyWarning::SensitivePath(path.clone()));
        }
    }

    // Rule 2: every allow_write path must be covered by an allow_read entry
    for write_path in &fs.allow_write {
        if !is_covered_by_read_scope(write_path, &fs.allow_read) {
            report.warnings.push(PolicyWarning::WriteOutsideReadScope {
                write_path: write_path.clone(),
            });
        }
    }

    // Rule 3: block_hidden: false requires a written reason
    if !fs.block_hidden && fs.allow_hidden_reason.is_none() {
        report
            .warnings
            .push(PolicyWarning::BlockHiddenDisabledWithoutReason);
    }

    Ok(())
}

fn validate_network(net: &NetworkPolicy, report: &mut ValidationReport) -> Result<(), PolicyError> {
    for rule in &net.allow_outbound {
        match rule.max_requests_per_minute {
            Some(0) => {
                return Err(PolicyError::ValidationError(format!(
                    "network rule for '{}': max_requests_per_minute must be > 0",
                    rule.host
                )));
            }
            None => {
                report.warnings.push(PolicyWarning::NoRateLimit {
                    host: rule.host.clone(),
                });
            }
            Some(_) => {}
        }
    }
    Ok(())
}

fn validate_environment_vars(allow_read: &[String], report: &mut ValidationReport) {
    for var in allow_read {
        let upper = var.to_uppercase();
        if SENSITIVE_ENV_PREFIXES
            .iter()
            .any(|p| upper.starts_with(p) || upper == *p)
        {
            report
                .warnings
                .push(PolicyWarning::SensitiveEnvVar(var.clone()));
        }
    }
}

fn validate_mcp_server(
    server: &McpServerPolicy,
    report: &mut ValidationReport,
) -> Result<(), PolicyError> {
    // Rule 4: HTTP transport requires an endpoint URL
    if server.transport == McpTransport::Http && server.endpoint.is_none() {
        return Err(PolicyError::MissingField(format!(
            "mcp_server '{}': endpoint is required for http transport",
            server.name
        )));
    }

    validate_filesystem(&server.policy.filesystem, report)?;
    validate_network(&server.policy.network, report)?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn is_covered_by_read_scope(write_path: &Path, read_paths: &[std::path::PathBuf]) -> bool {
    read_paths.iter().any(|r| write_path.starts_with(r))
}

fn is_sensitive_fs_path(path: &Path) -> bool {
    let s = path.to_string_lossy().to_lowercase();
    // Strip leading `~/` so `~/.ssh` and `/home/user/.ssh` both match
    let s = s.trim_start_matches("~/").trim_start_matches('/');
    SENSITIVE_FS_SUFFIXES
        .iter()
        .any(|pattern| s.starts_with(pattern) || s.contains(&format!("/{}", pattern)))
}

// ---------------------------------------------------------------------------
// Tests — Red phase first, then green
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;
    use crate::types::{
        EnvironmentPolicy, FilesystemPolicy, KernexPolicy, McpPolicy, McpServerPolicy,
        McpTransport, NetworkPolicy, NetworkRule, ResourceLimits,
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

    // --- agent_name ---------------------------------------------------------

    #[test]
    fn test_validate_empty_agent_name_returns_missing_field() {
        let mut policy = minimal_policy();
        policy.agent_name = "".to_string();
        let err = policy.validate().unwrap_err();
        assert!(matches!(err, PolicyError::MissingField(_)));
    }

    #[test]
    fn test_validate_whitespace_agent_name_returns_missing_field() {
        let mut policy = minimal_policy();
        policy.agent_name = "   ".to_string();
        assert!(matches!(
            policy.validate().unwrap_err(),
            PolicyError::MissingField(_)
        ));
    }

    #[test]
    fn test_validate_valid_agent_name_passes() {
        let policy = minimal_policy();
        assert!(policy.validate().is_ok());
    }

    // --- filesystem ---------------------------------------------------------

    #[test]
    fn test_validate_root_read_access_emits_warning() {
        let mut policy = minimal_policy();
        policy.filesystem.allow_read = vec![PathBuf::from("/")];
        let report = policy.validate().unwrap();
        assert!(report.warnings.contains(&PolicyWarning::RootReadAccess));
    }

    #[test]
    fn test_validate_absolute_read_path_emits_warning() {
        let mut policy = minimal_policy();
        policy.filesystem.allow_read = vec![PathBuf::from("/home/user/project")];
        let report = policy.validate().unwrap();
        assert!(report
            .warnings
            .contains(&PolicyWarning::AbsoluteReadPath(PathBuf::from(
                "/home/user/project"
            ))));
    }

    #[test]
    fn test_validate_relative_read_path_no_warning() {
        let mut policy = minimal_policy();
        policy.filesystem.allow_read = vec![PathBuf::from("./src")];
        let report = policy.validate().unwrap();
        assert!(!report
            .warnings
            .iter()
            .any(|w| matches!(w, PolicyWarning::AbsoluteReadPath(_))));
    }

    #[test]
    fn test_validate_write_outside_read_scope_emits_warning() {
        let mut policy = minimal_policy();
        policy.filesystem.allow_read = vec![PathBuf::from("./src")];
        policy.filesystem.allow_write = vec![PathBuf::from("./output")]; // not under ./src
        let report = policy.validate().unwrap();
        assert!(report
            .warnings
            .contains(&PolicyWarning::WriteOutsideReadScope {
                write_path: PathBuf::from("./output")
            }));
    }

    #[test]
    fn test_validate_write_within_read_scope_no_warning() {
        let mut policy = minimal_policy();
        policy.filesystem.allow_read = vec![PathBuf::from("./src")];
        policy.filesystem.allow_write = vec![PathBuf::from("./src/gen")];
        let report = policy.validate().unwrap();
        assert!(!report
            .warnings
            .iter()
            .any(|w| matches!(w, PolicyWarning::WriteOutsideReadScope { .. })));
    }

    #[test]
    fn test_validate_block_hidden_false_without_reason_emits_warning() {
        let mut policy = minimal_policy();
        policy.filesystem.block_hidden = false;
        policy.filesystem.allow_hidden_reason = None;
        let report = policy.validate().unwrap();
        assert!(report
            .warnings
            .contains(&PolicyWarning::BlockHiddenDisabledWithoutReason));
    }

    #[test]
    fn test_validate_block_hidden_false_with_reason_no_warning() {
        let mut policy = minimal_policy();
        policy.filesystem.block_hidden = false;
        policy.filesystem.allow_hidden_reason = Some("dotenv files needed".to_string());
        let report = policy.validate().unwrap();
        assert!(!report
            .warnings
            .contains(&PolicyWarning::BlockHiddenDisabledWithoutReason));
    }

    #[test]
    fn test_validate_sensitive_ssh_path_emits_warning() {
        let mut policy = minimal_policy();
        policy.filesystem.allow_read = vec![PathBuf::from("~/.ssh")];
        let report = policy.validate().unwrap();
        assert!(report
            .warnings
            .iter()
            .any(|w| matches!(w, PolicyWarning::SensitivePath(_))));
    }

    #[test]
    fn test_validate_sensitive_etc_shadow_emits_warning() {
        let mut policy = minimal_policy();
        policy.filesystem.allow_read = vec![PathBuf::from("/etc/shadow")];
        let report = policy.validate().unwrap();
        assert!(report
            .warnings
            .iter()
            .any(|w| matches!(w, PolicyWarning::SensitivePath(_))));
    }

    // --- network ------------------------------------------------------------

    #[test]
    fn test_validate_zero_rate_limit_returns_validation_error() {
        let mut policy = minimal_policy();
        policy.network.allow_outbound = vec![NetworkRule {
            host: "api.example.com".to_string(),
            port: 443,
            max_requests_per_minute: Some(0),
            max_payload_bytes: None,
        }];
        let err = policy.validate().unwrap_err();
        assert!(matches!(err, PolicyError::ValidationError(_)));
    }

    #[test]
    fn test_validate_no_rate_limit_emits_warning() {
        let mut policy = minimal_policy();
        policy.network.allow_outbound = vec![NetworkRule {
            host: "api.example.com".to_string(),
            port: 443,
            max_requests_per_minute: None,
            max_payload_bytes: None,
        }];
        let report = policy.validate().unwrap();
        assert!(report.warnings.contains(&PolicyWarning::NoRateLimit {
            host: "api.example.com".to_string()
        }));
    }

    #[test]
    fn test_validate_positive_rate_limit_no_warning() {
        let mut policy = minimal_policy();
        policy.network.allow_outbound = vec![NetworkRule {
            host: "api.example.com".to_string(),
            port: 443,
            max_requests_per_minute: Some(60),
            max_payload_bytes: None,
        }];
        let report = policy.validate().unwrap();
        assert!(!report
            .warnings
            .iter()
            .any(|w| matches!(w, PolicyWarning::NoRateLimit { .. })));
    }

    // --- resource limits ----------------------------------------------------

    #[test]
    fn test_validate_cpu_percent_100_returns_validation_error() {
        let mut policy = minimal_policy();
        policy.resource_limits = Some(ResourceLimits {
            max_memory_mb: None,
            max_cpu_percent: Some(100),
            max_procs: None,
            max_disk_write_mb_per_min: None,
        });
        let err = policy.validate().unwrap_err();
        assert!(matches!(err, PolicyError::ValidationError(_)));
    }

    #[test]
    fn test_validate_cpu_percent_0_returns_validation_error() {
        let mut policy = minimal_policy();
        policy.resource_limits = Some(ResourceLimits {
            max_memory_mb: None,
            max_cpu_percent: Some(0),
            max_procs: None,
            max_disk_write_mb_per_min: None,
        });
        assert!(matches!(
            policy.validate().unwrap_err(),
            PolicyError::ValidationError(_)
        ));
    }

    #[test]
    fn test_validate_cpu_percent_in_range_passes() {
        let mut policy = minimal_policy();
        policy.resource_limits = Some(ResourceLimits {
            max_memory_mb: None,
            max_cpu_percent: Some(50),
            max_procs: None,
            max_disk_write_mb_per_min: None,
        });
        assert!(policy.validate().is_ok());
    }

    // --- MCP servers --------------------------------------------------------

    #[test]
    fn test_validate_http_mcp_without_endpoint_returns_missing_field() {
        let mut policy = minimal_policy();
        policy.mcp_servers = vec![McpServerPolicy {
            name: "my-server".to_string(),
            transport: McpTransport::Http,
            endpoint: None,
            policy: McpPolicy::default(),
        }];
        let err = policy.validate().unwrap_err();
        assert!(matches!(err, PolicyError::MissingField(_)));
    }

    #[test]
    fn test_validate_http_mcp_with_endpoint_passes() {
        let mut policy = minimal_policy();
        policy.mcp_servers = vec![McpServerPolicy {
            name: "my-server".to_string(),
            transport: McpTransport::Http,
            endpoint: Some("https://mcp.example.com".to_string()),
            policy: McpPolicy::default(),
        }];
        assert!(policy.validate().is_ok());
    }

    #[test]
    fn test_validate_stdio_mcp_without_endpoint_passes() {
        let mut policy = minimal_policy();
        policy.mcp_servers = vec![McpServerPolicy {
            name: "my-server".to_string(),
            transport: McpTransport::Stdio,
            endpoint: None,
            policy: McpPolicy::default(),
        }];
        assert!(policy.validate().is_ok());
    }

    // --- env vars -----------------------------------------------------------

    #[test]
    fn test_validate_sensitive_env_var_emits_warning() {
        let mut policy = minimal_policy();
        policy.environment.allow_read = vec!["AWS_SECRET_ACCESS_KEY".to_string()];
        let report = policy.validate().unwrap();
        assert!(report
            .warnings
            .iter()
            .any(|w| matches!(w, PolicyWarning::SensitiveEnvVar(_))));
    }

    #[test]
    fn test_validate_non_sensitive_env_var_no_warning() {
        let mut policy = minimal_policy();
        policy.environment.allow_read = vec!["ANTHROPIC_API_KEY".to_string()];
        // ANTHROPIC_ is not in the sensitive prefix list
        let report = policy.validate().unwrap();
        assert!(!report
            .warnings
            .iter()
            .any(|w| matches!(w, PolicyWarning::SensitiveEnvVar(_))));
    }
}
