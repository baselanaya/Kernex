use serde::{Deserialize, Serialize};
use std::path::PathBuf;

fn default_version() -> u8 {
    1
}

fn default_true() -> bool {
    true
}

/// Root policy document. Corresponds to a `kernex.yaml` file.
///
/// Serde rules enforced on every struct:
/// - `#[serde(deny_unknown_fields)]` — typos in user YAML are caught at parse time.
/// - `#[serde(default)]` — optional fields fall back to safe defaults.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct KernexPolicy {
    /// Schema version. Currently always `1`.
    #[serde(default = "default_version")]
    pub version: u8,

    /// Human-readable name for the agent this policy governs.
    /// Required — empty string is rejected by `validate()`.
    pub agent_name: String,

    #[serde(default)]
    pub filesystem: FilesystemPolicy,

    #[serde(default)]
    pub network: NetworkPolicy,

    #[serde(default)]
    pub environment: EnvironmentPolicy,

    /// Optional resource caps enforced via cgroup v2.
    #[serde(default)]
    pub resource_limits: Option<ResourceLimits>,

    /// Per-MCP-server sandbox policies.
    #[serde(default)]
    pub mcp_servers: Vec<McpServerPolicy>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct FilesystemPolicy {
    #[serde(default)]
    pub allow_read: Vec<PathBuf>,

    #[serde(default)]
    pub allow_write: Vec<PathBuf>,

    /// Block access to hidden directories and files (`.ssh`, `.aws`, …).
    /// SECURITY: defaults to `true`. Must be opt-out, never opt-in.
    #[serde(default = "default_true")]
    pub block_hidden: bool,

    /// Human-readable reason why `block_hidden` was disabled. Required
    /// when `block_hidden: false`; validated by `KernexPolicy::validate()`.
    #[serde(default)]
    pub allow_hidden_reason: Option<String>,
}

impl Default for FilesystemPolicy {
    fn default() -> Self {
        Self {
            allow_read: Vec::new(),
            allow_write: Vec::new(),
            block_hidden: true,
            allow_hidden_reason: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct NetworkPolicy {
    #[serde(default)]
    pub allow_outbound: Vec<NetworkRule>,

    /// Block all outbound connections not in `allow_outbound`.
    /// Defaults to `true` (zero-trust).
    #[serde(default = "default_true")]
    pub block_all_other: bool,
}

impl Default for NetworkPolicy {
    fn default() -> Self {
        Self {
            allow_outbound: Vec::new(),
            block_all_other: true,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct NetworkRule {
    pub host: String,
    pub port: u16,
    /// Rate limit in requests per minute. Must be > 0 when set.
    #[serde(default)]
    pub max_requests_per_minute: Option<u32>,
    #[serde(default)]
    pub max_payload_bytes: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct EnvironmentPolicy {
    /// Explicit list of environment variable names the agent may read.
    #[serde(default)]
    pub allow_read: Vec<String>,

    /// Block access to environment variables not in `allow_read`.
    /// Defaults to `true` (zero-trust).
    #[serde(default = "default_true")]
    pub block_all_other: bool,
}

impl Default for EnvironmentPolicy {
    fn default() -> Self {
        Self {
            allow_read: Vec::new(),
            block_all_other: true,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ResourceLimits {
    #[serde(default)]
    pub max_memory_mb: Option<u64>,

    /// Valid range: 1–99. `100` is not accepted (use `None` to mean "no limit").
    #[serde(default)]
    pub max_cpu_percent: Option<u8>,

    #[serde(default)]
    pub max_procs: Option<u32>,

    #[serde(default)]
    pub max_disk_write_mb_per_min: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct McpServerPolicy {
    pub name: String,
    pub transport: McpTransport,
    /// Required when `transport` is `Http`.
    #[serde(default)]
    pub endpoint: Option<String>,
    #[serde(default)]
    pub policy: McpPolicy,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum McpTransport {
    Stdio,
    Http,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct McpPolicy {
    #[serde(default)]
    pub filesystem: FilesystemPolicy,
    #[serde(default)]
    pub network: NetworkPolicy,
}

// ---------------------------------------------------------------------------
// Tests — Red phase: written before implementation, describe desired behavior
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_filesystem_policy_blocks_hidden_by_default() {
        let policy = FilesystemPolicy::default();
        assert!(
            policy.block_hidden,
            "block_hidden must default to true (SECURITY invariant)"
        );
    }

    #[test]
    fn test_filesystem_policy_has_empty_paths_by_default() {
        let policy = FilesystemPolicy::default();
        assert!(policy.allow_read.is_empty());
        assert!(policy.allow_write.is_empty());
    }

    #[test]
    fn test_network_policy_blocks_all_other_by_default() {
        let policy = NetworkPolicy::default();
        assert!(
            policy.block_all_other,
            "block_all_other must default to true"
        );
        assert!(policy.allow_outbound.is_empty());
    }

    #[test]
    fn test_environment_policy_blocks_all_other_by_default() {
        let policy = EnvironmentPolicy::default();
        assert!(
            policy.block_all_other,
            "block_all_other must default to true"
        );
        assert!(policy.allow_read.is_empty());
    }

    #[test]
    fn test_kernex_policy_has_safe_defaults_when_omitted() {
        // Parse a minimal YAML — only agent_name is required.
        let yaml = "agent_name: test-agent";
        let policy: KernexPolicy = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(policy.version, 1);
        assert!(policy.filesystem.block_hidden);
        assert!(policy.network.block_all_other);
        assert!(policy.environment.block_all_other);
        assert!(policy.resource_limits.is_none());
        assert!(policy.mcp_servers.is_empty());
    }

    #[test]
    fn test_kernex_policy_deny_unknown_fields_rejects_typo() {
        let yaml = "agent_name: test\nfilesytem: {}"; // typo: filesytem
        let result: Result<KernexPolicy, _> = serde_yaml::from_str(yaml);
        assert!(result.is_err(), "unknown field should be rejected");
    }

    #[test]
    fn test_mcp_transport_serializes_lowercase() {
        let t = McpTransport::Http;
        let s = serde_yaml::to_string(&t).unwrap();
        assert!(
            s.trim() == "http",
            "McpTransport::Http should serialize as 'http', got: {s}"
        );
    }
}
