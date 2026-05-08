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

impl FilesystemPolicy {
    /// Return a copy of this policy with hidden paths stripped from
    /// `allow_read` and `allow_write` when `block_hidden` is set, alongside
    /// the list of skipped paths so the caller can surface them to the user.
    ///
    /// This exists specifically so that callers using `Command::pre_exec`
    /// can do the filtering (and any logging) **in the parent process** before
    /// the fork. After fork, between fork and execve, calling anything that
    /// allocates or takes locks (including the `tracing::warn!` macro) is
    /// async-signal-unsafe and can deadlock the child if a parent thread
    /// held an allocator lock at fork time. Pre-filtering removes the only
    /// reason the enforcement code path needed to log.
    ///
    /// `block_hidden = false` is a no-op: returns a clone with empty `skipped`.
    pub fn filter_for_enforcement(&self) -> (Self, Vec<std::path::PathBuf>) {
        if !self.block_hidden {
            return (self.clone(), Vec::new());
        }

        let mut skipped: Vec<std::path::PathBuf> = Vec::new();
        let mut keep_read: Vec<std::path::PathBuf> = Vec::with_capacity(self.allow_read.len());
        let mut keep_write: Vec<std::path::PathBuf> = Vec::with_capacity(self.allow_write.len());

        for p in &self.allow_read {
            if Self::is_hidden_path(p) {
                skipped.push(p.clone());
            } else {
                keep_read.push(p.clone());
            }
        }

        for p in &self.allow_write {
            if Self::is_hidden_path(p) {
                skipped.push(p.clone());
            } else {
                keep_write.push(p.clone());
            }
        }

        (
            Self {
                allow_read: keep_read,
                allow_write: keep_write,
                block_hidden: self.block_hidden,
                allow_hidden_reason: self.allow_hidden_reason.clone(),
            },
            skipped,
        )
    }

    /// Returns `true` if any *normal* component of `path` starts with `.`.
    ///
    /// Special components `.` and `..` are excluded — only real names like
    /// `.ssh` count. Mirrors the implementation that previously lived in
    /// `kernex-linux::landlock`; centralised here so policy callers don't
    /// need to depend on the platform crate to do hidden-path detection.
    pub fn is_hidden_path(path: &std::path::Path) -> bool {
        use std::path::Component;
        path.components().any(|c| {
            if let Component::Normal(name) = c {
                name.to_string_lossy().starts_with('.')
            } else {
                false
            }
        })
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

    // -----------------------------------------------------------------------
    // FilesystemPolicy::filter_for_enforcement
    // -----------------------------------------------------------------------

    #[test]
    fn test_filter_for_enforcement_strips_hidden_when_block_hidden_true() {
        let p = FilesystemPolicy {
            allow_read: vec![PathBuf::from("/etc"), PathBuf::from("/home/u/.ssh")],
            allow_write: vec![PathBuf::from("/tmp/out"), PathBuf::from("/home/u/.aws")],
            block_hidden: true,
            allow_hidden_reason: None,
        };

        let (filtered, skipped) = p.filter_for_enforcement();

        assert_eq!(filtered.allow_read, vec![PathBuf::from("/etc")]);
        assert_eq!(filtered.allow_write, vec![PathBuf::from("/tmp/out")]);
        assert!(skipped.contains(&PathBuf::from("/home/u/.ssh")));
        assert!(skipped.contains(&PathBuf::from("/home/u/.aws")));
        assert_eq!(skipped.len(), 2);
    }

    #[test]
    fn test_filter_for_enforcement_passthrough_when_block_hidden_false() {
        let p = FilesystemPolicy {
            allow_read: vec![PathBuf::from("/home/u/.ssh")],
            allow_write: vec![],
            block_hidden: false,
            allow_hidden_reason: Some("intentional".to_string()),
        };

        let (filtered, skipped) = p.filter_for_enforcement();

        assert_eq!(filtered.allow_read, vec![PathBuf::from("/home/u/.ssh")]);
        assert!(skipped.is_empty());
    }

    #[test]
    fn test_filter_for_enforcement_preserves_block_hidden_flag() {
        // The cleaned policy must preserve block_hidden so that any
        // defense-in-depth check downstream still fires.
        let p = FilesystemPolicy {
            allow_read: vec![PathBuf::from("/etc")],
            allow_write: vec![],
            block_hidden: true,
            allow_hidden_reason: None,
        };
        let (filtered, _) = p.filter_for_enforcement();
        assert!(filtered.block_hidden);
    }

    #[test]
    fn test_filter_for_enforcement_no_change_when_no_hidden_paths() {
        let p = FilesystemPolicy {
            allow_read: vec![PathBuf::from("/etc"), PathBuf::from("/usr/lib")],
            allow_write: vec![PathBuf::from("/tmp")],
            block_hidden: true,
            allow_hidden_reason: None,
        };
        let (filtered, skipped) = p.filter_for_enforcement();
        assert_eq!(filtered.allow_read, p.allow_read);
        assert_eq!(filtered.allow_write, p.allow_write);
        assert!(skipped.is_empty());
    }

    #[test]
    fn test_is_hidden_path_detects_dotfile() {
        use std::path::Path;
        assert!(FilesystemPolicy::is_hidden_path(Path::new(".ssh")));
        assert!(FilesystemPolicy::is_hidden_path(Path::new("/home/u/.ssh")));
        assert!(FilesystemPolicy::is_hidden_path(Path::new(
            "/home/u/.config/gh/hosts.yml"
        )));
    }

    #[test]
    fn test_is_hidden_path_does_not_flag_dot_or_dotdot() {
        use std::path::Path;
        // The literal current/parent dir components must not register as hidden.
        assert!(!FilesystemPolicy::is_hidden_path(Path::new(".")));
        assert!(!FilesystemPolicy::is_hidden_path(Path::new("..")));
        assert!(!FilesystemPolicy::is_hidden_path(Path::new("./src/main.rs")));
        assert!(!FilesystemPolicy::is_hidden_path(Path::new(
            "../sibling/src"
        )));
    }

    #[test]
    fn test_is_hidden_path_does_not_flag_normal_paths() {
        use std::path::Path;
        assert!(!FilesystemPolicy::is_hidden_path(Path::new(
            "/tmp/output.txt"
        )));
        assert!(!FilesystemPolicy::is_hidden_path(Path::new(
            "/home/user/projects/code.rs"
        )));
    }
}
