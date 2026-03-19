use std::path::PathBuf;

use crate::types::{KernexPolicy, NetworkRule};

/// A single change between two policies.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DiffEntry {
    /// A path, host, or variable was added — always a scope expansion.
    Added { field: String, value: String },
    /// A path, host, or variable was removed — always a scope reduction.
    Removed { field: String, value: String },
    /// A boolean or structured value changed.
    Changed {
        field: String,
        old_value: String,
        new_value: String,
        is_scope_expansion: bool,
    },
}

impl DiffEntry {
    /// `true` if applying this change would expand what the agent can access.
    pub fn is_scope_expansion(&self) -> bool {
        match self {
            DiffEntry::Added { .. } => true,
            DiffEntry::Removed { .. } => false,
            DiffEntry::Changed {
                is_scope_expansion, ..
            } => *is_scope_expansion,
        }
    }
}

/// The complete diff between two `KernexPolicy` instances.
#[derive(Debug, Clone, Default)]
pub struct PolicyDiff {
    pub entries: Vec<DiffEntry>,
}

impl PolicyDiff {
    /// `true` if any entry in this diff expands the agent's permitted scope.
    /// Scope expansions require `--accept-expansions` to apply.
    pub fn has_scope_expansions(&self) -> bool {
        self.entries.iter().any(DiffEntry::is_scope_expansion)
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// Compute the diff between `old` and `new` policies.
/// Scope expansions are flagged; see `PolicyDiff::has_scope_expansions`.
pub fn diff_policies(old: &KernexPolicy, new: &KernexPolicy) -> PolicyDiff {
    let mut entries: Vec<DiffEntry> = Vec::new();

    // Filesystem paths
    diff_path_list(
        "filesystem.allow_read",
        &old.filesystem.allow_read,
        &new.filesystem.allow_read,
        &mut entries,
    );
    diff_path_list(
        "filesystem.allow_write",
        &old.filesystem.allow_write,
        &new.filesystem.allow_write,
        &mut entries,
    );

    // block_hidden — disabling it widens access to hidden dirs (expansion)
    if old.filesystem.block_hidden != new.filesystem.block_hidden {
        entries.push(DiffEntry::Changed {
            field: "filesystem.block_hidden".to_string(),
            old_value: old.filesystem.block_hidden.to_string(),
            new_value: new.filesystem.block_hidden.to_string(),
            // Disabling block_hidden = expansion; re-enabling = reduction
            is_scope_expansion: !new.filesystem.block_hidden,
        });
    }

    // Network rules
    diff_network_rules(
        &old.network.allow_outbound,
        &new.network.allow_outbound,
        &mut entries,
    );

    // block_all_other — turning it off = expansion
    if old.network.block_all_other != new.network.block_all_other {
        entries.push(DiffEntry::Changed {
            field: "network.block_all_other".to_string(),
            old_value: old.network.block_all_other.to_string(),
            new_value: new.network.block_all_other.to_string(),
            is_scope_expansion: !new.network.block_all_other,
        });
    }

    // Environment vars
    diff_string_list(
        "environment.allow_read",
        &old.environment.allow_read,
        &new.environment.allow_read,
        &mut entries,
    );

    // environment block_all_other
    if old.environment.block_all_other != new.environment.block_all_other {
        entries.push(DiffEntry::Changed {
            field: "environment.block_all_other".to_string(),
            old_value: old.environment.block_all_other.to_string(),
            new_value: new.environment.block_all_other.to_string(),
            is_scope_expansion: !new.environment.block_all_other,
        });
    }

    PolicyDiff { entries }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn diff_path_list(field: &str, old: &[PathBuf], new: &[PathBuf], entries: &mut Vec<DiffEntry>) {
    for path in new {
        if !old.contains(path) {
            entries.push(DiffEntry::Added {
                field: field.to_string(),
                value: path.display().to_string(),
            });
        }
    }
    for path in old {
        if !new.contains(path) {
            entries.push(DiffEntry::Removed {
                field: field.to_string(),
                value: path.display().to_string(),
            });
        }
    }
}

fn diff_string_list(field: &str, old: &[String], new: &[String], entries: &mut Vec<DiffEntry>) {
    for item in new {
        if !old.contains(item) {
            entries.push(DiffEntry::Added {
                field: field.to_string(),
                value: item.clone(),
            });
        }
    }
    for item in old {
        if !new.contains(item) {
            entries.push(DiffEntry::Removed {
                field: field.to_string(),
                value: item.clone(),
            });
        }
    }
}

fn diff_network_rules(old: &[NetworkRule], new: &[NetworkRule], entries: &mut Vec<DiffEntry>) {
    for rule in new {
        if !old
            .iter()
            .any(|r| r.host == rule.host && r.port == rule.port)
        {
            entries.push(DiffEntry::Added {
                field: "network.allow_outbound".to_string(),
                value: format!("{}:{}", rule.host, rule.port),
            });
        }
    }
    for rule in old {
        if !new
            .iter()
            .any(|r| r.host == rule.host && r.port == rule.port)
        {
            entries.push(DiffEntry::Removed {
                field: "network.allow_outbound".to_string(),
                value: format!("{}:{}", rule.host, rule.port),
            });
        }
    }
}

// ---------------------------------------------------------------------------
// Tests — Red phase first
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;
    use crate::types::{
        EnvironmentPolicy, FilesystemPolicy, KernexPolicy, NetworkPolicy, NetworkRule,
    };

    fn base_policy() -> KernexPolicy {
        KernexPolicy {
            version: 1,
            agent_name: "test-agent".to_string(),
            filesystem: FilesystemPolicy {
                allow_read: vec![PathBuf::from("./src")],
                allow_write: vec![],
                block_hidden: true,
                allow_hidden_reason: None,
            },
            network: NetworkPolicy {
                allow_outbound: vec![NetworkRule {
                    host: "api.anthropic.com".to_string(),
                    port: 443,
                    max_requests_per_minute: Some(60),
                    max_payload_bytes: None,
                }],
                block_all_other: true,
            },
            environment: EnvironmentPolicy {
                allow_read: vec!["ANTHROPIC_API_KEY".to_string()],
                block_all_other: true,
            },
            resource_limits: None,
            mcp_servers: vec![],
        }
    }

    #[test]
    fn test_diff_identical_policies_is_empty() {
        let policy = base_policy();
        let diff = diff_policies(&policy, &policy);
        assert!(diff.is_empty());
    }

    // --- filesystem ---------------------------------------------------------

    #[test]
    fn test_diff_detects_added_read_path() {
        let old = base_policy();
        let mut new = old.clone();
        new.filesystem.allow_read.push(PathBuf::from("./logs"));

        let diff = diff_policies(&old, &new);
        assert!(diff.entries.contains(&DiffEntry::Added {
            field: "filesystem.allow_read".to_string(),
            value: "./logs".to_string(),
        }));
    }

    #[test]
    fn test_diff_detects_removed_read_path() {
        let old = base_policy();
        let mut new = old.clone();
        new.filesystem.allow_read.clear();

        let diff = diff_policies(&old, &new);
        assert!(diff.entries.contains(&DiffEntry::Removed {
            field: "filesystem.allow_read".to_string(),
            value: "./src".to_string(),
        }));
    }

    #[test]
    fn test_diff_added_read_path_is_scope_expansion() {
        let old = base_policy();
        let mut new = old.clone();
        new.filesystem.allow_read.push(PathBuf::from("./logs"));

        let diff = diff_policies(&old, &new);
        assert!(diff.has_scope_expansions());
    }

    #[test]
    fn test_diff_removed_read_path_is_not_scope_expansion() {
        let old = base_policy();
        let mut new = old.clone();
        new.filesystem.allow_read.clear();

        let diff = diff_policies(&old, &new);
        assert!(!diff.has_scope_expansions());
    }

    #[test]
    fn test_diff_disabling_block_hidden_is_scope_expansion() {
        let old = base_policy();
        let mut new = old.clone();
        new.filesystem.block_hidden = false;
        new.filesystem.allow_hidden_reason = Some("needed for .env".to_string());

        let diff = diff_policies(&old, &new);
        let entry = diff.entries.iter().find(
            |e| matches!(e, DiffEntry::Changed { field, .. } if field == "filesystem.block_hidden"),
        );
        assert!(entry.is_some());
        assert!(entry.unwrap().is_scope_expansion());
    }

    #[test]
    fn test_diff_reenabling_block_hidden_is_not_scope_expansion() {
        let mut old = base_policy();
        old.filesystem.block_hidden = false;
        old.filesystem.allow_hidden_reason = Some("temporary".to_string());
        let mut new = old.clone();
        new.filesystem.block_hidden = true;
        new.filesystem.allow_hidden_reason = None;

        let diff = diff_policies(&old, &new);
        let entry = diff.entries.iter().find(
            |e| matches!(e, DiffEntry::Changed { field, .. } if field == "filesystem.block_hidden"),
        );
        assert!(entry.is_some());
        assert!(!entry.unwrap().is_scope_expansion());
    }

    // --- network ------------------------------------------------------------

    #[test]
    fn test_diff_detects_added_network_rule() {
        let old = base_policy();
        let mut new = old.clone();
        new.network.allow_outbound.push(NetworkRule {
            host: "api.openai.com".to_string(),
            port: 443,
            max_requests_per_minute: Some(30),
            max_payload_bytes: None,
        });

        let diff = diff_policies(&old, &new);
        assert!(diff.entries.contains(&DiffEntry::Added {
            field: "network.allow_outbound".to_string(),
            value: "api.openai.com:443".to_string(),
        }));
    }

    #[test]
    fn test_diff_detects_removed_network_rule() {
        let old = base_policy();
        let mut new = old.clone();
        new.network.allow_outbound.clear();

        let diff = diff_policies(&old, &new);
        assert!(diff.entries.contains(&DiffEntry::Removed {
            field: "network.allow_outbound".to_string(),
            value: "api.anthropic.com:443".to_string(),
        }));
    }

    #[test]
    fn test_diff_block_all_other_false_is_scope_expansion() {
        let old = base_policy();
        let mut new = old.clone();
        new.network.block_all_other = false;

        let diff = diff_policies(&old, &new);
        let entry = diff.entries.iter().find(
            |e| matches!(e, DiffEntry::Changed { field, .. } if field == "network.block_all_other"),
        );
        assert!(entry.unwrap().is_scope_expansion());
    }

    // --- environment --------------------------------------------------------

    #[test]
    fn test_diff_detects_added_env_var() {
        let old = base_policy();
        let mut new = old.clone();
        new.environment
            .allow_read
            .push("OPENAI_API_KEY".to_string());

        let diff = diff_policies(&old, &new);
        assert!(diff.entries.contains(&DiffEntry::Added {
            field: "environment.allow_read".to_string(),
            value: "OPENAI_API_KEY".to_string(),
        }));
    }

    #[test]
    fn test_diff_detects_removed_env_var() {
        let old = base_policy();
        let mut new = old.clone();
        new.environment.allow_read.clear();

        let diff = diff_policies(&old, &new);
        assert!(diff.entries.contains(&DiffEntry::Removed {
            field: "environment.allow_read".to_string(),
            value: "ANTHROPIC_API_KEY".to_string(),
        }));
    }
}
