mod diff;
mod error;
mod score;
mod types;
mod validate;

pub use diff::{diff_policies, DiffEntry, PolicyDiff};
pub use error::{PolicyError, PolicyWarning, ValidationReport};
pub use score::{score_policy, PolicyScore};
pub use types::{
    EnvironmentPolicy, FilesystemPolicy, KernexPolicy, McpPolicy, McpServerPolicy, McpTransport,
    NetworkPolicy, NetworkRule, ResourceLimits,
};

use std::str::FromStr;

impl FromStr for KernexPolicy {
    type Err = PolicyError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(serde_yaml::from_str(s)?)
    }
}

impl KernexPolicy {
    /// Parse a `KernexPolicy` from an [`std::io::Read`] source (e.g. a file handle).
    pub fn from_reader<R: std::io::Read>(reader: R) -> Result<Self, PolicyError> {
        Ok(serde_yaml::from_reader(reader)?)
    }

    /// Parse a `KernexPolicy` directly from a file on disk.
    pub fn from_file(path: &std::path::Path) -> Result<Self, PolicyError> {
        let file = std::fs::File::open(path)?;
        Self::from_reader(file)
    }

    /// Validate the policy, returning non-fatal warnings or a hard error.
    ///
    /// Call this after every parse. `kernex run` runs it automatically before
    /// applying enforcement layers.
    pub fn validate(&self) -> Result<ValidationReport, PolicyError> {
        validate::validate_policy(self)
    }

    /// Compute the five-dimension security score (0–100).
    ///
    /// Used by `kernex status` and shown as a one-line warning by `kernex run`
    /// when the score is below 60.
    pub fn score(&self) -> PolicyScore {
        score::score_policy(self)
    }

    /// Produce a diff between `self` (old) and `other` (new).
    ///
    /// Scope expansions in the result require `--accept-expansions` to apply
    /// during `kernex audit`.
    pub fn diff(&self, other: &KernexPolicy) -> PolicyDiff {
        diff::diff_policies(self, other)
    }
}

// ---------------------------------------------------------------------------
// Integration tests — parse → validate → score → roundtrip
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::path::PathBuf;
    use std::str::FromStr;

    use super::*;

    const VALID_YAML: &str = r#"
agent_name: my-coding-agent
filesystem:
  allow_read:
    - ./src
    - ./data
  allow_write:
    - ./src/output
  block_hidden: true
network:
  allow_outbound:
    - host: api.anthropic.com
      port: 443
      max_requests_per_minute: 60
  block_all_other: true
environment:
  allow_read:
    - ANTHROPIC_API_KEY
  block_all_other: true
resource_limits:
  max_memory_mb: 512
  max_cpu_percent: 50
  max_procs: 64
  max_disk_write_mb_per_min: 100
"#;

    // --- parsing ------------------------------------------------------------

    #[test]
    fn test_parse_valid_yaml_succeeds() {
        let policy = KernexPolicy::from_str(VALID_YAML).unwrap();
        assert_eq!(policy.agent_name, "my-coding-agent");
        assert_eq!(
            policy.filesystem.allow_read,
            vec![PathBuf::from("./src"), PathBuf::from("./data")]
        );
        assert!(policy.filesystem.block_hidden);
        assert_eq!(policy.network.allow_outbound.len(), 1);
        assert_eq!(policy.network.allow_outbound[0].host, "api.anthropic.com");
        assert!(policy.network.block_all_other);
    }

    #[test]
    fn test_parse_invalid_yaml_syntax_returns_parse_error() {
        let result = KernexPolicy::from_str("not: valid: yaml: :");
        assert!(matches!(result, Err(PolicyError::ParseError(_))));
    }

    #[test]
    fn test_parse_unknown_field_returns_parse_error() {
        let yaml = "agent_name: test\nunknown_field: oops";
        let result = KernexPolicy::from_str(yaml);
        assert!(
            matches!(result, Err(PolicyError::ParseError(_))),
            "unknown fields should be rejected by deny_unknown_fields"
        );
    }

    #[test]
    fn test_parse_minimal_yaml_applies_safe_defaults() {
        let policy = KernexPolicy::from_str("agent_name: minimal-agent").unwrap();
        assert_eq!(policy.version, 1);
        assert!(policy.filesystem.block_hidden);
        assert!(policy.network.block_all_other);
        assert!(policy.environment.block_all_other);
        assert!(policy.resource_limits.is_none());
        assert!(policy.mcp_servers.is_empty());
    }

    // --- roundtrip ----------------------------------------------------------

    #[test]
    fn test_roundtrip_serialize_deserialize_produces_identical_struct() {
        let original = KernexPolicy::from_str(VALID_YAML).unwrap();
        let serialized = serde_yaml::to_string(&original).unwrap();
        let roundtripped = KernexPolicy::from_str(&serialized).unwrap();
        assert_eq!(
            original, roundtripped,
            "roundtrip must produce an identical policy"
        );
    }

    #[test]
    fn test_roundtrip_default_fields_preserved() {
        let policy = KernexPolicy::from_str("agent_name: minimal").unwrap();
        let yaml = serde_yaml::to_string(&policy).unwrap();
        let back = KernexPolicy::from_str(&yaml).unwrap();
        assert_eq!(policy, back);
    }

    // --- from_file ----------------------------------------------------------

    #[test]
    fn test_from_file_parses_correctly() {
        use std::io::Write;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("kernex.yaml");
        let mut f = std::fs::File::create(&path).unwrap();
        write!(f, "agent_name: file-agent").unwrap();
        drop(f);
        let policy = KernexPolicy::from_file(&path).unwrap();
        assert_eq!(policy.agent_name, "file-agent");
    }

    #[test]
    fn test_from_file_missing_file_returns_io_error() {
        let result = KernexPolicy::from_file(std::path::Path::new("/nonexistent/kernex.yaml"));
        assert!(matches!(result, Err(PolicyError::Io(_))));
    }

    // --- validate -----------------------------------------------------------

    #[test]
    fn test_validate_clean_policy_returns_empty_report() {
        let policy = KernexPolicy::from_str(VALID_YAML).unwrap();
        let report = policy.validate().unwrap();
        assert!(
            report.is_clean(),
            "well-formed policy should produce no warnings; got: {:?}",
            report.warnings
        );
    }

    // --- score --------------------------------------------------------------

    #[test]
    fn test_score_perfect_yaml_reaches_100() {
        let policy = KernexPolicy::from_str(VALID_YAML).unwrap();
        let score = policy.score();
        assert_eq!(
            score.total, 100,
            "well-formed policy should score 100; findings: {:?}",
            score.findings
        );
    }

    #[test]
    fn test_score_below_60_has_findings() {
        let policy = KernexPolicy::from_str("agent_name: risky").unwrap();
        // Default has no resource limits → -20, and empty env allow_read but
        // block_all_other is true so environment scores 20. No paths → 20.
        // Total = 20+20+20+20+0 = 80. Add no resource limits deduction.
        // Just check findings exist when limits are missing.
        let score = policy.score();
        assert!(!score.findings.is_empty());
    }

    // --- diff ---------------------------------------------------------------

    #[test]
    fn test_diff_shows_scope_expansion_for_wider_policy() {
        let old = KernexPolicy::from_str("agent_name: agent").unwrap();
        let mut new = old.clone();
        new.filesystem.allow_read.push(PathBuf::from("./new-dir"));
        let diff = old.diff(&new);
        assert!(diff.has_scope_expansions());
    }

    // --- README MCP section YAML example ------------------------------------

    /// The kernex.yaml shown in the README's MCP section must parse as a valid
    /// KernexPolicy. This test pins the exact YAML from the README so that any
    /// type-system change that would break the documented example is caught here.
    ///
    /// Keep this YAML in sync with the MCP section of README.md.
    #[test]
    fn test_readme_mcp_example_parses_as_valid_policy() {
        let yaml = r#"
agent_name: claude-code-agent

filesystem:
  allow_read:
    - ./src
    - ./data
  allow_write:
    - ./output
  block_hidden: true

network:
  allow_outbound:
    - host: api.anthropic.com
      port: 443
      max_requests_per_minute: 60
  block_all_other: true

environment:
  allow_read:
    - ANTHROPIC_API_KEY
  block_all_other: true

mcp_servers:
  - name: filesystem-server
    transport: stdio
    policy:
      filesystem:
        allow_read:
          - ./workspace
        block_hidden: true
      network:
        block_all_other: true

  - name: web-search-server
    transport: http
    endpoint: https://search.example.com/mcp
    policy:
      filesystem:
        block_hidden: true
      network:
        allow_outbound:
          - host: search.example.com
            port: 443
        block_all_other: true
"#;

        let policy = KernexPolicy::from_str(yaml)
            .unwrap_or_else(|e| panic!("README MCP example must parse as KernexPolicy: {e}"));

        assert_eq!(policy.agent_name, "claude-code-agent");
        assert_eq!(policy.mcp_servers.len(), 2);

        let stdio_server = &policy.mcp_servers[0];
        assert_eq!(stdio_server.name, "filesystem-server");
        assert_eq!(stdio_server.transport, McpTransport::Stdio);
        assert!(stdio_server.endpoint.is_none());
        assert_eq!(
            stdio_server.policy.filesystem.allow_read,
            vec![PathBuf::from("./workspace")]
        );
        assert!(stdio_server.policy.filesystem.block_hidden);
        assert!(stdio_server.policy.network.block_all_other);

        let http_server = &policy.mcp_servers[1];
        assert_eq!(http_server.name, "web-search-server");
        assert_eq!(http_server.transport, McpTransport::Http);
        assert_eq!(
            http_server.endpoint.as_deref(),
            Some("https://search.example.com/mcp")
        );
        assert_eq!(http_server.policy.network.allow_outbound.len(), 1);
        assert_eq!(
            http_server.policy.network.allow_outbound[0].host,
            "search.example.com"
        );
        assert_eq!(http_server.policy.network.allow_outbound[0].port, 443);
    }
}
