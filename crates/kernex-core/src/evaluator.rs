//! Three-tier policy evaluation against a [`KernexPolicy`].
//!
//! # Evaluation tiers
//!
//! Each [`PolicyQuery`] is classified into one of three tiers in this order:
//!
//! 1. **Auto-deny** — always blocked regardless of any allow-list entry:
//!    - Filesystem paths with hidden components when `block_hidden = true`
//!    - Network connections when `block_all_other = true` and host not in allowlist
//!    - Environment variable reads when `block_all_other = true` and name not in allowlist
//!
//! 2. **Auto-allow** — explicitly permitted by the active policy:
//!    - Path is within an `allow_read` or `allow_write` subtree
//!    - Network `host:port` matches an `allow_outbound` rule
//!    - Environment variable name is in `allow_read`
//!
//! 3. **Prompt** — not covered by the policy; a JIT confirmation is needed:
//!    - `Prompt(High)` for sensitive paths/variables (credential heuristics)
//!    - `Prompt(Medium)` for everything else outside scope

use std::path::Path;

use kernex_ipc::{Operation, PolicyQuery, Resource, RiskTier};
use kernex_policy::KernexPolicy;

/// Sensitive filesystem path fragments — any path containing one of these
/// triggers a `Prompt(High)` with `injection_signal = true`.
///
/// # SECURITY
///
/// This list is intentionally conservative. Additions require a security
/// review comment explaining the threat model.
const SENSITIVE_FS_PATTERNS: &[&str] = &[
    ".ssh",
    ".aws",
    ".gnupg",
    ".config/gcloud",
    ".config/gh",
    ".kube",
    ".netrc",
    "/etc/passwd",
    "/etc/shadow",
    "/etc/sudoers",
];

/// Sensitive environment variable prefixes/names — any variable whose
/// uppercase name contains one of these triggers `Prompt(High)`.
const SENSITIVE_ENV_PATTERNS: &[&str] = &[
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
// Result types
// ---------------------------------------------------------------------------

/// The verdict produced by evaluating a single query against the policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EvalVerdict {
    /// The operation is explicitly permitted by the active policy.
    Allow,
    /// The operation is explicitly denied by the active policy.
    Deny,
    /// The operation is not covered; surface a JIT prompt with this risk tier.
    Prompt(RiskTier),
}

/// Complete result of evaluating one [`PolicyQuery`].
#[derive(Debug, Clone)]
pub struct EvaluationResult {
    /// The enforcement verdict.
    pub verdict: EvalVerdict,
    /// Human-readable explanation, suitable for the JIT prompt `message` field.
    pub reason: String,
    /// `true` when this query matches a sensitive-path or credential heuristic.
    /// Used to increment the `injection_signals` session counter.
    pub injection_signal: bool,
}

// ---------------------------------------------------------------------------
// Public entry point
// ---------------------------------------------------------------------------

/// Evaluate a [`PolicyQuery`] against `policy` and return the enforcement
/// verdict plus context.
///
/// This function is **pure** — it does not mutate any state and can be called
/// from multiple threads concurrently.
pub fn evaluate(policy: &KernexPolicy, query: &PolicyQuery) -> EvaluationResult {
    match (&query.operation, &query.resource) {
        (
            op @ (Operation::FileRead | Operation::FileWrite | Operation::FileExec),
            Resource::Path(path),
        ) => evaluate_filesystem(policy, op, path),
        (Operation::NetworkConnect, Resource::Network { host, port }) => {
            evaluate_network(policy, host, *port)
        }
        (Operation::EnvRead, Resource::EnvVar(name)) => evaluate_env(policy, name),
        (Operation::Syscall, Resource::Syscall { nr, name: _ }) => {
            // Syscalls are enforced at the kernel level by seccomp.
            // A PolicyQuery for a syscall at the IPC level means the agent is
            // in audit mode. Treat unknown syscalls as high-risk prompts.
            EvaluationResult {
                verdict: EvalVerdict::Prompt(RiskTier::High),
                reason: format!("Agent invoked syscall {nr} — not covered by the active policy"),
                injection_signal: false,
            }
        }
        _ => {
            // Mismatch between operation type and resource kind — treat as deny.
            EvaluationResult {
                verdict: EvalVerdict::Deny,
                reason: format!(
                    "Operation {:?} does not match resource kind {:?}",
                    query.operation, query.resource
                ),
                injection_signal: false,
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Per-resource-type evaluation
// ---------------------------------------------------------------------------

fn evaluate_filesystem(policy: &KernexPolicy, op: &Operation, path: &Path) -> EvaluationResult {
    let fs = &policy.filesystem;

    // Tier 1a: hidden path guard.
    if fs.block_hidden && is_hidden_path(path) {
        return EvaluationResult {
            verdict: EvalVerdict::Deny,
            reason: format!(
                "Access to hidden path '{}' is blocked (block_hidden = true)",
                path.display()
            ),
            injection_signal: false,
        };
    }

    // Tier 1b: sensitive path heuristic — prompt with injection signal.
    if is_sensitive_fs_path(path) {
        return EvaluationResult {
            verdict: EvalVerdict::Prompt(RiskTier::High),
            reason: format!(
                "Agent attempted to access '{}' — this path may contain credentials \
                 or private keys. Possible prompt injection.",
                path.display()
            ),
            injection_signal: true,
        };
    }

    // Tier 2: check explicit allow-list.
    let allowed = match op {
        Operation::FileWrite | Operation::FileExec => path_is_allowed(path, &fs.allow_write),
        // Read is allowed if the path is within allow_read OR allow_write
        // (write permission implies read permission on the same subtree).
        _ => path_is_allowed(path, &fs.allow_read) || path_is_allowed(path, &fs.allow_write),
    };

    if allowed {
        return EvaluationResult {
            verdict: EvalVerdict::Allow,
            reason: format!(
                "Path '{}' is within the allow-listed subtree",
                path.display()
            ),
            injection_signal: false,
        };
    }

    // Tier 3: prompt — filesystem has no `block_all_other` flag because Landlock
    // enforces the deny at the kernel level. The IPC layer prompts for JIT expansion.
    EvaluationResult {
        verdict: EvalVerdict::Prompt(RiskTier::Medium),
        reason: format!(
            "Path '{}' is outside the active policy scope — confirm to add or deny",
            path.display()
        ),
        injection_signal: false,
    }
}

fn evaluate_network(policy: &KernexPolicy, host: &str, port: u16) -> EvaluationResult {
    let net = &policy.network;

    // Check allow-list first.
    let in_allowlist = net
        .allow_outbound
        .iter()
        .any(|r| r.host == host && r.port == port);

    if in_allowlist {
        return EvaluationResult {
            verdict: EvalVerdict::Allow,
            reason: format!("Outbound connection to {host}:{port} is allow-listed"),
            injection_signal: false,
        };
    }

    // block_all_other: hard deny.
    if net.block_all_other {
        return EvaluationResult {
            verdict: EvalVerdict::Deny,
            reason: format!(
                "Outbound connection to {host}:{port} is not allow-listed \
                 and block_all_other = true"
            ),
            injection_signal: false,
        };
    }

    // Tier 3: raw IP address not in the allow-list — high-risk prompt.
    // Named hosts get Medium; raw IPs bypass DNS controls and are treated
    // as a potential exfiltration signal.
    if is_unknown_ip_address(host) {
        return EvaluationResult {
            verdict: EvalVerdict::Prompt(RiskTier::High),
            reason: format!(
                "Agent attempted outbound connection to raw IP address {host}:{port} — \
                 this bypasses DNS controls and may indicate data exfiltration. \
                 Possible prompt injection."
            ),
            injection_signal: true,
        };
    }

    // Not blocked, not allowed, not a raw IP — prompt with Medium tier.
    EvaluationResult {
        verdict: EvalVerdict::Prompt(RiskTier::Medium),
        reason: format!(
            "Outbound connection to {host}:{port} is outside the active network policy"
        ),
        injection_signal: false,
    }
}

fn evaluate_env(policy: &KernexPolicy, name: &str) -> EvaluationResult {
    let env = &policy.environment;

    // Check allow-list first.
    if env.allow_read.iter().any(|n| n == name) {
        return EvaluationResult {
            verdict: EvalVerdict::Allow,
            reason: format!("Environment variable '{name}' is in the allow_read list"),
            injection_signal: false,
        };
    }

    // Sensitive env var — prompt with injection signal before block_all_other check.
    if is_sensitive_env_var(name) {
        return EvaluationResult {
            verdict: EvalVerdict::Prompt(RiskTier::High),
            reason: format!(
                "Agent attempted to read '{name}' — this variable may contain credentials. \
                 Possible prompt injection."
            ),
            injection_signal: true,
        };
    }

    // block_all_other: hard deny.
    if env.block_all_other {
        return EvaluationResult {
            verdict: EvalVerdict::Deny,
            reason: format!(
                "Environment variable '{name}' is not in allow_read \
                 and block_all_other = true"
            ),
            injection_signal: false,
        };
    }

    // Not blocked, not allowed — prompt.
    EvaluationResult {
        verdict: EvalVerdict::Prompt(RiskTier::Medium),
        reason: format!("Environment variable '{name}' is outside the active environment policy"),
        injection_signal: false,
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Returns `true` if `path` starts with any entry in `allowed`.
fn path_is_allowed(path: &Path, allowed: &[std::path::PathBuf]) -> bool {
    allowed.iter().any(|a| path.starts_with(a))
}

/// Returns `true` if any *Normal* component of `path` starts with `.`.
///
/// The special components `.` and `..` are not considered hidden.
fn is_hidden_path(path: &Path) -> bool {
    use std::path::Component;
    path.components().any(|c| {
        if let Component::Normal(name) = c {
            name.to_str().map(|s| s.starts_with('.')).unwrap_or(false)
        } else {
            false
        }
    })
}

/// Returns `true` if `path` contains any known sensitive pattern.
fn is_sensitive_fs_path(path: &Path) -> bool {
    let path_str = path.to_string_lossy();
    SENSITIVE_FS_PATTERNS.iter().any(|p| path_str.contains(p))
}

/// Returns `true` if `name` (case-insensitive) matches a sensitive env pattern.
fn is_sensitive_env_var(name: &str) -> bool {
    let upper = name.to_uppercase();
    SENSITIVE_ENV_PATTERNS.iter().any(|p| upper.contains(p))
}

/// Returns `true` if `host` is a raw IPv4 or IPv6 address rather than a
/// human-readable hostname.
///
/// Raw IP addresses in outbound connections that are not explicitly
/// allow-listed are treated as Tier 3 (High risk) because they often indicate
/// exfiltration to infrastructure that bypasses DNS-level controls.
///
/// # SECURITY
///
/// This is a heuristic, not a security boundary. The actual enforcement
/// boundary is the Landlock/seccomp layer. This classification surfaces a
/// high-risk JIT prompt to inform the user.
fn is_unknown_ip_address(host: &str) -> bool {
    use std::net::IpAddr;
    host.parse::<IpAddr>().is_ok()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use kernex_ipc::{Operation, PolicyQuery, Resource, RiskTier};
    use kernex_policy::{
        EnvironmentPolicy, FilesystemPolicy, KernexPolicy, NetworkPolicy, NetworkRule,
    };

    use super::*;

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

    fn file_read_query(path: &str) -> PolicyQuery {
        PolicyQuery {
            id: 1,
            operation: Operation::FileRead,
            resource: Resource::Path(PathBuf::from(path)),
        }
    }

    fn file_write_query(path: &str) -> PolicyQuery {
        PolicyQuery {
            id: 2,
            operation: Operation::FileWrite,
            resource: Resource::Path(PathBuf::from(path)),
        }
    }

    fn network_query(host: &str, port: u16) -> PolicyQuery {
        PolicyQuery {
            id: 3,
            operation: Operation::NetworkConnect,
            resource: Resource::Network {
                host: host.to_string(),
                port,
            },
        }
    }

    fn env_query(name: &str) -> PolicyQuery {
        PolicyQuery {
            id: 4,
            operation: Operation::EnvRead,
            resource: Resource::EnvVar(name.to_string()),
        }
    }

    // -- Filesystem: hidden path ---------------------------------------------

    #[test]
    fn test_evaluate_hidden_path_denied_when_block_hidden_true() {
        let policy = minimal_policy();
        let result = evaluate(&policy, &file_read_query("/home/user/.ssh/id_rsa"));
        assert_eq!(result.verdict, EvalVerdict::Deny);
        assert!(!result.injection_signal);
    }

    #[test]
    fn test_evaluate_hidden_path_prompts_high_when_block_hidden_false() {
        let mut policy = minimal_policy();
        policy.filesystem.block_hidden = false;
        // .ssh is also a sensitive pattern → Prompt(High) with injection_signal
        let result = evaluate(&policy, &file_read_query("/home/user/.ssh/id_rsa"));
        assert_eq!(result.verdict, EvalVerdict::Prompt(RiskTier::High));
        assert!(result.injection_signal);
    }

    #[test]
    fn test_evaluate_dotfile_path_with_block_hidden_false_and_not_sensitive_prompts_medium() {
        let mut policy = minimal_policy();
        policy.filesystem.block_hidden = false;
        // .profile is hidden but not in SENSITIVE_FS_PATTERNS
        let result = evaluate(&policy, &file_read_query("/home/user/.profile"));
        assert_eq!(result.verdict, EvalVerdict::Prompt(RiskTier::Medium));
    }

    // -- Filesystem: sensitive path ------------------------------------------

    #[test]
    fn test_evaluate_aws_credentials_prompts_high_with_injection_signal() {
        let mut policy = minimal_policy();
        policy.filesystem.block_hidden = false;
        let result = evaluate(&policy, &file_read_query("/home/user/.aws/credentials"));
        assert_eq!(result.verdict, EvalVerdict::Prompt(RiskTier::High));
        assert!(result.injection_signal);
    }

    #[test]
    fn test_evaluate_etc_passwd_prompts_high_with_injection_signal() {
        let mut policy = minimal_policy();
        policy.filesystem.block_hidden = false;
        let result = evaluate(&policy, &file_read_query("/etc/passwd"));
        assert_eq!(result.verdict, EvalVerdict::Prompt(RiskTier::High));
        assert!(result.injection_signal);
    }

    // -- Filesystem: allow-list ----------------------------------------------

    #[test]
    fn test_evaluate_path_in_allow_read_is_allowed() {
        let mut policy = minimal_policy();
        policy.filesystem.allow_read = vec![PathBuf::from("/tmp/output")];
        let result = evaluate(&policy, &file_read_query("/tmp/output/data.csv"));
        assert_eq!(result.verdict, EvalVerdict::Allow);
    }

    #[test]
    fn test_evaluate_path_in_allow_write_is_allowed_for_write_op() {
        let mut policy = minimal_policy();
        policy.filesystem.allow_write = vec![PathBuf::from("/tmp/output")];
        let result = evaluate(&policy, &file_write_query("/tmp/output/result.txt"));
        assert_eq!(result.verdict, EvalVerdict::Allow);
    }

    #[test]
    fn test_evaluate_path_in_allow_write_is_allowed_for_read_op() {
        let mut policy = minimal_policy();
        policy.filesystem.allow_write = vec![PathBuf::from("/tmp/output")];
        // Write permission implies read permission on the same subtree.
        let result = evaluate(&policy, &file_read_query("/tmp/output/result.txt"));
        assert_eq!(result.verdict, EvalVerdict::Allow);
    }

    #[test]
    fn test_evaluate_path_outside_policy_prompts_medium() {
        let mut policy = minimal_policy();
        policy.filesystem.allow_read = vec![PathBuf::from("/tmp/src")];
        let result = evaluate(&policy, &file_read_query("/tmp/data/other.csv"));
        assert_eq!(result.verdict, EvalVerdict::Prompt(RiskTier::Medium));
    }

    // -- Network -------------------------------------------------------------

    #[test]
    fn test_evaluate_network_in_allowlist_is_allowed() {
        let mut policy = minimal_policy();
        policy.network.allow_outbound = vec![NetworkRule {
            host: "api.anthropic.com".to_string(),
            port: 443,
            max_requests_per_minute: None,
            max_payload_bytes: None,
        }];
        let result = evaluate(&policy, &network_query("api.anthropic.com", 443));
        assert_eq!(result.verdict, EvalVerdict::Allow);
    }

    #[test]
    fn test_evaluate_network_not_in_allowlist_block_all_other_true_is_denied() {
        let policy = minimal_policy(); // block_all_other: true by default
        let result = evaluate(&policy, &network_query("evil.example.com", 443));
        assert_eq!(result.verdict, EvalVerdict::Deny);
    }

    #[test]
    fn test_evaluate_network_not_in_allowlist_block_all_other_false_prompts_medium() {
        let mut policy = minimal_policy();
        policy.network.block_all_other = false;
        let result = evaluate(&policy, &network_query("new-api.example.com", 80));
        assert_eq!(result.verdict, EvalVerdict::Prompt(RiskTier::Medium));
    }

    #[test]
    fn test_evaluate_network_port_mismatch_is_denied() {
        let mut policy = minimal_policy();
        policy.network.allow_outbound = vec![NetworkRule {
            host: "api.anthropic.com".to_string(),
            port: 443,
            max_requests_per_minute: None,
            max_payload_bytes: None,
        }];
        // Port 80 is not allowed — only 443.
        let result = evaluate(&policy, &network_query("api.anthropic.com", 80));
        assert_eq!(result.verdict, EvalVerdict::Deny);
    }

    // -- Environment ---------------------------------------------------------

    #[test]
    fn test_evaluate_env_in_allowlist_is_allowed() {
        let mut policy = minimal_policy();
        policy.environment.allow_read = vec!["ANTHROPIC_API_KEY".to_string()];
        let result = evaluate(&policy, &env_query("ANTHROPIC_API_KEY"));
        assert_eq!(result.verdict, EvalVerdict::Allow);
    }

    #[test]
    fn test_evaluate_env_sensitive_prompts_high_with_injection_signal() {
        let mut policy = minimal_policy();
        policy.environment.block_all_other = false;
        let result = evaluate(&policy, &env_query("AWS_SECRET_ACCESS_KEY"));
        assert_eq!(result.verdict, EvalVerdict::Prompt(RiskTier::High));
        assert!(result.injection_signal);
    }

    #[test]
    fn test_evaluate_env_not_in_allowlist_block_all_other_true_is_denied() {
        let policy = minimal_policy(); // block_all_other: true
        let result = evaluate(&policy, &env_query("MY_CUSTOM_VAR"));
        assert_eq!(result.verdict, EvalVerdict::Deny);
    }

    #[test]
    fn test_evaluate_env_not_in_allowlist_block_all_other_false_prompts_medium() {
        let mut policy = minimal_policy();
        policy.environment.block_all_other = false;
        let result = evaluate(&policy, &env_query("MY_CUSTOM_VAR"));
        assert_eq!(result.verdict, EvalVerdict::Prompt(RiskTier::Medium));
    }

    // -- is_hidden_path ------------------------------------------------------

    #[test]
    fn test_is_hidden_path_detects_dotfile() {
        assert!(is_hidden_path(Path::new("/home/user/.ssh")));
    }

    #[test]
    fn test_is_hidden_path_does_not_flag_current_dir_component() {
        assert!(!is_hidden_path(Path::new("./src/main.rs")));
    }

    // -- is_sensitive_fs_path: one test per pattern -------------------------

    #[test]
    fn test_is_sensitive_fs_path_detects_ssh() {
        assert!(is_sensitive_fs_path(Path::new("/home/user/.ssh/id_rsa")));
    }

    #[test]
    fn test_is_sensitive_fs_path_detects_aws() {
        assert!(is_sensitive_fs_path(Path::new(
            "/home/user/.aws/credentials"
        )));
    }

    #[test]
    fn test_is_sensitive_fs_path_detects_gnupg() {
        assert!(is_sensitive_fs_path(Path::new(
            "/home/user/.gnupg/secring.gpg"
        )));
    }

    #[test]
    fn test_is_sensitive_fs_path_detects_gcloud() {
        assert!(is_sensitive_fs_path(Path::new(
            "/home/user/.config/gcloud/credentials.json"
        )));
    }

    #[test]
    fn test_is_sensitive_fs_path_detects_config_gh() {
        assert!(is_sensitive_fs_path(Path::new(
            "/home/user/.config/gh/hosts.yml"
        )));
    }

    #[test]
    fn test_is_sensitive_fs_path_detects_kube() {
        assert!(is_sensitive_fs_path(Path::new("/home/user/.kube/config")));
    }

    #[test]
    fn test_is_sensitive_fs_path_detects_netrc() {
        assert!(is_sensitive_fs_path(Path::new("/home/user/.netrc")));
    }

    #[test]
    fn test_is_sensitive_fs_path_detects_etc_passwd() {
        assert!(is_sensitive_fs_path(Path::new("/etc/passwd")));
    }

    #[test]
    fn test_is_sensitive_fs_path_detects_etc_shadow() {
        assert!(is_sensitive_fs_path(Path::new("/etc/shadow")));
    }

    #[test]
    fn test_is_sensitive_fs_path_detects_etc_sudoers() {
        assert!(is_sensitive_fs_path(Path::new("/etc/sudoers")));
    }

    #[test]
    fn test_is_sensitive_fs_path_does_not_flag_normal_path() {
        assert!(!is_sensitive_fs_path(Path::new("/home/user/projects/src")));
    }

    // -- evaluate: Prompt(High) for every sensitive FS pattern --------------

    #[test]
    fn test_evaluate_gnupg_prompts_high_with_injection_signal() {
        let mut policy = minimal_policy();
        policy.filesystem.block_hidden = false;
        let result = evaluate(&policy, &file_read_query("/home/user/.gnupg/secring.gpg"));
        assert_eq!(result.verdict, EvalVerdict::Prompt(RiskTier::High));
        assert!(result.injection_signal);
    }

    #[test]
    fn test_evaluate_config_gcloud_prompts_high_with_injection_signal() {
        let mut policy = minimal_policy();
        policy.filesystem.block_hidden = false;
        let result = evaluate(
            &policy,
            &file_read_query("/home/user/.config/gcloud/credentials.json"),
        );
        assert_eq!(result.verdict, EvalVerdict::Prompt(RiskTier::High));
        assert!(result.injection_signal);
    }

    #[test]
    fn test_evaluate_config_gh_prompts_high_with_injection_signal() {
        let mut policy = minimal_policy();
        policy.filesystem.block_hidden = false;
        let result = evaluate(&policy, &file_read_query("/home/user/.config/gh/hosts.yml"));
        assert_eq!(result.verdict, EvalVerdict::Prompt(RiskTier::High));
        assert!(result.injection_signal);
    }

    #[test]
    fn test_evaluate_kube_config_prompts_high_with_injection_signal() {
        let mut policy = minimal_policy();
        policy.filesystem.block_hidden = false;
        let result = evaluate(&policy, &file_read_query("/home/user/.kube/config"));
        assert_eq!(result.verdict, EvalVerdict::Prompt(RiskTier::High));
        assert!(result.injection_signal);
    }

    #[test]
    fn test_evaluate_netrc_prompts_high_with_injection_signal() {
        let mut policy = minimal_policy();
        policy.filesystem.block_hidden = false;
        let result = evaluate(&policy, &file_read_query("/home/user/.netrc"));
        assert_eq!(result.verdict, EvalVerdict::Prompt(RiskTier::High));
        assert!(result.injection_signal);
    }

    #[test]
    fn test_evaluate_etc_shadow_prompts_high_with_injection_signal() {
        let mut policy = minimal_policy();
        policy.filesystem.block_hidden = false;
        let result = evaluate(&policy, &file_read_query("/etc/shadow"));
        assert_eq!(result.verdict, EvalVerdict::Prompt(RiskTier::High));
        assert!(result.injection_signal);
    }

    #[test]
    fn test_evaluate_etc_sudoers_prompts_high_with_injection_signal() {
        let mut policy = minimal_policy();
        policy.filesystem.block_hidden = false;
        let result = evaluate(&policy, &file_read_query("/etc/sudoers"));
        assert_eq!(result.verdict, EvalVerdict::Prompt(RiskTier::High));
        assert!(result.injection_signal);
    }

    // -- is_sensitive_env_var: one test per pattern -------------------------

    #[test]
    fn test_is_sensitive_env_var_detects_aws_prefix() {
        assert!(is_sensitive_env_var("AWS_SECRET_ACCESS_KEY"));
        assert!(is_sensitive_env_var("AWS_ACCESS_KEY_ID"));
    }

    #[test]
    fn test_is_sensitive_env_var_detects_google_prefix() {
        assert!(is_sensitive_env_var("GOOGLE_APPLICATION_CREDENTIALS"));
        assert!(is_sensitive_env_var("GOOGLE_CLOUD_PROJECT"));
    }

    #[test]
    fn test_is_sensitive_env_var_detects_github_token() {
        assert!(is_sensitive_env_var("GITHUB_TOKEN"));
    }

    #[test]
    fn test_is_sensitive_env_var_detects_npm_token() {
        assert!(is_sensitive_env_var("NPM_TOKEN"));
    }

    #[test]
    fn test_is_sensitive_env_var_detects_database_url() {
        assert!(is_sensitive_env_var("DATABASE_URL"));
    }

    #[test]
    fn test_is_sensitive_env_var_detects_secret() {
        assert!(is_sensitive_env_var("MY_SECRET"));
        assert!(is_sensitive_env_var("APP_SECRET_KEY"));
    }

    #[test]
    fn test_is_sensitive_env_var_detects_password() {
        assert!(is_sensitive_env_var("DB_PASSWORD"));
    }

    #[test]
    fn test_is_sensitive_env_var_detects_private_key() {
        assert!(is_sensitive_env_var("SSH_PRIVATE_KEY"));
        assert!(is_sensitive_env_var("TLS_PRIVATE_KEY"));
    }

    #[test]
    fn test_is_sensitive_env_var_is_case_insensitive() {
        assert!(is_sensitive_env_var("db_password"));
        assert!(is_sensitive_env_var("github_token"));
        assert!(is_sensitive_env_var("aws_secret_access_key"));
    }

    #[test]
    fn test_is_sensitive_env_var_does_not_flag_normal_var() {
        assert!(!is_sensitive_env_var("HOME"));
        assert!(!is_sensitive_env_var("PATH"));
        assert!(!is_sensitive_env_var("USER"));
    }

    // -- evaluate: Prompt(High) for every sensitive ENV pattern -------------

    #[test]
    fn test_evaluate_google_credentials_env_prompts_high() {
        let mut policy = minimal_policy();
        policy.environment.block_all_other = false;
        let result = evaluate(&policy, &env_query("GOOGLE_APPLICATION_CREDENTIALS"));
        assert_eq!(result.verdict, EvalVerdict::Prompt(RiskTier::High));
        assert!(result.injection_signal);
    }

    #[test]
    fn test_evaluate_github_token_env_prompts_high() {
        let mut policy = minimal_policy();
        policy.environment.block_all_other = false;
        let result = evaluate(&policy, &env_query("GITHUB_TOKEN"));
        assert_eq!(result.verdict, EvalVerdict::Prompt(RiskTier::High));
        assert!(result.injection_signal);
    }

    #[test]
    fn test_evaluate_npm_token_env_prompts_high() {
        let mut policy = minimal_policy();
        policy.environment.block_all_other = false;
        let result = evaluate(&policy, &env_query("NPM_TOKEN"));
        assert_eq!(result.verdict, EvalVerdict::Prompt(RiskTier::High));
        assert!(result.injection_signal);
    }

    #[test]
    fn test_evaluate_database_url_env_prompts_high() {
        let mut policy = minimal_policy();
        policy.environment.block_all_other = false;
        let result = evaluate(&policy, &env_query("DATABASE_URL"));
        assert_eq!(result.verdict, EvalVerdict::Prompt(RiskTier::High));
        assert!(result.injection_signal);
    }

    #[test]
    fn test_evaluate_secret_env_prompts_high() {
        let mut policy = minimal_policy();
        policy.environment.block_all_other = false;
        let result = evaluate(&policy, &env_query("APP_SECRET_KEY"));
        assert_eq!(result.verdict, EvalVerdict::Prompt(RiskTier::High));
        assert!(result.injection_signal);
    }

    #[test]
    fn test_evaluate_private_key_env_prompts_high() {
        let mut policy = minimal_policy();
        policy.environment.block_all_other = false;
        let result = evaluate(&policy, &env_query("SSH_PRIVATE_KEY"));
        assert_eq!(result.verdict, EvalVerdict::Prompt(RiskTier::High));
        assert!(result.injection_signal);
    }

    // -- Network: unknown outbound IPs are Tier 3 ---------------------------

    #[test]
    fn test_evaluate_unknown_ipv4_prompts_high_with_injection_signal() {
        let mut policy = minimal_policy();
        policy.network.block_all_other = false;
        // A raw IPv4 address not in the allowlist is treated as high-risk.
        let result = evaluate(&policy, &network_query("203.0.113.42", 443));
        assert_eq!(result.verdict, EvalVerdict::Prompt(RiskTier::High));
        assert!(result.injection_signal);
    }

    #[test]
    fn test_evaluate_unknown_ipv6_prompts_high_with_injection_signal() {
        let mut policy = minimal_policy();
        policy.network.block_all_other = false;
        let result = evaluate(&policy, &network_query("2001:db8::1", 443));
        assert_eq!(result.verdict, EvalVerdict::Prompt(RiskTier::High));
        assert!(result.injection_signal);
    }

    #[test]
    fn test_evaluate_allowlisted_ip_is_allowed() {
        let mut policy = minimal_policy();
        policy.network.allow_outbound = vec![NetworkRule {
            host: "203.0.113.42".to_string(),
            port: 443,
            max_requests_per_minute: None,
            max_payload_bytes: None,
        }];
        let result = evaluate(&policy, &network_query("203.0.113.42", 443));
        assert_eq!(result.verdict, EvalVerdict::Allow);
        // Explicitly allow-listed IP is not an injection signal.
        assert!(!result.injection_signal);
    }

    #[test]
    fn test_evaluate_hostname_not_in_allowlist_block_false_prompts_medium() {
        let mut policy = minimal_policy();
        policy.network.block_all_other = false;
        // Named hostname (not a raw IP) → Medium, not High.
        let result = evaluate(&policy, &network_query("new-api.example.com", 80));
        assert_eq!(result.verdict, EvalVerdict::Prompt(RiskTier::Medium));
    }
}
